#include <iostream>
// Signal handlers
#include <boost/asio/signal_set.hpp>

// Logging
#include "log4cpp/Category.hh"
#include "log4cpp/Appender.hh"
#include "log4cpp/FileAppender.hh"
#include "log4cpp/OstreamAppender.hh"
#include "log4cpp/Layout.hh"
#include "log4cpp/BasicLayout.hh"
#include "log4cpp/Priority.hh"
#include "log4cpp/PatternLayout.hh"

#include "functions.hpp"
#include "parser.hpp"
#include "rules.hpp"
#include "collector.hpp"
#include "controld.hpp"

// Create main logger
log4cpp::Category& logger = log4cpp::Category::getRoot();

class globalSettings
{
public:
	int report_interval;
	bool console_report;
	std::string intf;

	globalSettings()
	{
		// Default
		report_interval = 1;
		console_report = true;
		intf = "eth0"; // Interface for sniff
	}
};

void watcher(std::vector<std::shared_ptr<rcollection>>& collect,
	std::shared_ptr<rcollection> main_collect)
{
	rcollection prev_collect(*main_collect);
	while(1)
	{
	 	int i = 0;
		for(auto& c: collect)
		{
			if(*c != *main_collect) // актуализация таблицы правил в потоке
			{
				*c = *main_collect;
				logger.debug("update rules list in thread %d", i);
			}
			*main_collect += *c; // прибавляем счетчики потока 
			i++;
		}
		main_collect->calc_delta(prev_collect);
		prev_collect = *main_collect; // сохраняем новые счетчики и правила
		main_collect->check_triggers();

		//std::cout << main_collect->get_rules();
		boost::this_thread::sleep_for(boost::chrono::seconds(1));
	}
}

void start_control(boost::asio::io_service& io_service,
	short port, std::shared_ptr<rcollection> collect)
{
	try
	{
		server s(io_service, port, collect);
		io_service.run();
	}
	catch (std::exception& e)
	{
		std::cerr << "Exception: " << e.what() << "\n";
	}
}

int main(int argc, char* argv[]) {
	if (argc == 1)
	{
		std::cerr << "Usage: ddosdetector <interface>\n";
		return 1;
	}
	init_logging(logger);
	globalSettings glob_arg;

	glob_arg.intf = std::string(argv[1]);

	//std::cout << boost::asio::ip::address_v4::from_string("192.168.0.1/20").to_ulong();
	// Declare the supported options.
	boost::program_options::options_description general_opt("TCP rule options");
	general_opt.add_options()
		("dstip,d", boost::program_options::value<std::string>(), "destination ip address/net")
		("srcip,s", boost::program_options::value<std::string>(), "source ip address/net")
		("dport", boost::program_options::value<std::string>(), "destination port")
		("sport", boost::program_options::value<std::string>(), "source port")
		("pps-th", boost::program_options::value<std::string>(), "trigger threshold incomming packets per second (p,Kp,Mp,Tp,Pp)")
		("bps-th", boost::program_options::value<std::string>(), "trigger threshold incomming bits per second (b,Kb,Mb,Tb,Pb)")
		("pps-th-period", boost::program_options::value<unsigned int>(), "trigger threshold period in seconds (default 10)")
		("bps-th-period", boost::program_options::value<unsigned int>(), "trigger threshold period in seconds (default 10)")
		("action,j", boost::program_options::value<std::string>(), "run action when trigger active")
	;

// Set network adapter promisc mode ON
#ifdef __linux__
	manage_interface_promisc_mode(glob_arg.intf, 1);
	logger << log4cpp::Priority::WARN << "Please disable all types of offload for this NIC manually: ethtool -K " << glob_arg.intf << " gro off gso off tso off lro off";
#endif	/* __linux__ */

	boost::asio::io_service io_s;
	// Construct a signal set registered for process termination.
	boost::asio::signal_set signals(io_s, SIGINT, SIGTERM);
	// Start an asynchronous wait for one of the signals to occur.
	signals.async_wait(boost::bind(&boost::asio::io_service::stop, &io_s));

	// Create thread_group
	boost::thread_group threads;

	// Create vector of thread's rules
	std::vector<std::shared_ptr<rcollection>> threads_coll;

	// Эталонная колекция правил, по ней будут ровняться все потоки
	auto main_collect = std::make_shared<rcollection>(general_opt);
	
	// тестовые правила
	try
	{
		main_collect->tcp.add_rule(tcp_rule(command_parser::tokenize("-d 92.53.96.141/32 --dport 80 --pps-th 1Kp")));
		//main_collect->tcp.add_rule(tcp_rule(command_parser::tokenize("-d 127.0.0.1/32 --dport 80 --bps-trigger 10Mb")));
		//main_collect->tcp.add_rule(tcp_rule(command_parser::tokenize("-d 0.0.0.0/24 --dport 80 --bps-trigger 10Mb")));
		main_collect->tcp.add_rule(tcp_rule(command_parser::tokenize("-d 0.0.0.0/0 --bps-th 100Mb")));
	}
	catch(const std::exception& e) { logger << log4cpp::Priority::ERROR << "Test rules failed: " << e.what(); }

	// Start receiver threads
	try
	{
		start_receiver_threads(glob_arg.intf, threads, threads_coll, *main_collect);
	}
	catch(NetmapException& e)
	{
		logger << log4cpp::Priority::CRIT << "Netmap failed: " << e.what();
		return 1;
	}

	// старт потока наблюдателя
	threads.add_thread(new boost::thread(watcher, std::ref(threads_coll), main_collect));
	logger.debug("Starting watcher thread");

	// старт TCP сервера управления
	threads.add_thread(new boost::thread(start_control, std::ref(io_s), 1234, main_collect));
	logger.debug("Starting control server");

	// Start wait signals
	io_s.run();

	logger.debug("Exiting.....");
	// Interrupt threads
	threads.interrupt_all();
	logger.debug("Waiting threads");
	// Wait all threads for completion
	threads.join_all();

	return 0;
}
