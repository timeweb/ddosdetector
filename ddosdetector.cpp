#include <iostream>
// Signal handlers
#include <boost/asio.hpp>

// Logging
#include "log4cpp/Category.hh"
#include "log4cpp/Appender.hh"
#include "log4cpp/FileAppender.hh"
#include "log4cpp/OstreamAppender.hh"
#include "log4cpp/Layout.hh"
#include "log4cpp/BasicLayout.hh"
#include "log4cpp/Priority.hh"
#include "log4cpp/PatternLayout.hh"

#include "lib/queue.hpp"
#include "functions.hpp"
#include "parser.hpp"
#include "action.hpp"
#include "rules.hpp"
#include "collector.hpp"
#include "controld.hpp"

// Основной логер
log4cpp::Category& logger = log4cpp::Category::getRoot();


/*
   Основной поток - watcher. Селедит за синхронизацией правил во всех
   потоках-обработчиках очередей сетевой карты, собирает данные со
   счетчиков правил каждого потока, вычисляет итоговые показатели, проверяет
   триггеры на срабатывание и добавляет задания на выполнение.
*/
void watcher(std::vector<std::shared_ptr<rcollection>>& collect,
	std::shared_ptr<rcollection> main_collect,
	std::shared_ptr<ts_queue<action::job>> task_list)
{
	rcollection prev_collect(*main_collect);
	for(;;)
	{
		int i = 0;
		for(auto& c: collect)
		{
			if(*c != *main_collect) // если у потока неактуальная таблица правил
			{
				*c = *main_collect; // синхронизируем правила потока
				logger.debug("update rules list in thread %d", i);
			}
			*main_collect += *c; // прибавляем счетчики i-того потока 
			i++;
		}
		main_collect->calc_delta(prev_collect); // вычисляем delta показатели за 1 секунду времени
		prev_collect = *main_collect; // сохраняем новые счетчики и правила для следующего шага цикла
		main_collect->check_triggers(*task_list); // проверяем триггеры

		//std::cout << main_collect->get_rules();
		boost::this_thread::sleep_for(boost::chrono::seconds(1));
	}
}

// Сервер управления (TCP или UNIX socket)
void start_control(boost::asio::io_service& io_service,
	std::string port, std::shared_ptr<rcollection> collect)
{
	try
	{
		server serv(io_service, port, collect);
		io_service.run();
	}
	catch (std::exception& e)
	{
		logger << log4cpp::Priority::ERROR << "Controld server error: " << e.what();
	}
}

// Обработчик очереди заданий
void task_runner(std::shared_ptr<ts_queue<action::job>> task_list)
{
	action::job cur_job;
	for(;;)
	{
		boost::this_thread::interruption_point(); // Проверям был ли прерван поток
		if(task_list->wait_and_pop(cur_job, 1000)) // ждем одну секунду или появления задачи
		{
			cur_job.run(); // старт задачи
		}
	}
}

int main(int argc, char** argv) {
	// Настройки по-умолчанию
	std::string interface = "eth4";
	std::string config_file = "/etc/ddosdetector.conf";
	std::string rules_file = "/etc/ddosdetector.rules";
	std::string log_file = "";
	std::string port = "9090";
	bool debug_mode = false;

	// Опции запуска приложения
	namespace po = boost::program_options;
	po::options_description general_opt("General options");
	general_opt.add_options()
		("help,h", "show this help")
		("interface,i", po::value<std::string>(&interface), "network interface (default eth4)")
		("config,c", po::value<std::string>(&config_file), "load config (default /etc/ddosdetector.conf)")
		("rules,r", po::value<std::string>(&rules_file), "load rules from file (default /etc/ddosdetector.rules)")
		("log,l", po::value<std::string>(&log_file), "log file (default output to console)")
		("port,p", po::value<std::string>(&port), "port for controld tcp server (may be unix socket file)")
		("debug,d", "enable debug output")
	;

	// Настройки обработчика команд для правил слежения
	po::options_description base_opt("Base rule options");
	base_opt.add_options()
		("pps-th", po::value<std::string>(), "trigger threshold incomming packets per second (p,Kp,Mp,Tp,Pp)")
		("bps-th", po::value<std::string>(), "trigger threshold incomming bits per second (b,Kb,Mb,Tb,Pb)")
		("pps-th-period", po::value<unsigned int>(), "trigger threshold period in seconds (default 10)")
		("bps-th-period", po::value<unsigned int>(), "trigger threshold period in seconds (default 10)")
		("action,a", po::value<std::string>(), "run action when trigger active (type:param)")
		("next", "go to next rule in list")
	;
	// L3 header опции
	po::options_description ipv4_opt("IPv4 rule options");
	ipv4_opt.add_options()
		("dstip,d", po::value<std::string>(), "destination ip address/net")
		("srcip,s", po::value<std::string>(), "source ip address/net")
	;
	// L4 header опции
	po::options_description tcp_opt("TCP rule options");
	tcp_opt.add_options()
		("dport", po::value<std::string>(), "destination port")
		("sport", po::value<std::string>(), "source port")
		("seq", po::value<std::string>(), "check if sequence number = or > or < arg")
		("win", po::value<std::string>(), "check if window size number = or > or < arg")
		("ack", po::value<std::string>(), "check if acknowledgment number = or > or < arg")
		("hlen", po::value<std::string>(), "check if TCP header len = or > or < arg (in bytes)")
		("tcp-flag", po::value<std::string>(), "TCP flags <flag>:<enable>, where <enable> - 1 or 0; <flag> - U or R or P or S or A or F.")
	;
	po::options_description udp_opt("UDP rule options");
	udp_opt.add_options()
		("dport", po::value<std::string>(), "destination port")
		("sport", po::value<std::string>(), "source port")
	;
	po::options_description icmp_opt("ICMP rule options");
	icmp_opt.add_options()
		("dport", po::value<std::string>(), "destination port")
		("sport", po::value<std::string>(), "source port")
	;

	// Параметры для команды help(), собраны все опции
	po::options_description help_opt;
	help_opt.add(base_opt).add(ipv4_opt).add(tcp_opt).add(udp_opt).add(icmp_opt);

	// Параметры для TCP правил: базовые опции правил + ipv4 опции + TCP опции
	po::options_description tcp_rule_opt;
	tcp_rule_opt.add(base_opt).add(ipv4_opt).add(tcp_opt);

	// Параметры для UDP правил: базовые опции правил + ipv4 опции + UDP опции
	po::options_description udp_rule_opt;
	udp_rule_opt.add(base_opt).add(ipv4_opt).add(udp_opt);

	// Параметры для ICMP правил: базовые опции правил + ipv4 опции + ICMP опции
	po::options_description icmp_rule_opt;
	icmp_rule_opt.add(base_opt).add(ipv4_opt).add(icmp_opt);

	// Обработка аргументов
	po::variables_map vm; 
	try 
	{ 
		po::store(po::parse_command_line(argc, argv, general_opt), vm);
		if ( vm.count("help")  ) 
		{ 
			std::cout << "Basic Command Line Parameter App" << std::endl 
					  << general_opt << std::endl
					  << help_opt << std::endl;
			return 0; 
		} 
		po::notify(vm);
	} 
	catch(po::error& e) 
	{ 
		std::cerr << "ERROR: " << e.what() << std::endl << std::endl; 
		std::cerr << general_opt << std::endl; 
		return 1; 
	} 

	// Включение debug мода
	if(vm.count("debug"))
		debug_mode = true;

	// Инициализация логирования
	init_logging(logger, debug_mode, log_file);

// Включение promisc mode на сетевой карте (необходимо только в Linux)
#ifdef __linux__
	manage_interface_promisc_mode(interface, 1);
	logger << log4cpp::Priority::WARN
		   << "Please disable all types of offload for this NIC manually: ethtool -K "
		   << interface
		   << " gro off gso off tso off lro off";
#endif	/* __linux__ */

	// Экземпляр io_service, используется для отлова сигналов и работы сервера controld.
	boost::asio::io_service io_s;

	// Ловим сигналы  SIGINT, SIGTERM для завершения программы.
	boost::asio::signal_set signals(io_s, SIGINT, SIGTERM);
	signals.async_wait(boost::bind(&boost::asio::io_service::stop, &io_s));

	/* Лист потоков. В этот лист буду добавляться все потоки программы,
	   для отслеживания состояния и корректного прерывания
	*/
	boost::thread_group threads;

	/* Вектор указателей на листы правил. С каждым отдельным листом
	   правил работает один поток. Каждый лист синхронизируется потоком
	   watcher с эталонным листом main_collect.
	*/
	std::vector<std::shared_ptr<rcollection>> threads_coll;

	// Эталонная колекция правил, по ней будут ровняться все потоки
	auto main_collect = std::make_shared<rcollection>(help_opt, tcp_rule_opt/*,
													  udp_rule_opt, icmp_rule_opt*/);

	// Очередь заданий для сработавших триггеров
	auto  task_list = std::make_shared<ts_queue<action::job>>();

	// Загрузка конфигурации из файла
	if(is_file_exist(config_file))
	{
		logger.info("Load configuration file " + config_file);
		// TODO: чтение настроек с конфига
	}

	// Загрузка правил из файла
	/*
		rules_file_loader загружает текущий конфиг из файла при инициализации, а
		также устанавливает новый signal_set для перехвата SIGHUP и обновления конфига
		Каждый раз при попытке перезагрузить файл правил, выполняется проверка на
		существование файла.
	*/
	rules_file_loader rul_loader(io_s, rules_file, main_collect);
	try
	{
		rul_loader.start();
	}
	catch(std::exception& e)
	{
		logger << log4cpp::Priority::CRIT << "Rules file loader failed: " << e.what();
		return 1;
	}
	// Старт netmap интерфейса и запуск потоков обрабатывающих очереди сетевой карты
	netmap_receiver nm_recv(interface, threads, threads_coll, *main_collect);
	try
	{
		nm_recv.start();
	}
	catch(netmap::exception& e)
	{
		logger << log4cpp::Priority::CRIT << "Netmap failed: " << e.what();
		return 1;
	}

	// старт потока наблюдателя
	threads.add_thread(new boost::thread(watcher, std::ref(threads_coll), main_collect, task_list));
	logger.info("Start watcher thread");

	// старт TCP сервера управления
	threads.add_thread(new boost::thread(start_control, std::ref(io_s), port, main_collect));

	// старт обработчика заданий триггеров
	threads.add_thread(new boost::thread(task_runner, task_list));
	logger.info("Starting runner thread");

	// Ждме сигналы
	try
	{
		io_s.run();
	}
	catch(std::exception& e)
	{
		logger << log4cpp::Priority::ERROR << "Signal handler error: " << e.what();
	}

	// Завершение всех потоков
	threads.interrupt_all();
	logger.info("Waiting threads.....");
	// Ожидаем корректное завершение всех потоков
	threads.join_all();

	return 0;
}
