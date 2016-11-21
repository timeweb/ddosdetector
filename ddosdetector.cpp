#include <iostream>
// Signal handlers
#include <boost/asio.hpp>
#include <boost/program_options.hpp>

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
#include "influxdb.hpp"
#include "rules.hpp"
#include "collector.hpp"
#include "controld.hpp"

// Main logger
log4cpp::Category& logger = log4cpp::Category::getRoot();


/*
 The main thread - watcher. Monitors the synchronization of the rules in all
 threads processing queuing network card. Collects data counters the rules of
 each stream. Computes totals. Checks triggers on the operation and adds a
 task to perform.
*/
void watcher(std::vector<std::shared_ptr<RulesCollection>>& collect,
    std::shared_ptr<RulesCollection> main_collect,
    std::shared_ptr<ts_queue<action::TriggerJob>> task_list,
    std::shared_ptr<InfluxClient> influx)
{
    RulesCollection prev_collect(*main_collect);
    std::chrono::high_resolution_clock::time_point last_change;
    for(;;)
    {
        int i = 0;
        for(auto& c: collect)
        {
            // check the relevance of the rules table in thread
            if(*c != *main_collect) 
            {
                // synchronize the thread's rules
                *c = *main_collect; 
                logger.debug("update rules list in thread %d", i);
            }
            // add the counters of the i-thread
            *main_collect += *c; 
            i++;
        }
        // calculate delta metrics for the second time 1
        main_collect->calc_delta(prev_collect);
        // save the new counters and rules for the next cycle step
        prev_collect = *main_collect;
        // immediately after updating the rules does not make sense to check
        // triggers, the data is not relevant
        if(last_change == main_collect->last_change)
        {
            // check triggers
            main_collect->check_triggers(*task_list, *influx);
        }
        else
        {
            last_change = main_collect->last_change;
        }
        // sleep one second
        boost::this_thread::sleep_for(boost::chrono::seconds(1));
    }
}

void monitor(std::shared_ptr<RulesCollection> collect,
    std::shared_ptr<InfluxClient> influx, unsigned int period)
{
    int code = 0;
    for(;;)
    {
        std::string q = collect->get_influx_querys();
        code = influx->insert(q);
        if(code != 0)
        {
            logger.error("Bad request, curl lib return code: %d", code);
        }
        // sleep
        boost::this_thread::sleep_for(boost::chrono::seconds(period));
    }
}

/*
 Thread sends the data to the database InfluxDB, each period
*/
void start_control(boost::asio::io_service& io_service,
    std::string port, std::shared_ptr<RulesCollection> collect)
{
    try
    {
        ControlServer serv(io_service, port, collect);
        io_service.run();
    }
    catch (std::exception& e)
    {
        logger << log4cpp::Priority::ERROR
               << "Controld server error: "
               << e.what();
    }
}

/*
 Handler jobs in the queue. Parse all task_list which contains TriggerJob tasks
 and starts them in turn. The handler responds immediately to adding a job
 queue (dummy) or second waiting (this made for possible interrupt waiting
 process).
*/
void task_runner(std::shared_ptr<ts_queue<action::TriggerJob>> task_list)
{
    // buffer for task
    action::TriggerJob cur_job;
    for(;;)
    {
        // check exit
        boost::this_thread::interruption_point();
        // wait ano second or change status queue
        if(task_list->wait_and_pop(cur_job, 1000)) 
        {
            // start task
            cur_job.run(); 
        }
    }
}

int main(int argc, char** argv) {
    // Default settings
    std::string interface = "";
    std::string config_file = "/etc/ddosdetector.conf";
    std::string rules_file = "/etc/ddosdetector.rules";
    std::string log_file = "";
    std::string port = "9090";
    bool debug_mode = false;
    // Default for InfluxDB
    std::string influx_enable = "no";
    std::string influx_user = "";
    std::string influx_pass = "";
    std::string influx_db = "ddosdetector";
    std::string influx_host = "localhost";
    unsigned int influx_port = 8086;
    unsigned int influx_period = 60;

    // CLI arguments
    namespace po = boost::program_options;
    po::options_description argv_opt("General options");
    argv_opt.add_options()
        ("help,h", "show this help")
        ("interface,i", po::value<std::string>(&interface), "network interface (default eth4)")
        //("config,c", po::value<std::string>(&config_file), "load config (default /etc/ddosdetector.conf)")
        ("rules,r", po::value<std::string>(&rules_file), "load rules from file (default /etc/ddosdetector.rules)")
        ("log,l", po::value<std::string>(&log_file), "log file (default output to console)")
        ("port,p", po::value<std::string>(&port), "port for controld tcp server (may be unix socket file)")
        ("debug,d", "enable debug output")
    ;
    // Configuration file options
    po::options_description config_file_opt("Configuration file");
    config_file_opt.add_options()
        ("Main.Interface", po::value<std::string>(&interface))
        ("Main.Rules", po::value<std::string>(&rules_file))
        ("Main.Log", po::value<std::string>(&log_file))
        ("Main.Port", po::value<std::string>(&port))
        ("IndluxDB.Enable", po::value<std::string>(&influx_enable))
        ("IndluxDB.User", po::value<std::string>(&influx_user))
        ("IndluxDB.Password", po::value<std::string>(&influx_pass))
        ("IndluxDB.Database", po::value<std::string>(&influx_db))
        ("IndluxDB.Host", po::value<std::string>(&influx_host))
        ("IndluxDB.Port", po::value<unsigned int>(&influx_port))
        ("IndluxDB.Period", po::value<unsigned int>(&influx_period))
    ;
    // Base rule's options
    po::options_description base_opt("Base rule options");
    base_opt.add_options()
        ("pps-th", po::value<std::string>(), "trigger threshold incomming packets per second (p,Kp,Mp,Tp,Pp)")
        ("bps-th", po::value<std::string>(), "trigger threshold incomming bits per second (b,Kb,Mb,Tb,Pb)")
        ("pps-th-period", po::value<unsigned int>(), "trigger threshold period in seconds (default 10)")
        ("bps-th-period", po::value<unsigned int>(), "trigger threshold period in seconds (default 10)")
        ("action,a", po::value<std::string>(), "run action when trigger active (type:param)")
        ("comment,c", po::value<std::string>(), "comment for rule")
        ("next", "go to next rule in list")
    ;
    // L3 header options
    po::options_description ipv4_opt("IPv4 rule options");
    ipv4_opt.add_options()
        ("dstip,d", po::value<std::string>(), "destination ip address/net")
        ("srcip,s", po::value<std::string>(), "source ip address/net")
    ;
    // L4 header options
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
        ("hlen", po::value<std::string>(), "check if TCP header len = or > or < arg (in bytes)")
    ;
    po::options_description icmp_opt("ICMP rule options");
    icmp_opt.add_options()
        ("type", po::value<std::string>(), "check if ICMP packet type = or > or < arg")
        ("code", po::value<std::string>(), "check if ICMP packet code = or > or < arg")
    ;

    // Aggregate options for help() commands
    po::options_description help_opt;
    help_opt.add(base_opt).add(ipv4_opt).add(tcp_opt).add(udp_opt).add(icmp_opt);

    // Aggregate options for TCP rules: base options + ipv4 options + TCP options
    po::options_description tcp_rule_opt;
    tcp_rule_opt.add(base_opt).add(ipv4_opt).add(tcp_opt);

    // Aggregate options for UDP rules: base options + ipv4 options + UDP options
    po::options_description udp_rule_opt;
    udp_rule_opt.add(base_opt).add(ipv4_opt).add(udp_opt);

    // Aggregate options for ICMP rules: base options + ipv4 options + ICMP options
    po::options_description icmp_rule_opt;
    icmp_rule_opt.add(base_opt).add(ipv4_opt).add(icmp_opt);

    // Parse arguments
    po::variables_map vm;
    try 
    {
        // Load configuration from file
        std::ifstream cnf(config_file);
        if(cnf)
        {
            po::store(po::parse_config_file(cnf, config_file_opt, true), vm);
            po::notify(vm);
        }
        else
        {
            std::cerr << "Configuration file: " << config_file
                      << " not found" << std::endl;
        }
        po::store(po::parse_command_line(argc, argv, argv_opt), vm);
        po::notify(vm);
    } 
    catch(po::error& e) 
    { 
        std::cerr << "Parse options error: " << e.what() << std::endl << std::endl; 
        std::cerr << argv_opt << std::endl;
        return 1; 
    } 

    if (vm.count("help")) 
    { 
        std::cout << "Basic Command Line Parameter App" << std::endl 
                  << argv_opt << std::endl
                  << help_opt << std::endl;
        return 0; 
    }

    // Enable debug
    if(vm.count("debug"))
        debug_mode = true;

    // Setup logging
    init_logging(logger, debug_mode, log_file);

    if(interface == "")
    {
        logger << log4cpp::Priority::CRIT << "Interface '-i' not set";
        exit(1);
    }

    // Enable promisc mode on network adapter (only in Linux)
#ifdef __linux__
    manage_interface_promisc_mode(interface, 1);
    logger << log4cpp::Priority::WARN
           << "Please disable all types of offload for"
           << "this NIC manually: ethtool -K "
           << interface
           << " gro off gso off tso off lro off";
#endif  /* __linux__ */

    // The main object io_service, is used to capture
    // Signals and work controld server.
    boost::asio::io_service io_s;

    // Catch signals SIGINT, SIGTERM to complete the program.
    boost::asio::signal_set signals(io_s, SIGINT, SIGTERM);
    signals.async_wait(boost::bind(&boost::asio::io_service::stop, &io_s));

    // Thread sheet. This list will be added to all streams of the program,
    // to monitor the condition and safely terminate
    boost::thread_group threads;

    // Vector rules on lists of pointers. Each separate sheet
    // Rules works the same thread. Each sheet is synchronized flow
    // Watcher with a reference sheet main_collect.
    std::vector<std::shared_ptr<RulesCollection>> threads_coll;

    // Reference collection of rules for it will be all the threads
    auto main_collect = std::make_shared<RulesCollection>(help_opt,
                                                      tcp_rule_opt,
                                                      udp_rule_opt,
                                                      icmp_rule_opt);

    // Queues for TriggerJobs
    auto  task_list = std::make_shared<ts_queue<action::TriggerJob>>();

    // InfluxDB client
    auto influx_client = std::make_shared<InfluxClient>(influx_host,
                                                        influx_port,
                                                        influx_db,
                                                        influx_user,
                                                        influx_pass,
                                                        influx_enable);

    // Load rules from file
    /*
     RulesFileLoader loads the current configuration of the file during
     initialization and also sets new signal_set SIGHUP to intercept and
     updates config. Every time you try to reload the rules file is executed
     checking for file existence. The signal is also tied to the main
     io_service.
    */
    RulesFileLoader rul_loader(io_s, rules_file, main_collect);
    try
    {
        rul_loader.start();
    }
    catch(std::exception& e)
    {
        logger << log4cpp::Priority::CRIT << "Rules file loader failed: " << e.what();
        return 1;
    }
    /*
     Start netmap interface and start processing the queue of network threads
     cards. Class fills vector sheet rules (threads_coll) as
     creating flows linked to queues network card.
    */
    NetmapReceiver nm_recv(interface, threads, threads_coll, *main_collect);
    try
    {
        // connect to netmap, run threads
        nm_recv.start();
    }
    catch(NetmapException& e)
    {
        logger << log4cpp::Priority::CRIT << "Netmap failed: " << e.what();
        return 1;
    }

    // run thread-watcher
    threads.add_thread(new boost::thread(watcher, std::ref(threads_coll),
                                         main_collect, task_list,
                                         influx_client));
    logger.debug("Start watcher thread");

    // run control server
    threads.add_thread(new boost::thread(start_control,
                                         std::ref(io_s), port, main_collect));

    // run triggerjob watcher thread
    threads.add_thread(new boost::thread(task_runner, task_list));
    logger.debug("Starting runner thread");

    // start monitor thread
    if(influx_client->is_enable())
    {
        threads.add_thread(new boost::thread(monitor, main_collect,
                                             influx_client, influx_period));
        logger.debug("Start monitor thread");
    }

    // run TCP/UNIX socket server
    try
    {
        io_s.run();
    }
    catch(std::exception& e)
    {
        logger << log4cpp::Priority::ERROR << "Signal handler error: " << e.what();
    }

    // catch signal, interrupt all threads
    threads.interrupt_all();
    logger.info("Waiting threads.....");
    // wait all threads
    threads.join_all();

    return 0;
}
