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
   Основной поток - watcher. Следит за синхронизацией правил во всех
   потоках-обработчиках очередей сетевой карты, собирает данные со
   счетчиков правил каждого потока, вычисляет итоговые показатели, проверяет
   триггеры на срабатывание и добавляет задания на выполнение.
*/
void watcher(std::vector<std::shared_ptr<RulesCollection>>& collect,
    std::shared_ptr<RulesCollection> main_collect,
    std::shared_ptr<ts_queue<action::TriggerJob>> task_list)
{
    RulesCollection prev_collect(*main_collect);
    std::chrono::high_resolution_clock::time_point last_change;
    for(;;)
    {
        int i = 0;
        for(auto& c: collect)
        {
            // проверка акутальности таблиц правил у потока
            if(*c != *main_collect) 
            {
                // синхронизируем правила потока
                *c = *main_collect; 
                logger.debug("update rules list in thread %d", i);
            }
            // прибавляем счетчики i-того потока
            *main_collect += *c; 
            i++;
        }
        // вычисляем delta показатели за 1 секунду времени
        main_collect->calc_delta(prev_collect);
        // сохраняем новые счетчики и правила для следующего шага цикла
        prev_collect = *main_collect;
        // сразу после обновления правил нет смысла проверять
        // триггеры, данные будут не актуальны
        if(last_change == main_collect->last_change)
        {
            // проверяем триггеры
            main_collect->check_triggers(*task_list);
        }
        else
        {
            last_change = main_collect->last_change;
        }
        // на секунду засыпаем
        boost::this_thread::sleep_for(boost::chrono::seconds(1));
    }
}

/*
 Сервер управления controld (TCP или UNIX socket). Сервер привязывается к
 заранее созданному io_service объекту, для общего контроля.
*/
void start_control(boost::asio::io_service& io_service,
    std::string port, std::shared_ptr<RulesCollection> collect)
{
    try
    {
        // инициализируем сервер
        ControlServer serv(io_service, port, collect);
        // запускаем сервер
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
 Обработчик очереди заданий. Разбирает очередь task_list в которой содержатся
 задания TriggerJob и запускает их по очереди. Обработчик сразу реагирует на
 добавление задания в очередь (условная переменная), либо ждет секунду (это
 сделано для возможности прерывания процесса ожидания).
*/
void task_runner(std::shared_ptr<ts_queue<action::TriggerJob>> task_list)
{
    // выполняемая задача
    action::TriggerJob cur_job;
    for(;;)
    {
        // Проверям был ли прерван поток
        boost::this_thread::interruption_point();
        // ждем одну секунду или появления задачи
        if(task_list->wait_and_pop(cur_job, 1000)) 
        {
            // старт задачи
            cur_job.run(); 
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
        ("comment,c", po::value<std::string>(), "comment for rule")
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
        ("hlen", po::value<std::string>(), "check if TCP header len = or > or < arg (in bytes)")
    ;
    po::options_description icmp_opt("ICMP rule options");
    icmp_opt.add_options()
        ("type", po::value<std::string>(), "check if ICMP packet type = or > or < arg")
        ("code", po::value<std::string>(), "check if ICMP packet code = or > or < arg")
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

    // Включение debug режима
    if(vm.count("debug"))
        debug_mode = true;

    // Инициализация логирования
    init_logging(logger, debug_mode, log_file);

    if(!vm.count("interface"))
    {
        logger << log4cpp::Priority::CRIT << "Interface '-i' not set";
        exit(1);
    }

    // Включение promisc mode на сетевой карте (работает только в Linux)
#ifdef __linux__
    manage_interface_promisc_mode(interface, 1);
    logger << log4cpp::Priority::WARN
           << "Please disable all types of offload for"
           << "this NIC manually: ethtool -K "
           << interface
           << " gro off gso off tso off lro off";
#endif  /* __linux__ */

    // Основной объект io_service, используется для отлова
    // сигналов и работы сервера controld.
    boost::asio::io_service io_s;

    // Ловим сигналы  SIGINT, SIGTERM для завершения программы.
    boost::asio::signal_set signals(io_s, SIGINT, SIGTERM);
    signals.async_wait(boost::bind(&boost::asio::io_service::stop, &io_s));

    // Лист потоков. В этот лист буду добавляться все потоки программы,
    // для отслеживания состояния и корректного прерывания
    boost::thread_group threads;

    // Вектор указателей на листы правил. С каждым отдельным листом
    // правил работает один поток. Каждый лист синхронизируется потоком
    // watcher с эталонным листом main_collect.
    std::vector<std::shared_ptr<RulesCollection>> threads_coll;

    // Эталонная колекция правил, по ней будут ровняться все потоки
    auto main_collect = std::make_shared<RulesCollection>(help_opt,
                                                      tcp_rule_opt,
                                                      udp_rule_opt,
                                                      icmp_rule_opt);

    // Очередь заданий для сработавших триггеров
    auto  task_list = std::make_shared<ts_queue<action::TriggerJob>>();

    // Загрузка конфигурации из файла если он существует
    if(is_file_exist(config_file))
    {
        logger.info("Load configuration file " + config_file);
        // TODO: чтение настроек с конфига
    }

    // Загрузка правил из файла
    /*
        RulesFileLoader загружает текущий конфиг из файла при инициализации, а
        также устанавливает новый signal_set для перехвата SIGHUP и обновления
        конфига. Каждый раз при попытке перезагрузить файл правил, выполняется
        проверка на существование файла. Сигнал привязывается также к основному
        io_service.
    */
    RulesFileLoader rul_loader(io_s, rules_file, main_collect);
    try
    {
        // читаем конфиг в первый раз и привязываем сигнал
        rul_loader.start();
    }
    catch(std::exception& e)
    {
        logger << log4cpp::Priority::CRIT << "Rules file loader failed: " << e.what();
        return 1;
    }
    /*
        Старт netmap интерфейса и запуск потоков обрабатывающих очереди сетевой
        карты. Класс заполняет вектор листов правил (threads_coll) по мере
        создания потоков привязанных к очередям сетевой карты.
    */
    NetmapReceiver nm_recv(interface, threads, threads_coll, *main_collect);
    try
    {
        // подключаемся к драйверу netmap, запускаем потоки-получатели пакетов
        nm_recv.start();
    }
    catch(NetmapException& e)
    {
        logger << log4cpp::Priority::CRIT << "Netmap failed: " << e.what();
        return 1;
    }

    // старт потока наблюдателя
    threads.add_thread(new boost::thread(watcher, std::ref(threads_coll),
                                         main_collect, task_list));
    logger.info("Start watcher thread");

    // старт TCP сервера управления
    threads.add_thread(new boost::thread(start_control,
                                         std::ref(io_s), port, main_collect));

    // старт обработчика заданий триггеров
    threads.add_thread(new boost::thread(task_runner, task_list));
    logger.info("Starting runner thread");

    // Ждем сигналы и подключения к TCP/UNIX серверу
    try
    {
        io_s.run();
    }
    catch(std::exception& e)
    {
        logger << log4cpp::Priority::ERROR << "Signal handler error: " << e.what();
    }

    // Пойман сигнал завершения.
    // Завершение всех потоков
    threads.interrupt_all();
    logger.info("Waiting threads.....");
    // Ожидаем корректное завершение всех потоков и служб
    threads.join_all();

    return 0;
}
