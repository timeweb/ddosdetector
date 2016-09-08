#ifndef COLLECTOR_HPP
#define COLLECTOR_HPP

#include <stdio.h>
#include <iostream>

#include <sys/types.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <sys/sysctl.h>


// Logging
#include "log4cpp/Category.hh"
#include "log4cpp/Priority.hh"

#define NETMAP_WITH_LIBS
#define NETMAP_NO_DEBUG // Disable debug messages from Netmap
#include <net/netmap_user.h>
#include <boost/thread.hpp>
#include <boost/algorithm/string/replace.hpp>

#include "rules.hpp"
#include "exceptions.hpp"
#include "functions.hpp"

// Get log4cpp logger from main programm
extern log4cpp::Category& logger;

/*
 Класс-обработчик данных в одной очереди/потоке.
 Содержит объекты с которыми работает один поток. 
*/
class NetmapPoller
{
public:
    explicit NetmapPoller(const struct nm_desc* nmd);
    bool try_poll();
private:
    // поллер для определения поступления данных
    struct pollfd fds_;
    // кольцевая очередь с которой работает этот экземпляр поллера
    struct netmap_ring* rxring_;
};

/*
 Класс запускающий процесс получения и обработки пакетов.
 @param interface: сетевой интерфейс на котором запускается процесс
 @param threads: ссылка на список потоков, в него добавляются потоки-обработчики
                 пакетов
 @param rules: вектор коллекций правил, в него добавляются коллекции созданные
               для каждого отдельного потока. В дальнейшем этот вектор будет
               обрабытываться потоком watcher.
 @param collection: эталонная коллекция, с которой копируются потоковые
                    колекции, чтобы потоковые коллекции создались с необходимыми
                    параметрами.
*/
class NetmapReceiver
{
public:
    NetmapReceiver(const std::string interface,
                   boost::thread_group& threads,
                   std::vector<std::shared_ptr<RulesCollection>>& rules,
                   const RulesCollection& collection);
    // создание потоков-обработчиков, заполненеи vector rules
    void start();
private:
    /*
     фукнция обработки пакета
     @param packet: данные пакета начиная с Ethernet заголовка
     @param collect: коллекция, по правилам которой пакет будет проверяться
     @param len: длинна пакета (в байтах)
    */
    static bool check_packet(const u_char *packet,
                             std::shared_ptr<RulesCollection>& collect,
                             const unsigned int len);
    // функция-обработчик запускаемая в потоке
    void netmap_thread(struct nm_desc* netmap_descriptor,
                       int thread_number,
                       std::shared_ptr<RulesCollection> collect);

    // сетевой интерфейс на котором запускается процесс обработки пакетов
    std::string intf_;
    // netmap-имя интерфейса для запуска функций драйвера
    std::string netmap_intf_;
    // количество доступных ядер процессора
    int num_cpus_;
    // ссылка на список потоков программы
    boost::thread_group& threads_;
    // вектор коллекций правил
    std::vector<std::shared_ptr<RulesCollection>>& threads_rules_;
    // эталонная коллекция, с которой копируются все остальные
    RulesCollection main_collect_;
};

#endif // end COLLECTOR_HPP