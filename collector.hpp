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
//#define DEBUG_NETMAP_USER // Detail debugging
#include <net/netmap_user.h>
#include <boost/thread.hpp>
#include <boost/algorithm/string/replace.hpp>

#include "rules.hpp"
#include "exceptions.hpp"
#include "functions.hpp"

// Get log4cpp logger from main programm
extern log4cpp::Category& logger;

/*
 Handler class data in a single queue / thread.
 Contains objects it works with a single thread.
*/
class NetmapPoller
{
public:
    explicit NetmapPoller(const struct nm_desc* nmd);
    bool try_poll();
    u_char* get_buff_from_ring();
    void set_forward();
    void next();
    ~NetmapPoller();

    unsigned int buff_len;
private:
    struct pollfd fds_;
    unsigned int cur_slot_id_;
    struct netmap_ring* rxring_;

};

/*
Class starts the process of receiving and processing packets.
@param interface: the network interface on which you start the process
@param threads: a reference to a list of threads
@param rules: vector collection of rules, it added to the collection by
              for each thread. This vector is synchronized in watcher thread.
@param collection: reference collection, which are copied to the streaming
                   Collections to stream collection is created with the necessary
                   parameters.
*/
class NetmapReceiver
{
public:
    NetmapReceiver(const std::string interface,
                   boost::thread_group& threads,
                   std::vector<std::shared_ptr<RulesCollection>>& rules,
                   const RulesCollection& collection);
    // creating handler threads, filling vector rules
    void start();
private:
    /*
     packet processing function
     @param packet: packet data since the Ethernet header
     @param collect: collection, according to the rules which the package will be checked
     @param len: the length of the packet (in bytes)
    */
    static bool check_packet(const u_char *packet,
                             std::shared_ptr<RulesCollection>& collect,
                             const unsigned int len);
    // handler function is triggered in the stream
    void netmap_thread(struct nm_desc* netmap_descriptor,
                       int thread_number,
                       std::shared_ptr<RulesCollection> collect);

    // network interface that runs packet processing
    std::string intf_;
    // netmap-interface name to start driver functions
    std::string netmap_intf_;
    // the number of available processor cores
    int num_cpus_;
    // link to a list of program streams
    boost::thread_group& threads_;
    // vector collection rules
    std::vector<std::shared_ptr<RulesCollection>>& threads_rules_;
    // reference collection from which all other copies
    RulesCollection main_collect_;
};

#endif // end COLLECTOR_HPP
