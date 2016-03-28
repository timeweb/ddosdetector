#ifndef COLLECTOR_HPP
#define COLLECTOR_HPP

#include <stdio.h>
#include <iostream>

#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>

// Logging
#include "log4cpp/Category.hh"
#include "log4cpp/Priority.hh"

#define NETMAP_WITH_LIBS
//#define NETMAP_NO_DEBUG // Disable debug messages from Netmap
#include <net/netmap_user.h>
#include <boost/thread.hpp>
#include <boost/algorithm/string/replace.hpp>

#include "rules.hpp"
#include "exceptions.hpp"
#include "functions.hpp"

// Get log4cpp logger from main programm
extern log4cpp::Category& logger;

class netmap_poller
{
private:
	struct pollfd fds;
	struct netmap_if* nifp;
	struct netmap_ring* rxring;
public:
	explicit netmap_poller(struct nm_desc* nmd);
	bool try_poll();
	bool check_ring(int ring_id);
	struct netmap_ring* get_ring();
};

class netmap_receiver
{
private:
	std::string intf;
	std::string netmap_intf;
	int num_cpus;
	boost::thread_group& nm_rcv_threads;
	std::vector<std::shared_ptr<rcollection>>& threads_rules;
	rcollection main_collect;
	static bool check_packet(const u_char *packet, std::shared_ptr<rcollection>& collect, unsigned int len);
	void netmap_thread(struct nm_desc* netmap_descriptor, int thread_number, std::shared_ptr<rcollection> collect);
public:
	netmap_receiver(std::string interface, boost::thread_group& threads,
		std::vector<std::shared_ptr<rcollection>>& rules, rcollection collection);
	void start();
};

#endif // end COLLECTOR_HPP