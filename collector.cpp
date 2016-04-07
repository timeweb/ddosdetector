#include "collector.hpp"

// Get log4cpp logger from main programm
extern log4cpp::Category& logger;


netmap_poller::netmap_poller(struct nm_desc* nmd)
	: fds{nmd->fd, POLLIN}, nifp(nmd->nifp), rxring(NETMAP_RXRING(nmd->nifp, 0)) {}
bool netmap_poller::try_poll()
{
	int poll_result = poll(&fds, 1, 1000);
	if (poll_result == 0) {
		return false;
	}
	if (poll_result == -1) {
		throw netmap::exception("Netmap plugin: poll failed with return code -1");
	}
	return true;
}
// bool netmap_poller::check_ring(int ring_id)
// {
// 	rxring = NETMAP_RXRING(nifp, ring_id);
// 	if (nm_ring_empty(rxring)) {
// 		return false;
// 	}
// 	return true;
// }
// struct netmap_ring* netmap_poller::get_ring()
// {
// 	return rxring;
// }


bool netmap_receiver::check_packet(const u_char *packet, std::shared_ptr<rcollection>& collect, unsigned int len)
{
	// Decode Packet Header

	// Ethernet header
	struct ether_header *eth_header = (struct ether_header *) packet;
	if (eth_header->ether_type != htons(ETHERTYPE_IP)) {
		return false; // pass non-ip packet
	}

	// IP header
	struct ip *ip_hdr = (struct ip *) (packet + sizeof(struct ether_header));
	int size_ip = ip_hdr->ip_hl * 4;

	// DEBUG
	// std::cout << "\n\n== IP HEADER ==";
	// std::cout << "\nIP Version: " << ip_header.ihl();
	// std::cout << "\nHeader Length: " << std::dec << size_ip;
	// std::cout << "\nTotal Length: " << std::dec << ntohs(ip_hdr->ip_len);
	// std::cout << "\nSource IP: " << boost::asio::ip::address_v4(ip_hdr.ip_src.s_addr).to_string();
	// std::cout << "\nDestination IP: " << boost::asio::ip::address_v4(ip_hdr.ip_dst.s_addr).to_string();
	// std::cout << "\nProtocol: " << (int)ip_hdr->ip_p;

	if (ip_hdr->ip_p == IPPROTO_TCP) {
		// TCP Header
		struct tcphdr *tcp_hdr = (struct tcphdr*) (packet + sizeof(struct ether_header) + size_ip);
		collect->tcp.check_list(tcp_hdr, ntohl(ip_hdr->ip_src.s_addr), ntohl(ip_hdr->ip_dst.s_addr), len);
		return true;
	}
	if (ip_hdr->ip_p == IPPROTO_UDP) {
		// UDP Header
		struct udphdr *udp_hdr = (struct udphdr*) (packet + sizeof(struct ether_header) + size_ip);
		collect->udp.check_list(udp_hdr, ntohl(ip_hdr->ip_src.s_addr), ntohl(ip_hdr->ip_dst.s_addr), len);
		return true;
	}
	if (ip_hdr->ip_p == IPPROTO_ICMP) {
		// ICMP Header
		struct icmphdr *icmp_hdr = (struct icmphdr*) (packet + sizeof(struct ether_header) + size_ip);
		collect->icmp.check_list(icmp_hdr, ntohl(ip_hdr->ip_src.s_addr), ntohl(ip_hdr->ip_dst.s_addr), len);
		return true;
	}
	return false;
}

void netmap_receiver::netmap_thread(struct nm_desc* netmap_descriptor, int thread_number,
	std::shared_ptr<rcollection> collect)
{
	struct nm_pkthdr h;
	u_char* buf;

	logger.debug("Reading from fd %d thread id: %d", netmap_descriptor->fd, thread_number);

	netmap_poller poller(netmap_descriptor);
	try
	{
		for (;;)
		{	
			boost::this_thread::interruption_point(); // Проверям был ли прерван поток
			// We will wait 1000 microseconds for retry, for infinite timeout please use -1
			if(poller.try_poll())
			{
				while ( (buf = nm_nextpkt(netmap_descriptor, &h)) ) {
					check_packet(buf, collect, h.len);
				}
			}
		}
	}
	catch(...)
	{
		nm_close(netmap_descriptor);
		logger.debug("Thread %d closed", thread_number);
	}
}

netmap_receiver::netmap_receiver(std::string interface, boost::thread_group& threads,
	std::vector<std::shared_ptr<rcollection>>& rules,
	rcollection collection)
	: intf(interface), nm_rcv_threads(threads), threads_rules(rules), main_collect(collection)
{
	netmap_intf = get_netmap_intf(intf);
	/*
	  количество ядер в системе (чтобы привязать каждую очередь
	  сетевой карты к отдельному ядру).
	  TODO: проверить std::thread::hardware_concurrency() верней?
	*/
	num_cpus = sysconf(_SC_NPROCESSORS_ONLN);
	logger.info("We have %d cpus", num_cpus);
}

void netmap_receiver::start()
{
	struct nm_desc* main_nmd;
	struct nmreq base_nmd;
	bzero(&base_nmd, sizeof(base_nmd));

	// Magic from pkt-gen.c
	base_nmd.nr_tx_rings = base_nmd.nr_rx_rings = 0;
	base_nmd.nr_tx_slots = base_nmd.nr_rx_slots = 0;

	main_nmd = nm_open(netmap_intf.c_str(), &base_nmd, 0, NULL);

	if (main_nmd == NULL) {
		throw netmap::exception("open netmap interface '" + netmap_intf + "' failed.");
	}

	logger.debug("Mapped %dKB memory at %p", main_nmd->req.nr_memsize >> 10, main_nmd->mem);
	logger.debug("We have %d tx and %d rx rings", main_nmd->req.nr_tx_rings,
		main_nmd->req.nr_rx_rings);

	int num_rings = main_nmd->req.nr_rx_rings;
	if (num_rings > num_cpus)
	{
		logger.warn("number of ring queues (%d) greater than the number of processor cores (%d), the collector may not work best", num_rings, num_cpus);
	}
	/*
		переключение сетевой карты на работу с драйвером
		netmap требует времени (сетевая карта сбрасывается),
		ждем 2 секунды.
	*/
	int wait_link = 2;
	logger.info("Wait %d seconds for NIC reset", wait_link);
	sleep(wait_link);

	uint64_t nmd_flags = 0;
	nmd_flags |= NETMAP_NO_TX_POLL; // отключить очереди отправки пакетов

	for (int i = 0; i < num_rings; i++) {
		auto r_ptr = std::make_shared<rcollection>(main_collect);
		threads_rules.push_back(r_ptr);

		struct nm_desc nmd = *main_nmd;
		// This operation is VERY important!
		nmd.self = &nmd;

		nmd.req.nr_flags = NR_REG_ONE_NIC/* | NR_MONITOR_TX | NR_MONITOR_RX*/;
		nmd.req.nr_ringid = i;

		struct nm_desc* new_nmd =
			nm_open(netmap_intf.c_str(), NULL, nmd_flags | NM_OPEN_IFNAME | NM_OPEN_NO_MMAP, &nmd);

		if (new_nmd == NULL) {
			throw netmap::exception("open netmap interface '" + netmap_intf + "' failed.");
		}
		nm_rcv_threads.add_thread(new boost::thread(&netmap_receiver::netmap_thread, this, new_nmd, i, r_ptr));
	}

	logger.debug("Start %d receive on interface %s", num_cpus, netmap_intf.c_str());
}