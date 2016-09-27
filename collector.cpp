#include "collector.hpp"

// Get log4cpp logger from main programm
extern log4cpp::Category& logger;


NetmapPoller::NetmapPoller(const struct nm_desc* nmd)
    : buff_len(0), fds_{nmd->fd, POLLIN}, cur_slot_id_(0),
    rxring_(NETMAP_RXRING(nmd->nifp, nmd->first_rx_ring)) {}
bool NetmapPoller::try_poll()
{
    int poll_result = poll(&fds_, 1, 1000);
    if (poll_result == 0) {
        return false;
    }
    if (poll_result == -1) {
        throw NetmapException("Netmap plugin: poll failed with return code -1");
    }
    return true;
}
u_char* NetmapPoller::get_buff_from_ring()
{
    rxring_->flags |= NR_FORWARD;
    rxring_->flags |= NR_TIMESTAMP;
    if (nm_ring_empty(rxring_)) {
        return NULL;
    }
    cur_slot_id_ = rxring_->cur;
    // Get packet data
    u_int idx = rxring_->slot[cur_slot_id_].buf_idx;
    buff_len = rxring_->slot[cur_slot_id_].len;
    return (u_char *)NETMAP_BUF(rxring_, idx);
}
void NetmapPoller::set_forward()
{
    rxring_->slot[cur_slot_id_].flags |= NS_FORWARD;
}
void NetmapPoller::next()
{
    rxring_->cur = nm_ring_next(rxring_, cur_slot_id_);
    rxring_->head = rxring_->cur;
}
NetmapPoller::~NetmapPoller()
{
    rxring_ = NULL;
    delete rxring_;
}

bool NetmapReceiver::check_packet(const u_char *packet,
    std::shared_ptr<RulesCollection>& collect, const unsigned int len)
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
        struct tcphdr *tcp_hdr = (struct tcphdr*) (packet +
                                                   sizeof(struct ether_header) +
                                                   size_ip);
        return collect->tcp.check_list(tcp_hdr,
                                       ntohl(ip_hdr->ip_src.s_addr),
                                       ntohl(ip_hdr->ip_dst.s_addr),
                                       len);
    }
    if (ip_hdr->ip_p == IPPROTO_UDP) {
        // UDP Header
        struct udphdr *udp_hdr = (struct udphdr*) (packet +
                                                   sizeof(struct ether_header) +
                                                   size_ip);
        return collect->udp.check_list(udp_hdr,
                                       ntohl(ip_hdr->ip_src.s_addr),
                                       ntohl(ip_hdr->ip_dst.s_addr),
                                       len);
    }
    if (ip_hdr->ip_p == IPPROTO_ICMP) {
        // ICMP Header
        struct icmphdr *icmp_hdr = (struct icmphdr*) (packet +
                                                      sizeof(struct ether_header) +
                                                      size_ip);
        return collect->icmp.check_list(icmp_hdr,
                                        ntohl(ip_hdr->ip_src.s_addr),
                                        ntohl(ip_hdr->ip_dst.s_addr),
                                        len);
    }
    return false;
}

void NetmapReceiver::netmap_thread(struct nm_desc* nm_descr, int thread_number,
    std::shared_ptr<RulesCollection> collect)
{
    u_char* buf;

    logger.debug("Reading from fd %d thread id: %d", nm_descr->fd, thread_number);
    NetmapPoller poller(nm_descr);
    try
    {
        for (;;)
        {   // Проверям был ли прерван поток
            boost::this_thread::interruption_point(); 
            // ждем 1000 микросекунд и проверяем появились ли данные
            if(poller.try_poll())
            {
                // получаем данные пакетов
                while( (buf = poller.get_buff_from_ring()) )
                {
                    // если пакет подпадает под правило, то перерасываем его
                    // в host stack для ОС
                    if(check_packet(buf, collect, poller.buff_len))
                    {
                        // в host stack перебрасываем только пакеты из ring 0
                        // (thread id 0), так как функционал netmap: NS_FORWARD
                        // не потокобезопасен, и в противном случае течет память
                        // для мониторинга и дампов достаточно проброса пакетов
                        // только из одной очереди
                        if(thread_number == 0)
                        {
                            poller.set_forward();
                        }
                    }
                    poller.next();
                }
            }
        }
    }
    catch(...)
    {
        nm_close(nm_descr);
        logger.debug("Thread %d closed", thread_number);
    }
}

NetmapReceiver::NetmapReceiver(std::string interface, boost::thread_group& threads,
    std::vector<std::shared_ptr<RulesCollection>>& rules,
    const RulesCollection& collection)
    : intf_(interface), threads_(threads), threads_rules_(rules),
    main_collect_(collection)
{
    netmap_intf_ = get_netmap_intf(intf_);
#if defined (__FreeBSD__)
    int mib[2] = { CTL_HW, HW_NCPU };
    size_t len = sizeof(mib);
    sysctl(mib, 2, &num_cpus_, &len, NULL, 0);
#elif defined(__linux__)
    /*
      количество ядер в системе (чтобы привязать каждую очередь
      сетевой карты к отдельному ядру).
      TODO: проверить std::thread::hardware_concurrency() верней?
    */
    num_cpus_ = sysconf(_SC_NPROCESSORS_ONLN);
#else /* others */
    num_cpus_ = 1;
#endif
    logger.info("We have %d cpus", num_cpus_);
}

void NetmapReceiver::start()
{
    struct nm_desc* main_nmd;
    struct nmreq base_nmd;
    bzero(&base_nmd, sizeof(base_nmd));

    // Magic from pkt-gen.c
    base_nmd.nr_tx_rings = base_nmd.nr_rx_rings = 0;
    base_nmd.nr_tx_slots = base_nmd.nr_rx_slots = 0;

    main_nmd = nm_open(netmap_intf_.c_str(), &base_nmd, 0, NULL);

    if (main_nmd == NULL) {
        throw NetmapException("open netmap interface '" + netmap_intf_ + "' failed.");
    }

    logger.debug("Mapped %dKB memory at %p", main_nmd->req.nr_memsize >> 10, main_nmd->mem);
    logger.debug("We have %d tx and %d rx rings", main_nmd->req.nr_tx_rings,
        main_nmd->req.nr_rx_rings);

    int num_rings = main_nmd->req.nr_rx_rings;
    if (num_rings > num_cpus_)
    {
        logger.warn("number of ring queues (%d) greater than the number of processor cores (%d), the collector may not work best", num_rings, num_cpus_);
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
        auto r_ptr = std::make_shared<RulesCollection>(main_collect_);
        threads_rules_.push_back(r_ptr);

        struct nm_desc nmd = *main_nmd;
        // This operation is VERY important!
        nmd.self = &nmd;

        nmd.req.nr_flags = NR_REG_ONE_NIC/* | NR_MONITOR_TX | NR_MONITOR_RX*/;
        nmd.req.nr_ringid = i;

        struct nm_desc* new_nmd =
            nm_open(netmap_intf_.c_str(), NULL, nmd_flags | NM_OPEN_IFNAME | NM_OPEN_NO_MMAP, &nmd);

        if (new_nmd == NULL) {
            throw NetmapException("open netmap interface '" + netmap_intf_ + "' failed.");
        }
        threads_.add_thread(new boost::thread(&NetmapReceiver::netmap_thread, this, new_nmd, i, r_ptr));
    }

    logger.debug("Start %d receive on interface %s", num_cpus_, netmap_intf_.c_str());
}
