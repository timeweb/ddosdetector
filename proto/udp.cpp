#include "udp.hpp"

// class UdpRule

UdpRule::UdpRule()
    : Ipv4Rule(6), BaseRule() {}
UdpRule::UdpRule(const std::vector<std::string>& tkn_rule)
    : Ipv4Rule(6), BaseRule(tkn_rule) {}
void UdpRule::parse(const boost::program_options::options_description& opt)
{
    rule_type = "udp";
    parser::CommandParser cp(opt);
    boost::program_options::variables_map vm = cp.parse(tokenize_rule);
    // store text rule
    text_rule = cp.join(tokenize_rule);
    // parse L3 header
    ip_header_parse(vm);
    // parse rule options
    BaseRule_parse(vm);
    // parse L4 header
    if (vm.count("sport")) {
        src_port = parser::range_from_port_string(vm["sport"].as<std::string>());
    }
    if (vm.count("dport")) {
        dst_port = parser::range_from_port_string(vm["dport"].as<std::string>());
    }
    if (vm.count("hlen")) {
        len = parser::numcomp_from_string<uint16_t>(vm["hlen"].as<std::string>());
    }
}
bool UdpRule::check_packet(const struct udphdr *udp_hdr,
                           const uint32_t s_addr, const uint32_t d_addr) const
{
    // L3 header check
    if(!ip_src.in_this(s_addr)) // check source ip address
        return false;
    if(!ip_dst.in_this(d_addr)) // check destination ip address
        return false;
    // L4 header check
#if defined (__FreeBSD__)
    uint16_t h_sport = ntohs(udp_hdr->uh_sport);
#elif defined (__linux__)
    uint16_t h_sport = ntohs(udp_hdr->source);
#endif
    if(!src_port.in_this(h_sport))
        return false;
#if defined (__FreeBSD__)
    uint16_t h_dport = ntohs(udp_hdr->uh_dport);
#elif defined (__linux__)
    uint16_t h_dport = ntohs(udp_hdr->dest);
#endif
    if(!dst_port.in_this(h_dport))
        return false;
#if defined (__FreeBSD__)
    uint16_t h_len = udp_hdr->uh_ulen;
#elif defined (__linux__)
    uint16_t h_len = udp_hdr->len;
#endif
    if(!len.in_this(h_len))
        return false;

    // std::cout << "\n\n== IP HEADER ==";
    // std::cout << "\nSource IP: " << boost::asio::ip::address_v4(s_addr).to_string();
    // std::cout << "\nDestination IP: " << boost::asio::ip::address_v4(d_addr).to_string();
    // // TCP Header
    // std::cout << "\n== UDP HEADER ==";
    // std::cout << "\nSource Port: " << std::dec << h_sport;
    // std::cout << "\nDestination Port: " << std::dec << h_dport;
    // std::cout << "\nHeader lenght: " << h_len;
    // std::cout << "\nChecksum: " << std::hex << ntohs(udp_hdr->check);

    return true;
}
bool UdpRule::operator==(UdpRule const & other) const
{
    return (src_port == other.src_port
        && dst_port == other.dst_port
        && ip_src == other.ip_src
        && ip_dst == other.ip_dst
        && next_rule == other.next_rule
        && pps_trigger == other.pps_trigger
        && bps_trigger == other.bps_trigger
        && pps_trigger_period == other.pps_trigger_period
        && bps_trigger_period == other.bps_trigger_period
        && len == other.len);
}
UdpRule& UdpRule::operator+=( UdpRule& other)
{
    if (this != &other)
    {
        count_packets += other.count_packets;
        count_bytes += other.count_bytes;
        dst_top += other.dst_top;
        // сбрасываем счетчик у исходного правила
        other.count_packets = 0; 
        other.count_bytes = 0;
    }
    return *this;
}