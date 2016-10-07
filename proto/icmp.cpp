#include "icmp.hpp"

// class IcmpRule

IcmpRule::IcmpRule()
    : Ipv4Rule(6), BaseRule() {}
IcmpRule::IcmpRule(const std::vector<std::string>& tkn_rule)
    : Ipv4Rule(6), BaseRule(tkn_rule) {}
void IcmpRule::parse(const boost::program_options::options_description& opt)
{
    rule_type = "icmp";
    parser::CommandParser cp(opt);
    boost::program_options::variables_map vm = cp.parse(tokenize_rule);
    // store text rule
    text_rule = cp.join(tokenize_rule);
    // parse L3 header
    ip_header_parse(vm);
    // parse rule options
    BaseRule_parse(vm);
    // parse L4 header
    if (vm.count("type")) {
        type = parser::numcomp_from_string<uint8_t>(vm["type"].as<std::string>());
    }
    if (vm.count("code")) {
        code = parser::numcomp_from_string<uint8_t>(vm["code"].as<std::string>());
    }
}
bool IcmpRule::check_packet(const struct icmphdr *icmp_hdr,
    const uint32_t s_addr, const uint32_t d_addr) const
{
    // L3 header check
    if(!ip_src.in_this(s_addr)) // check source ip address
        return false;
    if(!ip_dst.in_this(d_addr)) // check destination ip address
        return false;
    // L4 header check
#if defined (__FreeBSD__)
    uint8_t h_type = icmp_hdr->icmp_type;
#elif defined (__linux__)
    uint8_t h_type = icmp_hdr->type;
#endif
    if(!type.in_this(h_type))
        return false;
#if defined (__FreeBSD__)
    uint8_t h_code = icmp_hdr->icmp_code;
#elif defined (__linux__)
    uint8_t h_code = icmp_hdr->code;
#endif
    if(!code.in_this(h_code))
        return false;

    // std::cout << "\n\n== IP HEADER ==";
    // std::cout << "\nSource IP: " << boost::asio::ip::address_v4(s_addr).to_string();
    // std::cout << "\nDestination IP: " << boost::asio::ip::address_v4(d_addr).to_string();
    // // TCP Header
    // std::cout << "\n== ICMP HEADER ==";
    // std::cout << "\nType: " << std::bitset<8>(h_type);
    // std::cout << "\nCode: " << std::bitset<8>(h_code);

    return true;
}
bool IcmpRule::operator==(IcmpRule const & other) const
{
    return (ip_src == other.ip_src
        && ip_dst == other.ip_dst
        && next_rule == other.next_rule
        && pps_trigger == other.pps_trigger
        && bps_trigger == other.bps_trigger
        && pps_trigger_period == other.pps_trigger_period
        && bps_trigger_period == other.bps_trigger_period
        && type == other.type
        && code == other.code);
}
IcmpRule& IcmpRule::operator+=( IcmpRule& other)
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