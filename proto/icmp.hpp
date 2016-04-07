#ifndef ICMP_HPP
#define ICMP_HPP

#include <iostream>
#include <vector>

#include <boost/program_options.hpp>

#include <netinet/ip_icmp.h>

#include "baserule.hpp"
#include "ip.hpp"

class IcmpRule : public Ipv4Rule, public BaseRule
{
public:
    NumComparable<uint8_t> type;
    NumComparable<uint8_t> code;
    IcmpRule();
    explicit IcmpRule(std::vector<std::string> tkn_rule);
    void parse(boost::program_options::options_description& opt);
    bool check_packet(struct icmphdr *icmp_hdr, uint32_t s_addr, uint32_t d_addr) const;
    bool operator==(IcmpRule const & other) const;
    IcmpRule& operator+=(IcmpRule& other);
    std::string make_info();
};

#endif // end ICMP_HPP