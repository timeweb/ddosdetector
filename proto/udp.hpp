#ifndef UDP_HPP
#define UDP_HPP

#include <iostream>
#include <vector>

#include <boost/program_options.hpp>

#include <netinet/udp.h>

#include "baserule.hpp"
#include "ip.hpp"

class UdpRule : public Ipv4Rule, public BaseRule
{
public:
    NumRange<uint16_t> src_port;
    NumRange<uint16_t> dst_port;
    NumComparable<uint16_t> len;
    UdpRule();
    explicit UdpRule(std::vector<std::string> tkn_rule);
    void parse(boost::program_options::options_description& opt);
    bool check_packet(struct udphdr *udp_hdr, uint32_t s_addr, uint32_t d_addr) const;
    bool operator==(UdpRule const & other) const;
    UdpRule& operator+=(UdpRule& other);
    std::string make_info();
};

#endif // end UDP_HPP