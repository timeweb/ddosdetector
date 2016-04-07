#ifndef TCP_HPP
#define TCP_HPP

#include <iostream>
#include <vector>
#include <bitset>

#include <boost/program_options.hpp>

#include <netinet/tcp.h>

#include "baserule.hpp"
#include "ip.hpp"

namespace tcprule
{
    const std::vector<char> accept_tcp_flags = { 'U', 'A', 'P', 'R', 'S', 'F' };
}

class tcp_flags
{
public:
    bool enable;

    tcp_flags();
    tcp_flags(std::pair<std::bitset<6>, std::bitset<6>> flags);
    bool in_this(const std::bitset<6>& flags) const;
    bool operator==(tcp_flags const & other) const;
private:
    std::bitset<6> bits_;
    std::bitset<6> mask_;
};

class TcpRule : public Ipv4Rule, public BaseRule
{
public:
    NumRange<uint16_t> src_port;
    NumRange<uint16_t> dst_port;
    NumComparable<uint32_t> seq;
    NumComparable<uint32_t> ack_seq;
    NumComparable<uint16_t> win;
    NumComparable<uint16_t> len;
    tcp_flags flags;
    TcpRule();
    explicit TcpRule(std::vector<std::string> tkn_rule);
    void parse(boost::program_options::options_description& opt);
    bool check_packet(struct tcphdr *tcp_hdr, uint32_t s_addr, uint32_t d_addr) const;
    bool operator==(TcpRule const & other) const;
    TcpRule& operator+=(TcpRule& other);
    std::string make_info();
};

#endif // end TCP_HPP