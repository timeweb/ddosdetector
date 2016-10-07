#ifndef UDP_HPP
#define UDP_HPP

#include <iostream>
#include <vector>

#include <boost/program_options.hpp>

#include <netinet/udp.h>

#include "baserule.hpp"
#include "ip.hpp"

/*
 Класс ICMP правил. Содержит проверяемые параметры пакета и также стандартный
 набор методов для proto-класса.
*/
class UdpRule : public Ipv4Rule, public BaseRule
{
public:
    UdpRule();
    explicit UdpRule(const std::vector<std::string>& tkn_rule);
    bool operator==(const UdpRule& other) const;
    UdpRule& operator+=(UdpRule& other);
    // парсинг текстового представления правила по правилам opt
    void parse(const boost::program_options::options_description& opt);
    // проверка L4 заголовка пакета на совпадение с правилом
    bool check_packet(const struct udphdr *udp_hdr,
                      const uint32_t s_addr,
                      const uint32_t d_addr) const;

    // Source port
    NumRange<uint16_t> src_port;
    // Destination port
    NumRange<uint16_t> dst_port;
    // UDP packet length
    NumComparable<uint16_t> len;
};

#endif // end UDP_HPP