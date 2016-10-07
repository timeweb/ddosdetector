#ifndef ICMP_HPP
#define ICMP_HPP

#include <iostream>
#include <vector>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/ip.h>

#include <boost/program_options.hpp>

#include <netinet/ip_icmp.h>

#include "baserule.hpp"
#include "ip.hpp"

/*
 Класс ICMP правил. Содержит проверяемые параметры пакета и также стандартный
 набор методов для proto-класса.
*/
class IcmpRule : public Ipv4Rule, public BaseRule
{
public:
    IcmpRule();
    explicit IcmpRule(const std::vector<std::string>& tkn_rule);
    bool operator==(const IcmpRule& other) const;
    IcmpRule& operator+=(IcmpRule& other);
    // парсинг текстового представления правила по правилам opt
    void parse(const boost::program_options::options_description& opt);
    // проверка L4 заголовка пакета на совпадение с правилом
    bool check_packet(const struct icmphdr *icmp_hdr,
                      const uint32_t s_addr,
                      const uint32_t d_addr) const;

    // ICMP packet type
    NumComparable<uint8_t> type;
    // ICMP packet code
    NumComparable<uint8_t> code;
};

#endif // end ICMP_HPP