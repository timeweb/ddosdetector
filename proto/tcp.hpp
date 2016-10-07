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
    // текстовое представление TCP флагов в правильном порядке, для
    // парсинга правил
    const std::vector<char> accept_tcp_flags = { 'U', 'A', 'P', 'R', 'S', 'F' };
}

/*
 Класс TCP флагов, позволяет производить сравнение всех флагов (bits_) сразу с
 использованием маски (mask_)
*/
class tcp_flags
{
public:
    tcp_flags();
    tcp_flags(const std::pair<std::bitset<6>, std::bitset<6>>& flags);
    bool operator==(const tcp_flags& other) const;
    // сравнение битов flags с параметром bits_ по маске mask_
    bool in_this(const std::bitset<6>& flags) const;

    bool enable;
private:
    // биты флагов
    std::bitset<6> bits_;
    // маска сравнения
    std::bitset<6> mask_;
};

/*
 Класс TCP правил. Содержит проверяемые параметры пакета и также стандартный
 набор методов для proto-класса.
*/
class TcpRule : public Ipv4Rule, public BaseRule
{
public:
    TcpRule();
    explicit TcpRule(const std::vector<std::string>& tkn_rule);
    bool operator==(const TcpRule& other) const;
    TcpRule& operator+=(TcpRule& other);
    // парсинг текстового представления правила по правилам opt
    void parse(const boost::program_options::options_description& opt);
    // проверка L4 заголовка пакета на совпадение с правилом
    bool check_packet(const struct tcphdr *tcp_hdr,
                      const uint32_t s_addr,
                      const uint32_t d_addr) const;

    // Source port 
    NumRange<uint16_t> src_port;
    // Destination port
    NumRange<uint16_t> dst_port;
    // Sequence number
    NumComparable<uint32_t> seq;
    // Acknowledge number
    NumComparable<uint32_t> ack_seq;
    // Window size
    NumComparable<uint16_t> win;
    // Length TCP packet
    NumComparable<uint16_t> len;
    // TCP flags
    tcp_flags flags;
};

#endif // end TCP_HPP