#ifndef IP_HPP
#define IP_HPP

#include <iostream>
#include <vector>

#include <boost/program_options.hpp>
#include <boost/asio/ip/address.hpp>

#include "../action.hpp"
#include "../parser.hpp"
#include "baserule.hpp"

/*
 Класс параметров IPv4 заголовка
*/
class Ipv4Rule
{
public:
    uint8_t ver_ihl;            // IP header length and IP packet version
    uint8_t tos;                // type of service
    uint16_t length;            // total length in bytes
    uint16_t identification;    // ID
    uint16_t flag_offset;       // fragment offset and flags
    uint8_t ttl;                // time to live
    uint8_t protocol;           // ip protocol type
    uint16_t checksum;          // Checksumm
    NumRange<uint32_t> ip_src;  // Source ip
    NumRange<uint32_t> ip_dst;  // Destination ip

    explicit Ipv4Rule(uint8_t proto);
    // Парсинг параметров IP пакета
    void ip_header_parse(const boost::program_options::variables_map& vm);
};

#endif // end IP_HPP