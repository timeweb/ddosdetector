#include "ip.hpp"

// struct Ipv4Rule
Ipv4Rule::Ipv4Rule(uint8_t proto)
    : ver_ihl(0), tos(0), length(0),
    identification(0), flag_offset(0), ttl(0), protocol(proto), checksum(0) {}
void Ipv4Rule::ip_header_parse(const boost::program_options::variables_map& vm)
{
    if (vm.count("srcip")) {
        ip_src = parser::range_from_ip_string(vm["srcip"].as<std::string>());
    }
    if (vm.count("dstip")) {
        ip_dst = parser::range_from_ip_string(vm["dstip"].as<std::string>());
    }
    // проверка обязательных параметров
    if(!ip_src.stat() && !ip_dst.stat())
        throw ParserException("destination ip or source ip will be set");
}