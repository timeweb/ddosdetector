#include "ip.hpp"

// struct ip_header_r
ip_header_r::ip_header_r(uint8_t proto)
	: ver_ihl(0), tos(0), length(0),
	identification(0), flag_offset(0), ttl(0), protocol(proto), checksum(0) {}
void ip_header_r::ip_header_parse(boost::program_options::variables_map& vm)
{
	try {
		ip_src = parser::range_from_ip_string(vm["srcip"].as<std::string>());
	} catch (const boost::bad_any_cast& e ) {}
	try {
		ip_dst = parser::range_from_ip_string(vm["dstip"].as<std::string>());
	} catch (const boost::bad_any_cast& e ) {}
	// проверка обязательных параметров
	if(!ip_src.stat() && !ip_dst.stat())
		throw parser::exception("destination ip or source ip will be set");
}