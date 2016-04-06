#ifndef UDP_HPP
#define UDP_HPP

#include <iostream>
#include <vector>

#include <boost/program_options.hpp>

#include <netinet/udp.h>

#include "baserule.hpp"
#include "ip.hpp"

class udp_rule : public ip_header_r, public ip_rule
{
public:
	numrange<uint16_t> src_port;
	numrange<uint16_t> dst_port;
	num_comparable<uint16_t> len;
	udp_rule();
	explicit udp_rule(std::vector<std::string> tkn_rule);
	void parse(boost::program_options::options_description& opt);
	bool check_packet(struct udphdr *udp_hdr, uint32_t s_addr, uint32_t d_addr) const;
	bool operator==(udp_rule const & other) const;
	udp_rule& operator+=(udp_rule& other);
	std::string make_info();
};

#endif // end UDP_HPP