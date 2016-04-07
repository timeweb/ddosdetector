#ifndef ICMP_HPP
#define ICMP_HPP

#include <iostream>
#include <vector>

#include <boost/program_options.hpp>

#include <netinet/ip_icmp.h>

#include "baserule.hpp"
#include "ip.hpp"

class icmp_rule : public ip_header_r, public ip_rule
{
public:
	num_comparable<uint8_t> type;
	num_comparable<uint8_t> code;
	icmp_rule();
	explicit icmp_rule(std::vector<std::string> tkn_rule);
	void parse(boost::program_options::options_description& opt);
	bool check_packet(struct icmphdr *icmp_hdr, uint32_t s_addr, uint32_t d_addr) const;
	bool operator==(icmp_rule const & other) const;
	icmp_rule& operator+=(icmp_rule& other);
	std::string make_info();
};

#endif // end ICMP_HPP