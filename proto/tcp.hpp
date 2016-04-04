#ifndef TCP_HPP
#define TCP_HPP

#include <iostream>
#include <vector>

#include <boost/program_options.hpp>

#include <netinet/tcp.h>

#include "baserule.hpp"
#include "ip.hpp"

class tcp_rule : public ip_header_r, public ip_rule
{
public:
	numrange<uint16_t> src_port;
	numrange<uint16_t> dst_port;
	tcp_rule();
	explicit tcp_rule(std::vector<std::string> tkn_rule);
	void parse(boost::program_options::options_description& opt);
	bool check_packet(struct tcphdr *tcp_hdr, uint32_t s_addr, uint32_t d_addr) const;
	bool operator==(tcp_rule const & other) const;
	tcp_rule& operator+=(tcp_rule& other);
	std::string make_info();
};

#endif // end TCP_HPP