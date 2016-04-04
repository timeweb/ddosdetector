#include "tcp.hpp"

// class tcp_rule
tcp_rule::tcp_rule()
	: ip_header_r(6), ip_rule() {}
tcp_rule::tcp_rule(std::vector<std::string> tkn_rule)
	: ip_header_r(6), ip_rule(tkn_rule) {}
void tcp_rule::parse(boost::program_options::options_description& opt)
{
	parser::command_parser cp(opt);
	boost::program_options::variables_map vm = cp.parse(tokenize_rule);
	text_rule = cp.join(tokenize_rule);
	// parse L3 header
	ip_header_parse(vm);
	// parse rule options
	ip_rule_parse(vm);
	// parse L4 header
	try {
		src_port = parser::range_from_port_string(vm["sport"].as<std::string>());
	} catch (const boost::bad_any_cast& e ) {}
	try {
		dst_port = parser::range_from_port_string(vm["dport"].as<std::string>());
	} catch (const boost::bad_any_cast& e ) {}
}
bool tcp_rule::check_packet(struct tcphdr *tcp_hdr, uint32_t s_addr, uint32_t d_addr) const
{
	// L3 header check
	if(!ip_src.in_this(s_addr)) // check source ip address
		return false;
	if(!ip_dst.in_this(d_addr)) // check destination ip address
		return false;
	// L4 header check
	uint16_t sport = ntohs(tcp_hdr->source);
	if(!src_port.in_this(sport))
		return false;
	uint16_t dport = ntohs(tcp_hdr->dest);
	if(!dst_port.in_this(dport))
		return false;

	// std::cout << "\n\n== IP HEADER ==";
	// std::cout << "\nSource IP: " << boost::asio::ip::address_v4(s_addr).to_string();
	// std::cout << "\nDestination IP: " << boost::asio::ip::address_v4(d_addr).to_string();
	// // TCP Header
	// std::cout << "\n== TCP HEADER ==";
	// std::cout << "\nSource Port: " << std::dec << sport;
	// std::cout << "\nDestination Port: " << std::dec << dport;
	// std::cout << "\nSEQ number: " << std::dec << ntohl(tcp_hdr->seq);
	// std::cout << "\nACK number: " << std::dec << ntohl(tcp_hdr->ack_seq);
	// std::cout << "\nHeader lenght: " << tcp_hdr->doff * 4;
	// std::cout << "\nURG flag: " << tcp_hdr->urg;
	// std::cout << "\nACK flag: " << tcp_hdr->ack;
	// std::cout << "\nPSH flag: " << tcp_hdr->psh;
	// std::cout << "\nRST flag: " << tcp_hdr->rst;
	// std::cout << "\nSYN flag: " << tcp_hdr->syn;
	// std::cout << "\nFIN flag: " << tcp_hdr->fin;
	// std::cout << "\nWindow size: " << std::dec << ntohs(tcp_hdr->window);
	// std::cout << "\nChecksum: " << std::hex << ntohs(tcp_hdr->check);

	return true;
}
bool tcp_rule::operator==(tcp_rule const & other) const
{
	return (src_port == other.src_port
		&& dst_port == other.dst_port
		&& ip_src == other.ip_src
		&& ip_dst == other.ip_dst);
}
tcp_rule& tcp_rule::operator+=( tcp_rule& other)
{
	if (this != &other)
	{
		count_packets += other.count_packets;
		count_bytes += other.count_bytes;
		// сбрасываем счетчик у исходного правила
		other.count_packets = 0; 
		other.count_bytes = 0;
	}
	return *this;
}
std::string tcp_rule::make_info()
{
	std::string info = "tcp|"
				+ ip_rule_info() + "|"
				+ (ip_src.stat() ? ip_src.to_cidr() : "") + "|"
				+ (ip_dst.stat() ? ip_dst.to_cidr() : "") + "|"
				+ (src_port.stat() ? src_port.to_range() : "") + "|"
				+ (dst_port.stat() ? dst_port.to_range() : "") + "|";
	return info;
}