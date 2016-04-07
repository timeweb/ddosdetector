#include "icmp.hpp"

// class icmp_rule
icmp_rule::icmp_rule()
	: ip_header_r(6), ip_rule() {}
icmp_rule::icmp_rule(std::vector<std::string> tkn_rule)
	: ip_header_r(6), ip_rule(tkn_rule) {}
void icmp_rule::parse(boost::program_options::options_description& opt)
{
	parser::command_parser cp(opt);
	boost::program_options::variables_map vm = cp.parse(tokenize_rule);
	// store text rule
	text_rule = cp.join(tokenize_rule);
	// parse L3 header
	ip_header_parse(vm);
	// parse rule options
	ip_rule_parse(vm);
	// parse L4 header
	if (vm.count("type")) {
		type = parser::numcomp_from_string<uint8_t>(vm["type"].as<std::string>());
	}
	if (vm.count("code")) {
		code = parser::numcomp_from_string<uint8_t>(vm["code"].as<std::string>());
	}
}
bool icmp_rule::check_packet(struct icmphdr *icmp_hdr, uint32_t s_addr, uint32_t d_addr) const
{
	// L3 header check
	if(!ip_src.in_this(s_addr)) // check source ip address
		return false;
	if(!ip_dst.in_this(d_addr)) // check destination ip address
		return false;
	// L4 header check
	uint8_t h_type = icmp_hdr->type;
	if(!type.in_this(h_type))
		return false;
	uint8_t h_code = icmp_hdr->code;
	if(!code.in_this(h_code))
		return false;

	// std::cout << "\n\n== IP HEADER ==";
	// std::cout << "\nSource IP: " << boost::asio::ip::address_v4(s_addr).to_string();
	// std::cout << "\nDestination IP: " << boost::asio::ip::address_v4(d_addr).to_string();
	// // TCP Header
	// std::cout << "\n== ICMP HEADER ==";
	// std::cout << "\nType: " << std::bitset<8>(h_type);
	// std::cout << "\nCode: " << std::bitset<8>(h_code);

	return true;
}
bool icmp_rule::operator==(icmp_rule const & other) const
{
	return (ip_src == other.ip_src
		&& ip_dst == other.ip_dst
		&& next_rule == other.next_rule
		&& pps_trigger == other.pps_trigger
		&& bps_trigger == other.bps_trigger
		&& pps_trigger_period == other.pps_trigger_period
		&& bps_trigger_period == other.bps_trigger_period
		&& type == other.type
		&& code == other.code);
}
icmp_rule& icmp_rule::operator+=( icmp_rule& other)
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
std::string icmp_rule::make_info()
{
	std::string info = "icmp|"
				+ ip_rule_info() + "|"
				+ (ip_src.stat() ? ip_src.to_cidr() : "") + "|"
				+ (ip_dst.stat() ? ip_dst.to_cidr() : "") + "|"
				+ type.to_str() + "|"
				+ code.to_str() + "|";
	return info;
}