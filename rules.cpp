#include "rules.hpp"

// struct ip_header_r
ip_header_r::ip_header_r(uint8_t proto)
	: protocol(proto) {}
void ip_header_r::ip_header_parse(boost::program_options::variables_map& vm)
{
	try {
		ip_src = range_from_ip_string(vm["srcip"].as<std::string>());
	} catch (const boost::bad_any_cast& e ) {}
	try {
		ip_dst = range_from_ip_string(vm["dstip"].as<std::string>());
	} catch (const boost::bad_any_cast& e ) {}
	// проверка обязательных параметров
	if(!ip_src.stat() && !ip_dst.stat())
		throw parser::exception("destination ip or source ip will be set");
}

// struct ip_rule
ip_rule::ip_rule()
	: count_packets(0), count_bytes(0), pps(0), bps(0),
	pps_trigger(0), bps_trigger(0), pps_last_not_triggered(0),
	bps_last_not_triggered(0), pps_trigger_period(10),
	bps_trigger_period(10) {}
ip_rule::ip_rule(std::vector<std::string> tkn_rule)
	: tokenize_rule(tkn_rule), count_packets(0), count_bytes(0),
	pps(0), bps(0), pps_trigger(0), bps_trigger(0), pps_last_not_triggered(0),
	bps_last_not_triggered(0), pps_trigger_period(10), bps_trigger_period(10) {}
void ip_rule::ip_rule_parse(boost::program_options::variables_map& vm)
{
	try {
		pps_trigger = from_short_size(vm["pps-th"].as<std::string>(), false);
	} catch (const boost::bad_any_cast& e ) {}
	try {
		bps_trigger = from_short_size(vm["bps-th"].as<std::string>());
	} catch (const boost::bad_any_cast& e ) {}
	try {
		pps_trigger_period = vm["pps-th-period"].as<unsigned int>();
	} catch (const boost::bad_any_cast& e ) {}
	try {
		bps_trigger_period = vm["bps-th-period"].as<unsigned int>();
	} catch (const boost::bad_any_cast& e ) {}
	try { 
		action = vm["action"].as<std::string>();
	} catch (const boost::bad_any_cast& e ) {}
	if(pps_trigger == 0 && bps_trigger == 0)
		throw parser::exception("pps or bps trigger will be set");
	if(pps_trigger > 0 && pps_trigger_period < 1)
		throw parser::exception("incorrect pps trigger period");
	if(bps_trigger > 0 && bps_trigger_period < 1)
		throw parser::exception("incorrect bps trigger period");
}
bool ip_rule::is_triggered()
{
	std::time_t cur_time = std::time(0);
	// триггер пакетов
	if(pps_trigger > 0)
	{
		if(pps > pps_trigger)
		{
			// if (current time - last good check) > trigger piriod
			if((cur_time - pps_last_not_triggered) > pps_trigger_period) 
			{
				std::cout << cur_time << " " << pps_last_not_triggered << " " << pps_trigger_period << std::endl;
				pps_last_not_triggered = cur_time; // чтобы триггер срабатывал один раз в период
				return true;
			}
		}
		else
		{
			pps_last_not_triggered = cur_time;
		}
	}
	// триггер байтов
	if(bps_trigger > 0)
	{
		if(bps > bps_trigger)
		{
			// if (current time - last good check) > trigger piriod
			if((cur_time - bps_last_not_triggered) > bps_trigger_period) 
			{
				std::cout << cur_time << " " << bps_last_not_triggered << " " << bps_trigger_period << std::endl;
				bps_last_not_triggered = cur_time; // чтобы триггер срабатывал один раз в период
				return true;
			}
		}
		else
		{
			bps_last_not_triggered = cur_time;
		}
	}
	return false;
}

// class tcp_rule
tcp_rule::tcp_rule()
	: ip_header_r(6), ip_rule() {}
tcp_rule::tcp_rule(std::vector<std::string> tkn_rule)
	: ip_header_r(6), ip_rule(tkn_rule) {}
void tcp_rule::parse(boost::program_options::options_description& opt)
{
	command_parser cp(opt);
	boost::program_options::variables_map vm = cp.parse(tokenize_rule);
	text_rule = cp.join(tokenize_rule);
	ip_header_parse(vm);
	ip_rule_parse(vm);
	try {
		src_port = range_from_port_string(vm["sport"].as<std::string>());
	} catch (const boost::bad_any_cast& e ) {}
	try {
		dst_port = range_from_port_string(vm["dport"].as<std::string>());
	} catch (const boost::bad_any_cast& e ) {}
}
bool tcp_rule::check_packet(struct tcphdr *tcp_hdr, uint32_t s_addr, uint32_t d_addr)
{
	if(!ip_src.in_this(s_addr)) // check source ip address
		return false;
	if(!ip_dst.in_this(d_addr)) // check destination ip address
		return false;
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
	return (src_port == other.src_port && dst_port == other.dst_port
		&& ip_src == other.ip_src && ip_dst == other.ip_dst);
}
tcp_rule& tcp_rule::operator+=( tcp_rule& other)
{
	if (this != &other)
	{
		count_packets += other.count_packets;
		count_bytes += other.count_bytes;
		other.count_packets = 0;
		other.count_bytes = 0;
	}
	return *this;
}

// struct rcollection
rcollection::rcollection(boost::program_options::options_description& tcp_opt)
	: types({"TCP", "UDP", "ICMP"}), tcp(tcp_opt) {}
rcollection::rcollection(const rcollection& parent)
	: types({"TCP", "UDP", "ICMP"}), tcp(parent.tcp.get_params()) 
{
	tcp = parent.tcp;
}
bool rcollection::operator!=(rcollection const & other)
{
	return !(tcp == other.tcp);
}
rcollection& rcollection::operator=(const rcollection& other)
{
	if (this != &other)
	{
		tcp = other.tcp;
	}
	return *this;
}
rcollection& rcollection::operator+=(rcollection& other)
{
	if (this != &other)
	{
		tcp += other.tcp;
	}
	return *this;
}
std::string rcollection::get_help()
{
	std::ostringstream stream;
	stream << tcp.get_params();
	return stream.str();
}
std::string rcollection::get_rules()
{
	std::string cnt;
	cnt += "TCP rules (num, rule, counter):\n";
	cnt += tcp.get_rules();
	return cnt;
}
bool rcollection::is_type(std::string type)
{
	if (std::find(types.begin(), types.end(), type) != types.end())
	{
		return true;
	}
	return false;
}
void rcollection::calc_delta(const rcollection& old)
{
	if (this != &old)
	{
		tcp.calc_delta(old.tcp);
	}
}
void rcollection::check_triggers()
{
	tcp.check_triggers();
}