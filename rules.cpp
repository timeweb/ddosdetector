#include "rules.hpp"

// class numrange
template<class T>
numrange<T>::numrange()
	: start(0), end(0), enable(false) {}
template<class T>
numrange<T>::numrange(std::pair<T, T> p)
	: start(p.first), end(p.second), enable(true) {}
template<class T>
bool numrange<T>::in_this(T& num) const
{
	if(!enable)
		return true;
	if(num != 0 && num >= start && num <= end)
	{
		return true;
	}
	else
	{
		return false;
	}
}
template<class T>
bool numrange<T>::stat() const
{
	return enable;
}
template<class T>
std::string numrange<T>::to_cidr()
{
	return boost::asio::ip::address_v4(start).to_string() + "-" + boost::asio::ip::address_v4(end).to_string();
}
template<class T>
std::string numrange<T>::to_range()
{
	return std::to_string(start) + "-" + std::to_string(end);
}
template<class T>
bool numrange<T>::operator==(numrange const & other) const
{
	return (start==other.start && end==other.end);
}
template<class T>
numrange<T>& numrange<T>::operator=(std::pair<T, T> p)
{
	if(p.first != 0 || p.second != 0)
	{
		start = p.first;
		end = p.second;
		enable = true;
	}
	return *this;
}

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
		pps_trigger = parser::from_short_size(vm["pps-th"].as<std::string>(), false);
	} catch (const boost::bad_any_cast& e ) {}
	try {
		bps_trigger = parser::from_short_size(vm["bps-th"].as<std::string>());
	} catch (const boost::bad_any_cast& e ) {}
	try {
		pps_trigger_period = vm["pps-th-period"].as<unsigned int>();
	} catch (const boost::bad_any_cast& e ) {}
	try {
		bps_trigger_period = vm["bps-th-period"].as<unsigned int>();
	} catch (const boost::bad_any_cast& e ) {}
	try { 
		act = parser::action_from_string(vm["action"].as<std::string>());
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
std::string ip_rule::ip_rule_info()
{
	std::string info = std::to_string(count_packets) + "|"
					+ std::to_string(count_bytes) + "|"
					+ std::to_string(pps) + "|"
					+ std::to_string(bps);
	return info;
}


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
	ip_header_parse(vm);
	ip_rule_parse(vm);
	try {
		src_port = parser::range_from_port_string(vm["sport"].as<std::string>());
	} catch (const boost::bad_any_cast& e ) {}
	try {
		dst_port = parser::range_from_port_string(vm["dport"].as<std::string>());
	} catch (const boost::bad_any_cast& e ) {}
}
bool tcp_rule::check_packet(struct tcphdr *tcp_hdr, uint32_t s_addr, uint32_t d_addr) const
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

// class rules_list
template<class T>
rules_list<T>::rules_list(boost::program_options::options_description opt)
	: parse_opt_(opt), last_update_(std::chrono::high_resolution_clock::now()) {}
template<class T>
bool rules_list<T>::operator==(rules_list const & other) const
{
	boost::lock(m_, other.m_);
	boost::lock_guard<boost::shared_mutex> g(m_, boost::adopt_lock);
	boost::lock_guard<boost::shared_mutex> g_other(other.m_, boost::adopt_lock);
	return (rules_ == other.rules_);
}
template<class T>
rules_list<T>& rules_list<T>::operator=(const rules_list& other)
{
	if (this != &other)
	{
		boost::lock(m_, other.m_);
		boost::lock_guard<boost::shared_mutex> g(m_, boost::adopt_lock);
		boost::lock_guard<boost::shared_mutex> g_other(other.m_, boost::adopt_lock);
		rules_ = other.rules_;
		last_update_ = other.last_update_;
	}
	return *this;
}
template<class T>
rules_list<T>& rules_list<T>::operator+=(rules_list& other)
{
	if (this != &other)
	{
		last_update_ = std::chrono::high_resolution_clock::now(); // current time point
		boost::lock(m_, other.m_);
		boost::lock_guard<boost::shared_mutex> g(m_, boost::adopt_lock);
		boost::lock_guard<boost::shared_mutex> g_other(other.m_, boost::adopt_lock);
		if(rules_.size() == other.rules_.size())
		{
			for(int i=0; i < rules_.size(); i++)
			{
				rules_[i] += other.rules_[i]; // прибавляем счетчики из other, затем обнуляем счетчики в other
			}
		}
		else
		{
			throw rule::exception("Current rules list size() != new rules list size()");
		}
	}
	return *this;
}
template<class T>
void rules_list<T>::calc_delta(const rules_list& rules_old)
{
	if(this != &rules_old)
	{
		boost::lock(m_, rules_old.m_);
		boost::lock_guard<boost::shared_mutex> g(m_, boost::adopt_lock);
		boost::lock_guard<boost::shared_mutex> g_old(rules_old.m_, boost::adopt_lock);
		if(rules_.size() == rules_old.rules_.size())
		{
			double delta_time = std::chrono::duration<double, std::milli>(last_update_ - rules_old.last_update_).count();
			uint64_t delta_c = 0;
			for(int i=0; i < rules_.size(); i++)
			{
				delta_c = rules_[i].count_packets - rules_old.rules_[i].count_packets;
				rules_[i].pps = round((delta_c / delta_time) * 1000);
				//std::cout << "Rule (" << delta_time << "ms.) #" << i << " delta_pps ("<< delta_c <<"): " << rules_[i].pps << " p: " << rules_[i].count_packets << " old_p: " << rules_old.rules_[i].count_packets << std::endl;

				delta_c = rules_[i].count_bytes - rules_old.rules_[i].count_bytes;
				rules_[i].bps = round((delta_c / delta_time) * 1000);
				//std::cout << "Rule (" << delta_time << "ms.) #" << i << " delta_b ("<< delta_c <<"): " << rules_[i].bps << " b: " << rules_[i].count_bytes << " old_b: " << rules_old.rules_[i].count_bytes << std::endl;
			}
		}
	}
}
template<class T>
void rules_list<T>::check_triggers(ts_queue<action::job>& task_list)
{
	boost::lock_guard<boost::shared_mutex> guard(m_);
	for(auto& r: rules_)
	{
		if(r.is_triggered())
		{
			task_list.push(action::job(r.act, r.make_info()));
		}
	}
}
template<class T>
void rules_list<T>::add_rule(T rule)
{
	rule.parse(parse_opt_);
	boost::lock_guard<boost::shared_mutex> guard(m_);
	rules_.push_back(rule);
}
template<class T>
void rules_list<T>::del_rule(int num)
{
	boost::lock_guard<boost::shared_mutex> guard(m_);
	if(num < 0 || num > (rules_.size()-1))
		throw rule::exception("not found " + std::to_string(num) + " rule");
	rules_.erase(rules_.begin() + num);
}
template<class T>
void rules_list<T>::insert_rule(int num, T rule)
{
	rule.parse(parse_opt_);
	boost::lock_guard<boost::shared_mutex> guard(m_);
	if(num < 0 || num > (rules_.size()-1))
		throw rule::exception("incorrect number rule '" + std::to_string(num)
			+ "', it should be: 0 < num < " + std::to_string(rules_.size()));
	std::vector<T> temp;
	temp.reserve(rules_.size() + 1);
	temp.insert(temp.end(), rules_.begin(), rules_.begin()+num);
	temp.push_back(rule);
	temp.insert(temp.end(), rules_.begin()+num, rules_.end());
	rules_ = temp;
}
// template<class T, typename H>
// void rules_list<T>::check_list(H& l4header, uint32_t s_addr, uint32_t d_addr, unsigned int len)
// {
// 	boost::lock_guard<boost::shared_mutex> guard(m_);
// 	for(auto& r: rules_)
// 	{
// 		if(r.check_packet(l4header, s_addr, d_addr))
// 		{
// 			r.count_packets++;
// 			r.count_bytes += len;
// 			break;
// 		}
// 	}
// }
template<class T>
std::string rules_list<T>::get_rules()
{
	std::string res = "";
	boost::shared_lock<boost::shared_mutex> guard(m_);
	for (int i=0; i<rules_.size(); i++)
	{
		res += std::to_string(i) + ":   "
			+ rules_[i].text_rule + "  : "
			+ parser::short_size(rules_[i].pps, false) + " ("
			+ parser::short_size(rules_[i].bps, true) + "), "
			+ std::to_string(rules_[i].count_packets) + " packets, "
			+ std::to_string(rules_[i].count_bytes) +  " bytes\n";
	}
	return res;
}
template<class T>
boost::program_options::options_description rules_list<T>::get_params() const
{
	return parse_opt_;
}

// struct rcollection
rcollection::rcollection(boost::program_options::options_description& tcp_opt)
	: types({"TCP", "UDP", "ICMP"}), tcp(tcp_opt) {}
rcollection::rcollection(const rcollection& parent)
	: types({"TCP", "UDP", "ICMP"}), tcp(parent.tcp.get_params()) 
{
	tcp = parent.tcp;
}
bool rcollection::operator!=(rcollection const & other) const
{
	return !(tcp == other.tcp);
}
rcollection& rcollection::operator=(const rcollection& other)
{
	if (this != &other)
	{
		types = other.types;
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
std::string rcollection::get_help() const
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
void rcollection::check_triggers(ts_queue<action::job>& task_list)
{
	tcp.check_triggers(task_list);
}

void load_rules_from_file(std::string& rules_file, std::shared_ptr<rcollection>& collect)
{
	std::ifstream r_file(rules_file);
	std::string line;
	while(std::getline(r_file, line))
	{
		std::vector<std::string> t_cmd = parser::tokenize(line);
		try
		{
			if(t_cmd[0] == "TCP")
			{
				collect->tcp.add_rule(tcp_rule(std::vector<std::string>(t_cmd.begin() + 1, t_cmd.end())));
			}
			else
			{
				throw parser::exception("Not found rule type '" + t_cmd[0] + "'");
			}
		}
		catch(const std::exception& e)
		{
			logger << log4cpp::Priority::ERROR << "Load rule failed: " << e.what();
		}
	}
}



template class numrange<uint16_t>;
template class numrange<uint32_t>;
template class rules_list<tcp_rule>;