#ifndef RULES_HPP
#define RULES_HPP

#include <iostream>
#include <vector>
#include <chrono>

#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>

#include <boost/thread.hpp>
#include <boost/program_options.hpp>
#include <boost/tokenizer.hpp>
#include <boost/asio/ip/address.hpp>

// Logging
#include "log4cpp/Category.hh"
#include "log4cpp/Priority.hh"

#include "exceptions.hpp"
#include "parser.hpp"


// Get log4cpp logger from main programm
extern log4cpp::Category& logger;


template<typename T>
class numrange
{
private:
	T start;
	T end;
	bool enable;
public:
	numrange() : start(0), end(0), enable(false) {}
	numrange(std::pair<T, T> p) : start(p.first), end(p.second), enable(true) {}
	bool in_this(T& num)
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
	bool stat()
	{
		return enable;
	}
	void print()
	{
		std::cout << start << " " << end << std::endl;
	}
	bool operator==(numrange const & other) const
	{
		return (start==other.start && end==other.end);
	}
	numrange& operator=(std::pair<T, T> p)
	{
		if(p.first != 0 || p.second != 0)
		{
			start = p.first;
			end = p.second;
			enable = true;
		}
		return *this;
	}
};

struct ip_header_r
{
	uint8_t ver_ihl;
	uint8_t tos;
	uint16_t length;
	uint16_t identification;
	uint16_t flag_offset;
	uint8_t ttl;
	uint8_t protocol;
	uint16_t checksum;
	numrange<uint32_t> ip_src;
	numrange<uint32_t> ip_dst;
	ip_header_r(uint8_t proto);
	void ip_header_parse(boost::program_options::variables_map& vm);
};

struct ip_rule
{
	std::string text_rule;
	std::vector<std::string> tokenize_rule;
	std::string action;
	uint64_t count_packets;              // счетчик пакетов
	uint64_t count_bytes;                // счетчик байт
	uint64_t pps;                        // счетчик пакетов в секунду
	uint64_t bps;                        // счетчик байт в секунду
	uint32_t pps_trigger;                // триггер срабатывания для pps (команда: --pps-trigger)
	uint32_t bps_trigger;                // триггер срабатывания для bps (команда: --bps-trigger)
	std::time_t pps_last_not_triggered;  // время последнего срабатывания pps триггера
	std::time_t bps_last_not_triggered;  // время последнего срабатывания bps триггера
	unsigned int pps_trigger_period;     // период, который должен быть активен триггер pps
	unsigned int bps_trigger_period;     // период, который должен быть активен триггер bps
	ip_rule();
	ip_rule(std::vector<std::string> tkn_rule);
	void ip_rule_parse(boost::program_options::variables_map& vm);
	bool is_triggered();
};

class tcp_rule : public ip_header_r, public ip_rule
{
public:
	numrange<uint16_t> src_port;
	numrange<uint16_t> dst_port;
	tcp_rule();
	tcp_rule(std::vector<std::string> tkn_rule);
	void parse(boost::program_options::options_description& opt);
	bool check_packet(struct tcphdr *tcp_hdr, uint32_t s_addr, uint32_t d_addr);
	bool operator==(tcp_rule const & other) const;
	tcp_rule& operator+=(tcp_rule& other);
};

template<typename T>
class rules_list
{
private:
	mutable boost::shared_mutex m_;
	std::vector<T> rules_;
	boost::program_options::options_description parse_opt_;
	std::chrono::high_resolution_clock::time_point last_update_;

public:
	rules_list(boost::program_options::options_description opt)
		: parse_opt_(opt), last_update_(std::chrono::high_resolution_clock::now()) {}
	bool operator==(rules_list const & other)
	{
		boost::lock(m_, other.m_);
		boost::lock_guard<boost::shared_mutex> g(m_, boost::adopt_lock);
		boost::lock_guard<boost::shared_mutex> g_other(other.m_, boost::adopt_lock);
		return (rules_ == other.rules_);
	}
	rules_list& operator=(const rules_list& other)
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
	rules_list& operator+=(rules_list& other)
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
	void calc_delta(const rules_list& rules_old)
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
	void check_triggers()
	{
		boost::lock_guard<boost::shared_mutex> guard(m_);
		for(auto& r: rules_)
		{
			if(r.is_triggered())
			{
				std::cout << "Rule: " << r.text_rule << " is TRIGGERED!" << std::endl;
			}
		}
	}
	void add_rule(T rule)
	{
		rule.parse(parse_opt_);
		boost::lock_guard<boost::shared_mutex> guard(m_);
		rules_.push_back(rule);
	}
	void del_rule(int num)
	{
		boost::lock_guard<boost::shared_mutex> guard(m_);
		if(num < 0 || num > (rules_.size()-1))
			throw rule::exception("not found " + std::to_string(num) + " rule");
		rules_.erase(rules_.begin() + num);
	}
	void insert_rule(int num, T rule)
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
	template<typename H>
	void check_list(H& l4header, uint32_t s_addr, uint32_t d_addr, unsigned int len)
	{
		boost::lock_guard<boost::shared_mutex> guard(m_);
		for(auto& r: rules_)
		{
			if(r.check_packet(l4header, s_addr, d_addr))
			{
				r.count_packets++;
				r.count_bytes += len;
				break;
			}
		}
	}
	std::string get_rules()
	{
		std::string res = "";
		boost::shared_lock<boost::shared_mutex> guard(m_);
		for (int i=0; i<rules_.size(); i++)
		{
			res += std::to_string(i) + ":   "
				+ rules_[i].text_rule + "  : "
				+ short_size(rules_[i].pps, false) + " ("
				+ short_size(rules_[i].bps, true) + "), "
				+ std::to_string(rules_[i].count_packets) + " packets, "
				+ std::to_string(rules_[i].count_bytes) +  " bytes\n";
		}
		return res;
	}
	boost::program_options::options_description get_params() const
	{
		return parse_opt_;
	}
};

template class numrange<uint16_t>;
template class numrange<uint32_t>;
template class rules_list<tcp_rule>;

class rcollection
{
private:
	std::vector<std::string> types;
public:
	rules_list<tcp_rule> tcp;
	rcollection(boost::program_options::options_description& tcp_opt);
	rcollection(const rcollection& parent);
	bool operator!=(rcollection const & other);
	rcollection& operator=(const rcollection& other);
	rcollection& operator+=(rcollection& other);
	std::string get_help();
	std::string get_rules();
	bool is_type(std::string type);
	void calc_delta(const rcollection& old);
	void check_triggers();
};

#endif // end RULES_HPP