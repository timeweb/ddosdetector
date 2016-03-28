#ifndef RULES_HPP
#define RULES_HPP

#include <iostream>
#include <fstream>
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
#include "lib/queue.hpp"
#include "action.hpp"


// Get log4cpp logger from main programm
extern log4cpp::Category& logger;


template<class T>
class numrange
{
private:
	T start;
	T end;
	bool enable;
public:
	numrange();
	explicit numrange(std::pair<T, T> p);
	bool in_this(T& num) const;
	bool stat() const;
	std::string to_cidr();
	std::string to_range();
	bool operator==(numrange const & other) const;
	numrange& operator=(std::pair<T, T> p);
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
	explicit ip_header_r(uint8_t proto);
	void ip_header_parse(boost::program_options::variables_map& vm);
};

struct ip_rule
{
	std::string text_rule;
	std::vector<std::string> tokenize_rule;
	action::action act;
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
	explicit ip_rule(std::vector<std::string> tkn_rule);
	void ip_rule_parse(boost::program_options::variables_map& vm);
	bool is_triggered();
	std::string ip_rule_info();
};

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

template<class T>
class rules_list
{
private:
	mutable boost::shared_mutex m_;
	std::vector<T> rules_;
	boost::program_options::options_description parse_opt_;
	std::chrono::high_resolution_clock::time_point last_update_;
public:
	explicit rules_list(boost::program_options::options_description opt);
	bool operator==(rules_list const & other)  const;
	rules_list& operator=(const rules_list& other);
	rules_list& operator+=(rules_list& other);
	void calc_delta(const rules_list& rules_old);
	void check_triggers(ts_queue<action::job>& task_list);
	void add_rule(T rule);
	void del_rule(int num);
	void insert_rule(int num, T rule);
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
	std::string get_rules();
	boost::program_options::options_description get_params() const;
};

class rcollection
{
private:
	std::vector<std::string> types;
public:
	rules_list<tcp_rule> tcp;
	explicit rcollection(boost::program_options::options_description& tcp_opt);
	rcollection(const rcollection& parent);
	bool operator!=(rcollection const & other) const;
	rcollection& operator=(const rcollection& other);
	rcollection& operator+=(rcollection& other);
	std::string get_help() const;
	std::string get_rules();
	bool is_type(std::string type);
	void calc_delta(const rcollection& old);
	void check_triggers(ts_queue<action::job>& task_list);
};

void load_rules_from_file(std::string& rules_file, std::shared_ptr<rcollection>& collect);

#endif // end RULES_HPP