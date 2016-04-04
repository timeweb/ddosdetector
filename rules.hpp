#ifndef RULES_HPP
#define RULES_HPP

#include <iostream>
#include <fstream>
#include <vector>
#include <chrono>

#include <boost/thread.hpp>
#include <boost/program_options.hpp>
#include <boost/tokenizer.hpp>
#include <boost/asio/signal_set.hpp>
#include <boost/format.hpp>

// Logging
#include "log4cpp/Category.hh"
#include "log4cpp/Priority.hh"

#include "exceptions.hpp"
#include "parser.hpp"
#include "lib/queue.hpp"
#include "action.hpp"
#include "functions.hpp"

// protocols
#include "ip.hpp"
#include "tcp.hpp"


// Get log4cpp logger from main programm
extern log4cpp::Category& logger;

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
	void clear();
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
				if(!r.next_rule)
				{
					break;
				}
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
	rcollection(const rcollection& parent, bool clear = false);
	bool operator!=(rcollection const & other) const;
	rcollection& operator=(const rcollection& other);
	rcollection& operator+=(rcollection& other);
	std::string get_help() const;
	std::string get_rules();
	bool is_type(std::string type);
	void calc_delta(const rcollection& old);
	void check_triggers(ts_queue<action::job>& task_list);
};

class rules_file_loader
{
private:
	boost::asio::signal_set sig_set_;
	std::string rules_config_file_;
	std::shared_ptr<rcollection>& collect;

	void reload_config();
	void sig_hook(boost::asio::signal_set& this_set_, boost::system::error_code error, int signal_number);
public:
	rules_file_loader(boost::asio::io_service& service, std::string file, std::shared_ptr<rcollection>& c);
	void start();
};

#endif // end RULES_HPP