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
#include "udp.hpp"
#include "icmp.hpp"

// Get log4cpp logger from main programm
extern log4cpp::Category& logger;

template<class T>
class RulesList
{
public:
    explicit RulesList(boost::program_options::options_description opt);
    bool operator==(RulesList const & other)  const;
    RulesList& operator=(const RulesList& other);
    RulesList& operator+=(RulesList& other);
    void calc_delta(const RulesList& rules_old);
    void check_triggers(ts_queue<action::TriggerJob>& task_list);
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
private:
    mutable boost::shared_mutex m_;
    std::vector<T> rules_;
    boost::program_options::options_description parse_opt_;
    std::chrono::high_resolution_clock::time_point last_update_;
};

class RulesCollection
{
public:
    RulesCollection(boost::program_options::options_description& help_opt,
                boost::program_options::options_description& tcp_opt,
                boost::program_options::options_description& udp_opt,
                boost::program_options::options_description& icmp_opt);
    RulesCollection(const RulesCollection& parent, bool clear = false);
    bool operator!=(RulesCollection const & other) const;
    RulesCollection& operator=(const RulesCollection& other);
    RulesCollection& operator+=(RulesCollection& other);
    std::string get_help() const;
    std::string get_rules();
    bool is_type(std::string type);
    void calc_delta(const RulesCollection& old);
    void check_triggers(ts_queue<action::TriggerJob>& task_list);
private:
    std::vector<std::string> types_;
    boost::program_options::options_description help_;
public:
    RulesList<TcpRule> tcp;
    RulesList<UdpRule> udp;
    RulesList<IcmpRule> icmp;
};

class RulesFileLoader
{
public:
    RulesFileLoader(boost::asio::io_service& service, std::string file, std::shared_ptr<RulesCollection>& c);
    void start();
private:
    boost::asio::signal_set sig_set_;
    std::string rules_config_file_;
    std::shared_ptr<RulesCollection>& collect_;

    void reload_config();
    void sig_hook(boost::asio::signal_set& this_set_, boost::system::error_code error, int signal_number);
};

#endif // end RULES_HPP