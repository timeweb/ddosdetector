#include "rules.hpp"

// class RulesList
template<class T>
RulesList<T>::RulesList(boost::program_options::options_description opt)
    : parse_opt_(opt), last_update_(std::chrono::high_resolution_clock::now()) {}
template<class T>
bool RulesList<T>::operator==(RulesList const & other) const
{
    boost::lock(m_, other.m_);
    boost::lock_guard<boost::shared_mutex> g(m_, boost::adopt_lock);
    boost::lock_guard<boost::shared_mutex> g_other(other.m_, boost::adopt_lock);
    return (rules_ == other.rules_);
}
template<class T>
RulesList<T>& RulesList<T>::operator=(const RulesList& other)
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
RulesList<T>& RulesList<T>::operator+=(RulesList& other)
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
            throw RuleException("Current rules list size() != new rules list size()");
        }
    }
    return *this;
}
template<class T>
void RulesList<T>::calc_delta(const RulesList& rules_old)
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

                delta_c = rules_[i].count_bytes - rules_old.rules_[i].count_bytes;
                rules_[i].bps = round((delta_c / delta_time) * 1000);
            }
        }
    }
}
template<class T>
void RulesList<T>::check_triggers(ts_queue<action::TriggerJob>& task_list)
{
    boost::lock_guard<boost::shared_mutex> guard(m_);
    for(auto& r: rules_)
    {
        if(r.is_triggered())
        {
            task_list.push(action::TriggerJob(r.act, r.make_info()));
        }
    }
}
template<class T>
void RulesList<T>::add_rule(T rule)
{
    rule.parse(parse_opt_);
    boost::lock_guard<boost::shared_mutex> guard(m_);
    rules_.push_back(rule);
}
template<class T>
void RulesList<T>::clear()
{
    boost::lock_guard<boost::shared_mutex> guard(m_);
    rules_.clear();
}
template<class T>
void RulesList<T>::del_rule(int num)
{
    boost::lock_guard<boost::shared_mutex> guard(m_);
    if(rules_.empty())
        throw RuleException("rules list is empty");
    if(num < 0 || num > (rules_.size()-1))
        throw RuleException("not found " + std::to_string(num) + " rule");
    rules_.erase(rules_.begin() + num);
}
template<class T>
void RulesList<T>::insert_rule(int num, T rule)
{
    rule.parse(parse_opt_);
    boost::lock_guard<boost::shared_mutex> guard(m_);
    if(rules_.empty())
        throw RuleException("rules list is empty");
    if(num < 0 || num > (rules_.size()-1))
        throw RuleException("incorrect number rule '" + std::to_string(num)
            + "', it should be: 0 < num < " + std::to_string(rules_.size()));
    std::vector<T> temp;
    temp.reserve(rules_.size() + 1);
    temp.insert(temp.end(), rules_.begin(), rules_.begin()+num);
    temp.push_back(rule);
    temp.insert(temp.end(), rules_.begin()+num, rules_.end());
    rules_ = temp;
}
template<class T>
std::string RulesList<T>::get_rules()
{
    std::string res = "";
    unsigned int max_text_size = 0;
    boost::format num_f("%5s");
    boost::shared_lock<boost::shared_mutex> guard(m_);
    for (int i=0; i<rules_.size(); i++)
    {
        if(rules_[i].text_rule.length() > max_text_size)
        {
            max_text_size = rules_[i].text_rule.length();
        }
    }
    for (int i=0; i<rules_.size(); i++)
    {
        res += boost::str(num_f % std::to_string(i))
            + ":   "
            + format_len(rules_[i].text_rule, max_text_size)
            + "  : "
            + parser::short_size(rules_[i].pps, false) + " ("
            + parser::short_size(rules_[i].bps, true) + "), "
            + std::to_string(rules_[i].count_packets) + " packets, "
            + std::to_string(rules_[i].count_bytes) +  " bytes\n";
    }
    return res;
}
template<class T>
boost::program_options::options_description RulesList<T>::get_params() const
{
    return parse_opt_;
}

// struct RulesCollection
RulesCollection::RulesCollection(boost::program_options::options_description& help_opt,
                         boost::program_options::options_description& tcp_opt,
                         boost::program_options::options_description& udp_opt,
                         boost::program_options::options_description& icmp_opt)
    : types_({"TCP", "UDP", "ICMP"}), help_(help_opt),
      tcp(tcp_opt), udp(udp_opt), icmp(icmp_opt) {}
RulesCollection::RulesCollection(const RulesCollection& parent, bool clear)
    : types_({"TCP", "UDP", "ICMP"}), tcp(parent.tcp.get_params()),
      udp(parent.udp.get_params()), icmp(parent.icmp.get_params()) 
{
    tcp = parent.tcp;
    udp = parent.udp;
    icmp = parent.icmp;
    if(clear)
    {
        tcp.clear();
        udp.clear();
        icmp.clear();
    }
}
bool RulesCollection::operator!=(RulesCollection const & other) const
{
    return !(tcp == other.tcp && udp == other.udp && icmp == other.icmp);
}
RulesCollection& RulesCollection::operator=(const RulesCollection& other)
{
    if (this != &other)
    {
        types_ = other.types_;
        tcp = other.tcp;
        udp = other.udp;
        icmp = other.icmp;
    }
    return *this;
}
RulesCollection& RulesCollection::operator+=(RulesCollection& other)
{
    if (this != &other)
    {
        tcp += other.tcp;
        udp += other.udp;
        icmp += other.icmp;
    }
    return *this;
}
std::string RulesCollection::get_help() const
{
    std::ostringstream stream;
    stream << help_;
    return stream.str();
}
std::string RulesCollection::get_rules()
{
    std::string cnt;
    cnt += "TCP rules (num, rule, counter):\n";
    cnt += tcp.get_rules();
    cnt += "UDP rules (num, rule, counter):\n";
    cnt += udp.get_rules();
    cnt += "ICMP rules (num, rule, counter):\n";
    cnt += icmp.get_rules();
    return cnt;
}
bool RulesCollection::is_type(std::string type)
{
    if (std::find(types_.begin(), types_.end(), type) != types_.end())
    {
        return true;
    }
    return false;
}
void RulesCollection::calc_delta(const RulesCollection& old)
{
    if (this != &old)
    {
        tcp.calc_delta(old.tcp);
        udp.calc_delta(old.udp);
        icmp.calc_delta(old.icmp);
    }
}
void RulesCollection::check_triggers(ts_queue<action::TriggerJob>& task_list)
{
    tcp.check_triggers(task_list);
    udp.check_triggers(task_list);
    icmp.check_triggers(task_list);
}


// class RulesFileLoader
void RulesFileLoader::reload_config()
{
    if(is_file_exist(rules_config_file_))
    {
        std::ifstream r_file(rules_config_file_);
        std::string line;
        RulesCollection buff_collect(*collect_, true); // copy with clear list

        while(std::getline(r_file, line))
        {
            std::vector<std::string> t_cmd = tokenize(line);
            if(t_cmd.size() > 1)
            {
                try
                {
                    if(t_cmd[0].at(0) == '#')
                    {
                        continue;
                    }
                    if(t_cmd[0] == "TCP")
                    {
                        buff_collect.tcp.add_rule(TcpRule(std::vector<std::string>(t_cmd.begin() + 1, t_cmd.end())));
                    }
                    else if(t_cmd[0] == "UDP")
                    {
                        buff_collect.udp.add_rule(UdpRule(std::vector<std::string>(t_cmd.begin() + 1, t_cmd.end())));
                    }
                    else if(t_cmd[0] == "ICMP")
                    {
                        buff_collect.icmp.add_rule(IcmpRule(std::vector<std::string>(t_cmd.begin() + 1, t_cmd.end())));
                    }
                    else
                    {
                        logger << log4cpp::Priority::ERROR << "Not found rule type '" + t_cmd[0] + "'";
                    }
                }
                catch(const std::exception& e)
                {
                    logger << log4cpp::Priority::ERROR << "Load rule failed: " << e.what();
                }
            }
        }
        *collect_ = buff_collect;
        logger << log4cpp::Priority::INFO << "Rules from file " << rules_config_file_ << " loaded";
    }
    else
    {
        logger << log4cpp::Priority::ERROR << "File " << rules_config_file_ << " not found";
    }
}
void RulesFileLoader::sig_hook(boost::asio::signal_set& this_set_,
    boost::system::error_code error, int signal_number)
{
    if (!error)
    {
        reload_config();
        sig_set_.async_wait(boost::bind(&RulesFileLoader::sig_hook, this, boost::ref(sig_set_), _1, _2));
    }
}
RulesFileLoader::RulesFileLoader(boost::asio::io_service& service,
    std::string file, std::shared_ptr<RulesCollection>& c)
    : sig_set_(service, SIGHUP), rules_config_file_(file), collect_(c) {}
void RulesFileLoader::start()
{
    reload_config();
    sig_set_.async_wait(boost::bind(&RulesFileLoader::sig_hook, this, boost::ref(sig_set_), _1, _2));
}



template class RulesList<TcpRule>;
template class RulesList<UdpRule>;
template class RulesList<IcmpRule>;