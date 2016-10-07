#include "rules.hpp"

// class RulesList
template<class T>
RulesList<T>::RulesList(boost::program_options::options_description opt)
    : parse_opt_(opt), last_update_(std::chrono::high_resolution_clock::now())
{}
template<class T>
bool RulesList<T>::operator==(const RulesList& other) const
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
            for(unsigned int i=0; i < rules_.size(); i++)
            {
                // прибавляем счетчики правил из other, затем обнуляем счетчики в other
                rules_[i] += other.rules_[i]; 
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
            // сколько прошло миллисекунд между итерациями
            double delta_time = std::chrono::duration<double, std::milli>(
                last_update_ - rules_old.last_update_).count();
            uint64_t delta_c = 0;
            for(unsigned int i=0; i < rules_.size(); i++)
            {
                // считаем дельту пакет/сек
                delta_c = rules_[i].count_packets - rules_old.rules_[i].count_packets;
                rules_[i].pps = round((delta_c / delta_time) * 1000);
                // считаем дельту байт/сек
                delta_c = rules_[i].count_bytes - rules_old.rules_[i].count_bytes;
                rules_[i].bps = round((delta_c / delta_time) * 1000);
            }
        }
    }
}
template<class T>
void RulesList<T>::check_triggers(ts_queue<action::TriggerJob>& task_list,
    InfluxClient& influx)
{
    boost::lock_guard<boost::shared_mutex> guard(m_);
    for(auto& r: rules_)
    {
        if(r.is_triggered()) // если триггер сработал
        {
            // добавляем задание триггера в очередь обработчика заданий
            task_list.push(action::TriggerJob(r.act, r.get_job_info()));
            // отправляем event в базу
            influx.insert(r.get_trigger_influx());
        }
        // очищаем  проверочные счетчики, чтобы не забивать память
        r.dst_top.clear();
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
void RulesList<T>::del_rule(const unsigned int num)
{
    boost::lock_guard<boost::shared_mutex> guard(m_);
    if(rules_.empty())
        throw RuleException("rules list is empty");
    if(num > (rules_.size()-1))
        throw RuleException("not found " + to_string(num) + " rule");
    rules_.erase(rules_.begin() + num);
}
template<class T>
void RulesList<T>::insert_rule(const unsigned int num, T rule)
{
    rule.parse(parse_opt_);
    boost::lock_guard<boost::shared_mutex> guard(m_);
    if(rules_.empty())
        throw RuleException("rules list is empty");
    if(num > (rules_.size()-1))
        throw RuleException("incorrect number rule '" + to_string(num)
            + "', it should be: 0 < num < " + to_string(rules_.size()));
    // сдвигаем все элементы списка начиная с num-того
    // вперед и добавляем новый элемент
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
    uint64_t all_count_packets = 0;
    uint64_t all_count_bytes = 0;
    uint64_t all_pps = 0;
    uint64_t all_bps = 0;
    unsigned int max_text_size = 0;
    boost::format num_f("%5s"); // форматируем по ширине вывод номеров правил
    boost::shared_lock<boost::shared_mutex> guard(m_);
    for (unsigned int i=0; i<rules_.size(); i++) // /находим самую длинную строку
    {
        if(rules_[i].text_rule.length() > max_text_size)
        {
            max_text_size = rules_[i].text_rule.length();
        }
    }
    for (unsigned int i=0; i<rules_.size(); i++)
    {
        res += boost::str(num_f % to_string(i))
            + ":   "
            // форматируем ширину всех строк по самой длинной строке
            + format_len(rules_[i].text_rule, max_text_size)
            + "  : "
            + parser::to_short_size(rules_[i].pps, false) + " ("
            + parser::to_short_size(rules_[i].bps, true) + "), "
            + to_string(rules_[i].count_packets) + " packets, "
            + to_string(rules_[i].count_bytes) +  " bytes\n";
        all_count_packets += rules_[i].count_packets;
        all_count_bytes += rules_[i].count_bytes;
        all_pps += rules_[i].pps;
        all_bps += rules_[i].bps;
    }
    res += "Total: "
        + parser::to_short_size(all_pps, false) + " ("
        + parser::to_short_size(all_bps, true) + "), "
        + to_string(all_count_packets) + " packets, "
        + to_string(all_count_bytes) +  " bytes\n\n";
    return res;
}
template<class T>
std::string RulesList<T>::get_influx_querys()
{
    std::string res = "";
    std::string t = "none";
    uint64_t all_count_packets = 0;
    uint64_t all_count_bytes = 0;
    uint64_t all_pps = 0;
    uint64_t all_bps = 0;
    boost::shared_lock<boost::shared_mutex> guard(m_);
    for (unsigned int i=0; i<rules_.size(); i++)
    {
        res += rules_[i].rule_type
            + ",rule=" + std::to_string(i)
            + " pps=" + to_string(rules_[i].pps)
            + ",bps=" + to_string(rules_[i].bps * 8)
            // + ",pk=" + to_string(rules_[i].count_packets)
            // + ",bt=" + to_string(rules_[i].count_bytes)
            + " {timestamp}\n";
        all_count_packets += rules_[i].count_packets;
        all_count_bytes += rules_[i].count_bytes;
        all_pps += rules_[i].pps;
        all_bps += rules_[i].bps;
        t = rules_[i].rule_type;
    }
    res += "total,type=" + t
        + " pps=" + to_string(all_pps)
        + ",bps=" + to_string(all_bps * 8)
        // + ",pk=" + to_string(all_count_packets)
        // + ",bt=" + to_string(all_count_bytes)
        + " {timestamp}\n";
    return res;
}
template<class T>
boost::program_options::options_description RulesList<T>::get_params() const
{
    return parse_opt_;
}

// struct RulesCollection
RulesCollection::RulesCollection(
                        boost::program_options::options_description& help_opt,
                        boost::program_options::options_description& tcp_opt,
                        boost::program_options::options_description& udp_opt,
                        boost::program_options::options_description& icmp_opt)
    : types_({"TCP", "UDP", "ICMP"}), help_(help_opt),
      tcp(tcp_opt), udp(udp_opt), icmp(icmp_opt),
      last_change(std::chrono::high_resolution_clock::now()) {}
RulesCollection::RulesCollection(const RulesCollection& parent, bool clear)
    : types_({"TCP", "UDP", "ICMP"}), tcp(parent.tcp.get_params()),
      udp(parent.udp.get_params()), icmp(parent.icmp.get_params()),
      last_change(std::chrono::high_resolution_clock::now())
{
    tcp = parent.tcp;
    udp = parent.udp;
    icmp = parent.icmp;
    if(clear)
    { // очищаем правила в списках правил
        tcp.clear();
        udp.clear();
        icmp.clear();
    }
    last_change = std::chrono::high_resolution_clock::now();
}
bool RulesCollection::operator!=(const RulesCollection& other) const
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
        last_change = std::chrono::high_resolution_clock::now();
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
std::string RulesCollection::get_influx_querys()
{
    std::string querys;
    querys += tcp.get_influx_querys();
    querys += udp.get_influx_querys();
    querys += icmp.get_influx_querys();
    std::string cur_time = std::to_string(std::time(0)) + "000000000";
    boost::replace_all(querys, "{timestamp}", cur_time);
    return querys;
}
bool RulesCollection::is_type(const std::string& type) const
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
void RulesCollection::check_triggers(ts_queue<action::TriggerJob>& task_list,
    InfluxClient& influx)
{
    tcp.check_triggers(task_list, influx);
    udp.check_triggers(task_list, influx);
    icmp.check_triggers(task_list, influx);
}


// class RulesFileLoader
RulesFileLoader::RulesFileLoader(boost::asio::io_service& service,
    const std::string& file, std::shared_ptr<RulesCollection>& c)
    : sig_set_(service, SIGHUP), rules_config_file_(file), collect_(c) {}
void RulesFileLoader::reload_config()
{
    if(is_file_exist(rules_config_file_))
    {
        std::ifstream r_file(rules_config_file_);
        std::string line;
        // Создаем копию текущей коллекции правил и очищаем правила в листах
        RulesCollection buff_collect(*collect_, true);

        while(std::getline(r_file, line))
        {
            // разбиваем строку в вектор по пробелам
            std::vector<std::string> t_cmd = tokenize(line);
            if(t_cmd.size() > 1)
            {
                try
                {
                    if(t_cmd[0].at(0) == '#')
                    {
                        continue;
                    }
                    if(t_cmd[0] == "TCP") // добавляем TCP правило
                    {
                        buff_collect.tcp.add_rule(
                            TcpRule(std::vector<std::string>(
                                    t_cmd.begin() + 1, t_cmd.end()
                                )
                            )
                        );
                    }
                    else if(t_cmd[0] == "UDP") // добавлем UDP правило
                    {
                        buff_collect.udp.add_rule(
                            UdpRule(std::vector<std::string>(
                                    t_cmd.begin() + 1, t_cmd.end()
                                )
                            )
                        );
                    }
                    else if(t_cmd[0] == "ICMP") // добавляем ICMP правило
                    {
                        buff_collect.icmp.add_rule(
                            IcmpRule(std::vector<std::string>(
                                    t_cmd.begin() + 1, t_cmd.end()
                                )
                            )
                        );
                    }
                    else // если правило неопределенного типа
                    {
                        logger << log4cpp::Priority::ERROR
                               << "Not found rule type '" + t_cmd[0] + "'";
                    }
                }
                catch(const std::exception& e)
                {
                    logger << log4cpp::Priority::ERROR
                           << "Load rule failed: " << e.what();
                }
            }
        }
        *collect_ = buff_collect;
        logger << log4cpp::Priority::INFO << "Rules from file " 
                                          << rules_config_file_
                                          << " loaded";
    }
    else
    {
        logger << log4cpp::Priority::ERROR << "File "
                                           << rules_config_file_
                                           << " not found";
    }
}
void RulesFileLoader::sig_hook(boost::asio::signal_set& this_set_,
    boost::system::error_code error, int signal_number)
{
    if (!error)
    {
        // загружаем правила из файла
        reload_config(); 
        // добавляем новое асинхронное задание для сигнала
        sig_set_.async_wait(boost::bind(&RulesFileLoader::sig_hook,
            this, boost::ref(sig_set_), _1, _2));
    }
}
void RulesFileLoader::start()
{
    // загружаем правила из файла
    reload_config();
    // добавляем новое асинхронное задание для сигнала
    sig_set_.async_wait(boost::bind(&RulesFileLoader::sig_hook,
        this, boost::ref(sig_set_), _1, _2));
}



template class RulesList<TcpRule>;
template class RulesList<UdpRule>;
template class RulesList<IcmpRule>;
