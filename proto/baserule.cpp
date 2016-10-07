#include "baserule.hpp"

// class CountersList
template<class Key, class Val>
CountersList<Key, Val>::CountersList() {};
template<class Key, class Val>
CountersList<Key, Val>& CountersList<Key, Val>::operator+=(CountersList& other)
{
    if (this != &other)
    {
        for(auto& om: other.map_)
        {
            map_[om.first] += om.second;
        }
        other.clear();
    }
    return *this;
}
template<class Key, class Val>
void CountersList<Key, Val>::print() const
{
    for(auto& m: map_) {
        std::cout << "first: " << m.first << " second: " << m.second << std::endl;
    }
}
template<class Key, class Val>
unsigned int CountersList<Key, Val>::size() const
{
    return map_.size();
}
template<class Key, class Val>
void CountersList<Key, Val>::clear()
{
    map_.clear();
}
template<class Key, class Val>
void CountersList<Key, Val>::increase(const Key& k)
{
    map_[k]++;
}
// template<class Key, class Val>
// void CountersList<Key, Val>::increase(const Key& k, const Val& v)
// {
//     map_[k] += v;
// }
template<class Key, class Val>
std::string CountersList<Key, Val>::get_max() const
{
    std::pair<Key, Val> max_val = {0, 0};
    for(auto& m: map_)
    {
        if(m.second > max_val.second)
        {
            max_val = m;
        }
    }
    return boost::asio::ip::address_v4(max_val.first).to_string();
}

// class NumRange
template<class T>
NumRange<T>::NumRange()
    : start_(0), end_(0), enable_(false) {}
template<class T>
NumRange<T>::NumRange(const std::pair<T, T>& p)
    : start_(p.first), end_(p.second), enable_(true) {}
template<class T>
bool NumRange<T>::in_this(T num) const
{
    if(!enable_)
        return true;
    if(num != 0 && num >= start_ && num <= end_)
    {
        return true;
    }
    else
    {
        return false;
    }
}
template<class T>
bool NumRange<T>::stat() const
{
    return enable_;
}
template<class T>
std::string NumRange<T>::to_cidr() const
{
    return boost::asio::ip::address_v4(start_).to_string() + "-" + boost::asio::ip::address_v4(end_).to_string();
}
template<class T>
std::string NumRange<T>::to_range() const
{
    return std::to_string(start_) + "-" + std::to_string(end_);
}
template<class T>
bool NumRange<T>::operator==(NumRange const & other) const
{
    return (start_==other.start_ && end_==other.end_);
}
template<class T>
NumRange<T>& NumRange<T>::operator=(const std::pair<T, T>& p)
{
    if(p.first != 0 || p.second != 0)
    {
        start_ = p.first;
        end_ = p.second;
        enable_ = true;
    }
    return *this;
}

// class NumComparable
template<class T>
NumComparable<T>::NumComparable()
    : num_(0), enable_(false), type_(0) {}
template<class T>
NumComparable<T>::NumComparable(const std::pair<T, unsigned short int>& p)
    : num_(p.first), enable_(true), type_(p.second) {}
template<class T>
bool NumComparable<T>::in_this(T num) const
{
    if(!enable_)
        return true;
    if(type_ == 0 && num == num_)
        return true;
    if(type_ == 1 && num > num_)
        return true;
    if(type_ == 2 && num < num_)
        return true;
    return false;
}
template<class T>
std::string NumComparable<T>::to_str() const
{
    return std::to_string(type_) + ":" + std::to_string(num_);
}
template<class T>
bool NumComparable<T>::operator==(NumComparable const & other) const
{
    return (num_==other.num_ && type_==other.type_);
}
template<class T>
NumComparable<T>& NumComparable<T>::operator=(const std::pair<T, unsigned short int>& p)
{
    num_ = p.first;
    type_ = p.second;
    enable_ = true;
    return *this;
}

// struct BaseRule
BaseRule::BaseRule()
    : rule_type("none"), comment(""), count_packets(0), count_bytes(0),
    next_rule(false), pps(0), bps(0), pps_trigger(0), bps_trigger(0),
    pps_last_not_triggered(0), bps_last_not_triggered(0),
    pps_trigger_period(10), bps_trigger_period(10) {}
BaseRule::BaseRule(const std::vector<std::string>& tkn_rule)
    : rule_type("none"), comment(""), count_packets(0), count_bytes(0),
    next_rule(false), pps(0), bps(0), pps_trigger(0), bps_trigger(0),
    pps_last_not_triggered(0), bps_last_not_triggered(0),
    pps_trigger_period(10), bps_trigger_period(10), tokenize_rule(tkn_rule) {}
void BaseRule::BaseRule_parse(const boost::program_options::variables_map& vm)
{
    if (vm.count("pps-th")) {
        pps_trigger = parser::from_short_size(vm["pps-th"].as<std::string>(), false);
    }
    if (vm.count("bps-th")) {
        bps_trigger = parser::from_short_size(vm["bps-th"].as<std::string>());
    }
    if (vm.count("pps-th-period")) {
        pps_trigger_period = vm["pps-th-period"].as<unsigned int>();
    }
    if (vm.count("bps-th-period")) {
        bps_trigger_period = vm["bps-th-period"].as<unsigned int>();
    }
    if (vm.count("action")) {
        act = parser::action_from_string(vm["action"].as<std::string>());
    }
    if (vm.count("comment")) {
        comment = vm["comment"].as<std::string>();
    }
    if (vm.count("next")) {
        next_rule = vm.count("next");
    }
    // проверка обязательных параметров
    if(pps_trigger == 0 && bps_trigger == 0)
        throw ParserException("pps or bps trigger will be set");
    if(pps_trigger > 0 && pps_trigger_period < 1)
        throw ParserException("incorrect pps trigger period");
    if(bps_trigger > 0 && bps_trigger_period < 1)
        throw ParserException("incorrect bps trigger period");
}
bool BaseRule::is_triggered()
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
                if(dst_top.size() > 0) // если адрес назначения известен
                {
                    return true;
                }
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
                if(dst_top.size() > 0) // если адрес назначения известен
                {
                    return true;
                }
            }
        }
        else
        {
            bps_last_not_triggered = cur_time;
        }
    }
    return false;
}
std::string BaseRule::get_job_info() const
{
    
    // std::string info = std::to_string(count_packets) + "|"
    //                 + std::to_string(count_bytes) + "|"
    //                 + std::to_string(pps) + "|"
    //                 + std::to_string(bps) + "|max: "
    //                 + dst_top.get_max()
    //                 + (comment == "" ? "" : "|" + comment);
    // return info;
    

    std::string info = rule_type + "|"
        + dst_top.get_max()
        + (comment == "" ? "" : "|" + comment)/* + "|"
        + (ip_src.stat() ? ip_src.to_cidr() : "") + "|"
        + (ip_dst.stat() ? ip_dst.to_cidr() : "") + "|"
        + (src_port.stat() ? src_port.to_range() : "") + "|"
        + (dst_port.stat() ? dst_port.to_range() : "") + "|"*/;
    return info;
}
std::string BaseRule::get_trigger_influx() const
{
    std::string info = "events,dst=" + dst_top.get_max()
        + " bps=" + std::to_string(bps * 8)
        + ",pps=" + std::to_string(pps)
        + ",type=\"" + rule_type
        + "\",comment=\"" + (comment)
        + "\"";
    return info;
}

template class CountersList<uint16_t, unsigned int>;
template class CountersList<uint32_t, unsigned int>;
template class NumRange<uint16_t>;
template class NumRange<uint32_t>;
template class NumComparable<uint8_t>;
template class NumComparable<uint16_t>;
template class NumComparable<uint32_t>;

