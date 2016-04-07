#include "baserule.hpp"

// class num_range
template<class T>
num_range<T>::num_range()
	: start(0), end(0), enable(false) {}
template<class T>
num_range<T>::num_range(std::pair<T, T> p)
	: start(p.first), end(p.second), enable(true) {}
template<class T>
bool num_range<T>::in_this(T& num) const
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
bool num_range<T>::stat() const
{
	return enable;
}
template<class T>
std::string num_range<T>::to_cidr()
{
	return boost::asio::ip::address_v4(start).to_string() + "-" + boost::asio::ip::address_v4(end).to_string();
}
template<class T>
std::string num_range<T>::to_range()
{
	return std::to_string(start) + "-" + std::to_string(end);
}
template<class T>
bool num_range<T>::operator==(num_range const & other) const
{
	return (start==other.start && end==other.end);
}
template<class T>
num_range<T>& num_range<T>::operator=(const std::pair<T, T>& p)
{
	if(p.first != 0 || p.second != 0)
	{
		start = p.first;
		end = p.second;
		enable = true;
	}
	return *this;
}

// class num_comparable
template<class T>
num_comparable<T>::num_comparable()
	: num_(0), enable(false), type_(0) {}
template<class T>
num_comparable<T>::num_comparable(const std::pair<T, unsigned short int>& p)
	: num_(p.first), enable(true), type_(p.second) {}
template<class T>
bool num_comparable<T>::in_this(T& num) const
{
	if(!enable)
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
std::string num_comparable<T>::to_str()
{
	return std::to_string(type_) + ":" + std::to_string(num_);
}
template<class T>
bool num_comparable<T>::operator==(num_comparable const & other) const
{
	return (num_==other.num_ && type_==other.type_);
}
template<class T>
num_comparable<T>& num_comparable<T>::operator=(const std::pair<T, unsigned short int>& p)
{
	num_ = p.first;
	type_ = p.second;
	enable = true;
	return *this;
}

// struct ip_rule
ip_rule::ip_rule()
	: count_packets(0), count_bytes(0), next_rule(false), pps(0), bps(0),
	pps_trigger(0), bps_trigger(0), pps_last_not_triggered(0),
	bps_last_not_triggered(0), pps_trigger_period(10),
	bps_trigger_period(10) {}
ip_rule::ip_rule(std::vector<std::string> tkn_rule)
	: tokenize_rule(tkn_rule), count_packets(0), count_bytes(0), next_rule(false),
	pps(0), bps(0), pps_trigger(0), bps_trigger(0), pps_last_not_triggered(0),
	bps_last_not_triggered(0), pps_trigger_period(10), bps_trigger_period(10) {}
void ip_rule::ip_rule_parse(boost::program_options::variables_map& vm)
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
	if (vm.count("next")) {
		next_rule = vm.count("next");
	}
	// проверка обязательных параметров
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

template class num_range<uint16_t>;
template class num_range<uint32_t>;
template class num_comparable<uint16_t>;
template class num_comparable<uint32_t>;