#ifndef BASERULE_HPP
#define BASERULE_HPP

#include <iostream>
#include <vector>

#include <boost/program_options.hpp>

#include "../action.hpp"
#include "../parser.hpp"

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


struct ip_rule
{
	std::string text_rule;
	std::vector<std::string> tokenize_rule;
	action::action act;
	uint64_t count_packets;              // счетчик пакетов
	uint64_t count_bytes;                // счетчик байт
	bool next_rule;                      // перейти к следующему правилу
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

#endif // end BASERULE_HPP