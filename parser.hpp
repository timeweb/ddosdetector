#ifndef COMMAND_PARSER_HPP
#define COMMAND_PARSER_HPP

#include <iostream>
#include <vector>
#include <sstream>
#include <iomanip>
#include <bitset>

#include <boost/program_options.hpp>
#include <boost/asio/ip/address.hpp>

#include "exceptions.hpp"
#include "action.hpp"
#include "functions.hpp"


namespace parser
{
	const std::vector<std::string> pref_b = { "b/s", "Kb/s", "Mb/s", "Gb/s", "Tb/s", "Pb/s" };
	const std::vector<std::string> pref_p = { "p/s", "Kp/s", "Mp/s", "Gp/s", "Tp/s", "Pp/s" };
	const std::vector<std::string> size_b = { "b", "Kb", "Mb", "Gb", "Tb", "Pb" };
	const std::vector<std::string> size_p = { "p", "Kp", "Mp", "Gp", "Tp", "Pp" };
	const std::vector<char> comp_t = { '=', '>', '<' };

	class command_parser
	{
	private:
		boost::program_options::options_description options_;
	public:
		explicit command_parser(boost::program_options::options_description opt);
		void add_opt(boost::program_options::options_description opt);
		boost::program_options::variables_map parse(std::vector<std::string> tokenize_input);
		void help() const;
		static std::string join(std::vector<std::string>& v);
	};

	std::pair<uint32_t, uint32_t> range_from_ip_string(std::string ipstr);
	std::pair<uint16_t, uint16_t> range_from_port_string(std::string portstr);
	std::string short_size(unsigned long int size, bool from_byte = true);
	uint64_t from_short_size(std::string size, bool to_byte = true);
	action::action action_from_string(std::string value);
	template<typename T>
	//std::pair<T, unsigned short int> numcomp_from_string(std::string value);
	std::pair<T, unsigned short int> numcomp_from_string(std::string value)
	{
		if(value.length() < 2)
		{
			throw exception("parametr '" + value + "' is too short, must be '>num', '=num' or '<num'");
		}
		size_t bad = 0;
		unsigned long int num;
		try
		{
			num = std::stoul(value.substr(1), &bad);
		}
		catch(const std::invalid_argument& e)
		{
			throw exception("bad number in '" + value.substr(1) + "'");
		}
		if((bad+1) != value.length()) // if unparsed symbols in string
		{
			throw exception("unparsed symbols in '" + value + "', must be '>num', '=num' or '<num'");
		}
		return std::make_pair<T, unsigned short int>((T)num, get_index<char>(comp_t, value.at(0)));
	}
	void conflicting_options(const boost::program_options::variables_map & vm,
							 const std::string & opt1, const std::string & opt2,
							 const std::string & opt3);
}

#endif // end COMMAND_PARSER_HPP