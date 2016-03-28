#ifndef COMMAND_PARSER_HPP
#define COMMAND_PARSER_HPP

#include <iostream>
#include <vector>
#include <sstream>
#include <iomanip>
#include <bitset>

#include <boost/program_options.hpp>
#include <boost/tokenizer.hpp>
#include <boost/asio/ip/address.hpp>

#include "exceptions.hpp"
#include "action.hpp"


namespace parser
{
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

	typedef boost::escaped_list_separator<char> separator_type;

	std::vector<std::string> tokenize(const std::string& input);
	std::pair<uint32_t, uint32_t> range_from_ip_string(std::string ipstr);
	std::pair<uint16_t, uint16_t> range_from_port_string(std::string portstr);
	std::string short_size(unsigned long int size, bool from_byte = true);
	int get_index(std::vector<std::string> vec, std::string& value);
	uint64_t from_short_size(std::string size, bool to_byte = true);
	action::action action_from_string(std::string value);
}

#endif // end COMMAND_PARSER_HPP