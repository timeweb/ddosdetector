#ifndef FUNCTIONS_HPP
#define FUNCTIONS_HPP

#include <stdlib.h> // atoi
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <net/if.h>
#include <fstream>
#include <iostream>
#include <string.h>
#include <algorithm>
#include <vector>

#include <boost/format.hpp>
#include <boost/tokenizer.hpp>


// Logging
#include "log4cpp/Category.hh"
#include "log4cpp/Appender.hh"
#include "log4cpp/FileAppender.hh"
#include "log4cpp/OstreamAppender.hh"
#include "log4cpp/Layout.hh"
#include "log4cpp/Priority.hh"
#include "log4cpp/PatternLayout.hh"

void init_logging(log4cpp::Category& logger, bool debug, std::string file);
#ifdef __linux__
bool manage_interface_promisc_mode(std::string interface_name, bool switch_on);
#endif
std::string get_netmap_intf(std::string& intf);
bool is_file_exist(const std::string& file_name);
std::string format_len(const std::string& s, unsigned int len);
typedef boost::escaped_list_separator<char> separator_type;
std::vector<std::string> tokenize(const std::string& input, separator_type& separator);
std::vector<std::string> tokenize(const std::string& input);
template<typename T>
int get_index(std::vector<T> vec, T& value)
{
	auto it = std::find(vec.begin(), vec.end(), value);
	if (it == vec.end())
	{
		throw std::invalid_argument("unsupported value");
	} else
	{
		return std::distance(vec.begin(), it);
	}
}

#endif // end FUNCTIONS_HPP