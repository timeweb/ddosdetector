#include "parser.hpp"

std::vector<std::string> command_parser::tokenize(const std::string& input)
{
	typedef boost::escaped_list_separator<char> separator_type;
	separator_type separator("\\",   // The escape characters.
							"= ",    // The separator characters.
							"\"\'"); // The quote characters.

	// Tokenize the intput.
	boost::tokenizer<separator_type> tokens(input, separator);

	// Copy non-empty tokens from the tokenizer into the result.
	std::vector<std::string> result;
	for(const auto& t: tokens)
	{
		if(!t.empty())
		{
			result.push_back(t);
		}
	}
	return result;
}
std::string command_parser::join(std::vector<std::string>& v)
{
	std::string res;
	for(unsigned int i=0; i < v.size(); i++)
	{
		res += v[i] + " ";
	}
	return res;
}
command_parser::command_parser(boost::program_options::options_description opt) : options_(opt) {}
void command_parser::add_opt(boost::program_options::options_description opt)
{
	options_.add(opt);
}
boost::program_options::variables_map command_parser::parse(std::vector<std::string> tokenize_input)
{
	//Parse mocked up tokenize_input.
	boost::program_options::variables_map vm;
	boost::program_options::command_line_parser parser(tokenize_input);
	boost::program_options::store(parser.options(options_).run(), vm);
	boost::program_options::notify(vm);
	return vm;
}
void command_parser::help()
{
	std::cout << options_ << "\n";
}

std::pair<uint32_t, uint32_t> range_from_ip_string(std::string ipstr)
{
	try
	{
		uint32_t start_ip;
		uint32_t end_ip;
		std::size_t found = ipstr.find("/");
		if (found!=std::string::npos)
		{
				std::string ip_part = ipstr.substr(0,found);
				uint32_t ip = boost::asio::ip::address_v4::from_string(ip_part).to_ulong();
				int keepbits = std::stoi(ipstr.substr(found+1));
				unsigned int mask = keepbits > 0 ? 0x00 - (1<<(32 - keepbits)) : 0xFFFFFFFF;
				start_ip = ip & mask;
				if( ip == 0 && mask == 0xFFFFFFFF)
				{
					end_ip = 0xFFFFFFFF;
				}
				else if(ip == 0) // net 0.0.0.0/0
				{
					end_ip = ~ip & ~mask;;
				}
				else
				{
					end_ip = ip | ~mask;
				}
		}
		else
		{
			start_ip = boost::asio::ip::address_v4::from_string(ipstr).to_ulong();
			end_ip = start_ip;
		}
		return std::make_pair(start_ip, end_ip);
	}
	catch(...)
	{
		return std::make_pair(0, 0);
	}
}

std::pair<uint16_t, uint16_t> range_from_port_string(std::string portstr)
{
	try
	{
		uint16_t start;
		uint16_t end;
		std::size_t found = portstr.find("-");
		if (found!=std::string::npos)
		{
			start = std::stoi(portstr.substr(0,found));
			end = std::stoi(portstr.substr(found+1));
		}
		else
		{
			start = end = std::stoi(portstr);
		}
		return std::make_pair(start, end);
	}
	catch(...)
	{
		return std::make_pair(0, 0);
	}
}

std::string short_size(unsigned long int size, bool from_byte)
{
	static const std::vector<std::string> pref_b = { "b/s", "Kb/s", "Mb/s", "Gb/s", "Tb/s", "Pb/s" };
	static const std::vector<std::string> pref_p = { "p/s", "Kp/s", "Mp/s", "Gp/s", "Tp/s", "Pp/s" };
	unsigned int cur = 0;
	unsigned long int rem = 0;
	size *= (from_byte ? 8 : 1); // convert to bits

	while (size >= 1000 && (cur < pref_b.size() && cur < pref_p.size())) {
		rem = size % 1000;
		size /= 1000;
		cur++;
	}
	double res = (float)size + (float)rem/1000;
	std::ostringstream ss;
	ss << std::fixed << std::setprecision(2) << res;
	if(from_byte)
	{
		return ss.str() + pref_b[cur];
	}
	else
	{
		return ss.str() + pref_p[cur];
	}
}

int get_index(std::vector<std::string> vec, std::string& value)
{
	auto it = std::find(vec.begin(), vec.end(), value);
	if (it == vec.end())
	{
		throw parser::exception("unsupported dimension");
	} else
	{
		return std::distance(vec.begin(), it);
	}
}

uint64_t from_short_size(std::string size, bool to_byte)
{
	static const std::vector<std::string> size_b = { "b", "Kb", "Mb", "Gb", "Tb", "Pb" };
	static const std::vector<std::string> size_p = { "p", "Kp", "Mp", "Gp", "Tp", "Pp" };
	size_t bad = 0;
	unsigned long int num = std::stoul(size, &bad);
	if((bad + 2) != size.length() || num < 1) // if unparsed symbols in string
	{
		throw parser::exception("unparsed symbols in '" + size + "'");
	}
	std::string pref = size.substr(size.length()-2);
	int pos;
	if(to_byte)
	{
		pos = get_index(size_b, pref);
	}
	else
	{
		pos = get_index(size_p, pref);
	}
	for(int i=0; i<pos; i++)
	{
		num *= 1000;
	}
	num /= (to_byte ? 8 : 1); // convert bit to bytes
	return num;
}