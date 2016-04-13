#include "parser.hpp"

namespace parser
{
    namespace po = boost::program_options;
    CommandParser::CommandParser(const po::options_description& opt)
        : options_(opt) {}
    void CommandParser::add_opt(const po::options_description& opt)
    {
        options_.add(opt);
    }
    po::variables_map CommandParser::parse(
        const std::vector<std::string>& tokenize_input)
    {
        //Parse mocked up tokenize_input.
        po::variables_map vm;
        std::vector<std::string> bad_opt;
        try
        {
            po::command_line_parser parser(tokenize_input);
            po::parsed_options parsed_opt = parser.options(options_).run();
            po::store(parsed_opt, vm);
            po::notify(vm);
            bad_opt = po::collect_unrecognized(parsed_opt.options,
                po::include_positional);
        }
        catch(std::exception& e)
        {
            throw ParserException("rule parse failed: " + std::string(e.what()));
        }
        if(!bad_opt.empty())
        {
            throw ParserException("bad option: " + join(bad_opt));
        }
        return vm;
    }
    void CommandParser::help() const
    {
        std::cout << options_ << "\n";
    }
    std::string CommandParser::join(const std::vector<std::string>& v)
    {
        std::string res;
        for(unsigned int i=0; i < v.size(); i++)
        {
            res += v[i] + " ";
        }
        return res;
    }

    // Функции parser::
    std::pair<uint32_t, uint32_t> range_from_ip_string(const std::string& ipstr)
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
                    int keepbits = std::atoi(ipstr.substr(found+1).c_str());
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

    std::pair<uint16_t, uint16_t> range_from_port_string(const std::string& portstr)
    {
        try
        {
            uint16_t start;
            uint16_t end;
            std::size_t found = portstr.find("-");
            if (found!=std::string::npos)
            {
                start = std::atoi(portstr.substr(0,found).c_str());
                end = std::atoi(portstr.substr(found+1).c_str());
            }
            else
            {
                start = end = std::atoi(portstr.c_str());
            }
            return std::make_pair(start, end);
        }
        catch(...)
        {
            return std::make_pair(0, 0);
        }
    }

    std::string to_short_size(unsigned long int size, bool its_byte)
    {
        unsigned int cur = 0;
        unsigned long int rem = 0;
        size *= (its_byte ? 8 : 1); // convert to bits

        while (size >= 1000 && (cur < pref_b.size() && cur < pref_p.size())) {
            rem = size % 1000;
            size /= 1000;
            cur++;
        }
        double res = (float)size + (float)rem/1000;
        std::ostringstream ss;
        ss << std::fixed << std::setprecision(2) << res;
        if(its_byte)
        {
            return ss.str() + pref_b[cur];
        }
        else
        {
            return ss.str() + pref_p[cur];
        }
    }

    uint64_t from_short_size(const std::string& size, bool its_byte)
    {
        size_t bad = 0;
        unsigned long int num;
        try
        {
            //num = std::atoi(size.c_str());
            num = std::stoul(size, &bad);
        }
        catch(const std::invalid_argument& e)
        {
            throw ParserException("bad number in '" + size + "'");
        }
        if(bad == size.length()) // if unparsed symbols in string
        {
            throw ParserException("unparsed symbols in '" + size + "', please add short prefix: p or b, Kp or Kb etc.");
        }
        std::string pref = size.substr(bad);
        int pos;
        if(its_byte)
        {
            pos = get_index<std::string>(size_b, pref);
        }
        else
        {
            pos = get_index<std::string>(size_p, pref);
        }
        for(int i=0; i<pos; i++)
        {
            num *= 1000;
        }
        num /= (its_byte ? 8 : 1); // convert bit to bytes
        return num;
    }

    action::Action action_from_string(const std::string& value)
    {
        separator_type separator("\\",    // The escape characters.
                                 ":",    // The separator characters.
                                 "\"\'"); // The quote characters.
        std::vector<std::string> tok_v = tokenize(value, separator);
        unsigned int size = tok_v.size();
        if(size == 1)
        {
            return action::Action(tok_v[0]);
        }
        else if(size == 2)
        {
            return action::Action(tok_v[0], tok_v[1]);
        }
        else
        {
            throw ParserException("upnparsed action '" + value + "', must be: '<type>:<param>'");
        }
    }
}