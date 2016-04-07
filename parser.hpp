#ifndef CommandParser_HPP
#define CommandParser_HPP

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

    class CommandParser
    {
    public:
        explicit CommandParser(boost::program_options::options_description opt);
        void add_opt(boost::program_options::options_description opt);
        boost::program_options::variables_map parse(std::vector<std::string> tokenize_input);
        void help() const;
        static std::string join(std::vector<std::string>& v);
    private:
        boost::program_options::options_description options_;
    };

    // FUNCTIONS ::parser
    std::pair<uint32_t, uint32_t> range_from_ip_string(const std::string& ipstr);
    std::pair<uint16_t, uint16_t> range_from_port_string(const std::string& portstr);
    std::string short_size(unsigned long int size, bool from_byte = true);
    uint64_t from_short_size(const std::string& size, bool to_byte = true);
    action::Action action_from_string(const std::string& value);
    template<typename T>
    std::pair<T, unsigned short int> numcomp_from_string(std::string value)
    {
        if(value.length() < 2)
        {
            throw ParserException("parametr '" + value + "' is too short, must be '>num', '=num' or '<num'");
        }
        size_t bad = 0;
        unsigned long int num;
        try
        {
            num = std::stoul(value.substr(1), &bad);
        }
        catch(const std::invalid_argument& e)
        {
            throw ParserException("bad number in '" + value.substr(1) + "'");
        }
        if((bad+1) != value.length()) // if unparsed symbols in string
        {
            throw ParserException("unparsed symbols in '" + value + "', must be '>num', '=num' or '<num'");
        }
        return std::make_pair/*<T, unsigned short int>*/((T)num, get_index<char>(comp_t, value.at(0)));
    }
    template<typename T>
    std::pair<T, T> bitset_from_string(const std::string& value,
        const std::vector<char>& accept_flags)
    {
        T bits;
        T mask;
        if(accept_flags.size() != bits.size())
            throw std::invalid_argument("bad parametr accept flags");
        separator_type separator("\\",    // The escape characters.
                                 ",",    // The separator characters.
                                 "\"\'"); // The quote characters.
        std::vector<std::string> tok_v = tokenize(value, separator);
        if(tok_v.empty())
            throw ParserException("empty option '" + value + "'");
        int indx;
        for(auto& f: tok_v)
        {
            if(f.length() != 3 || f.at(1) != ':'
                || (f.at(2) != '0' && f.at(2) != '1'))
            {
                throw ParserException("unparsed flag '" + f + "', must be: '<flag>:<enable>', where <enable> - 0 or 1.");
            }
            indx = get_index<char>(accept_flags, f.at(0)); // check if flag accept
            mask[indx] = true; // enable bit in mask
            bits[indx] = f.at(2)=='1' ? true : false; // add checked bit
        }
        return std::make_pair(bits, mask);
    }
}

#endif // end CommandParser_HPP