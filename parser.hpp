#ifndef CommandParser_HPP
#define CommandParser_HPP

#include <iostream>
#include <vector>
#include <sstream>
#include <iomanip>
#include <bitset>
#include <string>
#include <cstdlib>

#include <boost/program_options.hpp>
#include <boost/asio/ip/address.hpp>

#include "exceptions.hpp"
#include "action.hpp"
#include "functions.hpp"


namespace parser
{
    // сокращения для байт/сек
    const std::vector<std::string> pref_b = { "b/s", "Kb/s", "Mb/s",
                                              "Gb/s", "Tb/s", "Pb/s" };
    // сокращения для пакет/сек
    const std::vector<std::string> pref_p = { "p/s", "Kp/s", "Mp/s",
                                              "Gp/s", "Tp/s", "Pp/s" };
    // сокращения для количества байт
    const std::vector<std::string> size_b = { "b", "Kb", "Mb",
                                              "Gb", "Tb", "Pb" };
    // сокращения для количества пакетов 
    const std::vector<std::string> size_p = { "p", "Kp", "Mp",
                                              "Gp", "Tp", "Pp" };
    // возможные символы для указания типа сравнения
    const std::vector<char> comp_t = { '=', '>', '<' };

    /*
     класс для разбора строкового представления правил и парсинга команд
    */
    class CommandParser
    {
    public:
        explicit CommandParser(
            const  boost::program_options::options_description& opt);
        /*
         добавление опций в текущий options_
         @param opt: добавляемые опции
        */
        void add_opt(const boost::program_options::options_description& opt);
        /*
         парсинг правила, проверка параметров на ошибочные
         @param tokenize_input: строка правила разбитая в вектор по пробелам
        */
        boost::program_options::variables_map parse(
            const std::vector<std::string>& tokenize_input);
        /*
         вывод справки по камандам из текущего options_
        */
        void help() const;
        /*
         обратная операция - склейка vector<string> в одну строку
         @param v: вектор строк который нужно склеить
        */
        static std::string join(const std::vector<std::string>& v);
    private:
        boost::program_options::options_description options_;
    };

    // FUNCTIONS parser::
    /*
     парсинг строки с ip адресом (1.1.1.1) или ip сетью (1.1.1.1/24) в
     NumRange представление: start_ip и end_ip. Функция конвертирует ip
     адрес из CIDR представления в ulong, высчитывает первый и последний
     адрес по маске подсети и формирует из них pair<uint32_t, uint32_t>
     Если функции передается строка с ip адресов без подсети, то
     pair.first=pair.second.
    */
    std::pair<uint32_t, uint32_t> range_from_ip_string(const std::string& ipstr);
    /*
     парсинг диапозона значений из строки: <num>-<num> или <num>.
     Если передается одно число, без "-", то return pair.first=pair.second
    */
    std::pair<uint16_t, uint16_t> range_from_port_string(const std::string& portstr);
    /*
     преобразование числа в короткую запись с указанием типа (например: 10Mb).
     @param size: преобразыемое число
     @param its_byte: тип числа, байты или пакеты (Mp или Mb)
    */
    std::string to_short_size(unsigned long int size, bool its_byte = true);
    /*
     преобразует короткую запись числа с типом в число uint64_t.
     @param size: строка которую надо преобразовать
     @param its_byte: тип числа, байты или пакеты (Mp или Mb)
    */
    uint64_t from_short_size(const std::string& size, bool its_byte = true);
    /*
     преобразование строкового правила action в экземпляр класса action::Action
     Функция проверяет соответствие формату <type>:<param>
    */
    action::Action action_from_string(const std::string& value);
    /*
     преобразование правила сравнения (формат: >num, <num, =num) в
     pair<T,type_comp> где type_comp число соответствующее типу операции
     сравненияЖ 0 это =, > это 1, < это 2 (см. const comp_t).
    */
    template<typename T>
    std::pair<T, unsigned short int> numcomp_from_string(const std::string& value)
    {
        if(value.length() < 2)
        {
            throw ParserException("parametr '" + value + "' is too short, must be '>num', '=num' or '<num'");
        }
        size_t bad = 0;
        unsigned long int num;
        try
        {
            //num = std::atoi(value.substr(1).c_str());
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
    /*
     преобразование строки вида: f1:0,f2:1,f3:1,fn:[0,1] в pair<bits,mask>,
     где bits - это bitset сотсояния флагов, т.е. 0 и 1 из примера fn:[0,1]
     a mask - это bitset-маска указывающая какие биты проверять. Каждый флаг
     проверяется на корректность по списку accept_flags, из него же берется
     положение.

     Пример:
     vector<char> f_accept = { 'U', 'A', 'P', 'R', 'S', 'F' };
     pair<bitset<6>, bitset<6>> ex;
     ex = bitset_from_string<bitset<6>>("U:0,S:1,F:0");
     cout << "bits: " << ex.first << endl;
     cout << "mask: " << ex.second << endl;

     Результат:
     bits: 000010
     mask: 100011
    */
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