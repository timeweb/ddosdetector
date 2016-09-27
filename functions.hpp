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

/*
 инициализация логера logger, определение уровня логирования и цели
 куда будет писаться лог.
 @param debug: режим отладки
 @param file: файл куда писать лог, если =="", то вывод в консоль
*/
void init_logging(log4cpp::Category& logger, bool debug,
                  const std::string& file);
/*
 переключение сетевой карты в режим promisc on
*/
#ifdef __linux__
bool manage_interface_promisc_mode(const std::string& interface_name,
                                   bool switch_on);
#endif
/*
 преобразует имя интерфейса в netmap формат, т.е. из eth5 сделает
 netmap:eth5 как требуется для запуска nm_open() функции из библиотеки
 Если в названии интерфейса уже есть "netmap:", то изменения не производятся
*/
std::string get_netmap_intf(const std::string& intf);
/*
 проверяет существует ли файл, проверка выполняется через unix stat
*/
bool is_file_exist(const std::string& file_name);
/*
 проверяет исполняемый ли файл
*/
bool is_executable(const std::string& file_name);
/*
 форматирует строку по определенной длинне для выравнивания вывода
 @param s: строка
 @param len: минимальная длинна выходной строки
*/
std::string format_len(const std::string& s, unsigned int len);
/*
 делит строку input на элементы по признаку separator и формирует
 результат в vector<string>
*/
typedef boost::escaped_list_separator<char> separator_type;
std::vector<std::string> tokenize(const std::string& input,
                                  const separator_type& separator);
std::vector<std::string> tokenize(const std::string& input);
/*
 возвращает номер элемента value в списке vec, или вызывает исключение
 @param vec: вектор в котором искать элемент
 @param value: элемент который необходимо искать
*/
template<typename T>
int get_index(const std::vector<T>& vec, const T& value)
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

template <typename T>
std::string to_string(T val)
{
    std::stringstream stream;
    stream << val;
    return stream.str();
}

#endif // end FUNCTIONS_HPP