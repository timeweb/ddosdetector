#ifndef BASERULE_HPP
#define BASERULE_HPP

#include <iostream>
#include <vector>

#include <boost/program_options.hpp>

#include "../action.hpp"
#include "../parser.hpp"

/*
 Класс числового периода. Используется для хранения какого либо ограничения
 имеющего младшее и старшее число. Например представление посдети ip адресов:
 0.0.0.0/0  0-4294967295 как периода: 0-4294967295 позволяет в даллнейшем
 производить быструю проверку того, что ip адрес принадлежит подсети, с помощью
 функуции in_this().
*/
template<class T>
class NumRange
{
public:
    NumRange();
    explicit NumRange(const std::pair<T, T>& p);
    bool operator==(NumRange const & other) const;
    NumRange& operator=(const std::pair<T, T>& p);
    // проверка, что чилсо есть в периоде
    bool in_this(T num) const;
    // статус параметра (включен или выключен)
    bool stat() const;
    // возвращает период в формате CIDR, конвертируя числа в ip адреса
    std::string to_cidr() const;
    // возвращает период в формате строки запись через знак "-"
    std::string to_range() const;
private:
    // первое число промежутка
    T start_;
    // последнее число промежутка
    T end_;
    // статус
    bool enable_;
};
/*
 Класс сравниваемого числового параметра. Позволяет сохранить число и задать тип
 сравнения с этим числом (=, > или <). В дальнейшем вызов функции in_this()
 сравнит передаваемое число с параметром, причем сравнение будет типа type_
*/
template<class T>
class NumComparable
{
public:
    NumComparable();
    explicit NumComparable(const std::pair<T, unsigned short int>& p);
    bool operator==(NumComparable const & other) const;
    NumComparable& operator=(const std::pair<T, unsigned short int>& p);
    // сравнение num с параметром
    bool in_this(T num) const;
    // представление числа в виде строки с указанием типа сравнения
    std::string to_str() const;
private:
    // число параметра
    T num_;
    // статус
    bool enable_;
    // тип сравнения, модет быть:
    // 0 - это =
    // 1 - это >
    // 2 - это <
    unsigned short int type_;
};


class BaseRule
{
public:
    BaseRule();
    explicit BaseRule(const std::vector<std::string>& tkn_rule);
    void BaseRule_parse(const boost::program_options::variables_map& vm);
    // проверка триггеров правила, если триггер не сработал, то происходит
    // обновление времени в переменных: pps_last_not_triggered и
    // bps_last_not_triggered.
    bool is_triggered();
    std::string BaseRule_info() const;

    // базовые параметры правила
    std::string text_rule;               // текст правила
    action::Action act;                  // действие триггера
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
protected:
    // текст правила разбитый на составляющие (по пробелу или знаку =)
    std::vector<std::string> tokenize_rule;
};

#endif // end BASERULE_HPP