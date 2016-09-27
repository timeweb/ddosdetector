#ifndef Action_HPP
#define Action_HPP

#include <iostream>
#include <map>
#include <vector>
#include <functional>
#include <algorithm>
#include <syslog.h>
#include <stdlib.h>
#include <fstream>

// Logging
#include "log4cpp/Category.hh"
#include "log4cpp/Priority.hh"

#include "exceptions.hpp"
#include "functions.hpp"

// Get log4cpp logger from main programm
extern log4cpp::Category& logger;

namespace action
{
    /*
     Функции-операции. Эти функцию выполняют дейтсвие триггера когда он
     срабатывает.
    */
    // функция записи в лог-файл
    void job_log(const std::string& to, const std::string& data);
    // функция вызова стороннего скрипта
    void job_script(const std::string& to, const std::string& data);
    // фуекция дампа пакетов
    //void job_dump(const std::string& to, const std::string& data); // FUTURE: create dump traffic and store to .pcap file
    // функция записи сообщения в syslog
    void job_syslog(const std::string& to, const std::string& data);

    // допустимые типы заданий
    typedef std::function<void(const std::string&, const std::string&)> j_funct;
    typedef std::map<std::string, j_funct> types_map_t;
    struct type_list
    {
        static types_map_t jobs;
        static types_map_t::iterator find(const std::string& v);
        static types_map_t::iterator end();
    };

    /*
     Класс событие триггера. Содержит данные для вызова задания когда триггер
     сработал.
    */
    class Action
    {
    public:
        Action();
        Action(const Action& other);
        explicit Action(const std::string& type);
        Action(const std::string& type, const std::string& file);
        Action& operator=(const Action& other);
    private:
        // изменение типа задания
        std::string check_type(const std::string& type) const;
    protected:
        // тип задания, может быть: log, script, dump
        std::string type_;
        // имф файла, путь к скрипту, путь к логу и т.д.
        std::string file_;
    };

    /*
     Класс задание триггера. Содержит экземпляр события триггера, а также
     предоставлет интерфейс для выполнения задания заложенного в триггере
    */
    class TriggerJob : public Action
    {
    public:
        TriggerJob();
        TriggerJob(const Action& a, const std::string& d);
        // запуск задания триггера
        void run();
    private:
        // данные для задания триггера
        std::string data_;
    };
}

#endif // end Action_HPP