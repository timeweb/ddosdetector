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

// Get log4cpp logger from main programm
extern log4cpp::Category& logger;

namespace action
{
    void job_log(std::string& to, std::string& data);
    void job_script(std::string& to, std::string& data);
    //void job_dump(std::string& to, std::string& data); // FUTURE: create dump traffic and store to .pcap file
    void job_syslog(std::string& to, std::string& data);

    typedef std::function<void(std::string&, std::string&)> j_funct;
    typedef std::map<std::string, j_funct> types_map_t;
    struct type_list
    {
        static types_map_t jobs;
        static types_map_t::iterator find(std::string& v);
        static types_map_t::iterator end();
    };

    class Action
    {
    public:
        Action();
        Action(const Action& other);
        explicit Action(std::string& t);
        Action(std::string& t, std::string& j);
        void parse(std::string& t);
        Action& operator=(const Action& other);
    protected:
        std::string type_; // may be: log, script, dump
        std::string file_; // file name, path to script etc.
    };

    class TriggerJob : public Action
    {
    public:
        TriggerJob();
        TriggerJob(Action& a, std::string d);
        void run();
    private:
        std::string data_;
    };
}

#endif // end Action_HPP