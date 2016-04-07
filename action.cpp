#include "action.hpp"


namespace action
{
    // job functions
    void job_log(std::string& to, std::string& data)
    {
        logger << log4cpp::Priority::DEBUG << "JOB_LOG: " << to << " " << data;
        std::ofstream ofs(to, std::ios::out | std::ios::app);
        if(ofs)
        {
            ofs << "trigger alarm: " << data << "\n";
        }
        else
        {
            logger << log4cpp::Priority::ERROR
                << "do not have access to the log file "
                << to;
        }
        ofs.close();
    }
    void job_script(std::string& to, std::string& data)
    {
        logger << log4cpp::Priority::DEBUG << "JOB_SCRIPT: " << to << " " << data;
        std::string cmd = to + " \"" + data + "\" 2>1 /dev/null &";
        if(system(cmd.c_str()) == -1)
        {
            logger << log4cpp::Priority::ERROR
                << "run command: "
                << to << " "
                << data << " failed";
        }
    }
    // void job_dump(std::string& to, std::string& data)
    // {
    //  logger << log4cpp::Priority::DEBUG << "JOB_DUMP: " << to << " " << data;
    // }
    void job_syslog(std::string& to, std::string& data)
    {
        logger << log4cpp::Priority::DEBUG
            << "JOB_SYSLOG: "
            << to << " "
            << data;
        syslog(LOG_DAEMON, "trigger alarm: %s", data.c_str());
    }

    // map of types job
    types_map_t type_list::jobs = {
        {"log", std::bind(&job_log, std::placeholders::_1, std::placeholders::_2)},
        {"script", std::bind(&job_script, std::placeholders::_1, std::placeholders::_2)},
        //{"dump", std::bind(&job_dump, std::placeholders::_1, std::placeholders::_2)},
        {"syslog", std::bind(&job_syslog, std::placeholders::_1, std::placeholders::_2)}
    };
    types_map_t::iterator type_list::find(std::string& v)
    {
        return jobs.find(v);
    }
    types_map_t::iterator type_list::end()
    {
        return jobs.end();
    }

    // Actions
    Action::Action()
        : type_("syslog"), file_("") {}
    Action::Action(const Action& other)
        : type_(other.type_), file_(other.file_) {}
    Action::Action(std::string& t)
        : file_("")
    {
        parse(t);
    }
    Action::Action(std::string& t, std::string& j)
        : file_(j)
    {
        parse(t);
    }
    void Action::parse(std::string& t)
    {
        auto it_t = type_list::find(t);
        if(it_t == type_list::end())
            throw ParserException("incorrect Action job type '" + t + "'");
        type_ = t;
    }
    Action& Action::operator=(const Action& other)
    {
        if (this != &other)
        {
            type_ = other.type_;
            file_ = other.file_;
        }
        return *this;
    }

    TriggerJob::TriggerJob()
        : Action(), data_("") {}
    TriggerJob::TriggerJob(Action& a, std::string d)
        : Action(a), data_(d) {}
    void TriggerJob::run()
    {
        auto it_t = type_list::find(type_);
        if(it_t != type_list::end() && data_ != "")
            it_t->second(file_, data_);
    }
}
