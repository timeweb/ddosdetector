#include "action.hpp"


namespace action
{
	// job functions
	void job_log(std::string& to, std::string& data)
	{
		std::cout << "JOB_LOG: " << to << " " << data << std::endl;
	}
	void job_script(std::string& to, std::string& data)
	{
		std::cout << "JOB_SCRIPT: " << to << " " << data << std::endl;
	}
	void job_dump(std::string& to, std::string& data)
	{
		std::cout << "JOB_DUMP: " << to << " " << data << std::endl;
	}
	void job_syslog(std::string& to, std::string& data)
	{
		std::cout << "JOB_SYSLOG: " << to << " " << data << std::endl;
	}

	// map of types job
	types_map_t type_list::jobs = {
		{"log", std::bind(&job_log, std::placeholders::_1, std::placeholders::_2)},
		{"script", std::bind(&job_script, std::placeholders::_1, std::placeholders::_2)},
		{"dump", std::bind(&job_dump, std::placeholders::_1, std::placeholders::_2)},
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

	// actions
	action::action()
		: type("syslog"), file("") {}
	action::action(const action& other)
		: type(other.type), file(other.file) {}
	action::action(std::string& t)
		: file("")
	{
		parse(t);
	}
	action::action(std::string& t, std::string& j)
		: file(j)
	{
		parse(t);
	}
	void action::parse(std::string& t)
	{
		auto it_t = type_list::find(t);
		if(it_t == type_list::end())
			throw parser::exception("incorrect action job type '" + t + "'");
		type = t;
	}
	action& action::operator=(const action& other)
	{
		if (this != &other)
		{
			type = other.type;
			file = other.file;
		}
		return *this;
	}

	job::job()
		: action(), data("") {}
	job::job(action& a, std::string d)
		: action(a), data(d) {}
	void job::run()
	{
		auto it_t = type_list::find(type);
		if(it_t != type_list::end() && data != "")
			it_t->second(file, data);
	}
}
