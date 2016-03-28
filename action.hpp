#ifndef ACTION_HPP
#define ACTION_HPP

#include <iostream>
#include <map>
#include <vector>
#include <functional>
#include <algorithm>

#include "exceptions.hpp"

namespace action
{
	void job_log(std::string& to, std::string& data);
	void job_script(std::string& to, std::string& data);
	void job_dump(std::string& to, std::string& data);
	void job_syslog(std::string& to, std::string& data);

	typedef std::function<void(std::string&, std::string&)> j_funct;
	typedef std::map<std::string, j_funct> types_map_t;
	struct type_list
	{
		static types_map_t jobs;
		static types_map_t::iterator find(std::string& v);
		static types_map_t::iterator end();
	};

	class action
	{
	protected:
		std::string type; // may be: log, script, dump
		std::string file; // file name, path to script etc.
	public:
		action();
		action(const action& other);
		explicit action(std::string& t);
		action(std::string& t, std::string& j);
		void parse(std::string& t);
		action& operator=(const action& other);
	};

	class job : public action
	{
	private:
		std::string data;
	public:
		job();
		job(action& a, std::string d);
		void run();
	};
}

#endif // end ACTION_HPP