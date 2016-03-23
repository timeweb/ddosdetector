#ifndef EXCEPTIONS_HPP
#define EXCEPTIONS_HPP

#include <stdexcept>

namespace parser
{
	class exception: public std::exception
	{
	private:
		std::string message_;
	public:
		explicit exception(const std::string& message) 
			: message_(message) {};
		virtual const char* what() const throw()
		{
			return message_.c_str();
		}
	};
}

namespace rule
{
	class exception: public std::exception
	{
	private:
		std::string message_;
	public:
		explicit exception(const std::string& message) 
			: message_(message) {};
		virtual const char* what() const throw()
		{
			return message_.c_str();
		}
	};
}

class NetmapException: public std::exception
{
private:
	std::string message_;
public:
	explicit NetmapException(const std::string& message) 
		: message_(message) {};
	virtual const char* what() const throw()
	{
		return message_.c_str();
	}
};

#endif // end EXCEPTIONS_HPP