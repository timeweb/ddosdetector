#ifndef EXCEPTIONS_HPP
#define EXCEPTIONS_HPP

#include <stdexcept>

class ParserException: public std::exception
{
public:
    explicit ParserException(const std::string& message);
    virtual const char* what() const throw();
private:
    std::string message_;
};

class RuleException: public std::exception
{
public:
    explicit RuleException(const std::string& message);
    virtual const char* what() const throw();
private:
    std::string message_;
};

class NetmapException: public std::exception
{
public:
    explicit NetmapException(const std::string& message);
    virtual const char* what() const throw();
private:
    std::string message_;
};


#endif // end EXCEPTIONS_HPP