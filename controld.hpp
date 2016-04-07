#ifndef CONTROLD_HPP
#define CONTROLD_HPP
#include <stdio.h>
#include <signal.h>
#include <iostream>
#include <boost/asio.hpp>
#include <boost/thread.hpp>
//#include <type_traits>
#include <boost/lexical_cast.hpp>

// Logging
#include "log4cpp/Category.hh"
#include "log4cpp/Priority.hh"

#include "functions.hpp"
#include "parser.hpp"
#include "rules.hpp"

// Get log4cpp logger from main programm
extern log4cpp::Category& logger;

template<class T>
class ControlSession
    : public std::enable_shared_from_this<ControlSession<T>>
{
public:
    ControlSession(T socket, std::shared_ptr<RulesCollection> c);
    ~ControlSession();
    void start();

private:
    void do_read();
    void do_read_signal();
    void do_write(std::string msg);
    void parse();

    T socket_;
    std::shared_ptr<RulesCollection> collect_;
    enum { max_length = 4096 };
    char data_[max_length];
    std::string cmd_;
    const std::string cli = "ddoscontrold> ";
    std::string bad_symbols{'\n', '\r', '\0'};
};

class ControlServer
{
public:
    ControlServer(boost::asio::io_service& io_service, const std::string& p, std::shared_ptr<RulesCollection> c);
    ~ControlServer();
private:
    void do_tcp_accept();
    void do_unix_accept();

    bool unix_socket;
    std::string port;
    std::shared_ptr<boost::asio::ip::tcp::tcp::acceptor> tcp_acceptor_;
    std::shared_ptr<boost::asio::ip::tcp::tcp::socket> tcp_socket_;
    std::shared_ptr<boost::asio::local::stream_protocol::acceptor> unix_acceptor_;
    std::shared_ptr<boost::asio::local::stream_protocol::stream_protocol::socket> unix_socket_;
    std::shared_ptr<RulesCollection> collect_;
};

#endif // end CONTROLD_HPP