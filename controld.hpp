#ifndef CONTROLD_HPP
#define CONTROLD_HPP
#include <iostream>
#include <boost/asio.hpp>
#include <boost/thread.hpp>

// Logging
#include "log4cpp/Category.hh"
#include "log4cpp/Priority.hh"

#include "parser.hpp"
#include "rules.hpp"

// Get log4cpp logger from main programm
extern log4cpp::Category& logger;

class session
	: public std::enable_shared_from_this<session>
{
public:
	session(boost::asio::ip::tcp::tcp::socket socket, std::shared_ptr<rcollection> c);
	~session();
	void start();

private:
	void do_read();
	void do_read_signal();
	void do_write(std::string msg);
	void parse();

	boost::asio::ip::tcp::tcp::socket socket_;
	std::string client_ip_;
	std::shared_ptr<rcollection> collect_;
	enum { max_length = 1024 };
	char data_[max_length];
	std::string cmd_;
	const std::string cli = "ddoscontrold> ";
	std::string bad_symbols{'\n', '\r', '\0'};
};

class server
{
public:
	server(boost::asio::io_service& io_service, short port, std::shared_ptr<rcollection> c);
private:
	void do_accept();

	boost::asio::ip::tcp::tcp::acceptor acceptor_;
	boost::asio::ip::tcp::tcp::socket socket_;
	std::shared_ptr<rcollection> collect_;
};

#endif // end CONTROLD_HPP