#include "controld.hpp"


session::session(boost::asio::ip::tcp::tcp::socket socket, std::shared_ptr<rcollection> c)
	: socket_(std::move(socket)), collect_(c)
{
	client_ip_ = socket_.remote_endpoint().address().to_string();
}
session::~session()
{
	logger << log4cpp::Priority::DEBUG << "Client " << client_ip_ << " close connection";
}
void session::start()
{
	logger << log4cpp::Priority::DEBUG << "Client " << client_ip_ << " connected";
	do_read();
}
void session::do_read()
{
	do_write(cli);
	auto self(shared_from_this()); // Это делается для того, чтобы убедиться, что объект соединения переживет асинхронной операции: (. Т.е. асинхронной операция продолжается) до тех пор, как лямбда жив, экземпляр соединения жив, а также.
	memset(data_, 0, max_length); // зануляем буфер
	socket_.async_read_some(boost::asio::buffer(data_, max_length-1),
		[this, self](boost::system::error_code ec, std::size_t length)
		{
			if (!ec)
			{
				cmd_ += std::string(data_);
				if(cmd_.find('\n') != std::string::npos)
				{
					for(char& c: bad_symbols) // удаляем символы \n \r и т.д.
						cmd_.erase(std::remove(cmd_.begin(), cmd_.end(), c), cmd_.end());
					try
					{
						parse();
					}
					catch(...)
					{
						return;
					}
					cmd_ = "";
				}
				do_read();
			}
		}
	);
}
void session::do_read_signal() // TODO: добавить отлов сигнала Ctrl^D
{
	auto self(shared_from_this());
	memset(data_, 0, max_length);
	socket_.async_read_some(boost::asio::buffer(data_, max_length-1),
		[this, self](boost::system::error_code ec, std::size_t length)
		{
			if (!ec)
			{
				if(*data_ == 0x04) // Catch Ctrl^D signal for stoping monitor commands
					throw;
			}
		}
	);
}
void session::do_write(std::string msg)
{
	auto self(shared_from_this());
	memset(data_, 0, max_length); // зануляем буфер
	if(msg.length() > max_length)
	{
		strncpy(data_, msg.substr(0, max_length).c_str(), max_length);
	}
	else
	{
		strncpy(data_, msg.c_str(), msg.length());
	}
	boost::asio::async_write(socket_, boost::asio::buffer(data_, strlen(data_)),
		[this, self, msg](boost::system::error_code ec, std::size_t /*length*/)
		{
			if (!ec)
			{
				if(msg.length() > max_length)
					do_write(msg.substr(max_length, msg.length()));
			}
		}
	);
}
void session::parse()
{
	std::vector<std::string> t_cmd = command_parser::tokenize(cmd_);
	unsigned int words = t_cmd.size();
	if(words == 0)
		return;
	if(words == 1)
	{
		if(t_cmd[0] == "exit") // exit
			throw 1;
		if(t_cmd[0] == "help" || t_cmd[0] == "?") // help || ?
		{
			std::string help = "Console commands:";
			help += "<type> - may be TCP, UDP or ICMP; <num> - number (0..65535);\n";
			help += "  help                                show this help\n";
			help += "  add rule <type> <rule>              add new rule\n";
			help += "  insert rule <type> <num> <rule>     insert new rule by number\n";
			help += "  del rule <type> <num>               add new rule\n";
			help += "  show rules                          print all rules with counters\n";
			help += "  exit                                close connection\n";
			help += "\n\n" + collect_->get_help();
			do_write(help);
			return;
		}
	}
	try
	{
		if(words == 2)
		{
			if(t_cmd[0] == "show" && t_cmd[1] == "rules") // show rules
			{
				do_write(collect_->get_rules());
				return;
			}
			// TODO: сделать monitor rules команду, с обновлением раз в секунду
			// if(t_cmd[0] == "monitor" && t_cmd[1] == "rules") // show rules
			// {
			// 	for(int i=0; i<10; i++)
			// 	{

			// 		do_write("\033[2J\033[1;1H");
			// 		do_write(collect_->get_rules());
			// 		do_write("Use Ctrl^D for exit\n");
			// 		try { do_read_signal(); } catch(...) { continue; }
			// 		sleep(1);
			// 	}
			// 	return;
			// }
		}
		if(words >= 4)
		{
			if(t_cmd[1] == "rule") // add rules || del rules
			{
				if(!collect_->is_type(t_cmd[2]))
					throw parser::exception("Not found rule type '" + t_cmd[2] + "'");
				if(t_cmd[2] == "TCP")
				{
					if(t_cmd[0] == "add" && words > 4)
					{
						collect_->tcp.add_rule(tcp_rule(std::vector<std::string>(t_cmd.begin() + 3, t_cmd.end())));
						return;
					}
					int num = std::stoi(t_cmd[3]);
					if(t_cmd[0] == "insert" && words > 4)
					{
						collect_->tcp.insert_rule(num, tcp_rule(std::vector<std::string>(t_cmd.begin() + 4, t_cmd.end())));
					}
					if(t_cmd[0] == "del" && words == 4)
					{
						collect_->tcp.del_rule(num);
					}
				}
				return;
			}
		}
		do_write("Error: unknown command '" + cmd_ + "'. Please print 'help'.\n");
	}
	catch(const std::invalid_argument& e)
	{
		do_write("Error: parametr '<num>' not number. Please print 'help'.\n");
	}
	catch(const parser::exception& e)
	{
		do_write("Error parse rule: " + std::string(e.what()) + "\n");
	}
	catch(const rule::exception& e)
	{
		do_write("Error operation rule: " + std::string(e.what()) + "\n");
	}
	catch(...)
	{
		do_write("Ooops: very very bad command ;)'" + cmd_ + "'.\n");
	}
}


server::server(boost::asio::io_service& io_service, short port, std::shared_ptr<rcollection> c)
	: acceptor_(io_service, boost::asio::ip::tcp::tcp::endpoint(boost::asio::ip::tcp::tcp::v4(), port)),
		socket_(io_service), collect_(c)
{
	do_accept();
}
void server::do_accept()
{
	acceptor_.async_accept(socket_,
		[this](boost::system::error_code ec)
		{
			if (!ec)
			{
				try
				{
					std::make_shared<session>(std::move(socket_), std::ref(collect_))->start();
				}
				catch(...)
				{}
			}
			do_accept();
		}
	);
}