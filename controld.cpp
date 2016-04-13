#include "controld.hpp"

using namespace boost::asio;

template<class T>
ControlSession<T>::ControlSession(T socket,
        const std::shared_ptr<RulesCollection> c)
    : socket_(std::move(socket)), collect_(c)
{
    memset(data_, 0, max_length);
}
template<class T>
ControlSession<T>::~ControlSession()
{
    logger << log4cpp::Priority::DEBUG << "Client close connection";
}
template<class T>
void ControlSession<T>::start()
{
    logger << log4cpp::Priority::DEBUG << "Client connected";
    do_read();
}
template<class T>
void ControlSession<T>::do_read()
{
    do_write(cli_);
    auto self(this->shared_from_this());
    memset(data_, 0, max_length); // зануляем буфер
    socket_.async_read_some(buffer(data_, max_length-1),
        [this, self](boost::system::error_code ec, std::size_t length)
        {
            if (!ec)
            {
                cmd_ += std::string(data_);
                if(cmd_.find('\n') != std::string::npos)
                {
                    for(char& c: bad_symbols_) // удаляем символы \n \r и т.д.
                        cmd_.erase(std::remove(cmd_.begin(), cmd_.end(), c),
                                   cmd_.end());
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
template<class T>
void ControlSession<T>::do_read_signal() // FUTURE: добавить отлов сигнала Ctrl^D
{
    auto self(this->shared_from_this());
    memset(data_, 0, max_length);
    socket_.async_read_some(buffer(data_, max_length-1),
        [this, self](boost::system::error_code ec, std::size_t length)
        {
            if (!ec)
            {
                // Catch Ctrl^D signal for stoping monitor commands
                if(*data_ == 0x04) 
                    throw;
            }
        }
    );
}
template<class T>
void ControlSession<T>::do_write(const std::string& msg)
{
    auto self(this->shared_from_this());
    // memset(data_, 0, max_length);
    // if(msg.length() > max_length)
    // {
    //  strncpy(data_, msg.substr(0, max_length).c_str(), max_length);
    // }
    // else
    // {
    //  strncpy(data_, msg.c_str(), msg.length());
    // }
    async_write(socket_, buffer(msg),
        [this, self, msg](boost::system::error_code ec, std::size_t length)
        {
            if (!ec)
            {
                // if(msg.length() > max_length)
                // {
                //  do_write(msg.substr(max_length));
                // }
            }
        }
    );
}
template<class T>
void ControlSession<T>::parse()
{
    std::vector<std::string> t_cmd = tokenize(cmd_);
    unsigned int words = t_cmd.size();
    if(words == 0)
        return;
    if(words == 1)
    {
        if(t_cmd[0] == "exit") // exit
            throw 1;
        if(t_cmd[0] == "help" || t_cmd[0] == "?") // help || ?
        {
            std::string h = help_ + "\n\n" + collect_->get_help();
            do_write(h);
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
            if(t_cmd[0] == "reload" && t_cmd[1] == "rules") // show rules
            {
                raise(1);
                return;
            }
            // TODO: сделать monitor rules команду, с обновлением раз в секунду
            // if(t_cmd[0] == "monitor" && t_cmd[1] == "rules") // show rules
            // {
            //  for(int i=0; i<10; i++)
            //  {

            //      do_write("\033[2J\033[1;1H");
            //      do_write(collect_->get_rules());
            //      do_write("Use Ctrl^D for exit\n");
            //      try { do_read_signal(); } catch(...) { continue; }
            //      sleep(1);
            //  }
            //  return;
            // }
        }
        if(words >= 4)
        {
            if(t_cmd[1] == "rule") // add rules || del rules
            {
                if(!collect_->is_type(t_cmd[2]))
                    throw ParserException("Not found rule type '"
                                          + t_cmd[2] + "'");
                if(t_cmd[2] == "TCP")
                {
                    if(t_cmd[0] == "add" && words > 4)
                    {
                        collect_->tcp.add_rule(
                            TcpRule(
                                std::vector<std::string>(
                                    t_cmd.begin() + 3, t_cmd.end()
                                )
                            )
                        );
                        return;
                    }
                    int num = std::atoi(t_cmd[3].c_str());
                    if(t_cmd[0] == "insert" && words > 4)
                    {
                        collect_->tcp.insert_rule(
                            num,
                            TcpRule(
                                std::vector<std::string>(
                                    t_cmd.begin() + 4, t_cmd.end()
                                )
                            )
                        );
                    }
                    if(t_cmd[0] == "del" && words == 4)
                    {
                        collect_->tcp.del_rule(num);
                    }
                }
                else if(t_cmd[2] == "UDP")
                {
                    if(t_cmd[0] == "add" && words > 4)
                    {
                        collect_->udp.add_rule(
                            UdpRule(
                                std::vector<std::string>(
                                    t_cmd.begin() + 3, t_cmd.end()
                                )
                            )
                        );
                        return;
                    }
                    int num = std::atoi(t_cmd[3].c_str());
                    if(t_cmd[0] == "insert" && words > 4)
                    {
                        collect_->udp.insert_rule(
                            num,
                            UdpRule(
                                std::vector<std::string>(
                                    t_cmd.begin() + 4, t_cmd.end()
                                )
                            )
                        );
                    }
                    if(t_cmd[0] == "del" && words == 4)
                    {
                        collect_->udp.del_rule(num);
                    }
                }
                else if(t_cmd[2] == "ICMP")
                {
                    if(t_cmd[0] == "add" && words > 4)
                    {
                        collect_->icmp.add_rule(
                            IcmpRule(
                                std::vector<std::string>(
                                    t_cmd.begin() + 3, t_cmd.end()
                                )
                            )
                        );
                        return;
                    }
                    int num = std::atoi(t_cmd[3].c_str());
                    if(t_cmd[0] == "insert" && words > 4)
                    {
                        collect_->icmp.insert_rule(
                            num,
                            IcmpRule(
                                std::vector<std::string>(
                                    t_cmd.begin() + 4, t_cmd.end()
                                )
                            )
                        );
                    }
                    if(t_cmd[0] == "del" && words == 4)
                    {
                        collect_->icmp.del_rule(num);
                    }
                }
                return;
            }
        }
        do_write("Error: unknown command '"
                 + cmd_
                 + "'. Please print 'help'.\n");
    }
    catch(const std::invalid_argument& e)
    {
        do_write("Error: invalid argument '"
                 + std::string(e.what())
                 + "'. Please print 'help'.\n");
    }
    catch(const ParserException& e)
    {
        do_write("Error parse rule: " + std::string(e.what()) + "\n");
    }
    catch(const RuleException& e)
    {
        do_write("Error operation rule: " + std::string(e.what()) + "\n");
    }
    catch(...)
    {
        do_write("Ooops: very very bad command ;)'" + cmd_ + "'.\n");
    }
}


ControlServer::ControlServer(io_service& io_service, const std::string& port,
        std::shared_ptr<RulesCollection> collect)
    : is_unix_socket_(true), port_(port), collect_(collect)
{
    short num_port = 0;
    try
    {
        num_port = boost::lexical_cast<short>(port_);
        is_unix_socket_ = false;
    }
    catch(boost::bad_lexical_cast &) {}
    if(is_unix_socket_)
    {
        local::stream_protocol::endpoint ep(port_);
        unix_acceptor_ = std::make_shared<local::stream_protocol::stream_protocol::acceptor>(io_service, ep);
        unix_socket_ = std::make_shared<local::stream_protocol::stream_protocol::socket>(io_service);
        logger.info("Start controld unix socket server on " + port_);
        do_unix_accept();
    }
    else
    {
        ip::tcp::tcp::endpoint ep(ip::tcp::tcp::v4(), num_port);
        tcp_acceptor_ = std::make_shared<ip::tcp::tcp::acceptor>(io_service, ep);
        tcp_socket_ = std::make_shared<ip::tcp::tcp::socket>(io_service);
        logger.info("Start controld tcp server on " + to_string(num_port));
        do_tcp_accept();
    }
}
ControlServer::~ControlServer()
{
    if(is_unix_socket_ && is_file_exist(port_))
    {
        remove(port_.c_str());
    }
}
void ControlServer::do_tcp_accept()
{
    tcp_acceptor_->async_accept(*tcp_socket_,
        [this](boost::system::error_code ec)
        {
            if (!ec)
            {
                try
                {
                    std::make_shared<ControlSession<ip::tcp::tcp::socket>>
                        (
                            std::move(*tcp_socket_),
                            std::ref(collect_)
                        )->start();
                }
                catch(...)
                {}
            }
            do_tcp_accept();
        }
    );
}
void ControlServer::do_unix_accept()
{
    unix_acceptor_->async_accept(*unix_socket_,
        [this](boost::system::error_code ec)
        {
            if (!ec)
            {
                try
                {
                    std::make_shared<ControlSession<local::stream_protocol::stream_protocol::socket>>
                        (
                            std::move(*unix_socket_),
                            std::ref(collect_)
                        )->start();
                }
                catch(...)
                {}
            }
            do_unix_accept();
        }
    );
}


template class ControlSession<ip::tcp::tcp::socket>;
template class ControlSession<local::stream_protocol::stream_protocol::socket>;
