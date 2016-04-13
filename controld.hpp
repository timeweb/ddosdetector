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

/*
 Класс клиентской сессии. Обрабатывает подключение одного клиента,
 занимается распарсиванием команд полученных от клиента, выводит данные
 по запрошенным командам.
*/
template<class T>
class ControlSession
    : public std::enable_shared_from_this<ControlSession<T>>
{
public:
    ControlSession(T socket, const std::shared_ptr<RulesCollection> c);
    ~ControlSession();
    // запуск процесса обработчки сессии
    void start();

private:
    // получение данных от клиента, читает в буфер data_, размером max_length и
    // складывает данные в cmd_ пока не встретится символ завершения команды: \n
    void do_read();
    // FUTURE: функция, для отлова сигнала Ctrl^D (пока не используется)
    void do_read_signal();
    // отправка данных от клиента
    void do_write(const std::string& msg);
    // парсер команд полученных от клиента
    void parse();

    T socket_;
    // ссылка на эталонную коллекцию правил, для изменения
    std::shared_ptr<RulesCollection> collect_;
    // буфер
    enum { max_length = 4096 };
    char data_[max_length];
    // полученная команда от клиента
    std::string cmd_;
    // приветствие в консоли
    const std::string cli_ = "ddoscontrold> ";
    // символы удаляемые из полученных команд
    std::string bad_symbols_{'\n', '\r', '\0'};
    // help текст
    const std::string help_ = "Console commands:"
        "<type> - may be TCP, UDP or ICMP; <num> - number (0..65535);\n"
        "  help                                show this help\n"
        "  add rule <type> <rule>              add new rule\n"
        "  insert rule <type> <num> <rule>     insert new rule by number\n"
        "  del rule <type> <num>               add new rule\n"
        "  show rules                          print all rules with counters\n"
        "  reload rules                        reload all rules from file\n"
        "  exit                                close connection\n";
};

/*
 Класс TCP/UNIX сервер. При инициализации определается тип сервера. Если port -
 это число, то запускается TCP сервер на порту port. Если port - это путь к
 файлу, то запускается UNIX сервер.
*/
class ControlServer
{
public:
    /*
     Инициализация сервера.
     @param io_service: созданный заранее объект io_service
     @param port: порт на котором запускается сервер (либо путь к unix socket)
     @param collect: эталонная коллекция правил
    */
    ControlServer(boost::asio::io_service& io_service, const std::string& port,
                  std::shared_ptr<RulesCollection> collect);
    // деструктор следит за корректным удалением UNIX socket файла
    ~ControlServer();
private:
    // запуск tcp сервера
    void do_tcp_accept();
    // запуск unix сервера
    void do_unix_accept();

    // флаг unix сервера
    bool is_unix_socket_;
    // порт запуска
    std::string port_;
    // acceptors
    std::shared_ptr<boost::asio::ip::tcp::tcp::acceptor> tcp_acceptor_;
    std::shared_ptr<boost::asio::local::stream_protocol::acceptor> unix_acceptor_;
    // сокеты
    std::shared_ptr<boost::asio::ip::tcp::tcp::socket> tcp_socket_;
    std::shared_ptr<boost::asio::local::stream_protocol::stream_protocol::socket> unix_socket_;
    // эталонная коллекция
    std::shared_ptr<RulesCollection> collect_;
};

#endif // end CONTROLD_HPP