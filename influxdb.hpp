#ifndef INFLUXDB_HPP
#define INFLUXDB_HPP

#include <curl/curl.h>
#include <iostream>

// Logging
#include "log4cpp/Category.hh"
#include "log4cpp/Priority.hh"

// Get log4cpp logger from main programm
extern log4cpp::Category& logger;

class InfluxClient
{
public:
    InfluxClient(const std::string& host, const unsigned int port,
                 const std::string& db, const std::string& user,
                 const std::string& pass, const std::string& use);
    int insert(const std::string& query);
    bool is_enable() const;
private:
    std::string host_;
    unsigned int port_;
    std::string database_;
    std::string user_;
    std::string pass_;
    bool enable_;
    CURL *curl_;
    CURLcode code_;
};

#endif // end INFLUXDB_HPP