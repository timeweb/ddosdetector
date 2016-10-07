#include "influxdb.hpp"


InfluxClient::InfluxClient(const std::string& host, const unsigned int port,
                 const std::string& db, const std::string& user,
                 const std::string& pass, const std::string& use)
    : host_(host), port_(port), database_(db), user_(user), pass_(pass),
      enable_((use == "yes") ? true : false) {}
int InfluxClient::insert(const std::string& query)
{
    if(!enable_)
    {
        return 0;
    }
    std::string url = "http://" + host_ 
                    + ":" + std::to_string(port_)
                    + "/write?db=" + database_;
    // logger.debug("Send data to InfluxDB %s with %s:%s", url.c_str()
    //                                                   , user_.c_str()
    //                                                   , pass_.c_str());
    curl_ = curl_easy_init();
    if(!curl_) {
        return -1;
    }
    if(user_ != "" && pass_ != "")
    {
        curl_easy_setopt(curl_, CURLOPT_HTTPAUTH, CURLAUTH_BASIC);
        curl_easy_setopt(curl_, CURLOPT_USERPWD, (user_ + ":" + pass_).c_str());
    }
    curl_easy_setopt(curl_, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl_, CURLOPT_POST, 1);
    curl_easy_setopt(curl_, CURLOPT_POSTFIELDS, query.c_str());
    code_ = curl_easy_perform(curl_);
    curl_easy_cleanup(curl_);
    return (int)code_;
}
bool InfluxClient::is_enable() const
{
    return enable_;
}