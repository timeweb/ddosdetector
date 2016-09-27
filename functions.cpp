#include "functions.hpp"


// Get log4cpp logger from main programm
extern log4cpp::Category& logger;

void init_logging(log4cpp::Category& logger, bool debug, const std::string& file)
{
    // Log format
    log4cpp::PatternLayout *layout = new log4cpp::PatternLayout();
    if(debug)
    {
        layout->setConversionPattern("%d [%p] %t %m%n");
        logger.setPriority(log4cpp::Priority::DEBUG);
    }
    else
    {
        layout->setConversionPattern("%d [%p] %m%n");
        logger.setPriority(log4cpp::Priority::INFO);
    }
    // Log destination
    log4cpp::Appender *log_appender;
    if(file != "")
    {
        log_appender = new log4cpp::FileAppender("default", file);
    }
    else
    {
        log_appender = new log4cpp::OstreamAppender("console", &std::cout);
    }
    log_appender->setLayout(layout);
    logger.addAppender(log_appender);
    logger.info("Logger initialized");
}

#ifdef __linux__
bool manage_interface_promisc_mode(const std::string& interface_name, bool switch_on) {
    // We need really any socket for ioctl
    int fd = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);

    if (!fd) {
        logger << log4cpp::Priority::ERROR << "Can't create socket for promisc mode manager";
        return false;
    }

    struct ifreq ethreq;        
    memset(&ethreq, 0, sizeof(ethreq));
    strncpy(ethreq.ifr_name, interface_name.c_str(), IFNAMSIZ);

    int ioctl_res = ioctl(fd, SIOCGIFFLAGS, &ethreq);

    if (ioctl_res == -1) {
        logger << log4cpp::Priority::ERROR << "Can't get interface flags";
        return false;
    }
 
    bool promisc_enabled_on_device = ethreq.ifr_flags & IFF_PROMISC;

    if (switch_on) {
        if (promisc_enabled_on_device) {
            logger << log4cpp::Priority::DEBUG << "Interface " << interface_name << " in promisc mode already";
            return true;
        } else {
             logger << log4cpp::Priority::DEBUG << "Interface in non promisc mode now, switch it on";
             ethreq.ifr_flags |= IFF_PROMISC;
             
             int ioctl_res_set = ioctl(fd, SIOCSIFFLAGS, &ethreq);

             if (ioctl_res_set == -1) {
                 logger << log4cpp::Priority::ERROR << "Can't set interface flags";
                 return false;
             }

             return true;
        }
    } else { 
        if (!promisc_enabled_on_device) {
            logger << log4cpp::Priority::DEBUG << "Interface " << interface_name << " in normal mode already";
            return true;
        } else {
            logger << log4cpp::Priority::DEBUG << "Interface in promisc mode now, switch it off";

            ethreq.ifr_flags &= ~IFF_PROMISC;
            int ioctl_res_set = ioctl(fd, SIOCSIFFLAGS, &ethreq);
 
            if (ioctl_res_set == -1) {
                logger << log4cpp::Priority::ERROR << "Can't set interface flags";
                return false;
            }

            return true;
        }
    }
}

#endif // __linux__


std::string get_netmap_intf(const std::string& intf)
{
    if (intf.find("netmap:") == std::string::npos) {
        return "netmap:" + intf;
    } else {
        return intf;
    }
}

bool is_file_exist(const std::string& file_name)
{
    struct stat st;
    return (stat (file_name.c_str(), &st) == 0);
}

bool is_executable(const std::string& file_name)
{
    struct stat st;
    if(stat(file_name.c_str(), &st) < 0)
        return false;
    if ((st.st_mode & S_IEXEC) != 0)
        return true;
    return false;
}

std::string format_len(const std::string& s, unsigned int len)
{
    std::string s_format = "%-"
                        + to_string(len)
                        + "s";
    return boost::str(boost::format(s_format) % s);
}

std::vector<std::string> tokenize(const std::string& input, const separator_type& separator)
{
    // Tokenize the intput.
    boost::tokenizer<separator_type> tokens(input, separator);

    // Copy non-empty tokens from the tokenizer into the result.
    std::vector<std::string> result;
    for(const auto& t: tokens)
    {
        if(!t.empty())
        {
            result.push_back(t);
        }
    }
    return result;
}

std::vector<std::string> tokenize(const std::string& input)
{
    separator_type separator("\\",   // The escape characters.
                            " ",     // The separator characters.
                            "\"\'"); // The quote characters.

    return tokenize(input, separator);
}