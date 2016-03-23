#ifndef FUNCTIONS_HPP
#define FUNCTIONS_HPP

#include <stdlib.h> // atoi
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <net/if.h>
#include <fstream>
#include <iostream>
#include <string.h>


// Logging
#include "log4cpp/Category.hh"
#include "log4cpp/Appender.hh"
#include "log4cpp/FileAppender.hh"
#include "log4cpp/OstreamAppender.hh"
#include "log4cpp/Layout.hh"
#include "log4cpp/Priority.hh"
#include "log4cpp/PatternLayout.hh"

void init_logging(log4cpp::Category& logger);
#ifdef __linux__
bool manage_interface_promisc_mode(std::string interface_name, bool switch_on);
#endif

#endif // end FUNCTIONS_HPP