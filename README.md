# DDoS attack detector #
Ddosdetector System - a flexible tool for analyzing network traffic and automation of the process of protection against DDoS attacks. The system is based on the framework, [Luigi Rizzo](https://github.com/luigirizzo/netmap) [netmap](https://habrahabr.ru/post/183832/) and is designed to work with a large volume of traffic (10GB / sec and more) without loss of performance.

The system is written in C++ (Standard 11) using *STL* and *Boost (1.55)*. Writing and assembling was done on *Ubuntu 12.04.5 LTS* and compiler *g++4.8*. For static analysis and research style blunders used *cppcheck* version 1.73.

InfluxDB can be used for monitoring and collection of statistics.
![Grafana](docs/images/grafana.png)
*code of this Grafana dashboard in ./docs/INFLUXDB.md file*

README in Russian: *./docs/README_RUS.md*

## Principle of operation ##
The daemon runs on the SPAN interface (this interface is mirrored all traffic protected network) and starts to "listen" all traffic. The resulting traffic is passed through a set of rules. Each rule set of features by which the package is tested and a trigger that will work if the conditions are matched. A trigger is associated with a task that performs one action (logging, call scripts, etc.). All rules are added to the system are divided into several groups corresponding global L4 protocols (TCP, UDP, ICMP, etc.). Each rule is added to the same group and, in accordance with the protocol of the group may have different traffic processing parameters (for more information on available commands can be obtained from the Management Console, typing "help"). Each rule, in any group, there are a number of mandatory parameters, which add a rule without fail:
* source / destination ip address / network
* the trigger threshold (indicating critical importance for the achievement of which is caused by the action of the trigger)

An example of rules for search traffic:
```c++
ddoscontrold> show rules
TCP rules (num, rule, counter):
  -d 92.53.96.141/32 --pps-th 100p --hlen <20 --pps-th-period 60 --action log:/tmp/test.log --next    : 814.00p/s (735.03Kb/s), 157106 packets, 22975832 bytes
```
More functionality is described in the "Control" section.

Daemon is controlled through сonsole (access on TCP port or UNIX socket) standard utilities Linux (telnet/netcat/socat). The management console provides the user with the command line parameter selection, detection, counting the traffic, as well as the parameters of reaction to one or the other traffic.

System statistics can be sent to the InfluxDB data base for reporting and charting.

## Installation ##
Since the system works on the basis netmap driver is required to install this driver.
### Installing netmap driver on Ubuntu ###
To work correctly, the driver must collect netmap netmap module and collect network card driver with netmap support. This requires download the kernel source installed on your system (in example core version 3.10.90) and collect netmap with an indication of the source (build netmap patched network card driver from source and build them).

Download the kernel sources and unpack:
```bash
cd /usr/src
wget -S https://cdn.kernel.org/pub/linux/kernel/v3.x/linux-3.10.90.tar.xz
tar xpvf ./linux-3.10.90.tar.xz -C /usr/src/
```
Download netmap:
```bash
git clone https://github.com/luigirizzo/netmap
```
Configure the module assembly to enter the kernel source, and what we need drivers
```bash
cd ./netmap/LINUX/
./configure --kernel-sources=/usr/src/linux-3.10.90 --drivers=igb,ixgbe,e1000e
```
Build:
```bash
make
```
Load kernel modules in system:
```bash
insmod /usr/src/netmap/LINUX/netmap.ko
# for 10Gb/sec Intel ethernet adapter
rmmod ixgbe && insmod /usr/src/netmap/LINUX/ixgbe/ixgbe.ko
# for 1Gb/sec Intel ethernet adapter (may be other drivers)
rmmod igb && insmod /usr/src/netmap/LINUX/igb/igb.ko
rmmod e1000e && insmod /usr/src/netmap/LINUX/e1000e/e1000e.ko
```
then the system should appear interface with netmap:
```bash
# ls /dev/netmap 
/dev/netmap
```

### Installing ddosdetector ###
Build ddosdetector from source:
```bash
git clone https://velizarx@bitbucket.org/velizarx/ddosdetector.git
cd ./ddosdetector
make
```

## Run ##
To run the current user must have permissions to read and write to netmap interface (*/dev/netmap*). The network interface must be enabled. Network card driver that supports netmap must be loaded:
```bash
# lsmod | grep netmap
netmap                143360  27 ixgbe
# modinfo ixgbe | grep depends 
depends:        mdio,netmap,dca
```
**ATTENTION! If the connection to the remote current server (SSH, telnet, etc.), start ddosdetector system on the same network interface, through which the connection will result in the loss of access. Netmap driver disables the network card from the operating system!**

Run ddosdetector (in example interface eth4):
```bash
cd <path_to_ddosdetector_directory>
./ddosdetector -i eth4 -r ~/ddosdetector.rules -s /tmp/ddosd.sock -l ~/ddosdetector.log
```
Where:
* *-i eth4 (**parameter is required**)* - *eth4* interface system that gets mirrored traffic;
* *-r ~/ddosdetector.rules* - файл откуда будут загружены правила (этот параметр необязателен, по-умолчанию поиск файла производится по пути */etc/ddosdetector.rules*);
* *-s /tmp/ddosd.sock* - how to run the management server (in this case, the UNIX socket, the file */tmp/ddosd.sock*), may also be the path to the file or ip:port (then run TCP server to ip and port specified) parameter is optional. By default, TCP server runs on 127.0.0.1:9090;
* *-l ~/ddosdetector.log* - the path to the log file, the default output in the stdout

then you can connect to the system:
```bash
socat - UNIX-CONNECT:/tmp/ddosd.sock
```

## Control ##
### Configuration files ###
When you start the system tries to read the two configuration files:
* /etc/ddosdetector.conf - general system settings
* /etc/ddosdetector.rules - saved rules

File */etc/ddosdetector.conf* can contain the following settings (the value of the name):
```ini
[Main]
Interface = eth0
Rules = /etc/ddosdetector.rules
Log = /var/log/ddosdetector.log
Listen = 127.0.0.1:9090

[IndluxDB]
Enable = yes
User = ddosdetector
Password = p@$$w0rd
Database = ddosdetector
Host = localhost
Port = 8086
Period = 30
```
If the configuration file exists, the system start-up is reduced to the command execution:
```bash
./ddosdetector
```

### Connect to control server ###
To manage the system you want to connect to a running daemon. Depending on the start-up parameters, you must either connect to a TCP server or a UNIX socket.

#### TCP server ####
```bash
telnet 127.1 9090
```
where 127.1 and 9090 - this is the default start ip:port or specified ip:port options

#### UNIX socket server ####
```bash
# socat - UNIX-CONNECT:/tmp/ddosd.sock 
ddoscontrold>
```
where */tmp/ddosd.sock* - socket file specified at startup

### Setting ###
After connecting to the management server, you can display a list of all available commands:
```bash
$ socat - UNIX-CONNECT:/tmp/ddosd.sock 
ddoscontrold> help
Console commands:<type> - may be TCP, UDP or ICMP; <num> - number (0..65535);
  help                                show this help
  add rule <type> <rule>              add new rule
  insert rule <type> <num> <rule>     insert new rule by number
  del rule <type> <num>               add new rule
  show rules                          print all rules with counters
  reload rules                        reload all rules from file
  exit                                close connection


Base rule options:
  --pps-th arg          trigger threshold incomming packets per second 
                        (p,Kp,Mp,Tp,Pp)
  --bps-th arg          trigger threshold incomming bits per second 
                        (b,Kb,Mb,Tb,Pb)
  --pps-th-period arg   trigger threshold period in seconds (default 10)
  --bps-th-period arg   trigger threshold period in seconds (default 10)
  -a [ --action ] arg   run action when trigger active (type:param)
  --next                go to next rule in list

IPv4 rule options:
  -d [ --dstip ] arg    destination ip address/net
  -s [ --srcip ] arg    source ip address/net

TCP rule options:
  --dport arg           destination port
  --sport arg           source port
  --seq arg             check if sequence number = or > or < arg
  --win arg             check if window size number = or > or < arg
  --ack arg             check if acknowledgment number = or > or < arg
  --hlen arg            check if TCP header len = or > or < arg (in bytes)
  --tcp-flag arg        TCP flags <flag>:<enable>, where <enable> - 1 or 0; 
                        <flag> - U or R or P or S or A or F.

UDP rule options:
  --dport arg           destination port
  --sport arg           source port
  --hlen arg            check if TCP header len = or > or < arg (in bytes)

ICMP rule options:
  --type arg            check if ICMP packet type = or > or < arg
  --code arg            check if ICMP packet code = or > or < arg

```

Displayed in the help options are divided into two types: the parameters of the rules collection management (Part One "Console commands"), and the parameters of the rules themselves (all of which is below).
Traffic filtering rules can be added to one of the branches of L4 protocol level, is responsible for this mandatory argument *<type>*, and when inserting and removing the right index to the rule - it is his number (parameter *<num>*):

```bash
add rule <type> <rule>              add new rule
insert rule <type> <num> <rule>     insert new rule by number
del rule <type> <num>               add new rule
show rules                          print all rules with counters
```

#### Show rules ####
To view the operating rules and counters, use the command: **show rules**
```bash
ddoscontrold> show rules
TCP rules (num, rule, counter):
    0:   -d 92.53.96.141/32 --pps-th 100p --seq =0 --pps-th-period 60 --action log:/tmp/test.log --next     : 0.00p/s (0.00b/s), 0 packets, 0 bytes
    1:   -d 92.53.96.141/32 --pps-th 100p --win =0 --pps-th-period 60 --action log:/tmp/test.log --next     : 6.00p/s (2.88Kb/s), 6 packets, 360 bytes
    2:   -d 92.53.96.141/32 --pps-th 100p --hlen <20 --pps-th-period 60 --action log:/tmp/test.log --next   : 0.00p/s (0.00b/s), 0 packets, 0 bytes
    3:   -d 92.53.96.141/32 --pps-th 100p --pps-th-period 60 --action script:/tmp/test_script.py --next     : 330.00p/s (588.79Kb/s), 330 packets, 73611 bytes
    4:   -d 92.53.96.141/32 --dport 80-443 --pps-th 10p --action log:/tmp/test.log                          : 330.00p/s (588.79Kb/s), 330 packets, 73611 bytes
    5:   -d 92.53.116.85/32 --bps-th 100Mb --action log:/tmp/test.log                                       : 0.00p/s (0.00b/s), 0 packets, 0 bytes
    6:   -d 92.53.116.23/32 --bps-th 100Mb --action log:/tmp/test.log                                       : 0.00p/s (0.00b/s), 0 packets, 0 bytes
    7:   -d 92.53.116.22/32 --bps-th 100Mb --action log:/tmp/test.log                                       : 0.00p/s (0.00b/s), 0 packets, 0 bytes
    8:   -d 92.53.116.70/32 --bps-th 100Mb --action log:/tmp/test.log                                       : 4.00p/s (6.42Kb/s), 4 packets, 802 bytes
    9:   -d 0.0.0.0/0 --bps-th 100Mb --action syslog                                                        : 1.12Mp/s (7.71Gb/s), 1143222 packets, 985391222 bytes
UDP rules (num, rule, counter):
    0:   -d 92.53.116.200/32 --pps-th 100p --dport 53   : 1.99Kp/s (1.33Mb/s), 1986 packets, 166867 bytes
ICMP rules (num, rule, counter):
    0:   -d 92.53.96.141/32 --pps-th 100p --type =8 --code =0   : 2.00p/s (1.57Kb/s), 2 packets, 196 bytes
    1:   -d 92.53.96.141/32 --pps-th 100p --type =0 --code =0   : 0.00p/s (0.00b/s), 0 packets, 0 bytes
```
the first digit - number command, then the command text. After the second colon - counters rules. The entire list of rules divided the protocols L4 level.

#### Add rule ####
For example, the command for adding a rule of capture TCP SYN packets with the Window size = 0 (SYN Flood attack) with an entry in the log if the packet traffic of more than 10MB / s for 1 minute:
```bash
ddoscontrold> add rule TCP -d 92.53.96.141/32 --bps-th 10Mb --win =0 --tcp-flag S:1,A:0 --action log:/tmp/test_syn.log --pps-th-period 60
ddoscontrold> show rules
TCP rules (num, rule, counter):
    0:   -d 92.53.96.141/32 --pps-th 100p --seq =0 --pps-th-period 60 --action log:/tmp/test.log --next                   : 0.00p/s (0.00b/s), 0 packets, 0 bytes
    1:   -d 92.53.96.141/32 --pps-th 100p --win =0 --pps-th-period 60 --action log:/tmp/test.log --next                   : 1.00p/s (480.00b/s), 2232322 packets, 134037624 bytes
    2:   -d 92.53.96.141/32 --pps-th 100p --hlen <20 --pps-th-period 60 --action log:/tmp/test.log --next                 : 0.00p/s (0.00b/s), 0 packets, 0 bytes
    3:   -d 92.53.96.141/32 --pps-th 100p --pps-th-period 60 --action script:/tmp/test_script.py --next                   : 147.00p/s (191.18Kb/s), 408042174 packets, 59905853944 bytes
    4:   -d 92.53.96.141/32 --dport 80-443 --pps-th 10p --action log:/tmp/test.log                                        : 147.00p/s (191.18Kb/s), 407567038 packets, 59820452344 bytes
    5:   -d 92.53.116.85/32 --bps-th 100Mb --action log:/tmp/test.log                                                     : 0.00p/s (0.00b/s), 2072576 packets, 252829696 bytes
    6:   -d 92.53.116.23/32 --bps-th 100Mb --action log:/tmp/test.log                                                     : 0.00p/s (0.00b/s), 2490368 packets, 1139314688 bytes
    7:   -d 92.53.116.22/32 --bps-th 100Mb --action log:/tmp/test.log                                                     : 0.00p/s (0.00b/s), 9543749 packets, 10454889750 bytes
    8:   -d 92.53.116.70/32 --bps-th 100Mb --action log:/tmp/test.log                                                     : 5.00p/s (27.42Kb/s), 2732037 packets, 887561571 bytes
    9:   -d 0.0.0.0/0 --bps-th 100Mb --action syslog                                                                      : 1.12Mp/s (7.63Gb/s), 1788817419102 packets, 1539206358632609 bytes
   10:   -d 92.53.96.141/32 --bps-th 10Mb --win =0 --tcp-flag S:1,A:0 --action log:/tmp/test_syn.log --pps-th-period 60   : 0.00p/s (0.00b/s), 0 packets, 0 bytes
UDP rules (num, rule, counter):
    0:   -d 92.53.116.200/32 --pps-th 100p --dport 53   : 1.65Kp/s (1.11Mb/s), 2132791521 packets, 179117436614 bytes
ICMP rules (num, rule, counter):
    0:   -d 92.53.96.141/32 --pps-th 100p --type =8 --code =0   : 0.00p/s (0.00b/s), 1269760 packets, 124436480 bytes
    1:   -d 92.53.96.141/32 --pps-th 100p --type =0 --code =0   : 0.00p/s (0.00b/s), 0 packets, 0 bytes
```
The right to add to the end of a chain of rules TCP.
#### Delete rule ####
Removing rules made by its number and type:
```bash
ddoscontrold> del rule TCP 11
Error operation rule: not found 11 rule
ddoscontrold> del rule TCP 10
ddoscontrold> show rules
TCP rules (num, rule, counter):
    0:   -d 92.53.96.141/32 --pps-th 100p --seq =0 --pps-th-period 60 --action log:/tmp/test.log --next     : 0.00p/s (0.00b/s), 0 packets, 0 bytes
    1:   -d 92.53.96.141/32 --pps-th 100p --win =0 --pps-th-period 60 --action log:/tmp/test.log --next     : 0.00p/s (0.00b/s), 9144557568 packets, 549076107264 bytes
    2:   -d 92.53.96.141/32 --pps-th 100p --hlen <20 --pps-th-period 60 --action log:/tmp/test.log --next   : 0.00p/s (0.00b/s), 0 packets, 0 bytes
    3:   -d 92.53.96.141/32 --pps-th 100p --pps-th-period 60 --action script:/tmp/test_script.py --next     : 36.00p/s (29.01Kb/s), 1671489351748 packets, 245395354980098 bytes
    4:   -d 92.53.96.141/32 --dport 80-443 --pps-th 10p --action log:/tmp/test.log                          : 29.00p/s (22.78Kb/s), 1669542711350 packets, 245045485856773 bytes
    5:   -d 92.53.116.85/32 --bps-th 100Mb --action log:/tmp/test.log                                       : 0.00p/s (0.00b/s), 8490487811 packets, 1036269433082 bytes
    6:   -d 92.53.116.23/32 --bps-th 100Mb --action log:/tmp/test.log                                       : 0.00p/s (0.00b/s), 10201411584 packets, 4666950860800 bytes
    7:   -d 92.53.116.22/32 --bps-th 100Mb --action log:/tmp/test.log                                       : 0.00p/s (0.00b/s), 39095005184 packets, 42827336540160 bytes
    8:   -d 92.53.116.70/32 --bps-th 100Mb --action log:/tmp/test.log                                       : 0.00p/s (0.00b/s), 11191435264 packets, 3635753590784 bytes
    9:   -d 0.0.0.0/0 --bps-th 100Mb --action syslog                                                        : 1.19Mp/s (8.19Gb/s), 7327549925466711 packets, 6305063082930564060 bytes
UDP rules (num, rule, counter):
    0:   -d 92.53.116.200/32 --pps-th 100p --dport 53   : 1.33Kp/s (897.29Kb/s), 8736549554751 packets, 733718174039092 bytes
ICMP rules (num, rule, counter):
    0:   -d 92.53.96.141/32 --pps-th 100p --type =8 --code =0   : 0.00p/s (0.00b/s), 5201125376 packets, 509710131200 bytes
    1:   -d 92.53.96.141/32 --pps-th 100p --type =0 --code =0   : 0.00p/s (0.00b/s), 0 packets, 0 bytes
```
#### Reload rules from file ####
At startup, the system checks the configuration file previously saved rules (by default */etc/ddosdetector.rules*). If the reference system is already running, you can restart the rules from the file manually. Restart the rules of the file is performed either from the command control console **reload rules** any SIGHUP signal sent to the demon. For example rules file has the contents:
```bash
$ cat ~/ddosdetector.rules
TCP -d 92.53.96.141/32 --pps-th 100p --seq =0 --pps-th-period 60 --action log:/tmp/test.log --next
TCP -d 92.53.96.141/32 --pps-th 100p --win =0 --pps-th-period 60 --action log:/tmp/test.log --next
TCP -d 92.53.96.141/32 --pps-th 100p --hlen <20 --pps-th-period 60 --action log:/tmp/test.log --next
TCP -d 92.53.96.141/32 --pps-th 100p --pps-th-period 60 --action script:/tmp/test_script.py --next
TCP -d 92.53.96.141/32 --dport 80-443 --pps-th 10p --action log:/tmp/test.log
TCP -d 92.53.116.85/32 --bps-th 100Mb --action log:/tmp/test.log
TCP -d 92.53.116.23/32 --bps-th 100Mb --action log:/tmp/test.log
TCP -d 92.53.116.22/32 --bps-th 100Mb --action log:/tmp/test.log
TCP -d 92.53.116.70/32 --bps-th 100Mb --action log:/tmp/test.log
TCP -d 0.0.0.0/0 --bps-th 100Mb --action syslog
# test DNS server traffic
UDP -d 92.53.116.200/32 --pps-th 100p --dport 53 
ICMP -d 92.53.96.141/32 --pps-th 100p --type =8 --code =0
ICMP -d 92.53.96.141/32 --pps-th 100p --type =0 --code =0
TCP -d 92.53.96.141/32 --bps-th 10Mb --win =0 --tcp-flag S:1,A:0 --action log:/tmp/test_syn.log --pps-th-period 60 
```
reload file:
```bash
ddoscontrold> show rules
TCP rules (num, rule, counter):
UDP rules (num, rule, counter):
ICMP rules (num, rule, counter):
ddoscontrold> reload rules
ddoscontrold> show rules
TCP rules (num, rule, counter):
    0:   -d 92.53.96.141/32 --pps-th 100p --seq =0 --pps-th-period 60 --action log:/tmp/test.log --next                   : 0.00p/s (0.00b/s), 0 packets, 0 bytes
    1:   -d 92.53.96.141/32 --pps-th 100p --win =0 --pps-th-period 60 --action log:/tmp/test.log --next                   : 6.00p/s (2.88Kb/s), 6 packets, 360 bytes
    2:   -d 92.53.96.141/32 --pps-th 100p --hlen <20 --pps-th-period 60 --action log:/tmp/test.log --next                 : 0.00p/s (0.00b/s), 0 packets, 0 bytes
    3:   -d 92.53.96.141/32 --pps-th 100p --pps-th-period 60 --action script:/tmp/test_script.py --next                   : 81.00p/s (64.02Kb/s), 81 packets, 8003 bytes
    4:   -d 92.53.96.141/32 --dport 80-443 --pps-th 10p --action log:/tmp/test.log                                        : 81.00p/s (64.02Kb/s), 81 packets, 8003 bytes
    5:   -d 92.53.116.85/32 --bps-th 100Mb --action log:/tmp/test.log                                                     : 2.00p/s (3.23Kb/s), 2 packets, 404 bytes
    6:   -d 92.53.116.23/32 --bps-th 100Mb --action log:/tmp/test.log                                                     : 0.00p/s (0.00b/s), 0 packets, 0 bytes
    7:   -d 92.53.116.22/32 --bps-th 100Mb --action log:/tmp/test.log                                                     : 0.00p/s (0.00b/s), 0 packets, 0 bytes
    8:   -d 92.53.116.70/32 --bps-th 100Mb --action log:/tmp/test.log                                                     : 0.00p/s (0.00b/s), 0 packets, 0 bytes
    9:   -d 0.0.0.0/0 --bps-th 100Mb --action syslog                                                                      : 1.14Mp/s (7.87Gb/s), 1155506 packets, 997256842 bytes
   10:   -d 92.53.96.141/32 --bps-th 10Mb --win =0 --tcp-flag S:1,A:0 --action log:/tmp/test_syn.log --pps-th-period 60   : 0.00p/s (0.00b/s), 0 packets, 0 bytes
UDP rules (num, rule, counter):
    0:   -d 92.53.116.200/32 --pps-th 100p --dport 53   : 1.32Kp/s (882.97Kb/s), 1319 packets, 110387 bytes
ICMP rules (num, rule, counter):
    0:   -d 92.53.96.141/32 --pps-th 100p --type =8 --code =0   : 0.00p/s (0.00b/s), 0 packets, 0 bytes
    1:   -d 92.53.96.141/32 --pps-th 100p --type =0 --code =0   : 0.00p/s (0.00b/s), 0 packets, 0 bytes
```

## Future ##
* Save the current rules to a file
* Option to run in daemon mode
* Trigger to stop attacks
* "Monitor" display counters in the Management Console. Enter "monitor rules" command causes the page to display statistics and updated once a second. Cancel on *Ctrl^D*;
* SNMP monitoring counters rules

## For developers ##
Description of the project structure of the code in a file (currently only in Russian): ./docs/FOR_DEVELOPERS.md