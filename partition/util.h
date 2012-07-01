#ifndef UTIL_H
#define UTIL_H

//#define DEBUG 1
#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE 500
#include <pthread.h>
//#undef _XOPEN_SOURCE                                                                                                                                       
#endif

#include <stdio.h>
#include <math.h>


using namespace std;
#include <iostream>
#include <fstream>
#include <string>
#include <map>
#include <vector>
#include <list>
#include <set>
#include <algorithm>
#include <arpa/inet.h>
//#include "etheraddress.h"

#define MAX_DOUBLE 99999999

#define MAX_POLICY_COUNT 65000
//8600000
//2000
#define MAX_CUBE 100000
#define MAX_ROUTER 5000
#define MAX_INTERFACE 100
#define MAX_CONFIG_INTERFACE 10000 
//in backbonelist.tbl
#define MAX_LINK 20000

#define MAX_PROTO 255
#define MAX_ADDR ((int)(exp2(32)-1))

#define INTERFACE_INTERNAL 0
#define INTERFACE_EXTERNAL 1

//ACL_ATTR
//actions
#define ACTION_ACCEPT 0
#define ACTION_DENY  1
#define ACTION_RATE_LIMIT 2
#define ACTION_READONLY 3

#define NETWORK_CBB 0 //cbb
#define NETWORK_USIPFR 1 //vpn over cbb
#define NETWORK_LIGHTSPEED 2 //iptv
#define NETWORK_ENTERPRISE 3 
#define NETWORK_CAMPUS 4
#define NETWORK_SBC 5

#define MAX_STRING_LEN 1000

#define IPLEN 64

#define FORMAT_EXT 0
#define FORMAT_STD 1
#define FORMAT_XR 2
#define FORMAT_JUNOS 3
#define FORMAT_LIGHTSPEED 4

#define CACHE_MICRO 0
#define CACHE_WILD 1
#define CACHE_TIME 2
#define CACHE_SIZE 3

uint32_t str2ip(const char * str);
char * ip2str(uint32_t ip);

class ShortestPath {
 public:
  int length;
  int16_t next;
};

class Link {
 public:
  int from;
  int to;
  int weight;
};

void calc_shortest_path(ShortestPath * spath, int n, int m, Link * link);

double get_current_time();

void get_spath(int nrouter, char * filename, ShortestPath * spath);
void dump_spath(int nrouter, char * filename, ShortestPath * spath);

#endif //UTIL_H
