#ifndef READFILE_HH
#define READFILE_HH

#include <fstream>
#include <iostream>

#include "util.h"
#include "policy.hh"
#include "interface.hh"
#include "link.hh"

class router_interface_class;
class policy_class;
class policy_index_class;
class link_class;
class interface_class;
class acl_link_class;

extern policy_class * policy_list;
extern map<router_interface_class, vector<policy_index_class> > rule_group;

extern vector<interface_class> interface_set[MAX_ROUTER];
extern int nlink;
extern Link link_list[MAX_LINK];
extern acl_link_class * acl_link_list;

void read_interface(char * filename);

void read_network(char * filename);

void read_file(char * filename);


void read_file_campus(char * filename, int rid);

#endif
