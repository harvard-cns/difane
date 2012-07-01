// -*- related-file-name: "port.cc" -*-
#ifndef CLICK_PORT_HH
#define CLICK_PORT_HH
#include <click/algorithm.hh>
#include <click/atomic.hh>
#include <click/list.hh>
#include "forward.hh"

CLICK_CXX_PROTECT
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
CLICK_CXX_UNPROTECT

#define PORT_NAME 20

class Datapath;

class Port {
public:
  u16 port_no;
  u32 config;             /* Some subset of OFPPC_* flags. */
  u32 state;              /* Some subset of OFPPS_* flags. */
  Datapath *dp;
  struct list_head node;   /* Element in datapath.ports. */
  SpinlockIRQ port_lock;
  List_member<Port> port_link;
  struct net_device_stats *stats;
  char name[PORT_NAME];
  uint8_t mac[OFP_ETH_ALEN]; 
public:
  
  struct net_device_stats *get_stats() { return stats;};
  void set_dp(Datapath *dp) { this->dp = dp; };
  void set_portno(u16 port_no) { this->port_no = port_no; };
  u16 get_portno() { return port_no; };
  Port(Datapath *dp, int port_no);
  ~Port();
  struct list_head get_list_head() {return node;};
  void fill_port_desc(struct ofp_phy_port *desc);
};

typedef List<Port, &Port::port_link> port_list;

CLICK_ENDDECLS
#endif
