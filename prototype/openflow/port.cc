// -*- c-basic-offset: 4; related-file-name: "port.hh" -*-
/*
 * port.{cc,hh} -- Openflow port
 */

#include <click/config.h>
#include <click/glue.hh>
#include "openflow_genl.hh"
#include "port.hh"
#include "openflow.hh"
CLICK_CXX_PROTECT
#include <linux/netdevice.h>
#include <linux/rtnetlink.h>
#include <linux/mutex.h>
#include <linux/ethtool.h>
CLICK_CXX_UNPROTECT
CLICK_DECLS

Port::Port(Datapath *arg_dp, int pnum):port_lock()
{
  config = 0;
  state = 0;

  dp = arg_dp;
  port_no = pnum;
  // cp for click port
  sprintf(name, "cp%d",port_no);
  random_ether_addr(mac);
  //memset(mac[0],0,1);
  mac [0] &= 0x00;
  return;
}

Port::~Port()
{
}

void 
Port::fill_port_desc(struct ofp_phy_port *desc)
{
    unsigned long flags;
    desc->port_no = htons(port_no);
    strncpy(desc->name, name, OFP_MAX_PORT_NAME_LEN);
    desc->name[OFP_MAX_PORT_NAME_LEN-1] = '\0';
    memcpy(desc->hw_addr, mac, ETH_ALEN);
    desc->curr = 0;
    desc->supported = 0;
    desc->advertised = 0;
    desc->peer = 0;
    
    flags = port_lock.acquire();
    desc->config = htonl(config);
    desc->state = htonl(state);
    port_lock.release(flags);
    
    // Hardcoding for now. 1GB for Click ports.
    desc->supported |= OFPPF_1GB_HD;

    desc->curr = htonl(desc->curr);
    desc->supported = htonl(desc->supported);
    desc->advertised = htonl(desc->advertised);
    desc->peer = htonl(desc->peer);
}

CLICK_ENDDECLS
ELEMENT_REQUIRES(linuxmodule)
ELEMENT_PROVIDES(OPENFLOW_PORT)
