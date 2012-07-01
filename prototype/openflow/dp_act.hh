// -*- related-file-name: "dp_act.cc" -*-
#ifndef CLICK_OFDP_ACT_HH
#define CLICK_OFDP_ACT_HH

#include <click/config.h>
#include <click/packet.hh>
#include <click/sync.hh>
#include "openflow.hh"
#include "datapath.hh"

CLICK_CXX_PROTECT
#include <linux/kernel.h>
#include <linux/spinlock.h>
#include <linux/list.h>
#include <linux/types.h>
#include <linux/rcupdate.h>
#include <linux/gfp.h>
#include <linux/skbuff.h>
#include <linux/if_ether.h>
#include <linux/netlink.h>
#include <net/genetlink.h>
CLICK_CXX_UNPROTECT

CLICK_DECLS

#define ACT_VALIDATION_OK ((uint16_t)-1)

uint16_t validate_actions(Datapath *, const struct sw_flow_key *,
			  const struct ofp_action_header *, size_t);

void execute_actions(Datapath *dp, Packet *p_in,
		     struct sw_flow_key *key,
		     const struct ofp_action_header *actions, size_t actions_len,
		     int ignore_no_fwd);

CLICK_ENDDECLS
#endif /* dp_act.hh */
