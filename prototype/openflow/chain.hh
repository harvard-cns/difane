// -*- related-file-name: "chain.cc" -*-
#ifndef CLICK_OFCHAIN_HH
#define CLICK_OFCHAIN_HH

#include <click/config.h>
#include <click/packet.hh>
#include <click/sync.hh>
#include <click/element.hh>

CLICK_CXX_PROTECT
#include <linux/kernel.h>
#include <linux/spinlock.h>
#include <linux/list.h>
#include <linux/types.h>
#include <linux/rcupdate.h>
#include <linux/gfp.h>
#include <linux/skbuff.h>
#include <linux/if_ether.h>
CLICK_CXX_UNPROTECT

#include "openflow.hh"
#include "datapath.hh"
#include "chain.hh"
#include "flow.hh"
#include "table.hh"

CLICK_DECLS

struct sw_flow;
struct sw_flow_key;
struct ofp_action_header;
struct datapath;

#define TABLE_LINEAR_MAX_FLOWS  100
#define TABLE_HASH_MAX_FLOWS	65536

/* Set of tables chained together in sequence from cheap to expensive. */
#define CHAIN_MAX_TABLES 4
struct OFChain {
        Spinlock hook_lock;
	int n_tables;
	FlowTable *tables[CHAIN_MAX_TABLES];

	Datapath *dp;
	struct module *owner;

  OFChain():hook_lock() {
    n_tables = 0;
    for (int i = 0; i < CHAIN_MAX_TABLES; i++) {
      tables[i] = NULL;
    }
    dp = NULL;
    owner = NULL;
  };

  ~OFChain() {};
  int add_table(FlowTable *table);
  int chain_create(Datapath *);
  void chain_destroy();
  sw_flow *chain_lookup(const sw_flow_key *);
  int chain_insert(sw_flow *flow);
  int chain_modify(const sw_flow_key *key, 
		   uint16_t priority, int strict,
		   const struct ofp_action_header *actions, size_t actions_len);
  int chain_delete(const sw_flow_key *key, 
		   uint16_t out_port, uint16_t priority, int strict);
  int chain_timeout();
};

CLICK_ENDDECLS
#endif /* chain.hh */
