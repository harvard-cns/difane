// -*- c-basic-offset: 4; related-file-name: "chain.hh" -*-
/*
 * chain.{cc,hh} -- Openflow chain
 */

#include <click/config.h>
#include <clicknet/ether.h>
#include <clicknet/ip.h>
#include <clicknet/tcp.h>
#include <clicknet/udp.h>
#include <clicknet/icmp.h>
#include "table.hh"
#include "table_hash.hh"
#include "table_linear.hh"
#include "flow.hh"
#include "chain.hh"
#include "openflow.hh"
#include "datapath.hh"

CLICK_CXX_PROTECT
#include <linux/module.h>
#include <linux/rcupdate.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
CLICK_CXX_UNPROTECT

CLICK_DECLS

/* Attempts to append 'table' to the set of tables in 'chain'.  Returns 0 or
 * negative error.  If 'table' is null it is assumed that table creation failed
 * due to out-of-memory. */
int 
OFChain::add_table(FlowTable *table)
{
	if (table == NULL)
		return -ENOMEM;
	if (n_tables >= CHAIN_MAX_TABLES) {
		click_chatter("OPENFLOW: too many tables in chain\n");
		table->destroy();
		delete table;
		return -ENOBUFS;
	}
	tables[n_tables++] = table;

	return 0;
}

/* Creates and returns a new chain associated with 'dp'.  Returns NULL if the
 * chain cannot be created. */
int
OFChain::chain_create(Datapath *dp)
{
  FlowTable *fht = NULL, *flt = NULL;

  this->dp = dp;
  fht = new FlowTable_Hash;
  if (fht) {
      if (fht->create(0x1EDC6F41, TABLE_HASH_MAX_FLOWS)) {
	  goto error;
      }
      if (add_table(fht))
	  goto error;
  }
  else
      goto error;

  flt = new FlowTable_Linear;
  if (flt) {
      if (flt->create(TABLE_LINEAR_MAX_FLOWS)) {
	  goto destroy_hash_table;
      }

      if (add_table(flt)) {
	  goto destroy_linear_table;
      }
  }
  else 
      goto destroy_hash_table;

  return 0;

destroy_linear_table:
  flt->destroy();
  delete flt;
destroy_hash_table:
  fht->destroy();
  delete fht;
error:
  return -1;
}

/* Searches 'chain' for a flow matching 'key', which must not have any wildcard
 * fields.  Returns the flow if successful, otherwise a null pointer.
 *
 * Caller must hold rcu_read_lock or dp_mutex. */
sw_flow *
OFChain::chain_lookup(const sw_flow_key *key)
{
  int i;

  BUG_ON(key->wildcards);
  for (i = 0; i < n_tables; i++) {
    FlowTable *t = tables[i];
    sw_flow *flow = t->lookup(key);
    t->n_lookup++;
    if (flow) {
      t->n_matched++;
      return flow;
    }
  }
  return NULL;
}

/* Inserts 'flow' into 'chain', replacing any duplicate flow.  Returns 0 if
 * successful or a negative error.
 *
 * If successful, 'flow' becomes owned by the chain, otherwise it is retained
 * by the caller.
 *
 * Caller must hold dp_mutex. */
int 
OFChain::chain_insert(struct sw_flow *flow)
{
  int i;
  might_sleep();
  for (i = 0; i < n_tables; i++) {
    FlowTable *t = tables[i];
    if (t) {
	if (t->insert(flow)) {
	    return 0;
	}
    }
  }
  return -ENOBUFS;
}

/* Modifies actions in 'chain' that match 'key'.  If 'strict' set, wildcards 
 * and priority must match.  Returns the number of flows that were modified.
 *
 * Expensive in the general case as currently implemented, since it requires
 * iterating through the entire contents of each table for keys that contain
 * wildcards.  Relatively cheap for fully specified keys. */
int
OFChain::chain_modify(const sw_flow_key *key, 
		      uint16_t priority, int strict,
		      const struct ofp_action_header *actions, size_t actions_len)
{
  int count = 0;
  int i;
  
  for (i = 0; i < n_tables; i++) {
    FlowTable *t = tables[i];
    count += t->modify(key, priority, strict, actions, actions_len);
  }

  return count;
}

/* Deletes from 'chain' any and all flows that match 'key'.  If 'out_port' 
 * is not OFPP_NONE, then matching entries must have that port as an 
 * argument for an output action.  If 'strict" is set, then wildcards and 
 * priority must match.  Returns the number of flows that were deleted.
 *
 * Expensive in the general case as currently implemented, since it requires
 * iterating through the entire contents of each table for keys that contain
 * wildcards.  Relatively cheap for fully specified keys.
 *
 * Caller must hold dp_mutex. */
int 
OFChain::chain_delete(const sw_flow_key *key, 
		uint16_t out_port, uint16_t priority, int strict)
{
  int count = 0;
  int i;

  might_sleep();
  for (i = 0; i < n_tables; i++) {
    FlowTable *t = tables[i];
    count += t->delete_flows(key, out_port, priority, strict);
  }
  
  return count;
}

/* Performs timeout processing on all the tables in 'chain'.  Returns the
 * number of flow entries deleted through expiration.
 *
 * Expensive as currently implemented, since it iterates through the entire
 * contents of each table.
 *
 * Caller must not hold dp_mutex, because individual tables take and release it
 * as necessary. */
int 
OFChain::chain_timeout()
{
  int count = 0;
  int i;
  might_sleep();
  for (i = 0; i < n_tables; i++) {
    FlowTable *t = tables[i];
    count += t->timeout(dp);
  }
  return count;
}

/* Destroys 'chain', which must not have any users. */
void 
OFChain::chain_destroy()
{
  int i;
  
  synchronize_rcu();
  for (i = 0; i < n_tables; i++) {
    FlowTable *t = tables[i];
    t->destroy();
    delete t;
  }
}

CLICK_ENDDECLS
ELEMENT_REQUIRES(linuxmodule)
ELEMENT_PROVIDES(OPENFLOW_CHAIN)
