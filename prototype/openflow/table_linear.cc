// -*- c-basic-offset: 4; related-file-name: "table_linear.hh" -*-
/*
 * table_linear.{cc,hh} -- Openflow table_linear
 */

#include <click/config.h>
#include <clicknet/ether.h>
#include <clicknet/ip.h>
#include <clicknet/tcp.h>
#include <clicknet/udp.h>
#include <clicknet/icmp.h>

#include "table_linear.hh"
#include "of_crc32.hh"
#include "flow.hh"
#include "openflow.hh"
#include "datapath.hh"

CLICK_CXX_PROTECT
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/mm.h>
#include <linux/highmem.h>
#include <asm/pgtable.h>
CLICK_CXX_UNPROTECT

CLICK_DECLS

sw_flow *
FlowTable_Linear::lookup(const sw_flow_key *key)
{
    struct sw_flow *flow;

    for (FlowList::const_iterator it = fl.begin(); it != fl.end(); ++it)
	if(sw_flow::flow_matches_1wild(key, &it->key))
	    return it.get();

    return NULL;
}

int 
FlowTable_Linear::insert(sw_flow *flow)
{
    FlowList::iterator it;
    /* Loop through the existing list of entries.  New entries will
     * always be placed behind those with equal priority.  Just replace
     * any flows that match exactly.
     */
    for (it = fl.begin(); it != fl.end(); ++it) {
	if (it->priority == flow->priority
                                && it->key.wildcards == flow->key.wildcards
	    && sw_flow::flow_matches_2wild(&it->key, &flow->key)) {
	    flow->serial = it->serial;
	    unsigned long flags = _lock.acquire();
	    fl.insert(it,flow);
	    FlowIterList::iterator fit(it.get());
	    il.insert(fit,flow);
	    fl.erase(it);
	    il.erase(fit);
	    _lock.release(flags);
	    sw_flow::flow_deferred_free(it.get());
	    return 1;
	}	
	if (it->priority < flow->priority) {
	    break;
	}
    }

    /* Make sure there's room in the table. */
    if (n_flows >= max_flows) {
	return 0;
    }
    n_flows++;
    /* Insert the entry immediately in front of where we're pointing. */
    flow->serial = next_serial++;

    unsigned long flags = _lock.acquire();
    if (!fl.empty() && it.get()) {
	fl.insert(it,flow);
    }
    else
	fl.push_back(flow);

    // Following simulates inserting an element after a certain elment.
    // Since List only supports inserting an element before an itertator,
    // I have to similuate it as follows
    if(!il.empty() && it.get()) {
	FlowIterList::iterator fit(it.get());
	FlowIterList::iterator kit = il.insert(fit,flow);
	sw_flow *ff = fit.get();
	il.erase(fit);
	il.insert(kit,ff);
    }
    else {
	il.push_back(flow);
    }
    // simulation over
    _lock.release(flags);
    return 1;
}
  
int 
FlowTable_Linear::modify(const sw_flow_key *key, uint16_t priority,
		  int strict,const struct ofp_action_header *actions, size_t actions_len)
{
    unsigned int count = 0;

    for (FlowList::const_iterator it = fl.begin(); it != fl.end(); ++it) {
	if (sw_flow::flow_matches_desc(&it->key, key, strict)
	    && (!strict || (it->priority == priority))) {
	    sw_flow::flow_replace_acts(it.get(), actions, actions_len);
	    count++;
	}
    }
    return count;
}

int 
FlowTable_Linear::do_delete(FlowList::iterator it)
{	
    sw_flow *flow = it.get();
    unsigned long flags = _lock.acquire();
    fl.erase(it);
    FlowIterList::iterator fit(flow);
    il.erase(fit);
    _lock.release(flags);
    sw_flow::flow_deferred_free(flow);
    return 1;
}

int 
FlowTable_Linear::delete_flows(sw_flow_key *key, uint16_t out_port, 
			       uint16_t priority, int strict)
{
    unsigned int count = 0;

    for (FlowList::iterator it = fl.begin(); it != fl.end(); ++it) {
	if (sw_flow::flow_matches_desc(&it->key, key, strict)
	    && sw_flow::flow_has_out_port(it.get(), out_port)
	    && (!strict || (it->priority == priority)))
	    count += do_delete(it);
    }

    n_flows -= count;
    return count;
}

int 
FlowTable_Linear::timeout(Datapath *dp)
{
    int count = 0;

    if (!fl.empty()) {
	dp->lock();
    
	for (FlowList::iterator it = fl.begin(); it != fl.end(); ++it) {
	    sw_flow *flow = it.get();
	    int reason = sw_flow::flow_timeout(flow);
	    if (reason >= 0) {
		count += do_delete(it);
		dp->send_flow_expired(flow, reason);
	    }
	}
	n_flows -= count;
	dp->unlock();
    }
    return count;
}

void 
FlowTable_Linear::destroy()
{
    for (FlowList::iterator it = fl.begin(); it != fl.end(); ++it) {
	sw_flow *flow = it.get();
	fl.erase(it);
	sw_flow::flow_free(flow);
    }
}
  
int 
FlowTable_Linear::iterate(const sw_flow_key *key, uint16_t out_port, struct sw_table_position *position,
	      int (*callback)(struct sw_flow *flow, void *private_data),
	      void *private_data)
{
    unsigned long start;

    start = position->priv[0];
    for (FlowIterList::iterator fit = il.begin(); fit != il.end(); ++fit) {
	if (fit->serial >= start
	    && sw_flow::flow_matches_2wild(key, &fit->key)
	    && sw_flow::flow_has_out_port(fit.get(), out_port)) {
	    int error = callback(fit.get(), private_data);
	    if (error) {
		position->priv[0] = fit->serial;
		return error;
	    }
	}
    }
    return 0;
}

void 
FlowTable_Linear::stats(struct sw_table_stats *stats)
{
    stats->name = "linear";
    stats->wildcards = OFPFW_ALL;
    stats->n_flows   = n_flows;
    stats->max_flows = max_flows;
    stats->n_lookup  = n_lookup;
    stats->n_matched = n_matched;
}

int 
FlowTable_Linear::create(unsigned int mf)
{
    max_flows = mf;
    n_flows = 0;
    next_serial = 0;
    return 0;
}

CLICK_ENDDECLS
ELEMENT_REQUIRES(linuxmodule)
ELEMENT_PROVIDES(OPENFLOW_TABLE_LINEAR)
