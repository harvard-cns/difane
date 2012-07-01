// -*- c-basic-offset: 4; related-file-name: "table_hash.hh" -*-
/*
 * table_hash.{cc,hh} -- Openflow table_hash
 */

#include <click/config.h>
#include <clicknet/ether.h>
#include <clicknet/ip.h>
#include <clicknet/tcp.h>
#include <clicknet/udp.h>
#include <clicknet/icmp.h>

#include "table_hash.hh"
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

void
print_key(struct sw_flow_key *sfk)
{
    WARN_ON(1);
    click_chatter("YYY: flow key(%u,%u,%u,%u,%u,%u,%u,[%x:%x:%x:%x:%x:%x],[%x:%x:%x:%x:%x:%x],%u,%u,%u,)",
		  sfk->nw_src,
		  sfk->nw_dst,
		  sfk->in_port,
		  sfk->dl_vlan,
		  sfk->dl_type,
		  sfk->tp_src,
		  sfk->tp_dst,
		  sfk->dl_src[0],sfk->dl_src[1],sfk->dl_src[2],sfk->dl_src[3],sfk->dl_src[4],sfk->dl_src[5],
		  sfk->dl_dst[0],sfk->dl_dst[1],sfk->dl_dst[2],sfk->dl_dst[3],sfk->dl_dst[4],sfk->dl_dst[5],
		  sfk->nw_proto,
		  sfk->pad,
		  sfk->wildcards);
}

struct sw_flow **
FlowTable_Hash::find_bucket(const struct sw_flow_key *key)
{
    unsigned int crc = of_crc32_calculate(&crc32, key, 
				       offsetof(struct sw_flow_key, wildcards));
    return &buckets[crc & bucket_mask];
}


sw_flow *
FlowTable_Hash::lookup(const sw_flow_key *key)
{
    struct sw_flow *flow = *find_bucket(key);
    return flow && flow->key.flow_keys_equal(*key) ? flow : NULL;
}

int 
FlowTable_Hash::insert(sw_flow *flow)
{
    struct sw_flow **bucket;
    int retval;

    if (flow->key.wildcards != 0) {
	click_chatter("OpenFlow Debug(%s,%d): Cannot insert flow as wildcard is set",__FUNCTION__,__LINE__);
	return 0;
    }

    bucket = find_bucket(&flow->key);
    if (*bucket == NULL) {
	n_flows++;
	rcu_assign_pointer(*bucket, flow);
	retval = 1;
    } else {
	struct sw_flow *old_flow = *bucket;
	if (old_flow->key.flow_keys_equal(flow->key)) {
	    rcu_assign_pointer(*bucket, flow);
	    sw_flow::flow_deferred_free(old_flow);
	    retval = 1;
	} else {
	    retval = 0;
	}
    }
    return retval;
}
  
int 
FlowTable_Hash::modify(const sw_flow_key *key, uint16_t priority,
		  int strict,const struct ofp_action_header *actions, size_t actions_len)
{
    unsigned int count = 0;

    if (key->wildcards == 0) {
	struct sw_flow **bucket = find_bucket(key);
	struct sw_flow *flow = *bucket;
	if (flow && sw_flow::flow_matches_desc(&flow->key, key, strict)
	    && (!strict || (flow->priority == priority))) {
	    sw_flow::flow_replace_acts(flow, actions, actions_len);
	    count = 1;
	}
    } else {
	unsigned int i;

	for (i = 0; i <= bucket_mask; i++) {
	    struct sw_flow **bucket = &buckets[i];
	    struct sw_flow *flow = *bucket;
	    if (flow && sw_flow::flow_matches_desc(&flow->key, key, strict)
		&& (!strict || (flow->priority == priority))) {
		sw_flow::flow_replace_acts(flow, actions, actions_len);
		count++;
	    }
	}
    }
    return count;
}

/* Caller must update n_flows. */
int 
FlowTable_Hash::do_delete(struct sw_flow **bucket, struct sw_flow *flow)
{
	rcu_assign_pointer(*bucket, NULL);
	sw_flow::flow_deferred_free(flow);
	return 1;
}

int 
FlowTable_Hash::delete_flows(sw_flow_key *key, uint16_t out_port, uint16_t priority, int strict)
{	
    unsigned int count = 0;

    if (key->wildcards == 0) {
	struct sw_flow **bucket = find_bucket(key);
	struct sw_flow *flow = *bucket;
	if (flow && flow->key.flow_keys_equal(*key)
	    && sw_flow::flow_has_out_port(flow, out_port))
	    count = do_delete(bucket, flow);
    } else {
	unsigned int i;

	for (i = 0; i <= bucket_mask; i++) {
	    struct sw_flow **bucket = &buckets[i];
	    struct sw_flow *flow = *bucket;
	    if (flow && sw_flow::flow_matches_desc(&flow->key, key, strict)
		&& sw_flow::flow_has_out_port(flow, out_port))
		count += do_delete(bucket, flow);
	}
    }
    n_flows -= count;
    return count;
}

int 
FlowTable_Hash::timeout(Datapath *dp)
{
    unsigned int i;
    int count = 0;

    dp->lock();
    for (i = 0; i <= bucket_mask; i++) {
	struct sw_flow **bucket = &buckets[i];
	struct sw_flow *flow = *bucket;
	if (flow) {
	    int reason = sw_flow::flow_timeout(flow);
	    if (reason >= 0) {
		count += do_delete(bucket, flow); 
		dp->send_flow_expired(flow, reason);
	    }
	}
    }
    n_flows -= count;
    dp->unlock();

    return count;
}

void 
FlowTable_Hash::destroy()
{
    unsigned int i;
    for (i = 0; i <= bucket_mask; i++) {
	if (buckets[i]) {
	    sw_flow::flow_free(buckets[i]);
	}
    }
    kmem_free(buckets, (bucket_mask + 1) * sizeof *buckets);
}
  
int 
FlowTable_Hash::iterate(const sw_flow_key *key, uint16_t out_port, struct sw_table_position *position,
	      int (*callback)(struct sw_flow *flow, void *private_data),
	      void *private_data)
{
    if (position->priv[0] > bucket_mask)
	return 0;

    if (key->wildcards == 0) {
	struct sw_flow *flow;
	int error;

	flow = lookup(key);
	if (!flow || !sw_flow::flow_has_out_port(flow, out_port))
	    return 0;

	error = callback(flow, private_data);
	if (!error)
	    position->priv[0] = -1;
	return error;
    } else {
	int i;

	for (i = position->priv[0]; i <= bucket_mask; i++) {
	    struct sw_flow *flow = buckets[i];
	    if (flow && sw_flow::flow_matches_1wild(&flow->key, key)
		&& sw_flow::flow_has_out_port(flow, out_port)) {
		int error = callback(flow, private_data);
		if (error) {
		    position->priv[0] = i;
		    return error;
		}
	    }
	}
	return 0;
    }
}

void 
FlowTable_Hash::stats(struct sw_table_stats *stats)
{
    stats->name = "hash";
    stats->wildcards = 0;          /* No wildcards are supported. */
    stats->n_flows   = n_flows;
    stats->max_flows = bucket_mask + 1;
    stats->n_lookup  = n_lookup;
    stats->n_matched = n_matched;
}

int 
FlowTable_Hash::create(unsigned int polynomial,
		     unsigned int n_buckets)
{
	BUG_ON(n_buckets & (n_buckets - 1));
	buckets = kmem_zalloc(n_buckets * sizeof *buckets);
	if (buckets == NULL) {
		click_chatter("failed to allocate %u buckets\n", n_buckets);
		return -1;
	}
	bucket_mask = n_buckets - 1;
	of_crc32_init(&crc32, polynomial);
	n_flows = 0;
	return 0;
}

static void *
FlowTable_Hash::kmem_alloc(size_t size)
{
	void *ptr;

#ifdef KMALLOC_MAX_SIZE
	if (size > KMALLOC_MAX_SIZE)
		return NULL;
#endif
	ptr = kmalloc(size, GFP_KERNEL);
	if (!ptr) {
		ptr = vmalloc(size);
		if (ptr)
			printk("openflow: used vmalloc for %lu bytes\n", 
					(unsigned long)size);
	}
	return ptr;
}

static void *
FlowTable_Hash::kmem_zalloc(size_t size)
{
	void *ptr = kmem_alloc(size);
	if (ptr)
		memset(ptr, 0, size);
	return ptr;
}

static void
FlowTable_Hash::kmem_free(void *ptr, size_t size)
{
	if (((unsigned long)ptr < VMALLOC_START) ||
		((unsigned long)ptr >= VMALLOC_END)) {
		kfree(ptr);
	} else {
		vfree(ptr);
	}
}

CLICK_ENDDECLS
ELEMENT_REQUIRES(linuxmodule)
ELEMENT_PROVIDES(OPENFLOW_TABLE_HASH)
