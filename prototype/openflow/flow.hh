// -*- related-file-name: "flow.cc" -*-
#ifndef CLICK_OFFLOW_HH
#define CLICK_OFFLOW_HH

#include <click/config.h>
#include <click/sync.hh>
#include <click/packet.hh>
#include <click/list.hh>

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

CLICK_DECLS

/* Identification data for a flow.
 * Network byte order except for the "wildcards" field.
 * Ordered to make bytewise comparisons (e.g. with memcmp()) fail quickly and
 * to keep the amount of padding to a minimum.
 * If you change the ordering of fields here, change flow_keys_equal() to
 * compare the proper fields.
 */
struct sw_flow_key {
	uint32_t nw_src;	/* IP source address. */
	uint32_t nw_dst;	/* IP destination address. */
	uint16_t in_port;	/* Input switch port */
	uint16_t dl_vlan;	/* Input VLAN. */
	uint16_t dl_type;	/* Ethernet frame type. */
	uint16_t tp_src;	/* TCP/UDP source port. */
	uint16_t tp_dst;	/* TCP/UDP destination port. */
	uint8_t dl_src[ETH_ALEN]; /* Ethernet source address. */
	uint8_t dl_dst[ETH_ALEN]; /* Ethernet destination address. */
	uint8_t nw_proto;	/* IP protocol. */
	uint8_t pad;		/* Pad to 32-bit alignment. */
	uint32_t wildcards;	/* Wildcard fields (host byte order). */
	uint32_t nw_src_mask;	/* 1-bit in each significant nw_src bit. */
	uint32_t nw_dst_mask;	/* 1-bit in each significant nw_dst bit. */

  sw_flow_key() {
	nw_src = 0;
	nw_dst = 0;
	in_port = 0;	
	dl_vlan = 0;	
	dl_type = 0;	
	tp_src = 0;	
	tp_dst = 0;	
	memset(dl_src,0,ETH_ALEN); 
	memset(dl_dst,0,ETH_ALEN); 
	nw_proto = 0;	
	pad = 0;	
	wildcards = 0;	
	nw_src_mask = 0;
	nw_dst_mask = 0;
  };

  bool flow_keys_equal(const sw_flow_key &k2) {
    return ((in_port == k2.in_port)
	    && (dl_vlan == k2.dl_vlan)
	    && (!memcmp(dl_src, k2.dl_src, ETH_ALEN))
	    && (!memcmp(dl_dst, k2.dl_dst, ETH_ALEN))
	    && (dl_type == k2.dl_type)
	    && (nw_src == k2.nw_src) 
	    && (nw_dst == k2.nw_dst)
	    && (nw_proto == k2.nw_proto)
	    && (tp_src == k2.tp_src)
	    && (tp_dst == k2.tp_dst));
  }
};

/* We keep actions as a separate structure because we need to be able to 
 * swap them out atomically when the modify command comes from a Flow
 * Modify message. */
struct sw_flow_actions {
	size_t actions_len;
	struct rcu_head rcu;

	struct ofp_action_header actions[0];
};

struct sw_flow {
        struct sw_flow_key key;
        typedef sw_flow_key key_type;
        typedef sw_flow_key key_const_reference;

        
        sw_flow *_hashnext;
	uint16_t priority;      /* Only used on entries with wildcards. */
	uint16_t idle_timeout;	/* Idle time before discarding (seconds). */
	uint16_t hard_timeout;  /* Hard expiration time (seconds) */
	unsigned long used;     /* Last used time (in jiffies). */

	struct sw_flow_actions *sf_acts;

	/* For use by table implementation. */
        List_member<sw_flow> node;
        List_member<sw_flow> iter_node;
	unsigned long serial;
	void *cb_private;

	SpinlockIRQ lock;         /* Lock this entry...mostly for stat updates */
	unsigned long init_time; /* When the flow was created (in jiffies). */
	uint64_t packet_count;   /* Number of packets associated with this entry */
	uint64_t byte_count;     /* Number of bytes associated with this entry */

	struct rcu_head rcu;
public:
  static int flow_init();
  static void flow_exit();
  sw_flow():lock(),key() { } ; 
  ~sw_flow() {};
  static int flow_matches_1wild(const struct sw_flow_key *, const struct sw_flow_key *);
  static int flow_fields_match(const struct sw_flow_key *a, const struct sw_flow_key *b,
			uint32_t w, uint32_t src_mask, uint32_t dst_mask);
  static sw_flow *flow_alloc(size_t actions_len, gfp_t flags);
  static void flow_free(sw_flow *f);
  static void rcu_free_flow_callback(struct rcu_head *rcu);
  static void rcu_free_acts_callback(struct rcu_head *rcu);

  static void flow_deferred_free(struct sw_flow *);
  static sw_flow* container_flow(struct rcu_head *rcu);
  static void flow_deferred_free_acts(struct sw_flow_actions *);
  static int flow_matches_2wild(const struct sw_flow_key *, const struct sw_flow_key *);
  static int flow_matches_desc(const struct sw_flow_key *, const struct sw_flow_key *, 
			int);
  
  static uint32_t make_nw_mask(int n_wild_bits);
  static void flow_extract_match(struct sw_flow_key* to, const struct ofp_match* from);
  static void flow_fill_match(struct ofp_match* to, const struct sw_flow_key* from);
  static int flow_timeout(struct sw_flow *flow);
  static int flow_has_out_port(struct sw_flow *flow, uint16_t out_port);
  static void flow_replace_acts(struct sw_flow *flow, const struct ofp_action_header *actions, size_t actions_len);
  static void print_flow(const struct sw_flow_key *key);
  static int flow_extract(Packet *pkt, uint16_t in_port, struct sw_flow_key *);

  static inline void flow_used(struct sw_flow *flow, Packet *pkt)
  {
    unsigned long flags;

    flow->used = jiffies;
    flags = flow->lock.acquire();
    flow->packet_count++;
    flow->byte_count += pkt->length();
    flow->lock.release(flags);
  }
};

typedef List<sw_flow,&sw_flow::node> FlowList;
typedef List<sw_flow,&sw_flow::iter_node> FlowIterList;

CLICK_ENDDECLS
#endif /* flow.h */
