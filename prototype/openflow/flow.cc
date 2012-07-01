// -*- c-basic-offset: 4; related-file-name: "flow.hh" -*-
/*
 * flow.{cc,hh} -- Openflow flow
 */

#include <click/config.h>
#include <clicknet/ether.h>
#include <clicknet/ip.h>
#include <clicknet/tcp.h>
#include <clicknet/udp.h>
#include <clicknet/icmp.h>
#include "flow.hh"
#include "openflow.hh"

CLICK_CXX_PROTECT
#include <linux/if.h>
#include <linux/if_vlan.h>
#include <linux/llc.h>
#include <net/llc_pdu.h>
CLICK_CXX_UNPROTECT

CLICK_DECLS

struct kmem_cache *flow_cache = NULL;

/* Internal function used to compare fields in flow. */
inline int 
sw_flow::flow_fields_match(const struct sw_flow_key *a, const struct sw_flow_key *b,
		      uint32_t w, uint32_t src_mask, uint32_t dst_mask)
{
	return ((w & OFPFW_IN_PORT || a->in_port == b->in_port)
		&& (w & OFPFW_DL_VLAN || a->dl_vlan == b->dl_vlan)
		&& (w & OFPFW_DL_SRC || !memcmp(a->dl_src, b->dl_src, ETH_ALEN))
		&& (w & OFPFW_DL_DST || !memcmp(a->dl_dst, b->dl_dst, ETH_ALEN))
		&& (w & OFPFW_DL_TYPE || a->dl_type == b->dl_type)
		&& !((a->nw_src ^ b->nw_src) & src_mask)
		&& !((a->nw_dst ^ b->nw_dst) & dst_mask)
		&& (w & OFPFW_NW_PROTO || a->nw_proto == b->nw_proto)
		&& (w & OFPFW_TP_SRC || a->tp_src == b->tp_src)
		&& (w & OFPFW_TP_DST || a->tp_dst == b->tp_dst));
}

/* Returns nonzero if 'a' and 'b' match, that is, if their fields are equal
 * modulo wildcards in 'b', zero otherwise. */
int 
sw_flow::flow_matches_1wild(const struct sw_flow_key *a, const struct sw_flow_key *b)
{
    return flow_fields_match(a, b, b->wildcards, b->nw_src_mask, b->nw_dst_mask);
}

/* Returns nonzero if 'a' and 'b' match, that is, if their fields are equal
 * modulo wildcards in 'a' or 'b', zero otherwise. */
int 
sw_flow::flow_matches_2wild(const struct sw_flow_key *a,
		       const struct sw_flow_key *b)
{
	return flow_fields_match(a, b,
				 a->wildcards | b->wildcards,
				 a->nw_src_mask & b->nw_src_mask,
				 a->nw_dst_mask & b->nw_dst_mask);
}

/* Returns nonzero if 't' (the table entry's key) and 'd' (the key
 * describing the match) match, that is, if their fields are
 * equal modulo wildcards, zero otherwise.  If 'strict' is nonzero, the
 * wildcards must match in both 't_key' and 'd_key'.  Note that the
 * table's wildcards are ignored unless 'strict' is set. */
int 
sw_flow::flow_matches_desc(const struct sw_flow_key *t, const struct sw_flow_key *d, 
		int strict)
{
	if (strict && d->wildcards != t->wildcards)
		return 0;
	return flow_matches_1wild(t, d);
}

static uint32_t 
sw_flow::make_nw_mask(int n_wild_bits)
{
	n_wild_bits &= (1u << OFPFW_NW_SRC_BITS) - 1;
	return n_wild_bits < 32 ? htonl(~((1u << n_wild_bits) - 1)) : 0;
}

void 
sw_flow::flow_extract_match(struct sw_flow_key* to, const struct ofp_match* from)
{
	to->wildcards = ntohl(from->wildcards) & OFPFW_ALL;
	to->pad = 0;
	to->in_port = from->in_port;
	to->dl_vlan = from->dl_vlan;
	memcpy(to->dl_src, from->dl_src, ETH_ALEN);
	memcpy(to->dl_dst, from->dl_dst, ETH_ALEN);
	to->dl_type = from->dl_type;

	to->nw_src = to->nw_dst = to->nw_proto = 0;
	to->tp_src = to->tp_dst = 0;

#define OFPFW_TP (OFPFW_TP_SRC | OFPFW_TP_DST)
#define OFPFW_NW (OFPFW_NW_SRC_MASK | OFPFW_NW_DST_MASK | OFPFW_NW_PROTO)
	if (to->wildcards & OFPFW_DL_TYPE) {
		/* Can't sensibly match on network or transport headers if the
		 * data link type is unknown. */
		to->wildcards |= OFPFW_NW | OFPFW_TP;
	} else if (from->dl_type == htons(ETH_P_IP)) {
		to->nw_src   = from->nw_src;
		to->nw_dst   = from->nw_dst;
		to->nw_proto = from->nw_proto;

		if (to->wildcards & OFPFW_NW_PROTO) {
			/* Can't sensibly match on transport headers if the
			 * network protocol is unknown. */
			to->wildcards |= OFPFW_TP;
		} else if (from->nw_proto == IPPROTO_TCP
				|| from->nw_proto == IPPROTO_UDP
				|| from->nw_proto == IPPROTO_ICMP) {
			to->tp_src = from->tp_src;
			to->tp_dst = from->tp_dst;
		} else {
			/* Transport layer fields are undefined.  Mark them as
			 * exact-match to allow such flows to reside in
			 * table-hash, instead of falling into table-linear. */
			to->wildcards &= ~OFPFW_TP;
		}
	} else {
		/* Network and transport layer fields are undefined.  Mark them
		 * as exact-match to allow such flows to reside in table-hash,
		 * instead of falling into table-linear. */
		to->wildcards &= ~(OFPFW_NW | OFPFW_TP);
	}

	/* We set these late because code above adjusts to->wildcards. */
	to->nw_src_mask = make_nw_mask(to->wildcards >> OFPFW_NW_SRC_SHIFT);
	to->nw_dst_mask = make_nw_mask(to->wildcards >> OFPFW_NW_DST_SHIFT);
}

void 
sw_flow::flow_fill_match(struct ofp_match* to, const struct sw_flow_key* from)
{
	to->wildcards = htonl(from->wildcards);
	to->in_port   = from->in_port;
	to->dl_vlan   = from->dl_vlan;
	memcpy(to->dl_src, from->dl_src, ETH_ALEN);
	memcpy(to->dl_dst, from->dl_dst, ETH_ALEN);
	to->dl_type   = from->dl_type;
	to->nw_src    = from->nw_src;
	to->nw_dst    = from->nw_dst;
	to->nw_proto  = from->nw_proto;
	to->tp_src    = from->tp_src;
	to->tp_dst    = from->tp_dst;
	to->pad       = 0;
}

int 
sw_flow::flow_timeout(struct sw_flow *flow)
{
	if (flow->idle_timeout != OFP_FLOW_PERMANENT
	    && time_after(jiffies, flow->used + flow->idle_timeout * HZ)) {
		return OFPER_IDLE_TIMEOUT;
	}
	else if (flow->hard_timeout != OFP_FLOW_PERMANENT
		 && time_after(jiffies,
			       flow->init_time + flow->hard_timeout * HZ)) {
		return OFPER_HARD_TIMEOUT;
	}
	else
		return -1;
}

/* Returns nonzero if 'flow' contains an output action to 'out_port' or
 * has the value OFPP_NONE. 'out_port' is in network-byte order. */
int 
sw_flow::flow_has_out_port(struct sw_flow *flow, uint16_t out_port)
{
	struct sw_flow_actions *sf_acts;
	size_t actions_len;
	uint8_t *p;

	if (out_port == htons(OFPP_NONE))
		return 1;

	sf_acts = rcu_dereference(flow->sf_acts);

	actions_len = sf_acts->actions_len;
	p = (uint8_t *)sf_acts->actions;

	while (actions_len > 0) {
		struct ofp_action_header *ah = (struct ofp_action_header *)p;
		size_t len = ntohs(ah->len);

		if (ah->type == htons(OFPAT_OUTPUT)) {
			struct ofp_action_output *oa = (struct ofp_action_output *)p;
			if (oa->port == out_port)
				return 1;
		}

		p += len;
		actions_len -= len;
	}

	return 0;
}

/* Copies 'actions' into a newly allocated structure for use by 'flow'
 * and safely frees the structure that defined the previous actions. */
void 
sw_flow::flow_replace_acts(struct sw_flow *flow, 
			   const struct ofp_action_header *actions, size_t actions_len)
{
	struct sw_flow_actions *sfa;
	struct sw_flow_actions *orig_sfa = flow->sf_acts;
	size_t size = sizeof *sfa + actions_len;

	sfa = kmalloc(size, GFP_ATOMIC);
	if (unlikely(!sfa))
		return;

	sfa->actions_len = actions_len;
	memcpy(sfa->actions, actions, actions_len);

	rcu_assign_pointer(flow->sf_acts, sfa);
	flow_deferred_free_acts(orig_sfa);

	return;
}

/* Prints a representation of 'key' to the kernel log. */
void 
sw_flow::print_flow(const struct sw_flow_key *key)
{
	printk("wild%08x port%04x:vlan%04x mac%02x:%02x:%02x:%02x:%02x:%02x"
			"->%02x:%02x:%02x:%02x:%02x:%02x "
			"proto%04x ip%u.%u.%u.%u->%u.%u.%u.%u port%d->%d\n",
			key->wildcards, ntohs(key->in_port), ntohs(key->dl_vlan),
			key->dl_src[0], key->dl_src[1], key->dl_src[2],
			key->dl_src[3], key->dl_src[4], key->dl_src[5],
			key->dl_dst[0], key->dl_dst[1], key->dl_dst[2],
			key->dl_dst[3], key->dl_dst[4], key->dl_dst[5],
			ntohs(key->dl_type),
			((unsigned char *)&key->nw_src)[0],
			((unsigned char *)&key->nw_src)[1],
			((unsigned char *)&key->nw_src)[2],
			((unsigned char *)&key->nw_src)[3],
			((unsigned char *)&key->nw_dst)[0],
			((unsigned char *)&key->nw_dst)[1],
			((unsigned char *)&key->nw_dst)[2],
			((unsigned char *)&key->nw_dst)[3],
			ntohs(key->tp_src), ntohs(key->tp_dst));
}

#define SNAP_OUI_LEN 3

struct eth_snap_hdr
{
	struct ethhdr eth;
	uint8_t  dsap;  /* Always 0xAA */
	uint8_t  ssap;  /* Always 0xAA */
	uint8_t  ctrl;
	uint8_t  oui[SNAP_OUI_LEN];
	uint16_t ethertype;
} __attribute__ ((packed));

static int is_snap(const struct eth_snap_hdr *esh)
{
	return (esh->dsap == LLC_SAP_SNAP
		&& esh->ssap == LLC_SAP_SNAP
		&& !memcmp(esh->oui, "\0\0\0", 3));
}


extern void print_key(struct sw_flow_key *sfk);

/* Parses the Ethernet frame in 'skb', which was received on 'in_port',
 * and initializes 'key' to match.  Returns 1 if 'skb' contains an IP
 * fragment, 0 otherwise. */
int 
sw_flow::flow_extract(Packet *pkt, uint16_t in_port,
		      struct sw_flow_key *key)
{
    click_ether *eth;
    struct eth_snap_hdr *esh;
    int retval = 0;
    int nh_ofs;

    memset(key, 0, sizeof *key);
    key->dl_vlan = htons(OFP_VLAN_NONE);
    key->in_port = htons(in_port);

    if (!pkt->has_mac_header()) {
	return 0;
    }

    eth = pkt->ether_header();
    esh = reinterpret_cast<eth_snap_hdr *>(eth);
    nh_ofs = sizeof *eth; 
    if (likely(ntohs(eth->ether_type) >= OFP_DL_TYPE_ETH2_CUTOFF))
	key->dl_type = eth->ether_type;
    else if (pkt->length() >= sizeof *esh && is_snap(esh)) {
	key->dl_type = esh->ethertype;
	nh_ofs = sizeof *esh;
    } else {
	key->dl_type = htons(OFP_DL_TYPE_NOT_ETH_TYPE);
	if (pkt->length() >= nh_ofs + sizeof(struct llc_pdu_un)) {
	    nh_ofs += sizeof(struct llc_pdu_un); 
	}
    }

    /* Check for a VLAN tag */
    if (key->dl_type == htons(ETH_P_8021Q) &&
	pkt->length() >= nh_ofs + sizeof(struct vlan_hdr)) {
	unsigned char *data = const_cast<unsigned char *>(pkt->data());
	struct vlan_hdr *vh = reinterpret_cast<struct vlan_hdr*>(data + nh_ofs);
	key->dl_type = vh->h_vlan_encapsulated_proto;
	key->dl_vlan = vh->h_vlan_TCI & htons(VLAN_VID_MASK);
	nh_ofs += sizeof(struct vlan_hdr);
    }

    memcpy(key->dl_src, eth->ether_shost, ETH_ALEN);
    memcpy(key->dl_dst, eth->ether_dhost, ETH_ALEN);

    /* Network layer. */

    if (key->dl_type == htons(ETH_P_IP)) {
	const click_ip *iph = (const click_ip *) (pkt->data() + nh_ofs);
	if (iph) {
		if (iph->ip_v == 4) {
			if (iph->ip_hl >= 5 
		    	&& ntohs(iph->ip_len) >= (iph->ip_hl << 2)
		    	&& reinterpret_cast<const uint8_t *>(iph) + (iph->ip_hl << 2) <= pkt->end_data()) {
		    		pkt->set_ip_header(iph, iph->ip_hl << 2);
			}
		}
	}
	else {
	    click_chatter("OpenFlow Debug(%s,%d): iph not found even if ETH_P_IP is set in the ether header, clearing transport header",
			 __FUNCTION__,__LINE__);
	    pkt->clear_transport_header();	
	}	
    }	

    if (key->dl_type == htons(ETH_P_IP) && pkt->has_network_header()) {
	const click_ip *nh = pkt->ip_header();
	int th_ofs = nh_ofs + nh->ip_hl * 4;
	key->nw_src = nh->ip_src.s_addr;
	key->nw_dst = nh->ip_dst.s_addr;
	key->nw_proto = nh->ip_p;

	/* Transport layer. */
	if (!(nh->ip_off & htons(IP_MF | IP_OFFMASK))) {
	    if (key->nw_proto == IPPROTO_TCP) {
		if (pkt->has_transport_header()) {
		    const click_tcp *tcp= pkt->tcp_header();
		    key->tp_src = tcp->th_sport;
		    key->tp_dst = tcp->th_dport;
		} else {
		    /* Avoid tricking other code into
		     * thinking that this packet has an L4
		     * header. */
		    key->nw_proto = 0;
		}
	    } else if (key->nw_proto == IPPROTO_UDP) {
		if (pkt->has_transport_header()) {
		    const click_udp *udp = pkt->udp_header();
		    key->tp_src = udp->uh_sport;
		    key->tp_dst = udp->uh_dport;
		} else {
		    /* Avoid tricking other code into
		     * thinking that this packet has an L4
		     * header. */
		    key->nw_proto = 0;
		}
	    } else if (key->nw_proto == IPPROTO_ICMP) {
		if (pkt->has_transport_header()) {
		    const click_icmp *icmp = pkt->icmp_header();

		    /* The ICMP type and code fields use the 16-bit
		     * transport port fields, so we need to store them
		     * in 16-bit network byte order. */
		    key->tp_src = htons(icmp->icmp_type);
		    key->tp_dst = htons(icmp->icmp_code);
		} else {
		    /* Avoid tricking other code into
		     * thinking that this packet has an L4
		     * header. */
		    key->nw_proto = 0;
		}
	    }
	} else {
	    retval = 1;
	}
    }

    return retval;
}

/* Initializes the flow module.
 * Returns zero if successful or a negative error code. */
static int 
sw_flow::flow_init()
{
    if (flow_cache) {
	return -1;
    }
    
    flow_cache = kmem_cache_create("flow", sizeof(struct sw_flow), 0,
				   0, NULL);
    if (flow_cache == NULL)
	return -ENOMEM;

    return 0;
}

/* Uninitializes the flow module. */
static void 
sw_flow::flow_exit()
{
    kmem_cache_destroy(flow_cache);
}

/* Allocates and returns a new flow with room for 'actions_len' actions, 
 * using allocation flags 'flags'.  Returns the new flow or a null pointer 
 * on failure. */
sw_flow *
sw_flow::flow_alloc(size_t actions_len, gfp_t flags)
{
	struct sw_flow_actions *sfa;
	size_t size = sizeof *sfa + actions_len;
	void *mem_ptr = NULL;
	if (flow_cache) {
	    mem_ptr = kmem_cache_alloc(flow_cache, flags);
	}
	else {
	    return NULL;
	}

	if (!mem_ptr) {
	    return NULL;
	}

	struct sw_flow *flow = new (mem_ptr) sw_flow();

	if (unlikely(!flow))
		return NULL;

	sfa = kmalloc(size, flags);
	if (unlikely(!sfa)) {
	    kmem_cache_free(flow_cache, flow);
		return NULL;
	}
	sfa->actions_len = actions_len;
	flow->sf_acts = sfa;

	return flow;
}

/* Frees 'flow' immediately. */
void 
sw_flow::flow_free(sw_flow *f)
{
    if (unlikely(!f))
	return;
    kfree(f->sf_acts);
    kmem_cache_free(flow_cache, f);
}

inline sw_flow*
sw_flow::container_flow(struct rcu_head *rcu)
{
    return reinterpret_cast<sw_flow*>((reinterpret_cast<char *>(rcu) - offsetof(sw_flow, rcu)));
}

/* RCU callback used by flow_deferred_free. */
void 
sw_flow::rcu_free_flow_callback(struct rcu_head *rcu)
{
     flow_free(container_flow(rcu));
}

/* Schedules 'flow' to be freed after the next RCU grace period.
 * The caller must hold rcu_read_lock for this to be sensible. */
void 
sw_flow::flow_deferred_free(struct sw_flow *flow)
{
	call_rcu(&flow->rcu, rcu_free_flow_callback);
}

/* RCU callback used by flow_deferred_free_acts. */
void 
sw_flow::rcu_free_acts_callback(struct rcu_head *rcu)
{
    struct sw_flow_actions *sf_acts = reinterpret_cast<sw_flow_actions*>
	((reinterpret_cast<char *>(rcu) - offsetof(sw_flow_actions, rcu)));
    kfree(sf_acts);
}

/* Schedules 'sf_acts' to be freed after the next RCU grace period.
 * The caller must hold rcu_read_lock for this to be sensible. */
void 
sw_flow::flow_deferred_free_acts(struct sw_flow_actions *sf_acts)
{
	call_rcu(&sf_acts->rcu, rcu_free_acts_callback);
}

CLICK_ENDDECLS
ELEMENT_REQUIRES(linuxmodule)
ELEMENT_PROVIDES(OPENFLOW_FLOW)
