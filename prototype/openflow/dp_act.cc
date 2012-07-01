// -*- c-basic-offset: 4; related-file-name: "dp_act.hh" -*-
/*
 * dp_act.{cc,hh} -- Openflow dp_act
 */
#include <click/config.h>
#include <clicknet/ether.h>
#include <clicknet/ip.h>
#include <clicknet/tcp.h>
#include <clicknet/udp.h>
#include <clicknet/icmp.h>
#include "openflow.hh"
#include "forward.hh"
#include "openflow_genl.hh"
#include "dp_act.hh"

CLICK_CXX_PROTECT
#include <linux/skbuff.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/if_vlan.h>
#include <net/checksum.h>
#include <linux/netdevice.h>
#include <linux/rtnetlink.h>
//#include <sys/socket.h>
CLICK_CXX_UNPROTECT

CLICK_DECLS

/*extern struct genl_multicast_group mc_group;

//Minlan
extern struct genl_family feedback_genl_family;
extern struct genl_multicast_group feedback_mc_group;

extern struct sender feedback_sender;
*/

static uint16_t
validate_output(Datapath *dp, const sw_flow_key *key, 
		const struct ofp_action_header *ah) 
{
  struct ofp_action_output *oa = (struct ofp_action_output *)ah;

  if (oa->port == htons(OFPP_NONE) || 
      (!(key->wildcards & OFPFW_IN_PORT) && oa->port == key->in_port)) 
    return OFPBAC_BAD_OUT_PORT;

  return ACT_VALIDATION_OK;
}


#define MAX_PAYLOAD 1024
struct sock *nl_sk = NULL;
#define NETLINK_TEST 17

static int 
do_output(Datapath *dp, Packet *p_in, size_t max_len,
		int out_port, int ignore_no_fwd)
{
	if (!p_in)
		return -ENOMEM;

        //send_feedback();

	return (likely(out_port != OFPP_CONTROLLER)
		? dp->output_port(p_in, out_port, ignore_no_fwd)
		: dp->output_control(p_in, dp->storage.store_packet(p_in),
					 max_len, OFPR_ACTION));
}


static Packet*
vlan_pull_tag(WritablePacket *p_in)
{
  struct sk_buff *skb = p_in->skb();
  struct vlan_ethhdr *vh = vlan_eth_hdr(skb);
  struct ethhdr *eh;

  /* Verify we were given a vlan packet */
  if (vh->h_vlan_proto != htons(ETH_P_8021Q)) {
    return p_in;
  }
	
  memmove(skb->data + VLAN_HLEN, skb->data, 2 * VLAN_ETH_ALEN);

  eh = (struct ethhdr *)skb_pull(skb, VLAN_HLEN);

  skb->protocol = eh->h_proto;
  skb->mac_header += VLAN_HLEN;
  Packet *r = Packet::make(skb);
  p_in->kill();
  return r;
}

Packet *
modify_vlan_tci(WritablePacket *p_in, sw_flow_key *key, 
		uint16_t tci, uint16_t mask)
{
  struct sk_buff *skb = p_in->skb();
  struct vlan_ethhdr *vh = vlan_eth_hdr(skb);

  if (key->dl_vlan != htons(OFP_VLAN_NONE)) {
    /* Modify vlan id, but maintain other TCI values */
    vh->h_vlan_TCI = (vh->h_vlan_TCI & ~(htons(mask))) | htons(tci);
  } else  {
    /* Add vlan header */

    /* xxx The vlan_put_tag function, doesn't seem to work
     * xxx reliably when it attempts to use the hardware-accelerated
     * xxx version.  We'll directly use the software version
     * xxx until the problem can be diagnosed.
     */
    skb = __vlan_put_tag(skb, tci);
    vh = vlan_eth_hdr(skb);
  }
  key->dl_vlan = vh->h_vlan_TCI & htons(VLAN_VID_MASK);
  Packet *r = Packet::make(skb);
  p_in->kill();
  return r;
}

Packet *
set_vlan_vid(WritablePacket *p_in, struct sw_flow_key *key, 
		const struct ofp_action_header *ah)
{
	struct ofp_action_vlan_vid *va = (struct ofp_action_vlan_vid *)ah;
	uint16_t tci = ntohs(va->vlan_vid);

	return modify_vlan_tci(p_in, key, tci, VLAN_VID_MASK);
}

/* Mask for the priority bits in a vlan header.  The kernel doesn't
 * define this like it does for VID. */
#define VLAN_PCP_MASK 0xe000

Packet *
set_vlan_pcp(WritablePacket *p_in, struct sw_flow_key *key, 
		const struct ofp_action_header *ah)
{
	struct ofp_action_vlan_pcp *va = (struct ofp_action_vlan_pcp *)ah;
	uint16_t tci = (uint16_t)va->vlan_pcp << 13;

	return modify_vlan_tci(p_in, key, tci, VLAN_PCP_MASK);
}

Packet *
strip_vlan(WritablePacket *p_in, struct sw_flow_key *key, 
		const struct ofp_action_header *ah)
{
	Packet *q = vlan_pull_tag(p_in);
	key->dl_vlan = htons(OFP_VLAN_NONE);

	return q;
}

Packet *
set_dl_addr(WritablePacket *p_in, struct sw_flow_key *key, 
		const struct ofp_action_header *ah)
{
  struct ofp_action_dl_addr *da = (struct ofp_action_dl_addr *)ah;
  struct sk_buff *skb = p_in->skb();
  struct ethhdr *eh = eth_hdr(skb);

  if (da->type == htons(OFPAT_SET_DL_SRC))
    memcpy(eh->h_source, da->dl_addr, sizeof eh->h_source);
  else
    memcpy(eh->h_dest, da->dl_addr, sizeof eh->h_dest);

  Packet *r = Packet::make(skb);
  p_in->kill();
  return r;
}

/* Updates 'sum', which is a field in 'skb''s data, given that a 4-byte field
 * covered by the sum has been changed from 'from' to 'to'.  If set,
 * 'pseudohdr' indicates that the field is in the TCP or UDP pseudo-header.
 * Based on nf_proto_csum_replace4. */
static void update_csum(__sum16 *sum, struct sk_buff *skb,
			__be32 from, __be32 to, int pseudohdr)
{
	__be32 diff[] = { ~from, to };
	if (skb->ip_summed != CHECKSUM_PARTIAL) {
		*sum = csum_fold(csum_partial((char *)diff, sizeof(diff),
				~csum_unfold(*sum)));
		if (skb->ip_summed == CHECKSUM_COMPLETE && pseudohdr)
			skb->csum = ~csum_partial((char *)diff, sizeof(diff),
						~skb->csum);
	} else if (pseudohdr)
		*sum = ~csum_fold(csum_partial((char *)diff, sizeof(diff),
				csum_unfold(*sum)));
}

Packet * 
set_nw_addr(WritablePacket *p_in, struct sw_flow_key *key, 
		const struct ofp_action_header *ah)
{
  struct sk_buff *skb = p_in->skb();
  struct ofp_action_nw_addr *na = (struct ofp_action_nw_addr *)ah;
  uint16_t eth_proto = ntohs(key->dl_type);

  if (eth_proto == ETH_P_IP) {
    click_ip *nh = p_in->ip_header();
    uint32_t new_addr, *field;
    
    new_addr = na->nw_addr;
    
    if (ah->type == htons(OFPAT_SET_NW_SRC))
      field = &nh->ip_src.s_addr;
    else
      field = &nh->ip_dst.s_addr;
    
    if (key->nw_proto == IPPROTO_TCP) {
      click_tcp *th = p_in->tcp_header();
      update_csum(&th->th_sum, skb, *field, new_addr, 1);
    } else if (key->nw_proto == IPPROTO_UDP) {
      click_udp *th = p_in->udp_header();
      update_csum(&th->uh_sum, skb, *field, new_addr, 1);
    }
    update_csum(&nh->ip_sum, skb, *field, new_addr, 0);
    *field = new_addr;
  }
  Packet *r = Packet::make(skb);
  p_in->kill();
  return r;
}

Packet *
set_tp_port(WritablePacket *p_in, struct sw_flow_key *key, 
		const struct ofp_action_header *ah)
{
  struct sk_buff *skb = p_in->skb();

  struct ofp_action_tp_port *ta = (struct ofp_action_tp_port *)ah;
  uint16_t eth_proto = ntohs(key->dl_type);

  if (eth_proto == ETH_P_IP) {
    uint16_t new_port, *field;
    
    new_port = ta->tp_port;

    if (key->nw_proto == IPPROTO_TCP) {
      click_tcp *th = p_in->tcp_header();

      if (ah->type == htons(OFPAT_SET_TP_SRC))
	field = &th->th_sport;
      else
	field = &th->th_dport;

      update_csum(&th->th_sum, skb, *field, new_port, 1);
      *field = new_port;
    } else if (key->nw_proto == IPPROTO_UDP) {
      click_udp *th = p_in->udp_header();

      if (ah->type == htons(OFPAT_SET_TP_SRC))
	field = &th->uh_sport;
      else
	field = &th->uh_dport;

      update_csum(&th->uh_sum, skb, *field, new_port, 1);
			*field = new_port;
    }
  }
  Packet *r = Packet::make(skb);
  p_in->kill();
  return r;
}

/*
Packet * 
send_feedback(WritablePacket *p_in, struct sw_flow_key *key, 
		const struct ofp_action_header *ah)
{
  struct sk_buff *skb = p_in->skb();
  struct ofp_action_nw_addr *na = (struct ofp_action_nw_addr *)ah;
  uint16_t eth_proto = ntohs(key->dl_type);

  if (eth_proto == ETH_P_IP) {
    click_ip *nh = p_in->ip_header();
    uint32_t new_addr, *field;
    
    new_addr = na->nw_addr;

    click_chatter("feed back ");

    if (ah->type == htons(OFPAT_SET_NW_SRC))
      field = &nh->ip_src.s_addr;
    else
      field = &nh->ip_dst.s_addr;
    
    if (key->nw_proto == IPPROTO_TCP) {
      click_tcp *th = p_in->tcp_header();
      update_csum(&th->th_sum, skb, *field, new_addr, 1);
    } else if (key->nw_proto == IPPROTO_UDP) {
      click_udp *th = p_in->udp_header();
      update_csum(&th->uh_sum, skb, *field, new_addr, 1);
    }
    update_csum(&nh->ip_sum, skb, *field, new_addr, 0);
    *field = new_addr;
  }
  Packet *r = Packet::make(skb);
  p_in->kill();
  return r;
}
*/

struct openflow_action {
  size_t min_size;
  size_t max_size;
  uint16_t (*validate)(Datapath *dp, 
		       const sw_flow_key *key,
		       const struct ofp_action_header *ah);
  Packet *(*execute)(Packet *p_in, 
		     struct sw_flow_key *key, 
		     const struct ofp_action_header *ah);
};

static struct openflow_action of_actions[OFPAT_SET_TP_DST+1] = {
        //of_actions[OFPAT_OUTPUT] = 
        {
		sizeof(struct ofp_action_output),
		sizeof(struct ofp_action_output),
		validate_output,
		NULL                   /* This is optimized into execute_actions */
	},
	//of_actions[OFPAT_SET_VLAN_VID] = 
	{
		sizeof(struct ofp_action_vlan_vid),
		sizeof(struct ofp_action_vlan_vid),
		NULL,
		set_vlan_vid
	},
	//of_actions[OFPAT_SET_VLAN_PCP] = 
	{
		sizeof(struct ofp_action_vlan_pcp),
		sizeof(struct ofp_action_vlan_pcp),
		NULL,
		set_vlan_pcp
	},
	//of_actions[OFPAT_STRIP_VLAN] = 
	{
		sizeof(struct ofp_action_header),
		sizeof(struct ofp_action_header),
		NULL,
		strip_vlan
	},
	//of_actions[OFPAT_SET_DL_SRC] = 
	{
		sizeof(struct ofp_action_dl_addr),
		sizeof(struct ofp_action_dl_addr),
		NULL,
		set_dl_addr
	},
	//of_actions[OFPAT_SET_DL_DST] = 
	{
		sizeof(struct ofp_action_dl_addr),
		sizeof(struct ofp_action_dl_addr),
		NULL,
		set_dl_addr
	},
	//of_actions[OFPAT_SET_NW_SRC] = 
	{
		sizeof(struct ofp_action_nw_addr),
		sizeof(struct ofp_action_nw_addr),
		NULL,
		set_nw_addr
	},
	//of_actions[OFPAT_SET_NW_DST] = 
	{
		sizeof(struct ofp_action_nw_addr),
		sizeof(struct ofp_action_nw_addr),
		NULL,
		set_nw_addr
	},
	//of_actions[OFPAT_SET_TP_SRC] = 
	{
		sizeof(struct ofp_action_tp_port),
		sizeof(struct ofp_action_tp_port),
		NULL,
		set_tp_port
	},
        //of_actions[OFPAT_FEEDBACK]
        /*{
          sizeof(struct ofp_action_feedback),
          sizeof(struct ofp_action_feedback),
          NULL,
          send_feedback
          },*/
	//of_actions[OFPAT_SET_TP_DST] = 
	{
		sizeof(struct ofp_action_tp_port),
		sizeof(struct ofp_action_tp_port),
		NULL,
		set_tp_port
	}
	/* OFPAT_VENDOR is not here, since it would blow up the array size. */
};

/* Validate built-in OpenFlow actions.  Either returns ACT_VALIDATION_OK
 * or an OFPET_BAD_ACTION error code. */
static uint16_t 
validate_ofpat(Datapath *dp, const struct sw_flow_key *key, 
		const struct ofp_action_header *ah, uint16_t type, uint16_t len)
{
	int ret = ACT_VALIDATION_OK;
	const struct openflow_action *act = &of_actions[type];

	if ((len < act->min_size) || (len > act->max_size)) 
		return OFPBAC_BAD_LEN;

	if (act->validate) 
		ret = act->validate(dp, key, ah);

	return ret;
}

/* Validate vendor-defined actions.  Either returns ACT_VALIDATION_OK
 * or an OFPET_BAD_ACTION error code. */
static uint16_t 
validate_vendor(Datapath *dp, const struct sw_flow_key *key, 
		const struct ofp_action_header *ah, uint16_t len)
{
	struct ofp_action_vendor_header *avh;
	int ret = ACT_VALIDATION_OK;

	if (len < sizeof(struct ofp_action_vendor_header))
		return OFPBAC_BAD_LEN;

	avh = (struct ofp_action_vendor_header *)ah;

	switch(ntohl(avh->vendor)) {

	default:
		return OFPBAC_BAD_VENDOR;
	}

	return ret;
}

/* Validates a list of actions.  If a problem is found, a code for the
 * OFPET_BAD_ACTION error type is returned.  If the action list validates, 
 * ACT_VALIDATION_OK is returned. */
uint16_t 
validate_actions(Datapath *dp, const struct sw_flow_key *key,
		const struct ofp_action_header *actions, size_t actions_len)
{
	uint8_t *p = (uint8_t *)actions;
	int err;

	while (actions_len >= sizeof(struct ofp_action_header)) {
		struct ofp_action_header *ah = (struct ofp_action_header *)p;
		size_t len = ntohs(ah->len);
		uint16_t type;

		/* Make there's enough remaining data for the specified length
		 * and that the action length is a multiple of 64 bits. */
		if ((actions_len < len) || (len % 8) != 0)
			return OFPBAC_BAD_LEN;

		type = ntohs(ah->type);
		if (type < (OFPAT_SET_TP_DST+1)) {
			err = validate_ofpat(dp, key, ah, type, len);
			if (err != ACT_VALIDATION_OK)
				return err;
		} else if (type == OFPAT_VENDOR) {
			err = validate_vendor(dp, key, ah, len);
			if (err != ACT_VALIDATION_OK)
				return err;
		} else 
			return OFPBAC_BAD_TYPE;

		p += len;
		actions_len -= len;
	}

	/* Check if there's any trailing garbage. */
	if (actions_len != 0) 
		return OFPBAC_BAD_LEN;

	return ACT_VALIDATION_OK;
}

/* Execute a built-in OpenFlow action against 'skb'. */
Packet *
execute_ofpat(Packet *p_in, struct sw_flow_key *key, 
		const struct ofp_action_header *ah, uint16_t type)
{
	const struct openflow_action *act = &of_actions[type];
	WritablePacket *q = NULL;

	if (act->execute)  {
	  q= p_in->uniqueify();
		if (!q) {
			if (net_ratelimit())
				printk("make_writable failed\n");
			return p_in;
		}
		q = act->execute(q, key, ah);
	}

	return q;
}

/* Execute a vendor-defined action against 'skb'. */
Packet *
execute_vendor(Packet *p_in, const struct sw_flow_key *key, 
		const struct ofp_action_header *ah)
{
	struct ofp_action_vendor_header *avh 
			= (struct ofp_action_vendor_header *)ah;

	/* NB: If changes need to be made to the packet, a call should be
	 * made to make_writable or its equivalent first. */

	switch(ntohl(avh->vendor)) {

	default:
		/* This should not be possible due to prior validation. */
		if (net_ratelimit())
			printk("attempt to execute action with unknown vendor: %#x\n", 
					ntohl(avh->vendor));
		break;
	}

	return p_in;
}

/* Execute a list of actions against 'skb'. */
void execute_actions(Datapath *dp, Packet *p_in,
		     struct sw_flow_key *key,
		     const struct ofp_action_header *actions, size_t actions_len,
		     int ignore_no_fwd)
{
  /* Every output action needs a separate clone of 'skb', but the common
   * case is just a single output action, so that doing a clone and
   * then freeing the original skbuff is wasteful.  So the following code
   * is slightly obscure just to avoid that. */
  int prev_port;
  size_t max_len=0;	 /* Initialze to make compiler happy */
  uint8_t *p = (uint8_t *)actions;

  prev_port = -1;

  /* The action list was already validated, so we can be a bit looser
   * in our sanity-checking. */
  while (actions_len > 0) {
    struct ofp_action_header *ah = (struct ofp_action_header *)p;
    size_t len = htons(ah->len);

    if (prev_port != -1) {
      do_output(dp, p_in->clone(),
		max_len, prev_port, ignore_no_fwd);
      prev_port = -1;
    }
    if (likely(ah->type == htons(OFPAT_OUTPUT))) {
      struct ofp_action_output *oa = (struct ofp_action_output *)p;
      prev_port = ntohs(oa->port);
      max_len = ntohs(oa->max_len);
    } else {
      uint16_t type = ntohs(ah->type);

      if (type < (OFPAT_SET_TP_DST+1)) 
	p_in = execute_ofpat(p_in, key, ah, type);
      else if (type == OFPAT_VENDOR) 
	p_in = execute_vendor(p_in, key, ah);

      if (!p_in) {
	if (net_ratelimit())
	  click_chatter("execute_actions lost skb\n");
	return;
      }
    }

    p += len;
    actions_len -= len;
  }
  if (prev_port != -1) {
      do_output(dp, p_in, max_len, prev_port, ignore_no_fwd);
  }
  else
    p_in->kill();
}

CLICK_ENDDECLS
ELEMENT_REQUIRES(linuxmodule)
ELEMENT_PROVIDES(OPENFLOW_ACTIONS)
