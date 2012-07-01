// -*- c-basic-offset: 4; related-file-name: "forward.hh" -*-
/*
 * forward.{cc,hh} -- Openflow forward path
 */

#include <click/config.h>
#include <click/glue.hh>
#include "openflow_genl.hh"
#include "datapath.hh"
#include "openflow.hh"
#include "forward.hh"
#include "chain.hh"
#include "dp_act.hh"

CLICK_CXX_PROTECT
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/if_ether.h>
#include <linux/if_vlan.h>
#include <asm/uaccess.h>
#include <linux/types.h>
CLICK_CXX_UNPROTECT
CLICK_DECLS

void fwd_port_input(OFChain *chain, Packet *pkt)
{
    if (run_flow_through_tables(chain, pkt)) {
		chain->dp->output_control(pkt, chain->dp->storage.store_packet(pkt), 
				  chain->dp->miss_send_len,
				  OFPR_NO_MATCH);
    }
}

int run_flow_through_tables(OFChain *chain, Packet *pkt)
{
	/* Ethernet address used as the destination for STP frames. */
	static const uint8_t stp_eth_addr[ETH_ALEN]
		= { 0x01, 0x80, 0xC2, 0x00, 0x00, 0x01 };
	struct sw_flow_key key;
	struct sw_flow *flow;

	unsigned int port_in = OFPP_NONE;

	if( pkt->anno_u8(6) ) {
	    port_in = pkt->anno_u8(5);
	}

	if (sw_flow::flow_extract(pkt, (int)port_in, &key)
	    && (chain->dp->flags & OFPC_FRAG_MASK) == OFPC_FRAG_DROP) {
		/* Drop fragment. */
	    pkt->kill();
		return 0;
	}

	flow = chain->chain_lookup(&key);
	if (likely(flow != NULL)) {
		struct sw_flow_actions *sf_acts = rcu_dereference(flow->sf_acts);
		sw_flow::flow_used(flow, pkt);
                //click_chatter("flow priority %d proto %d",flow->priority, key.nw_proto);
                if (flow->idle_timeout == CANONICAL_RULE && flow->priority == 123) {
                  send_feedback();
                }
		execute_actions(chain->dp, pkt, &key,
				sf_acts->actions, sf_acts->actions_len, 0);
		return 0;
	} else {
		return -ESRCH;
	}
}

static int
recv_hello(OFChain *chain, const struct sender *sender,
	   const void *msg)
{
    //click_chatter("OpenFlow Debug(%s,%d): Controller cmd",__FUNCTION__,__LINE__);
    return chain->dp->send_hello(sender, msg);
}

static int
recv_features_request(OFChain *chain, const struct sender *sender,
		      const void *msg) 
{
    //click_chatter("OpenFlow Debug(%s,%d): Controller cmd",__FUNCTION__,__LINE__);
    return chain->dp->send_features_reply(sender);
}

static int
recv_get_config_request(OFChain *chain, const struct sender *sender,
			const void *msg)
{
    //click_chatter("OpenFlow Debug(%s,%d): Controller cmd",__FUNCTION__,__LINE__);
    return chain->dp->send_config_reply(sender);
}

static int
recv_set_config(OFChain *chain, const struct sender *sender,
		const void *msg)
{
    //click_chatter("OpenFlow Debug(%s,%d): Controller cmd",__FUNCTION__,__LINE__);
    const struct ofp_switch_config *osc = msg;
    int flags;

    flags = ntohs(osc->flags) & (OFPC_SEND_FLOW_EXP | OFPC_FRAG_MASK);
    if ((flags & OFPC_FRAG_MASK) != OFPC_FRAG_NORMAL
	&& (flags & OFPC_FRAG_MASK) != OFPC_FRAG_DROP) {
	flags = (flags & ~OFPC_FRAG_MASK) | OFPC_FRAG_DROP;
    }
    chain->dp->flags = flags;
    
    chain->dp->miss_send_len = ntohs(osc->miss_send_len);

    return 0;
}

static int
recv_packet_out(OFChain *chain, const struct sender *sender,
		const void *msg)
{
    //click_chatter("OpenFlow Debug(%s,%d): Controller cmd",__FUNCTION__,__LINE__);
    const struct ofp_packet_out *opo = msg;
    struct sk_buff *skb = NULL;
    Packet *pkt = NULL;
    uint16_t v_code;
    struct sw_flow_key key;
    size_t actions_len = ntohs(opo->actions_len);

    if (actions_len > (ntohs(opo->header.length) - sizeof *opo)) {
	if (net_ratelimit()) 
	    printk("message too short for number of actions\n");
	return -EINVAL;
	}
    
    if (ntohl(opo->buffer_id) == (uint32_t) -1) {
	int data_len = ntohs(opo->header.length) - sizeof *opo - actions_len;

	/* FIXME: there is likely a way to reuse the data in msg. */
	skb = alloc_skb(data_len, GFP_ATOMIC);
	if (!skb)
	    return -ENOMEM;
	
	/* FIXME?  We don't reserve NET_IP_ALIGN or NET_SKB_PAD since
	 * we're just transmitting this raw without examining anything
	 * at those layers. */
	skb_put(skb, data_len);
	skb_copy_to_linear_data(skb,
				(uint8_t *)opo->actions + actions_len, 
				data_len);
	skb_reset_mac_header(skb);
	pkt = Packet::make(skb);
    } else {
	pkt = chain->dp->storage.retrieve_skb(ntohl(opo->buffer_id));
	if (!pkt)
	    return -ESRCH;
    }

    pkt->set_anno_u8(5, ntohs(opo->in_port));
    pkt->set_anno_u8(6, 1);
    sw_flow::flow_extract(pkt, ntohs(opo->in_port), &key);

    v_code = validate_actions(chain->dp, &key, opo->actions, actions_len);
    if (v_code != ACT_VALIDATION_OK) {
	chain->dp->send_error_msg(sender, OFPET_BAD_ACTION, v_code,
			  msg, ntohs(opo->header.length));
	goto error;
    }
 
    execute_actions(chain->dp, pkt, &key, opo->actions, actions_len, 1);
	
    return 0;
    
 error:
    kfree_skb(skb);
    if (pkt) {
	pkt->kill();
    }
    return -EINVAL;
}

static int
recv_port_mod(OFChain *chain, const struct sender *sender,
	      const void *msg)
{
    //click_chatter("OpenFlow Debug(%s,%d): Short-circuiting function",__FUNCTION__,__LINE__);
    return -1;
}

static int
recv_echo_request(OFChain *chain, const struct sender *sender,
		  const void *msg) 
{
    //click_chatter("OpenFlow Debug(%s,%d): Controller cmd",__FUNCTION__,__LINE__);
    return chain->dp->send_echo_reply(sender, msg);
}

static int
recv_echo_reply(OFChain *chain, const struct sender *sender,
		  const void *msg) 
{
    //click_chatter("OpenFlow Debug(%s,%d): Controller cmd",__FUNCTION__,__LINE__);
    return 0;
}

static int
add_flow(OFChain *chain, const struct sender *sender, 
		const struct ofp_flow_mod *ofm)
{
	int error = -ENOMEM;
	uint16_t v_code;
	struct sw_flow *flow;
	size_t actions_len = ntohs(ofm->header.length) - sizeof *ofm;

	/* Allocate memory. */
	flow = sw_flow::flow_alloc(actions_len, GFP_ATOMIC);
	if (flow == NULL)
	    goto error;
	sw_flow::flow_extract_match(&flow->key, &ofm->match);

	v_code = validate_actions(chain->dp, &flow->key, ofm->actions, actions_len);
	if (v_code != ACT_VALIDATION_OK) {
		chain->dp->send_error_msg(sender, OFPET_BAD_ACTION, v_code,
				  ofm, ntohs(ofm->header.length));
		goto error_free_flow;
	}

	/* Fill out flow. */
	flow->priority = flow->key.wildcards ? ntohs(ofm->priority) : -1;
	flow->idle_timeout = ntohs(ofm->idle_timeout);
	flow->hard_timeout = ntohs(ofm->hard_timeout);
	flow->used = jiffies;
	flow->init_time = jiffies;
	flow->byte_count = 0;
	flow->packet_count = 0;
	memcpy(flow->sf_acts->actions, ofm->actions, actions_len);

	/* Act. */
	error = chain->chain_insert(flow);

	if (error == -ENOBUFS) {
		chain->dp->send_error_msg(sender, OFPET_FLOW_MOD_FAILED, 
				OFPFMFC_ALL_TABLES_FULL, ofm, ntohs(ofm->header.length));
		goto error_free_flow;
	} else if (error) {
		goto error_free_flow;
	}

	error = 0;
	if (ntohl(ofm->buffer_id) != (uint32_t) -1) {
		Packet *pkt = chain->dp->storage.retrieve_skb(ntohl(ofm->buffer_id));
		if (pkt) {
			struct sw_flow_key key;
			sw_flow::flow_used(flow, pkt);
			pkt->set_anno_u8(5, ntohs(ofm->match.in_port));
			pkt->set_anno_u8(6, 1);
			sw_flow::flow_extract(pkt, ntohs(ofm->match.in_port), &key);
			execute_actions(chain->dp, pkt, &key, ofm->actions, actions_len, 0);
		}
		else
			error = -ESRCH;
	}
	return error;

error_free_flow:
	sw_flow::flow_free(flow);
error:
	if (ntohl(ofm->buffer_id) != (uint32_t) -1)
		chain->dp->storage.discard_skb(ntohl(ofm->buffer_id));
	return error;
}

static int
mod_flow(OFChain *chain, const struct sender *sender,
		const struct ofp_flow_mod *ofm)
{
	int error = -ENOMEM;
	uint16_t v_code;
	size_t actions_len;
	struct sw_flow_key key;
	uint16_t priority;
	int strict;

	sw_flow::flow_extract_match(&key, &ofm->match);

	actions_len = ntohs(ofm->header.length) - sizeof *ofm;

	v_code = validate_actions(chain->dp, &key, ofm->actions, actions_len);
	if (v_code != ACT_VALIDATION_OK) {
		chain->dp->send_error_msg(sender, OFPET_BAD_ACTION, v_code,
				  ofm, ntohs(ofm->header.length));
		goto error;
	}

	priority = key.wildcards ? ntohs(ofm->priority) : -1;
	strict = (ofm->command == htons(OFPFC_MODIFY_STRICT)) ? 1 : 0;
	chain->chain_modify(&key, priority, strict, ofm->actions, actions_len);

	if (ntohl(ofm->buffer_id) != (uint32_t) -1) {
		Packet *pkt = chain->dp->storage.retrieve_skb(ntohl(ofm->buffer_id));
		if (pkt) {
			struct sw_flow_key skb_key;
			sw_flow::flow_extract(pkt, ntohs(ofm->match.in_port), &skb_key);
			execute_actions(chain->dp, pkt, &skb_key, 
					ofm->actions, actions_len, 0);
		}
		else
			error = -ESRCH;
	}
	return error;

error:
	if (ntohl(ofm->buffer_id) != (uint32_t) -1)
		chain->dp->storage.discard_skb(ntohl(ofm->buffer_id));
	return error;
}

static int
recv_flow(OFChain *chain, const struct sender *sender, const void *msg)
{
    //click_chatter("OpenFlow Debug(%s,%d): Controller cmd",__FUNCTION__,__LINE__);
    
    const struct ofp_flow_mod *ofm = msg;
    uint16_t command = ntohs(ofm->command);
    
    if (command == OFPFC_ADD) {
	return add_flow(chain, sender, ofm);
    } else if ((command == OFPFC_MODIFY) || (command == OFPFC_MODIFY_STRICT)) {
	return mod_flow(chain, sender, ofm);
    }  else if (command == OFPFC_DELETE) {
	struct sw_flow_key key;
	sw_flow::flow_extract_match(&key, &ofm->match);
	return chain->chain_delete(&key, ofm->out_port, 0, 0) ? 0 : -ESRCH;
    } else if (command == OFPFC_DELETE_STRICT) {
	struct sw_flow_key key;
	uint16_t priority;
	sw_flow::flow_extract_match(&key, &ofm->match);
	priority = key.wildcards ? ntohs(ofm->priority) : -1;
	return chain->chain_delete(&key, ofm->out_port, 
				   priority, 1) ? 0 : -ESRCH;
    } else {
	return -ENOTSUPP;
    }
}

static int
recv_vendor(OFChain *chain, const struct sender *sender, 
		const void *msg)
{
    //click_chatter("OpenFlow Debug(%s,%d): Short-circuiting function",__FUNCTION__,__LINE__);
    return -EINVAL;
}

bool pkt_hndlrs_init = false;
struct openflow_packet {
    size_t min_size;
    int (*handler)(OFChain *, const struct sender *,
		   const void *);
};

static struct openflow_packet ofc_cmd_handlers[OFPT_PORT_MOD+1];

void
init_handlers(int index, size_t ms, int (*handler)(OFChain *, const struct sender *,
		   const void *))
{
    ofc_cmd_handlers[index].min_size = ms;
    ofc_cmd_handlers[index].handler = handler;
}


/* 'msg', which is 'length' bytes long, was received across Netlink from
 * 'sender'.  Apply it to 'chain'. */
int
fwd_control_input(OFChain *chain, const struct sender *sender,
		  const void *msg, size_t length)
{

    if (unlikely(!pkt_hndlrs_init)) {
	init_handlers(OFPT_HELLO, sizeof (struct ofp_header), recv_hello);
	init_handlers(OFPT_ECHO_REQUEST, sizeof (struct ofp_header), recv_echo_request);
	init_handlers(OFPT_ECHO_REPLY, sizeof (struct ofp_header), recv_echo_reply);
	init_handlers(OFPT_VENDOR, sizeof (struct ofp_vendor_header),recv_vendor);
	init_handlers(OFPT_FEATURES_REQUEST, sizeof (struct ofp_header), recv_features_request);
	init_handlers(OFPT_GET_CONFIG_REQUEST, sizeof (struct ofp_header),recv_get_config_request);
	init_handlers(OFPT_SET_CONFIG, sizeof (struct ofp_switch_config), recv_set_config);
	init_handlers(OFPT_PACKET_OUT, sizeof (struct ofp_packet_out), recv_packet_out);
	init_handlers(OFPT_FLOW_MOD, sizeof (struct ofp_flow_mod), recv_flow);
	init_handlers(OFPT_PORT_MOD, sizeof (struct ofp_port_mod), recv_port_mod);
	pkt_hndlrs_init = true;
    }
	
	struct ofp_header *oh;

	oh = (struct ofp_header *) msg;

	//if (oh->type != 3)
	//  click_chatter("OpenFlow Debug(%s,%d): Controller packet type %d",__FUNCTION__,__LINE__,oh->type);

	if (oh->version != OFP_VERSION
	    && oh->type != OFPT_HELLO
	    && oh->type != OFPT_ERROR
	    && oh->type != OFPT_ECHO_REQUEST
	    && oh->type != OFPT_ECHO_REPLY
	    && oh->type != OFPT_VENDOR)
	{
		chain->dp->send_error_msg(sender, OFPET_BAD_REQUEST,
				  OFPBRC_BAD_VERSION, msg, length);
		return -EINVAL;
	}
	if (ntohs(oh->length) != length) {
		if (net_ratelimit())
			click_chatter("OpenFlow Debug(%s,%d):received message length wrong: %d/%d\n", 
				      __FUNCTION__,__LINE__,ntohs(oh->length), length);
		return -EINVAL;
	}

	if (oh->type < (sizeof(ofc_cmd_handlers)/sizeof(openflow_packet)) ) {
		const struct openflow_packet *pkt = &ofc_cmd_handlers[oh->type];
		if (pkt->handler) {
			if (length < pkt->min_size)
				return -EFAULT;
			return pkt->handler(chain, sender, msg);
		}
	}
	chain->dp->send_error_msg(sender, OFPET_BAD_REQUEST,
			  OFPBRC_BAD_TYPE, msg, length);
	return -EINVAL;
}

CLICK_ENDDECLS
ELEMENT_REQUIRES(linuxmodule)
ELEMENT_PROVIDES(OPENFLOW_FORWARD)

