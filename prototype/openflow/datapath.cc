// -*- c-basic-offset: 4; related-file-name: "datapath.hh" -*-
/*
 * datapath.{cc,hh} -- Openflow datapath
 */

#include <click/config.h>
#include <click/glue.hh>
#include <click/sync.hh>
#include "openflow_genl.hh"
#include "datapath.hh"
#include "openflow.hh"
#include "flow.hh"
#include "packet_buffer.hh"
#include "ofswitch.hh"
CLICK_CXX_PROTECT
#include <linux/netdevice.h>
#include <linux/rtnetlink.h>
#include <linux/if_arp.h>
#include <linux/mutex.h>
#include <linux/dmi.h>
#include <linux/etherdevice.h>
CLICK_CXX_UNPROTECT
CLICK_DECLS

Datapath *dps[DP_MAX];

Datapath::Datapath():port_lock()
{
    mutex_init(&dp_mutex);
    for(int i=0;i<DP_MAX_PORTS;i++)
	ports[i] = NULL;
    random_ether_addr(mac);
    //memset(mac[0],0,1);
    mac [0] &= 0x00;
}

void
Datapath::cleanup()
{
    chain->chain_destroy();
}

int 
Datapath::initialize(int dp_idx)
{
    int err = -1;
    
    if (dp_idx < 0 || dp_idx >= DP_MAX)
	return -EINVAL;

    /* Exit early if a datapath with that number already exists. */
    if (dps[dp_idx]) {
        err = -EEXIST;
        goto err_unlock;
    }

    this->dp_idx = dp_idx;

    chain = new OFChain;
    if (chain->chain_create(this))
    	goto err_destroy_dp_dev;

    this->flags = 0;
    this->miss_send_len = OFP_DEFAULT_MISS_SEND_LEN;

    dps[dp_idx] = this;

    return 0;

err_destroy_dp_dev:
err_unlock:
		return err;
}

Datapath::~Datapath()
{
    dps[this->dp_idx] = NULL;
    del_all_ports();
}

/* Find and return a free port number under 'dp'. */
int 
Datapath::find_portno()
{
    int i;
    for (i = 0; i < DP_MAX_PORTS; i++)
	if (ports[i] == NULL)
	    return i;
    return -EXFULL;
}

int 
Datapath::add_switch_port(int port_num=-1)
{
    Port *p;

    if (port_num < 0) {
	    return -1;
    }

    p = new_port(port_num);
    if (IS_ERR(p))
	return PTR_ERR(p);

    return 0;
}

int
Datapath::send_port_status(Port *p, uint8_t status)
{
    struct sk_buff *skb;
    struct ofp_port_status *ops;

    ops = alloc_openflow_skb(this, sizeof *ops, OFPT_PORT_STATUS, NULL,
			     &skb);
    if (!ops)
	return -ENOMEM;
    ops->reason = status;
    memset(ops->pad, 0, sizeof ops->pad);
    p->fill_port_desc(&ops->desc);

    return send_openflow_skb(skb, NULL);
}

int 
Datapath::del_all_ports()
{
    unsigned long flags = port_lock.acquire();

    for(port_list::iterator pit = plist.begin(); pit != plist.end(); pit++) {
	Port *p = pit.get();
	del_switch_port(p);
    }
    port_lock.release(flags);
}

int 
Datapath::del_switch_port(Port *p)
{
    if ( p->get_portno() != OFPP_LOCAL)
	rcu_assign_pointer(ports[p->get_portno()], NULL);

    send_port_status(p, OFPPR_DELETE);
    plist.erase(p);

    delete p->stats;
    delete p;
}

Port *
Datapath::new_port(int port_no)
{
	Port *p;
	unsigned long flags;
	p = new Port(this, port_no);
	if (p == NULL)
		return ERR_PTR(-ENOMEM);
	
	p->stats = new struct net_device_stats;

	if (!p->stats) {
	    delete p;
	    return ERR_PTR(-ENOMEM);
	}

	memset(p->stats, 0, sizeof(struct net_device_stats));

	flags = port_lock.acquire();
	if (port_no < DP_MAX_PORTS)
		rcu_assign_pointer(ports[port_no], p); 

	plist.push_back(p);
	port_lock.release(flags);
	return p;
}

/* Find and return a free port number under 'dp'. */
int 
Datapath::find_portno(Datapath *dp)
{
	int i;
	unsigned long flags;
	for (i = 0; i < DP_MAX_PORTS; i++)
		if (dp->ports[i] == NULL)
			return i;
	return -EXFULL;
}

/* Retrieves the datapath id, which is the MAC address of the "of" device. */
uint64_t 
Datapath::get_datapath_id(struct net_device *dev)
{
	uint64_t id = 0;
	int i;

	for (i=0; i< OFP_ETH_ALEN; i++) 
		id |= (uint64_t)dev->dev_addr[i] << (8*(OFP_ETH_ALEN-1 - i));

	return id;
}

int
Datapath::send_error_msg(const struct sender *sender, 
			    uint16_t type, uint16_t code, const void *data, size_t len)
{
    struct sk_buff *skb;
    struct ofp_error_msg *oem;


    oem = alloc_openflow_skb(this, sizeof(*oem)+len, OFPT_ERROR,
			     sender, &skb);
    if (!oem)
	return -ENOMEM;

    oem->type = htons(type);
    oem->code = htons(code);
    memcpy(oem->data, data, len);

    return send_openflow_skb(skb, sender);
}

int 
Datapath::send_flow_expired( struct sw_flow *flow,
		     enum ofp_flow_expired_reason reason)
{
	struct sk_buff *skb;
	struct ofp_flow_expired *ofe;

	if (!(flags & OFPC_SEND_FLOW_EXP))
		return 0;

	ofe = alloc_openflow_skb(this, sizeof *ofe, OFPT_FLOW_EXPIRED, 0, &skb);
	if (!ofe)
		return -ENOMEM;

	sw_flow::flow_fill_match(&ofe->match, &flow->key);

	ofe->priority = htons(flow->priority);
	ofe->reason = reason;
	memset(ofe->pad, 0, sizeof ofe->pad);

	ofe->duration     = htonl((jiffies - flow->init_time) / HZ);
	memset(ofe->pad2, 0, sizeof ofe->pad2);
	ofe->packet_count = cpu_to_be64(flow->packet_count);
	ofe->byte_count   = cpu_to_be64(flow->byte_count);

	return send_openflow_skb(skb, NULL);
}

int
Datapath::send_features_reply(const struct sender *sender)
{
    struct sk_buff *skb;
    struct ofp_switch_features *ofr;
    size_t ofr_len, port_max_len;
    int port_count;

    /* Overallocate. */
    port_max_len = sizeof(struct ofp_phy_port) * DP_MAX_PORTS;
    ofr = alloc_openflow_skb(this, sizeof(*ofr) + port_max_len,
			     OFPT_FEATURES_REPLY, sender, &skb);
    if (!ofr)
	return -ENOMEM;

    /* Fill. */
    port_count = fill_features_reply(ofr);

    /* Shrink to fit. */
    ofr_len = sizeof(*ofr) + (sizeof(struct ofp_phy_port) * port_count);
    resize_openflow_skb(skb, &ofr->header, ofr_len);
    return send_openflow_skb(skb, sender);
}

uint64_t 
Datapath::get_datapath_id()
{
    uint64_t id = 0;
    int i;

    for (i=0; i<ETH_ALEN; i++)
	id |= (uint64_t)mac[i] << (8*(ETH_ALEN-1 - i));

    return id;
}

void
Datapath::set_uuid_mac()
{
    const char *uuid = dmi_get_system_info(DMI_PRODUCT_UUID);
    const char *uptr;
    int i;

    if (!uuid || *uuid == '\0' || strlen(uuid) != 36)
	return;

    /* We are only interested version 1 UUIDs, since the last six bytes
     * are an IEEE 802 MAC address. */
    if (uuid[14] != '1')
	return;

    /* Pull out the embedded MAC address.  The kernel's sscanf doesn't
     * support field widths on hex digits, so we use this hack. */
    uptr = uuid + 24;
    for (i=0; i<ETH_ALEN; i++) {
	unsigned char d[3];

	d[0] = *uptr++;
	d[1] = *uptr++;
	d[2] = '\0';

	mac[i] = simple_strtoul(d, NULL, 16);
    }
    /* If this is a Nicira one, then use it. */
    if (mac[0] != 0x00 || mac[1] != 0x23 || mac[2] != 0x20)
	return;
}

int
Datapath::fill_features_reply(struct ofp_switch_features *ofr)
{
    Port *p;
    uint64_t dpid = get_datapath_id();
    int port_count = 0;
    ofr->datapath_id  = cpu_to_be64(dpid);

    ofr->n_buffers    = htonl(N_PKT_BUFFERS);
    ofr->n_tables     = 2;
    ofr->capabilities = htonl(OFP_SUPPORTED_CAPABILITIES);
    ofr->actions      = htonl(OFP_SUPPORTED_ACTIONS);
    memset(ofr->pad, 0, sizeof ofr->pad);

    unsigned long flags = port_lock.acquire();
    int y = 1;
    for(port_list::iterator pit = plist.begin(); pit != plist.end(); pit++) {
	Port *p = pit.get();
	p->fill_port_desc(&ofr->ports[port_count]);
	port_count++;
    }
    port_lock.release(flags);

    return port_count;
}

int
Datapath::send_config_reply(const struct sender *sender)
{
    struct sk_buff *skb;
    struct ofp_switch_config *osc;

    osc = alloc_openflow_skb(this, sizeof *osc, OFPT_GET_CONFIG_REPLY, sender,
			     &skb);
    if (!osc)
	return -ENOMEM;

    osc->flags = htons(flags);
    osc->miss_send_len = htons(miss_send_len);

    int rc =  send_openflow_skb(skb, sender);

    return rc;
}

int
Datapath::send_echo_reply(const struct sender *sender,
                   const struct ofp_header *rq)
{
    struct sk_buff *skb;
    struct ofp_header *reply;

    reply = alloc_openflow_skb(this, ntohs(rq->length), OFPT_ECHO_REPLY,
			       sender, &skb);
    if (!reply)
	return -ENOMEM;

    memcpy(reply + 1, rq + 1, ntohs(rq->length) - sizeof *rq);
    return send_openflow_skb(skb, sender);
}

int
Datapath::send_hello(const struct sender *sender,
              const struct ofp_header *request)
{
    if (request->version < OFP_VERSION) {
	char err[64];
	sprintf(err, "Only version 0x%02x supported", OFP_VERSION);
	send_error_msg(sender, OFPET_HELLO_FAILED,
		       OFPHFC_INCOMPATIBLE, err, strlen(err));
	return -EINVAL;
    } else {
	struct sk_buff *skb;
	struct ofp_header *reply;

	reply = alloc_openflow_skb(this, sizeof *reply,
				   OFPT_HELLO, sender, &skb);
	if (!reply)
	    return -ENOMEM;

	return send_openflow_skb(skb, sender);
    }
}

/* Takes ownership of 'skb' and transmits it to 'dp''s control path.  If
 * 'buffer_id' != -1, then only the first 64 bytes of 'skb' are sent;
 * otherwise, all of 'skb' is sent.  'reason' indicates why 'skb' is being
 * sent. 'max_len' sets the maximum number of bytes that the caller
 * wants to be sent; a value of 0 indicates the entire packet should be
 * sent. */
int
Datapath::output_control(Packet *p_in,
			   uint32_t buffer_id, size_t max_len, int reason)
{
	/* FIXME?  Can we avoid creating a new skbuff in the case where we
	 * forward the whole packet? */
	struct sk_buff *f_skb;
	struct ofp_packet_in *opi;
	size_t fwd_len, opi_len;
	int err;

	fwd_len = p_in->length();
	if ((buffer_id != (uint32_t) -1) && max_len)
		fwd_len = min(fwd_len, max_len);

	opi_len = offsetof(struct ofp_packet_in, data) + fwd_len;
	opi = alloc_openflow_skb(this, opi_len, OFPT_PACKET_IN, NULL, &f_skb);
	if (!opi) {
		err = -ENOMEM;
		goto out;
	}
	opi->buffer_id      = htonl(buffer_id);
	opi->total_len      = htons(p_in->length());
        opi->in_port = OFPP_NONE;

	if( p_in->anno_u8(6) ) {
	    opi->in_port = htons(p_in->anno_u8(5));
	}

	opi->reason         = reason;
	opi->pad            = 0;
	skb_copy_bits(p_in->skb(), 0, opi->data, fwd_len);
	err = send_openflow_skb(f_skb, NULL);
out:
	p_in->kill();
	return err;
}

/* Send packets out all the ports except the originating one.  If the
 * "flood" argument is set, only send along the minimum spanning tree.
 */
int
Datapath::output_all(Packet *p_in, int flood)
{
    u32 disable = flood ? OFPPC_NO_FLOOD : 0;
    Port *p = NULL;
    int prev_port = -1;
    int pkt_port = p_in->anno_u8(5);

    unsigned long flags = port_lock.acquire();
    for(port_list::iterator pit = plist.begin(); pit != plist.end(); pit++) {
	p = pit.get();
	if ( pkt_port == p->port_no ||  p->config & disable) {
	    continue;
	}

	if (prev_port != -1) {
	    Packet *clone = p_in->clone();
	    if (!clone) {
		p_in->kill();
		return -ENOMEM;
	    }
	    output_port(clone, prev_port, 0); 
	}
	prev_port = p->port_no;
    }
    port_lock.release(flags);
    
    if (prev_port != -1) {
	output_port(p_in, prev_port, 0);
    }
    else {
	p_in->kill();
    }

    return 0;
}

/* Takes ownership of 'skb' and transmits it to 'out_port' on 'dp'.
 */
int 
Datapath::output_port(Packet *p_in, int out_port,
		   int ignore_no_fwd)
{
	switch (out_port){
	case OFPP_IN_PORT:
		/* Send it out the port it came in on, which is already set in
		 * the skb. */
	    if (!ofs->output(out_port).active()) {
			if (net_ratelimit())
			    click_chatter("skb device not set forwarding to in_port\n");
	                p_in->kill();
			return -ESRCH;
		}
	ofs->output(out_port).push(p_in);
	return 0;
		
	case OFPP_TABLE: {
		int retval = run_flow_through_tables(chain, p_in);
		if (retval)
		    p_in->kill();
		return retval;
	}

	case OFPP_FLOOD:
		return output_all(p_in, 1);

	case OFPP_ALL:
		return output_all(p_in, 0);

	case OFPP_CONTROLLER:
	    return output_control(p_in, storage.store_packet(p_in), 0, OFPR_ACTION);

	case OFPP_LOCAL: {
	    p_in->kill();
	    click_chatter("OpenFlow Debug(%s,%d): OFPP_LOCAL not supported yet",__FUNCTION__,__LINE__);
	    return -ESRCH;
	}

	case 0 ... DP_MAX_PORTS - 1: {
	    if (!ofs->output(out_port).active()) {
			if (net_ratelimit())
			    click_chatter("skb device not set forwarding to in_port\n");
	                p_in->kill();
			return -ESRCH;
	     }
	    ports[out_port]->stats->tx_packets++;
	    ports[out_port]->stats->tx_bytes += p_in->length();
	    ofs->output(out_port).push(p_in);
	    return 0;
	}

	default:
		goto bad_port;
	}

 bad_port:
	p_in->kill();
	if (net_ratelimit())
		click_chatter("can't forward to bad port %d\n", out_port);
	return -ENOENT;
}

CLICK_ENDDECLS
ELEMENT_REQUIRES(linuxmodule)
ELEMENT_PROVIDES(OPENFLOW_DATAPATH)
