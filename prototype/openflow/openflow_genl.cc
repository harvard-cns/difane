// -*- c-basic-offset: 4; related-file-name: "openflow_genl.hh" -*-
/*
 * openflow_genl.{cc,hh} -- a Genl class for Generic Netlink Communication.
 */

#include <click/config.h>
#include <click/glue.hh>
#include "openflow_genl.hh"
#include "datapath.hh"
#include "openflow.hh"
#include "chain.hh"
#include "ofswitch.hh"
CLICK_CXX_PROTECT
#include <linux/netdevice.h>
#include <linux/rtnetlink.h>
#include <linux/mutex.h>
CLICK_CXX_UNPROTECT
CLICK_DECLS


/** @file openflow_genl.hh
 * @brief Click's Openflow_Genl class.
 */

struct genl_family dp_genl_family;
struct genl_multicast_group mc_group;
struct nla_policy dp_genl_policy[DP_GENL_A_MAX + 1];
struct genl_ops dp_genl_ops_add_dp;
struct genl_ops dp_genl_ops_del_dp;
struct genl_ops dp_genl_ops_query_dp;
struct genl_ops dp_genl_ops_add_port;
struct genl_ops dp_genl_ops_del_port;
struct nla_policy dp_genl_openflow_policy[DP_GENL_A_MAX + 1];
struct genl_ops dp_genl_ops_openflow;
struct genl_ops *dp_genl_all_ops[6];

//Minlan
struct genl_family feedback_genl_family;
struct genl_multicast_group feedback_mc_group;
struct nla_policy feedback_genl_policy[FEEDBACK_GENL_A_MAX +1];
struct nla_policy feedback_genl_openflow_policy[FEEDBACK_GENL_A_MAX +1];
struct genl_ops feedback_genl_ops_openflow;
struct genl_ops feedback_genl_ops_query;
struct genl_ops * feedback_genl_all_ops[FEEDBACK_OPS_COUNT];

struct sender feedback_sender;

bool registered = false;

struct flow_stats_state {
	int table_idx;
	struct sw_table_position position;
	const struct ofp_flow_stats_request *rq;

	void *body;
	int bytes_used, bytes_allocated;
};

extern "C" 
int desc_stats_dump(Datapath *dp, void *state,
			    void *body, int *body_len)
{
	struct ofp_desc_stats *ods = body;
	int n_bytes = sizeof *ods;

	if (n_bytes > *body_len) {
		return -ENOBUFS;
	}
	*body_len = n_bytes;

	strncpy(ods->mfr_desc, "Openflow Click element", sizeof ods->mfr_desc);
	strncpy(ods->hw_desc, "Ported from reference linux kernel module", sizeof ods->hw_desc);
	strncpy(ods->sw_desc, "0.1", sizeof ods->sw_desc);
	strncpy(ods->serial_num, "None", sizeof ods->serial_num);

	return 0;
}

extern "C" int 
flow_stats_init(Datapath *dp, const void *body, int body_len, 
		  void **state)
{
	const struct ofp_flow_stats_request *fsr = body;
	struct flow_stats_state *s = kmalloc(sizeof *s, GFP_ATOMIC);
	if (!s)
		return -ENOMEM;
	s->table_idx = fsr->table_id == 0xff ? 0 : fsr->table_id;
	memset(&s->position, 0, sizeof s->position);
	s->rq = fsr;
	*state = s;
	return 0;
}

extern "C" int 
flow_stats_dump_callback(struct sw_flow *flow, void *private_data)
{
	struct sw_flow_actions *sf_acts = rcu_dereference(flow->sf_acts);
	struct flow_stats_state *s = private_data;
	struct ofp_flow_stats *ofs;
	int length;

	length = sizeof *ofs + sf_acts->actions_len;
	if (length + s->bytes_used > s->bytes_allocated)
		return 1;

	ofs = s->body + s->bytes_used;
	ofs->length          = htons(length);
	ofs->table_id        = s->table_idx;
	ofs->pad             = 0;
	ofs->match.wildcards = htonl(flow->key.wildcards);
	ofs->match.in_port   = flow->key.in_port;
	memcpy(ofs->match.dl_src, flow->key.dl_src, ETH_ALEN);
	memcpy(ofs->match.dl_dst, flow->key.dl_dst, ETH_ALEN);
	ofs->match.dl_vlan   = flow->key.dl_vlan;
	ofs->match.dl_type   = flow->key.dl_type;
	ofs->match.nw_src    = flow->key.nw_src;
	ofs->match.nw_dst    = flow->key.nw_dst;
	ofs->match.nw_proto  = flow->key.nw_proto;
	ofs->match.pad       = 0;
	ofs->match.tp_src    = flow->key.tp_src;
	ofs->match.tp_dst    = flow->key.tp_dst;
	ofs->duration        = htonl((jiffies - flow->init_time) / HZ);
	ofs->priority        = htons(flow->priority);
	ofs->idle_timeout    = htons(flow->idle_timeout);
	ofs->hard_timeout    = htons(flow->hard_timeout);
	memset(ofs->pad2, 0, sizeof ofs->pad2);
	ofs->packet_count    = cpu_to_be64(flow->packet_count);
	ofs->byte_count      = cpu_to_be64(flow->byte_count);
	memcpy(ofs->actions, sf_acts->actions, sf_acts->actions_len);

	s->bytes_used += length;
	return 0;
}

extern "C" int 
flow_stats_dump(Datapath *dp, void *state,
			   void *body, int *body_len)
{
	struct flow_stats_state *s = state;
	struct sw_flow_key match_key;
	int error = 0;

	s->bytes_used = 0;
	s->bytes_allocated = *body_len;
	s->body = body;

	sw_flow::flow_extract_match(&match_key, &s->rq->match);
	while (s->table_idx < dp->chain->n_tables
	       && (s->rq->table_id == 0xff || s->rq->table_id == s->table_idx))
	{
		FlowTable *table = dp->chain->tables[s->table_idx];

		error = table->iterate(&match_key, s->rq->out_port, 
				&s->position, flow_stats_dump_callback, s);
		if (error)
			break;

		s->table_idx++;
		memset(&s->position, 0, sizeof s->position);
	}
	*body_len = s->bytes_used;

	/* If error is 0, we're done.
	 * Otherwise, if some bytes were used, there are more flows to come.
	 * Otherwise, we were not able to fit even a single flow in the body,
	 * which indicates that we have a single flow with too many actions to
	 * fit.  We won't ever make any progress at that rate, so give up. */
	return !error ? 0 : s->bytes_used ? 1 : -ENOMEM;
}

extern "C" void 
flow_stats_done(void *state)
{
	kfree(state);
}

static int aggregate_stats_init(Datapath *dp,
				const void *body, int body_len,
				void **state)
{
	*state = (void *)body;
	return 0;
}

static int aggregate_stats_dump_callback(struct sw_flow *flow, void *private_data)
{
	struct ofp_aggregate_stats_reply *rpy = private_data;
	rpy->packet_count += flow->packet_count;
	rpy->byte_count += flow->byte_count;
	rpy->flow_count++;
	return 0;
}

static int aggregate_stats_dump(Datapath *dp, void *state,
				void *body, int *body_len)
{
	struct ofp_aggregate_stats_request *rq = state;
	struct ofp_aggregate_stats_reply *rpy;
	struct sw_table_position position;
	struct sw_flow_key match_key;
	int table_idx;

	if (*body_len < sizeof *rpy)
		return -ENOBUFS;
	rpy = body;
	*body_len = sizeof *rpy;

	memset(rpy, 0, sizeof *rpy);

	sw_flow::flow_extract_match(&match_key, &rq->match);
	table_idx = rq->table_id == 0xff ? 0 : rq->table_id;
	memset(&position, 0, sizeof position);
	while (table_idx < dp->chain->n_tables
	       && (rq->table_id == 0xff || rq->table_id == table_idx))
	{
		FlowTable *table = dp->chain->tables[table_idx];
		int error;

		error = table->iterate(&match_key, rq->out_port, &position,
				       aggregate_stats_dump_callback, rpy);
		if (error)
			return error;

		table_idx++;
		memset(&position, 0, sizeof position);
	}

	rpy->packet_count = cpu_to_be64(rpy->packet_count);
	rpy->byte_count = cpu_to_be64(rpy->byte_count);
	rpy->flow_count = htonl(rpy->flow_count);
	return 0;
}

static int table_stats_dump(Datapath *dp, void *state,
			    void *body, int *body_len)
{
	struct ofp_table_stats *ots;
	int n_bytes = dp->chain->n_tables * sizeof *ots;
	int i;
	if (n_bytes > *body_len)
		return -ENOBUFS;
	*body_len = n_bytes;
	for (i = 0, ots = body; i < dp->chain->n_tables; i++, ots++) {
		struct sw_table_stats stats;
		dp->chain->tables[i]->stats(&stats);
		strncpy(ots->name, stats.name, sizeof ots->name);
		ots->table_id = i;
		ots->wildcards = htonl(stats.wildcards);
		memset(ots->pad, 0, sizeof ots->pad);
		ots->max_entries = htonl(stats.max_flows);
		ots->active_count = htonl(stats.n_flows);
		ots->lookup_count = cpu_to_be64(stats.n_lookup);
		ots->matched_count = cpu_to_be64(stats.n_matched);
	}
	return 0;
}

struct port_stats_state {
	int port;
};

static int port_stats_init(Datapath *dp, const void *body, int body_len,
			   void **state)
{
	struct port_stats_state *s = kmalloc(sizeof *s, GFP_ATOMIC);
	if (!s)
		return -ENOMEM;
	s->port = 0;
	*state = s;
	return 0;
}

static int port_stats_dump(Datapath *dp, void *state,
			   void *body, int *body_len)
{
	struct port_stats_state *s = state;
	struct ofp_port_stats *ops;
	int n_ports, max_ports;
	int i;

	max_ports = *body_len / sizeof *ops;
	if (!max_ports)
		return -ENOMEM;
	ops = body;

	n_ports = 0;
	for (i = s->port; i < DP_MAX_PORTS && n_ports < max_ports; i++) {
		Port *p = dp->ports[i];
		struct net_device_stats *stats;
		if (!p) 
			continue;
		stats = p->get_stats();
		ops->port_no = htons(p->port_no);
		memset(ops->pad, 0, sizeof ops->pad);
		ops->rx_packets   = cpu_to_be64(stats->rx_packets);
		ops->tx_packets   = cpu_to_be64(stats->tx_packets);
		ops->rx_bytes     = cpu_to_be64(stats->rx_bytes);
		ops->tx_bytes     = cpu_to_be64(stats->tx_bytes);
		ops->rx_dropped   = cpu_to_be64(stats->rx_dropped);
		ops->tx_dropped   = cpu_to_be64(stats->tx_dropped);
		ops->rx_errors    = cpu_to_be64(stats->rx_errors);
		ops->tx_errors    = cpu_to_be64(stats->tx_errors);
		ops->rx_frame_err = cpu_to_be64(stats->rx_frame_errors);
		ops->rx_over_err  = cpu_to_be64(stats->rx_over_errors);
		ops->rx_crc_err   = cpu_to_be64(stats->rx_crc_errors);
		ops->collisions   = cpu_to_be64(stats->collisions);
		n_ports++;
		ops++;
	}

	s->port = i;
	*body_len = n_ports * sizeof *ops;
	return n_ports >= max_ports;
}

static void port_stats_done(void *state)
{
	kfree(state);
}

struct stats_type {
	/* Minimum and maximum acceptable number of bytes in body member of
	 * struct ofp_stats_request. */
	size_t min_body, max_body;

	/* Prepares to dump some kind of statistics on 'dp'.  'body' and
	 * 'body_len' are the 'body' member of the struct ofp_stats_request.
	 * Returns zero if successful, otherwise a negative error code.
	 * May initialize '*state' to state information.  May be null if no
	 * initialization is required.*/
	int (*init)(Datapath *dp, const void *body, int body_len,
		    void **state);

	/* Dumps statistics for 'dp' into the '*body_len' bytes at 'body', and
	 * modifies '*body_len' to reflect the number of bytes actually used.
	 * ('body' will be transmitted as the 'body' member of struct
	 * ofp_stats_reply.) */
	int (*dump)(Datapath *dp, void *state,
		    void *body, int *body_len);

	/* Cleans any state created by the init or dump functions.  May be null
	 * if no cleanup is required. */
	void (*done)(void *state);
};

static const struct stats_type stats[OFPST_PORT+1] = {
    //stats[OFPST_DESC] = 
    {
	0,
	0,
	NULL,
	desc_stats_dump,
	NULL
    },
    //stats[OFPST_FLOW] = 
    {
	sizeof(struct ofp_flow_stats_request),
	sizeof(struct ofp_flow_stats_request),
	flow_stats_init,
	flow_stats_dump,
	flow_stats_done
    },
    //stats[OFPST_AGGREGATE] = 
    {
	sizeof(struct ofp_aggregate_stats_request),
	sizeof(struct ofp_aggregate_stats_request),
	aggregate_stats_init,
	aggregate_stats_dump,
	NULL
    },
    //stats[OFPST_TABLE] = 
    {
	0,
	0,
	NULL,
	table_stats_dump,
	NULL
    },
    //stats[OFPST_PORT] = 
    {
	0,
	0,
	port_stats_init,
	port_stats_dump,
	port_stats_done
    }
};

extern "C" int
dp_genl_openflow_done(struct netlink_callback *cb)
{
    if (cb->args[0]) {
	const struct stats_type *s = &stats[cb->args[2]];
	if (s->done)
	    s->done((void *) cb->args[4]);
    }
    return 0;
}

extern "C" int
dp_genl_openflow_dumpit(struct sk_buff *skb, struct netlink_callback *cb)
{
    Datapath *dp;
    struct sender sender;
    const struct stats_type *s;
    struct ofp_stats_reply *osr;
    int dp_idx;
    int max_openflow_len, body_len;
    void *body;
    int err;
    
    /* Set up the cleanup function for this dump.  Linux 2.6.20 and later
     * support setting up cleanup functions via the .doneit member of
     * struct genl_ops.  This kluge supports earlier versions also. */
    cb->done = dp_genl_openflow_done;
    
    sender.pid = NETLINK_CB(cb->skb).pid;
    sender.seq = cb->nlh->nlmsg_seq;
    if (!cb->args[0]) {
	struct nlattr *attrs[DP_GENL_A_MAX + 1];
	struct ofp_stats_request *rq;
	struct nlattr *va;
	size_t len, body_len;
		int type;

		err = nlmsg_parse(cb->nlh, GENL_HDRLEN, attrs, DP_GENL_A_MAX,
				  dp_genl_openflow_policy);
		if (err < 0)
			return err;

		if (!attrs[DP_GENL_A_DP_IDX])
			return -EINVAL;
		dp_idx = nla_get_u16(attrs[DP_GENL_A_DP_IDX]);
		dp = Datapath::dp_get(dp_idx);
		if (!dp)
			return -ENOENT;

		va = attrs[DP_GENL_A_OPENFLOW];
		len = nla_len(va);
		if (!va || len < sizeof *rq)
			return -EINVAL;

		rq = nla_data(va);
		sender.xid = rq->header.xid;
		type = ntohs(rq->type);
		if (rq->header.version != OFP_VERSION) {
		    dp->send_error_msg(&sender, OFPET_BAD_REQUEST,
		    		  OFPBRC_BAD_VERSION, rq, len);
			return -EINVAL;
		}
		if (rq->header.type != OFPT_STATS_REQUEST
		    || ntohs(rq->header.length) != len)
			return -EINVAL;

		if (type > 4 || !stats[type].dump) {
			dp->send_error_msg(&sender, OFPET_BAD_REQUEST,
					  OFPBRC_BAD_STAT, rq, len);
			return -EINVAL;
		}

		s = &stats[type];
		body_len = len - offsetof(struct ofp_stats_request, body);
		if (body_len < s->min_body || body_len > s->max_body)
			return -EINVAL;

		cb->args[0] = 1;
		cb->args[1] = dp_idx;
		cb->args[2] = type;
		cb->args[3] = rq->header.xid;
		if (s->init) {
			void *state;
			err = s->init(dp, rq->body, body_len, &state);
			if (err)
				return err;
			cb->args[4] = (long) state;
		}
	} else if (cb->args[0] == 1) {
		sender.xid = cb->args[3];
		dp_idx = cb->args[1];
		s = &stats[cb->args[2]];

		dp = Datapath::dp_get(dp_idx);
		if (!dp)
			return -ENOENT;
	} else {
		return 0;
	}

	osr = put_openflow_headers(dp, skb, OFPT_STATS_REPLY, &sender,
				   &max_openflow_len);
	if (IS_ERR(osr))
		return PTR_ERR(osr);
	osr->type = htons(s - stats);
	osr->flags = 0;
	resize_openflow_skb(skb, &osr->header, max_openflow_len);
	body = osr->body;
	body_len = max_openflow_len - offsetof(struct ofp_stats_reply, body);

	err = s->dump(dp, (void *) cb->args[4], body, &body_len);

	if (err >= 0) {
		if (!err)
			cb->args[0] = 2;
		else
			osr->flags = ntohs(OFPSF_REPLY_MORE);
		resize_openflow_skb(skb, &osr->header,
				    (offsetof(struct ofp_stats_reply, body)
				     + body_len));
		err = skb->len;
	}

	return err;
}

extern "C" int 
dp_genl_openflow(struct sk_buff *skb, struct genl_info *info)
{
	struct nlattr *va = info->attrs[DP_GENL_A_OPENFLOW];
	Datapath *dp;
	struct ofp_header *oh;
	struct sender sender;
	int err;

	if (!info->attrs[DP_GENL_A_DP_IDX] || !va)
		return -EINVAL;
	
	dp = Datapath::dp_get(nla_get_u32(info->attrs[DP_GENL_A_DP_IDX]));
	if (!dp)
		return -ENOENT;

	if (nla_len(va) < sizeof(struct ofp_header))
		return -EINVAL;
	oh = nla_data(va);

	sender.xid = oh->xid;
	sender.pid = info->snd_pid;
	sender.seq = info->snd_seq;

	dp->lock();
	OFChain *chain = dp->chain;
	err = fwd_control_input(chain, &sender,
			nla_data(va), nla_len(va));
	dp->unlock();
	return err;
}

extern "C" int 
feedback_genl_openflow(struct sk_buff *skb, struct genl_info *info)
{
  /*	struct nlattr *va = info->attrs[DP_GENL_A_OPENFLOW];
	Datapath *dp;
	struct ofp_header *oh;
	struct sender sender;
	int err;

	if (!info->attrs[DP_GENL_A_DP_IDX] || !va)
		return -EINVAL;
	
	dp = Datapath::dp_get(nla_get_u32(info->attrs[DP_GENL_A_DP_IDX]));
	if (!dp)
		return -ENOENT;

	if (nla_len(va) < sizeof(struct ofp_header))
		return -EINVAL;
	oh = nla_data(va);

	sender.xid = oh->xid;
	sender.pid = info->snd_pid;
	sender.seq = info->snd_seq;

	dp->lock();
	OFChain *chain = dp->chain;
	err = fwd_control_input(chain, &sender,
			nla_data(va), nla_len(va));
	dp->unlock();
	return err;
  */
}

extern "C" int 
dp_genl_add_del_port(struct sk_buff *skb, struct genl_info *info)
{
    return -1;
}

/* Queries a datapath for related information.  Currently the only relevant
 * information is the datapath's multicast group ID.  Really we want one
 * multicast group per datapath, but because of locking issues[*] we can't
 * easily get one.  Thus, every datapath will currently return the same
 * global multicast group ID, but in the future it would be nice to fix that.
 *
 * [*] dp_genl_add, to add a new datapath, is called under the genl_lock
 *	 mutex, and genl_register_mc_group, called to acquire a new multicast
 *	 group ID, also acquires genl_lock, thus deadlock.
 */
extern "C" int 
dp_genl_query(struct sk_buff *skb, struct genl_info *info)
{
    Datapath *dp;
    struct sk_buff *ans_skb = NULL;
    int dp_idx;
    int err = -ENOMEM;

    if (!info->attrs[DP_GENL_A_DP_IDX])
	return -EINVAL;

    rcu_read_lock();
    dp_idx = nla_get_u32((info->attrs[DP_GENL_A_DP_IDX]));
    dp = Datapath::dp_get(dp_idx);

    if (!dp)
	err = -ENOENT;
    else {
	void *data;
	ans_skb = nlmsg_new(NLMSG_DEFAULT_SIZE, GFP_ATOMIC);
	if (!ans_skb) {
	    err = -ENOMEM;
	    goto err;
	}
	data = genlmsg_put_reply(ans_skb, info, &dp_genl_family,
				 0, DP_GENL_C_QUERY_DP);
	if (data == NULL) {
	    err = -ENOMEM;
	    goto err;
	}
	NLA_PUT_U32(ans_skb, DP_GENL_A_DP_IDX, dp_idx);
	NLA_PUT_U32(ans_skb, DP_GENL_A_MC_GROUP, mc_group.id);
	
	genlmsg_end(ans_skb, data);
	err = genlmsg_reply(ans_skb, info);
	ans_skb = NULL;
    }
 err:
 nla_put_failure:
    kfree_skb(ans_skb);
    rcu_read_unlock();
    return err;
}

extern "C" int 
feedback_genl_query(struct sk_buff *skb, struct genl_info *info)
{
  //click_chatter("enter feedback_genl_query");
    struct sk_buff *ans_skb = NULL;
    int err = -ENOMEM;

    feedback_sender.pid = info->snd_pid;
    feedback_sender.seq = info->snd_seq;
    
    void *data;
    ans_skb = nlmsg_new(NLMSG_DEFAULT_SIZE, GFP_ATOMIC);
    if (!ans_skb) {
      err = -ENOMEM;
      goto err;
    }
    data = genlmsg_put_reply(ans_skb, info, &feedback_genl_family,
                             0, FEEDBACK_GENL_C_QUERY);
    if (data == NULL) {
      err = -ENOMEM;
      goto err;
    }
    //NLA_PUT_U32(ans_skb, FEEDBACK_GENL_A_DP_IDX, dp_idx);
    NLA_PUT_U32(ans_skb, FEEDBACK_GENL_A_MC_GROUP, feedback_mc_group.id);
	
    genlmsg_end(ans_skb, data);
    err = genlmsg_reply(ans_skb, info);
    ans_skb = NULL;
 err:
 nla_put_failure:
    kfree_skb(ans_skb);
    rcu_read_unlock();
    return err;
}

extern "C" int 
dp_genl_del(struct sk_buff *skb, struct genl_info *info)
{
    int err;
    Datapath *dp = NULL;

    if (!info->attrs[DP_GENL_A_DP_IDX])
	return -EINVAL;

    dp = Datapath::dp_get(nla_get_u32((info->attrs[DP_GENL_A_DP_IDX])));

    if (!dp)
	err = -ENOENT;
    else {
	delete dp;
	err = 0;
    }
    return err;
}

extern "C" int 
dp_genl_add(struct sk_buff *skb, struct genl_info *info)
{
    if (!info->attrs[DP_GENL_A_DP_IDX])
	return -EINVAL;

    Datapath *dp = new Datapath;
    if ( dp == NULL ) {
	return -ENOMEM;
    }
    int rc = dp->initialize(nla_get_u32(info->attrs[DP_GENL_A_DP_IDX]));
    if (rc == -EEXIST) {
	delete dp;
    }
    return rc;
}

extern "C" void 
nla_shrink(struct sk_buff *skb, struct nlattr *nla, int len)
{
    int delta = nla_total_size(len) - nla_total_size(nla_len(nla));
    BUG_ON(delta > 0);
    skb->tail += delta;
    skb->len  += delta;
    nla->nla_len = nla_attr_size(len);
}

extern "C" void *
put_openflow_headers(Datapath *dp, struct sk_buff *skb, uint8_t type,
		     const struct sender *sender, int *max_openflow_len)
{
	struct ofp_header *oh;
	struct nlattr *attr;
	int openflow_len;

	/* Assemble the Generic Netlink wrapper. */
	if (!genlmsg_put(skb,
			 sender ? sender->pid : 0,
			 sender ? sender->seq : 0,
			 &dp_genl_family, 0, DP_GENL_C_OPENFLOW))
		return ERR_PTR(-ENOBUFS);
	if (nla_put_u32(skb, DP_GENL_A_DP_IDX, dp->get_idx()) < 0)
		return ERR_PTR(-ENOBUFS);
	openflow_len = (skb_tailroom(skb) - NLA_HDRLEN) & ~(NLA_ALIGNTO - 1);
	if (openflow_len < sizeof *oh)
		return ERR_PTR(-ENOBUFS);
	*max_openflow_len = openflow_len;
	attr = nla_reserve(skb, DP_GENL_A_OPENFLOW, openflow_len);
	BUG_ON(!attr);

	/* Fill in the header.  The caller is responsible for the length. */
	oh = nla_data(attr);
	oh->version = OFP_VERSION;
	oh->type = type;
	oh->xid = sender ? sender->xid : 0;

	return oh;
}

/* Resizes OpenFlow header 'oh', which must be at the tail end of 'skb', to new
 * length 'new_length' (in bytes), adjusting pointers and size values as
 * necessary. */
extern "C" void
resize_openflow_skb(struct sk_buff *skb,
                    struct ofp_header *oh, size_t new_length)
{
    struct nlattr *attr = ((void *) oh) - NLA_HDRLEN;
    nla_shrink(skb, attr, new_length);
    oh->length = htons(new_length);
    nlmsg_end(skb, (struct nlmsghdr *) skb->data);
}

/* Allocates a new skb to contain an OpenFlow message 'openflow_len' bytes in
 * length.  Returns a null pointer if memory is unavailable, otherwise returns
 * the OpenFlow header and stores a pointer to the skb in '*pskb'. 
 *
 * 'type' is the OpenFlow message type.  If 'sender' is nonnull, then it is
 * used as the message's destination.  'dp' must specify the datapath to
 * use.  */
extern "C" void *
alloc_openflow_skb(Datapath *dp, size_t openflow_len, uint8_t type,
		   const struct sender *sender, struct sk_buff **pskb) 
{
	struct ofp_header *oh;
	size_t genl_len;
	struct sk_buff *skb;
	int max_openflow_len;

	if ((openflow_len + sizeof(struct ofp_header)) > UINT16_MAX) {
		if (net_ratelimit())
			printk("alloc_openflow_skb: openflow message too large: %zu\n", 
					openflow_len);
		return NULL;
	}

	genl_len = nlmsg_total_size(GENL_HDRLEN + dp_genl_family.hdrsize);
	genl_len += nla_total_size(sizeof(uint32_t)); /* DP_GENL_A_DP_IDX */
	genl_len += nla_total_size(openflow_len);    /* DP_GENL_A_OPENFLOW */
	skb = *pskb = genlmsg_new(genl_len, GFP_ATOMIC);
	if (!skb) {
		if (net_ratelimit())
			printk("alloc_openflow_skb: genlmsg_new failed\n");
		return NULL;
	}

	oh = put_openflow_headers(dp, skb, type, sender, &max_openflow_len);
	BUG_ON(!oh || IS_ERR(oh));
	resize_openflow_skb(skb, oh, openflow_len);

	return oh;
}

/* Sends 'skb' to 'sender' if it is nonnull, otherwise multicasts 'skb' to all
 * listeners. */
extern "C" int
send_openflow_skb(struct sk_buff *skb, const struct sender *sender) 
{
	return (sender
		? genlmsg_unicast(skb, sender->pid)
		: genlmsg_multicast(skb, 0, mc_group.id, GFP_ATOMIC));
}

extern "C" int 
send_feedback() {
  //click_chatter("send_feedback");
  
  struct sk_buff *skb = NULL;

  int err;

  skb = genlmsg_new(NLMSG_GOODSIZE, GFP_ATOMIC);
  if (!skb) return -1;

  void * msg_head;
  msg_head = genlmsg_put(skb, 0, 0, &feedback_genl_family, 0, FEEDBACK_GENL_C_OPENFLOW); 
  if (!msg_head) return ERR_PTR(-ENOBUFS);

  int rc = nla_put_string(skb, FEEDBACK_GENL_A_OPENFLOW, "haha");
  if (rc < 0) return ERR_PTR(-ENOBUFS);

  genlmsg_end(skb, msg_head);

  //click_chatter("start send feedback");
  //int r = genlmsg_multicast(skb, 0, mc_group.id, GFP_ATOMIC);
  int r = genlmsg_unicast(skb, feedback_sender.pid);
  if (r < 0)
    click_chatter("error %d\n", r);
}

CLICK_ENDDECLS
ELEMENT_REQUIRES(linuxmodule)
ELEMENT_PROVIDES(OPENFLOW_GENL)
