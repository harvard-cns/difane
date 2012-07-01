// -*- related-file-name: "openflow_genl.cc" -*-
#ifndef CLICK_GENL_HH
#define CLICK_GENL_HH
#include <click/algorithm.hh>
#include <click/atomic.hh>
CLICK_CXX_PROTECT
#include <linux/netlink.h>
#include <net/genetlink.h>
CLICK_CXX_UNPROTECT
#include "datapath.hh"

CLICK_DECLS

#define DP_GENL_FAMILY_NAME "OpenFlow"
#define FEEDBACK_GENL_FAMILY_NAME "Feedback"

#define UINT32_MAX                        4294967295U
#define UINT16_MAX                        65535

#define CANONICAL_RULE 10001

/* Attributes that can be attached to the datapath's netlink messages. */
enum {
	DP_GENL_A_UNSPEC,
	DP_GENL_A_DP_IDX,	 /* Datapath Ethernet device name. */
	DP_GENL_A_PORTNAME,	 /* Device name for datapath port. */
	DP_GENL_A_MC_GROUP,	 /* Generic netlink multicast group. */
	DP_GENL_A_OPENFLOW,  /* OpenFlow packet. */

	__DP_GENL_A_MAX,
	DP_GENL_A_MAX = __DP_GENL_A_MAX - 1
};

enum {
  FEEDBACK_GENL_A_MC_GROUP,
  FEEDBACK_GENL_A_OPENFLOW, 

  __FEEDBACK_GENL_A_MAX,
  FEEDBACK_GENL_A_MAX = __FEEDBACK_GENL_A_MAX -1
};


/* Commands that can be executed on the datapath's netlink interface. */
enum dp_genl_command {
	DP_GENL_C_UNSPEC,
	DP_GENL_C_ADD_DP,	 /* Create datapath. */
	DP_GENL_C_DEL_DP,	 /* Destroy datapath. */
	DP_GENL_C_QUERY_DP,	 /* Get multicast group for datapath. */
	DP_GENL_C_ADD_PORT,	 /* Add port to datapath. */
	DP_GENL_C_DEL_PORT,	 /* Remove port from datapath. */
	DP_GENL_C_OPENFLOW,  /* Encapsulated OpenFlow protocol. */

	__DP_GENL_C_MAX,
	DP_GENL_C_MAX = __DP_GENL_C_MAX - 1
};

enum feedback_genl_command {
  FEEDBACK_GENL_C_QUERY,
  FEEDBACK_GENL_C_OPENFLOW
};
#define FEEDBACK_OPS_COUNT 2

extern "C" void nla_shrink(struct sk_buff *skb, struct nlattr *nla, int len);
extern "C" void *put_openflow_headers(Datapath *dp, struct sk_buff *skb, uint8_t type,
			   const struct sender *sender, int *max_openflow_len);
extern "C" void resize_openflow_skb(struct sk_buff *skb,
			 struct ofp_header *oh, size_t new_length);
extern "C" void *alloc_openflow_skb(Datapath *dp, size_t openflow_len, uint8_t type,
			 const struct sender *sender, struct sk_buff **pskb); 
extern "C" int send_openflow_skb(struct sk_buff *skb, const struct sender *sender);
extern "C" int dp_genl_add(struct sk_buff *skb, struct genl_info *info);
extern "C" int dp_genl_del(struct sk_buff *skb, struct genl_info *info);
extern "C" int dp_genl_query(struct sk_buff *skb, struct genl_info *info);
extern "C" int dp_genl_add_del_port(struct sk_buff *skb, struct genl_info *info);
extern "C" int dp_genl_openflow(struct sk_buff *skb, struct genl_info *info);
extern "C" int dp_genl_openflow_dumpit(struct sk_buff *skb, struct netlink_callback *cb);
extern "C" int dp_genl_openflow_done(struct netlink_callback *cb);

extern "C" int feedback_genl_openflow(struct sk_buff *skb, struct genl_info *info);
extern "C" int feedback_genl_query(struct sk_buff *skb, struct genl_info *info);
extern "C" int send_feedback();

CLICK_ENDDECLS
#endif
