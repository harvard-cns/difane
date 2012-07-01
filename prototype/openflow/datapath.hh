// -*- related-file-name: "datapath.cc" -*-
#ifndef CLICK_DATAPATH_HH
#define CLICK_DATAPATH_HH
#include <click/algorithm.hh>
#include <click/atomic.hh>
#include <click/sync.hh>
#include <click/element.hh>
#include "forward.hh"
#include "port.hh"
#include "chain.hh"
#include "packet_buffer.hh"

#define DP_MAX 32

CLICK_DECLS

/* Capabilities supported by this implementation. */
#define OFP_SUPPORTED_CAPABILITIES ( OFPC_FLOW_STATS \
                | OFPC_TABLE_STATS \
                | OFPC_PORT_STATS \
				     | OFPC_MULTI_PHY_TX )

/* Actions supported by this implementation. */
#define OFP_SUPPORTED_ACTIONS ( (1 << OFPAT_OUTPUT)		\
				| (1 << OFPAT_SET_VLAN_VID)	\
				| (1 << OFPAT_SET_VLAN_PCP)	\
				| (1 << OFPAT_STRIP_VLAN)	\
				| (1 << OFPAT_SET_DL_SRC)	\
				| (1 << OFPAT_SET_DL_DST)	\
				| (1 << OFPAT_SET_NW_SRC)	\
				| (1 << OFPAT_SET_NW_DST)	\
				| (1 << OFPAT_SET_TP_SRC)	\
				| (1 << OFPAT_SET_TP_DST) )


/* Information necessary to reply to the sender of an OpenFlow message. */
struct sender {
  uint32_t xid;           /* OpenFlow transaction ID of request. */
  uint32_t pid;           /* Netlink process ID of sending socket. */
  uint32_t seq;           /* Netlink sequence ID of request. */
};

class Ofswitch;
#define DP_MAX_PORTS 255

extern Datapath *dps[DP_MAX];

class Datapath {
public:
  int dp_idx;
  uint8_t mac[OFP_ETH_ALEN]; 
  struct timer_list timer;        /* Expiration timer. */
  OFChain *chain;  /* Forwarding rules. */
  struct task_struct *dp_task; /* Kernel thread for maintenance. */

  /* Data related to the "of" device of this datapath */
  struct net_device *netdev;

  /* Configuration set from controller */
  uint16_t flags;
  uint16_t miss_send_len;

  /* Switch ports. */
  Port *ports[DP_MAX_PORTS];
  Port *local_port; /* OFPP_LOCAL port. */
  SpinlockIRQ port_lock;
  port_list plist;
  struct mutex dp_mutex;
  Buffer storage;
  Ofswitch *ofs;
public:
  Datapath();
  ~Datapath();
  void lock() { mutex_lock(&dp_mutex); };
  void unlock() { mutex_unlock(&dp_mutex); };
  int output_all(Packet *p_in, int flood);

  static Datapath *dp_get(int dp_idx)
  {
    if (dp_idx < 0 || dp_idx > DP_MAX)
      return NULL;
    return rcu_dereference(dps[dp_idx]);
  };

  int get_idx() { return dp_idx; } ;
  OFChain *get_chain() { return chain; } ;
  uint64_t get_datapath_id(struct net_device *dev);
  int find_portno(Datapath *dp);
  int initialize(int dp_idx);
  void cleanup();
  int del_all_ports();

  int send_error_msg(const struct sender *sender, 
			uint16_t type, uint16_t code, const void *data, size_t len);

  int send_hello(const struct sender *sender,
		 const struct ofp_header *request);

  int send_features_reply(const struct sender *sender);

  int send_config_reply(const struct sender *sender);

  void set_uuid_mac();

  uint64_t get_datapath_id();

  int send_echo_reply(const struct sender *sender,
		      const struct ofp_header *rq);

  int add_switch_port(int port_num=-1);
  Port *new_port(int port_no);
  int find_portno();
  int del_switch_port(Port *p);
  int send_port_status(Port *p, uint8_t status);
  int fill_features_reply(struct ofp_switch_features *ofr);
  int send_flow_expired( struct sw_flow *flow,
			 enum ofp_flow_expired_reason reason);
  int output_port(Packet *p_in, int out_port, int ignore_no_fwd);
  int output_control(Packet *p_in, uint32_t buffer_id, size_t max_len, int reason);

};

CLICK_ENDDECLS
#endif
