#include <click/config.h>
#include <click/error.hh>

#include "ofswitch.hh"
#include "datapath.hh"
#include "port.hh"
#include "forward.hh"

CLICK_CXX_PROTECT
#include <linux/netdevice.h>
#include <linux/rtnetlink.h>
#include <linux/mutex.h>
CLICK_CXX_UNPROTECT

CLICK_DECLS

extern bool registered;
extern struct genl_family dp_genl_family;
extern struct genl_multicast_group mc_group;
extern struct nla_policy dp_genl_policy[DP_GENL_A_MAX + 1];
extern struct genl_ops dp_genl_ops_add_dp;
extern struct genl_ops dp_genl_ops_del_dp;
extern struct genl_ops dp_genl_ops_query_dp;
extern struct genl_ops dp_genl_ops_add_port;
extern struct genl_ops dp_genl_ops_del_port;
extern struct nla_policy dp_genl_openflow_policy[DP_GENL_A_MAX + 1];
extern struct genl_ops dp_genl_ops_openflow;
extern struct genl_ops *dp_genl_all_ops[6];

//Minlan
extern struct genl_family feedback_genl_family;
extern struct genl_multicast_group feedback_mc_group;
extern struct nla_policy feedback_genl_policy[FEEDBACK_GENL_A_MAX + 1];
extern struct nla_policy feedback_genl_openflow_policy[FEEDBACK_GENL_A_MAX + 1];
extern struct genl_ops feedback_genl_ops_openflow;
extern struct genl_ops feedback_genl_ops_query;
extern struct genl_ops * feedback_genl_all_ops[FEEDBACK_OPS_COUNT];

Ofswitch::Ofswitch():_timer(this)
{
}

void 
Ofswitch::push(int port, Packet *p_in) {
  p_in->set_anno_u8(5, port);
  p_in->set_anno_u8(6, 1);
  OFChain *ofchain = dp0->chain;
  ofchain->dp = dp0;
  dp0->ports[port]->stats->rx_packets++;
  dp0->ports[port]->stats->rx_bytes += p_in->length();
  fwd_port_input(ofchain, p_in);
}

void
Ofswitch::run_timer(Timer *timer)
{
  // Call code to time out flow entries
  dp0->chain->chain_timeout();
  _timer.reschedule_after_msec(CHAIN_PURGE_FREQUENCY);
}

Ofswitch::~Ofswitch()
{
}

int
Ofswitch::configure(Vector<String> &conf, ErrorHandler *errh)
{
  return 0;
}

void
Ofswitch::cleanup(CleanupStage stage)
{
    if (stage >= CLEANUP_INITIALIZED) {
	dp0->cleanup();
	if (registered) {
	  genl_unregister_family(&dp_genl_family);
          genl_unregister_family(&feedback_genl_family);
	}

	sw_flow::flow_exit();
    }
}

int
Ofswitch::initialize(ErrorHandler *errh)
{
  int err = 0;

  for (int k = 0; k < DP_MAX; k++) {
    dps[k] = NULL;
  }

  sw_flow::flow_init();

    /* Generic Netlink interface.
     *
     * See netlink(7) for an introduction to netlink.  See
     * http://linux-net.osdl.org/index.php/Netlink for more information and
     * pointers on how to work with netlink and Generic Netlink in the kernel and
     * in userspace. */
    dp_genl_family.id = GENL_ID_GENERATE;
    dp_genl_family.hdrsize = 0;
    strcpy(dp_genl_family.name, DP_GENL_FAMILY_NAME);
    dp_genl_family.version = 1;
    dp_genl_family.maxattr = DP_GENL_A_MAX;

    /* Attribute policy: what each attribute may contain.  */
    dp_genl_policy[DP_GENL_A_DP_IDX].type = NLA_U32;
    dp_genl_policy[DP_GENL_A_MC_GROUP].type = NLA_U32;
    dp_genl_policy[DP_GENL_A_PORTNAME].type = NLA_STRING;

    dp_genl_ops_add_dp.cmd = DP_GENL_C_ADD_DP;
    dp_genl_ops_add_dp.flags = GENL_ADMIN_PERM; /* Requires CAP_NET_ADMIN privilege. */
    dp_genl_ops_add_dp.policy = dp_genl_policy;
    dp_genl_ops_add_dp.doit = dp_genl_add;
    dp_genl_ops_add_dp.dumpit = NULL;

    dp_genl_ops_add_dp.cmd = DP_GENL_C_ADD_DP;
    dp_genl_ops_add_dp.flags = GENL_ADMIN_PERM; /* Requires CAP_NET_ADMIN privilege. */
    dp_genl_ops_add_dp.policy = dp_genl_policy;
    dp_genl_ops_add_dp.doit = dp_genl_add;
    dp_genl_ops_add_dp.dumpit = NULL;

    dp_genl_ops_del_dp.cmd = DP_GENL_C_DEL_DP;
    dp_genl_ops_del_dp.flags = GENL_ADMIN_PERM; /* Requires CAP_NET_ADMIN privilege. */
    dp_genl_ops_del_dp.policy = dp_genl_policy;
    dp_genl_ops_del_dp.doit = dp_genl_del;
    dp_genl_ops_del_dp.dumpit = NULL;

    dp_genl_ops_query_dp.cmd = DP_GENL_C_QUERY_DP;
    dp_genl_ops_query_dp.flags = GENL_ADMIN_PERM; /* Requires CAP_NET_ADMIN privilege. */
    dp_genl_ops_query_dp.policy = dp_genl_policy;
    dp_genl_ops_query_dp.doit = dp_genl_query;
    dp_genl_ops_query_dp.dumpit = NULL;

    dp_genl_ops_add_port.cmd = DP_GENL_C_ADD_PORT;
    dp_genl_ops_add_port.flags = GENL_ADMIN_PERM; /* Requires CAP_NET_ADMIN privilege. */
    dp_genl_ops_add_port.policy = dp_genl_policy;
    dp_genl_ops_add_port.doit = dp_genl_add_del_port;
    dp_genl_ops_add_port.dumpit = NULL;

    dp_genl_ops_del_port.cmd = DP_GENL_C_DEL_PORT;
    dp_genl_ops_del_port.flags = GENL_ADMIN_PERM; /* Requires CAP_NET_ADMIN privilege. */
    dp_genl_ops_del_port.policy = dp_genl_policy;
    dp_genl_ops_del_port.doit = dp_genl_add_del_port;
    dp_genl_ops_del_port.dumpit = NULL;

    dp_genl_openflow_policy[DP_GENL_A_DP_IDX].type = NLA_U32;

    dp_genl_ops_openflow.cmd = DP_GENL_C_OPENFLOW;
    dp_genl_ops_openflow.flags = GENL_ADMIN_PERM; /* Requires CAP_NET_ADMIN privilege. */
    dp_genl_ops_openflow.policy = dp_genl_openflow_policy;
    dp_genl_ops_openflow.doit = dp_genl_openflow;
    dp_genl_ops_openflow.dumpit = dp_genl_openflow_dumpit;

    /* Keep this operation first.  Generic Netlink dispatching
     * looks up operations with linear search, so we want it at the
     * front. */
    dp_genl_all_ops[0] = &dp_genl_ops_openflow;
    dp_genl_all_ops[1] = &dp_genl_ops_add_dp;
    dp_genl_all_ops[2] = &dp_genl_ops_del_dp;
    dp_genl_all_ops[3] = &dp_genl_ops_query_dp;
    dp_genl_all_ops[4] = &dp_genl_ops_add_port;
    dp_genl_all_ops[5] = &dp_genl_ops_del_port;

    err = genl_register_family(&dp_genl_family);

    if (err) {
      return -1;
    }

    //Minlan
    feedback_genl_policy[FEEDBACK_GENL_A_OPENFLOW].type = NLA_STRING;
    feedback_genl_policy[FEEDBACK_GENL_A_MC_GROUP].type = NLA_U32;
    
    feedback_genl_ops_query.cmd = FEEDBACK_GENL_C_QUERY;
    feedback_genl_ops_query.flags = 0;//GENL_ADMIN_PERM; /* Requires CAP_NET_ADMIN privilege. */
    feedback_genl_ops_query.policy = feedback_genl_policy;
    feedback_genl_ops_query.doit = feedback_genl_query;
    feedback_genl_ops_query.dumpit = NULL;

    feedback_genl_ops_openflow.cmd = FEEDBACK_GENL_C_OPENFLOW;
    feedback_genl_ops_openflow.flags = GENL_ADMIN_PERM; /* Requires CAP_NET_ADMIN privilege. */
    feedback_genl_ops_openflow.policy = feedback_genl_openflow_policy;
    feedback_genl_ops_openflow.doit = feedback_genl_openflow;
    feedback_genl_ops_openflow.dumpit = NULL;
    
    feedback_genl_family.id = GENL_ID_GENERATE;
    feedback_genl_family.hdrsize = 0;
    strcpy(feedback_genl_family.name, FEEDBACK_GENL_FAMILY_NAME);
    feedback_genl_family.version = 1;
    feedback_genl_family.maxattr = FEEDBACK_GENL_A_MAX;
    err = genl_register_family(&feedback_genl_family);
    if (err < 0) {
      click_chatter("register feedback_genl_family fail");
      return -1;
    }

    registered = true;

    for (int i = 0; i < 6; i++) {
      err = genl_register_ops(&dp_genl_family, dp_genl_all_ops[i]);
      if (err) {
	goto err_unregister;
      }
    }

    //Minlan
    feedback_genl_all_ops[0] = &feedback_genl_ops_query;
    feedback_genl_all_ops[1] = &feedback_genl_ops_openflow;

    for (int i = 0; i < FEEDBACK_OPS_COUNT; i ++) {
      err = genl_register_ops(&feedback_genl_family, feedback_genl_all_ops[i]);
      if (err) {
        click_chatter("feedback genl_register_ops fail");
        goto err_unregister;
      }
    }

    strcpy(mc_group.name, "openflow");
    err = genl_register_mc_group(&dp_genl_family, &mc_group);
    if (err < 0)
	goto err_unregister;

    //Minlan
    strcpy(feedback_mc_group.name, "feedback");
    err = genl_register_mc_group(&feedback_genl_family, &feedback_mc_group);
    if (err < 0) {
      click_chatter("feedback genl_register_mc_group fail");
      goto err_unregister;
    }

    //click_chatter("start dp0 %d %d", feedback_genl_family.id, feedback_mc_group.id);
    dp0 = new Datapath;

   if ( dp0 == NULL ) {
	err = -ENOMEM;
        click_chatter("dp0 error 1");
	goto err_unregister;
    }

   dp0->ofs = this;
   err = dp0->initialize(0);
   rcu_assign_pointer(dps[0], dp0);

   if (err == -EEXIST) {
     click_chatter("dp0 error 2");
     delete dp0;
     goto err_unregister;
   }

   for(int p=0; p < nports(true); p++) {
     err = dp0->add_switch_port(p);
     if (err) {
       click_chatter("dp0 add_switch_port error");
       goto err_delete_ports;
     }
   }

  _timer.initialize(this);
  _timer.reschedule_after_msec(CHAIN_PURGE_FREQUENCY);
  
  click_chatter("switch initialize succeed");
    return 0;
 err_delete_ports:
    dp0->del_all_ports();

 err_unregister:
    genl_unregister_family(&dp_genl_family);
    genl_unregister_family(&feedback_genl_family);
    sw_flow::flow_exit();
    click_chatter("OpenFlow Debug(%s,%d): Error(%d) while registering the family",__FUNCTION__,__LINE__,err);
    return -1;
}

CLICK_ENDDECLS
ELEMENT_REQUIRES(linuxmodule)
ELEMENT_REQUIRES(OPENFLOW_GENL)
EXPORT_ELEMENT(Ofswitch)
