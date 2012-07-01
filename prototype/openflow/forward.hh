// -*- related-file-name: "forward.cc" -*-
#ifndef CLICK_FORWARD_HH
#define CLICK_FORWARD_HH
#include <click/algorithm.hh>
#include <click/atomic.hh>
CLICK_CXX_PROTECT
#include <linux/types.h>
CLICK_CXX_UNPROTECT
#include "datapath.hh"
#include "flow.hh"

CLICK_DECLS

struct sk_buff;
struct OFChain;

int fwd_control_input(OFChain *, const struct sender *,
 		      const void *, size_t);
int run_flow_through_tables(OFChain *chain, Packet *pkt);
void fwd_port_input(OFChain *chain, Packet *pkt);

CLICK_ENDDECLS
#endif
