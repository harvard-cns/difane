// -*- related-file-name: "table_linear.cc" -*-
#ifndef CLICK_TABLE_LINEAR_HH
#define CLICK_TABLE_LINEAR_HH
#include <click/algorithm.hh>
#include <click/atomic.hh>
CLICK_CXX_PROTECT
#include <linux/types.h>
CLICK_CXX_UNPROTECT

#include "flow.hh"
#include "table.hh"
#include "of_crc32.hh"

CLICK_DECLS

class FlowTable_Linear : public FlowTable {
public:
  unsigned int max_flows;
  unsigned int n_flows;
  unsigned long int next_serial;
  FlowList fl;
  FlowIterList il;
  SpinlockIRQ _lock;

public:
  FlowTable_Linear():fl(),il() {
  };

  ~FlowTable_Linear() { };
  int create(unsigned int max_flows);
  int create(unsigned int polynomial, unsigned int n_buckets) {return -1;};
  sw_flow *lookup(const sw_flow_key *key);
  int insert(sw_flow *flow);
  int modify(const sw_flow_key *key, uint16_t priority,
	     int strict,const struct ofp_action_header *actions, size_t actions_len);
  int do_delete(FlowList::iterator it);
  int delete_flows(sw_flow_key *key, uint16_t out_port, uint16_t priority, int strict);
  int timeout(Datapath *dp);
  void destroy();
  int iterate(const sw_flow_key *key, uint16_t out_port, struct sw_table_position *position,
	      int (*callback)(struct sw_flow *flow, void *private_data),
	      void *private_data);
  void stats(struct sw_table_stats *stats);
};

CLICK_ENDDECLS
#endif
