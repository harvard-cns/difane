// -*- related-file-name: "table_hash.cc" -*-
#ifndef CLICK_TABLE_HASH_HH
#define CLICK_TABLE_HASH_HH
#include <click/algorithm.hh>
#include <click/atomic.hh>
CLICK_CXX_PROTECT
#include <linux/types.h>
CLICK_CXX_UNPROTECT

#include "flow.hh"
#include "table.hh"
#include "of_crc32.hh"

CLICK_DECLS

class FlowTable_Hash : public FlowTable {
public:
  struct of_crc32 crc32;
  unsigned int n_flows;
  unsigned int bucket_mask; /* Number of buckets minus 1. */
  struct sw_flow **buckets;

public:
  FlowTable_Hash() {
    n_flows = 0;
    bucket_mask = 0;
    buckets = NULL;
  };

  ~FlowTable_Hash() {};
  int create(unsigned int polynomial, unsigned int n_buckets);
  int create(unsigned int max_flows) {return -1;};
  sw_flow *lookup(const sw_flow_key *key);
  int insert(sw_flow *flow);
  int modify(const sw_flow_key *key, uint16_t priority,
	     int strict,const struct ofp_action_header *actions, size_t actions_len);
  int delete_flows(sw_flow_key *key, uint16_t out_port, uint16_t priority, int strict);
  int timeout(Datapath *dp);
  void destroy();
  int iterate(const sw_flow_key *key, uint16_t out_port, struct sw_table_position *position,
	      int (*callback)(struct sw_flow *flow, void *private_data),
	      void *private_data);
  void stats(struct sw_table_stats *stats);

  static void *kmem_alloc(size_t);
  static void *kmem_zalloc(size_t);
  static void kmem_free(void *, size_t);

  struct sw_flow **find_bucket(const struct sw_flow_key *key);
  int do_delete(struct sw_flow **bucket, struct sw_flow *flow);
};

CLICK_ENDDECLS
#endif
