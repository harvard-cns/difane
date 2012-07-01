#ifndef CLICK_TABLE_HH
#define CLICK_TABLE_HH
#include <click/algorithm.hh>
#include <click/atomic.hh>
CLICK_CXX_PROTECT
#include <linux/types.h>
CLICK_CXX_UNPROTECT

#include "flow.hh"
#include "of_crc32.hh"

CLICK_DECLS

class Datapath;
/* Table statistics. */
struct sw_table_stats {
	const char *name;            /* Human-readable name. */
	uint32_t wildcards;          /* Bitmap of OFPFW_* wildcards that are
	                                supported by the table. */
	unsigned int n_flows;        /* Number of active flows. */
	unsigned int max_flows;      /* Flow capacity. */
	unsigned long int n_lookup;  /* Number of packets looked up. */
	unsigned long int n_matched; /* Number of packets that have hit. */
};

/* Position within an iteration of a sw_table.
 *
 * The contents are private to the table implementation, except that a position
 * initialized to all-zero-bits represents the start of a table. */
struct sw_table_position {
	unsigned long priv[4];
};

class FlowTable {
public:
  /* The number of packets that have been looked up and matched,
   * respecitvely.  To make these 100% accurate, they should be atomic.  
   * However, we're primarily concerned about speed. */
  unsigned long long n_lookup;
  unsigned long long n_matched;

public:
  FlowTable() {
    n_lookup = 0;
    n_matched = 0;
  };

  virtual ~FlowTable() {};
  virtual int create(unsigned int polynomial, unsigned int n_buckets) = 0;
  virtual int create(unsigned int max_flows) = 0;
  virtual sw_flow *lookup(const sw_flow_key *key) = 0;
  virtual int insert(sw_flow *flow) = 0;
  virtual int modify(const sw_flow_key *key, uint16_t priority,
	     int strict,const struct ofp_action_header *actions, size_t actions_len) = 0;
  virtual int delete_flows(sw_flow_key *key, uint16_t out_port, uint16_t priority, int strict) = 0;
  virtual int timeout(Datapath *dp) = 0;
  virtual void destroy() = 0;
  virtual int iterate(const sw_flow_key *key, uint16_t out_port, struct sw_table_position *position,
	      int (*callback)(struct sw_flow *flow, void *private_data),
	      void *private_data) = 0;
  virtual void stats(struct sw_table_stats *stats) = 0;

};

CLICK_ENDDECLS
#endif
