// -*- related-file-name: "packet_buffer.cc" -*-
#ifndef CLICK_OFPACKET_BUFFER_HH
#define CLICK_OFPACKET_BUFFER_HH

#include <click/config.h>
#include <click/packet.hh>
#include <click/sync.hh>
#include "openflow.hh"

CLICK_CXX_PROTECT
#include <linux/kernel.h>
#include <linux/spinlock.h>
#include <linux/list.h>
#include <linux/types.h>
#include <linux/rcupdate.h>
#include <linux/gfp.h>
#include <linux/skbuff.h>
#include <linux/if_ether.h>
CLICK_CXX_UNPROTECT

CLICK_DECLS

#define OVERWRITE_SECS	1
#define OVERWRITE_JIFFIES (OVERWRITE_SECS * HZ)

/* Buffers are identified to userspace by a 31-bit opaque ID.  We divide the ID
 * into a buffer number (low bits) and a cookie (high bits).  The buffer number
 * is an index into an array of buffers.  The cookie distinguishes between
 * different packets that have occupied a single buffer.  Thus, the more
 * buffers we have, the lower-quality the cookie... */
#define PKT_BUFFER_BITS 8
#define N_PKT_BUFFERS (1 << PKT_BUFFER_BITS)
#define PKT_BUFFER_MASK (N_PKT_BUFFERS - 1)
#define PKT_COOKIE_BITS (32 - PKT_BUFFER_BITS)

struct buffer_entry {
        Packet *pkt;
	uint32_t cookie;
	unsigned long exp_jiffies;
};

struct Buffer {
  buffer_entry buffers[N_PKT_BUFFERS];
  unsigned int buffer_idx;
  SpinlockIRQ buffer_lock;

  Buffer():buffer_lock() { 
    buffer_idx = 0;
    for (int i = 0; i < N_PKT_BUFFERS; i++) {
      buffers[i].pkt = NULL;
      buffers[i].cookie = i*i;
      buffers[i].exp_jiffies = jiffies;
    }
  };

  uint32_t store_packet(Packet *p_in);
  Packet *retrieve_skb(uint32_t id);
  void fwd_discard_all(void);
  void discard_skb(uint32_t id);
  void fwd_exit(void);
};

CLICK_ENDDECLS
#endif /* packet_buffer.hh */
