// -*- c-basic-offset: 4; related-file-name: "packet_buffer.hh" -*-
/*
 * packet_buffer.{cc,hh} -- Openflow packet_buffer
 */

#include <click/config.h>
#include <clicknet/ether.h>
#include <clicknet/ip.h>
#include <clicknet/tcp.h>
#include <clicknet/udp.h>
#include <clicknet/icmp.h>
#include "packet_buffer.hh"
#include "openflow.hh"

CLICK_CXX_PROTECT
#include <linux/if.h>
#include <linux/if_vlan.h>
#include <linux/llc.h>
#include <net/llc_pdu.h>
CLICK_CXX_UNPROTECT

CLICK_DECLS

uint32_t 
Buffer::store_packet(Packet *p_in)
{
    Packet *old_pkt = NULL;
    Packet *clone = p_in->clone();
    buffer_entry *p;
    uint32_t id;
    unsigned long flags;

    WritablePacket *q = clone->uniqueify();
    if (!q)
	return -1;

    flags = buffer_lock.acquire();    

    buffer_idx = (buffer_idx + 1) & PKT_BUFFER_MASK;
    p = &buffers[buffer_idx];
    if (p->pkt) {
	/* Don't buffer packet if existing entry is less than
	 * OVERWRITE_SECS old. */
	if (time_before(jiffies, p->exp_jiffies)) {
	    buffer_lock.release(flags);

	    q->kill();
	    return -1;
	} else {
	    /* Defer packet freeing until interrupts re-enabled.
	     * FIXME: we only need to do that if it has a
	     * destructor, but it never should since we orphan
	     * sk_buffs on entry. */
	    old_pkt = p->pkt;
	}
    }
    /* Don't use maximum cookie value since the all-bits-1 id is
     * special. */
    if (++p->cookie >= (1u << PKT_COOKIE_BITS) - 1)
	p->cookie = 0;
    p->pkt = q->clone();
    p->exp_jiffies = jiffies + OVERWRITE_JIFFIES;
    id = buffer_idx | (p->cookie << PKT_BUFFER_BITS);
    buffer_lock.release(flags);

    if (old_pkt)
	old_pkt->kill();

    return id;
}

Packet *
Buffer::retrieve_skb(uint32_t id)
{
    Packet *q = NULL;
    buffer_entry *p;
    unsigned long flags;

    flags = buffer_lock.acquire();

    p = &buffers[id & PKT_BUFFER_MASK];
    if (p->cookie == id >> PKT_BUFFER_BITS) {
		q = p->pkt;
		p->pkt = NULL;
    } else {
	click_chatter("cookie mismatch: %x != %x\n",
	       id >> PKT_BUFFER_BITS, p->cookie);
    }
    buffer_lock.release(flags);

    return q;
}

void 
Buffer::fwd_discard_all(void) 
{
    int i;
    unsigned long flags;

    for (i = 0; i < N_PKT_BUFFERS; i++) {
	Packet *q;

	/* Defer pkt freeing until interrupts re-enabled. */
	flags = buffer_lock.acquire();
	q = buffers[i].pkt;
	buffers[i].pkt = NULL;
	buffer_lock.release(flags);
	
	q->kill();
    }
}

void 
Buffer::discard_skb(uint32_t id)
{
    Packet *old_pkt = NULL;
    buffer_entry *p;
    unsigned long flags; 

    flags = buffer_lock.acquire();
    p = &buffers[id & PKT_BUFFER_MASK];
    if (p->cookie == id >> PKT_BUFFER_BITS) {
	/* Defer packet freeing until interrupts re-enabled. */
	old_pkt = p->pkt;
	p->pkt = NULL;
    }
    buffer_lock.release(flags);

    if (old_pkt)
	old_pkt->kill;
}

void 
Buffer::fwd_exit(void)
{
	fwd_discard_all();
}

CLICK_ENDDECLS
ELEMENT_REQUIRES(linuxmodule)
ELEMENT_PROVIDES(OPENFLOW_PACKET_BUFFER)
