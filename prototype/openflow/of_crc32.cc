// -*- c-basic-offset: 4; related-file-name: "of_crc32.hh" -*-
/*
 * of_crc32.{cc,hh} -- Openflow of_crc32
 */

#include <click/config.h>
#include <clicknet/ether.h>
#include <clicknet/ip.h>
#include <clicknet/tcp.h>
#include <clicknet/udp.h>
#include <clicknet/icmp.h>
#include "of_crc32.hh"
#include "openflow.hh"

CLICK_DECLS

void of_crc32_init(struct of_crc32 *crc, unsigned int polynomial)
{
	int i;

	for (i = 0; i < OF_CRC32_TABLE_SIZE; ++i) {
		unsigned int reg = i << 24;
		int j;
		for (j = 0; j < OF_CRC32_TABLE_BITS; j++) {
			int topBit = (reg & 0x80000000) != 0;
			reg <<= 1;
			if (topBit)
				reg ^= polynomial;
			}
			crc->table[i] = reg;
	}
}

unsigned int of_crc32_calculate(const struct of_crc32 *crc,
			const void *data_, size_t n_bytes)
{
	// FIXME: this can be optimized by unrolling, see linux-2.6/lib/of_crc32.c.
	const uint8_t *data = data_;
	unsigned int result = 0;
	size_t i;

	for (i = 0; i < n_bytes; i++) {
		unsigned int top = result >> 24;
		top ^= data[i];
		result = (result << 8) ^ crc->table[top];
	}
	return result;
}

CLICK_ENDDECLS
ELEMENT_REQUIRES(linuxmodule)
ELEMENT_PROVIDES(OPENFLOW_OF_CRC32)
