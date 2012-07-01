// -*- related-file-name: "of_crc32.cc" -*-
#ifndef CLICK_OF_CRC32_HH
#define CLICK_OF_CRC32_HH
#include <click/algorithm.hh>
#include <click/atomic.hh>
CLICK_CXX_PROTECT
#include <linux/types.h>
#ifndef __KERNEL__
#include <stdint.h>
#endif
#include <stddef.h>
CLICK_CXX_UNPROTECT

CLICK_DECLS

#define OF_CRC32_TABLE_BITS 8
#define OF_CRC32_TABLE_SIZE (1u << OF_CRC32_TABLE_BITS)

struct of_crc32 {
		unsigned int table[OF_CRC32_TABLE_SIZE];
};

void of_crc32_init(struct of_crc32 *, unsigned int polynomial);
unsigned int of_crc32_calculate(const struct of_crc32 *,
							 const void *data_, size_t n_bytes);

CLICK_ENDDECLS
#endif
