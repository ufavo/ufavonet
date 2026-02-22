#ifndef __packet_internal_h__
#define __packet_internal_h__

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "../include/packet.h"

struct packet
{
	uint32_t	index;
	uint32_t 	length;
	uint8_t 	*data;
	size_t		size;
	uint32_t 	write_op_count;
	uint8_t 	realloc_allowed;

	uint8_t 	bits_index;
	uint8_t 	*bits_byte;
};

static inline void
_packet_init_from_buf(packet_t *restrict p, void *buf, size_t size)
{
	memset(p, 0, sizeof(*p));
	p->data = buf;
	p->size = size;
	p->realloc_allowed = 0;
}

#endif
