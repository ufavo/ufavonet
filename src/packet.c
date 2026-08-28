/*
 * Packet implementation.
 * Copyright (C) 2023  Luiz Gustavo Sassanovicz Borsoi
 *
 * This file is part of Ufavonet.
 *
 * Ufavonet is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Ufavonet is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */


#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#include <winsock2.h>
#else
#include <arpa/inet.h>
#endif
#include "_hooks.h"
#include "../include/packet.h"
#include "_packet.h"

#define ceil_int_division(A,B) ((A + (B-1)) / B)

#if __BIG_ENDIAN__
# define htonll(x) (x)
# define ntohll(x) (x)
#else
# define htonll(x) (((uint64_t)htonl((x) & 0xFFFFFFFF) << 32) | htonl((x) >> 32))
# define ntohll(x) (((uint64_t)ntohl((x) & 0xFFFFFFFF) << 32) | ntohl((x) >> 32))
#endif


/* index is always one position ahead, so instead subtracting one in the comparision below, we just check if it's greater then */
#define READCHECK(packet_ptr,size) if ((packet_ptr)->index + size > (packet_ptr)->length) { return EPACKET_ERR_OUT_OF_BOUNDS; }
#define WRITECHECK(packet_ptr,sz) if ((packet_ptr)->index + sz >= (packet_ptr)->size && (packet_ptr)->realloc_allowed == 0) { return EPACKET_ERR_OUT_OF_BOUNDS; }

#define RESETPACKET(p) \
	memset(p, 0, sizeof(*p)); \
	p->realloc_allowed = 1;


inline packet_t *
packet_init(void)
{
	packet_t *p = umalloc(sizeof(*p));
	if (!p) return NULL;
	RESETPACKET(p);
	return p;
}

inline packet_t *
packet_init_from_buff(void *buff, const size_t size)
{
	packet_t *p = packet_init();
	if (!p) return NULL;
	p->data = buff;
	p->size = size;
	p->realloc_allowed = 0;
	return p;
}

inline packet_t *
packet_init_from_buffcpy(const void *restrict buff, const size_t size)
{
	packet_t *p = packet_init();
	if (!p) return NULL;
	p->data = umalloc(size);
	if (p->data == NULL) {
		ufree(p);
		return NULL;
	}
	memcpy(p->data, buff, size);
	p->size = size;
	p->realloc_allowed = 1;
	return p;
}

inline packet_t *
packet_init_prealloc(uint32_t size)
{
	packet_t *p = packet_init();
	if (!p)		return NULL;
	if (!size)	return p;

	p->data = umalloc(size);
	if (!p->data) {
		packet_free(&p);
		return NULL;
	}
	p->size = size;
	return p;
}

inline int
packet_free(packet_t *restrict *p)
{
	if (!p) return EPACKET_ERR_NULL;
	if (!*p) return EPACKET_ERR_NULL;
	if ((*p)->realloc_allowed == 1)
		ufree((*p)->data);
	ufree(*p);
	*p = NULL;
	return 0;
}

inline int
packet_rewind(packet_t *restrict p)
{
	p->index = 0;
	p->bits_byte = NULL;
	p->bits_index = 0;
	p->write_op_count = 0;

	return 0;
}

inline uint32_t
packet_get_length(packet_t *restrict p)
{
	return p->length;
}

inline size_t
packet_get_buffsize(packet_t *restrict p)
{
	return p->size;
}

inline void *
packet_get_buff(packet_t *restrict p)
{
	return p->data;
}

inline int
packet_set_buff(packet_t *restrict p, void *buff, const size_t size)
{
	if (buff == NULL) {
		if (p->realloc_allowed == 1) {
			ufree(p->data);
		}
		RESETPACKET(p);
		return 0;
	}
	if (p->realloc_allowed == 1) {
		ufree(p->data);
	}
	p->realloc_allowed = 0;
	p->data = buff;
	p->size = size;
	p->length = 0;
	packet_rewind(p);
	return 0;
}

inline uint32_t
packet_get_index(packet_t *restrict p)
{
	return p->index;
}

inline uint32_t
packet_set_index(packet_t *restrict p, uint32_t index)
{
	if (index > p->length)
		index = p->length;
	p->index = index;
	return index;
}

inline int
packet_set_length(packet_t *restrict p, const uint32_t value)
{
	if (value > p->size) return EPACKET_ERR_OUT_OF_BOUNDS;
	p->length = value;
	return 0;
}

inline uint32_t
packet_get_readable(packet_t *restrict p)
{
	return p->length - p->index; 
}

inline uint32_t
packet_get_write_op_count(packet_t *restrict p)
{
	return p->write_op_count;
}

static inline int
_packet_buffer_expand(packet_t *restrict p, const size_t size)
{
	if(p->size < p->index + size) {
		if (p->realloc_allowed) {
			size_t new_size = p->size + (PACKET_ALLOC_SIZE * ceil_int_division(size, PACKET_ALLOC_SIZE));

			void *rallc = urealloc(p->data, new_size);
			if (!rallc)
				return EPACKET_ERR_OUT_OF_MEMORY;

			p->data = rallc;
			p->size = new_size;
		} else {
			return EPACKET_ERR_OUT_OF_BOUNDS;
		}
	}

	return 0;
}

inline int
packet_w_deferred(packet_t *restrict p, const size_t size, void **out)
{
	*out = NULL;

	int err = _packet_buffer_expand(p, size);
	if (err) return err;

	*out = p->data + p->index;
	p->index += size;
	p->length = p->index;
	return err;
}

inline int
packet_w(packet_t *restrict p, const void *restrict ptr, const size_t size)
{
	if (!size) return 0;
	int err = _packet_buffer_expand(p, size);
	if (err) return err;

	memcpy(p->data + p->index, ptr, size);
	p->index += size;
	p->length = p->index;
	p->write_op_count++;
	return 0;
}


inline int
packet_w_64_t(packet_t *restrict p, const void *restrict ptr)
{
	int64_t ivalue = htonll(*((int64_t*)ptr));
	return packet_w(p, &ivalue, sizeof(int64_t));
}

inline int
packet_w_32_t(packet_t *restrict p, const void *restrict ptr)
{
	int32_t ivalue = htonl(*((int32_t*)ptr));
	return packet_w(p, &ivalue, sizeof(int32_t));
}

inline int
packet_w_16_t(packet_t *restrict p, const void *restrict ptr)
{
	int16_t ivalue = htons(*(int16_t*)ptr);
	return packet_w(p, &ivalue, sizeof(int16_t));
}

inline int
packet_w_8_t(packet_t *restrict p, const void *restrict ptr)
{
	return packet_w(p, ptr, sizeof(int8_t));
}

static inline int
_packet_w_bits(packet_t *restrict p, const uint8_t src, const uint8_t n, packet_deferred_bits_t *restrict loc)
{
	uint_fast8_t 	loc_idx = 0;
	uint8_t 		t, masked;
	int 			err = 0;

	if (p->bits_byte == NULL) {
		t = 0;
		
		err = packet_w_8_t(p, &t);
		if (err > 0) return err;

		loc->byte_idx[loc_idx++] = p->index - 1;
		loc->bit_idx = 0;
		
		p->bits_byte = p->data + p->index - 1;
		p->bits_index = 0;
		p->write_op_count--;
	} else if (p->bits_index + n > 8) {
		WRITECHECK(p, 1);
		
		loc->byte_idx[loc_idx++] = p->bits_byte - p->data;
		loc->bit_idx = p->bits_index;
	}

	masked = (src & (0xFF >> (8-n)));
	*p->bits_byte |= masked << p->bits_index;

	p->bits_index += n;
	if (p->bits_index > 8) {
		/* needs another byte to fully store src */
		t = 0;
		err = packet_w_8_t(p, &t);
		if (err > 0) return err;

		loc->byte_idx[loc_idx] = p->index - 1;
		p->bits_byte = p->data + p->index - 1;

		p->bits_index -= 8;
		*p->bits_byte |= masked >> (n - p->bits_index);
		p->write_op_count--;
	} else if (p->bits_index == 8) {
		p->bits_byte = NULL;
		p->bits_index = 0;
	}

	p->write_op_count++;
	return EPACKET_ERR_NONE;
}

inline int
packet_w_bits(packet_t *restrict p, const uint8_t src, const uint8_t n)
{
	if (n > 8) return EPACKET_ERR_OUT_OF_BOUNDS;

	packet_deferred_bits_t dummy;
	return _packet_w_bits(p, src, n, &dummy);
}

inline int
packet_w_bits_deferred(packet_t *restrict p, const uint8_t src, const uint8_t n, packet_deferred_bits_t *restrict loc)
{
	if (n > 8) return EPACKET_ERR_OUT_OF_BOUNDS;

	loc->byte_idx[0] = loc->byte_idx[1] = 0;
	loc->bit_idx = 0;
	loc->n = n;
	return _packet_w_bits(p, src, n, loc);
}

inline int
packet_w_bits_over(packet_t *restrict p, const uint8_t src, const packet_deferred_bits_t loc)
{
	if (loc.bit_idx >= 8 || loc.n > 8 || loc.byte_idx[0] > p->length)
		return EPACKET_ERR_OUT_OF_BOUNDS;

	uint8_t n = loc.n;
	uint8_t bit_idx = loc.bit_idx;
	uint8_t mask = (0xFF >> (8-n));
	uint8_t masked = (src & mask);

	// set to zero before storing, making overwrites possible
	p->data[loc.byte_idx[0]] &= ~(mask << bit_idx);
	p->data[loc.byte_idx[0]] |= masked << bit_idx;
	bit_idx += n;

	// handle extra byte
	if (bit_idx > 8) {
		if (loc.byte_idx[1] > p->length)
			return EPACKET_ERR_OUT_OF_BOUNDS;

		bit_idx -= 8;
		// set to zero before storing, making overwrites possible
		p->data[loc.byte_idx[1]] &= ~(mask >> (n - bit_idx));
		p->data[loc.byte_idx[1]] |= masked >> (n - bit_idx);
	}

	return EPACKET_ERR_NONE;
}

inline int
packet_r_bits(packet_t *restrict p, uint8_t *restrict ptr, const uint8_t n)
{
	if (n > 8) return EPACKET_ERR_OUT_OF_BOUNDS;

	*ptr = 0;

	if (p->bits_byte == NULL) {
		READCHECK(p, 1);
		p->bits_byte = p->data + p->index;
		p->index++;
		p->bits_index = 0;
	}
	/* extract the bits from the current byte and put them in the output ptr */
	*ptr |= (((0xFF >> (8-n)) << p->bits_index) & *p->bits_byte) >> p->bits_index;

	p->bits_index += n;
	if (p->bits_index > 8) {
		/* there are more bits stored in another byte */
		READCHECK(p, 1);
		p->bits_byte = p->data + p->index;
		p->index++;
		p->bits_index -= 8;
		/* extract the remaining bits shift to correct position and put them in the output ptr */
		*ptr |= ((0xFF >> (8 - p->bits_index)) & *p->bits_byte) << (n - p->bits_index);
	} else if (p->bits_index == 8) {
		p->bits_byte = NULL;
		p->bits_index = 0;
	}
	return 0;
}

inline int
packet_measure_vlen29(uint32_t value)
{
	if (value < 128) return 1;
	if (value < 0x4000) return 2;
	if (value < 0x200000) return 3;
	if (value < 0x20000000) return 4;
	return 0;
}

inline int
packet_w_vlen29(packet_t *restrict p, const uint32_t value)
{
	uint8_t buffer[] = {0,0,0,0};

	if (value < 128) { /* 2^7 */
		buffer[0] = (uint8_t)value;
		packet_w(p, buffer, 1);
	} else if (value < 0x4000) { /* 2^14*/
		buffer[0] = (value >> 7) | 128;
		buffer[1] = value & 127;
		packet_w(p, buffer, 2);
	} else if (value < 0x200000) { /* 2^21 */
		buffer[0] = (value >> 14) | 128;
		buffer[1] = (value >> 7) | 128;
		buffer[2] = value & 127;
		packet_w(p, buffer, 3);
	} else if (value < 0x20000000) { /* 2^29 */
		buffer[0] = (value >> 22) | 128;
		buffer[1] = (value >> 15) | 128;
		buffer[2] = (value >> 8) | 128;
		buffer[3] = value;
		packet_w(p, buffer, 4);
	} else {
		return EPACKET_ERR_OUT_OF_BOUNDS;
	}
	return 0;
}

inline int
packet_r(packet_t *restrict p, void *restrict ptr, const size_t size)
{
	if (!size) return 0;

	READCHECK(p, size);
    memcpy(ptr, p->data + p->index, size);
    p->index += size;
	return 0;
}

inline int
packet_r_64_t(packet_t *restrict p, void *restrict ptr)
{
	READCHECK(p, sizeof(int64_t));
	int64_t result = (int64_t)ntohll(*(int64_t *)(p->data + p->index));
	memcpy(ptr, &result, sizeof(int64_t)); 
	p->index += sizeof(int64_t);
	return 0;
}

inline int
packet_r_32_t(packet_t *restrict p, void *restrict ptr)
{
	READCHECK(p, sizeof(int32_t));
	int32_t result = (int32_t)ntohl(*(int32_t *)(p->data + p->index));
	memcpy(ptr, &result, sizeof(int32_t)); 
	p->index += sizeof(int32_t);
	return 0;
}

inline int
packet_r_16_t(packet_t *restrict p, void *restrict ptr)
{
	READCHECK(p, sizeof(int16_t));
	int16_t result = (int16_t)ntohs(*(int16_t *)(p->data + p->index));
	memcpy(ptr, &result, sizeof(int16_t)); 
	p->index += sizeof(int16_t);
	return 0;
}

inline int
packet_r_8_t(packet_t *restrict p, void *restrict ptr)
{
	return packet_r(p, ptr, sizeof(uint8_t));
}

inline int
packet_r_vlen29(packet_t *restrict p, uint32_t *restrict ptr)
{
	uint32_t	value = 0;
	uint8_t		byte = 0;
	int 		i, err;

	for (i = 0; i < 4; i++) {
		err = packet_r_8_t(p, &byte);
		if (err > 0) {
			return err;
		}
		if (i == 3) {
			value = (value << 8) | byte;
			break;
		} else {
			value = (value << 7) | (byte & 127);
		}
		if (!((byte & 128) != 0)) {
			/* the bit is not set, stop */
			break;
		}
	}
	memcpy(ptr, &value, sizeof(uint32_t));
	return 0;
}

inline int
packet_skip(packet_t *restrict p, const size_t size)
{
	READCHECK(p, size);
	p->index += size;
	return 0;
}

inline int
packet_skip_bits(packet_t *restrict p, const int n)
{
	if (n <= 0 || n > 8) return EPACKET_ERR_OUT_OF_BOUNDS;

	p->bits_index += n;
	if (p->bits_index > 8) {
		READCHECK(p, n);
		p->bits_index -= 8;
		p->bits_byte = p->data + p->index;
		p->index++;
	}
	return 0;
}

inline int
packet_skip_vlen29(packet_t *restrict p)
{
	uint32_t dummy;
	return packet_r_vlen29(p, &dummy);
}

inline int
packet_rw_packet(packet_t *restrict p_from, packet_t *restrict p_to, const size_t size)
{
	READCHECK(p_from, size);

	int err = packet_w(p_to, p_from->data + p_from->index, size);
	if (err) return err;
	p_from->index += size;
	return 0;
}
