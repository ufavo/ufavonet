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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

#include "../include/packet.h"

#define ceil_int_division(A,B) ((A + (B-1)) / B)

#if __BIG_ENDIAN__
# define htonll(x) (x)
# define ntohll(x) (x)
#else
# define htonll(x) (((uint64_t)htonl((x) & 0xFFFFFFFF) << 32) | htonl((x) >> 32))
# define ntohll(x) (((uint64_t)ntohl((x) & 0xFFFFFFFF) << 32) | ntohl((x) >> 32))
#endif


#define NULLCHECK(packet_ptr) if ((packet_ptr) == NULL) { return EPACKET_ERR_NULL; }
/* index is always one position ahead, so instead subtracting one in the comparision below, we just check if it's greater then */
#define READCHECK(packet_ptr,size) if ((packet_ptr)->index + size > (packet_ptr)->length) { return EPACKET_ERR_OUT_OF_BOUNDS; }
#define WRITECHECK(packet_ptr,sz) if ((packet_ptr)->index + sz >= (packet_ptr)->size && (packet_ptr)->realloc_allowed == 0) { return EPACKET_ERR_OUT_OF_BOUNDS; }


struct packet
{
	uint32_t	index;
	uint8_t 	*data;
	size_t		size;
	uint32_t 	length;
	uint8_t 	realloc_allowed;

	uint8_t 	*bits_byte;
	int 		bits_index;
}; 

packet_t *
packet_init(void)
{
	packet_t *p = malloc(sizeof(packet_t));
	if (p == NULL) {
		return NULL;
	}
	p->data = NULL;
	p->size = 0;
	p->index = 0;
	p->length = 0;
	p->realloc_allowed = 1;
	p->bits_byte = NULL;
	p->bits_index = 0;
	return p;
}

packet_t *
packet_init_from_buff(void *buff, const size_t size)
{
	packet_t *p = packet_init();
	if (p == NULL) {
		return NULL;
	}
	p->data = buff;
	p->size = size;
	p->realloc_allowed = 0;
	return p;
}

packet_t *
packet_init_from_buffcpy(const void *buff, const size_t size)
{
	packet_t *p = packet_init();
	if (p == NULL) {
		return NULL;
	}
	p->data = malloc(size);
	if (p->data == NULL) {
		free(p);
		return NULL;
	}
	memcpy(p->data, buff, size);
	p->size = size;
	p->realloc_allowed = 1;
	return p;
}

int
packet_free(packet_t **p)
{
	NULLCHECK(p);
	NULLCHECK(*p);
	if ((*p)->realloc_allowed == 1) {
		free((*p)->data);
	}
	free(*p);
	*p = NULL;
	return 0;
}

int
packet_rewind(packet_t *p)
{
	NULLCHECK(p)
	p->index = 0;
	p->bits_byte = NULL;
	p->bits_index = 0;

	return 0;
}

uint32_t
packet_get_length(packet_t *p)
{
	NULLCHECK(p);
	return p->length;
}

size_t
packet_get_buffsize(packet_t *p)
{
	NULLCHECK(p);
	return p->size;
}

void *
packet_get_buff(packet_t *p)
{
	if (p == NULL)
		return NULL;
	return p->data;
}

int
packet_set_length(packet_t *p, const uint32_t value)
{
	NULLCHECK(p);
	if (value > p->size) {
		return EPACKET_ERR_OUT_OF_BOUNDS;
	}
	p->length = value;
	return 0;
}

uint32_t
packet_get_readable(packet_t *p)
{
	NULLCHECK(p);
	return (p->index >= p->length) ? (p->bits_index < 8 && p->bits_byte != NULL ? 1 : 0) : p->length - p->index; 
}

int
packet_w(packet_t *p, const void *ptr, const size_t size)
{
	NULLCHECK(p);

	if(p->data) {
		if(p->size <= p->index + size) {
			if (p->realloc_allowed == 1) {
				p->size += PACKET_ALLOC_SIZE * ceil_int_division(size, PACKET_ALLOC_SIZE);
				void *rallc = realloc(p->data, p->size);
				if (rallc == NULL) {
					free(p->data);
					p->index = 0;
					p->length = 0;
					p->size = 0;
					p->data = NULL;
					return EPACKET_ERR_OUT_OF_MEMORY;
				}
				p->data = rallc;
			} else {
				return EPACKET_ERR_OUT_OF_BOUNDS;
			}
		} 
	} else if (p->realloc_allowed == 1) {
		p->size = PACKET_ALLOC_SIZE * ceil_int_division(size, PACKET_ALLOC_SIZE);
		p->data = malloc(p->size);
		if (p->data == NULL) {
			p->size = 0;
			return EPACKET_ERR_OUT_OF_MEMORY;
		}
		p->index = 0;
	} else {
		return EPACKET_ERR_OUT_OF_BOUNDS;
	}
	memcpy(p->data + p->index, ptr, size);
	p->index += size;
	p->length = p->index;
	return 0;
}


int
packet_w_64_t(packet_t *p, const void *ptr)
{
	int64_t ivalue = htonll(*((int64_t*)ptr));
	return packet_w(p, &ivalue, sizeof(int64_t));
}

int
packet_w_32_t(packet_t *p, const void *ptr)
{
	int32_t ivalue = htonl(*((int32_t*)ptr));
	return packet_w(p, &ivalue, sizeof(int32_t));
}

int
packet_w_16_t(packet_t *p, const void *ptr)
{
	int16_t ivalue = htons(*(int16_t*)ptr);
	return packet_w(p, &ivalue, sizeof(int16_t));
}

int
packet_w_8_t(packet_t *p, const void *ptr)
{
	return packet_w(p, ptr, sizeof(int8_t));
}

int
packet_w_bits(packet_t *p, const uint8_t src, const int n)
{
	NULLCHECK(p);

	uint16_t 	masked;
	uint8_t 	t;
	int err = 0;
	if (p->bits_byte == NULL) {
		t = 0;
		err = packet_w_8_t(p, &t);
		if(err > 0) {
			return err;
		}
		p->bits_byte = p->data + p->index - 1;
		p->bits_index = 0;
	} else if (p->bits_index + n > 8) {
		WRITECHECK(p, 1);
	}

	masked = (src & (0xFF >> (8-n)));
	*p->bits_byte |= masked << p->bits_index;

	p->bits_index += n;
	if (p->bits_index > 8) {
		/* needs another byte to fully store src */
		t = 0;
		err = packet_w_8_t(p, &t);
		if(err > 0) {
			return err;
		}
		p->bits_byte = p->data + p->index - 1;

		p->bits_index -= 8;
		*p->bits_byte |= masked >> (n - p->bits_index);
	} else if (p->bits_index == 8) {
		p->bits_byte = NULL;
		p->bits_index = 0;
	}
	return 0;
}

int
packet_r_bits(packet_t *p, uint8_t *ptr, const int n)
{
	NULLCHECK(p);
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

int
packet_w_vlen29(packet_t *p, const uint32_t value)
{
	NULLCHECK(p);

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

int
packet_r(packet_t *p, void *ptr, const size_t size)
{
	NULLCHECK(p);
	READCHECK(p, size);
    memcpy(ptr, p->data + p->index, size);
    p->index += size;
	return 0;
}

int
packet_r_64_t(packet_t *p, void *ptr)
{
	NULLCHECK(p);
	READCHECK(p, sizeof(int64_t));
	int64_t result = (int64_t)ntohll(*(int64_t *)(p->data + p->index));
	memcpy(ptr, &result, sizeof(int64_t)); 
	p->index += sizeof(int64_t);
	return 0;
}

int
packet_r_32_t(packet_t *p, void *ptr)
{
	NULLCHECK(p);
	READCHECK(p, sizeof(int32_t));
	int32_t result = (int32_t)ntohl(*(int32_t *)(p->data + p->index));
	memcpy(ptr, &result, sizeof(int32_t)); 
	p->index += sizeof(int32_t);
	return 0;
}

int
packet_r_16_t(packet_t *p, void *ptr)
{
	NULLCHECK(p);
	READCHECK(p, sizeof(int16_t));
	int16_t result = (int16_t)ntohs(*(int16_t *)(p->data + p->index));
	memcpy(ptr, &result, sizeof(int16_t)); 
	p->index += sizeof(int16_t);
	return 0;
}

int
packet_r_8_t(packet_t *p, void *ptr)
{
	return packet_r(p, ptr, sizeof(uint8_t));
}

int
packet_r_vlen29(packet_t *p, uint32_t *ptr)
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
