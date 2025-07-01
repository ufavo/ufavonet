/*
 * Packet interface.
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

#ifndef __UFAVONET_PACKET_HEADER__
#define __UFAVONET_PACKET_HEADER__

#define PACKET_ALLOC_SIZE 256

typedef struct packet packet_t;

enum packeterr
{
	EPACKET_ERR_NONE = 0,
	/* Writing: not enough space in buffer. (initialized with `packet_init_from_buf`?).
	 * Reading: trying to read past the length of data available in the buffer. */
	EPACKET_ERR_OUT_OF_BOUNDS, //EOf
	/* `packet_t` ptr is null */
	EPACKET_ERR_NULL,
	/* Out of memory. Memory allocation failed. */
	EPACKET_ERR_OUT_OF_MEMORY,
};

/* Initialize a empty packet.
 * Returns `NULL` if memory allocation fails. */
packet_t *packet_init(void);
/* Initialize a packet that points to `buff` of `size`. 
 * The resulting packet is unable to grow.
 * Returns `NULL` if memory allocation fails. */
packet_t *packet_init_from_buff(void *buff, const size_t size);
/* Initialize a packet with a copy of `size` bytes from `buff`.
 * The resulting packet can grow as normal.
 * Returns `NULL` if memory allocation fails. */
packet_t *packet_init_from_buffcpy(const void *buff, const size_t size);

int packet_free(packet_t **p);
/* Rewind a given packet, making it possible to reread or overwrite it. */
int packet_rewind(packet_t *p);


/* Returns `0` if `p` is `NULL`. Otherwise returns how much readable data this packet contains, in bytes. */
uint32_t packet_get_length(packet_t *p);
/* Returns `0` if `p` is `NULL`. Otherwise returns the size of the internal buffer. */
size_t packet_get_buffsize(packet_t *p);
/* Returns `NULL` if `p` is `NULL`. Otherwise returns the pointer to the internal buffer. */
void *packet_get_buff(packet_t *p);
/* Sets the internal buffer pointer to `buff` of `size` and rewinds the packet.
 * Passing `NULL` to `buff` resets the packet, as if it was just initialized with `packet_init`.
 * Returns `enum packeterr` error code. */
int packet_set_buff(packet_t *p, void *buff, const size_t size);
/* Returns `0` if `p` is `NULL`. Otherwise returns the internal buffer index */
uint32_t packet_get_index(packet_t *p);
/* Sets how much readable data this packet contains, in bytes.
 * `value` cannot exceed buffer size. 
 * Returns `enum packeterr` error code. */
int packet_set_length(packet_t *p, const uint32_t value);
/* Sets the size of the internal buffer.
 * This function do nothing but set the internal buffer size. 
 * It should be used only if the buffer size has changed and there is a need to do so.
 * If the size is smaller then before, data loss may occour.
 * Returns `EPACKET_ERR_NOT_ALLOWED` if the packet was not initialized with `packet_init_from_buff`. */
int packet_set_size(packet_t *p, const size_t size);
/* Returns `0` if `p` is `NULL`. Otherwise returns the amount of data available for reading, in bytes. */
uint32_t packet_get_readable(packet_t *p);
/* Returns the number of write operations performed on the packet since the last rewind/init */
uint32_t packet_get_write_op_count(packet_t *p);


/* Adds `size` bytes from `ptr` to `p`.
 * Returns `enum packeterr` error code. */
int packet_w(packet_t *p, const void *ptr, const size_t size);
/* Adds 8 bytes from `ptr` to `p`.
 * `packet_r_64_t` should be used for reading. 
 * Returns `enum packeterr` error code. */
int packet_w_64_t(packet_t *p, const void *ptr);
/* Adds 4 bytes from `ptr` to `p`.
 *`packet_r_32_t` should be used for reading.
 * Returns `enum packeterr` error code. */
int packet_w_32_t(packet_t *p, const void *ptr);
/* Adds 2 bytes from `ptr` to `p`.
 *`packet_r_16_t` should be used for reading.
 * Returns `enum packeterr` error code. */
int packet_w_16_t(packet_t *p, const void *ptr);
/* Adds 1 byte from `ptr` to `p`.
 *`packet_r_8_t` or `packet_r` should be used for reading.
 * Returns `enum packeterr` error code. */
int packet_w_8_t(packet_t *p, const void *ptr);
/* Adds `n` bits from `src` to `p`.
 * `n` ranges from 1 to 8.
 * `packet_r_bits` should be used for reading.
 * Returns `enum packeterr` error code. */
int packet_w_bits(packet_t *p, const uint8_t src, const int n);
/* Adds `value` to `p` using variable length encoding.
 * This function is not suitable for floating point variables.
 * `value` cannot be bigger than 29bits.
 * `packet_r_vlen29` should be used for reading.
 * Returns `enum packeterr` error code. */
int packet_w_vlen29(packet_t *p, const uint32_t value);

/* Returns `enum packeterr` error code. */
int packet_r(packet_t *p, void *ptr, const size_t size);
/* Returns `enum packeterr` error code. */
int packet_r_64_t(packet_t *p, void *ptr);
/* Returns `enum packeterr` error code. */
int packet_r_32_t(packet_t *p, void *ptr);
/* Returns `enum packeterr` error code. */
int packet_r_16_t(packet_t *p, void *ptr);
/* Returns `enum packeterr` error code. */
int packet_r_8_t(packet_t *p, void *ptr);
/* Returns `enum packeterr` error code. */
int packet_r_bits(packet_t *p, uint8_t *ptr, const int n);
/* Returns `enum packeterr` error code. */
int packet_r_vlen29(packet_t *p, uint32_t *ptr);

/* Reads `size` bytes from packet `p_from` to packet `p_to` 
 * Returns `enum packeterr` error code. */
int packet_rw_packet(packet_t *p_from, packet_t *p_to, const size_t size);
/* Returns `enum packeterr` error code. */
int packet_skip(packet_t *p, const size_t size);
/* Returns `enum packeterr` error code. */
int packet_skip_bits(packet_t *p, const int n);
/* Returns `enum packeterr` error code. */
int packet_skip_vlen29(packet_t *p);

#endif
