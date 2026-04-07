/*
 * Network messaging implementation.
 * Copyright (C) 2026  Luiz Gustavo Sassanovicz Borsoi
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
#include <string.h>

#include "_hooks.h"
#include "netmsg.h"

/*
 * Message structure (msg):
 * [vlen:size][payload]
 *
 * Group structure (group):
 * [u8:group_id][msg 0][...][msg N][u8:\0]
 *
 * Acknowledgement structure (ackgroup):
 * [u8:group_id_inclusive_range_start][u8:count]
 *
 * Netmsg structure:
 * [bit:has_ack][ackgroup][bit:has_msg][u8:group_cnt][group 0][...][group N]
 *
 */

inline int32_t
netmsg_init(netmsg_ctx_t *restrict ctx, uint32_t prealloc_packet_bytes)
{
	memset(ctx, 0, sizeof(*ctx));
	
	ctx->pkt = prealloc_packet_bytes? packet_init_prealloc(prealloc_packet_bytes) : packet_init();
	if (!ctx->pkt) return 0;	

	return 1;
}

inline void
netmsg_reset(netmsg_ctx_t *restrict ctx)
{
	packet_t *pkt = ctx->pkt;
	memset(ctx, 0, sizeof(*ctx));

	ctx->pkt = pkt;
	packet_rewind(ctx->pkt);
	packet_set_length(ctx->pkt, 0);
}

inline void
netmsg_deinit(netmsg_ctx_t *restrict ctx)
{
	packet_free(&ctx->pkt);
}


inline int32_t
netmsg_pack(netmsg_ctx_t *restrict ctx, packet_t *restrict p, uint8_t round_trip_ticks)
{
	int err;
	
	const uint8_t has_ack = ctx->acknowledged_count > 0 && ctx->needs_to_send_ack;
	const uint8_t has_msg = packet_get_length(ctx->pkt) > 0;

	// Wait for the round-trip time to avoid unneeded retransmission.
	if (ctx->pack_cooldown_ticks++ >= round_trip_ticks) {
		ctx->pack_cooldown_ticks = 0;
	} else {
		ulogf_dbg("Didn't pack due to cooldown");
		ctx->pack_cooldown_ticks++;
		err = packet_w_bits(p, 0, 2);
		if (err) return -err;
		return ENETMSG_ERR_NONE;
	}

	ulogf_dbg("Has ack: %c. Has msg: %c.", has_ack? 'y' : 'n', has_msg? 'y' : 'n');
	// Write acknowledgements
	err = packet_w_bits(p, has_ack, 1);
	if (err) return -err;
	if (has_ack) {
		err = packet_w_8_t(p, &ctx->acknowledged_id_start);
		if (err) return -err;
	
		uint8_t ackcnt = ctx->acknowledged_count - 1;
		err = packet_w_8_t(p, &ackcnt);
		if (err) return -err;

		ulogf_dbg("ACK'ed range. From: %" PRIu8" To: %" PRIu8, ctx->acknowledged_id_start, (uint8_t)(ctx->acknowledged_id_start+(ctx->acknowledged_count-1)));
		ctx->needs_to_send_ack = 0;
	}

	// Write messages
	err = packet_w_bits(p, has_msg, 1);
	if (err) return -err;

	if (!has_msg) return ENETMSG_ERR_NONE;

	uint8_t gcnt = ctx->pack_cnt;
	uint32_t length = packet_get_length(ctx->pkt);

	if (ctx->pack_cnt == NETMSG_MAX_SEND_PACK_CNT)
		ctx->pkt_length_at_max_send_pack = length + (ctx->has_new_msg? 1 : 0);

	if (ctx->pack_cnt > NETMSG_MAX_SEND_PACK_CNT) {
		// New messages will keep piling up on the same group until at least one previous group is ack'ed.
		gcnt = NETMSG_MAX_SEND_PACK_CNT;
		length = ctx->pkt_length_at_max_send_pack;
	} else {
		// Write terminator to the latest group to indicate its end
		if (ctx->has_new_msg) {
			ctx->has_new_msg = 0;
			uint8_t zero = 0;
			err = packet_w_8_t(ctx->pkt, &zero);
			if (err) return -err;
			length++;
		}
	}

	// Write group count
	err = packet_w_8_t(p, &gcnt);
	if (err) return -err;


	packet_rewind(ctx->pkt);
	
	err = packet_rw_packet(ctx->pkt, p, length);
	if (err) return -err;

	// length may be smaller due to max_send_pack_cnt.
	// make sure index is at the end
	packet_set_index(ctx->pkt, packet_get_length(ctx->pkt));

	ulogf_dbg("Packed %" PRIu8 " groups", gcnt);
	return ENETMSG_ERR_NONE;
}

/* This function assumes that the first byte (gid) is already consumed. */
static inline int32_t
pkt_unpack_group_skip(packet_t *restrict p)
{
	int err;
	do {
		uint32_t len;
		err = packet_r_vlen29(p, &len);
		if (err) return ENETMSG_ERR_INVALID;

		err = packet_skip(p, len);
		if (err) return ENETMSG_ERR_INVALID;

		// peek to check for group end
		uint32_t idx = packet_get_index(p);
		uint8_t tmp = 0;
		err = packet_r_8_t(p, &tmp);
		if (err != EPACKET_ERR_OUT_OF_BOUNDS && err)
			return ENETMSG_ERR_INVALID;
		if (!tmp) break;
		packet_set_index(p, idx);
	} while (1);

	return ENETMSG_ERR_NONE;
}

static inline int32_t
pkt_unpack_ackgroup(netmsg_ctx_t *restrict ctx, packet_t *restrict p)
{
	int err;
	uint8_t start, count;
	err = packet_r_8_t(p, &start);
	if (err) 	return -err;
	err = packet_r_8_t(p, &count);
	if (err) 	return -err;

	ulogf_dbg("Ack group range. From: %" PRIu8 " To: %" PRIu8, start, (uint8_t)start+count);

	if (count+1 > NETMSG_MAX_SEND_PACK_CNT) return ENETMSG_ERR_INVALID;

	if (ctx->pack_cnt == 0) return ENETMSG_ERR_NONE;

	packet_rewind(ctx->pkt);

	uint8_t i, found;
	for (i = found = 0; i <= count; i++) {
		uint8_t gid;
		err = packet_r_8_t(ctx->pkt, &gid);
		if (err) return -err;

		if (gid != (uint8_t)(start + i)) {
			// case 1: found at least one but ACK'ed a gid that was never sent.
			if (found) {
				ulogf_inf("Sender ACK'ed a gid that was never sent.");
				return ENETMSG_ERR_INVALID;
			}
			// case 2: ACK'ed a recently sent high value gid e.g 254
			if (gid < (uint8_t)(start + i)) {
				packet_rewind(ctx->pkt);
				continue;
			}
			// case 3: gid possibly already ack'ed previously (allow a small window)
			if (gid > start && gid - start <= (NETMSG_MAX_SEND_PACK_CNT / 2))
				continue;
			ulogf_inf("Sender ACK'ed an out of order gid that was never sent.");
			return ENETMSG_ERR_INVALID;
		}
		found = 1;
	
		// Skip group
		pkt_unpack_group_skip(ctx->pkt);
		ctx->pack_cnt--;

		if (packet_get_readable(ctx->pkt) == 0) {
			if (i == count) break;
		}
	}
	if (!found) return ENETMSG_ERR_NONE;

	// remove acknowledged payload from the pending packet
	uint8_t *pktstart = packet_get_buff(ctx->pkt);
	uint32_t pkt_idx = packet_get_index(ctx->pkt);
	uint32_t pkt_length = packet_get_length(ctx->pkt);
	pkt_length -= pkt_idx;

	ulogf_dbg("Removing acked payload. New queue length: %" PRIu32 " (-%" PRIi64")", pkt_length, packet_get_length(ctx->pkt) - (int64_t)pkt_length);

	memmove(pktstart, pktstart + pkt_idx, pkt_length);
	packet_set_length(ctx->pkt, pkt_length);
	packet_set_index(ctx->pkt, pkt_length);

	return ENETMSG_ERR_NONE;
}


inline int32_t
netmsg_unpack_next(netmsg_ctx_t *restrict ctx, packet_t *restrict p, void **out, uint32_t *out_size)
{
	int err = 0;

	*out = NULL;
	*out_size = 0;

	if (!ctx->unpack_cnt) {
		uint8_t hasmsg = 0;

		// check if acknowledgements are present
		err = packet_r_bits(p, &hasmsg, 1);
		if (err) 		return -err;
		if (hasmsg) {
			// handle acknowledged group range
			err = pkt_unpack_ackgroup(ctx, p);
			if (err) return err;
		}

		// check if messages are present
		err = packet_r_bits(p, &hasmsg, 1);
		if (err) 		return -err;
		if (!hasmsg) return ENETMSG_ERR_NONE;

		err = packet_r_8_t(p, &ctx->unpack_cnt);
		if (err) {
			ctx->unpack_cnt = 0;
			return -1;
		}

		if (ctx->unpack_cnt > NETMSG_MAX_SEND_PACK_CNT) return ENETMSG_ERR_INVALID;

		ulogf_dbg("Unpacking msg with %d groups", ctx->unpack_cnt);

		// force pack on the next pack call
		ctx->pack_cooldown_ticks = UINT8_MAX;
		ctx->needs_to_send_ack = 1;

		// Read first gid
		err = packet_r_8_t(p, &hasmsg);
		if (err) return ENETMSG_ERR_INVALID;

		const uint8_t already_acked = ctx->acknowledged_id_start + (ctx->acknowledged_count - 1);
		const uint8_t ackidstart = hasmsg;

		// Ignore already acknowledged messages
		if (ctx->acknowledged_count > 0) {
			uint8_t ackcnt = 0;

			do {
				const int32_t diff = (int32_t)hasmsg - already_acked;
				const int32_t apply = (diff < 128 && diff > 0) || (diff < -128);
				if (!apply) {
					ulogf_dbg("Skip gid: %d", (int)hasmsg);
					err = pkt_unpack_group_skip(p);
					if (err) {
						ulogf_err("Failed attempt to skip gid: %d", (int)hasmsg);
						ctx->unpack_cnt = 0;
						return err;
					}
					ackcnt++;
					if (--ctx->unpack_cnt == 0) return ENETMSG_ERR_NONE;
					// Read next gid
					err = packet_r_8_t(p, &hasmsg);
					if (err) return -err;
				} else break;
			} while (1);
			ctx->acknowledged_id_start = ackidstart;
			ctx->acknowledged_count = ackcnt;
		}
		ctx->acknowledged_count++;
	}

	// Read the next message
	err = packet_r_vlen29(p, out_size);
	if (err) return -err;
	*out = ((uint8_t *)packet_get_buff(p)) + packet_get_index(p);
	err = packet_skip(p, *out_size);
	if (err) {
		*out = NULL;
		return -err;
	}
	ulogf_dbg("Got msg of size: %" PRIu32, *out_size);

	// peek to check if there are more messages in the current group
	const uint32_t idx = packet_get_index(p);
	uint8_t tmp;
	err = packet_r_8_t(p, &tmp);
	if (err) return -err;

	if (tmp) {
		// is a message. undo peek
		packet_set_index(p, idx);
		return ENETMSG_ERR_NONE_AGAIN;
	}

	if (--ctx->unpack_cnt == 0) {
		ulogf_dbg("Successfuly unpacked all message groups");
		return ENETMSG_ERR_NONE;
	}

	// Read next gid
	err = packet_r_8_t(p, &tmp);
	if (err) return -err;

	// check if it's within expected
	if (tmp != (uint8_t)(ctx->acknowledged_id_start + ctx->acknowledged_count)) {
		ulogf_dbg("Unpacked ack gid differs from expected. Got: %d; Expected: %d;\n", (int)tmp, (int)(uint8_t)(ctx->acknowledged_id_start + ctx->acknowledged_count));
		return ENETMSG_ERR_INVALID;
	}

	ctx->acknowledged_count++;

	return ENETMSG_ERR_NONE_AGAIN;
}

inline int32_t
netmsg_enqueue(netmsg_ctx_t *restrict ctx, const void *data, const uint32_t size)
{
	if (!data && size) {
		ulogf_crt("Attempting to enqueue message of size %"PRIu32" that points to NULL", size);
		return -1;
	}

	int err;
	if (!ctx->has_new_msg) {
		err = packet_w_8_t(ctx->pkt, &ctx->next_available_pack_id);
		if (err) return -err;
		ctx->next_available_pack_id++;
		ctx->has_new_msg = 1;
		ctx->pack_cnt++;
	}

	err = packet_w_vlen29(ctx->pkt, size);
	if (err) return -err;
	err += packet_w(ctx->pkt, data, size);
	if (err) return -err;

	// force pack on the next pack call
	ctx->pack_cooldown_ticks = UINT8_MAX;

	return ctx->next_available_pack_id;
}
