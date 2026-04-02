/*
 * Networking implementation.
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

#include "utime.h"
#include "_packet.h"

#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "_hooks.h"
#include "usocket.c"
#include "netmsg.h"
#include "_crypto.h"
#include "handshake.h"
#include "../modules/uthash/src/uthash.h"
#include "../include/net.h"
#include "_net.h"
#include "netfrag.h"

static const uint16_t _mtuv[] = {576-28,600-28,800-28,900-28,1000-28,1100-28,1280-28,1400-28,1420-28,1492-28,1500-28,1530-28,1600-28,2000-28,4096-28,7935-28,8000-28,9000-28,9216-28,12288-28,16384-28,65535-28};//
#define MTUV_LENGTH ((uint8_t)(sizeof(_mtuv) / sizeof(*_mtuv)))

/* struct that holds common data */
struct conncommon {
	conn_header_t remote;
	uint16_t 	tick_local_noresp_count;
	uint16_t 	tick_local;
	uint16_t 	tick_remote_latest;
	uint16_t 	send_skip_count;

	uint8_t 	status;
	uint8_t 	disconnect_reason;
	uint8_t 	handshake_status;
	uint8_t 	round_trip_flag_expected;
	uint8_t 	round_trip_counter;
	uint8_t 	round_trip_ticks;
	float 		round_trip_ticks_ema;

	uint16_t 	mtu;
	uint16_t 	mtu_local_max;
	uint8_t 	mtu_idx;
	uint8_t 	mtu_interleave_flag;
	uint8_t 	mtu_status;
	uint16_t 	mtu_reply_retention;
	uint16_t 	mtu_cooldown_ticks;

	netmsg_ctx_t 		msgctx;
	crypto_ctx_t 		crypto;
	netfrag_multibuilder_t 	fragbuilder;
};

/* struct that represents a client in the server */
struct srvclient {
	struct conncommon 	common;
	usocket_addr_t 		sockaddr;
	void 				*userdata;

	/* Hash table stuff */
	uint64_t 		id;
	UT_hash_handle 	hh;
};

/* struct that holds data needed by a client */
struct cliconn {
	struct clievents 	events;
	struct conncommon 	common;
	handshake_t 		handshake;
	uint8_t 			srv_public_key[crypto_box_PUBLICKEYBYTES];
};

/* struct that holds data needed by a server */
struct srvconn {
	uint_fast8_t 		is_closing;
	struct srvevents 	events;
	struct srvclient 	*connected_clients;
	crypto_keypair_t 	keypair;
};

/* struct that represents a connection, be it a server or a client. */
struct netconn {
	uint16_t 			tick_local;
	uint8_t 			type;
	uint16_t 			tick_underrun_count; //> Prevents log spam
	utime_t 			timing;
	int_fast64_t 		tick_time_margin_us;
	int_fast64_t 		tick_time_target_us;
	int_fast64_t 		tick_time_underrun_us;
	
	struct netstats 	stats;
	struct netsettings 	settings;
	float 				rtt_ema_alpha;
	
	const uint8_t 		*secure_ciphers;
	
	usocket_t 			udp_sock;

	union {
		struct srvconn 	srv;
		struct cliconn 	cli;
	} data;

	void 				*userdata;

	packet_t 			*in_packet;
	packet_t 			*out_packet;
	packet_t 			*payload_packet;
	uint8_t 			in_buffer[65535];
	uint8_t 			out_buffer[65535];
};

static inline float
ema(float alpha, float late_ema, float sample)
{
	return (sample * alpha) + (late_ema * (1.0f - alpha));
}

static inline float
ema_alpha(float n)
{
	return 2.0f / (n + 1.0f);
}

/* a given tick is valid if (tick > last tick) && (tick <= expected + margin && tick >= expected - margin)  */
static inline int
tick_remote_applicable(uint16_t received, uint16_t last_applied, uint16_t expected, uint16_t margin)
{
	int32_t diff  = received - expected;
	int32_t diff1 = received - last_applied;

	if (diff > 32768)		 diff  -= 65536;
	else if (diff < -32768)	 diff  += 65536;

	if (diff1 > 32768)		 diff1 -= 65536;
	else if (diff1 < -32768) diff1 += 65536;

	return ((diff < 0 ? -diff : diff) <= (margin) && diff1 >= 0);
}

static inline uint8_t
_conn_outpkt_header_mtu_status(struct conncommon *restrict c)
{
	uint8_t status = c->status;
	if (status == EPROT_STATUS_CONNECTED) {
		status = c->remote.mtu_reply && c->mtu_interleave_flag? EPROT_STATUS_CONNECTED_MTU_DISCOVERY_REPLY_DISCOVERY : 
				(c->remote.mtu_reply? EPROT_STATUS_CONNECTED_MTU_DISCOVERY_REPLY :
				(c->mtu_interleave_flag? EPROT_STATUS_CONNECTED_MTU_DISCOVERY : status));
	}
	return status;
}

#define PROTO_HEADER_SIZE(status) ((status) == EPROT_STATUS_CONNECTED_MTU_DISCOVERY_REPLY_DISCOVERY || (status) == EPROT_STATUS_CONNECTED_MTU_DISCOVERY_REPLY? 6 : 4)
#define PROTO_HEADER_FRAG_SIZE 3

static inline void
_conn_mtu_send_prepass(netconn_t *restrict conn, struct conncommon *restrict c)
{
	/* mtu discovery / reply */
	/* detect loss and attempt mtu drop */
	if (c->mtu_status == EMTU_STATUS_OK && (c->remote.frag_shared.noresp > 4 || c->tick_local_noresp_count > 4)) {
		if (c->mtu_idx > 0) {
			c->mtu = _mtuv[--c->mtu_idx];
			ulogf_ntc("Packet loss. Dropping MTU guess from %"PRIu16" to %"PRIu16, _mtuv[c->mtu_idx+1], _mtuv[c->mtu_idx]);
			c->mtu_status = EMTU_STATUS_DISCOVERY_DOWN;
			c->mtu_interleave_flag = UINT8_MAX;
			c->mtu_cooldown_ticks = 0;
		}
	}
	
	if (c->status != EPROT_STATUS_CONNECTED)
		return;

	if (c->mtu_status == EMTU_STATUS_OK && c->mtu_cooldown_ticks >= conn->settings.tick_rate)
		return;

	if (c->remote.mtu != c->mtu && c->remote.mtu) {
		/* other party is receiving. found mtu? try going up on next ticks */
		c->mtu = c->remote.mtu;
		c->remote.mtu = 0;
		ulogf_dbg("Received MTU: %"PRIu16, c->mtu);
		if (c->mtu_status == EMTU_STATUS_DISCOVERY_DOWN) {
			c->mtu_status = EMTU_STATUS_DISCOVERY_UP;
			c->mtu_cooldown_ticks = 0;
		} else if (_mtuv[MTUV_LENGTH-1] == c->mtu) {
			/* reached maximum mtu */
			c->mtu_cooldown_ticks = conn->settings.tick_rate - 1;
			ulogf_dbg("Advertised maximum MTU: %"PRIu16", currently at %"PRIu16, _mtuv[c->mtu_idx], c->mtu);
			c->mtu_status = EMTU_STATUS_OK;
		} else if (c->mtu >= _mtuv[c->mtu_idx]) {
			/* avoid further advertising of this mtu */
			c->mtu_cooldown_ticks = 0;
			while (c->mtu_idx < MTUV_LENGTH-1 && c->mtu >= _mtuv[c->mtu_idx])
				c->mtu_idx++;
			ulogf_inf("MTU Discovery: %"PRIu16, _mtuv[c->mtu_idx]);
		}
	}
	
	if (c->mtu_status == EMTU_STATUS_OK && c->mtu_cooldown_ticks < conn->settings.tick_rate) {
		c->mtu_cooldown_ticks++;
		if (c->mtu_cooldown_ticks == conn->settings.tick_rate) {
			while (_mtuv[c->mtu_idx] > c->mtu && c->mtu_idx) c->mtu_idx--;
			ulogf_inf("MTU Discovery complete. MTU: %"PRIu16, c->mtu);
		}
		return;
	}

	if (c->mtu_status == EMTU_STATUS_DISCOVERY_UP) {
		/* send 0.25s worth of samples, interleaved to avoid 100% loss when reaching the path mtu (each step up takes twice the amount of samples) */
		if (c->mtu_cooldown_ticks >= conn->settings.tick_rate / 4) {
			c->mtu_cooldown_ticks = 0;
			if (c->mtu_idx < MTUV_LENGTH-1 && _mtuv[c->mtu_idx] < c->mtu_local_max) {
				c->mtu_idx++;
			} else {
				/* reached maximum mtu */
				ulogf_inf("Advertised MTU: %"PRIu16", currently at %"PRIu16, _mtuv[c->mtu_idx], c->mtu);
				c->mtu_status = EMTU_STATUS_OK;
				return;
			}
			ulogf_inf("MTU Discovery: %"PRIu16, _mtuv[c->mtu_idx]);
		}
	}
}

static inline int
_conn_mtu_send_pass(netconn_t *restrict conn, struct conncommon *restrict c, int64_t header_overhead, size_t *restrict out_mtu)
{
	*out_mtu = c->mtu;
	
	if (c->mtu_status != EMTU_STATUS_DISCOVERY_UP || c->status != EPROT_STATUS_CONNECTED)
		return EFRAG_FLAG_NONE;

	if (!c->mtu_interleave_flag) {
		c->mtu_interleave_flag = ~c->mtu_interleave_flag;
		return EFRAG_FLAG_NONE;
	}

	*out_mtu = _mtuv[c->mtu_idx];

	c->mtu_cooldown_ticks++;
	c->mtu_interleave_flag = ~c->mtu_interleave_flag;
	
	/* pad with zeroes if there is not enough data */
	int mtu_padding = (int64_t)_mtuv[c->mtu_idx] - (int64_t)(conn->payload_packet->length + header_overhead);
	if (mtu_padding > 0) {
		conn->payload_packet->index = conn->payload_packet->length;
		void *out;
		packet_w_deferred(conn->payload_packet, mtu_padding, &out);
		memset(out, 0, mtu_padding);
		memset(out, 1, 1);
		packet_rewind(conn->payload_packet);
		ulogf_dbg("MTU Discovery added padding: %d bytes", mtu_padding);
		return EFRAG_FLAG_NONE;
	}

	/* doing discovery but dont have enough space for the padding flag byte */
	ulogf_dbg("MTU Discovery requires fragmentation");
	return EFRAG_FLAG_FIRST;
}

static inline int
_mtu_rm_padding_from_pkt(packet_t *restrict pkt)
{
	int64_t i = pkt->length - 1;
	while (pkt->data[i] == 0 && i > 0) i--;
	if (pkt->data[i] != 1) return 0;
	pkt->length = i;
	return 1;
}

static inline int
_conn_udp_send(netconn_t *restrict conn, usocket_addr_t *restrict addr)
{
	size_t length = packet_get_length(conn->out_packet);
	if (usock_udp_send(&conn->udp_sock, addr, conn->out_buffer, length)) {
		conn->stats.total_sent_bytes += length;
		return 1;
	}
	return 0;
}

static inline void
_conn_prepare_outpkt(netconn_t *restrict conn, struct conncommon *restrict c, uint8_t status, uint8_t frag_flag, uint8_t secure, int32_t first_diff)
{
	packet_rewind(conn->out_packet);
	packet_w_16_t(conn->out_packet, &conn->tick_local);

	packet_w_bits(conn->out_packet, frag_flag, EFRAG_FLAG_SIZE_BITS);
	ulogf_dbg("Write frag flag: %"PRIu8, frag_flag);
	if (frag_flag == EFRAG_FLAG_MIDDLE || frag_flag == EFRAG_FLAG_LAST) {
		assert_dbg(conn->out_packet->length == PROTO_HEADER_FRAG_SIZE);
		packet_w_bits(conn->out_packet, first_diff, 8 - EFRAG_FLAG_SIZE_BITS);
		return;
	}

	const int noresp_max = (0xFF >> EFRAG_FLAG_SIZE_BITS);
	packet_w_bits(conn->out_packet, c->tick_local_noresp_count > noresp_max? noresp_max : c->tick_local_noresp_count, 8 - EFRAG_FLAG_SIZE_BITS);

	ulogf_dbg("Write status: %"PRIu8, status);
	packet_w_bits(conn->out_packet, status, EPROT_STATUS_SIZE);
	packet_w_bits(conn->out_packet, c->round_trip_flag_expected, 1);
	packet_w_bits(conn->out_packet, c->remote.round_trip_flag_echo, 1);
	packet_w_bits(conn->out_packet, secure, 2);

	/* write mtu discovery reply */
	if (status == EPROT_STATUS_CONNECTED_MTU_DISCOVERY_REPLY_DISCOVERY ||
		status == EPROT_STATUS_CONNECTED_MTU_DISCOVERY_REPLY) {
		packet_w_16_t(conn->out_packet, &c->remote.mtu_reply);
	}

	assert_dbg(conn->out_packet->length == PROTO_HEADER_SIZE(status));
}

static inline int
_conn_payload_from_secure(netconn_t *restrict conn, struct conncommon *restrict c)
{
	if (c->status == EPROT_STATUS_CONNECTED && c->remote.status == EPROT_STATUS_CONNECT)
		return 0;

	int ret = tick_remote_applicable(c->remote.tick, c->tick_remote_latest, c->tick_local, conn->settings.expected_tick_tolerance) || c->tick_local_noresp_count > 16384;
	if (!ret) return 0;

	packet_rewind(conn->payload_packet);
	int32_t nonce_diff = tick_diff(c->remote.tick, c->tick_remote_latest);
	if (c->handshake_status >= EHANDSHAKE_STATUS_SERVER_OK) {
		/* refuses unauthenticated packets after handshake */
		if (c->remote.secure == ESECURE_NONE) {
			c->tick_local 			= c->remote.tick;
			c->tick_remote_latest 	= c->remote.tick;
			c->tick_local_noresp_count = 0;
			return 0;
		}
	} else if (c->remote.secure == ESECURE_NONE) {
		/* passthrough */
		ulogf_dbg("Received passthrough payload, remote: %d", c->remote.tick);
		packet_rw_packet(conn->in_packet, conn->payload_packet, packet_get_readable(conn->in_packet));
	}

	if (c->remote.secure == ESECURE_ENCRYPT) {
		/* offset nonce for this packet */
		cipher_ctx_t rx = c->crypto.rx;
		crypto_nonce_add(&rx, nonce_diff);

		ulogf_dbg("Received: self_tick: %d, tick_remote: %d, rx nonce[0]: %d, diff: %d", conn->tick_local, c->remote.tick, rx.data[0], nonce_diff);
		/* decrypt */
		ret = !crypto_decrypt_packet(&rx, conn->in_packet, conn->payload_packet);

	} else if (c->remote.secure == ESECURE_AUTH && c->remote.frag_flag == EFRAG_FLAG_NONE) {
		ulogf_dbg("Received authenticated payload");
		uint8_t rx_hash[crypto_shorthash_BYTES];
		uint8_t hash[crypto_shorthash_BYTES];
		uint8_t *nonce = conn->in_packet->data + conn->in_packet->index;
		
		/* offset nonce for this packet */
		uint64_t rx_nonce = c->crypto.auth_rx.nonce + nonce_diff;

		/* store received hash */
		if (packet_r(conn->in_packet, rx_hash, sizeof(rx_hash)))
			return 0;

		/* overwrite received hash with nonce */
		memcpy(nonce, &rx_nonce, sizeof(rx_nonce));

		/* hash */
		if (crypto_shorthash(hash, conn->in_packet->data, conn->in_packet->length, c->crypto.auth_rx.key))
			return 0;

		/* verify authenticity */
		if (memcmp(hash, rx_hash, sizeof(hash)) != 0) {
			ulogf_wrn("Auth failed, dropping packet.");
			return 0;
		}

		/* passthrough */
		packet_rw_packet(conn->in_packet, conn->payload_packet, packet_get_readable(conn->in_packet));
	}

	/* add rx nonce */
	if (c->handshake_status >= EHANDSHAKE_STATUS_SERVER_OK) {
		crypto_nonce_add(&c->crypto.rx, nonce_diff);
		c->crypto.auth_rx.nonce += nonce_diff;
	}

	packet_rewind(conn->payload_packet);
	if (ret) {
		c->tick_local 			= c->remote.tick;
		if (c->status != EPROT_STATUS_DISCONNECT)
			c->tick_remote_latest 	= c->remote.tick;
		c->tick_local_noresp_count = 0;
	}
	if (c->remote.payload_padding) {
		ret = _mtu_rm_padding_from_pkt(conn->payload_packet);
		ulogf_dbg("%s padding from payload", ret? "Removed" : "Failed to remove");
	}
	return ret;
}

/* fragmented packets are authenticated by default */
static inline int
_conn_udp_send_fragmented(netconn_t *restrict conn, usocket_addr_t *restrict addr, struct conncommon *restrict c, packet_t *pkt_in, size_t mtu, uint8_t secure, uint8_t status)
{
	ulogf_dbg("Fragmented send");
	uint8_t hash[crypto_shorthash_BYTES];

	packet_rewind(conn->out_packet);
	uint8_t ret = EFRAG_FLAG_FIRST;

	netfrag_slicer_t slicer = {0};
	slicer.frag_size = mtu - (PROTO_HEADER_FRAG_SIZE + sizeof(hash));
	slicer.pkt_in = pkt_in;// conn->payload_packet;
	slicer.pkt_frag_out = conn->out_packet;
	
	/* at 128 tick/s ~= 78 * 10us ~= 0.78ms */
	int max_retries = 10000 / (int)conn->settings.tick_rate;

	const int32_t first_diff = PROTO_HEADER_FRAG_SIZE - PROTO_HEADER_SIZE(status);
	assert_dbg(first_diff < 0);

	do {
		_conn_prepare_outpkt(conn, c, status, ret, secure, -first_diff);

		/* write nonce */
		uint32_t nonce_idx = conn->out_packet->index;
		packet_w(conn->out_packet, &c->crypto.auth_tx.nonce, sizeof(c->crypto.auth_tx.nonce));

		/* write slice */
		ret = netfrag_slice_next(&slicer, first_diff);

		/* hash */
		crypto_shorthash(hash, conn->out_packet->data, conn->out_packet->length, c->crypto.auth_tx.key);

		/* replace nonce with hash */
		memcpy(conn->out_packet->data + nonce_idx, hash, sizeof(hash));

		int r;
		do {
			r = _conn_udp_send(conn, addr);
			if (!r && slicer.frag_idx == 1) {
				/* network or os cant keep up, and nothing was sent */
				return 0;
			} else if (!r) {
				/* at least one fragment was already sent. keep trying */
				utime_usleep(10);
				max_retries--;
			}
		} while (!r && max_retries > 0);

	} while (ret != EFRAG_FLAG_NONE);

	return 1;
}

static inline int
_conn_fragmented_reassemble(netconn_t *restrict conn, struct conncommon *restrict c, conn_header_t *restrict remote)
{
	if (remote->frag_flag == EFRAG_FLAG_NONE)
		return ENETFRAG_DONE;
	if (c->handshake_status < EHANDSHAKE_STATUS_SERVER_OK)
		return ENETFRAG_OK;
	
	/* avoid wasting cpu time on intentionally dropped packets */
	if (netfrag_multibuilder_being_dropped(&c->fragbuilder, remote->tick))
		return ENETFRAG_OK;
	
	ulogf_dbg("Received a fragment");

	/* offset nonce for this fragment */
	int32_t nonce_diff = tick_diff(remote->tick, c->tick_remote_latest);
	uint64_t rx_nonce = c->crypto.auth_rx.nonce + nonce_diff;

	uint8_t rx_hash[crypto_shorthash_BYTES];
	uint8_t hash[crypto_shorthash_BYTES];
	uint8_t *nonce = conn->in_packet->data + conn->in_packet->index;
		
	/* store received hash */
	if (packet_r(conn->in_packet, rx_hash, sizeof(rx_hash)))
		return ENETFRAG_OK;

	/* overwrite received hash with nonce */
	memcpy(nonce, &rx_nonce, sizeof(rx_nonce));

	/* hash */
	if (crypto_shorthash(hash, conn->in_packet->data, conn->in_packet->length, c->crypto.auth_rx.key))
		return ENETFRAG_OK;

	/* verify authenticity */
	if (memcmp(hash, rx_hash, sizeof(hash)) != 0) {
		ulogf_wrn("Auth failed, dropping fragment.");
		return ENETFRAG_OK;
	}

	int32_t first_diff = 0;
	if (remote->frag_flag == EFRAG_FLAG_MIDDLE) {
		first_diff = -remote->frag_shared.frag_first_diff;
	}

	packet_t *pkt = NULL;
	int err = netfrag_multibuilder_reconstruct(&c->fragbuilder, conn->in_packet, first_diff, remote, &pkt);
	if (err == ENETFRAG_DONE) {
		packet_t *dst_pkt = remote->secure == ESECURE_ENCRYPT? conn->in_packet : conn->payload_packet;
		packet_rewind(dst_pkt);
		packet_rw_packet(pkt, dst_pkt, packet_get_readable(pkt));
		packet_rewind(dst_pkt);
	}
	return err;
}

static inline int
_conn_payload_secure(netconn_t *restrict conn, struct conncommon *restrict c, usocket_addr_t *restrict addr)
{
	packet_rewind(conn->payload_packet);
	if (c->handshake_status == EHANDSHAKE_STATUS_CLIENT_OK) {
		uint8_t secure = conn->settings.secure;
		if (conn->payload_packet->length == 0)
			secure = ESECURE_AUTH;

		const size_t secure_overhead[] = {
			[ESECURE_ENCRYPT] = crypto_cipher_mac_size(c->crypto.tx.type),
			[ESECURE_AUTH] = crypto_shorthash_BYTES,
			[ESECURE_NONE] = 0
		};
	
		uint8_t frag_flag = EFRAG_FLAG_NONE;
		uint8_t status = c->status;
		size_t mtu = _mtuv[0];

		if (status == EPROT_STATUS_CONNECTED) {
			_conn_mtu_send_prepass(conn, c);
			status = _conn_outpkt_header_mtu_status(c);
			size_t header_overhead = PROTO_HEADER_SIZE(status) + secure_overhead[secure];
			frag_flag = _conn_mtu_send_pass(conn, c, header_overhead, &mtu);

			if (frag_flag == EFRAG_FLAG_NONE) {	
				size_t final_size = conn->payload_packet->length + header_overhead;
				frag_flag = (final_size > mtu? EFRAG_FLAG_FIRST : EFRAG_FLAG_NONE);
			}
		}

		if (secure == ESECURE_ENCRYPT) {
			ulogf_dbg("Write encrypted; tick: %d, tick_local: %d, tx nonce[0]: %d", conn->tick_local, c->tick_local, c->crypto.tx.data[0]);
			
			if (frag_flag) {
				packet_rewind(conn->in_packet);
				crypto_encrypt_packet(&c->crypto.tx, conn->payload_packet, conn->in_packet);
				packet_rewind(conn->in_packet);
				return _conn_udp_send_fragmented(conn, addr, c, conn->in_packet, mtu, secure, status);
			}

			_conn_prepare_outpkt(conn, c, status, frag_flag, secure, 0);
			crypto_encrypt_packet(&c->crypto.tx, conn->payload_packet, conn->out_packet);
		} else if (secure == ESECURE_AUTH) {
			ulogf_dbg("Write authenticated");

			if (frag_flag)
				return _conn_udp_send_fragmented(conn, addr, c, conn->payload_packet, mtu, secure, status);

			uint8_t hash[crypto_shorthash_BYTES];
			
			_conn_prepare_outpkt(conn, c, status, frag_flag, secure, 0);

			/* write nonce */
			uint32_t nonce_idx = conn->out_packet->index;
			packet_w(conn->out_packet, &c->crypto.auth_tx.nonce, sizeof(c->crypto.auth_tx.nonce));

			/* write payload */
			packet_rw_packet(conn->payload_packet, conn->out_packet, packet_get_length(conn->payload_packet));

			/* hash */
			crypto_shorthash(hash, conn->out_packet->data, conn->out_packet->length, c->crypto.auth_tx.key);

			/* replace nonce with hash */
			memcpy(conn->out_packet->data + nonce_idx, hash, sizeof(hash));

		} else {
			_conn_prepare_outpkt(conn, c, status, frag_flag, secure, 0);
			packet_rw_packet(conn->payload_packet, conn->out_packet, packet_get_length(conn->payload_packet));
		}
		return _conn_udp_send(conn, addr);
	}

	ulogf_dbg("Write unauthenticated");
	_conn_prepare_outpkt(conn, c, c->status, EFRAG_FLAG_NONE, ESECURE_NONE, 0);
	packet_rw_packet(conn->payload_packet, conn->out_packet, packet_get_length(conn->payload_packet));
	return _conn_udp_send(conn, addr);
}

static inline void
_send_disconnect(netconn_t *restrict conn, usocket_addr_t *restrict cli_addr, uint8_t reason, struct conncommon *restrict c)
{
	packet_rewind(conn->payload_packet);
	packet_w_8_t(conn->payload_packet, &reason);
	_conn_payload_secure(conn, c, cli_addr);
	ulogf_dbg("Sent client disconnect: %s:%"PRIu16, inet_ntoa(cli_addr->tcp_udp.sin_addr), ntohs(cli_addr->tcp_udp.sin_port));
}

static inline void
_server_client_disconnect(netconn_t *restrict conn, netsrvclient_t *c, uint8_t reason)
{
	if (!c->common.disconnect_reason)
		c->common.disconnect_reason = reason;
	if (conn) {
		if (c->common.status == EPROT_STATUS_CONNECTED)
			conn->data.srv.events.ondisconnect(conn, conn->userdata, c->common.disconnect_reason, c, &c->userdata);
		c->common.status = EPROT_STATUS_DISCONNECT;
	} else {
		c->common.status = EPROT_STATUS_DISCONNECT_PENDING;
	}
	c->common.tick_remote_latest = 0;
}

static inline int
_conncommon_init(netconn_t *restrict conn, struct conncommon *restrict c)
{
	if (!netmsg_init(&c->msgctx, 256))
		return 0;

	uint32_t max_pkt_sz = conn->settings.frag_max_recv_packet_size;
	max_pkt_sz = max_pkt_sz? (max_pkt_sz < 4096? 4096 : max_pkt_sz) : 65535;
	if (!netfrag_multibuilder_init(&c->fragbuilder, max_pkt_sz, conn->settings.frag_prealloc_packet_size, _mtuv[0])) {
		netmsg_deinit(&c->msgctx);
		return 0;
	}

	return 1;
}

static inline void
_conncommon_deinit(struct conncommon *restrict c)
{
	netmsg_deinit(&c->msgctx);
	netfrag_multibuilder_deinit(&c->fragbuilder);
}

static inline void
_server_client_free(netconn_t *restrict conn, netsrvclient_t *c)
{
	ulogf_dbg("Removed client: %s:%"PRIu16, server_cli_get_addrstr(c), server_cli_get_port(c));
	HASH_DEL(conn->data.srv.connected_clients, c);
	_conncommon_deinit(&c->common);
	ufree(c);
}

static inline int
_conncommon_mtu_config(struct conncommon *restrict c, usocket_addr_t *restrict addr)
{
	int mtu = usock_udp_get_local_mtu(addr);
	if (!mtu) {
		ulogf_crt("Failed to obtain interface MTU for %s:%"PRIu16, inet_ntoa(addr->tcp_udp.sin_addr), ntohs(addr->tcp_udp.sin_port));
		return 0;
	}
	mtu -= 28;
	c->mtu_local_max = mtu;
	c->mtu = mtu;
	for (c->mtu_idx = 0; c->mtu > _mtuv[c->mtu_idx] && c->mtu_idx < MTUV_LENGTH-1; c->mtu_idx++);
	ulogf_ntc("Interface MTU (%s:%"PRIu16"): %"PRIu16, inet_ntoa(addr->tcp_udp.sin_addr), ntohs(addr->tcp_udp.sin_port), c->mtu);
	return 1;
}

static inline netsrvclient_t *
_server_client_init(netconn_t *restrict conn, usocket_addr_t *restrict cli_addr, uint64_t cli_id)
{
	netsrvclient_t *client = umalloc(sizeof(*client));
	if (!client) {
		ulogf_crt("Failed to allocate srv_client");
		return NULL;
	}
	memset(client, 0, sizeof(*client));

	if (!_conncommon_init(conn, &client->common)) {
		ufree(client);
		return NULL;
	}

	if (!_conncommon_mtu_config(&client->common, cli_addr)) {
		_conncommon_deinit(&client->common);
		ufree(client);
		return NULL;
	}

	client->id = cli_id;
	memcpy(&client->sockaddr, cli_addr, sizeof(*cli_addr));

	HASH_ADD(hh, conn->data.srv.connected_clients, id, sizeof(cli_id), client);

	if (ufavonet_global.uthash_oom) {
		_conncommon_deinit(&client->common);
		ufree(client);
		ulogf_crt("uthash OOM");
		ufavonet_global.uthash_oom = 0;
		return NULL;
	}
	ulogf_dbg("Initialized client: %s:%"PRIu16, server_cli_get_addrstr(client), server_cli_get_port(client));
	return client;
}

static inline void
_client_disconnect(netconn_t **__conn, uint8_t reason)
{
	netconn_t *conn = *__conn;
	struct conncommon *s = &conn->data.cli.common;

	/* hold until the server replies. unless it's a timeout */
	if (s->remote.status == EPROT_STATUS_DISCONNECT || reason == EDISCONNECT_TIMEOUT) {
		if (s->status != EPROT_STATUS_DISCONNECT)
			conn->data.cli.events.ondisconnect(__conn, conn->userdata, reason);
		if (!*__conn) return;
		s->remote.status = EPROT_STATUS_DISCONNECT;
	}

	s->status = EPROT_STATUS_DISCONNECT;
	s->disconnect_reason = reason;
	s->tick_remote_latest = 0;
}


#define _conn_netmsg_unpack_all(ctx,pkt,onunpack,onerror,onviolation) \
	do { \
		void *data = NULL; \
		uint32_t size = 0; \
		int32_t err = netmsg_unpack_next(ctx, pkt, &data, &size); \
		if (data) \
			onunpack; \
		if (err == ENETMSG_ERR_NONE_AGAIN) 	continue; \
		if (err == ENETMSG_ERR_NONE) 		break; \
		if (err == ENETMSG_ERR_INVALID) { \
			/* Protocol violation */ \
			onviolation; \
			break; \
		} \
		/* Internal error */ \
		onerror; \
		break; \
	} while (1);

/* Returns 0 on failure (connection being terminated) */
static inline int
_server_netmsg_unpack_all(netconn_t *restrict conn, netsrvclient_t *restrict client, packet_t *restrict p_in)
{
	packet_t tmp = {0};
	_conn_netmsg_unpack_all(&client->common.msgctx, p_in, {
		if (conn->data.srv.events.onreceivemsg) {
			tmp.data = data;
			tmp.size = size;
			tmp.length = size;
			packet_rewind(&tmp);
			conn->data.srv.events.onreceivemsg(conn, conn->userdata, &tmp, client);
		}
	}, {
		ulogf_wrn("Internal error during message unpacking");
		_server_client_disconnect(conn, client, EDISCONNECT_INTERNAL_ERROR);
		return 0;
	}, {
		ulogf_wrn("Protocol violation during message unpacking");
		_server_client_disconnect(conn, client, EDISCONNECT_PROTOCOL_VIOLATION);
		return 0;
	});
	return 1;
}

static inline int
_server_onconnect_internal(netconn_t *restrict conn, netsrvclient_t *restrict client, packet_t *restrict p_in, packet_t *restrict p_out)
{
	int ret = ECONNECTION_AGAIN;
	int err = handshake_server_onestep(p_in, p_out, &conn->data.srv.keypair,
									conn->secure_ciphers, &client->common.crypto,
									conn->tick_local, client->common.remote.tick,
									!conn->settings.dont_distribute_public_key);
	switch (err) {
		case EHANDSHAKE_ERR_INPUT:
			ulogf_err("Protocol violation during handshake");
			client->common.disconnect_reason = EDISCONNECT_PROTOCOL_VIOLATION;
			return ECONNECTION_REFUSE;

		case EHANDSHAKE_ERR_INTERNAL:
			ulogf_err("Internal error during handshake");
			client->common.disconnect_reason = EDISCONNECT_INTERNAL_ERROR;
			return ECONNECTION_REFUSE;

		case EHANDSHAKE_ERR_REFUSED:
			client->common.disconnect_reason = EDISCONNECT_WONT_GIVE_PUBLIC_KEY;
			return ECONNECTION_REFUSE;

		default:
		case EHANDSHAKE_ERR_DECRYPT:
		case EHANDSHAKE_ERR_CIPHERS:
		case EHANDSHAKE_ERR_CHECKBYTES:
			client->common.disconnect_reason = EDISCONNECT_HANDSHAKE;
			return ECONNECTION_REFUSE;

		case 1:
			ret = ECONNECTION_ALLOW;
			client->common.tick_local 			= client->common.remote.tick + 32768;
			client->common.tick_remote_latest 	= client->common.remote.tick + 32768;
			break;

		case 0:
			ret = ECONNECTION_AGAIN;
			break;
	}

	// Announce server tickrate
	packet_w_16_t(p_out, &conn->settings.tick_rate);
	return ret;
}

static inline int
_client_onconnect_internal(netconn_t **__conn, packet_t *restrict p_in, packet_t *restrict p_out)
{
	netconn_t *conn = *__conn;

	int err = 0;
	int ret = 1;
	uint16_t crypto_start_remote_tick = 0;
	uint16_t crypto_start_local_tick = 0;
	err = handshake_client_step(&conn->data.cli.handshake, p_in, p_out,
							 conn->data.cli.srv_public_key, conn->secure_ciphers,
							 &conn->data.cli.common.crypto, &crypto_start_remote_tick,
							 &crypto_start_local_tick);
	switch (err) {
		case EHANDSHAKE_ERR_INPUT:
			ulogf_ntc("Protocol violation during handshake");
			_client_disconnect(__conn, EDISCONNECT_PROTOCOL_VIOLATION);
			return -1;
		
		case EHANDSHAKE_ERR_INTERNAL:
			ulogf_err("Internal error during handshake");
			_client_disconnect(__conn, EDISCONNECT_INTERNAL_ERROR);
			return -1;
		
		default:
		case EHANDSHAKE_ERR_CIPHERS:
		case EHANDSHAKE_ERR_CHECKBYTES:
			_client_disconnect(__conn, EDISCONNECT_HANDSHAKE);
			return -1;

		case 0:
			/* Not done yet */
			ret = 0;
			break;

		case 1: {
			/* Server's tx nonce is always 1 ahead. Compensate for that in client's rx nonce. */
			crypto_nonce_add(&conn->data.cli.common.crypto.rx, 1);
			conn->data.cli.common.crypto.auth_rx.nonce += 1;
			
			/* sync with the tick at the server during handshake so that the rx nonce is kept in sync with the server's tx nonce */
			conn->data.cli.common.tick_local = crypto_start_remote_tick;
			conn->data.cli.common.tick_remote_latest = crypto_start_remote_tick;
			/* bump local tick so that the server is able to sync it's rx nonce with the client's tx nonce */
			conn->tick_local = crypto_start_local_tick + 32768 + 1;
			break;
		}
	}

	if (packet_get_readable(p_in) == 0)
		return 0;

	// Apply tickrate
	uint16_t server_tick_rate = 0;
	err = packet_r_16_t(p_in, &server_tick_rate);
	if (err) goto fail;

	if (server_tick_rate != conn->settings.tick_rate && server_tick_rate) {
		// use the same rate as the server
		ulogf_ntc("Tick rate mismatch. Server: %" PRIu16 "; Client: %" PRIu16". Now running at %" PRIu16 ".", server_tick_rate, conn->settings.tick_rate, server_tick_rate);

		#define update_setting(value) if (value) (value) = ((int32_t)(server_tick_rate) * (int32_t)(value)) / (int32_t)(conn->settings.tick_rate)
		update_setting(conn->settings.kick_notice_tick);
		update_setting(conn->settings.timeout_tick);
		update_setting(conn->settings.pending_conn_timeout_tick);
		#undef update_setting
		
		conn->tick_time_target_us = 1000000L / server_tick_rate;
		conn->settings.tick_rate = server_tick_rate;
		conn->rtt_ema_alpha = ema_alpha(server_tick_rate * 0.1f);
	}
	return ret;

fail:
	if (err == EPACKET_ERR_OUT_OF_BOUNDS) {
		ulogf_ntc("Protocol violation during internal connect stage");
		_client_disconnect(__conn, EDISCONNECT_PROTOCOL_VIOLATION);
	} else {
		ulogf_err("Internal error during internal connect stage. packet err: %" PRIi32, err);
		_client_disconnect(__conn, EDISCONNECT_INTERNAL_ERROR);
	}
	return -1;
}

static inline void
_server_netmsg_pack_connect(netconn_t *restrict conn, netsrvclient_t *restrict client, void *data, size_t size)
{
	packet_t pin;
	_packet_init_from_buf(&pin, data, size);
	packet_set_length(&pin, size);
	packet_rewind(conn->out_packet);

	enum netconn_connect_result res = ECONNECTION_REFUSE;

	if (client->common.handshake_status == EHANDSHAKE_STATUS_TICK_SYNC) {
		// Internal onconnect
		res = _server_onconnect_internal(conn, client, &pin, conn->out_packet);
		client->common.tick_local_noresp_count = 0;
		if (res == ECONNECTION_ALLOW) {
			netmsg_enqueue(&client->common.msgctx, conn->out_buffer, packet_get_length(conn->out_packet));
			client->common.handshake_status = EHANDSHAKE_STATUS_SERVER_OK;
			return;
		}
	} else if (client->common.handshake_status == EHANDSHAKE_STATUS_SERVER_OK) {
		/* client reached status CLIENT_OK. Start sending secure packets. */
		client->common.handshake_status = EHANDSHAKE_STATUS_CLIENT_OK;
		// User onconnect
		res = conn->data.srv.events.onconnect ? conn->data.srv.events.onconnect(conn, conn->userdata, &pin, conn->out_packet, client, &client->userdata) : ECONNECTION_ALLOW;
	}

	switch(res) {
		case ECONNECTION_ALLOW:
			client->common.status = EPROT_STATUS_CONNECTED;
			break;
		case ECONNECTION_REFUSE:
			_server_client_disconnect(conn, client, EDISCONNECT_REFUSED);
			break;
		case ECONNECTION_AGAIN:
			if (packet_get_write_op_count(conn->out_packet))
				netmsg_enqueue(&client->common.msgctx, conn->out_buffer, packet_get_length(conn->out_packet));
			break;
	}
}

static inline int
_server_netmsg_unpack_onconnect(netconn_t *restrict conn, netsrvclient_t *restrict client, packet_t *restrict p_in)
{
	int once = 0;
	_conn_netmsg_unpack_all(&client->common.msgctx, p_in, {
		if (once) {
			ulogf_ntc("Protocol violation: Client sent more then one message at a time during connect stage.");
			_server_client_disconnect(conn, client, EDISCONNECT_PROTOCOL_VIOLATION);
			return 0;
		}
		_server_netmsg_pack_connect(conn, client, data, size);
		once = 1;
	}, {
		ulogf_wrn("Internal error during message unpacking");
		_server_client_disconnect(conn, client, EDISCONNECT_INTERNAL_ERROR);
		return 0;
	}, {
		ulogf_wrn("Protocol violation during message unpacking");
		_server_client_disconnect(conn, client, EDISCONNECT_PROTOCOL_VIOLATION);
		return 0;
	});
	return 1;
}

static inline int
_client_netmsg_pack_connect(netconn_t **__conn, void *data, size_t size)
{
	netconn_t *conn = *__conn;

	packet_t pin;
	_packet_init_from_buf(&pin, data, size);
	packet_set_length(&pin, size);
	packet_rewind(conn->out_packet);
	conn->out_packet->length = 0;

	if (conn->data.cli.common.handshake_status <= EHANDSHAKE_STATUS_TICK_SYNC) {
		conn->data.cli.common.tick_local_noresp_count = 0;
		int res = _client_onconnect_internal(__conn, &pin, conn->out_packet);
		if (res == 1) {
			conn->data.cli.common.handshake_status = EHANDSHAKE_STATUS_CLIENT_OK;

			if (packet_get_write_op_count(conn->out_packet)) {
				netmsg_enqueue(&conn->data.cli.common.msgctx, conn->out_buffer, packet_get_length(conn->out_packet));
				return 1;
			}
		} else if (res < 0)
			return 0;
	}

	if (conn->data.cli.common.handshake_status == EHANDSHAKE_STATUS_CLIENT_OK && conn->data.cli.events.onconnect)
		conn->data.cli.events.onconnect(conn, conn->userdata, &pin, conn->out_packet);

	/* always send a last message to let the server know when the client is done */
	if (packet_get_write_op_count(conn->out_packet) || conn->data.cli.common.handshake_status == EHANDSHAKE_STATUS_CLIENT_OK)
		netmsg_enqueue(&conn->data.cli.common.msgctx, conn->out_buffer, packet_get_length(conn->out_packet));

	return 1;
}

/* Returns 0 on failure (connection being terminated) */
static inline int
_client_netmsg_unpack_all(netconn_t **__conn, packet_t *restrict p_in)
{
	netconn_t *conn = *__conn;
	int once = 0;
	packet_t tmp = {0};
	_conn_netmsg_unpack_all(&conn->data.cli.common.msgctx, p_in, {
		if (conn->data.cli.common.remote.status == EPROT_STATUS_CONNECT) {
			if (once) {
				ulogf_ntc("Protocol violation: Server sent more then one message at a time during connect stage.");
				_client_disconnect(__conn, EDISCONNECT_PROTOCOL_VIOLATION);
				return 0;
			}
			if (!_client_netmsg_pack_connect(__conn, data, size))
				return 0;
			once++;
		} else if (conn->data.cli.events.onreceivemsg) {
			tmp.data = data;
			tmp.size = size;
			tmp.length = size;
			packet_rewind(&tmp);
			conn->data.cli.events.onreceivemsg(conn, conn->userdata, &tmp);
		}
	}, {
		ulogf_wrn("Internal error during message unpacking");
		_client_disconnect(__conn, EDISCONNECT_INTERNAL_ERROR);
		return 0;
	}, {
		ulogf_wrn("Protocol violation during message unpacking");
		_client_disconnect(__conn, EDISCONNECT_PROTOCOL_VIOLATION);
		return 0;
	});
	return 1;
}

#undef _conn_netmsg_unpack_all


static inline int
_conn_recv(netconn_t *restrict conn, usocket_addr_t *restrict addr, conn_header_t *restrict remote)
{
	ssize_t recvlen;
	int err;
	
	recvlen = usock_udp_recv(&conn->udp_sock, addr, conn->in_buffer, 65535);
	if (recvlen <= 0) {
		// error or no data.
		return 0;
	}

	conn->stats.total_received_bytes += recvlen;
	packet_rewind(conn->in_packet);
	packet_set_length(conn->in_packet, recvlen);
	packet_rewind(conn->payload_packet);
	packet_set_length(conn->payload_packet, 0);

	/* Read header */
	err = packet_r_16_t(conn->in_packet, &remote->tick);
	if (err) return 0;
	err = packet_r_bits(conn->in_packet, &remote->frag_flag, EFRAG_FLAG_SIZE_BITS);
	if (err) return 0;
	err = packet_r_bits(conn->in_packet, &remote->frag_shared.noresp, 8 - EFRAG_FLAG_SIZE_BITS);
	if (err) return 0;

	remote->payload_padding = 0;
	if (remote->frag_flag == EFRAG_FLAG_MIDDLE || remote->frag_flag == EFRAG_FLAG_LAST) {
		assert_dbg(conn->in_packet->index == PROTO_HEADER_FRAG_SIZE);
		return 1;
	}

	err = packet_r_bits(conn->in_packet, &remote->status, EPROT_STATUS_SIZE);
	if (err) return 0;
	err = packet_r_bits(conn->in_packet, &remote->round_trip_flag_echo, 1);
	if (err) return 0;
	err = packet_r_bits(conn->in_packet, &remote->round_trip_flag, 1);
	if (err) return 0;
	err = packet_r_bits(conn->in_packet, &remote->secure, 2);
	if (err) return 0;

	remote->mtu = 0;
	uint8_t recv_status = remote->status;
	if (remote->status == EPROT_STATUS_CONNECTED_MTU_DISCOVERY) {
		remote->status = EPROT_STATUS_CONNECTED;
		/* The other side is performing MTU discovery. This side must include the number of bytes received in it's reply. */
		remote->mtu_reply = (uint16_t)packet_get_length(conn->in_packet);
		remote->payload_padding = remote->frag_flag == EFRAG_FLAG_NONE;
	} else if (remote->status == EPROT_STATUS_CONNECTED_MTU_DISCOVERY_REPLY) {
		remote->status = EPROT_STATUS_CONNECTED;
		/* This side is performing MTU discovery and the other side received the payload. */
		err = packet_r_16_t(conn->in_packet, &remote->mtu);
		if (err) return 0;
	} else if (remote->status == EPROT_STATUS_CONNECTED_MTU_DISCOVERY_REPLY_DISCOVERY) {
		remote->status = EPROT_STATUS_CONNECTED;
		/* both cases */
		/* The other side is performing MTU discovery. This side must include the number of bytes received in it's reply. */
		remote->mtu_reply = (uint16_t)packet_get_length(conn->in_packet);
		remote->payload_padding = remote->frag_flag == EFRAG_FLAG_NONE;
		/* This side is performing MTU discovery and the other side received the payload. */
		err = packet_r_16_t(conn->in_packet, &remote->mtu);
		if (err) return 0;
	}
	ulogf_dbg("status: %"PRIu8", padding: %"PRIu8 ", frag_flag: %"PRIu8, recv_status, remote->payload_padding, remote->frag_flag);

	assert_dbg(conn->in_packet->index == PROTO_HEADER_SIZE(recv_status));
	return 1;
}

static inline void
_conncommon_tick(struct conncommon *restrict c, float rtt_ema_alpha)
{
	c->tick_local++;

	if (c->handshake_status >= EHANDSHAKE_STATUS_SERVER_OK) {
		/* Add tx nonce */
		crypto_nonce_add(&c->crypto.tx, 1);
		c->crypto.auth_tx.nonce += 1;
	}

	/* handle rtt */
	if (c->round_trip_counter < UINT8_MAX)
		c->round_trip_counter++;

	/* rtt bit got echoed back */
	if (c->remote.round_trip_flag == c->round_trip_flag_expected) {
		c->round_trip_flag_expected = ~c->remote.round_trip_flag & 1;
		c->round_trip_ticks = c->round_trip_counter;
		c->round_trip_counter = 0;
		c->round_trip_ticks_ema = ema(rtt_ema_alpha, c->round_trip_ticks_ema, c->round_trip_ticks);
	}
}

/* retain and keep sending the largest mtu_reply for at least 1 second after it was received */
static inline uint16_t
_mtu_retain_reply(struct conncommon *restrict c, uint16_t late_mtu_reply, uint16_t mtu_reply, uint16_t tick_rate)
{
	uint16_t r = mtu_reply;
	if (c->remote.mtu_reply) {
		if (c->mtu_reply_retention < tick_rate) {
			if (late_mtu_reply > mtu_reply) {
				r = late_mtu_reply;
				c->mtu_reply_retention = 0;
			}
		} else {
			c->mtu_reply_retention = 0;
		}
		c->mtu_reply_retention++;
	}
	return r;
}

static inline netsrvclient_t *
_server_recv(netconn_t *restrict conn)
{
	usocket_addr_t 	cli_addr = {0};

	conn_header_t remote = {0};

	if (!_conn_recv(conn, &cli_addr, &remote))
		return NULL;


	/* Find client by id */
	netsrvclient_t 	*client = NULL;
	uint64_t 		cli_id 	= SOCKADDR_TO_KEY(cli_addr.tcp_udp);
	HASH_FIND(hh, conn->data.srv.connected_clients, &cli_id, sizeof(cli_id), client);

	if (!client) {
		struct conncommon c = {0};
		c.remote = remote;
		if (remote.status != EPROT_STATUS_CONNECT || remote.secure != ESECURE_NONE) {
			ulogf_dbg("Client already disconnected");
			/* Already disconnected. Reinforce disconnection. */
			_send_disconnect(conn, &cli_addr, EDISCONNECT_NONE, &c);
			return NULL;
		}

		if (conn->data.srv.is_closing)
			return NULL;

		/* fragmented packets are not allowed in this state */
		if (remote.frag_flag != EFRAG_FLAG_NONE)
			return NULL;

		/* initialize client */
		client = _server_client_init(conn, &cli_addr, cli_id);
		if (!client) {
			_send_disconnect(conn, &cli_addr, EDISCONNECT_INTERNAL_ERROR, &c);
			ulogf_wrn("Failed to initialize client");
			return NULL;
		}
		client->common.tick_remote_latest	= remote.tick;
		client->common.tick_local			= remote.tick;
		/* the client is the one that needs to catch up with the server */
		client->common.handshake_status 	= EHANDSHAKE_STATUS_TICK_SYNC;
	}

	/* reassemble fragmented packets */
	switch (_conn_fragmented_reassemble(conn, &client->common, &remote)) {
		case ENETFRAG_DONE: break;
		case ENETFRAG_OK: return NULL;
		case ENETFRAG_ERROR:
			ulogf_wrn("Internal error during frag reassemble");
			_server_client_disconnect(conn, client, EDISCONNECT_INTERNAL_ERROR);
			return NULL;
		case ENETFRAG_VIOLATION:
			ulogf_wrn("Protocol violation during frag reassemble");
			_server_client_disconnect(conn, client, EDISCONNECT_PROTOCOL_VIOLATION);
			return NULL;
	}

	remote.mtu_reply = _mtu_retain_reply(&client->common, client->common.remote.mtu_reply, remote.mtu_reply, conn->settings.tick_rate);
	client->common.remote = remote;
	return client;
}

static inline int
_server_process_recv(netconn_t *restrict conn)
{
	int i;
	int recv_cnt = 0;
	/* Receive data from clients */
	for (i = 2; i;) {
		netsrvclient_t *c = _server_recv(conn);
		if (!c) { i--; continue; }
		recv_cnt++;

		int applicable = _conn_payload_from_secure(conn, &c->common);
		if (!applicable) continue;

		/* handle disconnection */
		if (c->common.remote.status == EPROT_STATUS_DISCONNECT) {
			/* handle disconnection initiated by the client */
			if (c->common.status != EPROT_STATUS_DISCONNECT) {
				ulogf_dbg("Client initiated disconnection");
				uint8_t reason;
				/* Fallback to generic disconnect if reading the reason fails. */
				if (packet_r_8_t(conn->payload_packet, &reason))
					reason = EDISCONNECT;
				_server_client_disconnect(conn, c, reason);
				_send_disconnect(conn, &c->sockaddr, reason, &c->common);
			}
			_server_client_free(conn, c);	
			continue;
		}

		if (c->common.status == EPROT_STATUS_DISCONNECT)
			continue;

		if (c->common.status == EPROT_STATUS_DISCONNECT_PENDING) {
			_server_client_disconnect(conn, c, c->common.disconnect_reason);
			continue;
		}

		if (conn->data.srv.is_closing)
			continue;


		/* handle connect */
		if (c->common.remote.status == EPROT_STATUS_CONNECT) {
			if (c->common.status == EPROT_STATUS_CONNECT) {
				_server_netmsg_unpack_onconnect(conn, c, conn->payload_packet);
				continue;
			}
		}

		/* handle messages */
		if (!_server_netmsg_unpack_all(conn, c, conn->payload_packet)) {
			/* error. client being dropped. */
			continue;
		}

		/* handle default EPROT_STATUS_CONNECTED behaviour */
		conn->data.srv.events.onreceivepkt(conn, conn->userdata, conn->payload_packet, c, c->userdata);

		i = 2;
	}
	return recv_cnt;
}

static inline void
_server_process_send(netconn_t *restrict conn)
{
	netsrvclient_t *client;

	/* before send event */
	if (conn->data.srv.events.bonsendpkt != NULL)
		if (HASH_COUNT(conn->data.srv.connected_clients) > 0)
			conn->data.srv.events.bonsendpkt(conn, conn->userdata, conn->data.srv.connected_clients);

	/* process and send data to connected clients */
	for (client = conn->data.srv.connected_clients; client; ) {
		
		/* client tick */
		_conncommon_tick(&client->common, conn->rtt_ema_alpha);

		/* handle server kick */
		if (client->common.status == EPROT_STATUS_DISCONNECT_PENDING)
			_server_client_disconnect(conn, client, client->common.disconnect_reason);

		/* handle disconnected */
		if (client->common.status == EPROT_STATUS_DISCONNECT) {
			if (client->common.tick_remote_latest++ == conn->settings.kick_notice_tick) {
				/* Disconnect notice already sent multiple times. Remove client */
				if (!client->hh.next) {
					_server_client_free(conn, client);
					break;
				}
				netsrvclient_t *c = client;
				_server_client_free(conn, c);
				goto next_client;
			}
			_send_disconnect(conn, &client->sockaddr, client->common.disconnect_reason, &client->common);
			goto next_client;
		}

		/* handle timeout */
		{
			client->common.tick_local_noresp_count++;

			const uint16_t timeout_ticks = client->common.status == EPROT_STATUS_CONNECT? conn->settings.pending_conn_timeout_tick : conn->settings.timeout_tick;
			if (client->common.tick_local_noresp_count == timeout_ticks) {
				_server_client_disconnect(conn, client, EDISCONNECT_TIMEOUT);
				_send_disconnect(conn, &client->sockaddr, client->common.disconnect_reason, &client->common);
				goto next_client;
			}
		}

		if (client->common.status != EPROT_STATUS_CONNECTED && client->common.status != EPROT_STATUS_CONNECT)
			goto next_client;

		/* prepare packet */
		packet_rewind(conn->payload_packet);

		/* write messages */
		int32_t err = netmsg_pack(&client->common.msgctx, conn->payload_packet, (uint8_t)client->common.round_trip_ticks_ema);
		if (err != ENETMSG_ERR_NONE) {
			ulogf_crt("Failed to pack messages. Dropping connection. Err: %" PRIi32, err);
			_server_client_disconnect(conn, client, EDISCONNECT_INTERNAL_ERROR);
			_send_disconnect(conn, &client->sockaddr, EDISCONNECT_INTERNAL_ERROR, &client->common);
			continue;
		}

		if (client->common.status == EPROT_STATUS_CONNECTED) {
			/* call onsend. only for connected clients. */
			conn->data.srv.events.onsendpkt(conn, conn->userdata, conn->payload_packet, client, client->userdata);

			/* netmsg_pack() always perform at least one write operation.
			 * The packet must be sent if netmsg_pack() performed more then
			 * one write or onsendpkt() performed one or more writes. */
			if (packet_get_write_op_count(conn->payload_packet) == 1) {
				/* avoid sending empty packets if possible */
				if (client->common.send_skip_count++ < conn->settings.timeout_tick / 8)
					goto next_client;
				client->common.send_skip_count = 0;
			}
		}

		_conn_payload_secure(conn, &client->common, &client->sockaddr);

next_client:
		client = client->hh.next;
	}
}

static inline int
_client_process_recv(netconn_t **__conn)
{
	netconn_t *conn = *__conn;
	struct conncommon *s = &conn->data.cli.common;

	if (s->status == EPROT_STATUS_DISCONNECT &&
		s->remote.status == EPROT_STATUS_DISCONNECT)
		return 0;

	int recv_cnt = 0;

	while (1) {
		conn_header_t remote = s->remote;		
		if (!_conn_recv(conn, &conn->udp_sock.addr, &remote))
			return recv_cnt;
		
		recv_cnt++;

		/* reassemble fragmented packets */
		switch (_conn_fragmented_reassemble(conn, s, &remote)) {
			case ENETFRAG_DONE: break;
			case ENETFRAG_OK: continue;
			case ENETFRAG_ERROR:
				ulogf_wrn("Internal error during frag reassemble");
				_client_disconnect(__conn, EDISCONNECT_INTERNAL_ERROR);
				return 0;
			case ENETFRAG_VIOLATION:
				ulogf_wrn("Protocol violation during frag reassemble");
				_client_disconnect(__conn, EDISCONNECT_PROTOCOL_VIOLATION);
				return 0;
		}

		remote.mtu_reply = _mtu_retain_reply(s, s->remote.mtu_reply, remote.mtu_reply, conn->settings.tick_rate);
		s->remote = remote;

		/* sync first tick */
		if (s->handshake_status == EHANDSHAKE_STATUS_NONE) {
			s->tick_local 			= s->remote.tick;
			s->tick_remote_latest 	= s->remote.tick;
			s->handshake_status 	= EHANDSHAKE_STATUS_TICK_SYNC;
		}
		
		int applicable = _conn_payload_from_secure(conn, s);
		if (!applicable) continue;

		/* handle disconnection */
		if (s->status == EPROT_STATUS_DISCONNECT)
			return recv_cnt;

		if (s->remote.status == EPROT_STATUS_DISCONNECT) {
			uint8_t reason;
			if (packet_r_8_t(conn->payload_packet, &reason))
				reason = EDISCONNECT;
			/* report back to the server */
			_send_disconnect(conn, &conn->udp_sock.addr, reason, s);
			_client_disconnect(__conn, reason);
			return 0;
		}

		/* handle messages */
		if (!_client_netmsg_unpack_all(__conn, conn->payload_packet)) {
			/* error. connection being dropped. */
			return recv_cnt;
		}

		s->status = s->remote.status;
		if (s->remote.status == EPROT_STATUS_CONNECT)
			continue;
		
		conn->data.cli.events.onreceivepkt(conn, conn->userdata, conn->payload_packet);
	}
	return recv_cnt;
}

static inline void
_client_process_send(netconn_t **__conn)
{
	if (!__conn) 	return;
	if (!*__conn) 	return;

	netconn_t *conn = *__conn;
	struct conncommon *s = &conn->data.cli.common;

	/* server tick */
	_conncommon_tick(s, conn->rtt_ema_alpha);

	/* Handle disconnect */
	if (s->remote.status == EPROT_STATUS_DISCONNECT) {
		_client_disconnect(__conn, s->disconnect_reason);
		return;
	}

	if (s->status == EPROT_STATUS_DISCONNECT) {
		if (s->tick_remote_latest++ >= conn->settings.kick_notice_tick) {
			/* Disconnect notice already sent multiple times */
			s->remote.status = EPROT_STATUS_DISCONNECT;
			_client_disconnect(__conn, s->disconnect_reason);
			return;
		}
		_send_disconnect(conn, &conn->udp_sock.addr, conn->data.cli.common.disconnect_reason, s);
		return;
	}

	/* handle timeout */
	{
		s->tick_local_noresp_count++;

		const uint16_t timeout_ticks = s->status == EPROT_STATUS_CONNECT? conn->settings.pending_conn_timeout_tick : conn->settings.timeout_tick;
		if (s->tick_local_noresp_count == timeout_ticks) {
			_client_disconnect(__conn, EDISCONNECT_TIMEOUT);
			return;
		}
	}

	
	/* prepare packet */
	packet_rewind(conn->payload_packet);

	/* write messages */
	int32_t err = netmsg_pack(&conn->data.cli.common.msgctx, conn->payload_packet, (uint8_t)s->round_trip_ticks_ema);
	if (err != ENETMSG_ERR_NONE) {
		ulogf_crt("Failed to pack messages. Dropping connection. Err: %" PRIi32, err);
		_send_disconnect(conn, &conn->udp_sock.addr, EDISCONNECT_INTERNAL_ERROR, s);
		_client_disconnect(__conn, EDISCONNECT_INTERNAL_ERROR);
		return;
	}

	if (s->status != EPROT_STATUS_CONNECT) {
		/* call onsend */
		conn->data.cli.events.onsendpkt(conn, conn->userdata, conn->payload_packet);

		/* netmsg_pack() always perform at least one write operation.
		 * The packet must be sent if netmsg_pack() performed more then
		 * one write or onsendpkt() performed one or more writes. */
		if (packet_get_write_op_count(conn->payload_packet) == 1) {
			/* avoid sending empty packets if possible */
			if (s->send_skip_count++ < conn->settings.timeout_tick / 8)
				return;
			s->send_skip_count = 0;
		}
	}

	_conn_payload_secure(conn, s, &conn->udp_sock.addr);
}

static inline netconn_t *
_conn_init(const struct netsettings settings, void *userdata)
{
	assert_dbg(NETCONN_SECURE_KEYPAIR_SIZE == (crypto_box_PUBLICKEYBYTES + crypto_box_SECRETKEYBYTES));
	if (!crypto_init()) return NULL;

	netconn_t *conn = umalloc(sizeof(*conn));
	if (!conn) {
		ulogf_crt("Failed to allocate memory for netconn_t");
		return NULL;
	}
	memset(conn, 0, sizeof(*conn));
	conn->settings = settings;
	conn->userdata = userdata;
	if (settings.tick_rate) {
		conn->rtt_ema_alpha = ema_alpha(settings.tick_rate * 0.1f);
		conn->tick_time_target_us = 1000000L / settings.tick_rate;

		/* measure approx. sleep overhead */
		int_fast64_t max = 0;
		utime_t t = {0};
		utime_remaining(&t, 0);
		int i;
		/* 100 ms worth of samples */
		for (i = 0; i < 100000 / 100; i++) {
			utime_usleep(100);
			int_fast64_t o = utime_remaining(&t, 100);
			/* always assume at least 500us + 50% of overhead */
			o = (o <= -500? -o : 500) * 1.50;
			if (o > max)
				max = o;
		}
		ulogf_dbg("Estimated relaxed tick margin: %" PRIi64 "us", (int64_t)max);
		conn->tick_time_margin_us = max;
	}
	conn->tick_time_underrun_us = -INT64_MAX;

	conn->in_packet = packet_init_from_buff(conn->in_buffer, sizeof(conn->in_buffer));
	conn->out_packet = packet_init_from_buff(conn->out_buffer, sizeof(conn->out_buffer));
	conn->payload_packet = packet_init_prealloc(65535);
	conn->secure_ciphers = crypto_cipher_benchmark(128);
	
	return conn;
}

static inline void
_conn_deinit(netconn_t *conn)
{
	usock_udp_deinit(&conn->udp_sock);
	packet_free(&conn->in_packet);
	packet_free(&conn->out_packet);
	packet_free(&conn->payload_packet);
	ufree(conn);
}

static inline int
_conn_socket_init(netconn_t *restrict conn, enum netconn_protocol proto, const char *restrict hostname, uint16_t port)
{
	switch (proto) {
		case EPROTO_UDP: return usock_udp_init(hostname, port, &conn->udp_sock);
		default:
			ulogf_err("Unknown protocol");
			return 0;
	}
	return 0;
}

static inline void
server_tick(netconn_t **__conn)
{
	netconn_t *conn = *__conn;

	if (conn->data.srv.is_closing) {
		if (conn->data.srv.is_closing >= 2)
			return;

		/* Server is closing. 
		 * Incoming packets are ignored. (except by disconnection acknowledgements) */
		if (HASH_COUNT(conn->data.srv.connected_clients) == 0) {
			conn->data.srv.events.onsrvclose(__conn, conn->userdata);
			if (*__conn) conn->data.srv.is_closing++;
			return;
		}
	}

	_server_process_recv(conn);
	_server_process_send(conn);
	
	conn->tick_local++;
}

static inline void
client_tick(netconn_t **__conn)
{
	_client_process_recv(__conn);
	_client_process_send(__conn);

	if (*__conn)
		(*__conn)->tick_local++;
}

static inline void
server_cleanup(netconn_t *c)
{
	struct srvclient 	*client;

	if (HASH_COUNT(c->data.srv.connected_clients) > 0) {
		/* if for some reason the server is not empty */
		for (client = c->data.srv.connected_clients; client != NULL; ) {
			/* anounce disconnect if not disconnected yet */
			if (client->common.status != EPROT_STATUS_DISCONNECT)
				_send_disconnect(c, &client->sockaddr, EDISCONNECT_SERVER_CLOSING, &client->common);

			/* free client */
			_server_client_free(c, client);
			client = c->data.srv.connected_clients;
		}
	}
}

/********************************
 *		SERVER PUBLIC API		*
 ********************************/

netconn_t *
server_init(const struct srvevents events, const struct netsettings settings, void *userdata)
{
	netconn_t *conn = _conn_init(settings, userdata);
	if (!conn) return NULL;
	conn->data.srv.events = events;
	conn->type = ETYPE_SERVER;
	return conn;
}

int
server_secure_keypair_generate(netconn_t *restrict conn)
{
	if (!conn) return 0;
	if (conn->type != ETYPE_SERVER) return 0;

	ulogf_ntc("Generating new keypair");
	if (crypto_box_keypair(conn->data.srv.keypair.pk, conn->data.srv.keypair.sk)) {
		ulogf_err("Failed to generate keypair");
		return 0;
	}
	return 1;
}

int
server_secure_keypair_import(netconn_t *restrict conn, const uint8_t *restrict in_keypair)
{
	if (!conn) return 0;
	if (conn->type != ETYPE_SERVER) return 0;
	memcpy(conn->data.srv.keypair.pk, in_keypair, sizeof(conn->data.srv.keypair.pk));
	memcpy(conn->data.srv.keypair.sk, in_keypair + sizeof(conn->data.srv.keypair.pk), sizeof(conn->data.srv.keypair.sk));
	return 1;
}

int
server_secure_keypair_export(netconn_t *restrict conn, uint8_t *restrict out_keypair)
{
	if (!conn) return 0;
	if (conn->type != ETYPE_SERVER) return 0;
	memcpy(out_keypair, conn->data.srv.keypair.pk, sizeof(conn->data.srv.keypair.pk));
	memcpy(out_keypair + sizeof(conn->data.srv.keypair.pk), conn->data.srv.keypair.sk, sizeof(conn->data.srv.keypair.sk));
	return 1;
}

int
server_listen(netconn_t *restrict conn, enum netconn_protocol proto, const char *restrict hostname, uint16_t port)
{
	int r = _conn_socket_init(conn, proto, hostname, port);
	if (!r) return r;
	return usock_udp_bind(&conn->udp_sock);
}

void
server_close(netconn_t *restrict conn, uint8_t restarting)
{
	if (!conn) return;
	if (conn->data.srv.is_closing) return;

	uint8_t reason = restarting? EDISCONNECT_SERVER_RESTARTING : EDISCONNECT_SERVER_CLOSING;

	struct srvclient 	*client;
	if (HASH_COUNT(conn->data.srv.connected_clients) > 0) {
		for (client = conn->data.srv.connected_clients; client != NULL; client = client->hh.next) {
			/* disconnect all clients */
			_server_client_disconnect(conn, client, reason);
		}
	}
	conn->data.srv.is_closing = 1;
}

void
server_cli_disconnect(netsrvclient_t *restrict client, enum netconn_disconnect_reason reason)
{
	if (!client) return;
	_server_client_disconnect(NULL, client, reason);
}

netsrvclient_t *
server_cli_get_next(netsrvclient_t *client)
{
	if (!client) return NULL;

	netsrvclient_t *next = client->hh.next;

	while (next) {
		if (next->common.status == EPROT_STATUS_CONNECTED)
			return next;
		next = next->hh.next;
	}

	return NULL;
}

void *
server_cli_get_userdata(netsrvclient_t *restrict client)
{
	if (!client) return NULL;
	return client->userdata;
}

uint16_t
server_cli_get_port(netsrvclient_t *restrict client)
{
	return ntohs(client->sockaddr.tcp_udp.sin_port);
}

char *
server_cli_get_addrstr(netsrvclient_t *restrict client)
{
	return inet_ntoa(client->sockaddr.tcp_udp.sin_addr);
}

int32_t
server_cli_sendmessage(netsrvclient_t *restrict client, const void *restrict buffer, const uint32_t size)
{
	if (!client) return -1;
	return netmsg_enqueue(&client->common.msgctx, buffer, size);
}

uint16_t
server_cli_get_tick_remote(netsrvclient_t *restrict client)
{
	if (!client) return 0;
	return client->common.tick_remote_latest;
}

float
server_cli_get_ping_ms(netsrvclient_t *restrict client, float tickrate)
{
	if (!client) return NAN;
	return client->common.round_trip_ticks_ema / (tickrate * 0.001f);
}

float
server_cli_get_ping_ticks(netsrvclient_t *restrict client)
{
	if (!client) return NAN;
	return client->common.round_trip_ticks_ema;
}

/********************************
 *		CLIENT PUBLIC API		*
 ********************************/

netconn_t *
client_init(const struct clievents events, const struct netsettings settings, void *userdata)
{
	netconn_t *conn = _conn_init(settings, userdata);
	if (!conn) return NULL;
	conn->data.cli.events = events;
	conn->type = ETYPE_CLIENT;

	if (!_conncommon_init(conn, &conn->data.cli.common)) {
		_conn_deinit(conn);
		return NULL;
	}

	return conn;
}

int
client_secure_pubkey_import(netconn_t *restrict conn, const uint8_t *restrict in_pubkey)
{
	if (!conn) return 0;
	if (conn->type != ETYPE_CLIENT) return 0;
	memcpy(conn->data.cli.srv_public_key, in_pubkey, sizeof(conn->data.cli.srv_public_key));
	return 1;
}

int
client_connect(netconn_t *restrict conn, enum netconn_protocol proto, const char *restrict hostname, uint16_t port)
{
	if (!_conn_socket_init(conn, proto, hostname, port)) return 0;
	
	if (!_conncommon_mtu_config(&conn->data.cli.common, &conn->udp_sock.addr)) {
		usock_udp_deinit(&conn->udp_sock);
		return 0;
	}
	/* call first onconnect */
	netmsg_reset(&conn->data.cli.common.msgctx);
	_client_netmsg_pack_connect((netconn_t **)&conn, NULL, 0);
	return 1;
}

void
client_disconnect(netconn_t *restrict conn)
{
	if (!conn) return;
	conn->data.cli.common.status = EPROT_STATUS_DISCONNECT;
	conn->data.cli.common.disconnect_reason = EDISCONNECT;
	conn->data.cli.common.tick_remote_latest = 0;
}

int32_t
client_sendmessage(netconn_t *restrict conn, const void *restrict buffer, const uint32_t size)
{
	if (!conn) return -1;
	if (conn->data.cli.common.status != EPROT_STATUS_CONNECTED) return -1;
	return netmsg_enqueue(&conn->data.cli.common.msgctx, buffer, size);
}

uint16_t
client_get_tick_remote(netconn_t *restrict conn)
{
	if (!conn) return 0;
	return conn->data.cli.common.tick_remote_latest;
}

float
client_get_ping_ms(netconn_t *restrict conn)
{
	if (!conn) return NAN;
	return conn->data.cli.common.round_trip_ticks_ema / (conn->settings.tick_rate * 0.001f);
}

float
client_get_ping_ticks(netconn_t *restrict conn)
{
	if (!conn) return NAN;
	return conn->data.cli.common.round_trip_ticks_ema;
}

/********************************
 *		GENERIC PUBLIC API		*
 ********************************/

void
conn_free(netconn_t **conn)
{
	if (!conn)	return;
	if (!*conn)	return;

	if ((*conn)->type == ETYPE_SERVER)
		server_cleanup(*conn);

	if ((*conn)->type == ETYPE_CLIENT)
		_conncommon_deinit(&(*conn)->data.cli.common);

	_conn_deinit(*conn);
	*conn = NULL;
}

inline void
conn_tick(netconn_t **conn)
{
	if (!conn) 	return;
	if (!*conn) return;

	switch ((*conn)->type) {
		case ETYPE_CLIENT: client_tick(conn); break;
		case ETYPE_SERVER: server_tick(conn); break;
	}
}

inline int
conn_recv(netconn_t **conn)
{
	if (!conn) 	return 0;
	if (!*conn) return 0;

	switch ((*conn)->type) {
		case ETYPE_CLIENT:
			return _client_process_recv(conn);
		case ETYPE_SERVER:
			if (!(*conn)->data.srv.is_closing)
				return _server_process_recv(*conn);
			break;
	}
	return 0;
}

inline int_fast64_t
conn_process_non_blocking(netconn_t **conn)
{
	if (!conn)	return 0;
	if (!*conn)	return 0;

	conn_recv(conn);
	if (!*conn)	return 0;

	/* handle idle server */
	if ((*conn)->type == ETYPE_SERVER) {
		int_fast64_t idle_sleep = (*conn)->settings.idle_sleep_seconds;
		if (idle_sleep) {
			if (HASH_COUNT((*conn)->data.srv.connected_clients) == 0) {
				idle_sleep *= 1000000;
				utime_usleep(idle_sleep);
				utime_remaining(&(*conn)->timing, idle_sleep);
			}
		}
	}

	const int_fast64_t target_us = (*conn)->tick_time_target_us;
	const int_fast64_t remaining_us = utime_remaining(&(*conn)->timing, target_us);

	if (remaining_us <= 0) {

		/* handle underrun */
		if (remaining_us < -(int_fast64_t)(target_us * 0.05)) {
			(*conn)->tick_time_underrun_us += -remaining_us;
		} else {
			(*conn)->tick_time_underrun_us = 0;
		}

		int_fast64_t underrun = (*conn)->tick_time_underrun_us;
		if (underrun >= target_us) {
			/* log only once per second */
			if ((*conn)->tick_underrun_count++ == 1000000L / (target_us + (-remaining_us))) {
				ulogf_alr("Can't keep up. Running %" PRIi64 " ticks behind.", (int64_t)(underrun / target_us));
				(*conn)->tick_underrun_count = 0;
				(*conn)->tick_time_underrun_us = 0;
			}
		}

		conn_tick(conn);
	}
	return remaining_us;
}

inline void
conn_process_blocking_busy(netconn_t **conn)
{
	int_fast64_t remaining_us;
	do {
		remaining_us = conn_process_non_blocking(conn);
	} while (remaining_us > 0);
}

void
conn_process_blocking_relaxed(netconn_t **conn, double relax_ratio)
{
	if (!conn)	return;
	if (!*conn)	return;

	int_fast64_t margin = (*conn)->tick_time_margin_us;
	int_fast64_t remaining_us = conn_process_non_blocking(conn);

	int_fast64_t relaxed_us = remaining_us * relax_ratio;

	if (relaxed_us > margin) {
		utime_t t = {0};
		utime_remaining(&t, relaxed_us);
		remaining_us = relaxed_us;
		int cnt = 20;
		while (remaining_us > margin && cnt) {
			cnt--;
			if (conn_recv(conn)) {
				cnt = 20;
				utime_usleep(10);
			}
			remaining_us = utime_remaining(&t, relaxed_us);
		}
		relaxed_us = remaining_us;
	}

	if (relaxed_us > margin)
		utime_usleep(relaxed_us);

	conn_process_blocking_busy(conn);
}

uint16_t
conn_get_tick_local(netconn_t *restrict conn)
{
	if (!conn) return 0;
	return conn->tick_local;
}

uint16_t
conn_get_tick_rate(netconn_t *restrict conn)
{
	if (!conn) return 0;
	return conn->settings.tick_rate;
}

const struct netstats *
conn_get_stats(netconn_t *restrict conn)
{
	return (const struct netstats *)&conn->stats;
}
