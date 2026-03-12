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

#include <assert.h>
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

enum {
	ETYPE_SERVER = 0,
	ETYPE_CLIENT
};

enum {
	EPROT_STATUS_SIZE = 2,
	
	EPROT_STATUS_CONNECT = 0,
	EPROT_STATUS_CONNECTED,
	EPROT_STATUS_DISCONNECT,

	/* not sent through network */
	EPROT_STATUS_DISCONNECT_PENDING
};

enum {
	EHANDSHAKE_STATUS_NONE = 0,
	EHANDSHAKE_STATUS_TICK_SYNC,
	EHANDSHAKE_STATUS_SERVER_OK,
	EHANDSHAKE_STATUS_CLIENT_OK,
};

#define SERVER_BUFFER_LEN UINT16_MAX

#define SOCKADDR_TO_KEY(sockaddr) \
    ((((uint64_t)(sockaddr.sin_addr.s_addr)) << 16) | \
     ((uint64_t)(sockaddr.sin_port)))

/* struct that holds common data */
struct conncommon {
	uint16_t 	tick_local_noresp_count;
	uint16_t 	tick_local;
	uint16_t 	tick_remote_latest;
	uint16_t 	tick_remote;
	uint16_t 	send_skip_count;

	uint8_t 	status_local;
	uint8_t 	status_remote;
	uint8_t 	disconnect_reason;
	uint8_t 	handshake_status;
	uint8_t 	secure;

	netmsg_ctx_t 		msgctx;
	crypto_ctx_t 		crypto;
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

static inline int32_t
tick_diff(uint16_t x, uint16_t y)
{
	int32_t z = x - y;
	return z > 32768? z - 65536 : (z < -32768? z + 65536 : z);
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

static inline void
_conn_udp_send(netconn_t *restrict conn, usocket_addr_t *restrict addr)
{
	size_t length = packet_get_length(conn->out_packet);
	if (usock_udp_send(&conn->udp_sock, addr, conn->out_buffer, length))
		conn->stats.total_sent_bytes += length;
}

static inline int
_conn_payload_from_secure(netconn_t *restrict conn, struct conncommon *restrict c)
{
	int ret = tick_remote_applicable(c->tick_remote, c->tick_remote_latest, c->tick_local, conn->settings.expected_tick_tolerance) || c->tick_local_noresp_count > 16384;
	if (!ret) return 0;

	packet_rewind(conn->payload_packet);
	int32_t nonce_diff = tick_diff(c->tick_remote, c->tick_remote_latest);
	if (c->handshake_status >= EHANDSHAKE_STATUS_SERVER_OK) {
		/* add rx nonce */
		crypto_nonce_add(&c->crypto.rx, nonce_diff);
		c->crypto.auth_rx.nonce += nonce_diff;

		/* refuses unauthenticated packets after handshake */
		if (c->secure == ESECURE_NONE) {
			c->tick_local 			= c->tick_remote;
			c->tick_remote_latest 	= c->tick_remote;
			c->tick_local_noresp_count = 0;
			return 0;
		}
	} else if (c->secure == ESECURE_NONE) {
		/* passthrough */
		ulogf_dbg("Received passthrough payload, remote: %d", c->tick_remote);
		packet_rw_packet(conn->in_packet, conn->payload_packet, packet_get_readable(conn->in_packet));
	}

	if (c->secure == ESECURE_ENCRYPT) {
		ulogf_dbg("Received: self_tick: %d, tick_remote: %d, rx nonce[0]: %d, diff: %d", conn->tick_local, c->tick_remote, c->crypto.rx.data[0], nonce_diff);
		/* decrypt */
		ret = !crypto_decrypt_packet(&c->crypto.rx, conn->in_packet, conn->payload_packet);

	} else if (c->secure == ESECURE_AUTH) {
		ulogf_dbg("Received authenticated payload");
		uint8_t rx_hash[crypto_shorthash_BYTES];
		uint8_t hash[crypto_shorthash_BYTES];
		uint8_t *nonce = conn->in_packet->data + conn->in_packet->index;

		/* store received hash */
		if (packet_r(conn->in_packet, rx_hash, sizeof(rx_hash)))
			return 0;

		/* overwrite received hash with nonce */
		memcpy(nonce, &c->crypto.auth_rx.nonce, sizeof(c->crypto.auth_rx.nonce));

		/* hash */
		if (crypto_shorthash(hash, conn->in_packet->data, conn->in_packet->length, c->crypto.auth_rx.key))
			return 0;

		/* verify authenticity */
		if (memcmp(hash, rx_hash, sizeof(hash)) != 0)
			return 0;

		/* passthrough */
		packet_rw_packet(conn->in_packet, conn->payload_packet, packet_get_readable(conn->in_packet));
	}

	packet_rewind(conn->payload_packet);
	if (ret) {
		c->tick_local 			= c->tick_remote;
		c->tick_remote_latest 	= c->tick_remote;
		c->tick_local_noresp_count = 0;
	}
	return ret;
}

static inline int
_conn_payload_secure(netconn_t *restrict conn, struct conncommon *restrict c)
{
	packet_rewind(conn->payload_packet);
	if (c->handshake_status == EHANDSHAKE_STATUS_CLIENT_OK) {
		uint8_t secure = conn->settings.secure;
		if (conn->payload_packet->length == 0)
			secure = ESECURE_AUTH;

		packet_w_bits(conn->out_packet, secure, 2);

		if (secure == ESECURE_ENCRYPT) {
			ulogf_dbg("Write encrypted; tick: %d, tick_local: %d, tx nonce[0]: %d", conn->tick_local, c->tick_local, c->crypto.tx.data[0]);
			crypto_encrypt_packet(&c->crypto.tx, conn->payload_packet, conn->out_packet);
		} else if (secure == ESECURE_AUTH) {
			ulogf_dbg("Write authenticated");
			uint8_t hash[crypto_shorthash_BYTES];

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
			packet_rw_packet(conn->payload_packet, conn->out_packet, packet_get_length(conn->payload_packet));
		}
	} else {
		ulogf_dbg("Write unauthenticated");
		packet_w_bits(conn->out_packet, ESECURE_NONE, 2);
		packet_rw_packet(conn->payload_packet, conn->out_packet, packet_get_length(conn->payload_packet));
	}

	return 1;
}

static inline void
_send_disconnect(netconn_t *restrict conn, usocket_addr_t *restrict cli_addr, uint8_t reason, struct conncommon *restrict c)
{
	packet_rewind(conn->out_packet);
	packet_w_16_t(conn->out_packet, &conn->tick_local);
	packet_w_bits(conn->out_packet, EPROT_STATUS_DISCONNECT, EPROT_STATUS_SIZE);
	packet_rewind(conn->payload_packet);
	packet_w_8_t(conn->payload_packet, &reason);
	if (c) _conn_payload_secure(conn, c);
	_conn_udp_send(conn, cli_addr);
	ulogf_dbg("Sent client disconnect: %s:%d", inet_ntoa(cli_addr->tcp_udp.sin_addr), ntohs(cli_addr->tcp_udp.sin_port));
}

static inline void
_server_client_disconnect(netconn_t *restrict conn, netsrvclient_t *c, uint8_t reason)
{
	if (!c->common.disconnect_reason)
		c->common.disconnect_reason = reason;
	if (conn) {
		conn->data.srv.events.ondisconnect(conn, conn->userdata, c->common.disconnect_reason, c, &c->userdata);
		c->common.status_local = EPROT_STATUS_DISCONNECT;
	} else {
		c->common.status_local = EPROT_STATUS_DISCONNECT_PENDING;
	}
	c->common.tick_remote_latest = 0;
}

static inline void
_server_client_free(netconn_t *restrict conn, netsrvclient_t *c)
{
	ulogf_dbg("Removed client: %s:%d", server_cli_get_addrstr(c), server_cli_get_port(c));
	HASH_DEL(conn->data.srv.connected_clients, c);
	netmsg_deinit(&c->common.msgctx);
	ufree(c);
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

	if (!netmsg_init(&client->common.msgctx, 32)) {
		ufree(client);
		return NULL;
	}

	client->id = cli_id;
	memcpy(&client->sockaddr, cli_addr, sizeof(*cli_addr));

	HASH_ADD(hh, conn->data.srv.connected_clients, id, sizeof(cli_id), client);

	if (ufavonet_global.uthash_oom) {
		netmsg_deinit(&client->common.msgctx);
		ufree(client);
		ulogf_crt("uthash OOM");
		ufavonet_global.uthash_oom = 0;
		return NULL;
	}
	ulogf_dbg("Initialized client: %s:%d", server_cli_get_addrstr(client), server_cli_get_port(client));
	return client;
}

static inline void
_client_disconnect(netconn_t **__conn, uint8_t reason)
{
	netconn_t *conn = *__conn;
	struct conncommon *s = &conn->data.cli.common;

	/* hold until the server replies. unless it's a timeout */
	if (s->status_remote == EPROT_STATUS_DISCONNECT || reason == EDISCONNECT_TIMEOUT) {
		conn->data.cli.events.ondisconnect(__conn, conn->userdata, reason);
		if (!*__conn) return;
		s->status_remote = EPROT_STATUS_DISCONNECT;
	}

	s->status_local = EPROT_STATUS_DISCONNECT;
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
	_conn_netmsg_unpack_all(&client->common.msgctx, p_in, {
		if (conn->data.srv.events.onreceivemsg)
			conn->data.srv.events.onreceivemsg(conn, conn->userdata, data, size, client);
	}, {
		_server_client_disconnect(conn, client, EDISCONNECT_INTERNAL_ERROR);
		return 0;
	}, {
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
									conn->tick_local, client->common.tick_remote,
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
			client->common.tick_local 			= client->common.tick_remote + 32768;
			client->common.tick_remote_latest 	= client->common.tick_remote + 32768;
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
			client->common.status_local = EPROT_STATUS_CONNECTED;
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
		_server_client_disconnect(conn, client, EDISCONNECT_INTERNAL_ERROR);
		return 0;
	}, {
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
	_conn_netmsg_unpack_all(&conn->data.cli.common.msgctx, p_in, {
		if (conn->data.cli.common.status_remote == EPROT_STATUS_CONNECT) {
			if (once) {
				ulogf_ntc("Protocol violation: Server sent more then one message at a time during connect stage.");
				_client_disconnect(__conn, EDISCONNECT_PROTOCOL_VIOLATION);
				return 0;
			}
			if (!_client_netmsg_pack_connect(__conn, data, size))
				return 0;
			once++;
		} else if (conn->data.cli.events.onreceivemsg)
			conn->data.cli.events.onreceivemsg(conn, conn->userdata, data, size);
	}, {
		_client_disconnect(__conn, EDISCONNECT_INTERNAL_ERROR);
		return 0;
	}, {
		_client_disconnect(__conn, EDISCONNECT_PROTOCOL_VIOLATION);
		return 0;
	});
	return 1;
}

#undef _conn_netmsg_unpack_all


static inline int
_conn_recv(netconn_t *restrict conn, usocket_addr_t *restrict addr, uint16_t *restrict remote_tick, uint8_t *restrict remote_status, uint8_t *restrict secure)
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
	err = packet_r_16_t(conn->in_packet, remote_tick);
	if (err) return 0;
	err = packet_r_bits(conn->in_packet, remote_status, EPROT_STATUS_SIZE);
	if (err) return 0;
	err = packet_r_bits(conn->in_packet, secure, 2);
	if (err) return 0;

	return 1;
}

static inline void
_conncommon_tick(struct conncommon *restrict c)
{
	c->tick_local++;

	if (c->handshake_status >= EHANDSHAKE_STATUS_SERVER_OK) {
		/* Add tx nonce */
		crypto_nonce_add(&c->crypto.tx, 1);
		c->crypto.auth_tx.nonce += 1;
	}
}


static inline netsrvclient_t *
_server_recv(netconn_t *restrict conn)
{
	usocket_addr_t 	cli_addr = {0};

	uint16_t 	remote_tick;
	uint8_t 	remote_status;
	uint8_t 	secure;

	if (!_conn_recv(conn, &cli_addr, &remote_tick, &remote_status, &secure))
		return NULL;


	/* Find client by id */
	netsrvclient_t 	*client = NULL;
	uint64_t 		cli_id 	= SOCKADDR_TO_KEY(cli_addr.tcp_udp);
	HASH_FIND(hh, conn->data.srv.connected_clients, &cli_id, sizeof(cli_id), client);

	if (!client) {
		if (remote_status != EPROT_STATUS_CONNECT || secure != ESECURE_NONE) {
			ulogf_dbg("Client already disconnected");
			/* Already disconnected. Reinforce disconnection. */
			_send_disconnect(conn, &cli_addr, EDISCONNECT_NONE, NULL);
			return NULL;
		}

		if (conn->data.srv.is_closing)
			return NULL;

		/* initialize client */
		client = _server_client_init(conn, &cli_addr, cli_id);
		if (!client) {
			_send_disconnect(conn, &cli_addr, EDISCONNECT_INTERNAL_ERROR, NULL);
			ulogf_wrn("Failed to initialize client");
			return NULL;
		}
		client->common.tick_remote_latest	= remote_tick;
		client->common.tick_local			= remote_tick;
		/* the client is the one that needs to catch up with the server */
		client->common.handshake_status 	= EHANDSHAKE_STATUS_TICK_SYNC;
	}

	client->common.tick_remote = remote_tick;
	client->common.status_remote = remote_status;
	client->common.secure = secure;
	return client;
}

static inline void
_server_process_recv(netconn_t *restrict conn)
{
	int i;
	/* Receive data from clients */
	for (i = 2; i;) {
		netsrvclient_t *c = _server_recv(conn);
		if (!c) { i--; continue; }
		
		int applicable = _conn_payload_from_secure(conn, &c->common);
		if (!applicable) continue;

		/* handle disconnection */
		if (c->common.status_remote == EPROT_STATUS_DISCONNECT) {
			/* handle disconnection initiated by the client */
			if (c->common.status_local != EPROT_STATUS_DISCONNECT) {
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

		if (c->common.status_local == EPROT_STATUS_DISCONNECT)
			continue;

		if (c->common.status_local == EPROT_STATUS_DISCONNECT_PENDING) {
			_server_client_disconnect(conn, c, c->common.disconnect_reason);
			continue;
		}

		if (conn->data.srv.is_closing)
			continue;


		/* handle connect */
		if (c->common.status_remote == EPROT_STATUS_CONNECT) {
			if (c->common.status_local == EPROT_STATUS_CONNECT) {
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
		_conncommon_tick(&client->common);

		/* handle server kick */
		if (client->common.status_local == EPROT_STATUS_DISCONNECT_PENDING)
			_server_client_disconnect(conn, client, client->common.disconnect_reason);

		/* handle disconnected */
		if (client->common.status_local == EPROT_STATUS_DISCONNECT) {
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

			const uint16_t timeout_ticks = client->common.status_local == EPROT_STATUS_CONNECT? conn->settings.pending_conn_timeout_tick : conn->settings.timeout_tick;
			if (client->common.tick_local_noresp_count == timeout_ticks) {
				_send_disconnect(conn, &client->sockaddr, client->common.disconnect_reason, &client->common);
				_server_client_disconnect(conn, client, EDISCONNECT_TIMEOUT);
				goto next_client;
			}
		}

		if (client->common.status_local != EPROT_STATUS_CONNECTED && client->common.status_local != EPROT_STATUS_CONNECT)
			goto next_client;

		/* prepare packet */
		packet_rewind(conn->out_packet);
		packet_w_16_t(conn->out_packet, &conn->tick_local);
		packet_w_bits(conn->out_packet, client->common.status_local, EPROT_STATUS_SIZE);
		packet_rewind(conn->payload_packet);

		/* write messages */
		int32_t err = netmsg_pack(&client->common.msgctx, conn->payload_packet);
		if (err != ENETMSG_ERR_NONE) {
			ulogf_crt("Failed to pack messages. Dropping connection. Err: %" PRIi32, err);
			_server_client_disconnect(conn, client, EDISCONNECT_INTERNAL_ERROR);
			_send_disconnect(conn, &client->sockaddr, EDISCONNECT_INTERNAL_ERROR, &client->common);
			continue;
		}

		if (client->common.status_local == EPROT_STATUS_CONNECTED) {
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

		_conn_payload_secure(conn, &client->common);
		_conn_udp_send(conn, &client->sockaddr);

next_client:
		client = client->hh.next;
	}
}

static inline void
_client_process_recv(netconn_t **__conn)
{
	netconn_t *conn = *__conn;
	struct conncommon *s = &conn->data.cli.common;

	if (s->status_local == EPROT_STATUS_DISCONNECT &&
		s->status_remote == EPROT_STATUS_DISCONNECT)
		return;

	while (1) {
		if (!_conn_recv(conn, &conn->udp_sock.addr, &s->tick_remote, &s->status_remote, &s->secure))
			return;

		/* sync first tick */
		if (s->handshake_status == EHANDSHAKE_STATUS_NONE) {
			s->tick_local 			= s->tick_remote;
			s->tick_remote_latest 	= s->tick_remote;
			s->handshake_status 	= EHANDSHAKE_STATUS_TICK_SYNC;
		}
		
		int applicable = _conn_payload_from_secure(conn, s);
		if (!applicable) continue;

		/* handle disconnection */
		if (s->status_local == EPROT_STATUS_DISCONNECT)
			return;

		if (s->status_remote == EPROT_STATUS_DISCONNECT) {
			uint8_t reason;
			if (packet_r_8_t(conn->payload_packet, &reason))
				reason = EDISCONNECT;
			/* report back to the server */
			_send_disconnect(conn, &conn->udp_sock.addr, reason, s);
			_client_disconnect(__conn, reason);
			return;
		}

		/* handle messages */
		if (!_client_netmsg_unpack_all(__conn, conn->payload_packet)) {
			/* error. connection being dropped. */
			return;
		}

		s->status_local = s->status_remote;
		if (s->status_remote == EPROT_STATUS_CONNECT)
			continue;
		
		conn->data.cli.events.onreceivepkt(conn, conn->userdata, conn->payload_packet);
	}
}

static inline void
_client_process_send(netconn_t **__conn)
{
	if (!__conn) 	return;
	if (!*__conn) 	return;

	netconn_t *conn = *__conn;
	struct conncommon *s = &conn->data.cli.common;

	/* server tick */
	_conncommon_tick(s);

	/* Handle disconnect */
	if (s->status_remote == EPROT_STATUS_DISCONNECT) {
		_client_disconnect(__conn, s->disconnect_reason);
		return;
	}

	if (s->status_local == EPROT_STATUS_DISCONNECT) {
		if (s->tick_remote_latest++ == conn->settings.kick_notice_tick) {
			/* Disconnect notice already sent multiple times */
			s->status_remote = EPROT_STATUS_DISCONNECT;
			_client_disconnect(__conn, s->disconnect_reason);
			return;
		}
		_send_disconnect(conn, &conn->udp_sock.addr, conn->data.cli.common.disconnect_reason, s);
		return;
	}

	/* handle timeout */
	{
		s->tick_local_noresp_count++;

		const uint16_t timeout_ticks = s->status_local == EPROT_STATUS_CONNECT? conn->settings.pending_conn_timeout_tick : conn->settings.timeout_tick;
		if (s->tick_local_noresp_count == timeout_ticks) {
			_client_disconnect(__conn, EDISCONNECT_TIMEOUT);
			return;
		}
	}

	
	/* prepare packet */
	packet_rewind(conn->out_packet);
	packet_w_16_t(conn->out_packet, &conn->tick_local);
	packet_w_bits(conn->out_packet, s->status_local, EPROT_STATUS_SIZE);
	packet_rewind(conn->payload_packet);

	/* write messages */
	int32_t err = netmsg_pack(&conn->data.cli.common.msgctx, conn->payload_packet);
	if (err != ENETMSG_ERR_NONE) {
		ulogf_crt("Failed to pack messages. Dropping connection. Err: %" PRIi32, err);
		_send_disconnect(conn, &conn->udp_sock.addr, EDISCONNECT_INTERNAL_ERROR, s);
		_client_disconnect(__conn, EDISCONNECT_INTERNAL_ERROR);
		return;
	}

	if (s->status_local != EPROT_STATUS_CONNECT) {
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

	_conn_payload_secure(conn, s);
	_conn_udp_send(conn, &conn->udp_sock.addr);
}

static inline netconn_t *
_conn_init(const struct netsettings settings, void *userdata)
{
	assert(NETCONN_SECURE_KEYPAIR_SIZE == (crypto_box_PUBLICKEYBYTES + crypto_box_SECRETKEYBYTES));
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
			if (client->common.status_local != EPROT_STATUS_DISCONNECT)
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
		if (next->common.status_local == EPROT_STATUS_CONNECTED)
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
	if (client->common.status_local != EPROT_STATUS_CONNECTED) return -1;
	return netmsg_enqueue(&client->common.msgctx, buffer, size);
}

uint16_t
server_cli_get_external_tick(netsrvclient_t *restrict client)
{
	if (!client) return 0;
	return client->common.tick_remote_latest;
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
	if (!netmsg_init(&conn->data.cli.common.msgctx, 128)) {
		_conn_deinit(conn);
		return NULL;
	}

	/* call first onconnect */
	_client_netmsg_pack_connect(&conn, NULL, 0);
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
	return _conn_socket_init(conn, proto, hostname, port);
}

void
client_disconnect(netconn_t *restrict conn)
{
	if (!conn) return;
	conn->data.cli.common.status_local = EPROT_STATUS_DISCONNECT;
	conn->data.cli.common.disconnect_reason = EDISCONNECT;
}

int32_t
client_sendmessage(netconn_t *restrict conn, const void *restrict buffer, const uint32_t size)
{
	if (!conn) return -1;
	if (conn->data.cli.common.status_local != EPROT_STATUS_CONNECTED) return -1;
	return netmsg_enqueue(&conn->data.cli.common.msgctx, buffer, size);
}

uint16_t
client_get_remote_tick(netconn_t *restrict conn)
{
	if (!conn) return 0;
	return conn->data.cli.common.tick_remote_latest;
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

inline int_fast64_t
conn_process_non_blocking(netconn_t **conn)
{
	if (!conn)	return 0;
	if (!*conn)	return 0;

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

const struct netstats *
conn_get_stats(netconn_t *restrict conn)
{
	return (const struct netstats *)&conn->stats;
}
