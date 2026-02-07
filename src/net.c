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

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "_hooks.h"
#include "usocket.c"
#include "netmsg.h"
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
};

/* struct that represents a client in the server */
struct srvclient {
	struct conncommon 	common;
	usocket_addr_t 		sockaddr;
	netmsg_ctx_t 		msgctx;
	void 				*userdata;

	/* Hash table stuff */
	uint64_t 		id;
	UT_hash_handle 	hh;
};

/* struct that holds data needed by a client */
struct cliconn {
	struct clievents 	events;
	struct conncommon 	common;	
	netmsg_ctx_t 		msgctx;
};

/* struct that holds data needed by a server */
struct srvconn {
	uint_fast8_t 		is_closing;
	struct srvevents 	events;
	struct srvclient 	*connected_clients;
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
	
	usocket_t 			udp_sock;

	union {
		struct srvconn 	srv;
		struct cliconn 	cli;
	} data;

	void 				*userdata;

	packet_t 			*in_packet;
	packet_t 			*out_packet;
	uint8_t 			in_buffer[65535];
	uint8_t 			out_buffer[65535];
};

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

static inline void
_send_disconnect(netconn_t *restrict conn, usocket_addr_t *restrict cli_addr, uint8_t reason)
{
	packet_rewind(conn->out_packet);
	packet_w_16_t(conn->out_packet, &conn->tick_local);
	packet_w_bits(conn->out_packet, EPROT_STATUS_DISCONNECT, EPROT_STATUS_SIZE);
	packet_w_8_t(conn->out_packet, &reason);
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
	netmsg_deinit(&c->msgctx);
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

	if (!netmsg_init(&client->msgctx, 32)) {
		ufree(client);
		return NULL;
	}

	client->id = cli_id;
	memcpy(&client->sockaddr, cli_addr, sizeof(*cli_addr));

	HASH_ADD(hh, conn->data.srv.connected_clients, id, sizeof(cli_id), client);

	if (ufavonet_global.uthash_oom) {
		netmsg_deinit(&client->msgctx);
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
	_conn_netmsg_unpack_all(&client->msgctx, p_in, {
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

/* Returns 0 on failure (connection being terminated) */
static inline int
_client_netmsg_unpack_all(netconn_t **__conn, packet_t *restrict p_in)
{
	netconn_t *conn = *__conn;
	_conn_netmsg_unpack_all(&conn->data.cli.msgctx, p_in, {
		if (conn->data.cli.events.onreceivemsg)
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
_conn_recv(netconn_t *restrict conn, usocket_addr_t *restrict addr, uint16_t *restrict remote_tick, uint8_t *restrict remote_status)
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

	/* Read header */
	err = packet_r_16_t(conn->in_packet, remote_tick);
	if (err) return 0;
	err = packet_r_bits(conn->in_packet, remote_status, EPROT_STATUS_SIZE);
	if (err) return 0;

	return 1;
}

static inline netsrvclient_t *
_server_recv(netconn_t *restrict conn)
{
	usocket_addr_t 	cli_addr = {0};

	uint16_t 	remote_tick;
	uint8_t 	remote_status;

	if (!_conn_recv(conn, &cli_addr, &remote_tick, &remote_status))
		return NULL;


	/* Find client by id */
	netsrvclient_t 	*client = NULL;
	uint64_t 		cli_id 	= SOCKADDR_TO_KEY(cli_addr.tcp_udp);
	HASH_FIND(hh, conn->data.srv.connected_clients, &cli_id, sizeof(cli_id), client);

	if (!client) {
		if (remote_status != EPROT_STATUS_CONNECT) {
			ulogf_dbg("Client already disconnected");
			/* Already disconnected. Reinforce disconnection. */
			_send_disconnect(conn, &cli_addr, EDISCONNECT_NONE);
			return NULL;
		}

		if (conn->data.srv.is_closing)
			return NULL;

		/* initialize client */
		client = _server_client_init(conn, &cli_addr, cli_id);
		if (!client) {
			_send_disconnect(conn, &cli_addr, EDISCONNECT_INTERNAL_ERROR);
			ulogf_wrn("Failed to initialize client");
			return NULL;
		}
		client->common.tick_remote_latest	= remote_tick;
		client->common.tick_local			= remote_tick;
	}

	client->common.tick_remote = remote_tick;
	client->common.status_remote = remote_status;
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

		/* handle disconnection */
		if (c->common.status_remote == EPROT_STATUS_DISCONNECT) {
			/* handle disconnection initiated by the client */
			if (c->common.status_local != EPROT_STATUS_DISCONNECT) {
				ulogf_dbg("Client initiated disconnection");
				uint8_t reason;
				/* Fallback to generic disconnect if reading the reason fails. */
				if (packet_r_8_t(conn->in_packet, &reason))
					reason = EDISCONNECT;
				_server_client_disconnect(conn, c, reason);
				_send_disconnect(conn, &c->sockaddr, reason);
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


		uint8_t tick_applicable = tick_remote_applicable(c->common.tick_remote, c->common.tick_remote_latest, c->common.tick_local, conn->settings.expected_tick_tolerance);


		/* handle connect */
		if (c->common.status_remote == EPROT_STATUS_CONNECT) {
			if (c->common.status_local == EPROT_STATUS_CONNECT) {
				/* call onconnect */
				packet_rewind(conn->out_packet);
				packet_w_16_t(conn->out_packet, &conn->tick_local);
				packet_w_bits(conn->out_packet, c->common.status_local, EPROT_STATUS_SIZE);
				switch((enum netconn_connect_result)conn->data.srv.events.onconnect(conn, conn->userdata, conn->in_packet, conn->out_packet, c, &c->userdata)) {
					case ECONNECTION_ALLOW:
						c->common.status_local 			= EPROT_STATUS_CONNECTED;
						c->common.tick_local 			= c->common.tick_remote;
						c->common.tick_remote_latest 	= c->common.tick_remote;
						break;
					case ECONNECTION_REFUSE:
						_server_client_disconnect(conn, c, EDISCONNECT_REFUSED);
						break;
					case ECONNECTION_AGAIN:
						_conn_udp_send(conn, &c->sockaddr);
						break;
				}
			}
			continue;
		}


		/* handle default EPROT_STATUS_CONNECTED behaviour */
		if (tick_applicable || c->common.tick_local_noresp_count > 16384) {
			c->common.tick_local 			= c->common.tick_remote;
			c->common.tick_remote_latest 	= c->common.tick_remote;

			/* handle messages */
			if (!_server_netmsg_unpack_all(conn, c, conn->in_packet)) {
				/* error. client being dropped. */
				continue;
			}

			/* call onreceive */
			conn->data.srv.events.onreceivepkt(conn, conn->userdata, conn->in_packet, c, c->userdata);

			c->common.tick_local_noresp_count = 0;
		}

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
		client->common.tick_local++;

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
			_send_disconnect(conn, &client->sockaddr, client->common.disconnect_reason);
			goto next_client;
		}

		/* handle timeout */
		{
			client->common.tick_local_noresp_count++;

			const uint16_t timeout_ticks = client->common.status_local == EPROT_STATUS_CONNECT? conn->settings.pending_conn_timeout_tick : conn->settings.timeout_tick;
			if (client->common.tick_local_noresp_count == timeout_ticks) {
				_send_disconnect(conn, &client->sockaddr, client->common.disconnect_reason);
				_server_client_disconnect(conn, client, EDISCONNECT_TIMEOUT);
				goto next_client;
			}
		}

		if (client->common.status_local != EPROT_STATUS_CONNECTED)
			goto next_client;

		/* prepare packet */
		packet_rewind(conn->out_packet);
		packet_w_16_t(conn->out_packet, &conn->tick_local);
		packet_w_bits(conn->out_packet, client->common.status_local, EPROT_STATUS_SIZE);
		
		const uint32_t write_op_cnt = packet_get_write_op_count(conn->out_packet);

		/* write messages */
		int32_t err = netmsg_pack(&client->msgctx, conn->out_packet);
		if (err != ENETMSG_ERR_NONE) {
			ulogf_crt("Failed to pack messages. Dropping connection. Err: %" PRIi32, err);
			_server_client_disconnect(conn, client, EDISCONNECT_INTERNAL_ERROR);
			_send_disconnect(conn, &client->sockaddr, EDISCONNECT_INTERNAL_ERROR);
			continue;
		}

		/* call onsend */
		conn->data.srv.events.onsendpkt(conn, conn->userdata, conn->out_packet, client, client->userdata);

		/* netmsg_pack() always perform at least one write operation.
		 * The packet must be sent if netmsg_pack() performed more then
		 * one write or onsendpkt() performed one or more writes. */
		if (packet_get_write_op_count(conn->out_packet) == write_op_cnt + 1) {
			/* avoid sending empty packets if possible */
			if (client->common.send_skip_count++ < conn->settings.timeout_tick / 8)
				goto next_client;
			client->common.send_skip_count = 0;
		}

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
		if (!_conn_recv(conn, &conn->udp_sock.addr, &s->tick_remote, &s->status_remote))
			return;

		/* handle disconnection */
		if (s->status_local == EPROT_STATUS_DISCONNECT)
			return;

		if (s->status_remote == EPROT_STATUS_DISCONNECT) {
			uint8_t reason;
			if (packet_r_8_t(conn->in_packet, &reason))
				reason = EDISCONNECT;
			/* report back to the server */
			_send_disconnect(conn, &conn->udp_sock.addr, reason);
			_client_disconnect(__conn, reason);
			return;
		}


		uint8_t tick_applicable = tick_remote_applicable(s->tick_remote, s->tick_remote_latest, s->tick_local, conn->settings.expected_tick_tolerance);


		/* apply */
		if (tick_applicable) {
			s->tick_remote_latest 		= s->tick_remote;
			s->tick_local 				= s->tick_remote;
			s->tick_local_noresp_count	= 0;

			/* handle messages */
			if (!_client_netmsg_unpack_all(__conn, conn->in_packet)) {
				/* error. connection being dropped. */
				return;
			}

			if (s->tick_remote == EPROT_STATUS_CONNECT) {
				packet_rewind(conn->out_packet);
				packet_w_16_t(conn->out_packet, &conn->tick_local);
				packet_w_bits(conn->out_packet, s->status_local, EPROT_STATUS_SIZE);
				conn->data.cli.events.onconnect(conn, conn->userdata, conn->in_packet, conn->out_packet);
				continue;
			}
			
			/* call onreceive */
			conn->data.cli.events.onreceivepkt(conn, conn->userdata, conn->in_packet);
			s->status_local = s->status_remote;
		}
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
	conn->data.cli.common.tick_local++;

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
		_send_disconnect(conn, &conn->udp_sock.addr, conn->data.cli.common.disconnect_reason);
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

	/* handle connect */
	if (s->status_local == EPROT_STATUS_CONNECT) {
		/* out packet already prepared by client_init func. 
		 * overriding the tick number is safe (granted to be the first 2 bytes). */
		uint32_t length = packet_get_length(conn->out_packet);
		packet_rewind(conn->out_packet);
		packet_w_16_t(conn->out_packet, &conn->tick_local);
		packet_set_length(conn->out_packet, length);
		_conn_udp_send(conn, &conn->udp_sock.addr);
		return;
	}
	
	/* prepare packet */
	packet_rewind(conn->out_packet);
	packet_w_16_t(conn->out_packet, &conn->tick_local);
	packet_w_bits(conn->out_packet, s->status_local, EPROT_STATUS_SIZE);

	const uint32_t write_op_cnt = packet_get_write_op_count(conn->out_packet);

	/* write messages */
	int32_t err = netmsg_pack(&conn->data.cli.msgctx, conn->out_packet);
	if (err != ENETMSG_ERR_NONE) {
		ulogf_crt("Failed to pack messages. Dropping connection. Err: %" PRIi32, err);
		_send_disconnect(conn, &conn->udp_sock.addr, EDISCONNECT_INTERNAL_ERROR);
		_client_disconnect(__conn, EDISCONNECT_INTERNAL_ERROR);
		return;
	}

	/* call onsend */
	conn->data.cli.events.onsendpkt(conn, conn->userdata, conn->out_packet);

	/* netmsg_pack() always perform at least one write operation.
	 * The packet must be sent if netmsg_pack() performed more then
	 * one write or onsendpkt() performed one or more writes. */
	if (packet_get_write_op_count(conn->out_packet) == write_op_cnt + 1) {
		/* avoid sending empty packets if possible */
		if (s->send_skip_count++ < conn->settings.timeout_tick / 8)
			return;
		s->send_skip_count = 0;
	}
	_conn_udp_send(conn, &conn->udp_sock.addr);
}

static inline netconn_t *
_conn_init(const struct netsettings settings, void *userdata)
{
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
	
	return conn;
}

static inline void
_conn_deinit(netconn_t *conn)
{
	usock_udp_deinit(&conn->udp_sock);
	packet_free(&conn->in_packet);
	packet_free(&conn->out_packet);
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
				_send_disconnect(c, &client->sockaddr, EDISCONNECT_SERVER_CLOSING);

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
	return netmsg_enqueue(&client->msgctx, buffer, size);
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
	if (!netmsg_init(&conn->data.cli.msgctx, 128)) {
		_conn_deinit(conn);
		return NULL;
	}

	/* prepare first packet */
	packet_w_16_t(conn->out_packet, &conn->tick_local);
	packet_w_bits(conn->out_packet, conn->data.cli.common.status_local, EPROT_STATUS_SIZE);
	conn->data.cli.events.onconnect(conn, conn->userdata, conn->in_packet, conn->out_packet);
	return conn;
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
	return netmsg_enqueue(&conn->data.cli.msgctx, buffer, size);
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
