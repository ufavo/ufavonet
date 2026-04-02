/*
 * Networking interface.
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

#ifndef __UFAVONET_NET_HEADER__
#define __UFAVONET_NET_HEADER__

#include <stdint.h>
#include <stddef.h>
#include "packet.h"

enum netconn_disconnect_reason
{
	/* The server disconnected the client with no reason */
	EDISCONNECT_NONE = 0,
	/* The client notified a disconnect. */
	EDISCONNECT,
	/* Server is closing. */
	EDISCONNECT_SERVER_CLOSING,
	/* Server is restarting. */
	EDISCONNECT_SERVER_RESTARTING,
	/* The client was unable to negotiate a connection in time. */
	EDISCONNECT_TIMEOUT,
	/* The client connection request was refused by the server. */
	EDISCONNECT_REFUSED,
	/* The server encountered an error and needed to disconnect the client. */
	EDISCONNECT_INTERNAL_ERROR,
	/* From the server pov the client violated the protocol. */
	EDISCONNECT_PROTOCOL_VIOLATION,
	/* Handshake failed. */
	EDISCONNECT_HANDSHAKE,
	/* The server refused to give it's public key. */
	EDISCONNECT_WONT_GIVE_PUBLIC_KEY,
	/* RX or TX nonces got desynced for some reason and no further cryptographic operations can be performed */
	EDISCONNECT_SECURE_DESYNC,

	/* Reserved range for application defined reasons */
	EDISCONNECT_APP_CUSTOM_START	= 64,
	EDISCONNECT_APP_CUSTOM_END		= 255
};

enum netconn_connect_result
{
	/* Keep in pending state. 
	 * `onconnect` will be called until `CONNECTION_ALLOW` or `CONNECTION_REFUSE` is returned.
	 * Sends `out` packet if not empty.
	 * `userdata` is assigned to this client. */
	ECONNECTION_AGAIN = 0,
	/* Allows the connection.
	 * Sends `p_out` packet if not empty. 
	 * `userdata` is assigned to this client. */
	ECONNECTION_ALLOW,
	/* Refuses the connection.
	 * Kicks the client with `KICKINF_CONNECTION_REFUSED` message.
	 * `p_out` packet is ignored.
	 * `userdata` is assigned to this client.
	 * `ondisconnect` is called as soon as this value is returned. */
	ECONNECTION_REFUSE,
};

enum netconn_protocol
{
	EPROTO_UDP = 0,
};

enum netconn_secure
{
	ESECURE_ENCRYPT = 0,
	ESECURE_NONE,
	ESECURE_AUTH,
};

#define NETCONN_SECURE_PK_SIZE 32
#define NETCONN_SECURE_SK_SIZE 32
#define NETCONN_SECURE_KEYPAIR_SIZE (NETCONN_SECURE_PK_SIZE + NETCONN_SECURE_SK_SIZE)

typedef struct netconn netconn_t;
typedef struct srvclient netsrvclient_t;

struct netsettings {
	/* Incoming packets exceeding this size will be dropped.
	 * Each connection will require up to three times this amount of additional memory.
	 * Useful for limiting resource usage (as fragmented packets require more memory and cpu time).
	 * Min: 4096; When unset defaults to 65535; */
	uint32_t 	frag_max_recv_packet_size;
	/* Preallocs backing packets for fragmented reassemble. When unset nothing is prealloc'ed. */
	uint32_t 	frag_prealloc_packet_size;
	/* Amount of ticks with no successful authentication. 
	 * When this value is exceeded during a pending connection state the client is kicked.
	 * Should not exceed 16384 (2^14). 
	 * This setting is exclusive to server. */
	uint16_t 	pending_conn_timeout_tick;
	/* Amount of ticks with no response.
	 * As a client, when this value is exceeded, the event `ondisconnect` is called and the connection should be terminated.
	 * As a server, When this value is exceeded the client is kicked. */
	uint16_t 	timeout_tick;
	/* The maximum amount of ticks sent as kick notice (by server) or disconnect notice (client) before actually kicking the client (server) or disconnecting (client). 
	 * Half the tick rate is enough. */
	uint16_t 	kick_notice_tick;
	/* When a packet arrives it can be out of order. To determine if it should be considered, the tick number of the packet is compared against a expected value.
	 * This setting specifies the margin of the expected value.
	 * Should not exceed 16384 (2^14), as a tick number is represented with 16 bits that wraps around when the max value is reached.
	 * For a value of 10, the packet will be considered if (`remote_tick` > `last_applied_remote_tick`) && (`remote_tick` <= `local_tick` + 10 && `remote_tick` >= `local_tick` - 10).
	 * A value of 8192 is highly recommended. Smaller values can be a problem with poor connections. A higher value significantly increases the chances of applying the wrong packet. */
	uint16_t 	expected_tick_tolerance;
	/* How many times per second a tick is processed. Only applies to `conn_process_*` functions. */
	uint16_t 	tick_rate;

	/* Determines the security of outgoing packets. After the handshake only authenticated or encrypted packets are accepted.
	 * See `enum netconn_secure`. Defaults to `ESECURE_ENCRYPT` */
	uint8_t 	secure;
	/* When set the server doesn't distribute it's public key to clients */
	uint8_t 	dont_distribute_public_key;
	/* Seconds to sleep between ticks when the server has no clients connected */
	uint8_t 	idle_sleep_seconds;
};

struct srvevents {
	/* Called during the process of connection negotiation.
	 * This is where authentication/identification/verification should happen if needed.
	 * A client is considered connected whenever `CONNECTION_ALLOW` is returned. 
	 * `userdata` can be assigned anytime `onconnect` is called. */
	int 	(*onconnect)(netconn_t *conn, void *userdata, packet_t *p_in, packet_t *p_out, netsrvclient_t *client, void **cli_userdata);
	/* Called when a client is kicked, disconnects or lose connection to the server. 
	 * Called even if the client has not succeeded the `onconnect` process.
	 * Called once per client.
	 * This is the last call before `client` resources are released. 
	 * If `userdata` has no more references, release it's resources here. */
	void	(*ondisconnect)(netconn_t *conn, void *userdata, int disconnect_reason, netsrvclient_t *client, void **cli_userdata);
	/* Called whenever a message sent was acknowledged by the receiver. */
	void 	(*onmessageack)(netconn_t *conn, void *userdata, int32_t message_batch_id, netsrvclient_t *client);
	/* Called during a server tick if a valid packet is available.
	 * This event is only called for clients that got approved in the `onconnect` stage. */
	void	(*onreceivepkt)(netconn_t *conn, void *userdata, packet_t *p_in, netsrvclient_t *client, void *cli_userdata);
	/* Called when a message arrives. */
	void 	(*onreceivemsg)(netconn_t *conn, void *userdata, packet_t *p_in, netsrvclient_t *client);
	/* Called before the onsendpkt event occours for any client.
	 * Only called once per tick. */
	void 	(*bonsendpkt)(netconn_t *conn, void *userdata, netsrvclient_t *first);
	/* Called every server tick.
	 * This event is only called for clients that got approved in the `onconnect` stage. */
	void  	(*onsendpkt)(netconn_t *conn, void *userdata, packet_t *p_out, netsrvclient_t *client, void *cli_userdata);
	/* Called after a `KICKINF_SERVER_CLOSING` kick happens for all connected clients.
	 * This event is triggered by a call to `server_close`. */
	void 	(*onsrvclose)(netconn_t **conn, void *userdata);
};

struct clievents {
	/* Step were the connection is negotiated.
	 * Called until server accept/timeout the connection request. */
	void	(*onconnect)(netconn_t *conn, void *userdata, packet_t *p_in, packet_t *p_out);
	/* Called when a disconnection occours. */
	void	(*ondisconnect)(netconn_t **conn, void *userdata, int disconnect_reason);
	/* Called whenever a message sent was acknowledged by the receiver. */
	void 	(*onmessageack)(netconn_t *conn, void *userdata, int32_t message_batch_id);
	/* Called during a client tick if a valid packet is avaliable. */
	void	(*onreceivepkt)(netconn_t *conn, void *userdata, packet_t *p_in);
	/* Called when a message arrives. */
	void 	(*onreceivemsg)(netconn_t *conn, void *userdata, packet_t *p_in);
	/* Called every client tick. */
	void	(*onsendpkt)(netconn_t *conn, void *userdata, packet_t *p_out);
};

struct netstats {
	uint64_t 	total_received_bytes;
	uint64_t	total_sent_bytes;
};

netconn_t *server_init(const struct srvevents events, const struct netsettings settings, void *userdata);
/* Generates a new keypair.
 * Returns 1 on success and 0 on failure. */
int server_secure_keypair_generate(netconn_t *restrict conn);
/* Reads `NETCONN_SECURE_KEYPAIR_SIZE` bytes from `in_keypair`.
 * Returns 1 on success and 0 on failure. */
int server_secure_keypair_import(netconn_t *restrict conn, const uint8_t *restrict in_keypair);
/* Writes `NETCONN_SECURE_KEYPAIR_SIZE` bytes to `out_keypair`.
 * The public key is in the first `NETCONN_SECURE_PK_SIZE` bytes.
 * Returns 1 on success and 0 on failure. */
int server_secure_keypair_export(netconn_t *restrict conn, uint8_t *restrict out_keypair);
/* Opens and binds a socket with given protocol, hostname and port.
 * Must not be called again after success.
 * Returns 1 on success and 0 on failure. */
int	server_listen(netconn_t *restrict conn, enum netconn_protocol proto, const char *restrict hostname, uint16_t port);
/* Initiate the process of closing the server.
 * After called, eventually `onsrvclose` event will be triggered. */
void server_close(netconn_t *restrict conn, uint8_t restarting);
/* Disconnects the given `client` from the server it's associated with. */
void server_cli_disconnect(netsrvclient_t *restrict client, enum netconn_disconnect_reason reason);

netconn_t *client_init(const struct clievents events, const struct netsettings settings, void *userdata);
/* Reads `NETCONN_SECURE_PK_SIZE` bytes from `in_pubkey`.
 * Returns 1 on success and 0 on failure. */
int client_secure_pubkey_import(netconn_t *restrict conn, const uint8_t *restrict in_pubkey);
/* Opens and binds a socket with given protocol, hostname and port.
 * Must not be called again after success.
 * Returns 1 on success and 0 on failure. */
int	client_connect(netconn_t *restrict conn, enum netconn_protocol proto, const char *restrict hostname, uint16_t port);
/* Send a message to the server.
 * Returns the id of the batch whose the message is part of. The id can be used to identify the batch of the message during `onmessageack` event. */
int32_t client_sendmessage(netconn_t *restrict conn, const void *restrict buffer, const uint32_t size);
/* Disconnects the client.
 * After called, eventually `ondisconnect` event will be triggered. */
void client_disconnect(netconn_t *restrict conn);

uint16_t client_get_tick_remote(netconn_t *restrict conn);
float client_get_ping_ms(netconn_t *restrict conn);
float client_get_ping_ticks(netconn_t *restrict conn);

/* return the next client, or NULL. 
 * can be used in the event `bonsendpkt` with the `first` client. */
netsrvclient_t 	*server_cli_get_next(netsrvclient_t *client);
void 			*server_cli_get_userdata(netsrvclient_t *restrict client);
/* return the port of the client in host byte order */
uint16_t 		server_cli_get_port(netsrvclient_t *restrict client);
/* return a pointer to the internal array containing the address of the `client` represented as a string */
char 			*server_cli_get_addrstr(netsrvclient_t *restrict client);
/* Send a message to a client.
 * Returns the id of the batch whose the message is part of. The id can be used to identify the batch of the message during `onmessageack` event. */
int32_t 		server_cli_sendmessage(netsrvclient_t *restrict client, const void *restrict buffer, const uint32_t size);

uint16_t 	server_cli_get_tick_remote(netsrvclient_t *restrict client);
float		server_cli_get_ping_ms(netsrvclient_t *restrict client, float tickrate);
float		server_cli_get_ping_ticks(netsrvclient_t *restrict client);

uint16_t 	conn_get_tick_local(netconn_t *restrict conn);
uint16_t	conn_get_tick_rate(netconn_t *restrict conn);
/* return a pointer to the internal netstats struct */
const struct netstats *conn_get_stats(netconn_t *restrict conn);

/* Provides fine grained tick control. The user is responsible to manage the timing of each call.
 * Runs a single tick (receive / process / send). Must be called at a the same rate by all parties until 
 * the event (`onsrvclose` when a server; `ondisconnect` when a client) is triggered.
 * Can be called safely even with `NULL` values. */
void conn_tick(netconn_t **conn);
/* Receives and processes pending packets. Can be used to minimize loss or delay when manually controlling
 * the tick rate with `conn_tick()` (especially when dealing with fragmented packets).
 * Can be called multiple times per tick. 
 * Returns the number of received packets. */
int conn_recv(netconn_t **conn);

/* Runs a tick `tick_rate` times per second. Should be called in a loop that runs fast enough to keep up 
 * with `tick_rate`. Returns immediately (i.e. doesn't block waiting for the appropriate time to run the tick).
 *
 * Returns the time left in microseconds before the next run.
 * Return values of zero or less indicates that the tick was run during the call.
 * A negative return value (also in microseconds) indicates underrun (the loop is not going fast enough). */
int_fast64_t 	conn_process_non_blocking(netconn_t **conn);
/* Runs a tick `tick_rate` times per second. Should be called in a loop that runs fast enough to keep up 
 * with `tick_rate`. Busy waits for the exact time to run the tick and returns after running it. */
void 			conn_process_blocking_busy(netconn_t **conn);
/* Runs a tick `tick_rate` times per second. Should be called in a loop that runs fast enough to keep up 
 * with `tick_rate`. Sleeps the `relax_ratio` portion and then busy waits the remaining time to run the tick
 * and returns after running it.
 * `relax_ratio` ranges from:
 * 		0.0 (completely busy; precise but wastes cpu cycles)
 * 	to
 * 		1.0 (completely relaxed; less precise; may underrun occasionally) */
void 			conn_process_blocking_relaxed(netconn_t **conn, double relax_ratio);

/* Close the socket and release resources.
 * Can be called in the event (`onsrvclose` when a server; `ondisconnect` when a client). */
void conn_free(netconn_t **conn);

#endif
