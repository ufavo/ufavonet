#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>

#include "include/packet.h"
#include "include/net.h"
#include "include/hooks.h"

static volatile int isclosing = 0;

void handlesigint(int x) {
    isclosing = 1;
}

void
print_dreason(int disconnect_reason)
{
	switch((enum netconn_disconnect_reason)disconnect_reason) {
		case EDISCONNECT_NONE: 					puts("Disconnected by the server"); 	break;
		case EDISCONNECT:						puts("Disconnected");					break;
		case EDISCONNECT_SERVER_CLOSING:		puts("Server closing");					break;
		case EDISCONNECT_SERVER_RESTARTING:		puts("Server restarting");				break;
		case EDISCONNECT_REFUSED:				puts("Connection refused");				break;
		case EDISCONNECT_TIMEOUT:				puts("Connection timed out");			break;
		case EDISCONNECT_PROTOCOL_VIOLATION:	puts("Protocol violation");				break;
		case EDISCONNECT_INTERNAL_ERROR:		puts("Internal error");					break;
	}
}

void
cli_onconnect(netconn_t *conn, void *userdata, packet_t *p_in, packet_t *p_out)
{
	printf("This message only appears if server returns ECONNECTION_AGAIN.\n");
}

void
cli_ondisconnect(netconn_t **conn, void *userdata, int disconnect_reason)
{
	client_free(conn);
	printf("\nDisconnected! Reason: ");
	print_dreason(disconnect_reason);
	printf("Exiting.\n");
}

void
cli_onreceivepkt(netconn_t *conn, void *userdata, packet_t *p_in)
{
	char msg[256];
	packet_r(p_in, msg, packet_get_readable(p_in));
	printf("Received from server: %s\n", msg);
}

void
cli_onsendpkt(netconn_t *conn, void *userdata, packet_t *p_out)
{
	const char *str = "Hello server!";
	packet_w(p_out, str, strlen(str)+1);
	printf("Sent a message to server.\n");
}

int
srv_onconnect(netconn_t *conn, void *userdata, packet_t *p_in, packet_t *p_out, netsrvclient_t *client, void **cli_userdata)
{
	printf("Client [%s:%d] connected!\n", server_cli_get_addrstr(client), server_cli_get_port(client));
	return ECONNECTION_ALLOW;	
}

void
srv_ondisconnect(netconn_t *conn, void *userdata, int disconnect_reason, netsrvclient_t *client, void **cli_userdata)
{
	printf("Client [%s:%d] disconnected! Reason: ", server_cli_get_addrstr(client), server_cli_get_port(client));
	print_dreason(disconnect_reason);
}

void
srv_onreceivepkt(netconn_t *conn, void *userdata, packet_t *p_in, netsrvclient_t *client, void *cli_userdata)
{
	char msg[256];
	/* Read the string from in packet */
	packet_r(p_in, msg, packet_get_readable(p_in));
	printf("Received from client [%s:%d]: %s\n", server_cli_get_addrstr(client), server_cli_get_port(client), msg);
}

void
srv_onsendpkt(netconn_t *conn, void *userdata, packet_t *p_out, netsrvclient_t *client, void *cli_userdata)
{
	const char *str = "Hello client!";
	/* Write the string to outgoing packet */
	packet_w(p_out, str, strlen(str) + 1);
	printf("Sent a message to client [%s:%d].\n", server_cli_get_addrstr(client), server_cli_get_port(client));
}

void
srv_onsrvclose(netconn_t **conn, void *userdata)
{
	server_free(conn);
	printf("\nServer closed gracefully.\n");
}
//#include <ufavolog.h>
int
main(const int argc, const char **args)
{
	int i;
	/* Settings */
	const struct netsettings settings = {
		.pending_conn_timeout_tick = 20,
		.kick_notice_tick = 5,
		.timeout_tick = 30,
		.expected_tick_tolerance = 8192,
	};
	/* Events */
	const struct clievents cli_events = { 
		.onconnect=&cli_onconnect, 
		.ondisconnect=&cli_ondisconnect, 
		.onreceivepkt=&cli_onreceivepkt,
		.onsendpkt=&cli_onsendpkt
	};
	const struct srvevents srv_events = {
		.onconnect = &srv_onconnect,
		.ondisconnect = &srv_ondisconnect,
		.onreceivepkt = &srv_onreceivepkt,
		.onsendpkt = &srv_onsendpkt,
		.onsrvclose = &srv_onsrvclose
	};

	if (argc < 2) {
usage:
		fprintf(stderr, "Usage: %s s or %s c\n", args[0], args[0]);
		return 1;
	}
	/* handle ctrl+c */
	signal(SIGINT, handlesigint);

//	ufavolog_init((const ufavolog_ctx_t){.level = LOG_DEBUG, .colored = 1, .stream = stderr});
//	ufavonet_set_hooks((const ufavonet_hooks_t){.log = ufavolog3});
	ufavonet_set_log_conf((const ufavonet_log_conf_t){.fd = stderr, .level = LOG_DEBUG});

	netconn_t *conn = NULL;

	if (args[1][0] == 'c') {
		conn = client_init(cli_events, settings, NULL);
		client_connect(conn, EPROTO_UDP, "localhost", 27444);
		printf("Client started!\n");
	} else if (args[1][0] == 's') {
		conn = server_init(srv_events, settings, NULL);
		server_listen(conn, EPROTO_UDP, "localhost", 27444);
		printf("Server started!\n");
	} else {
		goto usage;
	}
	printf("Press CTRL-C at any time to stop.\n");
	while(conn != NULL) {
		if (args[1][0] == 'c') {
			client_process(&conn);
			if (isclosing == 1) {
				client_disconnect(conn);
			}
		} else {
			server_process(&conn);
			if (isclosing == 1) {
				server_close(conn, 0);
			}
		}
		sleep(1);
	}
	return 0;
}
