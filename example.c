#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <ufavonet/packet.h>
#include <ufavonet/net.h>

static volatile int isclosing = 0;

void handlesigint(int x) {
    isclosing = 1;
}

void
print_dreason(int disconnect_reason)
{
	switch((enum netconn_kick_reason)disconnect_reason) {
		case EKICK_NONE:
			printf("Kicked.\n");
		break;
		case EKICK_DISCONNECT:
			printf("Disconnect.\n");
		break;
		case EKICK_SERVER_CLOSING:
			printf("Server is closing.\n");
		break;
		case EKICK_CONNECTION_REFUSED:
			printf("Connection refused.\n");
		break;
		case EKICK_CONNECTION_TIMEOUT:
			printf("Timed out.\n");
		break;	
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
	
	netconn_t *conn = NULL;

	if (args[1][0] == 'c') {
		conn = client_init(inet_addr("127.0.0.1"), htons(27444), cli_events, settings, NULL);
		printf("Client started!\n");
	} else if (args[1][0] == 's') {
		conn = server_init(htonl(INADDR_ANY), htons(27444), srv_events, settings, NULL);
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
				server_close(conn);
			}
		}
		sleep(1);
	}
	return 0;
}
