#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <unistd.h>
#include "include/packet.h"
#include "include/net.h"
#include "src/netmsg.h"
#include "src/_hooks.h"

#ifdef _WIN32
#define random() rand()
#define srandom(val) srand(val)
#endif

#define TEST(testfunc) printf(#testfunc"\t\t\t\t\t"); total++; if (testfunc == EXIT_SUCCESS) { printf("OK\n"); ok++; }

#define TEST_CMP(in,out,printtype,before_exit) if (in != out) { printf("FAILED\n%d:\tout != in (" printtype " != " printtype ")\n", __LINE__, out, in); before_exit; return EXIT_FAILURE; }

#define TEST_CMPSTR(in,out,printtype,before_exit) if (strcmp(in,out) != 0) { printf("FAILED\n%d:\tout != in (" printtype " != " printtype ")\n", __LINE__, out, in); before_exit; return EXIT_FAILURE; }


#define TEST_LOOP_COUNT	8192

int
test_packet_rw_bits()
{
	uint8_t out, k;
	packet_t 	*p;
	int 	i, j;
	int 	err;
	p = packet_init();
	k = 0;
	for (i = 0; i < 0xFF; i++) {
		for (j = 1; j <= 8; j++) {
			if ((err = packet_w_bits(p, i, j)) > 0) {
				printf("error packet_w_bits: %d\n", err);
			}
			k+=j;
		}
	}

	packet_rewind(p);	
	
	for (i = 0; i < 0xFF; i++) {
		for (j = 1; j <= 8; j++) {
			if( (err = packet_r_bits(p, &out, j)) > 0) {
				printf("error packet_w_bits: %d\n", err);
			}
			k = ((0xFF >> (8 - j)) & i);
			TEST_CMP(k,out,"%" PRIu8,packet_free(&p));
		}
	}
	packet_free(&p);
	return EXIT_SUCCESS;
}

int
test_packet_rw_vlen29()
{
	packet_t 	*p;
	uint32_t 	i, j;

	p = packet_init_prealloc(8);

	uint32_t	numv[] = {
		112,		// 1 byte
		200,		// 2 bytes
		17384,		// 3 bytes
		3897152,	// 4 bytes
	};

	for (i = 0; i < (uint32_t)(sizeof(numv) / sizeof(*numv)); i++) {
		packet_rewind(p);
		packet_w_vlen29(p, numv[i]);
		
		packet_rewind(p);
		packet_r_vlen29(p, &j);
		TEST_CMP(numv[i], j, "%" PRIu32, packet_free(&p));
	}

	packet_free(&p);
	return EXIT_SUCCESS;
}

int
test_packet_all()
{
	packet_t 	*p;
	
	/* input */
	uint8_t 	in_bits_a = random() % 16;
	uint8_t 	in_bits_b = random() % 16;
	int8_t 		in_int8_a = random();
	int16_t 	in_int16_a = random();
	float 		in_float_a = random() * 0.117246f;
	int32_t 	in_int32_a = random();
	double 		in_double_a = random() * 0.2253286; 
	int64_t 	in_int64_a = random();
	char 		*in_str = "Hello packet!";
	uint32_t 	in_vlen = random() % (1 << 29);

	/* output */
	uint8_t 	out_bits_a;
	uint8_t 	out_bits_b;
	int8_t 		out_int8_a;
	int16_t 	out_int16_a;
	float 		out_float_a;
	int32_t 	out_int32_a;
	double 		out_double_a; 
	int64_t 	out_int64_a;
	char 		out_str[256];
	uint32_t 	out_vlen;

	p = packet_init();

	/* write */
	packet_w_vlen29(p, in_vlen);
	packet_w(p, in_str, strlen(in_str)+1);
	packet_w_64_t(p, &in_int64_a);
	packet_w_64_t(p, &in_double_a);
	packet_w_32_t(p, &in_int32_a);
	packet_w_32_t(p, &in_float_a);
	
	packet_w_bits(p, in_bits_a, 4);

	packet_w_16_t(p, &in_int16_a);
	packet_w_8_t(p, &in_int8_a);

	packet_w_bits(p, in_bits_b, 4);

	/* read */
	packet_rewind(p);

	packet_r_vlen29(p, &out_vlen);
	TEST_CMP(in_vlen, out_vlen, "%" PRIu32, packet_free(&p));
	packet_r(p, out_str, strlen(in_str)+1);
	TEST_CMPSTR(in_str, out_str, "%s", packet_free(&p));
	packet_r_64_t(p, &out_int64_a);
	TEST_CMP(in_int64_a, out_int64_a, "%" PRIi64, packet_free(&p));
	packet_r_64_t(p, &out_double_a);
	TEST_CMP(in_double_a, out_double_a, "%lf", packet_free(&p));
	packet_r_32_t(p, &out_int32_a);
	TEST_CMP(in_int32_a, out_int32_a, "%" PRIi32, packet_free(&p));
	packet_r_32_t(p, &out_float_a);
	TEST_CMP(in_float_a, out_float_a, "%f", packet_free(&p));
	packet_r_bits(p, &out_bits_a, 4);
	TEST_CMP(in_bits_a, out_bits_a, "%" PRIu8, packet_free(&p));
	packet_r_16_t(p, &out_int16_a);
	TEST_CMP(in_int16_a, out_int16_a, "%" PRIi16, packet_free(&p));
	packet_r_8_t(p, &out_int8_a);
	TEST_CMP(in_int8_a, out_int8_a, "%" PRIi8, packet_free(&p));
	packet_r_bits(p, &out_bits_b, 4);
	TEST_CMP(in_bits_b, out_bits_b, "%" PRIu8, packet_free(&p));

	packet_free(&p);
	return EXIT_SUCCESS;
}

/* declares a uint of n bits and write to p */
#define W_IN_OUT_UINT(type,count) uint##type##_t u_in##type[count]; uint##type##_t u_out##type = 0; \
	for(i = 0; i < count; i++) { \
		u_in##type[i] = random() % (UINT##type##_MAX); \
		packet_w_##type##_t(p, &u_in##type[i]); \
	}

#define W_IN_OUT_INT(type,count) int##type##_t in##type[count]; int##type##_t out##type = 0; \
	for(i = 0; i < count; i++) { \
		in##type[i] = (random() % (UINT##type##_MAX / 2)) * (random() % 2 == 0? 1 : -1); \
		packet_w_##type##_t(p, &in##type[i]); \
	}


#define TEST_IN_OUT_UINT(type,count,printformat) \
	for(i = 0; i < count; i++) { \
		packet_r_##type##_t(p, &u_out##type); \
		TEST_CMP(u_in##type[i],u_out##type,printformat,packet_free(&p)); \
	}

#define TEST_IN_OUT_INT(type,count,printformat) \
	for(i = 0; i < count; i++) { \
		packet_r_##type##_t(p, &out##type); \
		TEST_CMP(in##type[i],out##type,printformat,packet_free(&p)); \
	}

#define TESTPACKET_RW_N_T(n) TEST(test_packet_rw_##n##_t())

#define TESTBODY_PACKET_RW_N_T(n,printformat,extra_write,extra_read) \
	int test_packet_rw_##n##_t() { \
		int i; \
		packet_t *p = packet_init(); \
		W_IN_OUT_UINT(n, TEST_LOOP_COUNT); \
		W_IN_OUT_INT(n, TEST_LOOP_COUNT); \
		extra_write; \
		packet_rewind(p); \
		TEST_IN_OUT_UINT(n, TEST_LOOP_COUNT, printformat); \
		TEST_IN_OUT_INT(n, TEST_LOOP_COUNT, printformat); \
		extra_read; \
		packet_free(&p); \
		return EXIT_SUCCESS; \
	}

TESTBODY_PACKET_RW_N_T(8,"%" PRIu8,{},{})
TESTBODY_PACKET_RW_N_T(16,"%" PRIi16,{},{})
TESTBODY_PACKET_RW_N_T(32,"%" PRIi32,float in_f = 33.3498712f * (random() % 4000);float out_f = 0.0f;packet_w_32_t(p, &in_f);,{
					   packet_r_32_t(p, &out_f);
					   TEST_CMP(in_f, out_f,"%f",packet_free(&p));
					   })
TESTBODY_PACKET_RW_N_T(64,"%" PRIi64, double in_d = 33.3498712f * (random() % 4000);double out_d = 0.0f; packet_w_64_t(p, &in_d);,{
					   packet_r_64_t(p, &out_d);
					   TEST_CMP(in_d, out_d,"%lf",packet_free(&p));
					   })

int
test_netmsg()
{
	printf("\n");

	netmsg_ctx_t a, b;
	netmsg_init(&a, 256);
	netmsg_init(&b, 256);

	packet_t *pkt_from_a = packet_init();
	packet_t *pkt_from_b = packet_init();

	uint32_t msgc = 20000;
	uint64_t *msgv = malloc(sizeof(*msgv) * msgc);
	
	uint32_t i;
	for (i = 0; i < msgc; i++) {
		msgv[i] = (uint64_t)random();
	}

	uint32_t msg_rcv = 0;
	uint32_t msg_enq = 0;

	uint32_t a_drops = 0, b_drops = 0;

	// To start with, pack 200 groups to test MAX SEND behaviour.
	for (; msg_enq < 200; msg_enq++) {
		netmsg_enqueue(&a, msgv + msg_enq, sizeof(*msgv));
		netmsg_pack(&a, pkt_from_a);
		packet_rewind(pkt_from_a);
	}
	
	do {
		if (msg_enq < msgc) {
			// enqueue a random number of messages each "tick"
			uint32_t enq = msg_enq + (rand() % 4);
			if (enq > msgc)
				enq = msgc;
			for (; msg_enq < enq; msg_enq++)
				netmsg_enqueue(&a, msgv + msg_enq, sizeof(*msgv));
		}
		
		netmsg_pack(&a, pkt_from_a);
		packet_rewind(pkt_from_a);
//		puts("----END----");
	
		void *msg; uint32_t size;
		// Random packet drop
		if (rand() % 4 != 2) {
//			puts("-----B-----");
			// Deliver to 'b'
			while (netmsg_unpack_next(&b, pkt_from_a, &msg, &size) == ENETMSG_ERR_NONE) {
				if (!msg) break;
				if (msg_rcv == msgc) {
					ulogf_emr("unpack_next attempted to unpack more messages than what's available");
					goto fail;
				}
				if (size != sizeof(*msgv)) {
					ulogf_emr("size mismatch\n");
					goto fail;
				}
				if (memcmp(msg, msgv + msg_rcv, sizeof(*msgv)) != 0) {
					ulogf_emr("contents mismatch\n");
					goto fail;
				}
				msg_rcv++;
			}
			packet_rewind(pkt_from_a);
//			puts("----END----");
		} else a_drops++;
		
		// Pack b's response
		netmsg_pack(&b, pkt_from_b);
		packet_rewind(pkt_from_b);

		// Random packet drop
		if (rand() % 4 != 2) {
//			puts("-----A-----");
			// Deliver to 'a'
			netmsg_unpack_next(&a, pkt_from_b, &msg, &size);
			packet_rewind(pkt_from_b);
		} else b_drops++;

	} while (msg_rcv < msgc);
	
	ulogf_inf("dropped packets from A: %u; from B: %u\n", a_drops, b_drops);
	netmsg_deinit(&a);
	netmsg_deinit(&b);
	packet_free(&pkt_from_a);
	packet_free(&pkt_from_b);
	free(msgv);
	return EXIT_SUCCESS;
fail:
	netmsg_deinit(&a);
	netmsg_deinit(&b);
	packet_free(&pkt_from_a);
	packet_free(&pkt_from_b);
	free(msgv);
	return EXIT_FAILURE;
}

/* networking test */
#define NETTEST_CLI_MESSAGE "Hello from client."
#define NETTEST_SRV_MESSAGE "Hello from server."
int nettest_clistep = 0;
int nettest_srvstep = 0;
int nettest_step = 0;
int nettest_fail = 0;
char nettest_failmsg[1024];
/* client side */
void
cli_onconnect(netconn_t *conn, void *userdata, packet_t *p_in, packet_t *p_out)
{
	/* complete the server onconnect sum challenge */
	uint32_t x = 0, y = 0, z = 0;
	packet_r_32_t(p_in, &x);
	packet_r_32_t(p_in, &y);
	z = x + y;
	packet_w_32_t(p_out, &z);
	printf("\t[client] onconnect event got called with: %d + %d = %d\n", x, y, z);
	/* client side onconnect got called, so it's working. */
	if (nettest_clistep == 0) {
		nettest_clistep++;
	}
}
void
cli_ondisconnect(netconn_t **conn, void *userdata, int disconnect_reason)
{
	client_free(conn);
	printf("\t[client] ondisconnect got called with reason: %d\n", disconnect_reason);
}
void
cli_onreceivepkt(netconn_t *conn, void *userdata, packet_t *p_in)
{
	uint8_t len = 0;
	char msg[256];
	packet_r_8_t(p_in, &len);
	packet_r(p_in, msg, len);

	if (nettest_clistep == 1) {
		nettest_clistep++;
		printf("\t[client] onreceivepkt event got called with: %s\n", msg);
	}

	if (strcmp(msg, NETTEST_SRV_MESSAGE) != 0) {
		if (nettest_fail == 0) {
			nettest_fail = 1;
			sprintf(nettest_failmsg, "%d: cli onreceivepkt strcmp failed.\n", __LINE__);
		}
	}
}

struct serversumchallenge {
	uint32_t x;
	uint32_t y;
	uint32_t z;
};

void
cli_onsendpkt(netconn_t *conn, void *userdata, packet_t *p_out)
{
	const char *str = NETTEST_CLI_MESSAGE;
	const uint8_t len = strlen(str)+1;

	packet_w_8_t(p_out, &len);
	packet_w(p_out, str, len);

	if (nettest_clistep == 2) {
		nettest_clistep++;
		printf("\t[client] onsendpkt event got called.\n");
	}
}
/* server side */
int
onconnect(netconn_t *conn, void *userdata, packet_t *p_in, packet_t *p_out, netsrvclient_t *client, void **cliuserdata)
{
	struct serversumchallenge *challenge;
	printf("\t[server] onconnect event got called.\n");

	if (*cliuserdata == NULL) {
		printf("\t[server] onconnect setting up challenge.\n");
		/* setup a sum challenge */
		*cliuserdata = malloc(sizeof(struct serversumchallenge));
		challenge = *cliuserdata;
		challenge->x = random() % (UINT32_MAX / 4);
		challenge->y = random() % (UINT32_MAX / 4);
		challenge->z = challenge->x + challenge->y;
	} else if (packet_get_readable(p_in) >= 4) {
		/* check challenge response */
		printf("\t[server] onconnect verifying challenge response.\n");
		uint32_t cli_resp = 0;
		challenge = *cliuserdata;
		packet_r_32_t(p_in, &cli_resp);
		if (challenge->z == cli_resp) {
			free(challenge);
			*cliuserdata = NULL;
			nettest_step++;
			printf("\t[server] onconnect event allowed the connection.\n");
			return ECONNECTION_ALLOW;
		}
	}
	challenge = *cliuserdata;
	packet_w_32_t(p_out, &challenge->x);
	packet_w_32_t(p_out, &challenge->y);
	return ECONNECTION_AGAIN;
}
void
ondisconnect(netconn_t *conn, void *userdata, int disconnect_reason, netsrvclient_t *client, void **cliuserdata)
{
	printf("\t[server] ondisconnect got called with reason: %d\n", disconnect_reason);
}
void
onreceivepkt(netconn_t *conn, void *userdata, packet_t *p_in, netsrvclient_t *client, void *cliuserdata)
{
	uint8_t len = 0;
	char msg[256];
	packet_r_8_t(p_in, &len);
	packet_r(p_in, msg, len);

	printf("\t[server] onreceivepkt event got called with: %s\n", msg);
	if (strcmp(msg, NETTEST_CLI_MESSAGE) != 0) {
		if (nettest_fail == 0) {
			nettest_fail = 1;
			sprintf(nettest_failmsg, "%d: srv onreceivepkt strcmp failed.\n", __LINE__);
		}
	}
}
void
onsendpkt(netconn_t *conn, void *userdata, packet_t *p_out, netsrvclient_t *client, void *cliuserdata)
{
	const char *str = NETTEST_SRV_MESSAGE;
	const uint8_t len = strlen(str)+1;

	packet_w_8_t(p_out, &len);
	packet_w(p_out, str, len);

	printf("\t[server] onsendpkt event got called.\n");
}

void
onsrvclose(netconn_t **conn, void *userdata)
{
	printf("\t[server] onsrvclose event got called.\n");
	server_free(conn);
}

int
test_all()
{
	printf("\n");
	int i;
	/* setup settings */
	const struct netsettings settings = {
		.pending_conn_timeout_tick = 200,
		.kick_notice_tick = 10,
		.timeout_tick = 400,
		.expected_tick_tolerance = 8192,
	};
	/* setup events */
	const struct clievents clievents = { 
		.onconnect=&cli_onconnect, 
		.ondisconnect=&cli_ondisconnect, 
		.onreceivepkt=&cli_onreceivepkt,
		.onsendpkt=&cli_onsendpkt
	};
	const struct srvevents srvevents = {
		.onconnect = &onconnect,
		.ondisconnect = &ondisconnect,
		.onreceivepkt = &onreceivepkt,
		.onsendpkt = &onsendpkt,
		.onsrvclose = &onsrvclose
	};

	netconn_t *cli_info = NULL, *srv_info = NULL;
	/* initialize server and client */
	srv_info = server_init(srvevents, settings, NULL);
	server_listen(srv_info, EPROTO_UDP, "localhost", 25565);
	cli_info = client_init(clievents, settings, NULL);
	client_connect(cli_info, EPROTO_UDP, "localhost", 25565);

	/* process loop */
	for(i = 0; srv_info != NULL && i < 2048; i++) {
		client_process(&cli_info);
		server_process(&srv_info);
		if (nettest_clistep == 3) {
			client_disconnect(cli_info);
			nettest_clistep++;
		} else if (cli_info == NULL) {
			server_close(srv_info, 0);
			nettest_srvstep++;
		}
		usleep(5000);	
	}
	if (srv_info != NULL) {
		server_free(&srv_info);
		client_free(&cli_info);
		printf("FAILED\n\tFailed to test all events.\n");
		return EXIT_FAILURE;
	} else if (nettest_fail == 1) {
		printf("FAILED\n%s",nettest_failmsg);
		return EXIT_FAILURE;
	}
	return EXIT_SUCCESS;
}

int
main()
{
	int total = 0, ok = 0;
	srandom(time(NULL));

	TEST(test_packet_rw_bits());
	TESTPACKET_RW_N_T(8);
	TESTPACKET_RW_N_T(16);
	TESTPACKET_RW_N_T(32);
	TESTPACKET_RW_N_T(64);
	TEST(test_packet_rw_vlen29());
	TEST(test_packet_all());
	TEST(test_netmsg());
	TEST(test_all());
	printf("Total=%d, OK=%d\n", total, ok);
	return 0;
}
