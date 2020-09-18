/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2020 OmniOS Community Edition (OmniOSce) Association.
 */

/*
 * Test ancillary data receipt via recvmsg()
 */

#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <pthread.h>
#include <err.h>

static boolean_t debug;
static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t cv = PTHREAD_COND_INITIALIZER;
static pthread_mutex_t cmutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t ccv = PTHREAD_COND_INITIALIZER;
static boolean_t server_ready = _B_FALSE;
static boolean_t client_done = _B_FALSE;

static in_addr_t testip;

#define	DEBUG(x) if (debug) printf x

#define	TESTPORT	32123

#define	RT_RECVTOS	0x1
#define	RT_RECVTTL	0x2
#define	RT_RECVPKTINFO	0x4
#define	RT_RECVMASK	0x7

#define	RT_SETTOS	0x10
#define	RT_SETTTL	0x20
#define	RT_STREAM	0x40
#define	RT_SKIP		0x80

typedef struct recvmsg_test {
	char *name;		/* Name of the test */
	uint8_t tos;		/* TOS to set */
	uint8_t ttl;		/* TTL to set */
	uint8_t flags;		/* Test flags, RT_ */
} recvmsg_test_t;

static recvmsg_test_t tests[] = {
	{
		.name = "baseline",
		.flags = 0,
	},

	/* Combinations of receive flags */
	{
		.name = "recv TOS",
		.flags = RT_RECVTOS,
	},

	{
		.name = "recv TTL",
		.flags = RT_RECVTTL,
	},

	{
		.name = "recv PKTINFO",
		.flags = RT_RECVPKTINFO,
	},

	{
		.name = "recv TOS,TTL",
		.flags = RT_RECVTOS | RT_RECVTTL,
	},

	{
		.name = "recv TTL,PKTINFO",
		.flags = RT_RECVTTL | RT_RECVPKTINFO,
	},

	{
		.name = "recv TOS,PKTINFO",
		.flags = RT_RECVTOS | RT_RECVPKTINFO,
	},

	{
		.name = "recv TOS,TTL,PKTINFO",
		.flags = RT_RECVTOS | RT_RECVTTL | RT_RECVPKTINFO,
	},

	/* Manually set TTL and TOS */

	{
		.name = "set TOS,TTL",
		.flags = RT_SETTOS | RT_SETTTL,
		.ttl = 11,
		.tos = 0xe0
	},

	{
		.name = "set/recv TOS,TTL",
		.flags = RT_SETTOS | RT_SETTTL | RT_RECVTOS | RT_RECVTTL,
		.ttl = 32,
		.tos = 0x48
	},

	{
		.name = "set TOS,TTL, recv PKTINFO",
		.flags = RT_SETTOS | RT_SETTTL | RT_RECVPKTINFO,
		.ttl = 173,
		.tos = 0x78
	},

	{
		.name = "set TOS,TTL, recv TOS,TTL,PKTINFO",
		.flags = RT_SETTOS | RT_SETTTL | RT_RECVTOS | RT_RECVTTL |
		    RT_RECVPKTINFO,
		.ttl = 54,
		.tos = 0x90
	},

	/* STREAM socket */

	{
		.name = "STREAM set TOS",
		.flags = RT_STREAM | RT_SETTOS,
		.tos = 0xe0
	},

	/*
	 * The ancillary data are not returned for the loopback TCP path,
	 * so these tests are skipped by default.
	 * To run them, use two different zones (or machines) and run:
	 *	recvmsg.64 -s 'test name'
	 * on the first, and:
	 *	recvmsg.64 -c <first machine IP> 'test name'
	 * on the second.
	 */
	{
		.name = "STREAM recv TOS",
		.flags = RT_STREAM | RT_RECVTOS | RT_SKIP,
	},

	{
		.name = "STREAM set/recv TOS",
		.flags = RT_STREAM | RT_SETTOS | RT_RECVTOS | RT_SKIP,
		.tos = 0x48
	},

	/* End of tests */

	{
		.name = NULL
	}
};

static boolean_t
servertest(recvmsg_test_t *t)
{
	struct sockaddr_in addr;
	boolean_t pass = _B_TRUE;
	int sockfd, readfd, acceptfd = -1, c = 1;

	DEBUG(("\nserver %s: starting\n", t->name));

	sockfd = socket(AF_INET,
	    t->flags & RT_STREAM ? SOCK_STREAM : SOCK_DGRAM, 0);
	if (sockfd == -1)
		err(EXIT_FAILURE, "failed to create server socket");

	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = INADDR_ANY;
	addr.sin_port = htons(TESTPORT);

	if (bind(sockfd, (struct sockaddr *)&addr, sizeof (addr)) == -1)
		err(EXIT_FAILURE, "server socket bind failed");

	if (t->flags & RT_RECVTOS) {
		DEBUG((" : setting RECVTOS\n"));
		if (setsockopt(sockfd, IPPROTO_IP, IP_RECVTOS, &c,
		    sizeof (c)) == -1) {
			printf("[FAIL] %s - "
			    "couldn't set TOS on server socket: %s\n",
			    t->name, strerror(errno));
			pass = _B_FALSE;
		}
	}

	if (t->flags & RT_RECVTTL) {
		DEBUG((" : setting RECVTTL\n"));
		if (setsockopt(sockfd, IPPROTO_IP, IP_RECVTTL, &c,
		    sizeof (c)) == -1) {
			printf("[FAIL] %s - "
			    "couldn't set TTL on server socket: %s\n",
			    t->name, strerror(errno));
			pass = _B_FALSE;
		}
	}

	if (t->flags & RT_RECVPKTINFO) {
		DEBUG((" : setting RECVPKTINFO\n"));
		if (setsockopt(sockfd, IPPROTO_IP, IP_PKTINFO, &c,
		    sizeof (c)) == -1) {
			printf("[FAIL] %s - "
			    "couldn't set PKTINFO on server socket: %s\n",
			    t->name, strerror(errno));
			pass = _B_FALSE;
		}
	}

	if (t->flags & RT_STREAM) {
		if (listen(sockfd, 1) == -1)
			err(EXIT_FAILURE, "Could not listen on sever socket");
	}

	/* Signal the client that the server is ready for the next test */
	if (debug)
		printf(" : signalling client\n");
	(void) pthread_mutex_lock(&mutex);
	server_ready = _B_TRUE;
	(void) pthread_cond_signal(&cv);
	(void) pthread_mutex_unlock(&mutex);

	if (t->flags & RT_STREAM) {
		struct sockaddr_in caddr;
		socklen_t sl = sizeof (caddr);

		if ((acceptfd = accept(sockfd, (struct sockaddr *)&caddr,
		    &sl)) == -1) {
			err(EXIT_FAILURE, "socket accept failed");
		}
		readfd = acceptfd;
	} else {
		readfd = sockfd;
	}

	/* Receive the datagram */

	struct msghdr msg;
	char buf[0x100];
	char cbuf[CMSG_SPACE(0x400)];
	struct iovec iov[1] = {0};
	ssize_t r;

	iov[0].iov_base = buf;
	iov[0].iov_len = sizeof (buf);

	bzero(&msg, sizeof (msg));
	msg.msg_iov = iov;
	msg.msg_iovlen = 1;
	msg.msg_control = cbuf;
	msg.msg_controllen = sizeof (cbuf);

	DEBUG((" : waiting for message\n"));

	r = recvmsg(readfd, &msg, 0);
	if (r <= 0) {
		printf("[FAIL] %s - recvmsg returned %d (%s)\n",
		    t->name, r, strerror(errno));
		pass = _B_FALSE;
		goto out;
	}

	DEBUG((" : recvmsg returned %d (flags=0x%x, controllen=%d)\n",
	    r, msg.msg_flags, msg.msg_controllen));

	if (r != strlen(t->name)) {
		printf("[FAIL] %s - got '%.*s' (%d bytes), expected '%s'\n",
		    t->name, r, buf, r, t->name);
		pass = _B_FALSE;
	}

	DEBUG((" : Received '%.*s'\n", r, buf));

	if (msg.msg_flags != 0) {
		printf("[FAIL] %s - received flags 0x%x\n",
		    t->name, msg.msg_flags);
		pass = _B_FALSE;
	}

	uint8_t flags = 0;

	for (struct cmsghdr *cm = CMSG_FIRSTHDR(&msg); cm != NULL;
	    cm = CMSG_NXTHDR(&msg, cm)) {
		uint8_t d;

		DEBUG((" : >> Got cmsg %x/%x - length %u\n",
		    cm->cmsg_level, cm->cmsg_type, cm->cmsg_len));

		if (cm->cmsg_level != IPPROTO_IP)
			continue;

		switch (cm->cmsg_type) {
		case IP_PKTINFO:
			flags |= RT_RECVPKTINFO;
			if (debug) {
				struct in_pktinfo *pi =
				    (struct in_pktinfo *)CMSG_DATA(cm);
				printf(" : ifIndex: %u\n", pi->ipi_ifindex);
			}
			break;
		case IP_RECVTTL:
			if (cm->cmsg_len != CMSG_LEN(sizeof (uint8_t))) {
				printf(
				    "[FAIL] %s - cmsg_len was %u expected %u\n",
				    t->name, cm->cmsg_len,
				    CMSG_LEN(sizeof (uint8_t)));
				pass = _B_FALSE;
				break;
			}
			flags |= RT_RECVTTL;
			memcpy(&d, CMSG_DATA(cm), sizeof (d));
			DEBUG((" : RECVTTL = %u\n", d));
			if (t->flags & RT_SETTTL && d != t->ttl) {
				printf("[FAIL] %s - TTL was %u, expected %u\n",
				    t->name, d, t->ttl);
				pass = _B_FALSE;
			}
			break;
		case IP_RECVTOS:
			if (cm->cmsg_len != CMSG_LEN(sizeof (uint8_t))) {
				printf(
				    "[FAIL] %s - cmsg_len was %u expected %u\n",
				    t->name, cm->cmsg_len,
				    CMSG_LEN(sizeof (uint8_t)));
				pass = _B_FALSE;
				break;
			}
			flags |= RT_RECVTOS;
			memcpy(&d, CMSG_DATA(cm), sizeof (d));
			DEBUG((" : RECVTOS = %u\n", d));
			if (t->flags & RT_SETTOS && d != t->tos) {
				printf("[FAIL] %s - TOS was %u, expected %u\n",
				    t->name, d, t->tos);
				pass = _B_FALSE;
			}
			break;
		}
	}

	if ((t->flags & RT_RECVMASK) != flags) {
		printf("[FAIL] %s - Did not receive everything expected, "
		    "flags %#x vs. %#x\n", t->name,
		    flags, t->flags & RT_RECVMASK);
		pass = _B_FALSE;
	}

	/* Wait for the client to finish */
	(void) pthread_mutex_lock(&cmutex);
	while (!client_done)
		(void) pthread_cond_wait(&ccv, &cmutex);
	client_done = _B_FALSE;
	(void) pthread_mutex_unlock(&cmutex);

out:
	if (acceptfd != -1)
		(void) close(acceptfd);
	(void) close(sockfd);

	if (pass)
		printf("[PASS] %s\n", t->name);

	return (pass);
}

static int
server(const char *test)
{
	int ret = EXIT_SUCCESS;
	recvmsg_test_t *t;

	for (t = tests; t->name != NULL; t++) {
		if (test != NULL) {
			if (strcmp(test, t->name) != 0)
				continue;
			client_done = _B_TRUE;
			return (servertest(t));
		}
		if (t->flags & RT_SKIP) {
			printf("[SKIP] %s - (requires two separate zones)\n",
			    t->name);
			continue;
		}
		if (!servertest(t))
			ret = EXIT_FAILURE;
	}

	return (ret);
}

static void
clienttest(recvmsg_test_t *t)
{
	struct sockaddr_in addr;
	int s, ret;

	DEBUG(("client %s: starting\n", t->name));

	s = socket(AF_INET, t->flags & RT_STREAM ? SOCK_STREAM : SOCK_DGRAM, 0);
	if (s == -1)
		err(EXIT_FAILURE, "failed to create client socket");

	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = testip;
	addr.sin_port = htons(TESTPORT);

	if (t->flags & RT_STREAM) {
		if (connect(s, (struct sockaddr *)&addr, sizeof (addr)) == -1)
			err(EXIT_FAILURE, "failed to connect to server");
	}

	if (t->flags & RT_SETTOS) {
		int c = t->tos;

		DEBUG(("client %s: setting TOS = 0x%x\n", t->name, c));
		if (setsockopt(s, IPPROTO_IP, IP_TOS, &c, sizeof (c)) == -1)
			err(EXIT_FAILURE, "could not set TOS on client socket");
	}

	if (t->flags & RT_SETTTL) {
		int c = t->ttl;

		DEBUG(("client %s: setting TTL = 0x%x\n", t->name, c));
		if (setsockopt(s, IPPROTO_IP, IP_TTL, &c, sizeof (c)) == -1)
			err(EXIT_FAILURE, "could not set TTL on client socket");
	}

	DEBUG(("client %s: sending\n", t->name));

	if (t->flags & RT_STREAM) {
		ret = send(s, t->name, strlen(t->name), 0);
		shutdown(s, SHUT_RDWR);
	} else {
		ret = sendto(s, t->name, strlen(t->name), 0,
		    (struct sockaddr *)&addr, sizeof (addr));
	}

	if (ret == -1)
		err(EXIT_FAILURE, "sendto failed to send data to server");

	DEBUG(("client %s: done\n", t->name));

	close(s);
}

static void *
client(void *arg)
{
	char *test = (char *)arg;
	recvmsg_test_t *t;

	for (t = tests; t->name != NULL; t++) {
		if (test != NULL) {
			if (strcmp(test, t->name) != 0)
				continue;
			clienttest(t);
			return (NULL);
		}
		if (t->flags & RT_SKIP)
			continue;
		/* Wait for the server to be ready to receive */
		(void) pthread_mutex_lock(&mutex);
		while (!server_ready)
			(void) pthread_cond_wait(&cv, &mutex);
		server_ready = _B_FALSE;
		(void) pthread_mutex_unlock(&mutex);
		clienttest(t);
		/* Tell the server we are done */
		(void) pthread_mutex_lock(&cmutex);
		client_done = _B_TRUE;
		(void) pthread_cond_signal(&ccv);
		(void) pthread_mutex_unlock(&cmutex);
	}

	return (NULL);
}

int
main(int argc, const char **argv)
{
	int ret = EXIT_SUCCESS;
	pthread_t cthread;

	if (argc > 1 && strcmp(argv[1], "-d") == 0) {
		debug = _B_TRUE;
		argc--, argv++;
	}

	/* -c <server IP> <test name> */
	if (argc == 4 && strcmp(argv[1], "-c") == 0) {
		testip = inet_addr(argv[2]);
		printf("TEST IP: %s\n", argv[2]);
		if (testip == INADDR_NONE) {
			err(EXIT_FAILURE,
			    "Could not parse destination IP address");
		}
		client((void *)argv[3]);
		return (ret);
	}

	/* -s <test name> */
	if (argc == 3 && strcmp(argv[1], "-s") == 0)
		return (server(argv[2]));

	testip = inet_addr("127.0.0.1");
	if (testip == INADDR_NONE)
		err(EXIT_FAILURE, "Could not parse destination IP address");

	if (pthread_create(&cthread, NULL, client, NULL) == -1)
		err(EXIT_FAILURE, "Could not create client thread");

	ret = server(NULL);

	if (pthread_join(cthread, NULL) != 0)
		err(EXIT_FAILURE, "join client thread failed");

	return (ret);
}
