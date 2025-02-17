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
 * Copyright 2025 Oxide Computer Company
 */

/*
 * This is a mini/silent version of netcat. It's used by a few of the networking
 * tests in this folder to make sure we exercise a full TCP state machine by
 * calling shutdown(SHUT_RD) specifically to make sure that we can hit the
 * TCPS_LAST_ACK state.
 *
 * It basically sets up an event port and tracks attempting to:
 *
 *  - Connect to a target source
 *  - Read some data from the target source (but doesn't care how much)
 *  - Call shutdown for read
 *  - Close the socket
 *
 * We put a 5 second timeout on all of these as an arbitrary threshold.
 */

#include <err.h>
#include <stdlib.h>
#include <port.h>
#include <sys/socket.h>
#include <netdb.h>
#include <port.h>
#include <sys/debug.h>
#include <errno.h>

uint32_t timeout_sec = 5;
const char *hello = "Hello World";

static void
msnc_wait(int port, int sock, int event)
{
	port_event_t pe;
	timespec_t ts;

	if (port_associate(port, PORT_SOURCE_FD, sock, event, NULL) != 0) {
		err(EXIT_FAILURE, "failed to associate for event 0x%x", event);
	}

	ts.tv_sec = (time_t)timeout_sec;
	ts.tv_nsec = 0;
	if (port_get(port, &pe, &ts) != 0) {
		err(EXIT_FAILURE, "failed to wait for event 0x%x", event);
	}

	VERIFY3U(pe.portev_source, ==, PORT_SOURCE_FD);
	VERIFY3U(pe.portev_object, ==, sock);
	if ((pe.portev_events & event) == 0) {
		err(EXIT_FAILURE, "got events we weren't going to handle: "
		    "0x%x, wanted 0x%x", event, event);
	}
}

int
main(int argc, char *argv[])
{
	int ret, cerr, sock, eport;
	struct addrinfo *res, hints;
	socklen_t sz = sizeof (cerr);
	uint8_t buf[16];

	if (argc != 3) {
		(void) fprintf(stderr, "missing required arguments\n");
		errx(EXIT_FAILURE, "msnc: Usage <ip> <port>");
	}

	(void) memset(&hints, 0, sizeof (struct addrinfo));
	hints.ai_flags = AI_NUMERICHOST | AI_ADDRCONFIG;
	hints.ai_family = PF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	if ((ret = getaddrinfo(argv[1], argv[2], &hints, &res)) != 0) {
		errx(EXIT_FAILURE, "failed to resolve %s: %s", argv[1],
		    gai_strerror(ret));
	}

	sock = socket(res->ai_family, res->ai_socktype | SOCK_NONBLOCK,
	    res->ai_protocol);
	if (sock < 0) {
		err(EXIT_FAILURE, "failed to create socket");
	}

	eport = port_create();
	if (eport < 0) {
		err(EXIT_FAILURE, "failed to create event port");
	}

	ret = connect(sock, res->ai_addr, res->ai_addrlen);
	if (ret != 0 && errno != EINPROGRESS && errno != EINTR) {
		err(EXIT_FAILURE, "failed to connect to %s:%s\n", argv[1],
		    argv[2]);
	}

	msnc_wait(eport, sock, POLLOUT);
	if (getsockopt(sock, SOL_SOCKET, SO_ERROR, &cerr, &sz) != 0) {
		err(EXIT_FAILURE, "failed to get connection status sockopt");
	}

	if (write(sock, hello, strlen(hello)) < 0) {
		err(EXIT_FAILURE, "failed to write any data to the socket");
	}

	/*
	 * Read some bytes, the exact quantity doesn't matter. But before that
	 * perform our shutdown() to help get the state machine in motion.
	 */
	msnc_wait(eport, sock, POLLIN);
	if (shutdown(sock, SHUT_WR) != 0) {
		err(EXIT_FAILURE, "failed to shutdown write side socket");
	}

	if (read(sock, buf, sizeof (buf)) < 0) {
		err(EXIT_FAILURE, "failed to read any data from remote side");
	}

	VERIFY0(close(sock));
	VERIFY0(close(eport));
	return (EXIT_SUCCESS);
}
