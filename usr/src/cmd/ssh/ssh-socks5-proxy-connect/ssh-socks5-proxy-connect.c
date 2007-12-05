/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 *
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * A SOCKS client that let's users 'ssh' to the
 * outside of the firewall by opening up a connection
 * through the SOCKS server. Supports only SOCKS v5.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <strings.h>
#include <unistd.h>
#include <inttypes.h>
#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <locale.h>
#include <libintl.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <sys/stropts.h>
#include <sys/stat.h>
#include <sys/varargs.h>
#include "proxy-io.h"

#define	DEFAULT_SOCKS5_PORT	"1080"

static int debug_flag = 0;

static void
usage(void)
{
	(void) fprintf(stderr, gettext("Usage: ssh-socks5-proxy-connect "
	    "[-h socks5_proxy_host] [-p socks5_proxy_port] \n"
	    "remote_host remote_port\n"));
	exit(1);
}

/* PRINTFLIKE1 */
static void
debug(const char *format, ...)
{
	char fmtbuf[BUFFER_SIZ];
	va_list args;

	if (debug_flag == 0) {
	    return;
	}
	va_start(args, format);
	(void) snprintf(fmtbuf, sizeof (fmtbuf),
	    "ssh-socks5-proxy: %s\n", format);
	(void) vfprintf(stderr, fmtbuf, args);
	va_end(args);
}

static void
signal_handler(int sig)
{
	exit(0);
}

static int
do_version_exchange(int sockfd)
{
	char buffer[3], recv_buf[2];

	buffer[0] = 0x05;			/* VER */
	buffer[1] = 0x01;			/* NMETHODS */
	buffer[2] = 0x00;			/* METHODS */

	if (write(sockfd, &buffer, sizeof (buffer)) < 0) {
	    perror("write");
	    return (0);
	}

	if (read(sockfd, &recv_buf, sizeof (recv_buf)) == -1) {
	    perror("read");
	    return (0);
	}

	/*
	 * No need to check the server's version as per
	 * the protocol spec. Check the method supported
	 * by the server. Currently if the server does not
	 * support NO AUTH, we disconnect.
	 */
	if (recv_buf[1] != 0x00) {
	    debug("Unsupported Authentication Method");
	    return (0);
	}

	/* Return success. */
	return (1);
}

static void
send_request(
    int sockfd,
    const char *ssh_host,
    uchar_t ssh_host_len,
    uint16_t *ssh_port)
{
	int failure = 1;
	char *buffer, *temp, recv_buf[BUFFER_SIZ];
	uchar_t version = 0x05, cmd = 0x01, rsv = 0x00, atyp = 0x03;

	buffer = malloc(strlen(ssh_host) + 7);

	temp = buffer;

	/* Assemble the request packet */
	(void) memcpy(temp, &version, sizeof (version));
	temp += sizeof (version);
	(void) memcpy(temp, &cmd, sizeof (cmd));
	temp += sizeof (cmd);
	(void) memcpy(temp, &rsv, sizeof (rsv));
	temp += sizeof (rsv);
	(void) memcpy(temp, &atyp, sizeof (atyp));
	temp += sizeof (atyp);
	(void) memcpy(temp, &ssh_host_len, sizeof (ssh_host_len));
	temp += sizeof (ssh_host_len);
	(void) memcpy(temp, ssh_host, strlen(ssh_host));
	temp += strlen(ssh_host);
	(void) memcpy(temp, ssh_port, sizeof (*ssh_port));
	temp += sizeof (*ssh_port);

	if (write(sockfd, buffer, temp - buffer) == -1) {
	    perror("write");
	    exit(1);
	}

	/*
	 * The maximum size of the protocol message we are waiting for is 10
	 * bytes -- VER[1], REP[1], RSV[1], ATYP[1], BND.ADDR[4] and
	 * BND.PORT[2]; see RFC 1928, section "6. Replies" for more details.
	 * Everything else is already a part of the data we are supposed to
	 * deliver to the requester. We know that BND.ADDR is exactly 4 bytes
	 * since as you can see below, we accept only ATYP == 1 which specifies
	 * that the IPv4 address is in a binary format.
	 */
	if (read(sockfd, &recv_buf, 10) == -1) {
	    perror("read");
	    exit(1);
	}

	/* temp now points to the recieve buffer. */
	temp = recv_buf;

	/* Check the server's version. */
	if (*temp++ != 0x05) {
	    (void) fprintf(stderr, gettext("Unsupported SOCKS version: %x\n"),
		recv_buf[0]);
	    exit(1);
	}

	/* Check server's reply */
	switch (*temp++) {
	    case 0x00:
		failure = 0;
		debug("CONNECT command Succeeded.");
		break;
	    case 0x01:
		debug("General SOCKS server failure.");
		break;
	    case 0x02:
		debug("Connection not allowed by ruleset.");
		break;
	    case 0x03:
		debug("Network Unreachable.");
		break;
	    case 0x04:
		debug("Host unreachable.");
		break;
	    case 0x05:
		debug("Connection refused.");
		break;
	    case 0x06:
		debug("TTL expired.");
		break;
	    case 0x07:
		debug("Command not supported");
		break;
	    case 0x08:
		debug("Address type not supported.");
		break;
	    default:
		(void) fprintf(stderr, gettext("ssh-socks5-proxy: "
		    "SOCKS Server reply not understood\n"));
	}

	if (failure == 1) {
	    exit(1);
	}

	/* Parse the rest of the packet */

	/* Ignore RSV */
	temp++;

	/* Check ATYP */
	if (*temp != 0x01) {
	    (void) fprintf(stderr, gettext("ssh-socks5-proxy: "
		"Address type not supported: %u\n"), *temp);
	    exit(1);
	}

	free(buffer);
}

int
main(int argc, char **argv)
{
	extern char 	*optarg;
	extern int	optind;
	int 		retval, err_code, sock;
	uint16_t 	ssh_port;
	uchar_t 	ssh_host_len;
	char 		*socks_server = NULL, *socks_port = NULL;
	char 		*ssh_host;
	struct 		addrinfo hints, *ai;
	struct 		pollfd fds[2];

	/* Initialization for variables, set locale and textdomain */

	(void) setlocale(LC_ALL, "");

#if !defined(TEXT_DOMAIN)	/* Should be defined by cc -D */
#define	TEXT_DOMAIN "SYS_TEST"  /* Use this only if it weren't */
#endif
	(void) textdomain(TEXT_DOMAIN);

	/* Set up the signal handler */
	(void) signal(SIGINT, signal_handler);
	(void) signal(SIGPIPE, signal_handler);
	(void) signal(SIGPOLL, signal_handler);

	while ((retval = getopt(argc, argv, "dp:h:")) != -1) {
	    switch (retval) {
		case 'h':
		    socks_server = optarg;
		    break;
		case 'p':
		    socks_port = optarg;
		    break;
		case 'd':
		    debug_flag = 1;
		    break;
		default:
		    break;
	    }
	}

	if (optind != argc - 2) {
		usage();
	}

	ssh_host = argv[optind++];
	ssh_host_len = (uchar_t)strlen(ssh_host);
	ssh_port = htons(atoi(argv[optind]));

	/*
	 * If the name and/or port number of the
	 * socks server were not passed on the
	 * command line, try the user's environment.
	 */
	if (socks_server == NULL) {
	    if ((socks_server = getenv("SOCKS5_SERVER")) == NULL) {
		(void) fprintf(stderr, gettext("ssh-socks5-proxy: "
		    "SOCKS5 SERVER not specified\n"));
		exit(1);
	    }
	}
	if (socks_port == NULL) {
	    if ((socks_port = getenv("SOCKS5_PORT")) == NULL) {
		socks_port = DEFAULT_SOCKS5_PORT;
	    }
	}

	debug("SOCKS5_SERVER = %s", socks_server);
	debug("SOCKS5_PORT = %s", socks_port);

	bzero(&hints, sizeof (struct addrinfo));
	hints.ai_family = PF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	if ((err_code = getaddrinfo(socks_server, socks_port, &hints, &ai))
	    != 0) {
	    (void) fprintf(stderr, "%s: %s\n", socks_server,
		gai_strerror(err_code));
	    exit(1);
	}

	if ((sock = socket(ai->ai_family, SOCK_STREAM, 0)) < 0) {
	    perror("socket");
	    exit(1);
	}

	/* Connect to the SOCKS server */
	if (connect(sock, ai->ai_addr, ai->ai_addrlen) == 0) {
	    debug("Connected to the SOCKS server");
	    /* Do the SOCKS v5 communication with the server. */
	    if (do_version_exchange(sock) > 0) {
		debug("Done version exchange");
		send_request(sock, ssh_host, ssh_host_len, &ssh_port);
	    } else {
		(void) fprintf(stderr, gettext("ssh-socks5-proxy: Client and "
		    "Server versions differ.\n"));
		(void) close(sock);
		exit(1);
	    }
	} else {
	    perror("connect");
	    (void) close(sock);
	    exit(1);
	}

	fds[0].fd = STDIN_FILENO; 	/* Poll stdin for data. */
	fds[1].fd = sock; 		/* Poll the socket for data. */
	fds[0].events = fds[1].events = POLLIN;

	for (;;) {
	    if (poll(fds, 2, INFTIM) == -1) {
		perror("poll");
		(void) close(sock);
		exit(1);
	    }

	    /* Data arrived on stdin, write it to the socket */
	    if (fds[0].revents & POLLIN) {
		if (proxy_read_write_loop(STDIN_FILENO, sock) == 0) {
			(void) close(sock);
			exit(1);
		}
	    } else if (fds[0].revents & (POLLERR | POLLHUP | POLLNVAL)) {
		(void) close(sock);
		exit(1);
	    }

	    /* Data arrived on the socket, write it to stdout */
	    if (fds[1].revents & POLLIN) {
		if (proxy_read_write_loop(sock, STDOUT_FILENO) == 0) {
			(void) close(sock);
			exit(1);
		}
	    } else if (fds[1].revents & (POLLERR | POLLHUP | POLLNVAL)) {
		(void) close(sock);
		exit(1);
	    }
	}

	/* NOTREACHED */
	return (0);
}
