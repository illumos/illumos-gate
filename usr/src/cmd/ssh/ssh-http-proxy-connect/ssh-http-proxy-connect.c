/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * An http client that let's users 'ssh' to the
 * outside of the firewall by opening up a connection
 * through the http proxy.
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

#define	DEFAULT_HTTPPROXYPORT	"80"
#define	CONNECT_STRLEN		256

static int debug_flag = 0;

static void
usage(void)
{
	(void) fprintf(stderr, gettext("Usage: ssh-http-proxy-connect "
	    "[-h http_proxy_host] [-p http_proxy_port]\n"
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
		"ssh-http-proxy: %s\n", format);
	(void) vfprintf(stderr, fmtbuf, args);
	va_end(args);
}

static void
signal_handler(int sig)
{
	exit(0);
}

int
main(int argc, char **argv)
{
	extern char 	*optarg;
	extern int	optind;
	int 		retval, err_code, sock, ssh_port;
	int		version, ret_code;
	char 		*httpproxy = NULL;
	char		*temp, *httpproxyport = NULL;
	char 		*ssh_host;
	char		connect_str[CONNECT_STRLEN], connect_reply[BUFFER_SIZ];
	char		*ret_string;
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
		    httpproxy = optarg;
		    break;
		case 'p':
		    httpproxyport = optarg;
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
	ssh_port = atoi(argv[optind]);

	/*
	 * If the name of the http proxy were not
	 * passed on the command line, try the
	 * user's environment. First try HTTPPROXY.
	 * If it's not set, try http_proxy.
	 * Check the url specified for http_proxy
	 * for errors.
	 */
	if (httpproxy == NULL) {
	    if ((httpproxy = getenv("HTTPPROXY")) == NULL) {
		/* Try the other environment variable http_proxy */
		if ((temp = getenv("http_proxy")) != NULL) {
		    temp += strlen("http://");
		    if (strpbrk(temp, ":") == NULL) {
			/* Malformed url */
			(void) fprintf(stderr, gettext("ssh-http-proxy: "
			    "Incorrect url specified for http_proxy "
			    "environment variable\n"));
			exit(1);
		    }
		    httpproxy = strtok(temp, ":");
		    httpproxyport = strtok(NULL, "/");
		} else {
		    (void) fprintf(stderr,
			gettext("ssh-http-proxy: http proxy not specified\n"));
		    exit(1);
		}
	    }
	}

	/*
	 * Extract the proxy port number from the user's environment.
	 * Ignored if HTTPPROXY is not set.
	 */
	if ((httpproxy != NULL) && (httpproxyport == NULL)) {
	    if ((httpproxyport = getenv("HTTPPROXYPORT")) == NULL) {
		    httpproxyport = DEFAULT_HTTPPROXYPORT;
	    }
	}

	debug("HTTPPROXY = %s", httpproxy);
	debug("HTTPPROXYPORT = %s", httpproxyport);

	bzero(&hints, sizeof (struct addrinfo));
	hints.ai_family = PF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	if ((err_code = getaddrinfo(httpproxy, httpproxyport, &hints, &ai))
	    != 0) {
	    (void) fprintf(stderr, "ssh-http-proxy: Unable to "
		"perform name lookup\n");
	    (void) fprintf(stderr, "%s: %s\n", httpproxy,
		gai_strerror(err_code));
	    exit(1);
	}

	if ((sock = socket(ai->ai_family, SOCK_STREAM, 0)) < 0) {
	    perror("socket");
	    exit(1);
	}

	/* Connect to the http proxy */
	if (connect(sock, ai->ai_addr, ai->ai_addrlen) == -1) {
	    (void) fprintf(stderr, gettext("ssh-http-proxy: Unable to connect"
		" to %s: %s\n"), httpproxy, strerror(errno));
	    (void) close(sock);
	    exit(1);
	} else {
	    /* Successful connection. */
	    (void) snprintf(connect_str, sizeof (connect_str),
		"CONNECT %s:%d HTTP/1.1\r\n\r\n", ssh_host, ssh_port);
	    if (write(sock, &connect_str, strlen(connect_str)) < 0) {
		perror("write");
		(void) close(sock);
		exit(1);
	    }

	    if (read(sock, connect_reply, sizeof (connect_reply)) == -1) {
		perror("read");
		(void) close(sock);
		exit(1);
	    }

	    if (sscanf(connect_reply, "HTTP/1.%d %d",
		&version, &ret_code) != 2) {
		(void) fprintf(stderr,
		    gettext("ssh-http-proxy: HTTP reply not understood\n"));
		(void) close(sock);
		exit(1);
	    }

	    ret_string = strtok(connect_reply, "\n");

	    /* If the return error code is not 200, print an error and quit. */
	    if (ret_code != 200) {
		(void) fprintf(stderr, "%s\n", ret_string);
		(void) close(sock);
		exit(1);
	    } else {
		debug("%s", ret_string);
	    }
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
