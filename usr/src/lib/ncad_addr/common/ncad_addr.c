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
 */
/*
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Shim library which should be LD_PRELOADed before running applications
 * that interact with NCA but do not explicitly use the AF_NCA family.
 * This library overloads AF_INET's version of bind(3SOCKET) with AF_NCA's
 * version.  The new version of bind checks to see if that the port is one
 * NCA is listening on, closes the socket(3SOCKET), and opens a new one
 * the family AF_NCA.  Afterwards, the real bind(3SOCKET) is called
 * descriptors, etc. *
 *
 * Compile:	cc -Kpic -G -o ncad_addr.so ncad_addr.c -lsocket -lnsl
 * Use:		LD_PRELOAD=/path/to/ncad_addr.so my_program
 */

#include <stdio.h>
#include <assert.h>
#include <dlfcn.h>
#include <door.h>
#include <errno.h>
#include <fcntl.h>
#include <inet/nd.h>
#include <unistd.h>
#include <stropts.h>
#include <sys/stat.h>
#include <string.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <netdb.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#pragma	weak bind = nca_bind
#pragma init(ncad_init)
#pragma	fini(ncad_fini)

#define	SEPARATOR	'/'

typedef int sfunc1_t(int, int, int);
typedef int sfunc2_t(int, const struct sockaddr *, socklen_t);

static sfunc1_t *real_socket;
static sfunc2_t *real_bind;

/*
 * It is used to represent an address NCA is willing to handle.
 */
typedef struct nca_address_s {
	uint16_t	port;	/* port, in network byte order */
	ipaddr_t	ipaddr;	/* IP address, in network byte order */
} nca_address_t;

static uint32_t		addrcount;	/* current address count */
static uint32_t		addrcapacity;	/* capacity of ncaaddrs */
static nca_address_t	*ncaaddrs;	/* array for all addresses */

/*
 * It loads all NCA addresses from a configuration file. A NCA address
 * entry is: ncaport=IPaddress:port. The line above can be repeatly for other
 * addresses. If IPaddress is '*', then it is translated into INADDR_ANY.
 */
static void
ncad_init(void)
{
	uint16_t	port;
	ipaddr_t	addr;
	FILE		*fp;
	char		*s, *p, *q;
	char		buffer[1024];
	const char	*filename = "/etc/nca/ncaport.conf";

	real_socket = (sfunc1_t *)dlsym(RTLD_NEXT, "socket");
	real_bind = (sfunc2_t *)dlsym(RTLD_NEXT, "bind");

	if ((fp = fopen(filename, "rF")) == NULL) {
		(void) fprintf(stderr, "Failed to open file %s for reading in "
				" ncad_addr.so. Error = %s\n",
				filename,
				(p = strerror(errno)) ? p : "unknown error");
		return;
	}

	while (fgets(buffer, sizeof (buffer), fp) != NULL) {
		s = buffer;

		/* remove '\n' at the end from fgets() */
		p = strchr(s, '\n');
		if (p != NULL)
			*p = '\0';

		/* remove spaces from the front */
		while (*s != '\0' && isspace(*s))
			s++;

		if (*s == '\0' || *s == '#')
			continue;

		/* it should start with ncaport= */
		p = strchr(s, '=');
		if (p == NULL || strncasecmp(s, "ncaport", 7) != 0)
			continue;

		p++;
		while (*p != '\0' && isspace(*p))
			p++;

		q = strchr(p, SEPARATOR);
		if (q == NULL)
			continue;
		*q++ = '\0';
		if (strcmp(p, "*") == 0) {
			addr = INADDR_ANY;
		} else {
			if (inet_pton(AF_INET, p, &addr) != 1) {
				struct in6_addr addr6;

				if (inet_pton(AF_INET6, p, &addr6) == 1) {
					(void) fprintf(stderr,
						"NCA does not support IPv6\n");
				} else {
					(void) fprintf(stderr,
						"Invalid IP address: %s\n", p);
				}
				continue;
			}
		}
		port = atoi(q);

		/* array is full, expand it */
		if (addrcount == addrcapacity) {
			if (addrcapacity == 0)
				addrcapacity = 64;
			else
				addrcapacity *= 2;
			ncaaddrs = realloc(ncaaddrs,
			    addrcapacity * sizeof (nca_address_t));
			if (ncaaddrs == NULL) {
				(void) fprintf(stderr, "out of memory");
				break;
			}
		}

		ncaaddrs[addrcount].ipaddr = addr;
		ncaaddrs[addrcount].port = htons(port);
		addrcount++;
	}

	(void) fclose(fp);
}

/*
 * It destroys memory at the end of program.
 */
static void
ncad_fini(void)
{
	if (ncaaddrs != NULL) {
		free(ncaaddrs);
		ncaaddrs = NULL;
	}
}

/*
 * If the bind is happening on a port NCA is listening on, close
 * the socket and open a new one with family AF_NCA.
 */
static int
nca_bind(int sock, const struct sockaddr *name, socklen_t namelen)
{
	struct sockaddr_in sin;
	int new_sock;
	int i;

	if (sock < 0) {
		errno = EBADF;
		return (-1);
	}

	if (real_socket == NULL) {
		if ((real_socket = (sfunc1_t *)dlsym(RTLD_NEXT, "socket"))
		    == NULL) {
			errno = EAGAIN;
			exit(-1);
		}
	}

	if (real_bind == NULL) {
		if ((real_bind = (sfunc2_t *)dlsym(RTLD_NEXT, "bind"))
		    == NULL) {
			errno = EAGAIN;
			exit(-1);
		}
	}

	if (name == NULL ||
	    ncaaddrs == NULL ||
	    name->sa_family != AF_INET ||
	    namelen != sizeof (sin)) {
		return (real_bind(sock, name, namelen));
	}

	(void) memcpy(&sin, name, sizeof (sin));

	/*
	 * If it is one of the addresses NCA is handling, convert it
	 * to NCA socket.
	 */
	for (i = 0; i < addrcount; i++) {
		if (sin.sin_port == ncaaddrs[i].port &&
		    (sin.sin_addr.s_addr == ncaaddrs[i].ipaddr ||
		    ncaaddrs[i].ipaddr == INADDR_ANY)) {
			/* convert to NCA socket */
			new_sock = real_socket(AF_NCA, SOCK_STREAM, 0);
			if (new_sock >= 0) {
				(void) dup2(new_sock, sock);
				(void) close(new_sock);
				sin.sin_family = AF_NCA;
			}
			break;
		}
	}

	return (real_bind(sock, (struct sockaddr *)&sin, namelen));
}
