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
 */
/*
 * Copyright (c) 1999 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <malloc.h>
#include <syslog.h>
#include <sys/tiuser.h>

#define	ACCFILE "/var/yp/securenets"
#define	MAXLINE 128

typedef union {
	struct in_addr	in4;
	struct in6_addr	in6;
} inaddr_t;

struct seclist {
	sa_family_t	af;
	inaddr_t	mask;
	inaddr_t	net;
	struct seclist	*next;
};

static int	string2inaddr(char *, sa_family_t *, inaddr_t *);
static int	addrequal(sa_family_t af, inaddr_t *laddr, inaddr_t *mask,
					inaddr_t *caddr);

static struct seclist *slist;
static int nofile = 0;

void
get_secure_nets(char *daemon_name)
{
	FILE *fp;
	char strung[MAXLINE], nmask[MAXLINE], net[MAXLINE];
	inaddr_t maskin, netin;
	sa_family_t maskaf, netaf;
	struct seclist *tmp1, *tmp2;
	int items = 0, line = 0;
	if (fp = fopen(ACCFILE, "r")) {
		tmp1 = (struct seclist *) malloc(sizeof (struct seclist));
		slist = tmp2 = tmp1;
		while (fgets(strung, MAXLINE, fp)) {
			line++;
			if (strung[strlen(strung) - 1] != '\n') {
				syslog(LOG_ERR|LOG_DAEMON,
					"%s: %s line %d: too long\n",
					daemon_name, ACCFILE, line);
				exit(1);
			}
			if (strung[0] != '#') {
				items++;
				if (sscanf(strung,
					"%46s%46s", nmask, net) < 2) {

					syslog(LOG_ERR|LOG_DAEMON,
					"%s: %s line %d: missing fields\n",
						daemon_name, ACCFILE, line);
					exit(1);
				}
				netaf = AF_UNSPEC;
				if (! string2inaddr(net, &netaf, &netin)) {
					syslog(LOG_ERR|LOG_DAEMON,
					"%s: %s line %d: error in address\n",
						daemon_name, ACCFILE, line);
					exit(1);
				}
				maskaf = netaf;
				if (! string2inaddr(nmask, &maskaf, &maskin) ||
						maskaf != netaf) {
					syslog(LOG_ERR|LOG_DAEMON,
					"%s: %s line %d: error in netmask\n",
						daemon_name, ACCFILE, line);
					exit(1);
				}
				if (! addrequal(netaf, &netin, &maskin,
							&netin)) {
					syslog(LOG_ERR|LOG_DAEMON,
			"%s: %s line %d: netmask does not match network\n",
						daemon_name, ACCFILE, line);
					exit(1);
				}

				tmp1->af = netaf;
				tmp1->mask = maskin;
				tmp1->net = netin;
				tmp1->next = (struct seclist *)
					malloc(sizeof (struct seclist));
				tmp2 = tmp1;
				tmp1 = tmp1->next;
			}
		}
		tmp2->next = NULL;
		/* if nothing to process, set nofile flag and free up memory */
		if (items == 0) {
			free(slist);
			nofile = 1;
		}
	} else {
		syslog(LOG_WARNING|LOG_DAEMON, "%s: no %s file\n",
			daemon_name, ACCFILE);
		nofile = 1;
	}
}

int
check_secure_net_ti(struct netbuf *caller, char *ypname) {
	struct seclist *tmp;
	sa_family_t af;
	inaddr_t addr;
	char buf[INET6_ADDRSTRLEN];

	if (nofile)
		return (1);

	af = ((struct sockaddr_storage *)caller->buf)->ss_family;
	if (af == AF_INET) {
		addr.in4 = ((struct sockaddr_in *)caller->buf)->sin_addr;
	} else if (af == AF_INET6) {
		addr.in6 = ((struct sockaddr_in6 *)caller->buf)->sin6_addr;
	} else {
		return (1);
	}

	tmp = slist;
	while (tmp != NULL) {
		if (af == tmp->af &&
			addrequal(af, &tmp->net, &tmp->mask, &addr)) {
			return (1);
		}
		tmp = tmp->next;
	}
	syslog(LOG_ERR|LOG_DAEMON, "%s: access denied for %s\n",
		ypname, inet_ntop(af,
			(af == AF_INET6) ? (void *)&addr.in6 :
				(void *)&addr.in4, buf, sizeof (buf)));

	return (0);
}


static int
string2inaddr(char *string, sa_family_t *af, inaddr_t *addr) {

	sa_family_t	stringaf = AF_UNSPEC;

	stringaf = (strchr(string, ':') != 0) ?	AF_INET6 : AF_INET;

	if (*af != AF_UNSPEC && strcmp(string, "host") == 0) {
		if (*af == AF_INET) {
			string = "255.255.255.255";
			stringaf = AF_INET;
		} else if (*af == AF_INET6) {
			string = "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff";
			stringaf = AF_INET6;
		}
	}

	*af = stringaf;
	if (inet_pton(*af, string, (*af == AF_INET6) ? (void *)&addr->in6 :
						(void *)&addr->in4) != 1) {
		return (0);
	}

	return (1);
}


static int
addrequal(sa_family_t af, inaddr_t *laddr, inaddr_t *mask, inaddr_t *caddr) {

	if (af == AF_INET6) {
		int i;
		for (i = 0; i < sizeof (laddr->in6.s6_addr); i++) {
			if ((caddr->in6.s6_addr[i] & mask->in6.s6_addr[i]) !=
					laddr->in6.s6_addr[i])
				return (0);
		}
		return (1);
	} else if (af == AF_INET) {
		return ((caddr->in4.s_addr & mask->in4.s_addr) ==
				laddr->in4.s_addr);
	} else {
		return (0);
	}
}


static void
print_inaddr(char *string, sa_family_t af, inaddr_t *addr) {

	char buf[INET6_ADDRSTRLEN];

	printf("%s %s %s\n",
		string, (af == AF_INET6)?"AF_INET6":"AF_INET",
		inet_ntop(af, (af == AF_INET6) ? (void *)&addr->in6 :
				(void *)&addr->in4, buf, sizeof (buf)));
}
