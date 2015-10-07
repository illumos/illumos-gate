/*
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*
 * Copyright (c) 1984 Regents of the University of California.
 * All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * Sun Microsystems, Inc.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *      This product includes software developed by the University of
 *      California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */


/*
 * arp - display, set, and delete arp table entries
 */

#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <netdb.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <net/if_types.h>
#include <net/if_dl.h>

static int file(char *);
static int set(int, char *[]);
static void get(char *);
static void delete(char *);
static void usage(void);

int
main(int argc, char *argv[])
{
	int c, nflags = 0, argsleft;
	int n_flag, a_flag, d_flag, f_flag, s_flag;

	n_flag = a_flag = d_flag = f_flag = s_flag = 0;

#define	CASE(x, y)				\
		case x:				\
			if (nflags > 0) {	\
				usage();	\
				exit(1);	\
			} else			\
				y##_flag = 1;	\
				nflags++;	\
			break

	while ((c = getopt(argc, argv, "nadfs")) != EOF) {
		switch (c) {
		case '?':
			usage();
			exit(1);
			/* NOTREACHED */
			break;
		case 'n':
			n_flag = 1;
			break;
		CASE('a', a);
		CASE('d', d);
		CASE('f', f);
		CASE('s', s);
		}
	}

#undef CASE

	/*
	 * -n only allowed with -a
	 */
	if (n_flag && !a_flag) {
		usage();
		exit(1);
	}

	argsleft = argc - optind;

	if (a_flag && (argsleft == 0)) {
		/*
		 * the easiest way to get the complete arp table
		 * is to let netstat, which prints it as part of
		 * the MIB statistics, do it.
		 */
		(void) execl("/usr/bin/netstat", "netstat",
		    (n_flag ? "-np" : "-p"),
		    "-f", "inet", (char *)0);
		(void) fprintf(stderr, "failed to exec netstat: %s\n",
		    strerror(errno));
		exit(1);

	} else if (s_flag && (argsleft >= 2)) {
		if (set(argsleft, &argv[optind]) != 0)
			exit(1);

	} else if (d_flag && (argsleft == 1)) {
		delete(argv[optind]);

	} else if (f_flag && (argsleft == 1)) {
		if (file(argv[optind]) != 0)
			exit(1);

	} else if ((nflags == 0) && (argsleft == 1)) {
		get(argv[optind]);

	} else {
		usage();
		exit(1);
	}
	return (0);
}

/*
 * Process a file to set standard arp entries
 */
static int
file(char *name)
{
	/*
	 * A line of input can be:
	 * <hostname> <macaddr> ["temp"] ["pub"] ["trail"] ["permanent"]
	 */
#define	MAX_LINE_LEN	(MAXHOSTNAMELEN + \
	sizeof (" xx:xx:xx:xx:xx:xx temp pub trail permanent\n"))
#define	MIN_ARGS	2
#define	MAX_ARGS	5

	FILE *fp;
	char line[MAX_LINE_LEN];
	int retval;

	if ((fp = fopen(name, "r")) == NULL) {
		(void) fprintf(stderr, "arp: cannot open %s\n", name);
		exit(1);
	}

	retval = 0;
	while (fgets(line, MAX_LINE_LEN, fp) != NULL) {
		char line_copy[MAX_LINE_LEN];
		char *args[MAX_ARGS];
		char *start;
		int i;

		/*
		 * Keep a copy of the un-altered line for error
		 * reporting.
		 */
		(void) strlcpy(line_copy, line, MAX_LINE_LEN);

		start = line_copy;
		for (i = 0; i < MAX_ARGS; i++) {
			if ((args[i] = strtok(start, " \t\n")) == NULL)
				break;

			start = NULL;
		}

		if (i < MIN_ARGS) {
			(void) fprintf(stderr, "arp: bad line: %s\n",
			    line);
			retval = 1;
			continue;
		}

		if (set(i, args) != 0)
			retval = 1;
	}

#undef	MAX_LINE_LEN
#undef	MIN_ARGS
#undef	MAX_ARGS

	(void) fclose(fp);
	return (retval);
}

/*
 * Set an individual arp entry
 */
static int
set(int argc, char *argv[])
{
	struct xarpreq ar;
	struct hostent *hp;
	struct sockaddr_in *sin;
	uchar_t *ea;
	int s;
	char *host = argv[0], *eaddr = argv[1];

	argc -= 2;
	argv += 2;
	(void) memset(&ar, 0, sizeof (ar));
	sin = (struct sockaddr_in *)&ar.xarp_pa;
	sin->sin_family = AF_INET;
	sin->sin_addr.s_addr = inet_addr(host);
	if (sin->sin_addr.s_addr == (in_addr_t)-1) {
		hp = gethostbyname(host);
		if (hp == NULL) {
			(void) fprintf(stderr, "arp: %s: unknown host\n",
			    host);
			return (1);
		}
		(void) memcpy(&sin->sin_addr, hp->h_addr,
		    sizeof (sin->sin_addr));
	}
	ea = _link_aton(eaddr, &s);
	if (ea == NULL) {
		if (s == -1) {
			(void) fprintf(stderr,
			    "arp: invalid link layer address '%s'\n", eaddr);
			return (1);
		}
		perror("arp: nomem");
		exit(1);
	}
	ar.xarp_ha.sdl_alen = s;
	(void) memcpy(LLADDR(&ar.xarp_ha), ea, ar.xarp_ha.sdl_alen);
	free(ea);
	ar.xarp_ha.sdl_family = AF_LINK;
	ar.xarp_flags = ATF_PERM;
	while (argc-- > 0) {
		if (strncmp(argv[0], "temp", 4) == 0) {
			ar.xarp_flags &= ~ATF_PERM;
		} else if (strncmp(argv[0], "pub", 3) == 0) {
			ar.xarp_flags |= ATF_PUBL;
		} else if (strncmp(argv[0], "trail", 5) == 0) {
			ar.xarp_flags |= ATF_USETRAILERS;
		} else if (strcmp(argv[0], "permanent") == 0) {
			ar.xarp_flags |= ATF_AUTHORITY;
		} else {
			(void) fprintf(stderr,
			    "arp: unknown keyword '%s'\n", argv[0]);
			return (1);
		}
		argv++;
	}

	if ((ar.xarp_flags & (ATF_PERM|ATF_AUTHORITY)) == ATF_AUTHORITY) {
		(void) fprintf(stderr, "arp: 'temp' and 'permanent' flags are "
		    "not usable together.\n");
		return (1);
	}

	s = socket(AF_INET, SOCK_DGRAM, 0);
	if (s < 0) {
		perror("arp: socket");
		exit(1);
	}
	if (ioctl(s, SIOCSXARP, (caddr_t)&ar) < 0) {
		perror(host);
		exit(1);
	}
	(void) close(s);
	return (0);
}

/*
 * Display an individual arp entry
 */
static void
get(char *host)
{
	struct xarpreq ar;
	struct hostent *hp;
	struct sockaddr_in *sin;
	uchar_t *ea;
	int s;
	char *str = NULL;

	(void) memset(&ar, 0, sizeof (ar));
	sin = (struct sockaddr_in *)&ar.xarp_pa;
	sin->sin_family = AF_INET;
	sin->sin_addr.s_addr = inet_addr(host);
	if (sin->sin_addr.s_addr == (in_addr_t)-1) {
		hp = gethostbyname(host);
		if (hp == NULL) {
			(void) fprintf(stderr, "arp: %s: unknown host\n",
			    host);
			exit(1);
		}
		(void) memcpy(&sin->sin_addr, hp->h_addr,
		    sizeof (sin->sin_addr));
	}
	s = socket(AF_INET, SOCK_DGRAM, 0);
	if (s < 0) {
		perror("arp: socket");
		exit(1);
	}
	ar.xarp_ha.sdl_family = AF_LINK;
	if (ioctl(s, SIOCGXARP, (caddr_t)&ar) < 0) {
		if (errno == ENXIO)
			(void) printf("%s (%s) -- no entry\n",
			    host, inet_ntoa(sin->sin_addr));
		else
			perror("SIOCGXARP");
		exit(1);
	}
	(void) close(s);
	ea = (uchar_t *)LLADDR(&ar.xarp_ha);
	if (ar.xarp_flags & ATF_COM) {
		str = _link_ntoa(ea, str, ar.xarp_ha.sdl_alen, IFT_OTHER);
		if (str != NULL) {
			(void) printf("%s (%s) at %s", host,
			    inet_ntoa(sin->sin_addr), str);
			free(str);
		} else {
			perror("arp: nomem");
			exit(1);
		}
	} else {
		(void) printf("%s (%s) at (incomplete)", host,
		    inet_ntoa(sin->sin_addr));
	}
	if (!(ar.xarp_flags & ATF_PERM))
		(void) printf(" temp");
	if (ar.xarp_flags & ATF_PUBL)
		(void) printf(" pub");
	if (ar.xarp_flags & ATF_USETRAILERS)
		(void) printf(" trail");
	if (ar.xarp_flags & ATF_AUTHORITY)
		(void) printf(" permanent");
	(void) printf("\n");
}

/*
 * Delete an arp entry
 */
static void
delete(char *host)
{
	struct xarpreq ar;
	struct hostent *hp;
	struct sockaddr_in *sin;
	int s;

	(void) memset(&ar, 0, sizeof (ar));
	sin = (struct sockaddr_in *)&ar.xarp_pa;
	sin->sin_family = AF_INET;
	sin->sin_addr.s_addr = inet_addr(host);
	if (sin->sin_addr.s_addr == (in_addr_t)-1) {
		hp = gethostbyname(host);
		if (hp == NULL) {
			(void) fprintf(stderr, "arp: %s: unknown host\n",
			    host);
			exit(1);
		}
		(void) memcpy(&sin->sin_addr, hp->h_addr,
		    sizeof (sin->sin_addr));
	}
	s = socket(AF_INET, SOCK_DGRAM, 0);
	if (s < 0) {
		perror("arp: socket");
		exit(1);
	}
	ar.xarp_ha.sdl_family = AF_LINK;
	if (ioctl(s, SIOCDXARP, (caddr_t)&ar) < 0) {
		if (errno == ENXIO)
			(void) printf("%s (%s) -- no entry\n",
			    host, inet_ntoa(sin->sin_addr));
		else
			perror("SIOCDXARP");
		exit(1);
	}
	(void) close(s);
	(void) printf("%s (%s) deleted\n", host, inet_ntoa(sin->sin_addr));
}

static void
usage(void)
{
	(void) printf("Usage: arp hostname\n");
	(void) printf("       arp -a [-n]\n");
	(void) printf("       arp -d hostname\n");
	(void) printf("       arp -s hostname ether_addr "
	    "[temp] [pub] [trail] [permanent]\n");
	(void) printf("       arp -f filename\n");
}
