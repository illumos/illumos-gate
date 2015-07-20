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
 * Copyright 2015 Gary Mills
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * University Copyright- Copyright (c) 1982, 1986, 1988
 * The Regents of the University of California
 * All Rights Reserved
 *
 * University Acknowledgment- Portions of this document are derived from
 * software developed by the University of California, Berkeley, and its
 * contributors.
 */

#include <sys/types.h>
#include <sys/sockio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stropts.h>
#include <arpa/nameser.h>
#include <resolv.h>

#include <netinet/in.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>

/*
 * Undocumented external function in libnsl
 */
extern int
getdomainname(char *, int);

#define	MAXIFS	256

/*
 * Resolver state default settings
 */

struct state _res = {
	RES_TIMEOUT,		/* retransmition time interval */
	4,				/* number of times to retransmit */
	RES_DEFAULT,		/* options flags */
	1,				/* number of name servers */
};

/*
 * Set up default settings.  If the configuration file exist, the values
 * there will have precedence.  Otherwise, the server address is set to
 * INADDR_LOOPBACK and the default domain name comes from the gethostname().
 * BUT if the NIS/RPC domain name is set, that is used if all else fails.
 *
 * The configuration file should only be used if you want to redefine your
 * domain or run without a server on your machine.
 *
 * Note the user can always override then domain name with the environment
 * variable LOCALDOMAIN which has absolute priority.
 *
 *
 * Return 0 if completes successfully, -1 on error
 */
int
res_init(void)
{
	register FILE *fp;
	register char *cp, **pp;
	register int n;
	char buf[BUFSIZ];
	int nserv = 0;    /* number of nameserver records read from file */
	int haveenv = 0;
	int havesearch = 0;

	_res.nsaddr.sin_addr.s_addr =  htonl(INADDR_LOOPBACK); /* INADDR_ANY */
	_res.nsaddr.sin_family = AF_INET;
	_res.nsaddr.sin_port = htons(NAMESERVER_PORT);
	_res.nscount = 1;

#ifdef SIOCGIFNUM
	{	int numifs, s, n, int_up;
		struct ifconf ifc;
		register struct ifreq *ifrp;
		struct ifreq ifr;
		unsigned bufsize;
		unsigned int flags;
		char *buf;

		if ((s = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
			perror("socket");
			return (-1);
		}
		if (ioctl(s, SIOCGIFNUM, (char *)&numifs) < 0) {
			numifs = MAXIFS;
		}
		bufsize = numifs * sizeof (struct ifreq);
		buf = (char *)malloc(bufsize);
		if (buf == NULL) {
			perror("out of memory");
			(void) close(s);
			return (-1);
		}
		ifc.ifc_len = bufsize;
		ifc.ifc_buf = buf;
		if (ioctl(s, SIOCGIFCONF, (char *)&ifc) < 0) {
			perror("ifconfig: SIOCGIFCONF");
			(void) close(s);
			free(buf);
			return (-1);
		}

		int_up = 0;
		ifrp = ifc.ifc_req;
		for (n = ifc.ifc_len / sizeof (struct ifreq); n > 0;
								n--, ifrp++) {
			(void) memset((void *) &ifr, 0, sizeof (ifr));
			strncpy(ifr.ifr_name, ifrp->ifr_name,
							sizeof (ifr.ifr_name));
			if (ioctl(s, SIOCGIFFLAGS, (char *)&ifr) < 0) {
				perror("SIOCGIFFLAGS");
				(void) close(s);
				free(buf);
				return (-1);
			}
			flags = ifr.ifr_flags;
			/* we are looking for a non-loopback interface */
			if ((flags & IFF_UP) && ((flags & IFF_LOOPBACK) == 0))
				int_up = 1;
		}
		(void) close(s);
		free(buf);
		if (int_up == 0) /* all the non-LOOPBACK interfaces are DOWN */
			return (-1);
	}
#endif /* SIOCGIFNUM */


	/*
	 * for the benefit of hidden NIS domains, we use the same procedure
	 * as sendmail: convert leading + to dot, then drop to first dot
	 */
	(void) getdomainname(buf, BUFSIZ);
	if (buf[0] == '+')
		buf[0] = '.';
#ifdef SYSV
	cp = strchr(buf, (int)'.');
#else
	cp = index(buf, '.');
#endif
	if (cp == NULL)
		strcpy(_res.defdname, buf);
	else
		strcpy(_res.defdname, cp+1);

	/* Allow user to override the local domain definition */
	if ((cp = getenv("LOCALDOMAIN")) != NULL) {
	(void) strncpy(_res.defdname, cp, sizeof (_res.defdname));
	haveenv++;
	}

	if ((fp = fopen(_PATH_RESCONF, "r")) != NULL) {
	/* read the config file */
	while (fgets(buf, sizeof (buf), fp) != NULL) {
	    /* read default domain name */
	    if (!strncmp(buf, "domain", sizeof ("domain") - 1)) {
		if (haveenv)	/* skip if have from environ */
			    continue;
		cp = buf + sizeof ("domain") - 1;
		while (*cp == ' ' || *cp == '\t')
		    cp++;
		if ((*cp == '\0') || (*cp == '\n'))
		    continue;
		(void) strncpy(_res.defdname, cp, sizeof (_res.defdname) - 1);
#ifdef SYSV
		if ((cp = strchr(_res.defdname, (int)'\n')) != NULL)
#else
		if ((cp = index(_res.defdname, '\n')) != NULL)
#endif
		    *cp = '\0';
		havesearch = 0;
		continue;
	    }
	    /* set search list */
	    if (!strncmp(buf, "search", sizeof ("search") - 1)) {
		if (haveenv)	/* skip if have from environ */
		    continue;
		cp = buf + sizeof ("search") - 1;
		while (*cp == ' ' || *cp == '\t')
		    cp++;
		if ((*cp == '\0') || (*cp == '\n'))
		    continue;
		(void) strncpy(_res.defdname, cp, sizeof (_res.defdname) - 1);
#ifdef SYSV
		if ((cp = strchr(_res.defdname, (int)'\n')) != NULL)
#else
		if ((cp = index(_res.defdname, '\n')) != NULL)
#endif
		    *cp = '\0';
		/*
		 * Set search list to be blank-separated strings
		 * on rest of line.
		 */
		cp = _res.defdname;
		pp = _res.dnsrch;
		*pp++ = cp;
		for (n = 0; *cp && pp < _res.dnsrch + MAXDNSRCH; cp++) {
		    if (*cp == ' ' || *cp == '\t') {
			*cp = 0;
			n = 1;
		    } else if (n) {
			*pp++ = cp;
			n = 0;
		    }
		}
		/* null terminate last domain if there are excess */
		while (*cp != '\0' && *cp != ' ' && *cp != '\t')
		    cp++;
		*cp = '\0';
		*pp++ = 0;
		havesearch = 1;
		continue;
	    }
	    /* read nameservers to query */
	    if (!strncmp(buf, "nameserver", sizeof ("nameserver") - 1) &&
		(nserv < MAXNS)) {
		cp = buf + sizeof ("nameserver") - 1;
		while (*cp == ' ' || *cp == '\t')
		    cp++;
		if ((*cp == '\0') || (*cp == '\n'))
		    continue;
		if ((_res.nsaddr_list[nserv].sin_addr.s_addr =
				inet_addr(cp)) == (unsigned) -1) {
		    _res.nsaddr_list[n].sin_addr.s_addr = INADDR_ANY;
		    continue;
		}
		_res.nsaddr_list[nserv].sin_family = AF_INET;
		_res.nsaddr_list[nserv].sin_port = htons(NAMESERVER_PORT);
		nserv++;
		continue;
	    }
	}
	if (nserv > 1)
	    _res.nscount = nserv;
	(void) fclose(fp);
	}
	if (_res.defdname[0] == 0) {
	if (gethostname(buf, sizeof (_res.defdname)) == 0 &&
#ifdef SYSV
	    (cp = strchr(buf, (int)'.')))
#else
	    (cp = index(buf, '.')))
#endif
		(void) strcpy(_res.defdname, cp + 1);
	}

	/* find components of local domain that might be searched */
	if (havesearch == 0) {
	pp = _res.dnsrch;
	*pp++ = _res.defdname;
	for (cp = _res.defdname, n = 0; *cp; cp++)
	    if (*cp == '.')
		n++;
	cp = _res.defdname;
	for (; n >= LOCALDOMAINPARTS && pp < _res.dnsrch + MAXDFLSRCH; n--) {
#ifdef SYSV
	    cp = strchr(cp, (int)'.');
#else
	    cp = index(cp, '.');
#endif
	    *pp++ = ++cp;
	}
	*pp++ = 0;
	}
	_res.options |= RES_INIT;
	return (0);
}
