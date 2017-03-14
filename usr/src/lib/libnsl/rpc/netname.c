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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/* Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T */
/* All Rights Reserved */
/*
 * Portions of this source code were derived from Berkeley
 * 4.3 BSD under license from the Regents of the University of
 * California.
 */
/*
 * ==== hack-attack:  possibly MT-safe but definitely not MT-hot.
 * ==== turn this into a real switch frontend and backends
 *
 * Well, at least the API doesn't involve pointers-to-static.
 */

/*
 * netname utility routines (getnetname, user2netname, host2netname).
 *
 * Convert from unix names (uid, gid) to network wide names.
 * This module is operating system dependent!
 * What we define here will work with any unix system that has adopted
 * the Sun NIS domain architecture.
 */

#undef NIS

#include "mt.h"
#include "rpc_mt.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <ctype.h>
#include <string.h>
#include <syslog.h>
#include <sys/param.h>
#include <rpc/rpc.h>
#include <rpcsvc/nis.h>
#include <rpcsvc/nis_dhext.h>
#include <nsswitch.h>
#include <syslog.h>
#include <errno.h>

#ifndef MAXHOSTNAMELEN
#define	MAXHOSTNAMELEN 256
#endif
#ifndef NGROUPS
#define	NGROUPS 16
#endif

/*
 * the value for NOBODY_UID is set by the SVID. The following define also
 * appears in netnamer.c
 */

#define	NOBODY_UID 60001

extern int getdomainname();
extern int key_call();
#define	OPSYS_LEN 4
static const char *OPSYS = "unix";

/*
 * default publickey policy:
 *	publickey: nis [NOTFOUND = return] files
 */


/*	NSW_NOTSUCCESS  NSW_NOTFOUND   NSW_UNAVAIL    NSW_TRYAGAIN */
#define	DEF_ACTION {__NSW_RETURN, __NSW_RETURN, __NSW_CONTINUE, __NSW_CONTINUE}

static struct __nsw_lookup lookup_files = {"files", DEF_ACTION, NULL, NULL},
		lookup_nis = {"nis", DEF_ACTION, NULL, &lookup_files};
static struct __nsw_switchconfig publickey_default =
			{0, "publickey", 2, &lookup_nis};

static mutex_t serialize_netname = ERRORCHECKMUTEX;


#define	MAXIPRINT	(11)	/* max length of printed integer */

/*
 * Convert unix cred to network-name by concatenating the
 * 3 pieces of information <opsys type> <uid> <domain>.
 */

static int
user2netname_nis(int *err, char netname[MAXNETNAMELEN + 1], uid_t uid,
    char *domain)
{
	int i;
	char *dfltdom;
	if (domain == NULL) {
		if (__rpc_get_default_domain(&dfltdom) != 0) {
			*err = __NSW_UNAVAIL;
			return (0);
		}
		domain = dfltdom;
	}
	if ((strlen(domain) + OPSYS_LEN + 3 + MAXIPRINT) >
	    (size_t)MAXNETNAMELEN) {
		*err = __NSW_UNAVAIL;
		return (0);
	}
	(void) snprintf(netname, MAXNETNAMELEN + 1,
	    "%s.%d@%s", OPSYS, (int)uid, domain);
	i = strlen(netname);
	if (netname[i-1] == '.')
		netname[i-1] = '\0';
	*err = __NSW_SUCCESS;
	return (1);
}

/*
 * Figure out my fully qualified network name
 */
int
getnetname(char name[MAXNETNAMELEN + 1])
{
	uid_t uid;

	uid = geteuid();
	if (uid == 0)
		return (host2netname(name, NULL, NULL));
	return (user2netname(name, uid, NULL));
}


/*
 * Figure out the fully qualified network name for the given uid.
 * This is a private interface.
 */
int
__getnetnamebyuid(char name[MAXNETNAMELEN + 1], uid_t uid)
{
	if (uid == 0)
		return (host2netname(name, NULL, NULL));
	return (user2netname(name, uid, NULL));
}

/*
 * Convert unix cred to network-name
 *
 * It uses the publickey policy in the /etc/nsswitch.conf file
 * (Unless the netname is "nobody", which is special cased).
 * If there is no publickey policy in /etc/nsswitch.conf,
 * the default publickey policy is used, which is
 *	publickey: nis [NOTFOUND=return] files
 * Note that for the non-nisplus case, there is no failover
 * so only the first entry would be relevant for those cases.
 */
int
user2netname(char netname[MAXNETNAMELEN + 1], const uid_t uid,
    const char *domain)
{
	struct __nsw_switchconfig *conf;
	struct __nsw_lookup *look;
	int needfree = 1, res = 0;
	enum __nsw_parse_err perr;
	int err;

	/*
	 * Take care of the special case of "nobody". If the uid is
	 * the value assigned by the SVID for nobody, return the string
	 * "nobody".
	 */

	if (uid == NOBODY_UID) {
		(void) strlcpy(netname, "nobody", MAXNETNAMELEN + 1);
		return (1);
	}

	netname[0] = '\0';  /* make null first (no need for memset) */

	if (mutex_lock(&serialize_netname) == EDEADLK) {
		/*
		 * This thread already holds this lock. This scenario
		 * occurs when a process requires a netname which
		 * itself requires a netname to look up. As we clearly
		 * can't continue like this we return 'nobody'.
		 */
		(void) strlcpy(netname, "nobody", MAXNETNAMELEN + 1);
		return (1);
	}

	conf = __nsw_getconfig("publickey", &perr);
	if (!conf) {
		conf = &publickey_default;
		needfree = 0;
	}

	for (look = conf->lookups; look; look = look->next) {
		/* ldap, nis, and files all do the same thing. */
		if (strcmp(look->service_name, "ldap") == 0 ||
		    strcmp(look->service_name, "nis") == 0 ||
		    strcmp(look->service_name, "files") == 0)
			res = user2netname_nis(&err,
			    netname, uid, (char *)domain);
		else {
			syslog(LOG_INFO,
			    "user2netname: unknown nameservice \
					for publickey info '%s'\n",
			    look->service_name);
			err = __NSW_UNAVAIL;
		}
		switch (look->actions[err]) {
			case __NSW_CONTINUE :
				break;
			case __NSW_RETURN :
				if (needfree)
					(void) __nsw_freeconfig(conf);
				(void) mutex_unlock(&serialize_netname);
				return (res);
			default :
				syslog(LOG_ERR,
			"user2netname: Unknown action for nameservice '%s'",
				    look->service_name);
			}
	}
	if (needfree)
		(void) __nsw_freeconfig(conf);
	(void) mutex_unlock(&serialize_netname);
	return (0);
}


/*
 * Convert host to network-name
 * This routine returns following netnames given the host and domain
 * arguments defined below: (domainname=y.z)
 *	  Arguments
 *	host	domain		netname
 *	----	------		-------
 *	-	-		unix.m@y.z (hostname=m)
 *	-	a.b		unix.m@a.b (hostname=m)
 *	-	-		unix.m@y.z (hostname=m.w.x)
 *	-	a.b		unix.m@a.b (hostname=m.w.x)
 *	h	-		unix.h@y.z
 *	h	a.b		unix.h@a.b
 *	h.w.x	-		unix.h@w.x
 *	h.w.x	a.b		unix.h@a.b
 */
int
host2netname(char netname[MAXNETNAMELEN + 1], const char *host,
    const char *domain)
{
	char *p;
	char hostname[MAXHOSTNAMELEN + 1];
	char domainname[MAXHOSTNAMELEN + 1];
	char *dot_in_host;
	int i;
	size_t len;

	netname[0] = '\0';  /* make null first (no need for memset) */

	if (host == NULL) {
		(void) strncpy(hostname, nis_local_host(), sizeof (hostname));
		p = (char *)strchr(hostname, '.');
		if (p) {
			*p++ = '\0';
			/* if no domain passed, use tail of nis_local_host() */
			if (domain == NULL) {
				domain = p;
			}
		}
	} else {
		len = strlen(host);
		if (len >= sizeof (hostname)) {
			return (0);
		}
		(void) strcpy(hostname, host);
	}

	dot_in_host = (char *)strchr(hostname, '.');
	if (domain == NULL) {
		p = dot_in_host;
		if (p) {
			p = (char *)nis_domain_of(hostname);
			len = strlen(p);
			if (len >= sizeof (domainname)) {
				return (0);
			}
			(void) strcpy(domainname, p);
		} else {
			domainname[0] = NULL;
			if (getdomainname(domainname, MAXHOSTNAMELEN) < 0)
				return (0);
		}
	} else {
		len = strlen(domain);
		if (len >= sizeof (domainname)) {
			return (0);
		}
		(void) strcpy(domainname, domain);
	}

	i = strlen(domainname);
	if (i == 0)
		/* No domainname */
		return (0);
	if (domainname[i - 1] == '.')
		domainname[i - 1] = 0;

	if (dot_in_host) {  /* strip off rest of name */
		*dot_in_host = '\0';
	}

	if ((strlen(domainname) + strlen(hostname) + OPSYS_LEN + 3)
	    > (size_t)MAXNETNAMELEN) {
		return (0);
	}

	(void) snprintf(netname, MAXNETNAMELEN + 1,
	    "%s.%s@%s", OPSYS, hostname, domainname);
	return (1);
}
