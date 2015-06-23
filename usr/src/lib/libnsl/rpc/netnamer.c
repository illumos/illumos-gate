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
/*
 * Copyright 2014 Nexenta Systems, Inc.  All rights reserved.
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
 * netname utility routines convert from netnames to unix names (uid, gid)
 *
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
#include <alloca.h>
#include <sys/types.h>
#include <ctype.h>
#include <grp.h>
#include <pwd.h>
#include <string.h>
#include <syslog.h>
#include <sys/param.h>
#include <nsswitch.h>
#include <rpc/rpc.h>
#include <rpcsvc/nis.h>
#include <rpcsvc/ypclnt.h>
#include <nss_dbdefs.h>

static const char    OPSYS[]	= "unix";
static const char    NETIDFILE[] = "/etc/netid";
static const char    NETID[]	= "netid.byname";
#define	OPSYS_LEN 4

extern int _getgroupsbymember(const char *, gid_t[], int, int);

/*
 * the value for NOBODY_UID is set by the SVID. The following define also
 * appears in netname.c
 */

#define	NOBODY_UID 60001

/*
 *	default publickey policy:
 *		publickey: nis [NOTFOUND = return] files
 */


/*		NSW_NOTSUCCESS  NSW_NOTFOUND   NSW_UNAVAIL    NSW_TRYAGAIN */
#define	DEF_ACTION {__NSW_RETURN, __NSW_RETURN, __NSW_CONTINUE, __NSW_CONTINUE}

static struct __nsw_lookup lookup_files = {"files", DEF_ACTION, NULL, NULL},
		lookup_nis = {"nis", DEF_ACTION, NULL, &lookup_files};
static struct __nsw_switchconfig publickey_default =
			{0, "publickey", 2, &lookup_nis};

static mutex_t serialize_netname_r = DEFAULTMUTEX;

struct netid_userdata {
	uid_t	*uidp;
	gid_t	*gidp;
	int	*gidlenp;
	gid_t	*gidlist;
};

static int
parse_uid(char *s, struct netid_userdata *argp)
{
	uid_t	u;

	if (!s || !isdigit(*s)) {
		syslog(LOG_ERR,
		    "netname2user: expecting uid '%s'", s);
		return (__NSW_NOTFOUND); /* xxx need a better error */
	}

	/* Fetch the uid */
	u = (uid_t)(atoi(s));

	if (u == 0) {
		syslog(LOG_ERR, "netname2user: should not have uid 0");
		return (__NSW_NOTFOUND);
	}
	*(argp->uidp) = u;
	return (__NSW_SUCCESS);
}


/* parse a comma separated gid list */
static int
parse_gidlist(char *p, struct netid_userdata *argp)
{
	int len;
	gid_t	g;

	if (!p || (!isdigit(*p))) {
		syslog(LOG_ERR,
		    "netname2user: missing group id list in '%s'.",
		    p);
		return (__NSW_NOTFOUND);
	}

	g = (gid_t)(atoi(p));
	*(argp->gidp) = g;

	len = 0;
	while (p = strchr(p, ','))
		argp->gidlist[len++] = (gid_t)atoi(++p);
	*(argp->gidlenp) = len;
	return (__NSW_SUCCESS);
}


/*
 * parse_netid_str()
 *
 * Parse uid and group information from the passed string.
 *
 * The format of the string passed is
 * 	uid:gid,grp,grp, ...
 *
 */
static int
parse_netid_str(char *s, struct netid_userdata *argp)
{
	char	*p;
	int	err;

	/* get uid */
	err = parse_uid(s, argp);
	if (err != __NSW_SUCCESS)
		return (err);

	/* Now get the group list */
	p = strchr(s, ':');
	if (!p) {
		syslog(LOG_ERR,
		    "netname2user: missing group id list in '%s'", s);
		return (__NSW_NOTFOUND);
	}
	++p;			/* skip ':' */
	err = parse_gidlist(p, argp);
	return (err);
}

/*
 * netname2user_files()
 *
 * This routine fetches the netid information from the "files" nameservice.
 * ie /etc/netid.
 */
static int
netname2user_files(int *err, char *netname, struct netid_userdata *argp)
{
	char 	buf[512];	/* one line from the file */
	char	*name;
	char	*value;
	char 	*res;
	FILE	*fd;

	fd = fopen(NETIDFILE, "rF");
	if (fd == NULL) {
		*err = __NSW_UNAVAIL;
		return (0);
	}
	/*
	 * for each line in the file parse it appropriately
	 * file format is :
	 *	netid	uid:grp,grp,grp # for users
	 *	netid	0:hostname	# for hosts
	 */
	while (!feof(fd)) {
		res = fgets(buf, 512, fd);
		if (res == NULL)
			break;

		/* Skip comments and blank lines */
		if ((*res == '#') || (*res == '\n'))
			continue;

		name = &(buf[0]);
		while (isspace(*name))
			name++;
		if (*name == '\0')	/* blank line continue */
			continue;
		value = name;		/* will contain the value eventually */
		while (!isspace(*value))
			value++;
		if (*value == '\0') {
			syslog(LOG_WARNING,
			    "netname2user: badly formatted line in %s.",
			    NETIDFILE);
			continue;
		}
		*value++ = '\0'; /* nul terminate the name */

		if (strcasecmp(name, netname) == 0) {
			(void) fclose(fd);
			while (isspace(*value))
				value++;
			*err = parse_netid_str(value, argp);
			return (*err == __NSW_SUCCESS);
		}
	}
	(void) fclose(fd);
	*err = __NSW_NOTFOUND;
	return (0);
}

/*
 * netname2user_nis()
 *
 * This function reads the netid from the NIS (YP) nameservice.
 */
static int
netname2user_nis(int *err, char *netname, struct netid_userdata *argp)
{
	char *domain;
	int yperr;
	char *lookup;
	int len;

	domain = strchr(netname, '@');
	if (!domain) {
		*err = __NSW_UNAVAIL;
		return (0);
	}

	/* Point past the '@' character */
	domain++;
	lookup = NULL;
	yperr = yp_match(domain, (char *)NETID, netname, strlen(netname),
	    &lookup, &len);
	switch (yperr) {
		case 0:
			break; /* the successful case */

		default :
			/*
			 *  XXX not sure about yp_match semantics.
			 * should err be set to NOTFOUND here?
			 */
			*err = __NSW_UNAVAIL;
			return (0);
	}
	if (lookup) {
		lookup[len] = '\0';
		*err = parse_netid_str(lookup, argp);
		free(lookup);
		return (*err == __NSW_SUCCESS);
	}
	*err = __NSW_NOTFOUND;
	return (0);
}

/*
 * Build the uid and gid from the netname for users in LDAP.
 * There is no netid container in LDAP. For this we build
 * the netname to user data dynamically from the passwd and
 * group data. This works only for users in a single domain.
 * This function is an interim solution until we support a
 * netid container in LDAP which enables us to do netname2user
 * resolution for multiple domains.
 */
static int
netname2user_ldap(int *err, char *netname, struct netid_userdata *argp)
{
	char buf[NSS_LINELEN_PASSWD];
	char *p2, *lasts;
	struct passwd pw;
	uid_t uidnu;
	int ngroups = 0;
	int count;
	char pwbuf[NSS_LINELEN_PASSWD];
	int maxgrp = sysconf(_SC_NGROUPS_MAX);
	gid_t *groups = alloca(maxgrp * sizeof (gid_t));

	if (strlcpy(buf, netname, NSS_LINELEN_PASSWD) >= NSS_LINELEN_PASSWD) {
		*err = __NSW_UNAVAIL;
		return (0);
	}

	/* get the uid from the netname */
	if (strtok_r(buf, ".", &lasts) == NULL) {
		*err = __NSW_UNAVAIL;
		return (0);
	}
	if ((p2 = strtok_r(NULL, "@", &lasts)) == NULL) {
		*err = __NSW_UNAVAIL;
		return (0);
	}
	uidnu = atoi(p2);

	/*
	 * check out the primary group and crosscheck the uid
	 * with the passwd data
	 */
	if ((getpwuid_r(uidnu, &pw, pwbuf, sizeof (pwbuf))) == NULL) {
		*err = __NSW_UNAVAIL;
		return (0);
	}

	*(argp->uidp) = pw.pw_uid;
	*(argp->gidp) = pw.pw_gid;

	/* search through all groups for membership */

	groups[0] = pw.pw_gid;

	ngroups = _getgroupsbymember(pw.pw_name, groups, maxgrp,
	    (pw.pw_gid <= MAXUID) ? 1 : 0);

	if (ngroups < 0) {
		*err = __NSW_UNAVAIL;
		return (0);
	}

	*(argp->gidlenp) = ngroups;

	for (count = 0; count < ngroups; count++) {
		(argp->gidlist[count]) = groups[count];
	}

	*err = __NSW_SUCCESS;
	return (1);

}

/*
 * Convert network-name into unix credential
 */
int
netname2user(const char netname[MAXNETNAMELEN + 1], uid_t *uidp, gid_t *gidp,
						int *gidlenp, gid_t *gidlist)
{
	struct __nsw_switchconfig *conf;
	struct __nsw_lookup *look;
	enum __nsw_parse_err perr;
	int needfree = 1, res;
	struct netid_userdata argp;
	int err;

	/*
	 * Take care of the special case of nobody. Compare the netname
	 * to the string "nobody". If they are equal, return the SVID
	 * standard value for nobody.
	 */

	if (strcmp(netname, "nobody") == 0) {
		*uidp = NOBODY_UID;
		*gidp = NOBODY_UID;
		*gidlenp = 0;
		return (1);
	}

	/*
	 * First we do some generic sanity checks on the name we were
	 * passed. This lets us assume they are correct in the backends.
	 *
	 * NOTE: this code only recognizes names of the form :
	 *		unix.UID@domainname
	 */
	if (strncmp(netname, OPSYS, OPSYS_LEN) != 0)
		return (0);
	if (!isdigit(netname[OPSYS_LEN+1]))	/* check for uid string */
		return (0);

	argp.uidp = uidp;
	argp.gidp = gidp;
	argp.gidlenp = gidlenp;
	argp.gidlist = gidlist;
	(void) mutex_lock(&serialize_netname_r);

	conf = __nsw_getconfig("publickey", &perr);
	if (!conf) {
		conf = &publickey_default;
		needfree = 0;
	} else
		needfree = 1; /* free the config structure */

	for (look = conf->lookups; look; look = look->next) {
		if (strcmp(look->service_name, "nis") == 0)
			res = netname2user_nis(&err, (char *)netname, &argp);
		else if (strcmp(look->service_name, "files") == 0)
			res = netname2user_files(&err, (char *)netname, &argp);
		else if (strcmp(look->service_name, "ldap") == 0)
			res = netname2user_ldap(&err, (char *)netname, &argp);
		else {
			syslog(LOG_INFO,
			    "netname2user: unknown nameservice for publickey"
			    "info '%s'\n", look->service_name);
			err = __NSW_UNAVAIL;
			res = 0;
		}
		switch (look->actions[err]) {
			case __NSW_CONTINUE :
				break;
			case __NSW_RETURN :
				if (needfree)
					(void) __nsw_freeconfig(conf);
				(void) mutex_unlock(&serialize_netname_r);
				return (res);
			default :
				syslog(LOG_ERR,
				    "netname2user: Unknown action for "
				    "nameservice '%s'", look->service_name);
		}
	}
	if (needfree)
		(void) __nsw_freeconfig(conf);
	(void) mutex_unlock(&serialize_netname_r);
	return (0);
}

/*
 * Convert network-name to hostname (fully qualified)
 * NOTE: this code only recognizes names of the form :
 *		unix.HOST@domainname
 *
 * This is very simple.  Since the netname is of the form:
 *	unix.host@domainname
 * We just construct the hostname using information from the domainname.
 */
int
netname2host(const char netname[MAXNETNAMELEN + 1], char *hostname,
							const int hostlen)
{
	char *p, *domainname;
	int len, dlen;

	if (!netname) {
		syslog(LOG_ERR, "netname2host: null netname");
		goto bad_exit;
	}

	if (strncmp(netname, OPSYS, OPSYS_LEN) != 0)
		goto bad_netname;
	p = (char *)netname + OPSYS_LEN;	/* skip OPSYS part */
	if (*p != '.')
		goto bad_netname;
	++p;				/* skip '.' */

	domainname = strchr(p, '@');	/* get domain name */
	if (domainname == 0)
		goto bad_netname;

	len = domainname - p;		/* host sits between '.' and '@' */
	domainname++;			/* skip '@' sign */

	if (len <= 0)
		goto bad_netname;

	if (hostlen < len) {
		syslog(LOG_ERR,
		    "netname2host: insufficient space for hostname");
		goto bad_exit;
	}

	if (isdigit(*p))		/* don't want uid here */
		goto bad_netname;

	if (*p == '\0')			/* check for null hostname */
		goto bad_netname;

	(void) strncpy(hostname, p, len);

	/* make into fully qualified hostname by concatenating domain part */
	dlen = strlen(domainname);
	if (hostlen < (len + dlen + 2)) {
		syslog(LOG_ERR,
		    "netname2host: insufficient space for hostname");
		goto bad_exit;
	}

	hostname[len] = '.';
	(void) strncpy(hostname+len+1, domainname, dlen);
	hostname[len+dlen+1] = '\0';

	return (1);

bad_netname:
	syslog(LOG_ERR, "netname2host: invalid host netname %s", netname);

bad_exit:
	hostname[0] = '\0';
	return (0);
}
