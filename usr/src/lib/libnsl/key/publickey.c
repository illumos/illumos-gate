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
 * Portions of this source code were derived from Berkeley 4.3 BSD
 * under license from the Regents of the University of California.
 */

/*
 * publickey.c
 *
 *
 * Public and Private (secret) key lookup routines. These functions
 * are used by the secure RPC auth_des flavor to get the public and
 * private keys for secure RPC principals. Originally designed to
 * talk only to YP, AT&T modified them to talk to files, and now
 * they can also talk to NIS+. The policy for these lookups is now
 * defined in terms of the nameservice switch as follows :
 *	publickey: nis files
 *
 */
#include "mt.h"
#include "../rpc/rpc_mt.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <assert.h>
#include <sys/types.h>
#include <pwd.h>
#include "nsswitch.h"
#include <rpc/rpc.h>
#include <rpc/key_prot.h>
#include <rpcsvc/nis.h>
#include <rpcsvc/ypclnt.h>
#include <rpcsvc/nis_dhext.h>
#include <thread.h>
#include "../nis/gen/nis_clnt.h"
#include <nss_dbdefs.h>


static const char *PKMAP = "publickey.byname";
static const char *PKFILE = "/etc/publickey";
static const char dh_caps_str[] = "DH";
static const char des_caps_str[] = AUTH_DES_AUTH_TYPE;

static char	*netname2hashname(const char *, char *, int, keylen_t,
				algtype_t);

#define	WORKBUFSIZE 1024

extern int xdecrypt();

extern int __yp_match_cflookup(char *, char *, char *, int, char **,
			int *, int *);


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

#ifndef NUL
#define	NUL '\0'
#endif

extern mutex_t serialize_pkey;

static int extract_secret();

/*
 * db_root is used for switch backends.
 */
static DEFINE_NSS_DB_ROOT(db_root);

/*
 * str2key
 */
/* ARGSUSED */
static int
str2key(const char *instr, int lenstr,
			void *ent, char *buffer, int buflen) {
	if (lenstr + 1 > buflen)
		return (NSS_STR_PARSE_ERANGE);
	/*
	 * We copy the input string into the output buffer
	 */
	(void) memcpy(buffer, instr, lenstr);
	buffer[lenstr] = '\0';

	return (NSS_STR_PARSE_SUCCESS);
}
/*
 * These functions are the "backends" for the switch for public keys. They
 * get both the public and private keys from each of the supported name
 * services (nis, files). They are passed the appropriate parameters
 * and return 0 if unsuccessful with *errp set, or 1 when they got just the
 * public key and 3 when they got both the public and private keys.
 *
 *
 * getkey_nis()
 *
 * Internal implementation of getpublickey() using NIS (aka Yellow Pages,
 * aka YP).
 *
 * NOTE : *** this function returns nsswitch codes and _not_ the
 * value returned by getpublickey.
 */
static int
getkeys_nis(int *errp, char *netname, char *pkey, char *skey, char *passwd)
{
	char 	*domain;
	char	*keyval = NULL;
	int	keylen, err, r = 0;
	char	*p;
	int	len;

	p = strchr(netname, '@');
	if (!p) {
		*errp = __NSW_UNAVAIL;
		return (0);
	}

	domain = ++p;


	/*
	 * Instead of calling yp_match(), we use __yp_match_cflookup() here
	 * which has time-out control for the binding operation to nis
	 * servers.
	 */
	err = __yp_match_cflookup(domain, (char *)PKMAP, netname,
	    strlen(netname), &keyval, &keylen, 0);

	switch (err) {
	case YPERR_KEY :
		if (keyval)
			free(keyval);
		*errp = __NSW_NOTFOUND;
		return (0);
	default :
		if (keyval)
			free(keyval);
		*errp = __NSW_UNAVAIL;
		return (0);
	case 0:
		break;
	}

	p = strchr(keyval, ':');
	if (p == NULL) {
		free(keyval);
		*errp = __NSW_NOTFOUND;
		return (0);
	}
	*p = 0;
	if (pkey) {
		len = strlen(keyval);
		if (len > HEXKEYBYTES) {
			free(keyval);
			*errp = __NSW_NOTFOUND;
			return (0);
		}
		(void) strcpy(pkey, keyval);
	}
	r = 1;
	p++;
	if (skey && extract_secret(p, skey, passwd))
		r |= 2;
	free(keyval);
	*errp = __NSW_SUCCESS;
	return (r);
}

/*
 * getkey_files()
 *
 * The files version of getpublickey. This function attempts to
 * get the publickey from the file PKFILE .
 *
 * This function defines the format of the /etc/publickey file to
 * be :
 *	netname <whitespace> publickey:privatekey
 *
 * NOTE : *** this function returns nsswitch codes and _not_ the
 * value returned by getpublickey.
 */

static int
getkeys_files(int *errp, char *netname, char *pkey, char *skey, char *passwd)
{
	char *mkey;
	char *mval;
	char buf[WORKBUFSIZE];
	int	r = 0;
	char *res;
	FILE *fd;
	char *p;
	char *lasts;

	fd = fopen(PKFILE, "rF");
	if (fd == NULL) {
		*errp = __NSW_UNAVAIL;
		return (0);
	}

	/* Search through the file linearly :-( */
	while ((res = fgets(buf, WORKBUFSIZE, fd)) != NULL) {

		if ((res[0] == '#') || (res[0] == '\n'))
			continue;
		else {
			mkey = strtok_r(buf, "\t ", &lasts);
			if (mkey == NULL) {
				syslog(LOG_INFO,
				"getpublickey: Bad record in %s for %s",
				    PKFILE, netname);
				continue;
			}
			mval = strtok_r(NULL, " \t#\n", &lasts);
			if (mval == NULL) {
				syslog(LOG_INFO,
				"getpublickey: Bad record in %s for %s",
				    PKFILE, netname);
				continue;
			}
			/* NOTE : Case insensitive compare. */
			if (strcasecmp(mkey, netname) == 0) {
				p = strchr(mval, ':');
				if (p == NULL) {
					syslog(LOG_INFO,
				"getpublickey: Bad record in %s for %s",
					    PKFILE, netname);
					continue;
				}

				*p = 0;
				if (pkey) {
					int len = strlen(mval);

					if (len > HEXKEYBYTES) {
						syslog(LOG_INFO,
				"getpublickey: Bad record in %s for %s",
						    PKFILE, netname);
						continue;
					}
					(void) strcpy(pkey, mval);
				}
				r = 1;
				p++;
				if (skey && extract_secret(p, skey, passwd))
					r |= 2;
				(void) fclose(fd);
				*errp = __NSW_SUCCESS;
				return (r);
			}
		}
	}

	(void) fclose(fd);
	*errp = __NSW_NOTFOUND;
	return (0);
}

/*
 * getpublickey(netname, key)
 *
 * This is the actual exported interface for this function.
 */

int
__getpublickey_cached(char *netname, char *pkey, int *from_cache)
{
	return (__getpublickey_cached_g(netname, KEYSIZE, 0, pkey,
	    HEXKEYBYTES+1, from_cache));
}

int
getpublickey(const char *netname, char *pkey)
{
	return (__getpublickey_cached((char *)netname, pkey, (int *)0));
}

void
__getpublickey_flush(const char *netname)
{
	__getpublickey_flush_g(netname, 192, 0);
}

int
getsecretkey(const char *netname, char *skey, const char *passwd)
{
	return (getsecretkey_g(netname, KEYSIZE, 0, skey, HEXKEYBYTES+1,
	    passwd));
}

/*
 *  Routines to cache publickeys.
 */


/*
 * Generic DH (any size keys) version of extract_secret.
 */
static int
extract_secret_g(
	char		*raw,		/* in  */
	char		*private,	/* out */
	int		prilen,		/* in  */
	char		*passwd,	/* in  */
	char		*netname,	/* in  */
	keylen_t	keylen,		/* in  */
	algtype_t	algtype)	/* in  */

{
	char	*buf = malloc(strlen(raw) + 1); /* private tmp buf */
	char	*p;

	if (!buf || !passwd || !raw || !private || !prilen ||
			!VALID_KEYALG(keylen, algtype)) {
		if (private)
			*private = NUL;
		if (buf)
			free(buf);
		return (0);
	}

	(void) strcpy(buf, raw);

	/* strip off pesky colon if it exists */
	p = strchr(buf, ':');
	if (p) {
		*p = 0;
	}

	/* raw buf has chksum appended, so let's verify it too */
	if (!xdecrypt_g(buf, keylen, algtype, passwd, netname, TRUE)) {
		private[0] = 0;
		free(buf);
		return (1); /* yes, return 1 even if xdecrypt fails */
	}

	if (strlen(buf) >= prilen) {
		private[0] = 0;
		free(buf);
		return (0);
	}

	(void) strcpy(private, buf);
	free(buf);
	return (1);
}

/*
 * extract_secret()
 *
 * This generic function will extract the private key
 * from a string using the given password. Note that
 * it uses the DES based function xdecrypt()
 */
static int
extract_secret(char *raw, char *private, char *passwd)
{
	return (extract_secret_g(raw, private, HEXKEYBYTES+1, passwd,
	    NULL, KEYSIZE, 0));
}

/*
 * getkeys_ldap_g()
 *
 * Fetches the key pair from LDAP.  This version handles any size
 * DH keys.
 */

void
_nss_initf_publickey(nss_db_params_t *p)
{
	p->name = NSS_DBNAM_PUBLICKEY;
	p->default_config = NSS_DEFCONF_PUBLICKEY;
}


static int
getkeys_ldap_g(
	int		*err,		/* in  */
	char		*netname,	/* in  */
	char		*pkey,		/* out */
	int		pkeylen,	/* in  */
	char		*skey,		/* out */
	int		skeylen,	/* in  */
	char		*passwd,	/* in  */
	keylen_t	keylen,		/* in  */
	algtype_t	algtype)	/* in  */
{
	int		r = 0;
	char		*p;
	char		keytypename[NIS_MAXNAMELEN+1];
	int		len;
	const bool_t	classic_des = AUTH_DES_KEY(keylen, algtype);
	int		rc = 0;
	nss_XbyY_args_t arg;
	nss_XbyY_buf_t	*buf = NULL;
	char		*keyval;

	NSS_XbyY_ALLOC(&buf, 0, NSS_BUFLEN_PUBLICKEY);

	NSS_XbyY_INIT(&arg, buf->result, buf->buffer, buf->buflen, str2key);
	arg.key.pkey.name = netname;

	/*
	 * LDAP stores the public and secret key info in entries using
	 * nisKeyObject objectclass.  Each key is tagged with the
	 * keytype, keylength, and algorithm.  The tag has the following
	 * format: {<keytype><keylength>-<algorithm>}.  For example,
	 * {DH192-0}.
	 */
	if (classic_des)
		(void) strcpy(keytypename, "{DH192-0}");
	else
		(void) sprintf(keytypename, "{%s%d-%d}",
		    dh_caps_str, keylen, algtype);
	arg.key.pkey.keytype = keytypename;

	if (nss_search(&db_root, _nss_initf_publickey, NSS_DBOP_KEYS_BYNAME,
	    &arg) != NSS_SUCCESS) {
		NSS_XbyY_FREE(&buf);
		*err = __NSW_NOTFOUND;
		return (0);
	}
	keyval = buf->buffer;
	p = strchr(keyval, ':');
	if (p == NULL) {
		NSS_XbyY_FREE(&buf);
		*err = __NSW_NOTFOUND;
		return (0);
	}
	*p = 0;
	if (pkey) {
		len = strlen(keyval);
		if (len > HEXKEYBYTES) {
			NSS_XbyY_FREE(&buf);
			*err = __NSW_NOTFOUND;
			return (0);
		}
		(void) strcpy(pkey, keyval);
	}
	r = 1;
	p++;
	if (skey && extract_secret(p, skey, passwd))
		r |= 2;
	NSS_XbyY_FREE(&buf);
	*err = __NSW_SUCCESS;
	return (r);
}


/*
 * Convert a netname to a name we will hash on.  For classic_des,
 * just copy netname as is.  But for new and improved ("now in
 * new longer sizes!") DHEXT, add a ":keylen-algtype" suffix to hash on.
 *
 * Returns the hashname string on success or NULL on failure.
 */
static char *
netname2hashname(
	const char *netname,
	char *hashname,
	int bufsiz,
	keylen_t keylen,
	algtype_t algtype)
{
	const bool_t classic_des = AUTH_DES_KEY(keylen, algtype);

	if (!netname || !hashname || !bufsiz)
		return (NULL);

	if (classic_des) {
		if (bufsiz > strlen(netname))
			(void) strcpy(hashname, netname);
		else
			return (NULL);
	} else {
		char tmp[128];
		(void) sprintf(tmp, ":%d-%d", keylen, algtype);
		if (bufsiz > (strlen(netname) + strlen(tmp)))
			(void) sprintf(hashname, "%s%s", netname, tmp);
		else
			return (NULL);
	}

	return (hashname);
}

/*
 * Flush netname's publickey of the given key length and algorithm type.
 */
void
__getpublickey_flush_g(const char *netname, keylen_t keylen, algtype_t algtype)
{
	char	*p, hashname[MAXNETNAMELEN+1];
	p = netname2hashname(netname, hashname, MAXNETNAMELEN, keylen, algtype);
}

/*
 * Generic DH (any size keys) version of __getpublickey_cached.
 */
int
__getpublickey_cached_g(const char netname[],	/* in  */
			keylen_t keylen,	/* in  */
			algtype_t algtype,	/* in  */
			char *pkey,		/* out */
			size_t pkeylen,		/* in  */
			int *from_cache)	/* in/out  */
{
	int	needfree = 1, res, err;
	struct __nsw_switchconfig *conf;
	struct __nsw_lookup *look;
	enum __nsw_parse_err perr;
	const bool_t classic_des = AUTH_DES_KEY(keylen, algtype);
	int	retry_cache = 0;

	if (!netname || !pkey)
		return (0);

	conf = __nsw_getconfig("publickey", &perr);
	if (!conf) {
		conf = &publickey_default;
		needfree = 0;
	}
	for (look = conf->lookups; look; look = look->next) {
		if (strcmp(look->service_name, "ldap") == 0) {
			res = getkeys_ldap_g(&err, (char *)netname,
			    pkey, pkeylen, NULL, 0, NULL,
			    keylen, algtype);
		/* long DH keys will not be in nis or files */
		} else if (classic_des &&
		    strcmp(look->service_name, "nis") == 0)
			res = getkeys_nis(&err, (char *)netname, pkey,
			    NULL, NULL);
		else if (classic_des &&
		    strcmp(look->service_name, "files") == 0)
			res = getkeys_files(&err, (char *)netname, pkey,
			    NULL, NULL);
		else {
			syslog(LOG_INFO, "Unknown publickey nameservice '%s'",
			    look->service_name);
			err = __NSW_UNAVAIL;
			res = 0;
		}

		switch (look->actions[err]) {
		case __NSW_CONTINUE :
			continue;
		case __NSW_RETURN :
			if (needfree)
				__nsw_freeconfig(conf);
			return ((res & 1) != 0);
		default :
			syslog(LOG_INFO, "Unknown action for nameservice %s",
			    look->service_name);
		}
	}

	if (needfree)
		__nsw_freeconfig(conf);
	return (0);
}



/*
 * Generic (all sizes) DH version of getpublickey.
 */
int
getpublickey_g(
	const char *netname,	/* in  */
	int keylen,		/* in  */
	int algtype,		/* in  */
	char *pkey,		/* out  */
	size_t pkeylen)		/* in  */
{
	return (__getpublickey_cached_g(netname, keylen, algtype, pkey,
	    pkeylen, (int *)0));
}

/*
 * Generic (all sizes) DH version of getsecretkey_g.
 */
int
getsecretkey_g(
	const char	*netname,	/* in  */
	keylen_t	keylen,		/* in  */
	algtype_t	algtype,	/* in  */
	char		*skey,		/* out */
	size_t		skeylen,	/* in  */
	const char	*passwd)	/* in  */
{
	int	needfree = 1, res, err;
	struct __nsw_switchconfig *conf;
	struct __nsw_lookup *look;
	enum __nsw_parse_err perr;
	const bool_t classic_des = AUTH_DES_KEY(keylen, algtype);

	if (!netname || !skey || !skeylen)
		return (0);

	conf = __nsw_getconfig("publickey", &perr);

	if (!conf) {
		conf = &publickey_default;
		needfree = 0;
	}

	for (look = conf->lookups; look; look = look->next) {
		if (strcmp(look->service_name, "ldap") == 0)
			res = getkeys_ldap_g(&err, (char *)netname,
			    NULL, 0, skey, skeylen,
			    (char *)passwd, keylen, algtype);
		/* long DH keys will not be in nis or files */
		else if (classic_des && strcmp(look->service_name, "nis") == 0)
			res = getkeys_nis(&err, (char *)netname,
			    NULL, skey, (char *)passwd);
		else if (classic_des &&
		    strcmp(look->service_name, "files") == 0)
			res = getkeys_files(&err, (char *)netname,
			    NULL, skey, (char *)passwd);
		else {
			syslog(LOG_INFO, "Unknown publickey nameservice '%s'",
			    look->service_name);
			err = __NSW_UNAVAIL;
			res = 0;
		}
		switch (look->actions[err]) {
		case __NSW_CONTINUE :
			continue;
		case __NSW_RETURN :
			if (needfree)
				__nsw_freeconfig(conf);
			return ((res & 2) != 0);
		default :
			syslog(LOG_INFO, "Unknown action for nameservice %s",
			    look->service_name);
		}
	}
	if (needfree)
		__nsw_freeconfig(conf);
	return (0);
}
