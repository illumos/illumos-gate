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

/* Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T */
/* All Rights Reserved */

/*
 * Portions of this source code were derived from Berkeley 4.3 BSD
 * under license from the Regents of the University of California.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

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
 * Note :
 * 1.  NIS+ combines the netid.byname and publickey.byname maps
 *	into a single NIS+ table named cred.org_dir
 * 2.  To use NIS+, the publickey needs to be
 *	publickey: nisplus
 *	(or have nisplus as the first entry).
 *	The nsswitch.conf file should be updated after running nisinit
 *	to reflect this.
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

static const char *PKTABLE = "cred.org_dir";
static const char *PKMAP = "publickey.byname";
static const char *PKFILE = "/etc/publickey";
static const char dh_caps_str[] = "DH";
static const char des_caps_str[] = AUTH_DES_AUTH_TYPE;

static char	*netname2hashname(const char *, char *, int, keylen_t,
				algtype_t);

#define	PKTABLE_LEN 12
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

static void pkey_cache_add();
static int pkey_cache_get();
static void pkey_cache_flush();

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
 * services (nis, nisplus, files). They are passed the appropriate parameters
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

static NIS_HASH_TABLE pkey_tbl;
struct pkey_item {
	NIS_HASH_ITEM item;
	char *pkey;
};

static void
pkey_cache_add(const char *netname, char *pkey)
{
	struct pkey_item *item;

	if (!netname || !pkey) {
		return;
	}

	item = calloc(1, sizeof (struct pkey_item));
	if (item == NULL) {
		return;
	}
	item->item.name = strdup(netname);
	if (item->item.name == NULL) {
		free((void *)item);
		return;
	}
	item->pkey = strdup(pkey);
	if (item->pkey == 0) {
		free(item->item.name);
		free(item);
		return;
	}

	(void) mutex_lock(&serialize_pkey);
	if (!nis_insert_item((NIS_HASH_ITEM *)item, &pkey_tbl)) {
		free(item->item.name);
		free(item->pkey);
		free((void *)item);
	}
	(void) mutex_unlock(&serialize_pkey);
}

static int
pkey_cache_get(const char *netname, char *pkey)
{
	struct pkey_item *item;

	if (!netname || !pkey) {
		return (0);
	}

	(void) mutex_lock(&serialize_pkey);
	item = (struct pkey_item *)nis_find_item((char *)netname, &pkey_tbl);
	if (item) {
		(void) strcpy(pkey, item->pkey);
	}

	(void) mutex_unlock(&serialize_pkey);
	return (item != 0);
}

static void
pkey_cache_flush(const char *netname)
{
	struct pkey_item *item;

	(void) mutex_lock(&serialize_pkey);

	item = (struct pkey_item *)nis_remove_item((char *)netname, &pkey_tbl);
	if (item) {
		free(item->item.name);
		free(item->pkey);
		free((void *)item);
	}
	(void) mutex_unlock(&serialize_pkey);
}

/*
 * To avoid a potential deadlock with a single root domain NIS+ server
 * talking to a sub-sub-domain server, the NIS+ directory cache manager
 * code must be able to add public keys to the cache. Hence this routine.
 */
void
__pkey_cache_add(char *netname, char *pkey, keylen_t pkeylen,
		algtype_t algtype) {

	char	hashname[MAXNETNAMELEN+1];

	pkey_cache_add(netname2hashname(netname, hashname, sizeof (hashname),
					pkeylen, algtype), pkey);
}

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
 * getkeys_nisplus_g()
 *
 * Fetches the key pair from NIS+.  This version handles any size
 * DH keys.
 */
static int
getkeys_nisplus_g(
	int		*err,		/* in  */
	char		*netname,	/* in  */
	char		*pkey,		/* out */
	int		pkeylen,	/* in  */
	char		*skey,		/* out */
	int		skeylen,	/* in  */
	char		*passwd,	/* in  */
	keylen_t	keylen,		/* in  */
	algtype_t	algtype,	/* in  */
	int		*retry_cache)	/* in/out */
{
	nis_result	*res;
	int		r = 0;
	char		*domain, *p;
	char		buf[NIS_MAXNAMELEN+1];
	char		keytypename[NIS_MAXNAMELEN+1];
	int		len;
	const bool_t	classic_des = AUTH_DES_KEY(keylen, algtype);

	domain = strchr(netname, '@');
	if (!domain) {
		*err = __NSW_UNAVAIL;
		return (0);
	}
	domain++;

	if (retry_cache != NULL && *retry_cache == 1) {
		nis_error	bcerr;
		directory_obj	obj;
		char		hashname[MAXNETNAMELEN];

		bcerr = __nis_CacheBind(domain, &obj);
		xdr_free(xdr_directory_obj, (char *)&obj);
		/*
		 * Even if the __nis_CacheBind failed, we may have reached
		 * part-way to the goal, so have another look in the public
		 * key cache.
		 */
		if (pkey_cache_get(netname2hashname(netname, hashname,
						MAXNETNAMELEN, pkeylen,
						algtype), pkey)) {
			*err = __NSW_SUCCESS;
			return (1);
		}
		*retry_cache = 0;
	}

	if ((strlen(netname)+PKTABLE_LEN+strlen(domain)+32) >
		(size_t)NIS_MAXNAMELEN) {
		*err = __NSW_UNAVAIL;
		return (0);
	}

	/*
	 * Cred table has following format for PK crypto entries:
	 * cname   auth_type auth_name public  private
	 * ----------------------------------------------------------
	 * nisname	AT	netname	pubkey	prikey
	 *
	 * where AT can be "DES" for classic AUTH_DES, or something like
	 * "DH640-0" for a longer Diffie-Hellman key pair.
	 */
	if (classic_des)
		(void) strcpy(keytypename, des_caps_str);
	else
		(void) sprintf(keytypename, "%s%d-%d",
			dh_caps_str, keylen, algtype);
	(void) sprintf(buf, "[auth_name=\"%s\",auth_type=%s],%s.%s",
		netname, keytypename, PKTABLE, domain);
	if (buf[strlen(buf)-1] != '.')
	(void) strcat(buf, ".");

	/*
	 * Because of some bootstrapping issues (keylogin, etc) the
	 * keys lookup needs to be done without auth.  This is
	 * less-then-ideal from a security perspective and hopefully
	 * will be revisited soon...
	 */
	res = nis_list(buf, USE_DGRAM+NO_AUTHINFO+FOLLOW_LINKS+FOLLOW_PATH,
			NULL, NULL);
	switch (res->status) {
	case NIS_SUCCESS:
	case NIS_S_SUCCESS:
		break;
	case NIS_NOTFOUND:
	case NIS_PARTIAL:
	case NIS_NOSUCHNAME:
	case NIS_NOSUCHTABLE:
		nis_freeresult(res);
		*err = __NSW_NOTFOUND;
		return (0);
	case NIS_S_NOTFOUND:
	case NIS_TRYAGAIN:
		syslog(LOG_ERR, "getkeys: (nis+ key lookup): %s\n",
			nis_sperrno(res->status));
		nis_freeresult(res);
		*err = __NSW_TRYAGAIN;
		return (0);
	default:
		*err = __NSW_UNAVAIL;
		syslog(LOG_ERR,
			"getkeys: (nis+ key lookup): %s\n",
			nis_sperrno(res->status));
		nis_freeresult(res);
		return (0);
	}

	if (pkey) {
		char *key_start;
		char *colon_pos;

		/*
		 * For backward compatibility with the old
		 * cred.org_dir format, first locate the ":", if any,
		 * and prepare to null it out.
		 */
		key_start = (char *)ENTRY_VAL(res->objects.objects_val, 3);
		colon_pos = strchr(key_start, ':');

		/*
		 * Set the value of len keeping in mind that both len
		 * and pklen include space for the terminating null.
		 */

		if (colon_pos != NULL)
			/*
			 * Set len to include the colon because that is
			 * where the terminating null will be
			 * placed.
			 */
			len = (int)((uintptr_t)colon_pos -
				    (uintptr_t)key_start + 1);
		else
			/*
			 * ENTRY_LEN already includes the terminating
			 * null.
			 */
			len = ENTRY_LEN(res->objects.objects_val, 3);

		if (len > pkeylen) {
			*err = __NSW_UNAVAIL;
			syslog(LOG_ERR,
		"getkeys(nis+): pub key for '%s' (keytype = '%s') too long",
				netname, keytypename);
			nis_freeresult(res);
			return (0);
		}

		(void) strncpy(pkey, key_start, len);

		/*
		 * Now null out the colon if it exists
		 */
		if (colon_pos != NULL)
			pkey[len-1] = NULL;

	}
	r = 1; /* At least public key was found; always true at this point */

	if (skey && extract_secret_g(ENTRY_VAL(res->objects.objects_val, 4),
				skey, skeylen, passwd, netname, keylen,
				algtype))
		r |= 2;

	nis_freeresult(res);
	*err = __NSW_SUCCESS;
	return (r);
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
	char *p, hashname[MAXNETNAMELEN+1];

	p = netname2hashname(netname, hashname, MAXNETNAMELEN, keylen, algtype);
	if (p)
		pkey_cache_flush(hashname);
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

	if (from_cache) {
		char hashname[MAXNETNAMELEN];
		if (pkey_cache_get(netname2hashname(netname, hashname,
						    MAXNETNAMELEN, keylen,
						    algtype), pkey)) {
			*from_cache = 1;
			return (1);
		}
		*from_cache = 0;
		retry_cache = 1;
	}

	conf = __nsw_getconfig("publickey", &perr);
	if (!conf) {
		conf = &publickey_default;
		needfree = 0;
	}
	for (look = conf->lookups; look; look = look->next) {
		if (strcmp(look->service_name, "nisplus") == 0) {
			res = getkeys_nisplus_g(&err, (char *)netname,
						pkey, pkeylen, NULL, 0, NULL,
						keylen, algtype, &retry_cache);
			if (retry_cache)
				*from_cache = 1;
		} else if (strcmp(look->service_name, "ldap") == 0) {
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
		}

		/*
		 *  If we found the publickey, save it in the cache.
		 *  However, if retry_cache == 1, it's already been
		 *  added to the cache under our feet.
		 */
		if (err == __NSW_SUCCESS && !retry_cache) {
			char hashname[MAXNETNAMELEN];
			pkey_cache_add(netname2hashname(netname, hashname,
							MAXNETNAMELEN, keylen,
							algtype), pkey);
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
 * The public key cache (used by nisd in this case) must be filled with
 * the data in the NIS_COLD_START file in order for extended Diffie-Hellman
 * operations to work.
 */
void
prime_pkey_cache(directory_obj *dobj)
{
	int scount;

	for (scount = 0; scount < dobj->do_servers.do_servers_len; scount++) {
		nis_server *srv = &(dobj->do_servers.do_servers_val[scount]);
		extdhkey_t	*keylens = NULL;
		char		*pkey = NULL, hashname[MAXNETNAMELEN];
		char		netname[MAXNETNAMELEN];
		int		kcount, nkeys = 0;

		(void) host2netname(netname, srv->name, NULL);

		/* determine the number of keys to process */
		if (!(nkeys = __nis_dhext_extract_keyinfo(srv, &keylens)))
			continue;

		/* store them */
		if (srv->key_type == NIS_PK_DHEXT) {
			for (kcount = 0; kcount < nkeys; kcount++) {
				if (!netname2hashname(netname, hashname,
						MAXNETNAMELEN,
						keylens[kcount].keylen,
						keylens[kcount].algtype))
					continue;

				if (!(pkey = __nis_dhext_extract_pkey(
					&srv->pkey, keylens[kcount].keylen,
					keylens[kcount].algtype)))
					continue;

				if (!pkey_cache_get(hashname, pkey))
					pkey_cache_add(hashname, pkey);
			}
		} else if (srv->key_type == NIS_PK_DH) {
			pkey = srv->pkey.n_bytes;

			if (netname2hashname(netname, hashname, MAXNETNAMELEN,
					KEYSIZE, 0) &&
				    !pkey_cache_get(hashname, pkey))
				pkey_cache_add(hashname, pkey);
		}
		if (keylens != NULL)
			free(keylens);
		keylens = NULL;
	}
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
		if (strcmp(look->service_name, "nisplus") == 0)
			res = getkeys_nisplus_g(&err, (char *)netname,
					NULL, 0, skey, skeylen,
					(char *)passwd, keylen, algtype, 0);
		else if (strcmp(look->service_name, "ldap") == 0)
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
