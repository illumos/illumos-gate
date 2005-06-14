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
 * Copyright 1994-2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 *	npd_svcsubr.c
 *	Contains the sub-routines required by the server.
 *
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <syslog.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <memory.h>
#include <shadow.h>
#include <crypt.h>
#include <rpc/rpc.h>
#include <rpc/xdr.h>
#include <rpc/key_prot.h>
#include <rpc/des_crypt.h>
#include <mp.h>
#include <rpcsvc/nis.h>
#include <rpcsvc/nispasswd.h>
#include <rpcsvc/nis_dhext.h>
#include <unistd.h>
#include <pwd.h>
#include <limits.h>
#include "npd_svcsubr.h"
#include "nisplus_tables.h"

extern int verbose;
extern bool_t debug;
extern bool_t generatekeys;

bool_t __npd_prin2netname(char *, char []);
static struct passwd *nis_object2passwd(nis_object *obj);

/*
 * get the password information for this user
 * the result should be freed using nis_freeresult()
 */
struct nis_result *
nis_getpwdent(user, domain)
char		*user;
char		*domain;
{
	char	buf[NIS_MAXNAMELEN];

	if ((user == NULL || *user == '\0') ||
		(domain == NULL || *domain == '\0'))
		return (NULL);

	/* strlen("[name=],passwd.org_dir.") + null + "." = 25 */
	if ((25 + strlen(user) + strlen(domain)) >
					(size_t)NIS_MAXNAMELEN)
		return (NULL);

	(void) sprintf(buf, "[name=%s],passwd.org_dir.%s", user, domain);
	if (buf[strlen(buf) - 1] != '.')
		(void) strcat(buf, ".");

	return (nis_list(buf, USE_DGRAM+MASTER_ONLY, NULL, NULL));
}

/*
 * get the credential information for this user
 * the result should be freed using nis_freeresult()
 */
static struct nis_result *
nis_getcredent(principal, domain, auth_type)
char	*principal;
char	*domain;
char	*auth_type;
{
	char	buf[NIS_MAXNAMELEN];

	if ((principal == NULL || *principal == '\0') ||
		(domain == NULL || *domain == '\0') || auth_type == NULL)
		return (NULL);

	/* strlen("[cname=,auth_type=],cred.org_dir.") + null + "." = 35 */
	if ((35 + strlen(principal) + strlen(domain)) >
				(size_t)NIS_MAXNAMELEN)
		return (NULL);

	(void) sprintf(buf, "[cname=%s,auth_type=%s],cred.org_dir.%s",
			principal, auth_type, domain);

	if (buf[strlen(buf) - 1] != '.')
		(void) strcat(buf, ".");

	return (nis_list(buf, USE_DGRAM+MASTER_ONLY, NULL, NULL));
}

static bool_t
__npd_fill_spwd(obj, sp)
struct nis_object *obj;
struct	spwd	*sp;
{
	long	val;
	char	*p = NULL, *ageinfo = NULL;
	char	*ep, *end;

	/* defaults */
	sp->sp_lstchg = -1;
	sp->sp_min = -1;
	sp->sp_max = -1;
	sp->sp_warn = -1;
	sp->sp_inact = -1;
	sp->sp_expire = -1;
	sp->sp_flag = 0;

	/* shadow information is in column 7 */
	if ((p = ENTRY_VAL(obj, 7)) == NULL)
		return (FALSE);
	if ((ageinfo = strdup(p)) == NULL)
		return (FALSE);

	p = ageinfo;
	end = ageinfo + ENTRY_LEN(obj, 7);

	/* format is: lstchg:min:max:warn:inact:expire:flag */

	val = strtol(p, &ep, 10);	/* base = 10 */
	if (*ep != ':' || ep >= end) {
		(void) free(ageinfo);
		return (FALSE);
	}
	if (ep != p)
		sp->sp_lstchg = val;
	p = ep + 1;

	val = strtol(p, &ep, 10);
	if (*ep != ':' || ep >= end) {
		(void) free(ageinfo);
		return (FALSE);
	}
	if (ep != p)
		sp->sp_min = val;
	p = ep + 1;

	val = strtol(p, &ep, 10);
	if (*ep != ':' || ep >= end) {
		(void) free(ageinfo);
		return (FALSE);
	}
	if (ep != p)
		sp->sp_max = val;
	p = ep + 1;

	val = strtol(p, &ep, 10);
	if (*ep != ':' || ep >= end) {
		(void) free(ageinfo);
		return (FALSE);
	}
	if (ep != p)
		sp->sp_warn = val;
	p = ep + 1;

	val = strtol(p, &ep, 10);
	if (*ep != ':' || ep >= end) {
		(void) free(ageinfo);
		return (FALSE);
	}
	if (ep != p)
		sp->sp_inact = val;
	p = ep + 1;

	val = strtol(p, &ep, 10);
	if (*ep != ':' || ep >= end) {
		(void) free(ageinfo);
		return (FALSE);
	}
	if (ep != p)
		sp->sp_expire = val;
	p = ep + 1;

	val = strtol(p, &ep, 10);
	if (*ep != ':' || ep >= end) {
		(void) free(ageinfo);
		return (FALSE);
	}
	if (ep != p)
		sp->sp_flag = val;

	(void) free(ageinfo);
	return (TRUE);
}
/*
 * checks if the password has aged sufficiently
 */
bool_t
__npd_has_aged(obj, res)
struct nis_object *obj;
int	*res;
{
	struct	spwd	sp;
	long	now;

	if (__npd_fill_spwd(obj, &sp) == TRUE) {

		now = DAY_NOW;
		if (sp.sp_lstchg != 0 && sp.sp_lstchg <= now) {
			/* password changed before or just now */
			if (now < (sp.sp_lstchg + sp.sp_min)) {
				*res = NPD_NOTAGED;
				return (FALSE);
			} else
				return (TRUE);
		}
	}
	*res = NPD_NOSHDWINFO;
	return (FALSE);
}

/*
 * Authenticate the admin by decrypting any of their secret keys with
 * the passwd they sent across.  If any of the secret keys, of mech types
 * listed in the NIS+ security cf, are decrypted, then return TRUE.
 */
bool_t
__authenticate_admin(char *prin, char *pass)
{
	char	*d;
	struct	nis_result	*cres;
	char    netname[MAXNETNAMELEN+1];
	mechanism_t **mechs;

	if ((prin == NULL || *prin == '\0') ||
		(pass == NULL || *pass == '\0'))
		return (FALSE);

	if (!__npd_prin2netname(prin, netname)) {
		syslog(LOG_ERR,
	"__authenticate_admin: cannot convert principal '%s' to netname", prin);
		return (FALSE);
	}

	d = strchr(prin, '.');
	if (d == NULL)
		d = nis_local_directory();
	else
		d++;

	if (mechs = __nis_get_mechanisms(FALSE)) {
		mechanism_t **mpp;
		char auth_type[MECH_MAXATNAME+1];

		for (mpp = mechs; *mpp; mpp++) {
			mechanism_t *mp = *mpp;

			if (verbose)
				syslog(LOG_INFO,
		"__authenticate_admin: trying mech '%s' for user '%s'",
				mp->alias ? mp->alias : "NULL", prin);

			if (AUTH_DES_COMPAT_CHK(mp)) {
				__nis_release_mechanisms(mechs);
				goto try_auth_des;
			}
			if (! VALID_MECH_ENTRY(mp))
				continue;

			if (!__nis_mechalias2authtype(mp->alias, auth_type,
							sizeof (auth_type)))
				continue;

			cres = nis_getcredent(prin, d, auth_type);
			if (cres != NULL && cres->status == NIS_SUCCESS) {
				char *sp;

				if (debug)
					syslog(LOG_DEBUG,
				"__authenticate_admin: got cred entry");

				sp = ENTRY_VAL(NIS_RES_OBJECT(cres), 4);

				if (sp != NULL) {
					if (xdecrypt_g(sp, mp->keylen,
							mp->algtype, pass,
							netname, TRUE)) {
						__nis_release_mechanisms(
							mechs);

						if (debug)
							syslog(LOG_DEBUG,
				"__authenticate_admin: xdecrypt success");

						(void) nis_freeresult(cres);
						return (TRUE);
					}
				}
			}
			if (cres != NULL)
				(void) nis_freeresult(cres);

		}
		__nis_release_mechanisms(mechs);
	} else {
		/*
		 * No valid mechs in the NIS+ security cf file,
		 * so let's try AUTH_DES.
		 */
	try_auth_des:
		cres = nis_getcredent(prin, d, AUTH_DES_AUTH_TYPE);
		if (cres != NULL && cres->status == NIS_SUCCESS) {
			char *sp;
			sp = ENTRY_VAL(NIS_RES_OBJECT(cres), 4);
			if (sp != NULL) {
				if (xdecrypt_g(sp, AUTH_DES_KEYLEN,
						AUTH_DES_ALGTYPE, pass,
						NULL, TRUE)) {
					(void) nis_freeresult(cres);
					return (TRUE);
				}
			}
		}
		if (cres != NULL)
			(void) nis_freeresult(cres);
	}

	return (FALSE);
}

/*
 * build a netname given a nis+ principal name
 */
bool_t
__npd_prin2netname(prin, netname)
char	*prin;
char	netname[MAXNETNAMELEN];
{
	nis_result	*pass_res;
	nis_object	*pobj;
	char		name[NIS_MAXNAMELEN];
	char		*domain;
	uid_t		uid;


	if (prin == NULL || *prin == '\0')
		return (FALSE);
	if (strlen(prin) > (size_t)NIS_MAXNAMELEN)
		return (FALSE);
	(void) sprintf(name, "%s", prin);

	/* get the domain name */
	if (name[strlen(name) - 1] == '.')
		name[strlen(name) - 1] = '\0';
	else
		return (FALSE);
	domain = strchr(name, '.');
	if (domain == NULL)
		return (FALSE);
	else
		*domain++ = '\0';

	/* nis_getpwdent() will fully qualify the domain */
	pass_res = nis_getpwdent(name, domain);

	if (pass_res == NULL)
		return (FALSE);

	switch (pass_res->status) {
	case NIS_SUCCESS:
		pobj = NIS_RES_OBJECT(pass_res);
		uid = atol(ENTRY_VAL(pobj, 2));
		(void) nis_freeresult(pass_res);
		/* we cannot simply call user2netname() ! */
		if ((strlen(domain) + 7 + 11) > (size_t)MAXNETNAMELEN)
			return (FALSE);
		(void) sprintf(netname, "unix.%d@%s", uid, domain);
		return (TRUE);

	case NIS_NOTFOUND:
		/*
		 * assumption: hosts DO NOT have their passwords
		 * stored in NIS+ ==> not a user but a host
		 */
		if ((strlen(domain) + 7 + strlen(name)) >
						(size_t)MAXNETNAMELEN)
			return (FALSE);
		(void) sprintf(netname, "unix.%s@%s", name, domain);
		(void) nis_freeresult(pass_res);
		return (TRUE);

	default:
		syslog(LOG_ERR, "no passwd entry found for %s", prin);
		(void) nis_freeresult(pass_res);
		return (FALSE);
	}
}

/*
 * make a new DH (classic "DES" or new "DH640-0") cred entry and add it
 */
bool_t
__npd_addcredent(char	*prin,		/* principal name */
		char	*domain,	/* domain name */
		char	*auth_type,	/* cred table auth type name */
		keylen_t keylen,	/* DH key length */
		algtype_t algtype,	/* DH algorithm type */
		char	*newpass)	/* new pw used to encrypt secret key */
{
	char	*public = NULL;
	char	*secret = NULL;
	char	*encrypted_secret = NULL;
	nis_object	obj;
	entry_col	ecol[5];
	struct nis_result *mod_res;
	char	buf[NIS_MAXNAMELEN];
	char	nisdomain[NIS_MAXNAMELEN];
	char	netname[MAXNETNAMELEN];
	int	status;
	bool_t	ret;

	/* check args */
	if ((prin == NULL || *prin == '\0') ||
	    (domain == NULL || *domain == '\0') || auth_type == NULL) {
		ret = FALSE;
		goto out;
	}

	if (strlen(domain) > (size_t)NIS_MAXNAMELEN) {
		ret = FALSE;
		goto out;
	}
	(void) sprintf(nisdomain, "%s", domain);
	if (nisdomain[strlen(buf) - 1] != '.')
		(void) strcat(buf, ".");

	/* build netname from principal name */
	if (__npd_prin2netname(prin, netname) == FALSE) {
		ret = FALSE;
		goto out;
	}

	/* initialize object */
	memset((char *)&obj, 0, sizeof (obj));
	memset((char *)ecol, 0, sizeof (ecol));

	obj.zo_name = "cred";
	obj.zo_ttl = 43200;
	obj.zo_data.zo_type = NIS_ENTRY_OBJ;
	obj.zo_owner = prin;
	obj.zo_group = nis_local_group();
	obj.zo_domain = nisdomain;
			/* owner: r; group: rmcd */
	obj.zo_access = (NIS_READ_ACC<<16)|
			((NIS_READ_ACC|NIS_MODIFY_ACC|
			NIS_CREATE_ACC|NIS_DESTROY_ACC)<<8);

	if (strcasecmp(auth_type, "LOCAL") != 0) {

		if ((public = malloc(BITS2NIBBLES(keylen) + 1)) == NULL) {
			syslog(LOG_ALERT, "malloc failed");
			ret = FALSE;
			goto out;
		}
		if ((secret = malloc(BITS2NIBBLES(keylen) + 1)) == NULL) {
			syslog(LOG_ALERT, "malloc failed");
			ret = FALSE;
			goto out;
		}

		/* generate key-pair */
		if (! __gen_dhkeys_g(public, secret, keylen, algtype,
					newpass)) {
			syslog(LOG_ERR,
				"could not generate DH key pair for %d-%d",
				keylen, algtype);
			ret = FALSE;
			goto out;
		}
		if (! xencrypt_g(secret, keylen, algtype, newpass, netname,
					&encrypted_secret, TRUE)) {
			syslog(LOG_ERR,
				"could not encrypt secret key for %d-%d",
				keylen, algtype);
			ret = FALSE;
			goto out;
		}

		/* build cred entry */
		ecol[0].ec_value.ec_value_val = prin;
		ecol[0].ec_value.ec_value_len = strlen(prin) + 1;

		ecol[1].ec_value.ec_value_val = auth_type;
		ecol[1].ec_value.ec_value_len = strlen(auth_type) + 1;

		ecol[2].ec_value.ec_value_val = netname;
		ecol[2].ec_value.ec_value_len = strlen(netname) + 1;

		ecol[3].ec_value.ec_value_val = public;
		ecol[3].ec_value.ec_value_len = strlen(public) + 1;

		ecol[4].ec_value.ec_value_val = encrypted_secret;
		ecol[4].ec_value.ec_value_len = strlen(encrypted_secret) + 1;
		ecol[4].ec_flags |= EN_CRYPT;
	}
	obj.EN_data.en_type = "cred_tbl";
	obj.EN_data.en_cols.en_cols_val = ecol;
	obj.EN_data.en_cols.en_cols_len = 5;

	/* strlen("cred.org_dir.") + null = 14 */
	if ((strlen(nisdomain) + 14) > (size_t)NIS_MAXNAMELEN)
		return (FALSE);
	(void) sprintf(buf, "cred.org_dir.%s", (char *)&nisdomain[0]);

	if (debug == TRUE)
		(void) nis_print_object(&obj);

	mod_res = nis_add_entry(buf, &obj, 0);
	status = mod_res->status;
	(void) nis_freeresult(mod_res);
	switch (status) {
	case NIS_SUCCESS:
		if (verbose)
			syslog(LOG_ERR,
		"generated Diffie-Hellman key pair (type %d-%d) for '%s'",
				keylen, algtype, prin);
		ret = TRUE;
		goto out;

	case NIS_PERMISSION:
		if (verbose == TRUE)
			syslog(LOG_ERR,
			"permission denied to add a %s cred entry for %s",
				auth_type, prin);
		ret = FALSE;
		goto out;

	default:
		if (verbose == TRUE)
			syslog(LOG_ERR,
				"error creating %s cred for %s, NIS+ error: %s",
				auth_type, prin, nis_sperrno(status));
		ret = FALSE;
		goto out;
	}

out:
	free(secret);
	free(public);
	free(encrypted_secret);

	return (ret);
}

/*
 * Reencrypt a DH cred tbl secret key and return a ptr to it's newly
 * allocated memory on successful return.  Also, if the global generatekeys
 * is set, return a ptr of newly allocated memory containing a new public
 * key too.
 *
 * Return NULL on any type of failure.
 *
 * Caller must free secret and public key memory on successful return.
 */
static char *
reencrypt_secret(char *oldcryptsecret,	/* in */
		char *oldpass,		/* in */
		char *newpass,		/* in */
		keylen_t keylen,	/* in */
		algtype_t algtype,	/* in */
		char **public,		/* out */
		bool_t *keyset,		/* out */
		char *netname)		/* in */
{
	char *secret = NULL;
	char *reencrypted_secret = NULL;
	char *tmppk = NULL;
	uint_t slen;

	if (!oldcryptsecret || !oldpass || !newpass ||
		(generatekeys && !public) || !keyset || !netname)
		return (NULL);

	slen = strlen(oldcryptsecret);

	if ((secret = malloc(slen + 1)) == NULL) {
		syslog(LOG_ALERT,
			"reencrypte_secret: no memory!");
		return (NULL);
	}

	(void) strcpy(secret, oldcryptsecret);

	if (xdecrypt_g(secret, keylen, algtype, oldpass, netname, TRUE) == 0) {
		if (verbose)
			syslog(LOG_ERR,
				"could not decrypt keytype %d-%d for '%s'",
				keylen, algtype, netname);

		if (generatekeys == TRUE) {
			if ((tmppk = malloc(slen + 1))
			    == NULL) {
				syslog(LOG_ALERT, "no memory!");
				free(secret);
				return (NULL);
			}
			if (!__gen_dhkeys_g(tmppk, secret, keylen,
					    algtype, newpass)) {
				syslog(LOG_ERR,
		"could not generate new Diffie-Hellman key pair for type %d-%d",
					keylen, algtype);
				free(secret);
				free(tmppk);
				return (NULL);
			}
			*keyset = TRUE;
			if (verbose)
				syslog(LOG_ERR,
		"generated Diffie-Hellman key pair (type %d-%d) for '%s'",
					keylen, algtype, netname);
		} else {
			free(secret);
			return (NULL);
		}
	}
	if (xencrypt_g(secret, keylen, algtype, newpass, netname,
			&reencrypted_secret, TRUE) == 0) {
		syslog(LOG_ERR, "could not encrypt keytype %d-%d",
			keylen, algtype);
		free(secret);
		free(tmppk);
		return (NULL);
	}

	free(secret);

	if (generatekeys == TRUE && *keyset == TRUE)
		*public = tmppk;
	return (reencrypted_secret);
}

/*
 * reencrypt the secret key (or generate a new key-pair)
 * and update the cred table (for 1 key of type 'authtype').
 */
int
__npd_upd_cred(char	*user,		/* user name */
		char	*domain,	/* domainname */
		char	*authtype,
		keylen_t keylen,
		algtype_t algtype,
		char	*oldpass,
		char	*newpass,
		int	*err)
{
	struct nis_result *cred_res, *mod_res;
	nis_object *cobj, *eobj;
	char	prin[NIS_MAXNAMELEN];
	char	netname[MAXNETNAMELEN];
	char	*oldcryptsecret = NULL;
	char	*newcryptsecret = NULL;
	char	*public = NULL;
	entry_col	ecol[5];
	char	buf[NIS_MAXNAMELEN];
	int	status;
	bool_t	keyset = FALSE;
	entry_col *	eobj_col;
	uint_t		eobj_col_len;
	char	short_opass[sizeof (des_block)+1], *short_opassp = NULL;
	char    short_npass[sizeof (des_block)+1], *short_npassp = NULL;

	if ((user == NULL || *user == '\0') ||
		(domain == NULL || *domain == '\0') || authtype == NULL) {
		*err = NPD_KEYNOTREENC;
		return (NIS_SYSTEMERROR);
	}
	/* "." + "." + null = 3 */
	if ((strlen(user) + strlen(domain) + 3) > (size_t)NIS_MAXNAMELEN) {
		*err = NPD_KEYNOTREENC;
		return (NIS_SYSTEMERROR);
	}
	(void) sprintf(prin, "%s.%s", user, domain);
	if (prin[strlen(prin) - 1] != '.')
		(void) strcat(prin, ".");

	if (__npd_prin2netname(prin, netname) == FALSE) {
		*err = NPD_KEYNOTREENC;
		return (NIS_SYSTEMERROR);
	}

	cred_res = nis_getcredent(prin, domain, authtype);
	if (cred_res == NULL) {
		*err = NPD_KEYNOTREENC;
		return (NIS_SYSTEMERROR);
	}
	status = cred_res->status;
	switch (status) {
	case NIS_SUCCESS:
		if (verbose == TRUE)
			syslog(LOG_ERR, "found a %s cred entry for %s",
				authtype, prin);
		cobj = NIS_RES_OBJECT(cred_res);
		if (cobj == NULL) {
			*err = NPD_KEYNOTREENC;
			break;
		}

		oldcryptsecret = ENTRY_VAL(cobj, 4);

		if (oldpass) {
			strlcpy(short_opass, oldpass, sizeof (short_opass));
			short_opassp = short_opass;
		}

		if (newpass) {
			strlcpy(short_npass, newpass, sizeof (short_npass));
			short_npassp = short_npass;
		}

		if (!(newcryptsecret = reencrypt_secret(oldcryptsecret,
						short_opassp, short_npassp,
						keylen, algtype,
						&public, &keyset, netname))) {
			*err = NPD_KEYNOTREENC;
			(void) nis_freeresult(cred_res);
			return (NIS_SYSTEMERROR);
		}

		memset((char *)ecol, 0, sizeof (ecol));

		if (keyset == TRUE && generatekeys == TRUE) {
			/* public key changed too */
			ecol[3].ec_value.ec_value_val = public;
			ecol[3].ec_value.ec_value_len = strlen(public) + 1;
			ecol[3].ec_flags = EN_MODIFIED;
		}
		ecol[4].ec_value.ec_value_val = newcryptsecret;
		ecol[4].ec_value.ec_value_len = strlen(newcryptsecret) + 1;
		ecol[4].ec_flags = EN_MODIFIED|EN_CRYPT;

		/* strlen("[cname=,auth_type=],cred.") + null + "." = 27 */
		if ((strlen(prin) + strlen(cobj->zo_domain) + strlen(authtype)
			+ 27) > (size_t)NIS_MAXNAMELEN) {
			*err = NPD_KEYNOTREENC;
			break;
		}
		(void) sprintf(buf, "[cname=%s,auth_type=%s],cred.%s",
			prin, authtype, cobj->zo_domain);
		if (buf[strlen(buf) - 1] != '.')
			(void) strcat(buf, ".");

		eobj = nis_clone_object(cobj, NULL);
		if (eobj == NULL) {
			*err = NPD_KEYNOTREENC;
			break;
		}

		eobj_col = eobj->EN_data.en_cols.en_cols_val;
		eobj_col_len = eobj->EN_data.en_cols.en_cols_len;

		eobj->EN_data.en_cols.en_cols_val = ecol;
		eobj->EN_data.en_cols.en_cols_len = 5;

		mod_res = nis_modify_entry(buf, eobj, 0);
		status = mod_res->status;
		if (status != NIS_SUCCESS)
			*err = NPD_KEYNOTREENC;
		else
			if (verbose)
				syslog(LOG_ERR,
			"Diffie-Hellman key (type %d-%d) reencrypted for '%s'",
					keylen, algtype, prin);

		/* restore ecol so that we can free eobj */
		eobj->EN_data.en_cols.en_cols_val = eobj_col;
		eobj->EN_data.en_cols.en_cols_len = eobj_col_len;
		(void) nis_destroy_object(eobj);
		(void) nis_freeresult(mod_res);
		break;

	case NIS_NOTFOUND:
		if (verbose == TRUE)
			syslog(LOG_ERR, "no %s cred for %s", authtype, prin);
		if ((generatekeys == TRUE) &&
		    (__npd_addcredent(prin, domain, authtype,
				keylen, algtype, short_npassp) == TRUE)) {
			*err = NPD_KEYSUPDATED;
			status = NIS_SUCCESS;
		} else {
			*err = NPD_KEYNOTREENC;
			status = NIS_SYSTEMERROR;
		}
		break;
	default:
		*err = NPD_KEYNOTREENC;
		syslog(LOG_ERR,
			"NIS+ error (%d) getting cred entry for %s",
			status, prin);
		break;
	}

	free(newcryptsecret);
	free(public);

	(void) nis_freeresult(cred_res);
	return (status);
}

/*
 * Loop thru configed DH mechs and if the cred entry exists
 * and can be decrypted with old pw, then reencrypt it.  If
 * it cannot be decrypted or does not exist, and the generatekeys
 * option is set, then create a new DH key pair.
 *
 * If any of the key possibilities are reencrypted or generated successfully,
 * then return NIS_SUCCESS (and set 'err' to NIS_SUCCESS).
 *
 * On failure, return the NIS error code and set 'err' to the NPD error code.
 */
int
__npd_upd_all_pk_creds(char *user,	/* in */
			char *domain,	/* in */
			char *oldpass,	/* in */
			char *newpass,	/* in */
			int  *err)	/* out */
{
	int ret;
	int localerr;
	int key_success = 0;
	mechanism_t	**mechs;
	mechanism_t	**mpp;

	if ((user == NULL || *user == '\0') ||
		(domain == NULL || *domain == '\0')) {
		*err = NPD_KEYNOTREENC;
		return (NIS_SYSTEMERROR);
	}
	/* "." + "." + null = 3 */
	if ((strlen(user) + strlen(domain) + 3) > (size_t)NIS_MAXNAMELEN) {
		*err = NPD_KEYNOTREENC;
		return (NIS_SYSTEMERROR);
	}

	if (debug)
		syslog(LOG_DEBUG, "__npd_upd_all_pk_creds: user = %s",
			user);
	if (mechs = __nis_get_mechanisms(FALSE)) {
		/*
		 * Try all the mechs listed in the NIS+ security cf (or until
		 * AUTH_DES (192bit DH keys) entry is reached).
		 */
		for (mpp = mechs; *mpp; mpp++) {
			mechanism_t *mp = *mpp;
			char auth_type[MECH_MAXATNAME+1];

			if (AUTH_DES_COMPAT_CHK(mp)) {
				__nis_release_mechanisms(mechs);
				goto try_auth_des;
			}

			if (!VALID_MECH_ENTRY(mp))
				continue;

			if (!__nis_mechalias2authtype(mp->alias, auth_type,
							sizeof (auth_type))) {
				syslog(LOG_ERR,
				"cannot convert mech alias '%s' to auth type",
					mp->alias);
				continue;
			}

			ret = __npd_upd_cred(user, domain, auth_type,
					mp->keylen, mp->algtype,
					oldpass, newpass, &localerr);
			if (ret == NIS_SUCCESS) {
				key_success++;
			} else {
				syslog(LOG_ERR,
				"cannot reencrypt ('%s') creds for '%s'",
					auth_type, user);
				if (debug)
					syslog(LOG_DEBUG,
	"__npd_upd_all_pk_creds: upd_cred fail; return = %d, localerr = %d",
						ret, localerr);
			}
		}
		__nis_release_mechanisms(mechs);

	} else {
		if (debug)
			syslog(LOG_DEBUG,
"__npd_upd_all_pk_creds: no valid GSS mechs found...trying AUTH_DES...");

try_auth_des:
		ret = __npd_upd_cred(user, domain, AUTH_DES_AUTH_TYPE,
					AUTH_DES_KEYLEN, AUTH_DES_ALGTYPE,
					oldpass, newpass, &localerr);
		if (ret == NIS_SUCCESS) {
			key_success++;
		} else {
			syslog(LOG_ERR,
				"cannot reencrypt ('%s') creds for '%s'",
				AUTH_DES_AUTH_TYPE, user);
			if (debug)
				syslog(LOG_DEBUG,
	"__npd_upd_all_pk_creds: upd_cred des fail; ret = %d, localerr = %d",
					ret, localerr);
		}
	}

	/*
	 * Return success if any of the key possibilities were
	 * reencrypted or generated.
	 */
	if (key_success > 0) {
		*err = NIS_SUCCESS;
		return (NIS_SUCCESS);
	}

	*err = NPD_KEYNOTREENC;
	return (NIS_SYSTEMERROR);
}

/*
 * encrypt new passwd
 */
char *
__npd_encryptpass(char *pass, nis_object *user)
{
	char *newpass;
	char *salt;
	struct passwd *pw;
	if (pass == NULL || *pass == '\0')
		return (NULL);

	/*
	 * We can't call getpwnam_r in here because the search paths
	 * for the machine running rpc.nispasswdd may not actually find
	 * the user.  It is for this reason we got the nis_result passed
	 * in - the output of nis_list().  We need to turn that into a
	 * struct passwd before passing it to crypt_gensalt(3c).
	 */
	pw = nis_object2passwd(user);
	salt = crypt_gensalt(pass, pw);
	newpass = crypt(pass, salt);
	if (salt != NULL) {
		free(salt);
		salt = NULL;
	}
	if (pw != NULL) {
		free(pw);
		pw = NULL;
	}
	return (newpass);
}


/*
 * find the passwd object for this user from the list
 * of dirs given. If object is found in more than one
 * place return an error, otherwise clone the object.
 * Note, the object should be freed using nis_destroy_object().
 */
bool_t
__npd_find_obj(user, dirlist, obj)
char	*user;
char	*dirlist;
nis_object **obj;	/* returned */
{
	char	*tmplist;
	char	*curdir, *end = NULL;
	char	buf[NIS_MAXNAMELEN];
	nis_result	*tmpres;
	nis_object	*tmpobj = NULL;

	if ((user == NULL || *user == '\0') ||
		(dirlist == NULL || *dirlist == '\0'))
		return (FALSE);

	*obj = NULL;
	if ((tmplist = strdup(dirlist)) == NULL) {
		syslog(LOG_CRIT, "out of memory");
		return (FALSE);
	}
	for (curdir = tmplist; curdir != NULL; curdir = end) {
		end = strchr(curdir, ' ');
		if (end != NULL)
			*end++ = NULL;
		if (strncasecmp(curdir, "org_dir", 7) != 0)
			continue;	/* not an org_dir */

		/* strlen("[name=],passwd." + null + "." = 17 */
		if ((strlen(user) + 17 + strlen(curdir)) >
				(size_t)NIS_MAXNAMELEN) {
			(void) free(tmplist);
			return (FALSE);
		}

		(void) sprintf(buf, "[name=%s],passwd.%s", user, curdir);
		if (buf[strlen(buf) - 1] != '.')
			(void) strcat(buf, ".");
		tmpres = nis_list(buf, USE_DGRAM+MASTER_ONLY, NULL, NULL);
		switch (tmpres->status) {
		case NIS_NOTFOUND:	/* skip */
			(void) nis_freeresult(tmpres);
			continue;

		case NIS_SUCCESS:
			if (NIS_RES_NUMOBJ(tmpres) != 1) {
				/* should only have one entry */
				(void) nis_freeresult(tmpres);
				(void) free(tmplist);
				if (tmpobj != NULL)
					(void) nis_destroy_object(tmpobj);
				return (FALSE);
			}
			if (tmpobj != NULL) {
				/* found in more than one dir */
				(void) nis_destroy_object(tmpobj);
				(void) nis_freeresult(tmpres);
				(void) free(tmplist);
				*obj = NULL;
				return (FALSE);
			}
			tmpobj = nis_clone_object(NIS_RES_OBJECT(tmpres), NULL);
			if (tmpobj == NULL) {
				syslog(LOG_CRIT, "out of memory");
				(void) nis_freeresult(tmpres);
				(void) free(tmplist);
				return (FALSE);
			}
			(void) nis_freeresult(tmpres);
			continue;

		default:
			/* some NIS+ error - quit processing */
			curdir = NULL;
			break;
		}
	}
	(void) nis_freeresult(tmpres);
	(void) free(tmplist);
	if (tmpobj == NULL)	/* no object found */
		return (FALSE);
	*obj = tmpobj;
	return (TRUE);
}

/*
 * go thru' the list of dirs and see if the host is a
 * master server for any 'org_dir'.
 */
bool_t
__npd_am_master(host, dirlist)
char	*host;
char	*dirlist;
{
	char	*tmplist;
	char	*curdir, *end = NULL;
	nis_server	**srvs;
	unsigned	sleep_time;
	unsigned	total_sleep_time;
	unsigned	next_log_time;

	if ((host == NULL || *host == '\0') ||
		(dirlist == NULL || *dirlist == '\0'))
		return (FALSE);

	if ((tmplist = strdup(dirlist)) == NULL) {
		syslog(LOG_CRIT, "out of memory");
		return (FALSE);
	}
	for (curdir = tmplist; curdir != NULL; curdir = end) {
		end = strchr(curdir, ' ');
		if (end != NULL)
			*end++ = NULL;
		if (strncasecmp(curdir, "org_dir", 7) != 0)
			continue;	/* not an org_dir */

		/*
		 * Attempt to get the nis serv list
		 * If no success after an hour, exit
		 */
		sleep_time = 1;
		total_sleep_time = 0;
		next_log_time = 60;
		while ((srvs = nis_getservlist(curdir)) == NULL) {
			if (total_sleep_time >= 3600)
				break;		/* give up after an hour */
			/*
			 * Log errors at 1 minute, 10 minutes, 20 minutes,
			 * 30 minutes, 40 minutes, and 50 minutes
			 */
			if (total_sleep_time >= next_log_time) {
				syslog(LOG_ERR,
		"cannot get a list of servers that serve '%s'. Retrying...",
					curdir);
				if (next_log_time == 60)
					next_log_time = 600;
				else
					next_log_time += 600;
			}
			(void) sleep(sleep_time);
			__nis_CacheRestart();
			total_sleep_time += sleep_time;
			/*
			 * sleep times of 1,2,4,8,16,29 seconds (total 60)
			 * and once a minute thereafter
			 */
			if (sleep_time <= 8)
				sleep_time += sleep_time;
			else if (sleep_time <= 16)
				sleep_time = 29;
			else
				sleep_time = 60;
		}

		if (srvs == NULL) {
			syslog(LOG_ERR,
		"cannot get a list of servers that serve '%s'", curdir);
			(void) free(tmplist);
			return (FALSE);
		}
		if (strcasecmp(host, srvs[0]->name) == 0) {
			(void) free(tmplist);
			(void) nis_freeservlist(srvs);
			return (TRUE);
		}
		(void) nis_freeservlist(srvs);
	}
	(void) free(tmplist);
	return (FALSE);
}


/*
 * check whether this principal has permission to
 * add/delete/modify an entry object
 */
bool_t
__npd_can_do(right, obj, prin, column)
unsigned long	right;		/* access right seeked */
nis_object *obj;		/* entry object */
char	*prin;			/* principal seeking access */
int	column;			/* column being modified */
{
	nis_result	*res;
	nis_object	*tobj;
	table_col	*tc;
	char		buf[NIS_MAXNAMELEN];
	int		mod_ok;

	/* strlen("passwd." + null + "." = 9 */
	if ((9 + strlen(obj->zo_domain)) > (size_t)NIS_MAXNAMELEN) {
		return (FALSE);
	}
	(void) sprintf(buf, "passwd.%s", obj->zo_domain);
	if (buf[strlen(buf) - 1] != '.')
		(void) strcat(buf, ".");

	res = nis_lookup(buf, MASTER_ONLY);

	if (res->status == NIS_SUCCESS) {
		tobj = NIS_RES_OBJECT(res);
		if (__type_of(tobj) != NIS_TABLE_OBJ) {
			(void) nis_freeresult(res);
			return (FALSE);
		}
	} else {
		(void) nis_freeresult(res);
		return (FALSE);
	}

	/* check the permission on the table */
	mod_ok = __nis_ck_perms(right, tobj->zo_access, tobj, prin, 1);
	if (mod_ok == TRUE) {
		(void) nis_freeresult(res);
		return (TRUE);
	}

	/* check the permission on the obj */
	mod_ok = __nis_ck_perms(right, obj->zo_access, obj, prin, 1);
	if (mod_ok == TRUE) {
		(void) nis_freeresult(res);
		return (TRUE);
	}

	if (column > tobj->TA_data.ta_maxcol) {
		/* invalid column */
		(void) nis_freeresult(res);
		return (FALSE);
	}
	tc = tobj->TA_data.ta_cols.ta_cols_val;	/* table columns */

	/* check the permission on column being modified */
	mod_ok = __nis_ck_perms(right, tc[column].tc_rights, obj, prin, 1);

	(void) nis_freeresult(res);
	return (mod_ok);
}

void
__npd_gen_rval(randval)
unsigned long *randval;
{
	int		i, shift;
	struct timeval	tv;
	unsigned int	seed = 0;

	for (i = 0; i < 1024; i++) {
		(void) gettimeofday(&tv, NULL);
		shift = i % 8 * sizeof (int);
		seed ^= (tv.tv_usec << shift) | (tv.tv_usec >> (32 - shift));
	}
	(void) srandom(seed);
	*randval = (ulong_t)random();
}

/*
 * The following code is a modified version of nis_object2ent which was
 * taken from usr/src/lib/nsswitch/nisplus/common/getpwnam.c.
 * If you make fixes here you should check if they are also valid for the
 * nss_nisplus.so version.
 *
 * The code had to be changed since the original was written for use inside
 * the nsswitch code which wasn't suitable for direct inclusion here.
 */
static struct passwd *
nis_object2passwd(nis_object *obj)
{
	char	*val, *endnum, *nullstring;
	struct 	passwd *pw;
	struct	entry_col *ecol;
	int	len;

	nullstring = strdup("");
	/*
	 * If we got more than one nis_object, we just ignore object(s)
	 * except the first. Although it should never have happened.
	 *
	 * ASSUMPTION: All the columns in the NIS+ tables are
	 * null terminated.
	 */

	if (obj->zo_data.zo_type != NIS_ENTRY_OBJ ||
		obj->EN_data.en_cols.en_cols_len < PW_COL) {
		/* namespace/table/object is curdled */
		return (NULL);
	}
	ecol = obj->EN_data.en_cols.en_cols_val;

	pw = malloc(sizeof (struct passwd));

	/*
	 * pw_name: user name
	 */
	EC_SET(ecol, PW_NDX_NAME, len, val);
	if (len < 2 || (*val == '\0'))
		return (NULL);
	pw->pw_name = strdup(val);

	/*
	 * pw_uid: user id
	 */
	EC_SET(ecol, PW_NDX_UID, len, val);
	if (len < 2) {
		return (NULL);
	} else {
		pw->pw_uid = strtol(val, &endnum, 10);
		if (*endnum != 0 || val == endnum) {
			return (NULL);
		}
	}

	/*
	 * pw_passwd: user passwd. Do not HAVE to get this here
	 * because the caller would do a getspnam() anyway.
	 */
	EC_SET(ecol, PW_NDX_PASSWD, len, val);
	if (len < 2) {
		/*
		 * don't return NULL pointer, lot of stupid programs
		 * out there.
		 */
		pw->pw_passwd = nullstring;
	} else {
		pw->pw_passwd = strdup(val);
	}

	/*
	 * pw_gid: user's primary group id.
	 */
	EC_SET(ecol, PW_NDX_GID, len, val);
	if (len < 2) {
		return (NULL);
	} else {
		pw->pw_gid = strtol(val, &endnum, 10);
		if (*endnum != 0 || val == endnum) {
			return (NULL);
		}
	}

	/*
	 * pw_gecos: user's real name.
	 */
	EC_SET(ecol, PW_NDX_GCOS, len, val);
	if (len < 2) {
		/*
		 * don't return NULL pointer, lot of stupid programs
		 * out there.
		 */
		pw->pw_gecos = nullstring;
	} else {
		pw->pw_gecos = strdup(val);
	}

	/*
	 * pw_dir: user's home directory
	 */
	EC_SET(ecol, PW_NDX_HOME, len, val);
	if (len < 2) {
		/*
		 * don't return NULL pointer, lot of stupid programs
		 * out there.
		 */
		pw->pw_dir = nullstring;
	} else {
		pw->pw_dir = strdup(val);
	}

	/*
	 * pw_shell: user's login shell
	 */
	EC_SET(ecol, PW_NDX_SHELL, len, val);
	if (len < 2) {
		/*
		 * don't return NULL pointer, lot of stupid programs
		 * out there.
		 */
		pw->pw_shell = nullstring;
	} else {
		pw->pw_shell = strdup(val);
	}

	/*
	 * pw_age and pw_comment shouldn't be used anymore, but various things
	 *   (allegedly in.ftpd) merrily do strlen() on them anyway, so we
	 *   keep the peace by returning a zero-length string instead of a
	 *   null pointer.
	 */
	pw->pw_age = pw->pw_comment = nullstring;
	if (debug)
		syslog(LOG_DEBUG, "nis_object2passwd:"
		"pw->pw_name = %s pw->pw_uid = %d pw->pw_gid = %d "
		"pw->pw_gecos = %s pw->pw_dir = %s pw->pw_shell = %s ",
		pw->pw_name, pw->pw_uid, pw->pw_gid, pw->pw_gecos, pw->pw_dir,
		pw->pw_shell);

	return (pw);
}
