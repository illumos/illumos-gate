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
 *
 *	npd_svc.c
 *	NPD service routines
 *
 */

#include <syslog.h>
#include <string.h>
#include <ctype.h>
#include <shadow.h>
#include <crypt.h>
#include <stdlib.h>
#include <unistd.h>
#include <rpcsvc/yppasswd.h>
#include <rpcsvc/nis.h>
#include <rpc/key_prot.h>
#include <rpc/des_crypt.h>
#include <rpcsvc/nispasswd.h>
#include "npd_cache.h"
#include "npd_svcsubr.h"
#include <sys/byteorder.h>
#include <rpcsvc/nis_dhext.h>

extern int max_attempts;
extern int cache_time;
extern int verbose;
extern int debug;

#define	_NPD_PASSMAXLEN	16
#define	MAX_RETRY	3

extern char	*ypfwd; /* YP domain to fwd NIS+ req	*/

/*
 * service routine for first part of the nispasswd update
 * protocol.
 */
bool_t
nispasswd_authenticate_1_svc(argp, result, rqstp)
npd_request *argp;
nispasswd_authresult *result;
struct svc_req *rqstp;
{
	return (nispasswd_authenticate_common_svc(argp,
	    result, rqstp, NISPASSWD_VERS));
}

/*
 * service routine for first part of the nispasswd update2
 * protocol.
 */
bool_t
nispasswd_authenticate_2_svc(argp, result, rqstp)
npd_request *argp;
nispasswd_authresult *result;
struct svc_req *rqstp;
{
	return (nispasswd_authenticate_common_svc(argp,
	    result, rqstp, NISPASSWD_VERS2));
}

bool_t
nispasswd_authenticate_common_svc(argp, result, rqstp, vers)
npd_request *argp;
nispasswd_authresult *result;
struct svc_req *rqstp;
rpcvers_t vers;
{
	bool_t	check_aging = TRUE;	/* default == check */
	bool_t	same_user = TRUE;	/* default == same user */
	bool_t	is_admin = FALSE;	/* default == not an admin */
	bool_t	entry_exp = FALSE;	/* default == not expired */
	bool_t	upd_entry = FALSE;	/* default == do not update */
	bool_t	refresh = FALSE;	/* default == do not refresh */
	int	ans = 0;
	char	prin[NIS_MAXNAMELEN];
	struct	update_item	*entry = NULL;
	nis_result	*pass_res;
	nis_object	*pobj;
	des_block	deskeys[3], ivec, cryptbuf;
	int	status;
	char	*oldpass;
	unsigned long	randval;
	uint32_t	rval, ident;
	keylen_t pkeylen;  /* public key length (bits) */
	algtype_t algtype; /* public key algorithm type */
	int passlen = __NPD2_MAXPASSBYTES;
	unsigned char *xpass;

	if (vers == NISPASSWD_VERS) {
		passlen = __NPD_MAXPASSBYTES;
	} else if (vers == NISPASSWD_VERS2) {
		passlen = __NPD2_MAXPASSBYTES;
	}

	if ((xpass = malloc(passlen + 1)) == NULL) {
		syslog(LOG_ERR,
		    "nispasswd_authenticate_common_svc: Out of memory");
		result->status = NPD_FAILED;
		result->nispasswd_authresult_u.npd_err = NPD_SYSTEMERR;
		return (TRUE);
	}

	if (verbose)
		syslog(LOG_ERR, "received NIS+ auth request for %s",
			argp->username);

	/* check if I'm running on the host == master(domain) */
	if (__nis_ismaster(nis_local_host(), argp->domain) == FALSE) {
		syslog(LOG_ERR, "not master for %s", argp->domain);
		result->status = NPD_FAILED;
		result->nispasswd_authresult_u.npd_err = NPD_NOTMASTER;
		goto auth_free_xpass;
	}

again:
	/* get caller info. from auth_handle */
	if (rqstp)
		(void) __nis_auth2princ_rpcgss(prin, rqstp, refresh, 0);
	else
		prin[0] = '\0';

	if (verbose)
		syslog(LOG_INFO, "_authenticate_: principal of req is %s",
			prin);

	/* caller == admin ? ; Y -> skip checks, N -> do aging checks */
	if ((*prin != '\0') && strcmp(prin, "nobody") != 0)
		/* authenticated user, check if they are privileged */
		if (__nis_isadmin(prin, "passwd", argp->domain) == TRUE) {
			check_aging = FALSE;
			is_admin = TRUE;
		}

	if ((*prin == '\0') || (strcmp(prin, "nobody") == 0)) {
				/* "." + null + "." = 3 */
		if ((strlen(argp->username) + strlen(argp->domain) + 3) >
			(size_t)NIS_MAXNAMELEN) {
			syslog(LOG_ERR, "buffer too small");
			result->status = NPD_FAILED;
			result->nispasswd_authresult_u.npd_err =
				NPD_BUFTOOSMALL;
			goto auth_free_xpass;
		}
		(void) sprintf(prin, "%s.%s", argp->username, argp->domain);
		if (prin[strlen(prin) - 1] != '.')
			(void) strcat(prin, ".");
		if (debug)
			syslog(LOG_DEBUG,
		"_authenticate_: 'nobody' or NUL prinicipal set to '%s'", prin);
	}

	/*
	 * The credential information may have changed for the user,
	 * we should refresh the cache to make sure or the user is
	 * a different user and the necessary checks need to be made.
	 */
	if (strncmp(prin, argp->username, strlen(argp->username)) != 0)
		if (refresh)
			same_user = FALSE;
		else {
			refresh = TRUE;
			goto again;
		}

	/* check if there is a cached entry */
	if ((find_upd_item(prin, &entry)) &&
		(strcmp(entry->ul_user, argp->username) == 0)) {

		/* found an entry - check if it has expired */
		if (entry->ul_expire > time(NULL)) {
			entry->ul_attempt = entry->ul_attempt + 1;
			/*
			 * check if this attempt > max_attempts.
			 */
			if (entry->ul_attempt > max_attempts) {
				syslog(LOG_ERR,
					"too many failed attempts for %s",
					argp->username);
				result->status = NPD_FAILED;
				result->nispasswd_authresult_u.npd_err =
					NPD_PASSINVALID;
				goto auth_free_xpass;
			}
			if (argp->ident == 0) {
				/*
				 * a new session and we have an entry cached
				 * but we have not reached max_attempts, so
				 * just update entry with the new pass
				 */
				upd_entry = TRUE;
			}
		} else {	/* entry has expired */
			(void) free_upd_item(entry);
			entry_exp = TRUE;
			entry = NULL;
		}
	} else {
		entry = (struct update_item *)__npd_item_by_key(argp->ident);
		if (entry == NULL)	/* no cached entry */
			if (argp->ident != 0) {
				syslog(LOG_ERR,
		"no cache entry found for %s but the identifier is %d",
					argp->username, argp->ident);
				result->status = NPD_FAILED;
				result->nispasswd_authresult_u.npd_err =
						NPD_IDENTINVALID;
				goto auth_free_xpass;
			}
	}

	/* get passwd info for username */
	pass_res = nis_getpwdent(argp->username, argp->domain);

	if (pass_res == NULL) {
		syslog(LOG_ERR, "invalid args %s and %s",
			argp->username, argp->domain);
		result->status = NPD_FAILED;
		result->nispasswd_authresult_u.npd_err = NPD_NOSUCHENTRY;
		goto auth_free_xpass;
	}
	switch (pass_res->status) {
	case NIS_SUCCESS:
		pobj = NIS_RES_OBJECT(pass_res);
		break;
	case NIS_NOTFOUND:
		syslog(LOG_ERR, "no passwd entry found for %s",
			argp->username);
		(void) nis_freeresult(pass_res);
		result->status = NPD_FAILED;
		result->nispasswd_authresult_u.npd_err = NPD_NOSUCHENTRY;
		goto auth_free_xpass;
	default:
		syslog(LOG_ERR,
			"NIS+ error (%d) getting passwd entry for %s",
			pass_res->status, argp->username);
		(void) nis_freeresult(pass_res);
		result->status = NPD_FAILED;
		result->nispasswd_authresult_u.npd_err = NPD_NISERROR;
		goto auth_free_xpass;
	}

	/* if user check if 'min' days have passed since 'lastchg' */
	if (check_aging) {
		if ((__npd_has_aged(pobj, &ans) == FALSE) &&
				ans == NPD_NOTAGED) {
			syslog(LOG_ERR,
				"password has not aged enough for %s",
				argp->username);
			(void) nis_freeresult(pass_res);
			result->status = NPD_FAILED;
			result->nispasswd_authresult_u.npd_err = ans;
			goto auth_free_xpass;
		}
	/* if ans == NPD_NOSHDWINFO then aging cannot be enforced */
	}

	/*
	 * Find out what key length and algorithm type we're dealing with.
	 */
	if (strncmp("DES", argp->key_type, 4) == 0) {
		pkeylen = AUTH_DES_KEYLEN;
		algtype = AUTH_DES_ALGTYPE;
	} else {
		/*
		 * This will check if the key_type exists in the
		 * NIS+ security cf.
		 */
		if (__nis_translate_mechanism(argp->key_type, &pkeylen,
						&algtype) < 0) {
			syslog(LOG_ERR,
				"cannot get keylen/algtype for key type '%s'",
				argp->key_type);
			(void) nis_freeresult(pass_res);
			result->status = NPD_FAILED;
			result->nispasswd_authresult_u.npd_err =
				NPD_INVALIDARGS;
			goto auth_free_xpass;
		}
	}

	/* generate CK (from P.c and S.d) */
	if (key_get_conv_g((const char *)argp->user_pub_key.user_pub_key_val,
				pkeylen, algtype, deskeys,
				AUTH_DES_KEY(pkeylen, algtype) ? 1 : 3) != 0) {
		syslog(LOG_ERR,
			"cannot generate common DES key for %s",
			argp->username);
		syslog(LOG_ERR, "is keyserv still running ?");
		syslog(LOG_ERR, "has %s keylogged in ?", nis_local_host());
		(void) nis_freeresult(pass_res);
		result->status = NPD_FAILED;
		result->nispasswd_authresult_u.npd_err = NPD_CKGENFAILED;
		goto auth_free_xpass;
	}
	/* decrypt the passwd sent */
	if (argp->npd_authpass.npd_authpass_len != passlen) {
		syslog(LOG_ERR, "password length wrong");
		(void) nis_freeresult(pass_res);
		result->status = NPD_TRYAGAIN;
		result->nispasswd_authresult_u.npd_err = NPD_PASSINVALID;
		goto auth_free_xpass;
	}
	(void) memcpy(xpass, argp->npd_authpass.npd_authpass_val,
			passlen);

	ivec.key.high = ivec.key.low = 0;
	if (AUTH_DES_KEY(pkeylen, algtype))
		status = cbc_crypt(deskeys[0].c, (char *)xpass,
					passlen, DES_DECRYPT | DES_HW,
					(char *)&ivec);
	else
		status = __cbc_triple_crypt(deskeys, (char *)xpass,
					passlen, DES_DECRYPT | DES_HW,
					(char *)&ivec);

	if (DES_FAILED(status)) {
		syslog(LOG_ERR, "failed to decrypt password");
		(void) nis_freeresult(pass_res);
		result->status = NPD_FAILED;
		result->nispasswd_authresult_u.npd_err = NPD_DECRYPTFAIL;
		goto auth_free_xpass;
	}

	/* assign an ID and generate R on the first call of a session */
	if (argp->ident == 0) {
		ident	= (uint32_t)__npd_hash_key(prin);
		if ((int)ident == -1) {
			syslog(LOG_ERR, "invalid ident value calculated");
			(void) nis_freeresult(pass_res);
			result->status = NPD_FAILED;
			result->nispasswd_authresult_u.npd_err = NPD_SYSTEMERR;
			goto auth_free_xpass;
		}
		(void) __npd_gen_rval(&randval);
	} else {
		/* second or third attempt */
		ident = argp->ident;
		if (entry == NULL) {
			if (entry_exp)	/* gen a new random val */
				(void) __npd_gen_rval(&randval);
			else {
				syslog(LOG_ERR, "cache corrupted");
				(void) nis_freeresult(pass_res);
				result->status = NPD_FAILED;
				result->nispasswd_authresult_u.npd_err =
					NPD_SYSTEMERR;
				goto auth_free_xpass;
			}
		} else {
			if (strcmp(entry->ul_user, argp->username) != 0) {
				/* gen a new random val */
				(void) __npd_gen_rval(&randval);
			} else
				randval = entry->ul_rval;
		}
	}

	rval = (uint32_t)randval;
	if (! __npd_ecb_crypt(&ident, &rval, &cryptbuf,
		sizeof (des_block), DES_ENCRYPT, &deskeys[0])) {
		syslog(LOG_ERR, "failed to encrypt verifier");
		(void) nis_freeresult(pass_res);
		result->status = NPD_FAILED;
		result->nispasswd_authresult_u.npd_err = NPD_ENCRYPTFAIL;
		goto auth_free_xpass;
	}
	/* encrypt the passwd and compare with that stored in NIS+ */
	if (same_user) {
		if ((oldpass = ENTRY_VAL(pobj, 1)) == NULL) {
			(void) nis_freeresult(pass_res);
			result->status = NPD_FAILED;
			result->nispasswd_authresult_u.npd_err = NPD_NOPASSWD;
			goto auth_free_xpass;
		}
		if (strcmp(crypt((const char *)xpass,
		    (const char *)oldpass), oldpass) != 0) {
			if (debug)
				syslog(LOG_DEBUG,
					"_authenticate_: pw decrypt failed");
			(void) nis_freeresult(pass_res);
			result->nispasswd_authresult_u.npd_verf.npd_xid =
					htonl(cryptbuf.key.high);
			result->nispasswd_authresult_u.npd_verf.npd_xrandval =
					htonl(cryptbuf.key.low);
			/* cache relevant info */
			if (entry == NULL) {
				ans = add_upd_item(prin, argp->username,
					same_user, argp->domain, ident, rval,
					&deskeys[0], (char *)xpass);
				if (ans <= 0) {
					result->status = NPD_FAILED;
					result->nispasswd_authresult_u.npd_err =
							NPD_SYSTEMERR;
				} else
					result->status = NPD_TRYAGAIN;
			} else {
				/* found an entry, attempt == max_attempts */
				if (entry->ul_attempt == max_attempts) {
					result->status = NPD_FAILED;
					result->nispasswd_authresult_u.npd_err =
							NPD_SYSTEMERR;
				/*
				 * not really a system error but we
				 * want the caller to think that 'cos
				 * they are obviously trying to break-in.
				 * Perhaps, we should not respond at all,
				 * the client side would timeout.
				 */
				}
			}
			if (verbose)
				(void) __npd_print_entry(prin);
			goto auth_free_xpass;
		}
	} else {
		if (is_admin == FALSE) {	/* not privileged */
			(void) nis_freeresult(pass_res);
			result->status = NPD_FAILED;
			result->nispasswd_authresult_u.npd_err =
					NPD_PERMDENIED;
			goto auth_free_xpass;
		}
		/* admin changing another users password */
		if (__authenticate_admin(prin, (char *)xpass) == FALSE) {
			/*
			 * we have no idea where this admin's
			 * passwd record is stored BUT we do know
			 * where their PK cred(s) is stored from
			 * the netname, so lets try to decrypt
			 * the secret key(s) with the passwd that
			 * was sent across.
			 */
			(void) nis_freeresult(pass_res);
			result->status = NPD_TRYAGAIN;
			result->nispasswd_authresult_u.npd_verf.npd_xid =
					htonl(cryptbuf.key.high);
			result->nispasswd_authresult_u.npd_verf.npd_xrandval =
					htonl(cryptbuf.key.low);
			/* cache relevant info */
			if (entry == NULL) {
				ans = add_upd_item(prin, argp->username,
					same_user, argp->domain, ident, rval,
					&deskeys[0], (char *)xpass);
				if (ans <= 0) {
					result->status = NPD_FAILED;
					result->nispasswd_authresult_u.npd_err =
							NPD_SYSTEMERR;
				}
			}
			goto auth_free_xpass;
		}
	}
	/* done with pass_res */
	(void) nis_freeresult(pass_res);
	/* cache relevant info */
	if (entry == NULL) {
		ans = add_upd_item(prin, argp->username, same_user,
			argp->domain, ident, rval, &deskeys[0],
			(char *)xpass);
		if (ans <= 0) {
			result->status = NPD_FAILED;
			result->nispasswd_authresult_u.npd_err =
					NPD_SYSTEMERR;
			goto auth_free_xpass;
		}
	} else {
		if (entry->ul_oldpass != NULL)
			free(entry->ul_oldpass);
		entry->ul_oldpass = strdup((char *)&xpass[0]);
		if (entry->ul_oldpass == NULL) {
			result->status = NPD_FAILED;
			result->nispasswd_authresult_u.npd_err =
					NPD_SYSTEMERR;
			goto auth_free_xpass;
		}
		if (upd_entry == TRUE) {
			entry->ul_ident = ident;
			entry->ul_rval = rval;
			entry->ul_key = deskeys[0];
		}
	}
	result->status = NPD_SUCCESS;
	result->nispasswd_authresult_u.npd_verf.npd_xid =
			htonl(cryptbuf.key.high);
	result->nispasswd_authresult_u.npd_verf.npd_xrandval =
			htonl(cryptbuf.key.low);
	if (verbose)
		(void) __npd_print_entry(prin);

auth_free_xpass:
	if (xpass != NULL)
		free(xpass);
	return (TRUE);
}

/*
 * service routine for second part of the nispasswd update
 * protocol.
 */
/* ARGSUSED2 */
bool_t
nispasswd_update_1_svc(updreq, res, rqstp)
npd_update		*updreq;
nispasswd_updresult	*res;
struct svc_req	*rqstp;
{
	return (nispasswd_update_common_svc((void *) updreq,
	    res, rqstp, NISPASSWD_VERS));
}

/*
 * service routine for second part of the nispasswd update2
 * protocol.
 */
/* ARGSUSED2 */
bool_t
nispasswd_update_2_svc(updreq, res, rqstp)
npd_update2		*updreq;
nispasswd_updresult	*res;
struct svc_req	*rqstp;
{
	return (nispasswd_update_common_svc((void *) updreq,
	    res, rqstp, NISPASSWD_VERS2));
}

/*
 * service routine for second part of the nispasswd update common
 * protocol.
 */
/* ARGSUSED2 */
bool_t
nispasswd_update_common_svc(tmp_updreq, res, rqstp, vers)
void    *tmp_updreq;
nispasswd_updresult	*res;
struct svc_req	*rqstp;
rpcvers_t   vers;
{
	struct update_item *entry;
	char	*newpass, buf[NIS_MAXNAMELEN];
	uint32_t	rand;
	struct nis_result *pass_res = NULL, *mod_res = NULL;
	struct nis_object *pobj = NULL, *eobj = NULL;
	entry_col	ecol[8];
	char	*old_gecos, *old_shell, *sp;
	char	shadow[80];
	static nispasswd_error	errlist[3];
	int error = NPD_SUCCESS;
	register int i;
	char *old_pass;
	entry_col *	eobj_col;
	uint_t		eobj_col_len;
	int pwflag = FALSE;
	int chg_passwd = TRUE;
	char	*pass;
	int	passlen = __NPD2_MAXPASSBYTES;
	npd_newpass	cryptbuf1;
	npd_newpass2	cryptbuf2;
	npd_update	*updreq1;
	npd_update2	*updreq2;
	char *gecos;
	char *shell;

	if (vers == NISPASSWD_VERS) {
		passlen = __NPD_MAXPASSBYTES;
		updreq1 = (npd_update *)tmp_updreq;
		gecos = updreq1->pass_info.pw_gecos;
		shell = updreq1->pass_info.pw_shell;
	} else if (vers == NISPASSWD_VERS2) {
		passlen = __NPD2_MAXPASSBYTES;
		updreq2 = (npd_update2 *)tmp_updreq;
		gecos = updreq2->pass_info.pw_gecos;
		shell = updreq2->pass_info.pw_shell;
	}

	if ((pass = malloc(passlen + 1)) == NULL) {
		syslog(LOG_ERR,
		    "nispasswd_update_common_svc: Out of memory");
		res->status = NPD_FAILED;
		res->nispasswd_updresult_u.npd_err = NPD_SYSTEMERR;
		return (TRUE);
	}

	/* set to success, and reset to error when warranted */
	res->status = NPD_SUCCESS;

	if (vers == NISPASSWD_VERS) {
		entry = (struct update_item *)__npd_item_by_key(updreq1->ident);
		if (entry == NULL) {
			syslog(LOG_ERR, "invalid identifier: %ld",
			    updreq1->ident);
			res->status = NPD_FAILED;
			res->nispasswd_updresult_u.npd_err = NPD_IDENTINVALID;
			goto upd_free_pass;
		}
	} else if (vers == NISPASSWD_VERS2) {
		entry = (struct update_item *)__npd_item_by_key(updreq2->ident);
		if (entry == NULL) {
			syslog(LOG_ERR, "invalid identifier: %ld",
			    updreq2->ident);
			res->status = NPD_FAILED;
			res->nispasswd_updresult_u.npd_err = NPD_IDENTINVALID;
			goto upd_free_pass;
		}
	}

	if (verbose) {
		syslog(LOG_DEBUG, "received NIS+ passwd update request for %s",
		    entry->ul_user);
	}

	/*
	 * iterate thru entry list and decrypt R sent and new passwd until
	 * we have a rand hit (or reach end of list)
	 */
	for (; entry != NULL;
	    entry = (struct update_item *)entry->ul_item.next) {
		if (vers == NISPASSWD_VERS) {
			/* decrypt R and new passwd */
			cryptbuf1.npd_xrandval =
			    ntohl(updreq1->xnewpass.npd_xrandval);
			for (i = 0; i < passlen; i++)
				cryptbuf1.pass[i] = updreq1->xnewpass.pass[i];

			if (! __npd_cbc_crypt(&rand, pass, passlen,
				&cryptbuf1, _NPD_PASSMAXLEN, DES_DECRYPT,
				&entry->ul_key)) {
				syslog(LOG_ERR, "failed to decrypt verifier");
				res->status = NPD_FAILED;
				res->nispasswd_updresult_u.npd_err =
				    NPD_DECRYPTFAIL;
				goto upd_free_pass;
			}
		} else if (vers == NISPASSWD_VERS2) {
			/* decrypt R and new passwd */

			cryptbuf2.npd_xrandval =
			    ntohl(updreq2->xnewpass.npd_xrandval);
			cryptbuf2.npd_pad = ntohl(updreq2->xnewpass.npd_pad);
			for (i = 0; i < passlen; i++)
				cryptbuf2.pass[i] = updreq2->xnewpass.pass[i];

			if (! __npd2_cbc_crypt(&rand, pass, passlen,
				&cryptbuf2, sizeof (cryptbuf2), DES_DECRYPT,
				&entry->ul_key)) {
				syslog(LOG_ERR, "failed to decrypt verifier");
				res->status = NPD_FAILED;
				res->nispasswd_updresult_u.npd_err =
				    NPD_DECRYPTFAIL;
				goto upd_free_pass;
			}
		}

		/* check if R sent/decrypted matches cached R */
		if (rand == entry->ul_rval) {
			if (verbose)
			    syslog(LOG_DEBUG, "rand hit (%ld) for user '%s'",
				    rand, entry->ul_user);
			break;
		} else
			if (verbose)
				syslog(LOG_ERR,
			    "rand miss: entry rval=%ld;  continue...",
				    entry->ul_rval);
	}

	if (entry == NULL) {
		if (verbose)
			syslog(LOG_ERR, "update failed; no rand matches");
		res->status = NPD_FAILED;
		res->nispasswd_updresult_u.npd_err = NPD_VERFINVALID;
		goto upd_free_pass;
	}

	/* create passwd struct with this pass & gecos/shell */
	pass_res = nis_getpwdent(entry->ul_user, entry->ul_domain);

	if (pass_res == NULL) {
		syslog(LOG_ERR, "invalid args %s and %s",
			entry->ul_user, entry->ul_domain);
		res->status = NPD_FAILED;
		res->nispasswd_updresult_u.npd_err = NPD_NOSUCHENTRY;
		goto upd_free_pass;
	}

	switch (pass_res->status) {
	case NIS_SUCCESS:
		pobj = NIS_RES_OBJECT(pass_res);
		break;
	case NIS_NOTFOUND:
		syslog(LOG_ERR, "no passwd entry found for %s",
			entry->ul_user);
		(void) nis_freeresult(pass_res);
		res->status = NPD_FAILED;
		res->nispasswd_updresult_u.npd_err = NPD_NOSUCHENTRY;
		goto upd_free_pass;
	default:
		syslog(LOG_ERR,
			"NIS+ error (%d) getting passwd entry for %s",
			pass_res->status, entry->ul_user);
		(void) nis_freeresult(pass_res);
		res->status = NPD_FAILED;
		res->nispasswd_updresult_u.npd_err = NPD_NISERROR;
		goto upd_free_pass;
	}

	old_pass =  ENTRY_VAL(pobj, 1);
	old_gecos = ENTRY_VAL(pobj, 4);
	old_shell = ENTRY_VAL(pobj, 6);

	/* can change passwd, shell or gecos */
	(void) memset(ecol, 0, sizeof (ecol));

	/* clear out the error list */
	(void) memset(errlist, 0, sizeof (errlist));

	/* if a gecos field is provided... */
	if (*gecos != '\0') {
		chg_passwd = FALSE;
		if (__npd_can_do(NIS_MODIFY_ACC, pobj,
			entry->ul_item.name, 4) == FALSE) {
			syslog(LOG_NOTICE,
		"insufficient permission for %s to change the gecos",
				entry->ul_user);
			res->status = NPD_PARTIALSUCCESS;
			errlist[0].npd_field = NPD_GECOS;
			errlist[0].npd_code = NPD_PERMDENIED;
			errlist[0].next = NULL;
		} else if (old_gecos == NULL ||
			strcmp(gecos, old_gecos) != 0) {

			ecol[4].ec_value.ec_value_val =
				gecos;
			ecol[4].ec_value.ec_value_len =
				strlen(gecos) + 1;
			ecol[4].ec_flags = EN_MODIFIED;
		}
	}
		/* if a shell field is provided... */
	if (*shell != '\0') {
		chg_passwd = FALSE;
		if (__npd_can_do(NIS_MODIFY_ACC, pobj,
			entry->ul_item.name, 6) == FALSE) {
			syslog(LOG_NOTICE,
		"insufficient permission for %s to change the shell",
				entry->ul_user);

			/*
			 * If already set to partial success, that means
			 * that gecos field and error was provided, so
			 * add the next item to the error list.
			 */
			if (res->status == NPD_PARTIALSUCCESS) {
				errlist[0].next = &errlist[1];
				errlist[1].npd_field = NPD_SHELL;
				errlist[1].npd_code = NPD_PERMDENIED;
				errlist[1].next = NULL;
			} else {
				res->status = NPD_PARTIALSUCCESS;
				errlist[0].npd_field = NPD_SHELL;
				errlist[0].npd_code = NPD_PERMDENIED;
				errlist[0].next = NULL;
			}
		} else if (old_shell == NULL ||
			strcmp(shell, old_shell) != 0) {
			ecol[6].ec_value.ec_value_val =
				shell;
			ecol[6].ec_value.ec_value_len =
				strlen(shell) + 1;
			ecol[6].ec_flags = EN_MODIFIED;
		}
	}
	/* otherwise password */
	if (chg_passwd == TRUE) {
		/* encrypt new passwd */
		if (!(newpass = __npd_encryptpass(pass,
			NIS_RES_OBJECT(pass_res)))) {
			syslog(LOG_ERR, "password encryption failed");
			res->status = NPD_FAILED;
			res->nispasswd_updresult_u.npd_err = NPD_ENCRYPTFAIL;
			goto end;
		}
		ecol[1].ec_value.ec_value_val = newpass;
		ecol[1].ec_value.ec_value_len = strlen(newpass) + 1;
		ecol[1].ec_flags = EN_CRYPT|EN_MODIFIED;
		pwflag = TRUE;
	}

	/* update lstchg field in the shadow area */
	sp = ENTRY_VAL(pobj, 7);
	if (pwflag && sp != NULL) {
		if ((sp = strchr(ENTRY_VAL(pobj, 7), ':')) == NULL) {
			syslog(LOG_ERR, "shadow column corrupted: user %s",
				entry->ul_user);
			(void) nis_freeresult(pass_res);
			res->status = NPD_FAILED;
			res->nispasswd_updresult_u.npd_err = NPD_SHDWCORRUPT;
			goto end;
		}
		(void) sprintf(shadow, "%d%s", (int)DAY_NOW, sp);
		ecol[7].ec_value.ec_value_val = shadow;
		ecol[7].ec_value.ec_value_len = strlen(shadow) + 1;
		ecol[7].ec_flags = EN_CRYPT|EN_MODIFIED;
	}

	/* clone an entry object to update passwd entry */
	eobj = nis_clone_object(pobj, NULL);
	if (eobj == NULL) {
		syslog(LOG_CRIT, "out of memory");
		res->status = NPD_FAILED;
		res->nispasswd_updresult_u.npd_err = NPD_SYSTEMERR;
		goto end;
	}

	/* save the old values for restoring before freeing the object */
	eobj_col = eobj->EN_data.en_cols.en_cols_val;
	eobj_col_len = eobj->EN_data.en_cols.en_cols_len;

	/* set column value to entry column */
	eobj->EN_data.en_cols.en_cols_val = ecol;
	eobj->EN_data.en_cols.en_cols_len = 8;

	/* strlen("[name=],passwd.") + null + "." = 17 */
	if ((strlen(entry->ul_user) + strlen(pobj->zo_domain) + 17) >
			(size_t)NIS_MAXNAMELEN) {
		syslog(LOG_ERR, "not enough buffer space");
		res->status = NPD_FAILED;
		res->nispasswd_updresult_u.npd_err = NPD_BUFTOOSMALL;
		goto end;
	}

	/* put together table index info and object modification */
	(void) sprintf(buf, "[name=%s],passwd.%s", entry->ul_user,
				pobj->zo_domain);

	/* add dot "." if necessary */
	if (buf[strlen(buf) - 1] != '.')
		(void) strcat(buf, ".");

	/* update NIS+ passwd table */
	mod_res = nis_modify_entry(buf, eobj, 0);

	/* if NIS+ update fails, bail now */
	if (mod_res->status != NIS_SUCCESS) {
		syslog(LOG_DEBUG, "could not update NIS+ passwd table");
		res->status = NPD_FAILED;
		res->nispasswd_updresult_u.npd_err = NPD_NISERROR;
		goto end;
	}

	/* NIS+ master updated; if YP-forwarding turned on, do YP */
	if (pwflag && ypfwd) {

		int try = 0;	/* retry counter for YP & NIS+ updates */

		/*
		 * Attempt the YP passwd map update;
		 * on failures use exponential backoff
		 */
		while ((update_authtok_nis_fwd(entry->ul_user, newpass,
			entry->ul_oldpass, ypfwd, old_gecos, old_shell)
			== -1) && (try < MAX_RETRY)) {
		    (void) sleep((unsigned)(1<<try));
		    try++;
		}

		/*
		 * On repeated failures (MAX_RETRY),
		 * give up & undo NIS+ table update
		 */
		if (try == MAX_RETRY) {
			try = 0;	/* clear for undo attempts */

			syslog(LOG_ERR,
			    "unable to update NIS(YP) passwd \
entry on %s for %s", ypfwd, entry->ul_user);

			/*
			 * The passwd tbl update failed, so set 'error'
			 * to an NPD failure.  Here is where it gets
			 * tricky.  The permissions on the passwd table
			 * must be turned off because the failover mech-
			 * anism will try to get NISD to make the update.
			 */
			error = res->status = NPD_FAILED;
			res->nispasswd_updresult_u.npd_err = NPD_SYSTEMERR;

			/* set "new" passwd back to old password */
			ecol[1].ec_value.ec_value_val = old_pass;
			ecol[1].ec_value.ec_value_len = strlen(old_pass) + 1;

			/* undo the NIS+ passwd table update */
			do {

				/* exponential backoff each try */
				if (try) (void) sleep((unsigned)(1<<try));

				/*
				 * Update table with old passwd information,
				 * freeing the old 'mod_res' struct first.
				 * 'eobj' has already been set to 'ecol' above.
				 */
				if (mod_res) (void) nis_freeresult(mod_res);
				mod_res = nis_modify_entry(buf, eobj, 0);

				/* On success, exit; otherwise increment ctr */
				if (mod_res->status == NIS_SUCCESS) break;
				else try++;

			} while (try < MAX_RETRY);

			/* NIS+ update repeated failures, bail now and log */
			if (try == MAX_RETRY) {
			    syslog(LOG_ERR, "WARNING: unable to undo NIS+ \
passwd update; maybe out-of-sync with YP map -- verify by hand");
			}
		}
	}

	/*
	 * The 'error' flag can only be changed from NPD_SUCCESS if
	 * YP updating was on and then, only in a failure scenario.
	 * In all other situations, update the credential!
	 */
	if (error == NPD_SUCCESS && pwflag) {

	    /* attempt to update PK cred(s) */
	    (void) __npd_upd_all_pk_creds(entry->ul_user, entry->ul_domain,
					entry->ul_oldpass, pass, &error);
	    if (error != NIS_SUCCESS) {
		if (res->status == NPD_PARTIALSUCCESS) {
			if (errlist[0].next == NULL) {
			    errlist[0].next = &errlist[1];
			    errlist[1].npd_field = NPD_SECRETKEY;
			    errlist[1].npd_code = error;
			    errlist[1].next = NULL;
			} else if (errlist[1].next == NULL) {
			    errlist[1].next = &errlist[2];
			    errlist[2].npd_field = NPD_SECRETKEY;
			    errlist[2].npd_code = error;
			    errlist[2].next = NULL;
			}
		} else {
		    res->status = NPD_PARTIALSUCCESS;
		    errlist[0].npd_field = NPD_SECRETKEY;
		    errlist[0].npd_code = error;
		    errlist[0].next = NULL;
		}

		/*
		 * Only set the reason union member if partial success;
		 * otherwise may wipe out npd_err union member.
		 */
		if (res->status == NPD_PARTIALSUCCESS)
		    res->nispasswd_updresult_u.reason = errlist[0];
	    }
	}

	/* Epilogue just consists of freeing up data */
end:
	/* Restore column stuff so that we can free eobj */
	if (eobj) {
		eobj->EN_data.en_cols.en_cols_val = eobj_col;
		eobj->EN_data.en_cols.en_cols_len = eobj_col_len;
		(void) nis_destroy_object(eobj);
	}

	/*
	 * The code to free pobj is not necessary as in
	 * yppasswdproc_update_1_svc() because pobj is
	 * freed when pass_res is just below.  Otherwise
	 * if it's in here, it will dump core.
	 */
	if (mod_res) (void) nis_freeresult(mod_res);
	if (pass_res) (void) nis_freeresult(pass_res);
	if (entry) (void) free_upd_item(entry);

upd_free_pass:
	if (pass != NULL)
		free(pass);
	return (TRUE);
}

/*
 * yppasswd update service routine.
 * The error codes returned are from the 4.x rpc.yppasswdd.c,
 * it seems that the client side only checks if the result is
 * non-zero in which case it prints a generic message !
 */
/* ARGSUSED2 */
bool_t
yppasswdproc_update_1_svc(yppass, result, rqstp)
struct yppasswd	*yppass;
int	*result;
struct svc_req	*rqstp;
{
	char	buf[NIS_MAXNAMELEN], *dom;
	struct passwd	*newpass;
	struct nis_result *mod_res = NULL;
	struct nis_object *pobj = NULL, *eobj = NULL;
	entry_col	ecol[8];
	char shadow[80], *sp, *p;
	char	*old_gecos, *old_shell, *old_pass;
	nis_server	*srv;
	nis_tag		tags[2], *tagres;
	int		status, ans;
	entry_col * 	eobj_col;
	uint_t		eobj_col_len;

	/* set new password from YP passwd struct */
	newpass = &yppass->newpw;

	if (verbose)
		syslog(LOG_ERR,
		"received yp password update request from %s",
		newpass->pw_name);

	/* fill-in NIS+ server information */
	srv = (nis_server *)__nis_host2nis_server(NULL, 0, &ans);
	if (srv == NULL) {
		syslog(LOG_ERR, "no host/addr information: %d", ans);
		*result = -1;
		return (TRUE);
	}

	/*
	 * make the nis_stats call to check if the server is running
	 * in compat mode and get the list of directories this server
	 * is serving
	 */
	tags[0].tag_type = TAG_NISCOMPAT;
	tags[0].tag_val = "";
	tags[1].tag_type = TAG_DIRLIST;
	tags[1].tag_val = "";

	status = nis_stats(srv, tags, 2, &tagres);
	__free_nis_server(srv);
	if (status != NIS_SUCCESS) {
		syslog(LOG_ERR, "nis_error: %d", status);
		*result = -1;
		return (1);
	}

	if ((strcmp(tagres[0].tag_val, "<Unknown Statistics>") == 0) ||
		(strcmp(tagres[1].tag_val, "<Unknown Statistics>") == 0)) {
		/* old server */
		syslog(LOG_ERR,
		"NIS+ server does not support the new statistics tags");
		nis_freetags(tagres, 2);
		*result = -1;
		return (1);
	}

	/* check if server is running in NIS compat mode */
	if (strcasecmp(tagres[0].tag_val, "OFF") == 0) {
		syslog(LOG_ERR,
		"Local NIS+ server is not running in NIS compat mode");
		*result = -1;
		nis_freetags(tagres, 2);
		return (1);
	}
	/*
	 * find the dir that has a passwd entry for this user
	 * POLICY: if user has a passwd stored in more then one
	 * dir then do not make an update. if user has an entry
	 * in only one dir, then make an update in that dir.
	 */

	if (! __npd_find_obj(newpass->pw_name, tagres[1].tag_val, &pobj)) {
		*result = -1;
		nis_freetags(tagres, 2);
		return (1);
	}
	nis_freetags(tagres, 2);

	old_pass = ENTRY_VAL(pobj, 1);
	old_gecos = ENTRY_VAL(pobj, 4);
	old_shell = ENTRY_VAL(pobj, 6);

	if (!__npd_has_aged(pobj, &ans) && ans == NPD_NOTAGED) {
		syslog(LOG_ERR, "password has not aged enough for %s",
			newpass->pw_name);
		*result = -1;
		goto ypend;
	}
	/* if ans == NPD_NOSHDWINFO then aging cannot be enforced */

	/* validate the old passwd */
	if (old_pass == NULL) {
		syslog(LOG_ERR, "no passwd found for %s", newpass->pw_name);
		*result = 7;	/* password incorrect */
		goto ypend;
	}

	/* mismatch on old passwd */
	if (strcmp(crypt((const char *)yppass->oldpass,
	    (const char *)old_pass), old_pass) != 0) {
		syslog(LOG_ERR, "incorrect passwd for %s", newpass->pw_name);
		*result = 7;
		goto ypend;
	}

	/* can change passwd, gecos or shell */
	(void) memset(ecol, 0, sizeof (ecol));

	if (strcmp(old_pass, newpass->pw_passwd) != 0) {
		ecol[1].ec_value.ec_value_val = newpass->pw_passwd;
		ecol[1].ec_value.ec_value_len =
				strlen(newpass->pw_passwd) + 1;
		ecol[1].ec_flags = EN_CRYPT|EN_MODIFIED;
	}

	if (strcmp(nis_leaf_of(pobj->zo_domain), "org_dir") == 0) {
		/* need to strip org_dir part of the domain */
		dom = strchr(pobj->zo_domain, '.');
		if (dom != NULL)
			dom++;
	} else
		dom = pobj->zo_domain;

			/* "." + null + "." = 3 */
	if ((strlen(newpass->pw_name) + strlen(dom) + 3) >
			(size_t)NIS_MAXNAMELEN) {
		syslog(LOG_ERR, "not enough buffer space");
		*result = -1;
		goto ypend;
	}
	(void) sprintf(buf, "%s.%s", newpass->pw_name, dom);
	if (buf[strlen(buf) - 1] != '.')
		(void) strcat(buf, ".");

	if (newpass->pw_gecos != NULL &&
		(old_gecos == NULL ||
			strcmp(old_gecos, newpass->pw_gecos) != 0)) {

		if (__npd_can_do(NIS_MODIFY_ACC, pobj, buf, 4) == FALSE) {
			syslog(LOG_NOTICE,
		"insufficient permission for %s to change the gecos",
				newpass->pw_name);
			*result = 2;
			goto ypend;
		}
		ecol[4].ec_value.ec_value_val = newpass->pw_gecos;
		ecol[4].ec_value.ec_value_len =
				strlen(newpass->pw_gecos) + 1;
		ecol[4].ec_flags = EN_MODIFIED;
	}

	if (newpass->pw_shell != NULL &&
		(old_shell == NULL ||
			strcmp(old_shell, newpass->pw_shell) != 0)) {

		if (! __npd_can_do(NIS_MODIFY_ACC, pobj, buf, 6)) {
			syslog(LOG_NOTICE,
		"insufficient permission for %s to change the shell",
				newpass->pw_name);
			*result = 2;
			goto ypend;
		}
		ecol[6].ec_value.ec_value_val = newpass->pw_shell;
		ecol[6].ec_value.ec_value_len =
				strlen(newpass->pw_shell) + 1;
		ecol[6].ec_flags = EN_MODIFIED;
	}
	/*
	 * from 4.x:
	 * This fixes a really bogus security hole, basically anyone can
	 * call the rpc passwd daemon, give them their own passwd and a
	 * new one that consists of ':0:0:Im root now:/:/bin/csh^J' and
	 * give themselves root access. With this code it will simply make
	 * it impossible for them to login again, and as a bonus leave
	 * a cookie for the always vigilant system administrator to ferret
	 * them out.
	 */

	for (p = newpass->pw_name; (*p != '\0'); p++)
		if ((*p == ':') || !(isprint(*p)))
			*p = '$';	/* you lose ! */
	for (p = newpass->pw_passwd; (*p != '\0'); p++)
		if ((*p == ':') || !(isprint(*p)))
			*p = '$';	/* you lose ! */

	/* update lstchg field */
	sp = ENTRY_VAL(pobj, 7);
	if (sp != NULL) {
		if ((sp = strchr(sp, ':')) == NULL) {
			syslog(LOG_ERR, "shadow column corrupted: user %s",
				newpass->pw_name);
			*result = -1;
			goto ypend;
		}
		(void) sprintf(shadow, "%d%s", (int)DAY_NOW, sp);
		ecol[7].ec_value.ec_value_val = shadow;
		ecol[7].ec_value.ec_value_len = strlen(shadow) + 1;
		ecol[7].ec_flags = EN_CRYPT|EN_MODIFIED;
	}

	/* clone an entry object to update passwd entry */
	eobj = nis_clone_object(pobj, NULL);
	if (eobj == NULL) {
		syslog(LOG_CRIT, "out of memory");
		*result = -1;
		goto ypend;
	}

	/* save the old values to restore while freeing the object */
	eobj_col = eobj->EN_data.en_cols.en_cols_val;
	eobj_col_len = eobj->EN_data.en_cols.en_cols_len;

	/* set column value to entry column */
	eobj->EN_data.en_cols.en_cols_val = ecol;
	eobj->EN_data.en_cols.en_cols_len = 8;

	/* strlen("[name=],passwd.") + null + "." = 17 */
	if ((strlen(newpass->pw_name) + strlen(pobj->zo_domain) + 17) >
			(size_t)NIS_MAXNAMELEN) {
		syslog(LOG_ERR, "not enough buffer space");
		*result = -1;
		goto ypend;
	}

	/* put together table index info and object modification */
	(void) sprintf(buf, "[name=%s],passwd.%s", newpass->pw_name,
			pobj->zo_domain);

	/* add dot "." if necessary */
	if (buf[strlen(buf) - 1] != '.')
		(void) strcat(buf, ".");

	/* update NIS+ passwd table */
	mod_res = nis_modify_entry(buf, eobj, 0);

	/* nisd in temp read-only mode (nisbackup(1M)) */
	if (mod_res->status == NIS_TRYAGAIN) {
		syslog(LOG_INFO,
			"could not update NIS+ passwd: %s",
			nis_sperrno(mod_res->status));
		/*
		 * 8 is the magic number from way back in 4.1.x.
		 * User should see
		 * "Password file/table busy. Try again later."
		 */
		*result = 8;
		goto ypend;
	}


	/* if NIS+ update fails, bail now */
	if (mod_res->status != NIS_SUCCESS) {
		syslog(LOG_ERR,
			"could not update NIS+ passwd: %s",
			nis_sperrno(mod_res->status));
		*result = 13;
		goto ypend;
	}

	/*
	 * nothing happens here because we cannot re-encrypt the credential
	 * because we do not have the unencrypted new password .... :^(
	 */
	*result = 0;

	/* NIS+ master updated; if YP-forwarding turned on, do YP */
	if (ypfwd) {

		int try = 0;	/* retry counter for YP & NIS+ updates */

		/*
		 * Attempt the YP passwd map update;
		 * on failures use exponential backoff
		 */
		while ((update_authtok_nis_fwd(newpass->pw_name,
			newpass->pw_passwd, yppass->oldpass, ypfwd,
			old_gecos, old_shell) == -1) &&
			(try < MAX_RETRY)) {
		    (void) sleep((unsigned)(1<<try));
		    try++;
		}

		/*
		 * On repeated failures (MAX_RETRY),
		 * give up & undo NIS+ table update
		 */
		if (try == MAX_RETRY) {
			try = 0;	/* clear for undo attempts */
			syslog(LOG_ERR,
			    "unable to update NIS(YP) passwd \
entry on %s for %s", ypfwd, newpass->pw_name);
			*result = -1;

			/* set "new" passwd back to old password */
			ecol[1].ec_value.ec_value_val = old_pass;
			ecol[1].ec_value.ec_value_len = strlen(old_pass) + 1;

			/* undo the NIS+ passwd table update */
			do {
				/* exponential backoff each try */
				if (try) (void) sleep((unsigned)(1<<try));

				/*
				 * Update table with old passwd information,
				 * freeing the old 'mod_res' struct first.
				 * 'eobj' has already been set to 'ecol' above.
				 */
				if (mod_res) (void) nis_freeresult(mod_res);
				mod_res = nis_modify_entry(buf, eobj, 0);

				/* On success, exit; otherwise increment ctr */
				if (mod_res->status == NIS_SUCCESS) break;
				else try++;

			} while (try < MAX_RETRY);

			/* NIS+ update repeated failures, bail now and log */
			if (try == MAX_RETRY) {
			    syslog(LOG_ERR, "WARNING: unable to undo NIS+ \
passwd update; maybe out-of-sync with YP map -- verify by hand");
			}
		}
	}

	/* the epilogue just consists of freeing up data */
ypend:
	/* Restore column stuff so that we can free eobj/pobj */
	if (eobj) {
	    eobj->EN_data.en_cols.en_cols_val = eobj_col;
	    eobj->EN_data.en_cols.en_cols_len = eobj_col_len;
	    (void) nis_destroy_object(eobj);
	}
	if (pobj)
	    (void) nis_destroy_object(pobj);
	if (mod_res) (void) nis_freeresult(mod_res);
	return (1);
}

/* ARGSUSED */
int
nispasswd_prog_1_freeresult(transp, xdr_result, result)
SVCXPRT *transp;
xdrproc_t xdr_result;
caddr_t result;
{

	/*
	 * (void) xdr_free(xdr_result, result);
	 * Insert additional freeing code here, if needed
	 */

	return (1);
}

/* ARGSUSED */
int
nispasswd_prog_2_freeresult(transp, xdr_result, result)
SVCXPRT *transp;
xdrproc_t xdr_result;
caddr_t result;
{

	/*
	 * (void) xdr_free(xdr_result, result);
	 * Insert additional freeing code here, if needed
	 */

	return (1);
}
