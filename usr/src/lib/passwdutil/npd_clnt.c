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
 *	npd_clnt.c
 *	Contains all the client-side routines to communicate
 *	with the NIS+ passwd update deamon.
 *
 */

#include <stdlib.h>
#include <syslog.h>
#include <string.h>
#include <shadow.h>
#include <rpc/rpc.h>
#include <rpc/xdr.h>
#include <rpc/des_crypt.h>
#include <mp.h>
#include <rpc/key_prot.h>
#include <rpcsvc/nis.h>
#include <rpcsvc/nispasswd.h>
#include <rpcsvc/nis_dhext.h>
#include <memory.h>
#include <sys/time.h>
#include <unistd.h>
#include <sys/types.h>

#define	_NPD_PASSMAXLEN	16

extern bool_t	__npd_ecb_crypt(uint32_t *, uint32_t *,
				des_block *, unsigned int, unsigned int,
				des_block *);
extern bool_t	__npd_cbc_crypt(uint32_t *, char *, unsigned int,
				npd_newpass *, unsigned int, unsigned int,
				des_block *);
extern bool_t	__npd2_cbc_crypt(uint32_t *, char *, unsigned int,
				npd_newpass2 *, unsigned int, unsigned int,
				des_block *);
rpcvers_t	clnt_vers = NISPASSWD_VERS2;

/*
 * Loop thru the NIS+ security cf entries until one DH(EXT) mech key is
 * successfully extracted from the server DHEXT netobj.  Copy the hex key
 * string to newly allocated memory and return it's address in 'keybuf'.
 * The caller must free this memory.  Also, dup the key length and algtype
 * "alias" string and return it's address in keystr  (which the caller
 * must also free on successful return).
 *
 * Policy: If no valid cf entries exist or if the entry is the "des" compat
 * one, then try it and then end search.
 *
 * Returns TRUE on success and FALSE on failure.
 */
static bool_t
get_dhext_key(
	netobj		*pkey,		/* in */
	char		**keybuf,	/* out */
	keylen_t	*keylen,	/* (bits) out */
	algtype_t	*keyalgtype,	/* out */
	char		**keystr)	/* out */
{
	mechanism_t	**mechs;  /* list of mechanisms	*/
	char		*hexkey;  /* hex public key */

	if (mechs = __nis_get_mechanisms(FALSE)) {
		mechanism_t **mpp;

		for (mpp = mechs; *mpp; mpp++) {
			mechanism_t *mp = *mpp;

			if (AUTH_DES_COMPAT_CHK(mp)) {
				__nis_release_mechanisms(mechs);
				goto try_auth_des;
			}
			if (! VALID_MECH_ENTRY(mp))
				continue;

			if (hexkey = __nis_dhext_extract_pkey(pkey,
			    mp->keylen, mp->algtype)) {
				if ((*keybuf = malloc(strlen(hexkey) + 1))
				    == 0) {
					syslog(LOG_ERR, "malloc failed");
					continue;  /* try next mech */
				}
				(void) strcpy(*keybuf, hexkey);
				*keylen = mp->keylen;
				*keyalgtype = mp->algtype;
				*keystr = strdup(mp->alias);
				__nis_release_mechanisms(mechs);
				return (TRUE);
			} else
				continue;
		}
		__nis_release_mechanisms(mechs);
		return (FALSE);
	} else {

	/* no valid cf mech entries or AUTH_DES compat entry found */
	try_auth_des:
		if (hexkey = __nis_dhext_extract_pkey(pkey,
		    AUTH_DES_KEYLEN, AUTH_DES_ALGTYPE)) {
			if ((*keybuf = malloc(strlen(hexkey) + 1)) == NULL) {
					syslog(LOG_ERR, "malloc failed");
					return (FALSE);
			}
			(void) strcpy(*keybuf, hexkey);
			*keylen = AUTH_DES_KEYLEN;
			*keyalgtype = AUTH_DES_ALGTYPE;
			*keystr = strdup(NIS_SEC_CF_DES_ALIAS);
			return (TRUE);
		}
	}
	return (FALSE);
}



/*
 * given the domain return the client handle to the rpc.nispasswdd
 * that I need to contact and the master_servers' publickey and the
 * the key length and algtype "alias" string.
 *
 * returns TRUE on success and FALSE on failure.
 *
 * on successful return, caller must free the srv_pubkey buf and
 * the keystr buf.
 */
bool_t
npd_makeclnthandle(domain, clnt, srv_pubkey,
			srv_keylen, srv_keyalgtype, key_type)
char		*domain;
CLIENT		**clnt;			/* out */
char		**srv_pubkey;		/* buf to hold the pubkey; out */
keylen_t	*srv_keylen;		/* server key lenth (bits); out */
algtype_t	*srv_keyalgtype;	/* server key algorithm type; out */
char		**key_type;		/* key length/algtype str buf; out */
{
	nis_server	**srvs;		/* servers that serve 'domain' */
	nis_server	*master_srv;
	char		buf[NIS_MAXNAMELEN];
	CLIENT		*tmpclnt = NULL;
	rpcvers_t	vers;

	if (domain == NULL || *domain == '\0')
		domain = nis_local_directory();

	/* strlen("org_dir.") + null + "." = 10 */
	if ((strlen(domain) + 10) > (size_t)NIS_MAXNAMELEN)
		return (FALSE);
	(void) snprintf(buf, sizeof (buf), "org_dir.%s", domain);
	if (buf[strlen(buf) - 1] != '.')
		(void) strcat(buf, ".");

	srvs = nis_getservlist(buf);
	if (srvs == NULL) {
		/* can't find any of the servers that serve this domain */
		/* something is very wrong ! */
		syslog(LOG_ERR,
			"can't get a list of servers for %s domain",
			domain);
		return (FALSE);
	}
	master_srv = srvs[0];	/* the first one is always the master */

	/*
	 * copy a publickey
	 */
	switch (master_srv->key_type) {
	case NIS_PK_DHEXT:
		if (!get_dhext_key(&(master_srv->pkey), srv_pubkey,
					srv_keylen, srv_keyalgtype,
					key_type)) {
			syslog(LOG_WARNING,
		"could not get a DHEXT public key for master server '%s'",
				master_srv->name);
			(void) nis_freeservlist(srvs);
			return (FALSE);
		}
		break;

	case NIS_PK_DH:
		if ((*srv_pubkey = malloc(master_srv->pkey.n_len)) == NULL) {
			syslog(LOG_ERR, "malloc failed");
			(void) nis_freeservlist(srvs);
			return (FALSE);
		}
		(void) strcpy(*srv_pubkey, master_srv->pkey.n_bytes);
		*srv_keylen = AUTH_DES_KEYLEN;
		*srv_keyalgtype = AUTH_DES_ALGTYPE;
		*key_type = strdup(AUTH_DES_AUTH_TYPE);
		break;

	case NIS_PK_NONE:
	default:
		/* server does not have a D-H key-pair */
		syslog(LOG_ERR, "no publickey for %s", master_srv->name);
		(void) nis_freeservlist(srvs);
		return (FALSE);
	}

	/*
	 * now that we have the universal addr for the master server,
	 * lets create the client handle to rpc.nispasswdd.
	 * always use VC and attempt to create an authenticated handle.
	 * nis_make_rpchandle() will attempt to use auth_des first,
	 * if user does not have D-H keys, then it will try auth_sys.
	 * sendsz and recvsz are 0 ==> choose defaults.
	 *
	 * First try NISPASSWD_VERS2. If it fails, fallback to NISPASSWD_VERS
	 */
	for (vers = NISPASSWD_VERS2;
		(vers >= NISPASSWD_VERS) && (tmpclnt == NULL); vers--) {
		tmpclnt = nis_make_rpchandle_gss_svc_ruid(master_srv, 0,
				NISPASSWD_PROG, vers, ZMH_VC+ZMH_AUTH, 0,
				0, NULL, NIS_SVCNAME_NISPASSWD);
		clnt_vers = vers;
	}

	/* done with server list */
	(void) nis_freeservlist(srvs);
	if (tmpclnt == NULL) {
		/*
		 * error syslog'd by nis_make_rpchandle()
		 */
		return (FALSE);
	}
	*clnt = tmpclnt;
	return (TRUE);
}

/* Default timeout can be changed using clnt_control() */
static	struct	timeval	TIMEOUT = { 55, 0 };

/*
 * initiate the passwd update request session by sending
 * username, domainname, the generated public key and
 * the callers' old passwd encrypted with the common DES key.
 * if it succeeds, decrypt the identifier and randval sent in
 * the response; otherwise return an appropriate error code.
 */
nispasswd_status
nispasswd_auth(user, domain, oldpass, u_pubkey, key_type, keylen,
		algtype, deskeys, clnt, ident, randval, err)
char		*user;		/* user name */
char		*domain;	/* domain */
char		*oldpass;	/* clear old password */
uchar_t		*u_pubkey;	/* users' public key */
char		*key_type;	/* key len and alg type string */
keylen_t	keylen;		/* user's public key length */
algtype_t	algtype;	/* user's public key algorithm type */
des_block	*deskeys;	/* the common DES key */
CLIENT		*clnt;		/* client handle to rpc.nispasswdd */
uint32_t	*ident;		/* ID, returned on first attempt */
uint32_t	*randval;	/* R, returned on first attempt */
int		*err;		/* error code, returned */
{
	npd_request	req_arg;
	nispasswd_authresult	res;
	des_block	ivec;
	unsigned char	xpass[_NPD_PASSMAXLEN+1];
	unsigned char	xpass2[__NPD2_MAXPASSBYTES+1];
	des_block	cryptbuf;
	int		cryptstat;
	int		i;

	if ((user == NULL || *user == '\0') ||
		(domain == NULL || *domain == '\0') ||
		(oldpass == NULL || *oldpass == '\0') ||
		(u_pubkey == NULL || *u_pubkey == '\0') ||
		(deskeys == (des_block *) NULL) ||
		(clnt == (CLIENT *) NULL)) {
		*err = NPD_INVALIDARGS;
		return (NPD_FAILED);
	}
	(void) memset((char *)&req_arg, 0, sizeof (req_arg));
	(void) memset((char *)&res, 0, sizeof (res));

	if (clnt_vers == NISPASSWD_VERS) {
		/* encrypt the passwd with the common des key */
		if (strlen(oldpass) > (size_t)_NPD_PASSMAXLEN) {
			*err = NPD_BUFTOOSMALL;
			return (NPD_FAILED);
		}
		(void) strlcpy((char *)xpass, oldpass, sizeof (xpass));
		for (i = strlen(oldpass); i < _NPD_PASSMAXLEN; i++)
			xpass[i] = '\0';

		ivec.key.high = ivec.key.low = 0;
		if (AUTH_DES_KEY(keylen, algtype))
			cryptstat = cbc_crypt((char *)deskeys[0].c,
					(char *)xpass, _NPD_PASSMAXLEN,
					DES_ENCRYPT | DES_HW, (char *)&ivec);
		else
			cryptstat = __cbc_triple_crypt(deskeys, (char *)xpass,
					_NPD_PASSMAXLEN, DES_ENCRYPT | DES_HW,
					(char *)&ivec);

		if (DES_FAILED(cryptstat)) {
			*err = NPD_ENCRYPTFAIL;
			return (NPD_FAILED);
		}
	} else {
		/* encrypt the passwd with the common des key */
		if (strlen(oldpass) > (size_t)__NPD2_MAXPASSBYTES) {
			*err = NPD_BUFTOOSMALL;
			return (NPD_FAILED);
		}
		(void) strlcpy((char *)xpass2, oldpass, sizeof (xpass2));
		for (i = strlen(oldpass); i < __NPD2_MAXPASSBYTES; i++)
			xpass2[i] = '\0';

		ivec.key.high = ivec.key.low = 0;
		if (AUTH_DES_KEY(keylen, algtype))
			cryptstat = cbc_crypt((char *)deskeys[0].c,
					(char *)xpass2, __NPD2_MAXPASSBYTES,
					DES_ENCRYPT | DES_HW, (char *)&ivec);
		else
			cryptstat = __cbc_triple_crypt(deskeys, (char *)xpass2,
					__NPD2_MAXPASSBYTES,
					DES_ENCRYPT | DES_HW, (char *)&ivec);

		if (DES_FAILED(cryptstat)) {
			*err = NPD_ENCRYPTFAIL;
			return (NPD_FAILED);
		}
	}

	req_arg.username = user;
	req_arg.domain = domain;
	req_arg.key_type = key_type;
	req_arg.user_pub_key.user_pub_key_len =
			strlen((char *)u_pubkey) + 1;
	req_arg.user_pub_key.user_pub_key_val = u_pubkey;
	if (clnt_vers == NISPASSWD_VERS) {
		req_arg.npd_authpass.npd_authpass_len = _NPD_PASSMAXLEN;
		req_arg.npd_authpass.npd_authpass_val = xpass;
	} else {
		req_arg.npd_authpass.npd_authpass_len = __NPD2_MAXPASSBYTES;
		req_arg.npd_authpass.npd_authpass_val = xpass2;
	}
	req_arg.ident = *ident;		/* on re-tries ident is non-zero */

	if (clnt_call(clnt, NISPASSWD_AUTHENTICATE,
		(xdrproc_t)xdr_npd_request, (caddr_t)&req_arg,
		(xdrproc_t)xdr_nispasswd_authresult, (caddr_t)&res,
		TIMEOUT) != RPC_SUCCESS) {

		/* following msg is printed on stderr */
		(void) clnt_perror(clnt,
		    "authenticate call to rpc.nispasswdd failed");
		*err = NPD_SRVNOTRESP;
		return (NPD_FAILED);
	}

	switch (res.status) {
	case NPD_SUCCESS:
	case NPD_TRYAGAIN:
		/*
		 * decrypt the ident & randval
		 */
		cryptbuf.key.high =
			ntohl(res.nispasswd_authresult_u.npd_verf.npd_xid);
		cryptbuf.key.low =
			ntohl(res.nispasswd_authresult_u.npd_verf.npd_xrandval);

		if (! __npd_ecb_crypt(ident, randval, &cryptbuf,
			sizeof (des_block), DES_DECRYPT, &(deskeys[0]))) {
			*err = NPD_DECRYPTFAIL;
			return (NPD_FAILED);
		}
		return (res.status);

	case NPD_FAILED:
		*err = res.nispasswd_authresult_u.npd_err;
		return (NPD_FAILED);
	default:
		/*
		 * should never reach this case !
		 */
		*err = NPD_SYSTEMERR;
		return (NPD_FAILED);
	}
	/* NOTREACHED */
}

/*
 * authenticated the caller, now send the identifier; and the
 * new password and the random value encrypted with the common
 * DES key. Send any other changed password information in the
 * clear.
 */
int
nispasswd_pass(clnt, ident, randval, deskey, newpass, gecos, shell, err, errlst)
CLIENT		*clnt;		/* client handle to rpc.nispasswdd */
uint32_t	ident;		/* ID */
uint32_t	randval;	/* R */
des_block	*deskey;	/* common DES key */
char		*newpass;	/* clear new password */
char		*gecos;		/* gecos */
char		*shell;		/* shell */
int		*err;		/* error code, returned */
nispasswd_error	**errlst;	/* error list on partial success, returned */
{
	npd_update	send_arg;
	npd_update2	send_arg2;
	nispasswd_updresult	result;
	npd_newpass	cryptbuf1;
	npd_newpass2	cryptbuf2;
	unsigned int	tmp_xrval;
	unsigned int	tmp_npd_pad;
	nispasswd_error	*errl = NULL, *p;
	char   xnewpass[__NPD_MAXPASSBYTES+1];
	char   xnewpass2[__NPD2_MAXPASSBYTES+1];

	if ((clnt == (CLIENT *) NULL) ||
		(deskey == (des_block *) NULL) ||
		(newpass == NULL || *newpass == '\0')) {
		*err = NPD_INVALIDARGS;
		return (NPD_FAILED);
	}

	if (clnt_vers == NISPASSWD_VERS) {
		(void) memset((char *)&send_arg, 0, sizeof (send_arg));
		(void) memset((char *)&result, 0, sizeof (result));
		send_arg.ident = ident;

		(void) strlcpy(xnewpass, newpass, sizeof (xnewpass));

		if (! __npd_cbc_crypt(&randval, xnewpass, strlen(xnewpass),
			&cryptbuf1, _NPD_PASSMAXLEN, DES_ENCRYPT, deskey)) {
			*err = NPD_ENCRYPTFAIL;
			return (NPD_FAILED);
		}
		tmp_xrval = cryptbuf1.npd_xrandval;
		cryptbuf1.npd_xrandval = htonl(tmp_xrval);
		send_arg.xnewpass = cryptbuf1;

		/* gecos */
		send_arg.pass_info.pw_gecos = gecos;

		/* shell */
		send_arg.pass_info.pw_shell = shell;

		if (clnt_call(clnt, NISPASSWD_UPDATE,
			(xdrproc_t)xdr_npd_update, (caddr_t)&send_arg,
			(xdrproc_t)xdr_nispasswd_updresult, (caddr_t)&result,
			TIMEOUT) != RPC_SUCCESS) {

			/* printed to stderr */
			(void) clnt_perror(clnt,
			    "update call to rpc.nispasswdd failed");
			*err = NPD_SRVNOTRESP;
			return (NPD_FAILED);
		}

	} else {
		(void) memset((char *)&send_arg2, 0, sizeof (send_arg2));
		(void) memset((char *)&result, 0, sizeof (result));
		send_arg2.ident = ident;

		(void) strlcpy(xnewpass2, newpass, sizeof (xnewpass2));

		if (! __npd2_cbc_crypt(&randval, xnewpass2, strlen(xnewpass2),
			&cryptbuf2, sizeof (cryptbuf2), DES_ENCRYPT,
			deskey)) {
			*err = NPD_ENCRYPTFAIL;
			return (NPD_FAILED);
		}
		tmp_xrval = cryptbuf2.npd_xrandval;
		tmp_npd_pad = cryptbuf2.npd_pad;
		cryptbuf2.npd_xrandval = htonl(tmp_xrval);
		cryptbuf2.npd_pad = htonl(tmp_npd_pad);

		send_arg2.xnewpass = cryptbuf2;
		/* gecos */
		send_arg2.pass_info.pw_gecos = gecos;
		/* shell */
		send_arg2.pass_info.pw_shell = shell;

		if (clnt_call(clnt, NISPASSWD_UPDATE,
			(xdrproc_t)xdr_npd_update2, (caddr_t)&send_arg2,
			(xdrproc_t)xdr_nispasswd_updresult, (caddr_t)&result,
			TIMEOUT) != RPC_SUCCESS) {

			/* printed to stderr */
			(void) clnt_perror(clnt,
			    "update call to rpc.nispasswdd failed");
			*err = NPD_SRVNOTRESP;
			return (NPD_FAILED);
		}
	}
	switch (result.status) {
	case NPD_SUCCESS:
		return (NPD_SUCCESS);
	case NPD_PARTIALSUCCESS:
		/* need to assign field/err code */
		errl = &result.nispasswd_updresult_u.reason;
		if (errl == (struct nispasswd_error *)NULL) {
			*err = NPD_SYSTEMERR;
			return (NPD_FAILED);
		}
		*errlst = (nispasswd_error *)
				calloc(1, sizeof (nispasswd_error));
		if (*errlst == (struct nispasswd_error *)NULL) {
			*err = NPD_SYSTEMERR;
			return (NPD_FAILED);
		}

		for (p = *errlst; errl != NULL; errl = errl->next) {
			p->npd_field = errl->npd_field;
			p->npd_code = errl->npd_code;
			if (errl->next != NULL) {
				p->next = (nispasswd_error *)
					calloc(1, sizeof (nispasswd_error));
				p = p->next;
			} else
				p->next = (nispasswd_error *) NULL;
		}
		return (NPD_PARTIALSUCCESS);
	case NPD_FAILED:
		*err = result.nispasswd_updresult_u.npd_err;
		return (NPD_FAILED);
	default:
		/*
		 * should never reach this case !
		 */
		*err = NPD_SYSTEMERR;
		return (NPD_FAILED);
	}
}

void
__npd_free_errlist(list)
nispasswd_error *list;
{
	nispasswd_error *p;

	if (list == NULL)
		return;
	for (; list != NULL; list = p) {
		p = list->next;
		free(list);
	}
	list = NULL;
}
