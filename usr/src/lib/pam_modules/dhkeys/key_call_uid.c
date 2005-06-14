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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <unistd.h>
#include <rpc/rpc.h>
#include <rpc/key_prot.h>
#include <rpcsvc/nis_dhext.h>
#include <syslog.h>
#include <note.h>

/* defined in usr/src/libnsl/rpc/key_call.c */
extern bool_t (*__key_encryptsession_pk_LOCAL)();
extern bool_t (*__key_decryptsession_pk_LOCAL)();
extern bool_t (*__key_gendes_LOCAL)();

#define	CLASSIC_PK_DH(k, a)	(((k) == 192) && ((a) == 0))

/*
 * authsys_create_uid(uid_t uid)
 *
 * Create SYS (UNIX) style authenticator for the given uid/gid
 * We don't include suplementary groups, since these are of no
 * interest for the keyserv operations that we do.
 */
AUTH *
authsys_create_uid(uid_t uid, gid_t gid)
{
	char	host[MAX_MACHINE_NAME + 1];
	AUTH	*res;

	if (gethostname(host, sizeof (host) - 1) == -1) {
		syslog(LOG_ERR,
			"pam_dhkeys: Can't determine hostname: %m");
		return (NULL);
	}
	host[MAX_MACHINE_NAME] = '\0';

	res = authsys_create(host, uid, gid, 0, (gid_t *)NULL);

	return (res);
}

/*
 * my_key_call(proc, xdr_arg, arg, xdr_rslt, rslt, uit, gid)
 *
 * my_key_call is a copy of key_call() from libnsl with the
 * added AUTHSYS rpc credential to make the keyserver use our
 * REAL UID instead of our EFFECTIVE UID when handling our keys.
 */
int
my_key_call(rpcproc_t proc, xdrproc_t xdr_arg, char *arg,
		xdrproc_t xdr_rslt, char *rslt, uid_t uid, gid_t gid)
{
	CLIENT		*clnt;
	struct timeval	wait_time = {0, 0};
	enum clnt_stat	status;
	int		vers;

	if (proc == KEY_ENCRYPT_PK && __key_encryptsession_pk_LOCAL) {
		cryptkeyres res;
		bool_t r;
		r = (*__key_encryptsession_pk_LOCAL)(uid, arg, &res);
		if (r == TRUE) {
			/* LINTED pointer alignment */
			*(cryptkeyres*)rslt = res;
			return (1);
		}
		return (0);
	}
	if (proc == KEY_DECRYPT_PK && __key_decryptsession_pk_LOCAL) {
		cryptkeyres res;
		bool_t r;
		r = (*__key_decryptsession_pk_LOCAL)(uid, arg, &res);
		if (r == TRUE) {
			/* LINTED pointer alignment */
			*(cryptkeyres*)rslt = res;
			return (1);
		}
		return (0);
	}
	if (proc == KEY_GEN && __key_gendes_LOCAL) {
		des_block res;
		bool_t r;
		r = (*__key_gendes_LOCAL)(uid, 0, &res);
		if (r == TRUE) {
			/* LINTED pointer alignment */
			*(des_block*)rslt = res;
			return (1);
		}
		return (0);
	}

	if ((proc == KEY_ENCRYPT_PK) || (proc == KEY_DECRYPT_PK) ||
	    (proc == KEY_NET_GET) || (proc == KEY_NET_PUT) ||
	    (proc == KEY_GET_CONV))
		vers = 2;	/* talk to version 2 */
	else
		vers = 1;	/* talk to version 1 */

	clnt = clnt_door_create(KEY_PROG, vers, 0);

	if (clnt == NULL)
		return (0);

	clnt->cl_auth = authsys_create_uid(uid, gid);

	status = CLNT_CALL(clnt, proc, xdr_arg, arg, xdr_rslt,
			rslt, wait_time);

	auth_destroy(clnt->cl_auth);
	clnt_destroy(clnt);

	return (status == RPC_SUCCESS ? 1 : 0);
}

int
key_setnet_uid(struct key_netstarg *arg, uid_t uid, gid_t gid)
{
	keystatus status;

	if (!my_key_call((rpcproc_t)KEY_NET_PUT, xdr_key_netstarg,
	    (char *)arg, xdr_keystatus, (char *)&status, uid, gid)) {
		return (-1);
	}
	if (status != KEY_SUCCESS) {
		return (-1);
	}

	return (1);
}

int
key_setnet_g_uid(const char *netname, const char *skey, keylen_t skeylen,
    const char *pkey, keylen_t pkeylen, algtype_t algtype,
    uid_t uid, gid_t gid)
{
	key_netstarg3 arg;
	keystatus status;

	arg.st_netname = (char *)netname;
	arg.algtype = algtype;

	if (skeylen == 0)
		arg.st_priv_key.keybuf3_len = 0;
	else
		arg.st_priv_key.keybuf3_len = skeylen/4 + 1;

	arg.st_priv_key.keybuf3_val = (char *)skey;

	if (pkeylen == 0)
		arg.st_pub_key.keybuf3_len = 0;
	else
		arg.st_pub_key.keybuf3_len = pkeylen/4 + 1;

	arg.st_pub_key.keybuf3_val = (char *)pkey;

	if (skeylen == 0) {
		if (pkeylen == 0) {
			/* debug("keylens are both 0"); */
			return (-1);
		}
		arg.keylen = pkeylen;
	} else {
		if ((pkeylen != 0) && (skeylen != pkeylen)) {
			/* debug("keylens don't match"); */
			return (-1);
		}
		arg.keylen = skeylen;
	}

	if (CLASSIC_PK_DH(arg.keylen, arg.algtype)) {
		key_netstarg tmp;

		if (skeylen != 0) {
			(void) memcpy(&tmp.st_priv_key, skey,
				sizeof (tmp.st_priv_key));
		} else {
			(void) memset(&tmp.st_priv_key, 0,
			    sizeof (tmp.st_priv_key));
		}
		if (pkeylen != 0) {
			(void) memcpy(&tmp.st_pub_key, skey,
			    sizeof (tmp.st_pub_key));
		} else {
			(void) memset(&tmp.st_pub_key, 0,
			    sizeof (tmp.st_pub_key));
		}
		tmp.st_netname = (char *)netname;
		return (key_setnet_uid(&tmp, uid, gid));
	}

	if (!my_key_call((rpcproc_t)KEY_NET_PUT_3, xdr_key_netstarg3,
	    (char *)&arg, xdr_keystatus, (char *)&status, uid, gid)) {
		return (-1);
	}

	if (status != KEY_SUCCESS) {
		/* debug("key_setnet3 status is nonzero"); */
		return (-1);
	}
	return (0);
}


/*
 * key_secretkey_is_set_uid() returns 1 if the keyserver has a secret key
 * stored for the caller's REAL uid; it returns 0 otherwise
 */
int
key_secretkey_is_set_uid(uid_t uid, gid_t gid)
{
	struct key_netstres 	kres;

	(void) memset((void*)&kres, 0, sizeof (kres));

	if (my_key_call((rpcproc_t)KEY_NET_GET, xdr_void, (char *)NULL,
			xdr_key_netstres, (char *)&kres, uid, gid) &&
	    (kres.status == KEY_SUCCESS) &&
	    (kres.key_netstres_u.knet.st_priv_key[0] != 0)) {
		/* avoid leaving secret key in memory */
		(void) memset(kres.key_netstres_u.knet.st_priv_key, 0,
		    HEXKEYBYTES);
		xdr_free(xdr_key_netstres, (char *)&kres);
		return (1);
	}
	return (0);
}

int
key_removesecret_g_uid(uid_t uid, gid_t gid)
{
	keystatus status;

	if (my_key_call((rpcproc_t)KEY_CLEAR_3, xdr_void, (char *)NULL,
	    xdr_keystatus, (char *)&status, uid, gid))
		return (-1);

	if (status != KEY_SUCCESS)
		return (-1);

	return (0);
}
