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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/* Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T */
/* All Rights Reserved */
/*
 * Portions of this source code were derived from Berkeley
 * 4.3 BSD under license from the Regents of the University of
 * California.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Interface to keyserver
 *
 * setsecretkey(key) - set your secret key
 * encryptsessionkey(agent, deskey) - encrypt a session key to talk to agent
 * decryptsessionkey(agent, deskey) - decrypt ditto
 * gendeskey(deskey) - generate a secure des key
 */

#include "mt.h"
#include "rpc_mt.h"
#include <errno.h>
#include <rpc/rpc.h>
#include <rpc/key_prot.h>
#include <stdio.h>
#include <syslog.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>

#define	CLASSIC_PK_DH(k, a)	(((k) == 192) && ((a) == 0))

#ifdef DEBUG
#define	debug(msg)	(void) fprintf(stderr, "%s\n", msg);
#else
#define	debug(msg)
#endif /* DEBUG */

int key_call(rpcproc_t, xdrproc_t, char *, xdrproc_t, char *);
int key_call_ext(rpcproc_t, xdrproc_t, char *, xdrproc_t, char *, int);
int key_setnet(struct key_netstarg *);

/*
 * Hack to allow the keyserver to use AUTH_DES (for authenticated
 * NIS+ calls, for example).  The only functions that get called
 * are key_encryptsession_pk, key_decryptsession_pk, and key_gendes.
 *
 * The approach is to have the keyserver fill in pointers to local
 * implementations of these functions, and to call those in key_call().
 */

bool_t (*__key_encryptsession_pk_LOCAL)() = NULL;
bool_t (*__key_decryptsession_pk_LOCAL)() = NULL;
bool_t (*__key_gendes_LOCAL)() = NULL;


int
key_setsecret(const char *secretkey)
{
	char netName[MAXNETNAMELEN+1];
	struct key_netstarg netst;
	int ret;

	if (getnetname(netName) == 0) {
		debug("getnetname failed");
		return (-1);
	}

	(void) memcpy(netst.st_priv_key, secretkey, HEXKEYBYTES);
	netst.st_pub_key[0] = 0;
	netst.st_netname = netName;

	/*
	 * Actual key login
	 * We perform the KEY_NET_PUT instead of the SET_KEY
	 * rpc call because key_secretkey_is_set function uses
	 * the KEY_NET_GET call which expects the netname to be
	 * set along with the key. Keylogin also uses KEY_NET_PUT.
	 */
	ret = key_setnet(&netst);

	/* erase our copy of the secret key */
	(void) memset(netst.st_priv_key, '\0', HEXKEYBYTES);

	if (ret == 1)
		return (0);

	return (-1);
}

int
key_setsecret_g(
	char *secretkey,
	keylen_t keylen,
	algtype_t algtype,
	des_block userkey)
{
	setkeyarg3 arg;
	keystatus status;

	if (CLASSIC_PK_DH(keylen, algtype))
		return (key_setsecret(secretkey));
	arg.key.keybuf3_len = keylen/4 + 1;
	arg.key.keybuf3_val = secretkey;
	arg.algtype = algtype;
	arg.keylen = keylen;
	arg.userkey = userkey;
	if (!key_call((rpcproc_t)KEY_SET_3, xdr_setkeyarg3, (char *)&arg,
			xdr_keystatus, (char *)&status))
		return (-1);
	if (status != KEY_SUCCESS) {
		debug("set3 status is nonzero");
		return (-1);
	}
	return (0);
}

int
key_removesecret_g_ext(int use_uid)
{
	keystatus status;

	if (!key_call_ext((rpcproc_t)KEY_CLEAR_3, xdr_void, NULL,
			xdr_keystatus, (char *)&status, use_uid)) {
		debug("remove secret key call failed");
		return (-1);
	}
	if (status != KEY_SUCCESS) {
		debug("remove secret status is nonzero");
		return (-1);
	}
	return (0);
}

/*
 * Use effective uid.
 */
int
key_removesecret_g(void)
{
	return (key_removesecret_g_ext(0));
}

/*
 * Use real uid.
 */
int
key_removesecret_g_ruid(void)
{
	return (key_removesecret_g_ext(1));
}

/*
 * key_secretkey_is_set() returns 1 if the keyserver has a secret key
 * stored for the caller's effective uid if use_ruid is 0 or
 * stored for the caller's real uid if use_ruid is 1.
 * it returns 0 otherwise.
 *
 * N.B.:  The KEY_NET_GET key call is undocumented.  Applications shouldn't
 * be using it, because it allows them to get the user's secret key.
 *
 */
int
key_secretkey_is_set_ext(int use_ruid)
{
	struct key_netstres 	kres;

	(void) memset(&kres, 0, sizeof (kres));
	if (key_call_ext((rpcproc_t)KEY_NET_GET, xdr_void, NULL,
			xdr_key_netstres, (char *)&kres, use_ruid) &&
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

/*
 * Use effective uid.
 */
int
key_secretkey_is_set(void)
{
	return (key_secretkey_is_set_ext(0));
}

/*
 * Use real uid.
 */
int
key_secretkey_is_set_ruid(void)
{
	return (key_secretkey_is_set_ext(1));
}

/*
 * key_secretkey_is_set_g_ext() returns 1 if the keyserver has a secret key
 * stored for the caller's uid, it returns 0 otherwise.
 * If (use_ruid == 0), for the caller's effective uid.
 * If (use_ruid == 1), for the caller's real uid.
 *
 * N.B.:  The KEY_NET_GET_3 key call is undocumented.  Applications shouldn't
 * be using it, because it allows them to get the user's secret key.
 */
int
key_secretkey_is_set_g_ext(keylen_t keylen, algtype_t algtype, int use_ruid)
{
	mechtype arg;
	key_netstres3 	kres;

	/*
	 * key_secretkey_is_set_g_ext is tricky because keylen == 0
	 * means check if any key exists for the caller (old/new, 192/1024 ...)
	 * Rather than handle this on the server side, we call the old
	 * routine if keylen == 0 and try the newer stuff only if that fails
	 */
	if ((keylen == 0) && key_secretkey_is_set_ext(use_ruid))
		return (1);
	if (CLASSIC_PK_DH(keylen, algtype))
		return (key_secretkey_is_set_ext(use_ruid));
	arg.keylen = keylen;
	arg.algtype = algtype;
	(void) memset(&kres, 0, sizeof (kres));
	if (key_call_ext((rpcproc_t)KEY_NET_GET_3, xdr_mechtype, (char *)&arg,
			xdr_key_netstres3, (char *)&kres, use_ruid) &&
	    (kres.status == KEY_SUCCESS) &&
	    (kres.key_netstres3_u.knet.st_priv_key.keybuf3_len != 0)) {
		/* avoid leaving secret key in memory */
		(void) memset(kres.key_netstres3_u.knet.st_priv_key.keybuf3_val,
			0, kres.key_netstres3_u.knet.st_priv_key.keybuf3_len);
		xdr_free(xdr_key_netstres3, (char *)&kres);
		return (1);
	}
	return (0);
}

/*
 * Use effective uid.
 */
int
key_secretkey_is_set_g(keylen_t keylen, algtype_t algtype)
{
	return (key_secretkey_is_set_g_ext(keylen, algtype, 0));
}

/*
 * Use real uid.
 */
int
key_secretkey_is_set_g_ruid(keylen_t keylen, algtype_t algtype)
{
	return (key_secretkey_is_set_g_ext(keylen, algtype, 1));
}


int
key_encryptsession_pk(const char *remotename, netobj *remotekey,
							des_block *deskey)
{
	cryptkeyarg2 arg;
	cryptkeyres res;

	arg.remotename = (char *)remotename;
	arg.remotekey = *remotekey;
	arg.deskey = *deskey;
	if (!key_call((rpcproc_t)KEY_ENCRYPT_PK, xdr_cryptkeyarg2, (char *)&arg,
			xdr_cryptkeyres, (char *)&res))
		return (-1);
	if (res.status != KEY_SUCCESS) {
		debug("encrypt status is nonzero");
		return (-1);
	}
	*deskey = res.cryptkeyres_u.deskey;
	return (0);
}

int
key_encryptsession_pk_g(
	const char *remotename,
	const char *remotekey,
	keylen_t remotekeylen,
	algtype_t algtype,
	des_block deskey[],
	keynum_t keynum
)
{
	cryptkeyarg3 arg;
	cryptkeyres3 res;

	if (CLASSIC_PK_DH(remotekeylen, algtype)) {
		int i;
		netobj npk;

		npk.n_len = remotekeylen/4 + 1;
		npk.n_bytes = (char *)remotekey;
		for (i = 0; i < keynum; i++) {
			if (key_encryptsession_pk(remotename, &npk, &deskey[i]))
				return (-1);
		}
		return (0);
	}
	arg.remotename = (char *)remotename;
	arg.remotekey.keybuf3_len = remotekeylen/4 + 1;
	arg.remotekey.keybuf3_val = (char *)remotekey;
	arg.keylen = remotekeylen;
	arg.algtype = algtype;
	arg.deskey.deskeyarray_len = keynum;
	arg.deskey.deskeyarray_val = deskey;
	(void) memset(&res, 0, sizeof (res));
	res.cryptkeyres3_u.deskey.deskeyarray_val = deskey;
	if (!key_call((rpcproc_t)KEY_ENCRYPT_PK_3,
			xdr_cryptkeyarg3, (char *)&arg,
			xdr_cryptkeyres3, (char *)&res))
		return (-1);
	if (res.status != KEY_SUCCESS) {
		debug("encrypt3 status is nonzero");
		return (-1);
	}
	if (res.cryptkeyres3_u.deskey.deskeyarray_len != keynum) {
		debug("number of keys don't match");
		return (-1);
	}
	return (0);
}

int
key_decryptsession_pk(const char *remotename, netobj *remotekey,
							des_block *deskey)
{
	cryptkeyarg2 arg;
	cryptkeyres res;

	arg.remotename = (char *)remotename;
	arg.remotekey = *remotekey;
	arg.deskey = *deskey;
	if (!key_call((rpcproc_t)KEY_DECRYPT_PK, xdr_cryptkeyarg2, (char *)&arg,
			xdr_cryptkeyres, (char *)&res))
		return (-1);
	if (res.status != KEY_SUCCESS) {
		debug("decrypt status is nonzero");
		return (-1);
	}
	*deskey = res.cryptkeyres_u.deskey;
	return (0);
}

int
key_decryptsession_pk_g(
	const char *remotename,
	const char *remotekey,
	keylen_t remotekeylen,
	algtype_t algtype,
	des_block deskey[],
	keynum_t keynum
)
{
	cryptkeyarg3 arg;
	cryptkeyres3 res;

	if (CLASSIC_PK_DH(remotekeylen, algtype)) {
		int i;
		netobj npk;

		npk.n_len = remotekeylen/4 + 1;
		npk.n_bytes = (char *)remotekey;
		for (i = 0; i < keynum; i++) {
			if (key_decryptsession_pk(remotename,
					&npk, &deskey[i]))
				return (-1);
		}
		return (0);
	}
	arg.remotename = (char *)remotename;
	arg.remotekey.keybuf3_len = remotekeylen/4 + 1;
	arg.remotekey.keybuf3_val = (char *)remotekey;
	arg.deskey.deskeyarray_len = keynum;
	arg.deskey.deskeyarray_val = deskey;
	arg.algtype = algtype;
	arg.keylen = remotekeylen;
	(void) memset(&res, 0, sizeof (res));
	res.cryptkeyres3_u.deskey.deskeyarray_val = deskey;
	if (!key_call((rpcproc_t)KEY_DECRYPT_PK_3,
			xdr_cryptkeyarg3, (char *)&arg,
			xdr_cryptkeyres3, (char *)&res))
		return (-1);
	if (res.status != KEY_SUCCESS) {
		debug("decrypt3 status is nonzero");
		return (-1);
	}
	if (res.cryptkeyres3_u.deskey.deskeyarray_len != keynum) {
		debug("number of keys don't match");
		return (-1);
	}
	return (0);
}

int
key_encryptsession(const char *remotename, des_block *deskey)
{
	cryptkeyarg arg;
	cryptkeyres res;

	arg.remotename = (char *)remotename;
	arg.deskey = *deskey;
	if (!key_call((rpcproc_t)KEY_ENCRYPT, xdr_cryptkeyarg, (char *)&arg,
			xdr_cryptkeyres, (char *)&res))
		return (-1);
	if (res.status != KEY_SUCCESS) {
		debug("encrypt status is nonzero");
		return (-1);
	}
	*deskey = res.cryptkeyres_u.deskey;
	return (0);
}

int
key_encryptsession_g(
	const char *remotename,
	keylen_t keylen,
	algtype_t algtype,
	des_block deskey[],
	keynum_t keynum
)
{
	cryptkeyarg3 arg;
	cryptkeyres3 res;

	if (CLASSIC_PK_DH(keylen, algtype))
		return (key_encryptsession(remotename, deskey));
	arg.remotename = (char *)remotename;
	arg.algtype = algtype;
	arg.keylen = keylen;
	arg.deskey.deskeyarray_len = keynum;
	arg.deskey.deskeyarray_val = deskey;
	arg.remotekey.keybuf3_len = 0;
	(void) memset(&res, 0, sizeof (res));
	res.cryptkeyres3_u.deskey.deskeyarray_val = deskey;
	if (!key_call((rpcproc_t)KEY_ENCRYPT_3, xdr_cryptkeyarg3, (char *)&arg,
			xdr_cryptkeyres3, (char *)&res))
		return (-1);
	if (res.status != KEY_SUCCESS) {
		debug("encrypt3 status is nonzero");
		return (-1);
	}
	if (res.cryptkeyres3_u.deskey.deskeyarray_len != keynum) {
		debug("encrypt3 didn't return same number of keys");
		return (-1);
	}
	return (0);
}


int
key_decryptsession(const char *remotename, des_block *deskey)
{
	cryptkeyarg arg;
	cryptkeyres res;

	arg.remotename = (char *)remotename;
	arg.deskey = *deskey;
	if (!key_call((rpcproc_t)KEY_DECRYPT, xdr_cryptkeyarg, (char *)&arg,
			xdr_cryptkeyres, (char *)&res))
		return (-1);
	if (res.status != KEY_SUCCESS) {
		debug("decrypt status is nonzero");
		return (-1);
	}
	*deskey = res.cryptkeyres_u.deskey;
	return (0);
}

int
key_decryptsession_g(
	const char *remotename,
	keylen_t keylen,
	algtype_t algtype,
	des_block deskey[],
	keynum_t keynum
)
{
	cryptkeyarg3 arg;
	cryptkeyres3 res;

	if (CLASSIC_PK_DH(keylen, algtype))
		return (key_decryptsession(remotename, deskey));
	arg.remotename = (char *)remotename;
	arg.algtype = algtype;
	arg.keylen = keylen;
	arg.deskey.deskeyarray_len = keynum;
	arg.deskey.deskeyarray_val = deskey;
	arg.remotekey.keybuf3_len = 0;
	(void) memset(&res, 0, sizeof (res));
	res.cryptkeyres3_u.deskey.deskeyarray_val = deskey;
	if (!key_call((rpcproc_t)KEY_DECRYPT_3, xdr_cryptkeyarg3, (char *)&arg,
			xdr_cryptkeyres3, (char *)&res))
		return (-1);
	if (res.status != KEY_SUCCESS) {
		debug("decrypt3 status is nonzero");
		return (-1);
	}
	if (res.cryptkeyres3_u.deskey.deskeyarray_len != keynum) {
		debug("decrypt3 didn't return same number of keys");
		return (-1);
	}
	return (0);
}

int
key_gendes(des_block *key)
{
	if (!key_call((rpcproc_t)KEY_GEN, xdr_void, NULL,
			xdr_des_block, (char *)key))
		return (-1);
	return (0);
}

int
key_gendes_g(
	des_block deskey[],
	keynum_t keynum
)
{
	deskeyarray res;

	res.deskeyarray_val = deskey;
	if (!key_call((rpcproc_t)KEY_GEN_3, xdr_keynum_t, (char *)&keynum,
			xdr_deskeyarray, (char *)&res))
		return (-1);
	if (res.deskeyarray_len != keynum) {
		debug("return length doesn't match\n");
		return (-1);
	}
	return (0);
}

/*
 * Call KEY_NET_PUT Operation to the keyserv.
 *
 * If use_ruid == 0, use effective uid.
 * If use_ruid == 1, use real uid.
 */
int
key_setnet_ext(struct key_netstarg *arg, int use_ruid)
{
	keystatus status;

	if (!key_call_ext((rpcproc_t)KEY_NET_PUT, xdr_key_netstarg,
		(char *)arg, xdr_keystatus, (char *)&status, use_ruid))
		return (-1);

	if (status != KEY_SUCCESS) {
		debug("key_setnet status is nonzero");
		return (-1);
	}
	return (1);
}

/*
 * Use effective uid.
 */
int
key_setnet(struct key_netstarg *arg)
{
	return (key_setnet_ext(arg, 0));
}

/*
 * Use real uid.
 */
int
key_setnet_ruid(struct key_netstarg *arg)
{
	return (key_setnet_ext(arg, 1));
}

/*
 * Input netname, secret and public keys (hex string representation)
 * of length skeylen/pkeylen (bits), and algorithm type. One, but not
 * both, of skey or pkey may have zero length. If both lengths are
 * specified, they must be the same.
 *
 * Call KEY_NET_PUT_3 Operation to the keyserv.
 * Stores the specified netname/pkey/skey triplet in the keyserv.
 *
 * If (use_ruid == 1), use real uid.
 * If (use_ruid == 0), use effective uid.
 */
int
key_setnet_g_ext(
	const char *netname,
	const char *skey,
	keylen_t skeylen,
	const char *pkey,
	keylen_t pkeylen,
	algtype_t algtype,
	int use_ruid)
{
	key_netstarg3 arg;
	keystatus status;

	arg.st_netname = (char *)netname;
	arg.algtype = algtype;
	if (skeylen == 0) {
		arg.st_priv_key.keybuf3_len = 0;
	} else {
		arg.st_priv_key.keybuf3_len = skeylen/4 + 1;
	}
	arg.st_priv_key.keybuf3_val = (char *)skey;
	if (pkeylen == 0) {
		arg.st_pub_key.keybuf3_len = 0;
	} else {
		arg.st_pub_key.keybuf3_len = pkeylen/4 + 1;
	}
	arg.st_pub_key.keybuf3_val = (char *)pkey;
	if (skeylen == 0) {
		if (pkeylen == 0) {
			debug("keylens are both 0");
			return (-1);
		}
		arg.keylen = pkeylen;
	} else {
		if ((pkeylen != 0) && (skeylen != pkeylen)) {
			debug("keylens don't match");
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
		return (key_setnet(&tmp));
	}
	if (!key_call_ext((rpcproc_t)KEY_NET_PUT_3,
		xdr_key_netstarg3, (char *)&arg,
		xdr_keystatus, (char *)&status, use_ruid)) {
		return (-1);
	}

	if (status != KEY_SUCCESS) {
		debug("key_setnet3 status is nonzero");
		return (-1);
	}
	return (0);
}

/*
 * Use effective uid.
 */
int
key_setnet_g(const char *netname, const char *skey, keylen_t skeylen,
	const char *pkey, keylen_t pkeylen, algtype_t algtype)
{
	return (key_setnet_g_ext(netname, skey, skeylen, pkey, pkeylen,
			algtype, 0));
}

/*
 * Use real uid.
 */
int
key_setnet_g_ruid(const char *netname, const char *skey, keylen_t skeylen,
	const char *pkey, keylen_t pkeylen, algtype_t algtype)
{
	return (key_setnet_g_ext(netname, skey, skeylen, pkey, pkeylen,
			algtype, 1));
}

int
key_get_conv(char *pkey, des_block *deskey)
{
	cryptkeyres res;

	if (!key_call((rpcproc_t)KEY_GET_CONV, xdr_keybuf, pkey,
		xdr_cryptkeyres, (char *)&res))
		return (-1);
	if (res.status != KEY_SUCCESS) {
		debug("get_conv status is nonzero");
		return (-1);
	}
	*deskey = res.cryptkeyres_u.deskey;
	return (0);
}

int
key_get_conv_g(
	const char *pkey,
	keylen_t pkeylen,
	algtype_t algtype,
	des_block deskey[],
	keynum_t keynum
)
{
	deskeyarg3 arg;
	cryptkeyres3 res;

	if (CLASSIC_PK_DH(pkeylen, algtype))
		return (key_get_conv((char *)pkey, deskey));
	arg.pub_key.keybuf3_len = pkeylen/4 + 1;
	arg.pub_key.keybuf3_val = (char *)pkey;
	arg.nkeys = keynum;
	arg.algtype = algtype;
	arg.keylen = pkeylen;
	(void) memset(&res, 0, sizeof (res));
	res.cryptkeyres3_u.deskey.deskeyarray_val = deskey;
	if (!key_call((rpcproc_t)KEY_GET_CONV_3, xdr_deskeyarg3, (char *)&arg,
		xdr_cryptkeyres3, (char *)&res))
		return (-1);
	if (res.status != KEY_SUCCESS) {
		debug("get_conv3 status is nonzero");
		return (-1);
	}
	if (res.cryptkeyres3_u.deskey.deskeyarray_len != keynum) {
		debug("get_conv3 number of keys dont match");
		return (-1);
	}
	return (0);
}

struct  key_call_private {
	CLIENT	*client;	/* Client handle */
	pid_t	pid;		/* process-id at moment of creation */
	int	fd;		/* client handle fd */
	dev_t	rdev;		/* device client handle is using */
};

static void set_rdev(struct key_call_private *);
static int check_rdev(struct key_call_private *);

static void
key_call_destroy(void *vp)
{
	struct key_call_private *kcp = (struct key_call_private *)vp;

	if (kcp != NULL && kcp->client != NULL) {
		(void) check_rdev(kcp);
		clnt_destroy(kcp->client);
		free(kcp);
	}
}

static pthread_key_t key_call_key = PTHREAD_ONCE_KEY_NP;

void
_key_call_fini(void)
{
	struct key_call_private	*kcp;

	if ((kcp = pthread_getspecific(key_call_key)) != NULL) {
		key_call_destroy(kcp);
		(void) pthread_setspecific(key_call_key, NULL);
	}
}

/*
 * Keep the handle cached.  This call may be made quite often.
 */
static CLIENT *
getkeyserv_handle(int vers, int stale)
{
	struct key_call_private	*kcp = NULL;
	int _update_did();

	kcp = thr_get_storage(&key_call_key, sizeof (*kcp), key_call_destroy);
	if (kcp == NULL) {
		syslog(LOG_CRIT, "getkeyserv_handle: out of memory");
		return (NULL);
	}

	/*
	 * if pid has changed, destroy client and rebuild
	 * or if stale is '1' then destroy client and rebuild
	 */
	if (kcp->client &&
	    (!check_rdev(kcp) || kcp->pid != getpid() || stale)) {
		clnt_destroy(kcp->client);
		kcp->client = NULL;
	}
	if (kcp->client) {
		int	fd;
		/*
		 * Change the version number to the new one.
		 */
		clnt_control(kcp->client, CLSET_VERS, (void *)&vers);
		if (!_update_did(kcp->client, vers)) {
			if (rpc_createerr.cf_stat == RPC_SYSTEMERROR)
				syslog(LOG_DEBUG, "getkeyserv_handle: "
						"out of memory!");
			return (NULL);
		}
		/* Update fd in kcp because it was reopened in _update_did */
		if (clnt_control(kcp->client, CLGET_FD, (void *)&fd) &&
		    (fd >= 0))
			(void) fcntl(fd, F_SETFD, FD_CLOEXEC); /* close exec */
		kcp->fd = fd;
		return (kcp->client);
	}

	if ((kcp->client = clnt_door_create(KEY_PROG, vers, 0)) == NULL)
		return (NULL);

	kcp->pid = getpid();
	set_rdev(kcp);
	(void) fcntl(kcp->fd, F_SETFD, FD_CLOEXEC);	/* close on exec */

	return (kcp->client);
}

/*
 * RPC calls to the keyserv.
 *
 * If (use_ruid == 1), use real uid.
 * If (use_ruid == 0), use effective uid.
 * Returns  0 on failure, 1 on success
 */
int
key_call_ext(rpcproc_t proc, xdrproc_t xdr_arg, char *arg, xdrproc_t xdr_rslt,
						char *rslt, int use_ruid)
{
	CLIENT		*clnt;
	struct timeval	wait_time = {0, 0};
	enum clnt_stat	status;
	int		vers;

	if (proc == KEY_ENCRYPT_PK && __key_encryptsession_pk_LOCAL) {
		cryptkeyres res;
		bool_t r;
		r = (*__key_encryptsession_pk_LOCAL)(geteuid(), arg, &res);
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
		r = (*__key_decryptsession_pk_LOCAL)(geteuid(), arg, &res);
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
		r = (*__key_gendes_LOCAL)(geteuid(), 0, &res);
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

	clnt = getkeyserv_handle(vers, 0);
	if (clnt == NULL)
		return (0);

	auth_destroy(clnt->cl_auth);
	if (use_ruid)
		clnt->cl_auth = authsys_create_ruid();
	else
		clnt->cl_auth = authnone_create();

	status = CLNT_CALL(clnt, proc, xdr_arg, arg, xdr_rslt,
			rslt, wait_time);

	switch (status) {
	case RPC_SUCCESS:
		return (1);

	case RPC_CANTRECV:
		/*
		 * keyserv was probably restarted, so we'll try once more
		 */
		if ((clnt = getkeyserv_handle(vers, 1)) == NULL)
			return (0);

		auth_destroy(clnt->cl_auth);
		if (use_ruid)
			clnt->cl_auth = authsys_create_ruid();
		else
			clnt->cl_auth = authnone_create();


		if (CLNT_CALL(clnt, proc, xdr_arg, arg, xdr_rslt, rslt,
						wait_time) == RPC_SUCCESS)
			return (1);
		return (0);

	default:
		return (0);
	}
}

/*
 * Use effective uid.
 */
int
key_call(rpcproc_t proc, xdrproc_t xdr_arg, char *arg, xdrproc_t xdr_rslt,
	char *rslt)
{
	return (key_call_ext(proc, xdr_arg, arg, xdr_rslt, rslt, 0));
}

/*
 * Use real uid.
 */
int
key_call_ruid(rpcproc_t proc, xdrproc_t xdr_arg, char *arg,
	xdrproc_t xdr_rslt, char *rslt)
{
	return (key_call_ext(proc, xdr_arg, arg, xdr_rslt, rslt, 1));
}

static void
set_rdev(struct key_call_private *kcp)
{
	int fd;
	struct stat stbuf;

	if (clnt_control(kcp->client, CLGET_FD, (char *)&fd) != TRUE ||
	    fstat(fd, &stbuf) == -1) {
		syslog(LOG_DEBUG, "keyserv_client:  can't get info");
		kcp->fd = -1;
		return;
	}
	kcp->fd = fd;
	kcp->rdev = stbuf.st_rdev;
}

static int
check_rdev(struct key_call_private *kcp)
{
	struct stat stbuf;

	if (kcp->fd == -1)
		return (1);    /* can't check it, assume it is okay */

	if (fstat(kcp->fd, &stbuf) == -1) {
		syslog(LOG_DEBUG, "keyserv_client:  can't stat %d", kcp->fd);
		/* could be because file descriptor was closed */
		/* it's not our file descriptor, so don't try to close it */
		clnt_control(kcp->client, CLSET_FD_NCLOSE, NULL);

		return (0);
	}
	if (kcp->rdev != stbuf.st_rdev) {
		syslog(LOG_DEBUG,
		    "keyserv_client:  fd %d changed, old=0x%x, new=0x%x",
		    kcp->fd, kcp->rdev, stbuf.st_rdev);
		/* it's not our file descriptor, so don't try to close it */
		clnt_control(kcp->client, CLSET_FD_NCLOSE, NULL);
		return (0);
	}
	return (1);    /* fd is okay */
}
