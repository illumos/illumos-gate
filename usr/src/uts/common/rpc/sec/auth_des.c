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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * Portions of this source code were derived from Berkeley 4.3 BSD
 * under license from the Regents of the University of California.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * auth_des.c, client-side implementation of DES authentication
 */

#include <sys/types.h>
#include <sys/t_lock.h>
#include <sys/time.h>
#include <sys/systm.h>
#include <sys/socket.h>
#include <sys/tiuser.h>
#include <sys/errno.h>
#include <rpc/des_crypt.h>
#include <rpc/types.h>
#include <rpc/auth.h>
#include <rpc/auth_des.h>
#include <rpc/xdr.h>
#include <rpc/clnt.h>
#include <rpc/rpc_msg.h>
#include <netinet/in.h>	/* XXX: just to get htonl() and ntohl() */
#include <sys/cmn_err.h>
#include <sys/debug.h>

#define	MILLION		1000000
#define	RTIME_TIMEOUT	5		/* seconds to wait for sync */

#define	AUTH_PRIVATE(auth)	(struct ad_private *)auth->ah_private
#define	ALLOC(object_type)	(object_type *) mem_alloc(sizeof (object_type))
#define	FREE(ptr, size)		mem_free((char *)(ptr), (int)size)
#define	ATTEMPT(xdr_op)		if (!(xdr_op))\
					return (FALSE)

#define	gettimeofday(tvp, tzp)	uniqtime(tvp)

static void	authdes_nextverf(AUTH *);
static bool_t	authdes_marshal(AUTH *, XDR *, struct cred *);
static bool_t	authdes_validate(AUTH *, struct opaque_auth *);
static bool_t	authdes_refresh(AUTH *, struct rpc_msg *, cred_t *);
static void	authdes_destroy(AUTH *);
static bool_t	synchronize(struct knetconfig *, struct netbuf *,
			int, struct timeval *);

static struct auth_ops *authdes_ops(void);

/*
 * This struct is pointed to by the ah_private field of an "AUTH *"
 */
struct ad_private {
	char *ad_fullname; 		/* client's full name */
	uint_t ad_fullnamelen;		/* length of name, rounded up */
	char *ad_servername; 		/* server's full name */
	uint_t ad_servernamelen;	/* length of name, rounded up */
	uint_t ad_window;		/* client specified window */
	bool_t ad_dosync;		/* synchronize? */
	struct netbuf ad_syncaddr;	/* remote host to synch with */
	struct knetconfig ad_synconfig; /* netconfig for the synch host */
	int   ad_calltype;		/* use rpc or straight call for sync */
	struct timeval ad_timediff;	/* server's time - client's time */
	uint32_t ad_nickname;		/* server's nickname for client */
	struct authdes_cred ad_cred;	/* storage for credential */
	struct authdes_verf ad_verf;	/* storage for verifier */
	struct timeval ad_timestamp;	/* timestamp sent */
	des_block ad_xkey;		/* encrypted conversation key */
};


/*
 * Create the client des authentication object
 */
/* ARGSUSED */
int
authdes_create(char *servername, uint_t window, struct netbuf *syncaddr,
	struct knetconfig *synconfig, des_block *ckey, int calltype,
	AUTH **retauth)
{
	AUTH *auth;
	struct ad_private *ad;
	char namebuf[MAXNETNAMELEN+1];
	int error = 0;
	enum clnt_stat stat;

	if (retauth == NULL)
		return (EINVAL);

	*retauth = NULL;

	/*
	 * Allocate everything now
	 */
	auth = ALLOC(AUTH);
	ad = ALLOC(struct ad_private);
	bzero(ad, sizeof (struct ad_private));
	if ((stat = kgetnetname(namebuf)) != 0) {
		cmn_err(CE_NOTE,
	"authdes_create: unable to get client's netname: %s (error %d)",
		    clnt_sperrno(stat), stat);
		goto failed;
	}

	ad->ad_fullnamelen = (uint_t)RNDUP(strlen(namebuf));
	ad->ad_fullname = mem_alloc(ad->ad_fullnamelen + 1);

	ad->ad_servernamelen = (uint_t)strlen(servername);
	ad->ad_servername = mem_alloc(ad->ad_servernamelen + 1);

	if (auth == NULL || ad == NULL || ad->ad_fullname == NULL ||
	    ad->ad_servername == NULL) {
		cmn_err(CE_NOTE, "authdes_create: out of memory");
		error = ENOMEM;
		goto failed;
	}

	/*
	 * Set up private data
	 */
	bcopy(namebuf, ad->ad_fullname, ad->ad_fullnamelen + 1);
	bcopy(servername, ad->ad_servername, ad->ad_servernamelen + 1);
	if (syncaddr != NULL) {
		ad->ad_syncaddr = *syncaddr;
		ad->ad_synconfig = *synconfig;
		ad->ad_dosync = TRUE;
		ad->ad_calltype = calltype;
	} else {
		ad->ad_timediff.tv_sec = 0;
		ad->ad_timediff.tv_usec = 0;
		ad->ad_dosync = FALSE;
	}
	ad->ad_window = window;
	if (ckey == NULL) {
		if ((stat = key_gendes(&auth->ah_key)) != RPC_SUCCESS) {
			cmn_err(CE_NOTE,
	"authdes_create: unable to gen conversation key: %s (error %d)",
			    clnt_sperrno(stat), stat);
			if (stat == RPC_INTR)
				error = EINTR;
			else if (stat == RPC_TIMEDOUT)
				error = ETIMEDOUT;
			else
				error = EINVAL;		/* XXX */
			goto failed;
		}
	} else
		auth->ah_key = *ckey;

	/*
	 * Set up auth handle
	 */
	auth->ah_cred.oa_flavor = AUTH_DES;
	auth->ah_verf.oa_flavor = AUTH_DES;
	auth->ah_ops = authdes_ops();
	auth->ah_private = (caddr_t)ad;

	if (!authdes_refresh(auth, NULL, CRED()))
		goto failed;

	*retauth = auth;
	return (0);

failed:
	if (ad != NULL && ad->ad_fullname != NULL)
		FREE(ad->ad_fullname, ad->ad_fullnamelen + 1);
	if (ad != NULL && ad->ad_servername != NULL)
		FREE(ad->ad_servername, ad->ad_servernamelen + 1);
	if (ad != NULL)
		FREE(ad, sizeof (struct ad_private));
	if (auth != NULL)
		FREE(auth, sizeof (AUTH));
	return ((error == 0) ? EINVAL : error);		/* XXX */
}

/*
 * Implement the five authentication operations
 */

/*
 * 1. Next Verifier
 */
/* ARGSUSED */
static void
authdes_nextverf(AUTH *auth)
{
	/* what the heck am I supposed to do??? */
}

/*
 * 2. Marshal
 */
/* ARGSUSED */
static bool_t
authdes_marshal(AUTH *auth, XDR *xdrs, struct cred *cr)
{
	/* LINTED pointer alignment */
	struct ad_private *ad = AUTH_PRIVATE(auth);
	struct authdes_cred *cred = &ad->ad_cred;
	struct authdes_verf *verf = &ad->ad_verf;
	des_block cryptbuf[2];
	des_block ivec;
	int status;
	int len;
	int32_t *ixdr;

	/*
	 * Figure out the "time", accounting for any time difference
	 * with the server if necessary.
	 */
	(void) gettimeofday(&ad->ad_timestamp, (struct timezone *)NULL);
	ad->ad_timestamp.tv_sec += ad->ad_timediff.tv_sec;
	ad->ad_timestamp.tv_usec += ad->ad_timediff.tv_usec;
	if (ad->ad_timestamp.tv_usec >= MILLION) {
		ad->ad_timestamp.tv_usec -= MILLION;
		ad->ad_timestamp.tv_sec += 1;
	}

	/*
	 * XDR the timestamp and possibly some other things, then
	 * encrypt them.
	 */
	ixdr = (int32_t *)cryptbuf;
	IXDR_PUT_INT32(ixdr, ad->ad_timestamp.tv_sec);
	IXDR_PUT_INT32(ixdr, ad->ad_timestamp.tv_usec);
	if (ad->ad_cred.adc_namekind == ADN_FULLNAME) {
		IXDR_PUT_U_INT32(ixdr, ad->ad_window);
		IXDR_PUT_U_INT32(ixdr, ad->ad_window - 1);
		ivec.key.high = ivec.key.low = 0;
		status = cbc_crypt((char *)&auth->ah_key, (char *)cryptbuf,
		    2 * sizeof (des_block), DES_ENCRYPT, (char *)&ivec);
	} else {
		status = ecb_crypt((char *)&auth->ah_key, (char *)cryptbuf,
		    sizeof (des_block), DES_ENCRYPT);
	}
	if (DES_FAILED(status)) {
		cmn_err(CE_NOTE, "authdes_marshal: DES encryption failure");
		return (FALSE);
	}
	ad->ad_verf.adv_xtimestamp = cryptbuf[0];
	if (ad->ad_cred.adc_namekind == ADN_FULLNAME) {
		ad->ad_cred.adc_fullname.window = cryptbuf[1].key.high;
		ad->ad_verf.adv_winverf = cryptbuf[1].key.low;
	} else {
		ad->ad_cred.adc_nickname = ad->ad_nickname;
		ad->ad_verf.adv_winverf = 0;
	}

	/*
	 * Serialize the credential and verifier into opaque
	 * authentication data.
	 */
	if (ad->ad_cred.adc_namekind == ADN_FULLNAME) {
		len = ((1 + 1 + 2 + 1) * BYTES_PER_XDR_UNIT +
		    ad->ad_fullnamelen);
	} else
		len = (1 + 1) * BYTES_PER_XDR_UNIT;

	if (ixdr = xdr_inline(xdrs, 2 * BYTES_PER_XDR_UNIT)) {
		IXDR_PUT_INT32(ixdr, AUTH_DES);
		IXDR_PUT_INT32(ixdr, len);
	} else {
		ATTEMPT(xdr_putint32(xdrs,
		    (int32_t *)&auth->ah_cred.oa_flavor));
		ATTEMPT(xdr_putint32(xdrs, (int32_t *)&len));
	}
	ATTEMPT(xdr_authdes_cred(xdrs, cred));

	len = (2 + 1) * BYTES_PER_XDR_UNIT;
	if (ixdr = xdr_inline(xdrs, 2 * BYTES_PER_XDR_UNIT)) {
		IXDR_PUT_INT32(ixdr, AUTH_DES);
		IXDR_PUT_INT32(ixdr, len);
	} else {
		ATTEMPT(xdr_putint32(xdrs,
		    (int32_t *)&auth->ah_verf.oa_flavor));
		ATTEMPT(xdr_putint32(xdrs, (int32_t *)&len));
	}
	ATTEMPT(xdr_authdes_verf(xdrs, verf));
	return (TRUE);
}

/*
 * 3. Validate
 */
static bool_t
authdes_validate(AUTH *auth, struct opaque_auth *rverf)
{
	/* LINTED pointer alignment */
	struct ad_private *ad = AUTH_PRIVATE(auth);
	struct authdes_verf verf;
	int status;
	uint32_t *ixdr;
	des_block buf;

	if (rverf->oa_length != (2 + 1) * BYTES_PER_XDR_UNIT)
		return (FALSE);

	/* LINTED pointer alignment */
	ixdr = (uint32_t *)rverf->oa_base;
	buf.key.high = (uint32_t)*ixdr++;
	buf.key.low = (uint32_t)*ixdr++;
	verf.adv_int_u = IXDR_GET_U_INT32(ixdr);

	/*
	 * Decrypt the timestamp
	 */
	status = ecb_crypt((char *)&auth->ah_key, (char *)&buf,
	    sizeof (des_block), DES_DECRYPT);

	if (DES_FAILED(status)) {
		cmn_err(CE_NOTE, "authdes_validate: DES decryption failure");
		return (FALSE);
	}

	/*
	 * xdr the decrypted timestamp
	 */
	/* LINTED pointer alignment */
	ixdr = (uint32_t *)buf.c;
	verf.adv_timestamp.tv_sec = IXDR_GET_INT32(ixdr) + 1;
	verf.adv_timestamp.tv_usec = IXDR_GET_INT32(ixdr);

	/*
	 * validate
	 */
	if (bcmp((char *)&ad->ad_timestamp, (char *)&verf.adv_timestamp,
	    sizeof (struct timeval)) != 0) {
		cmn_err(CE_NOTE, "authdes_validate: verifier mismatch");
		return (FALSE);
	}

	/*
	 * We have a nickname now, let's use it
	 */
	ad->ad_nickname = verf.adv_nickname;
	ad->ad_cred.adc_namekind = ADN_NICKNAME;
	return (TRUE);
}

/*
 * 4. Refresh
 *
 *  msg is a dummy argument here.
 */
/* ARGSUSED */
static bool_t
authdes_refresh(AUTH *auth, struct rpc_msg *msg, cred_t *cr)
{
	/* LINTED pointer alignment */
	struct ad_private *ad = AUTH_PRIVATE(auth);
	struct authdes_cred *cred = &ad->ad_cred;
	enum clnt_stat stat;

	if (ad->ad_dosync &&
	    !synchronize(&ad->ad_synconfig, &ad->ad_syncaddr,
	    ad->ad_calltype, &ad->ad_timediff)) {
		/*
		 * Hope the clocks are synced!
		 */
		timerclear(&ad->ad_timediff);
		cmn_err(CE_NOTE,
"authdes_refresh: unable to synchronize with server %s", ad->ad_servername);
	}
	ad->ad_xkey = auth->ah_key;
	if ((stat = key_encryptsession(ad->ad_servername, &ad->ad_xkey, cr)) !=
	    RPC_SUCCESS) {
		cmn_err(CE_NOTE,
"authdes_refresh: unable to encrypt conversation key for user (uid %d): "
		    "%s (error %d)",
		    (int)crgetuid(cr), clnt_sperrno(stat), stat);
		return (FALSE);
	}
	cred->adc_fullname.key = ad->ad_xkey;
	cred->adc_namekind = ADN_FULLNAME;
	cred->adc_fullname.name = ad->ad_fullname;
	return (TRUE);
}

/*
 * 5. Destroy
 */
static void
authdes_destroy(AUTH *auth)
{
	/* LINTED pointer alignment */
	struct ad_private *ad = AUTH_PRIVATE(auth);

	FREE(ad->ad_fullname, ad->ad_fullnamelen + 1);
	FREE(ad->ad_servername, ad->ad_servernamelen + 1);
	FREE(ad, sizeof (struct ad_private));
	FREE(auth, sizeof (AUTH));
}


/*
 * Synchronize with the server at the given address, that is,
 * adjust timep to reflect the delta between our clocks
 */
static bool_t
synchronize(struct knetconfig *synconfig, struct netbuf *syncaddr, int calltype,
	struct timeval *timep)
{
	struct timeval mytime;
	struct timeval timout;

	timout.tv_sec = RTIME_TIMEOUT;
	timout.tv_usec = 0;
	if (rtime(synconfig, syncaddr, calltype, timep, &timout) < 0)
		return (FALSE);
	(void) gettimeofday(&mytime, (struct timezone *)NULL);
	timep->tv_sec -= mytime.tv_sec;
	if (mytime.tv_usec > timep->tv_usec) {
		timep->tv_sec -= 1;
		timep->tv_usec += MILLION;
	}
	timep->tv_usec -= mytime.tv_usec;
	return (TRUE);
}

static struct auth_ops *
authdes_ops(void)
{
	static struct auth_ops ops;

	mutex_enter(&authdes_ops_lock);
	if (ops.ah_nextverf == NULL) {
		ops.ah_nextverf = authdes_nextverf;
		ops.ah_marshal = authdes_marshal;
		ops.ah_validate = authdes_validate;
		ops.ah_refresh = authdes_refresh;
		ops.ah_destroy = authdes_destroy;
		ops.ah_wrap = authany_wrap;
		ops.ah_unwrap = authany_unwrap;
	}
	mutex_exit(&authdes_ops_lock);
	return (&ops);
}
