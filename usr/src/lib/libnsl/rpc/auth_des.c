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
/* Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T */
/* All Rights Reserved */
/*
 * Portions of this source code were derived from Berkeley
 * 4.3 BSD under license from the Regents of the University of
 * California.
 */

/*
 * auth_des.c, client-side implementation of DES authentication
 *
 */

#include "mt.h"
#include "rpc_mt.h"
#include <rpc/rpc.h>
#include <rpc/des_crypt.h>
#include <syslog.h>
#include <stdlib.h>
#include <string.h>
#include <synch.h>
#undef NIS
#include <rpcsvc/nis.h>

#define	USEC_PER_SEC		1000000
#define	RTIME_TIMEOUT		5	/* seconds to wait for sync */

extern bool_t xdr_authdes_cred(XDR *, struct authdes_cred *);
extern bool_t xdr_authdes_verf(XDR *, struct authdes_verf *);
extern int key_encryptsession_pk(const char *, netobj *, des_block *);

extern bool_t __rpc_get_time_offset(struct timeval *, nis_server *, char *,
						char **, char **);
static struct auth_ops *authdes_ops(void);
static bool_t authdes_refresh(AUTH *, void *);

/*
 * This struct is pointed to by the ah_private field of an "AUTH *"
 */
struct ad_private {
	char *ad_fullname;		/* client's full name */
	uint_t ad_fullnamelen;		/* length of name, rounded up */
	char *ad_servername;		/* server's full name */
	size_t ad_servernamelen;	/* length of name, rounded up */
	uint_t ad_window;		/* client specified window */
	bool_t ad_dosync;		/* synchronize? */
	char *ad_timehost;		/* remote host to sync with */
	struct timeval ad_timediff;	/* server's time - client's time */
	uint_t ad_nickname;		/* server's nickname for client */
	struct authdes_cred ad_cred;	/* storage for credential */
	struct authdes_verf ad_verf;	/* storage for verifier */
	struct timeval ad_timestamp;	/* timestamp sent */
	des_block ad_xkey;		/* encrypted conversation key */
	uchar_t ad_pkey[1024];		/* Servers actual public key */
	char *ad_netid;			/* Timehost netid */
	char *ad_uaddr;			/* Timehost uaddr */
	nis_server *ad_nis_srvr;	/* NIS+ server struct */
};

extern AUTH *authdes_pk_seccreate(const char *, netobj *, uint_t, const char *,
				const des_block *, nis_server *);

/*
 * documented version of authdes_seccreate
 */
/*
 *	servername: 	network name of server
 *	win:		time to live
 *	timehost:	optional hostname to sync with
 *	ckey:		optional conversation key to use
 */

AUTH *
authdes_seccreate(const char *servername, const uint_t win,
	const char *timehost, const des_block *ckey)
{
	uchar_t	pkey_data[1024];
	netobj	pkey;

	if (!getpublickey(servername, (char *)pkey_data)) {
		syslog(LOG_ERR,
			"authdes_seccreate: no public key found for %s",
			servername);

		return (NULL);
	}

	pkey.n_bytes = (char *)pkey_data;
	pkey.n_len = (uint_t)strlen((char *)pkey_data) + 1;
	return (authdes_pk_seccreate(servername, &pkey, win, timehost,
					ckey, NULL));
}

/*
 * Slightly modified version of authdes_seccreate which takes the public key
 * of the server principal as an argument. This spares us a call to
 * getpublickey() which in the nameserver context can cause a deadlock.
 */

AUTH *
authdes_pk_seccreate(const char *servername, netobj *pkey, uint_t window,
	const char *timehost, const des_block *ckey, nis_server *srvr)
{
	AUTH *auth;
	struct ad_private *ad;
	char namebuf[MAXNETNAMELEN+1];

	/*
	 * Allocate everything now
	 */
	auth = malloc(sizeof (AUTH));
	if (auth == NULL) {
		syslog(LOG_ERR, "authdes_pk_seccreate: out of memory");
		return (NULL);
	}
	ad = malloc(sizeof (struct ad_private));
	if (ad == NULL) {
		syslog(LOG_ERR, "authdes_pk_seccreate: out of memory");
		goto failed;
	}
	ad->ad_fullname = ad->ad_servername = NULL; /* Sanity reasons */
	ad->ad_timehost = NULL;
	ad->ad_netid = NULL;
	ad->ad_uaddr = NULL;
	ad->ad_nis_srvr = NULL;
	ad->ad_timediff.tv_sec = 0;
	ad->ad_timediff.tv_usec = 0;
	(void) memcpy(ad->ad_pkey, pkey->n_bytes, pkey->n_len);
	if (!getnetname(namebuf))
		goto failed;
	ad->ad_fullnamelen = RNDUP((uint_t)strlen(namebuf));
	ad->ad_fullname = malloc(ad->ad_fullnamelen + 1);
	ad->ad_servernamelen = strlen(servername);
	ad->ad_servername = malloc(ad->ad_servernamelen + 1);

	if (ad->ad_fullname == NULL || ad->ad_servername == NULL) {
		syslog(LOG_ERR, "authdes_seccreate: out of memory");
		goto failed;
	}
	if (timehost != NULL) {
		ad->ad_timehost = malloc(strlen(timehost) + 1);
		if (ad->ad_timehost == NULL) {
			syslog(LOG_ERR, "authdes_seccreate: out of memory");
			goto failed;
		}
		(void) memcpy(ad->ad_timehost, timehost, strlen(timehost) + 1);
		ad->ad_dosync = TRUE;
	} else if (srvr != NULL) {
		ad->ad_nis_srvr = srvr;	/* transient */
		ad->ad_dosync = TRUE;
	} else {
		ad->ad_dosync = FALSE;
	}
	(void) memcpy(ad->ad_fullname, namebuf, ad->ad_fullnamelen + 1);
	(void) memcpy(ad->ad_servername, servername, ad->ad_servernamelen + 1);
	ad->ad_window = window;
	if (ckey == NULL) {
		if (key_gendes(&auth->ah_key) < 0) {
			syslog(LOG_ERR,
	"authdes_seccreate: keyserv(8) is unable to generate session key");
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

	if (!authdes_refresh(auth, NULL)) {
		goto failed;
	}
	ad->ad_nis_srvr = NULL; /* not needed any longer */
	return (auth);

failed:
	if (auth)
		free(auth);
	if (ad) {
		if (ad->ad_fullname)
			free(ad->ad_fullname);
		if (ad->ad_servername)
			free(ad->ad_servername);
		if (ad->ad_timehost)
			free(ad->ad_timehost);
		if (ad->ad_netid)
			free(ad->ad_netid);
		if (ad->ad_uaddr)
			free(ad->ad_uaddr);
		free(ad);
	}
	return (NULL);
}

/*
 * Implement the five authentication operations
 */

/*
 * 1. Next Verifier
 */
/*ARGSUSED*/
static void
authdes_nextverf(AUTH *auth)
{
	/* what the heck am I supposed to do??? */
}


/*
 * 2. Marshal
 */
static bool_t
authdes_marshal(AUTH *auth, XDR *xdrs)
{
/* LINTED pointer alignment */
	struct ad_private *ad = (struct ad_private *)auth->ah_private;
	struct authdes_cred *cred = &ad->ad_cred;
	struct authdes_verf *verf = &ad->ad_verf;
	des_block cryptbuf[2];
	des_block ivec;
	int status;
	int len;
	rpc_inline_t *ixdr;

	/*
	 * Figure out the "time", accounting for any time difference
	 * with the server if necessary.
	 */
	(void) gettimeofday(&ad->ad_timestamp, NULL);
	ad->ad_timestamp.tv_sec += ad->ad_timediff.tv_sec;
	ad->ad_timestamp.tv_usec += ad->ad_timediff.tv_usec;
	while (ad->ad_timestamp.tv_usec >= USEC_PER_SEC) {
		ad->ad_timestamp.tv_usec -= USEC_PER_SEC;
		ad->ad_timestamp.tv_sec++;
	}

	/*
	 * XDR the timestamp and possibly some other things, then
	 * encrypt them.
	 */
	ixdr = (rpc_inline_t *)cryptbuf;
	IXDR_PUT_INT32(ixdr, ad->ad_timestamp.tv_sec);
	IXDR_PUT_INT32(ixdr, ad->ad_timestamp.tv_usec);
	if (ad->ad_cred.adc_namekind == ADN_FULLNAME) {
		IXDR_PUT_U_INT32(ixdr, ad->ad_window);
		IXDR_PUT_U_INT32(ixdr, ad->ad_window - 1);
		ivec.key.high = ivec.key.low = 0;
		status = cbc_crypt((char *)&auth->ah_key, (char *)cryptbuf,
				2 * sizeof (des_block),
				DES_ENCRYPT | DES_HW, (char *)&ivec);
	} else {
		status = ecb_crypt((char *)&auth->ah_key, (char *)cryptbuf,
				sizeof (des_block),
				DES_ENCRYPT | DES_HW);
	}
	if (DES_FAILED(status)) {
		syslog(LOG_ERR, "authdes_marshal: DES encryption failure");
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
		len = ((1 + 1 + 2 + 1)*BYTES_PER_XDR_UNIT + ad->ad_fullnamelen);
	} else {
		len = (1 + 1)*BYTES_PER_XDR_UNIT;
	}

	if (ixdr = xdr_inline(xdrs, 2*BYTES_PER_XDR_UNIT)) {
		IXDR_PUT_INT32(ixdr, AUTH_DES);
		IXDR_PUT_INT32(ixdr, len);
	} else {
		if (!xdr_putint32(xdrs, (int *)&auth->ah_cred.oa_flavor))
			return (FALSE);
		if (!xdr_putint32(xdrs, &len))
			return (FALSE);
	}
	if (!xdr_authdes_cred(xdrs, cred))
		return (FALSE);

	len = (2 + 1)*BYTES_PER_XDR_UNIT;
	if (ixdr = xdr_inline(xdrs, 2*BYTES_PER_XDR_UNIT)) {
		IXDR_PUT_INT32(ixdr, AUTH_DES);
		IXDR_PUT_INT32(ixdr, len);
	} else {
		if (!xdr_putint32(xdrs, (int *)&auth->ah_verf.oa_flavor))
			return (FALSE);
		if (!xdr_putint32(xdrs, &len))
			return (FALSE);
	}
	return (xdr_authdes_verf(xdrs, verf));
}


/*
 * 3. Validate
 */
static bool_t
authdes_validate(AUTH *auth, struct opaque_auth *rverf)
{
/* LINTED pointer alignment */
	struct ad_private *ad = (struct ad_private *)auth->ah_private;
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
	verf.adv_int_u = (uint32_t)*ixdr++;

	/*
	 * Decrypt the timestamp
	 */
	status = ecb_crypt((char *)&auth->ah_key, (char *)&buf,
		sizeof (des_block), DES_DECRYPT | DES_HW);

	if (DES_FAILED(status)) {
		syslog(LOG_ERR, "authdes_validate: DES decryption failure");
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
	if (memcmp(&ad->ad_timestamp, &verf.adv_timestamp,
		sizeof (struct timeval)) != 0) {
		syslog(LOG_DEBUG, "authdes_validate: verifier mismatch");
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
 */
/*ARGSUSED*/
static bool_t
authdes_refresh(AUTH *auth, void *dummy)
{
/* LINTED pointer alignment */
	struct ad_private *ad = (struct ad_private *)auth->ah_private;
	struct authdes_cred *cred = &ad->ad_cred;
	int		ok;
	netobj		pkey;

	if (ad->ad_dosync) {
		ok = __rpc_get_time_offset(&ad->ad_timediff, ad->ad_nis_srvr,
					    ad->ad_timehost, &(ad->ad_uaddr),
					    &(ad->ad_netid));
		if (!ok) {
			/*
			 * Hope the clocks are synced!
			 */
			ad->ad_dosync = 0;
			syslog(LOG_DEBUG,
		    "authdes_refresh: unable to synchronize clock");
		}
	}
	ad->ad_xkey = auth->ah_key;
	pkey.n_bytes = (char *)(ad->ad_pkey);
	pkey.n_len = (uint_t)strlen((char *)ad->ad_pkey) + 1;
	if (key_encryptsession_pk(ad->ad_servername, &pkey, &ad->ad_xkey) < 0) {
		syslog(LOG_INFO,
	"authdes_refresh: keyserv(8) is unable to encrypt session key");
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
	struct ad_private *ad = (struct ad_private *)auth->ah_private;

	free(ad->ad_fullname);
	free(ad->ad_servername);
	if (ad->ad_timehost)
		free(ad->ad_timehost);
	if (ad->ad_netid)
		free(ad->ad_netid);
	if (ad->ad_uaddr)
		free(ad->ad_uaddr);
	free(ad);
	free(auth);
}

static struct auth_ops *
authdes_ops(void)
{
	static struct auth_ops ops;
	extern mutex_t ops_lock;

	/* VARIABLES PROTECTED BY ops_lock: ops */

	(void) mutex_lock(&ops_lock);
	if (ops.ah_nextverf == NULL) {
		ops.ah_nextverf = authdes_nextverf;
		ops.ah_marshal = authdes_marshal;
		ops.ah_validate = authdes_validate;
		ops.ah_refresh = authdes_refresh;
		ops.ah_destroy = authdes_destroy;
	}
	(void) mutex_unlock(&ops_lock);
	return (&ops);
}
