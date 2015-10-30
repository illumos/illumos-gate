/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2014 Nexenta Systems, Inc.  All rights reserved.
 */

/*
 * SMB authentication service
 *
 * This service listens on a local AF_UNIX socket, spawning a
 * thread to service each connection.  The client-side of such
 * connections is the in-kernel SMB service, with an open and
 * connect done in the SMB session setup handler.
 */

#include <sys/types.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <signal.h>
#include <stdio.h>
#include <note.h>
#include <net/if.h>
#include <net/route.h>
#include <sys/sockio.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <pthread.h>
#include <syslog.h>
#include <smbsrv/libsmb.h>
#include <netsmb/spnego.h>

#include "smbd.h"
#include "smbd_authsvc.h"

/* Arbitrary value outside the (small) range of valid OIDs */
#define	special_mech_raw_NTLMSSP	(spnego_mech_oid_NTLMSSP + 100)

static struct sockaddr_un smbauth_sockname = {
	AF_UNIX, SMB_AUTHSVC_SOCKNAME };

typedef struct spnego_mech_handler {
	int mh_oid; /* SPNEGO_MECH_OID */
	int (*mh_init)(authsvc_context_t *);
	int (*mh_work)(authsvc_context_t *);
	void (*mh_fini)(authsvc_context_t *);
} spnego_mech_handler_t;

static int smbd_authsock_create(void);
static void smbd_authsock_destroy(void);
static void *smbd_authsvc_listen(void *);
static void *smbd_authsvc_work(void *);
static void smbd_authsvc_flood(void);

static int smbd_authsvc_oldreq(authsvc_context_t *);
static int smbd_authsvc_clinfo(authsvc_context_t *);
static int smbd_authsvc_esfirst(authsvc_context_t *);
static int smbd_authsvc_esnext(authsvc_context_t *);
static int smbd_authsvc_escmn(authsvc_context_t *);
static int smbd_authsvc_gettoken(authsvc_context_t *);
static int smbd_raw_ntlmssp_esfirst(authsvc_context_t *);
static int smbd_raw_ntlmssp_esnext(authsvc_context_t *);

/*
 * We can get relatively large tokens now, thanks to krb5 PAC.
 * Might be better to size these buffers dynamically, but these
 * are all short-lived so not bothering with that for now.
 */
int smbd_authsvc_bufsize = 65000;

static mutex_t smbd_authsvc_mutex = DEFAULTMUTEX;

/*
 * The maximum number of authentication thread is limited by the
 * smbsrv smb_threshold_...(->sv_ssetup_ct) mechanism.  However,
 * due to occasional delays closing these auth. sockets, we need
 * a little "slack" on the number of threads we'll allow, as
 * compared with the in-kernel limit.  We could perhaps just
 * remove this limit now, but want it for extra safety.
 */
int smbd_authsvc_maxthread = SMB_AUTHSVC_MAXTHREAD + 32;
int smbd_authsvc_thrcnt = 0;	/* current thrcnt */
int smbd_authsvc_hiwat = 0;	/* largest thrcnt seen */
#ifdef DEBUG
int smbd_authsvc_slowdown = 0;
#endif

/*
 * These are the mechanisms we support, in order of preference.
 * But note: it's really the _client's_ preference that matters.
 * See &pref in the spnegoIsMechTypeAvailable() calls below.
 * Careful with this table; the code below knows its format and
 * may skip the fist two entries to ommit Kerberos.
 */
static const spnego_mech_handler_t
mech_table[] = {
	{
		spnego_mech_oid_Kerberos_V5,
		smbd_krb5ssp_init,
		smbd_krb5ssp_work,
		smbd_krb5ssp_fini
	},
	{
		spnego_mech_oid_Kerberos_V5_Legacy,
		smbd_krb5ssp_init,
		smbd_krb5ssp_work,
		smbd_krb5ssp_fini
	},
#define	MECH_TBL_IDX_NTLMSSP	2
	{
		spnego_mech_oid_NTLMSSP,
		smbd_ntlmssp_init,
		smbd_ntlmssp_work,
		smbd_ntlmssp_fini
	},
	{
		/* end marker */
		spnego_mech_oid_NotUsed,
		NULL, NULL, NULL
	},
};

static const spnego_mech_handler_t
smbd_auth_mech_raw_ntlmssp = {
	special_mech_raw_NTLMSSP,
	smbd_ntlmssp_init,
	smbd_ntlmssp_work,
	smbd_ntlmssp_fini
};


/*
 * Start the authentication service.
 * Returns non-zero on error.
 */
int
smbd_authsvc_start(void)
{
	pthread_attr_t	attr;
	pthread_t	tid;
	int		rc;

	rc = smbd_authsock_create();
	if (rc)
		return (rc);

	(void) pthread_attr_init(&attr);
	(void) pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
	rc = pthread_create(&tid, &attr, smbd_authsvc_listen, &smbd);
	(void) pthread_attr_destroy(&attr);
	if (rc) {
		smbd_authsock_destroy();
		return (rc);
	}

	smbd.s_authsvc_tid = tid;
	return (0);
}

void
smbd_authsvc_stop(void)
{

	if (smbd.s_authsvc_tid != 0) {
		(void) pthread_kill(smbd.s_authsvc_tid, SIGTERM);
		smbd.s_authsvc_tid = 0;
	}
}

static int
smbd_authsock_create(void)
{
	int sock = -1;

	sock = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sock < 0) {
		smbd_report("authsvc, socket create failed, %d", errno);
		return (errno);
	}

	(void) unlink(smbauth_sockname.sun_path);
	if (bind(sock, (struct sockaddr *)&smbauth_sockname,
	    sizeof (smbauth_sockname)) < 0) {
		smbd_report("authsvc, socket bind failed, %d", errno);
		(void) close(sock);
		return (errno);
	}

	if (listen(sock, SOMAXCONN) < 0) {
		smbd_report("authsvc, socket listen failed, %d", errno);
		(void) close(sock);
		return (errno);
	}

	smbd.s_authsvc_sock = sock;
	return (0);
}

static void
smbd_authsock_destroy(void)
{
	int fid;

	if ((fid = smbd.s_authsvc_sock) != -1) {
		smbd.s_authsvc_sock = -1;
		(void) close(fid);
	}
}

static void *
smbd_authsvc_listen(void *arg)
{
	authsvc_context_t *ctx;
	pthread_attr_t	attr;
	pthread_t	tid;
	socklen_t	slen;
	int		ls, ns, rc;

	_NOTE(ARGUNUSED(arg))

	(void) pthread_attr_init(&attr);
	(void) pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

	ls = smbd.s_authsvc_sock;
	for (;;) {

		slen = 0;
		ns = accept(ls, NULL, &slen);
		if (ns < 0) {
			switch (errno) {
			case ECONNABORTED:
				continue;
			case EINTR:
				/* normal termination */
				goto out;
			default:
				smbd_report("authsvc, socket accept failed,"
				    " %d", errno);
				goto out;
			}
		}

		/*
		 * Limit the number of auth. sockets
		 * (and the threads that service them).
		 */
		(void) mutex_lock(&smbd_authsvc_mutex);
		if (smbd_authsvc_thrcnt >= smbd_authsvc_maxthread) {
			(void) mutex_unlock(&smbd_authsvc_mutex);
			(void) close(ns);
			smbd_authsvc_flood();
			continue;
		}
		smbd_authsvc_thrcnt++;
		if (smbd_authsvc_hiwat < smbd_authsvc_thrcnt)
			smbd_authsvc_hiwat = smbd_authsvc_thrcnt;
		(void) mutex_unlock(&smbd_authsvc_mutex);

		ctx = smbd_authctx_create();
		if (ctx == NULL) {
			smbd_report("authsvc, can't allocate context");
			(void) mutex_lock(&smbd_authsvc_mutex);
			smbd_authsvc_thrcnt--;
			(void) mutex_unlock(&smbd_authsvc_mutex);
			(void) close(ns);
			goto out;
		}
		ctx->ctx_socket = ns;

		rc = pthread_create(&tid, &attr, smbd_authsvc_work, ctx);
		if (rc) {
			smbd_report("authsvc, thread create failed, %d", rc);
			(void) mutex_lock(&smbd_authsvc_mutex);
			smbd_authsvc_thrcnt--;
			(void) mutex_unlock(&smbd_authsvc_mutex);
			smbd_authctx_destroy(ctx);
			goto out;
		}
		ctx = NULL; /* given to the new thread */
	}

out:
	(void) pthread_attr_destroy(&attr);
	smbd_authsock_destroy();
	return (NULL);
}

static void
smbd_authsvc_flood(void)
{
	static uint_t count;
	static time_t last_report;
	time_t now = time(NULL);

	count++;
	if (last_report + 60 < now) {
		last_report = now;
		smbd_report("authsvc: flooded %u", count);
		count = 0;
	}
}

authsvc_context_t *
smbd_authctx_create(void)
{
	authsvc_context_t *ctx;

	ctx = malloc(sizeof (*ctx));
	if (ctx == NULL)
		return (NULL);
	bzero(ctx, sizeof (*ctx));

	ctx->ctx_irawlen = smbd_authsvc_bufsize;
	ctx->ctx_irawbuf = malloc(ctx->ctx_irawlen);
	ctx->ctx_orawlen = smbd_authsvc_bufsize;
	ctx->ctx_orawbuf = malloc(ctx->ctx_orawlen);
	if (ctx->ctx_irawbuf == NULL || ctx->ctx_orawbuf == NULL)
		goto errout;

	ctx->ctx_ibodylen = smbd_authsvc_bufsize;
	ctx->ctx_ibodybuf = malloc(ctx->ctx_ibodylen);
	ctx->ctx_obodylen = smbd_authsvc_bufsize;
	ctx->ctx_obodybuf = malloc(ctx->ctx_obodylen);
	if (ctx->ctx_ibodybuf == NULL || ctx->ctx_obodybuf == NULL)
		goto errout;

	return (ctx);

errout:
	smbd_authctx_destroy(ctx);
	return (NULL);
}

void
smbd_authctx_destroy(authsvc_context_t *ctx)
{
	if (ctx->ctx_socket != -1) {
		(void) close(ctx->ctx_socket);
		ctx->ctx_socket = -1;
	}

	if (ctx->ctx_token != NULL)
		smb_token_destroy(ctx->ctx_token);

	if (ctx->ctx_itoken != NULL)
		spnegoFreeData(ctx->ctx_itoken);
	if (ctx->ctx_otoken != NULL)
		spnegoFreeData(ctx->ctx_otoken);

	free(ctx->ctx_irawbuf);
	free(ctx->ctx_orawbuf);
	free(ctx->ctx_ibodybuf);
	free(ctx->ctx_obodybuf);

	free(ctx);
}

/*
 * Limit how long smbd_authsvc_work will wait for the client to
 * send us the next part of the authentication sequence.
 */
static struct timeval recv_tmo = { 30, 0 };

/*
 * Also set a timeout for send, where we're sending a response to
 * the client side (in smbsrv).  That should always be waiting in
 * recv by the time we send, so a short timeout is OK.
 */
static struct timeval send_tmo = { 15, 0 };

static void *
smbd_authsvc_work(void *arg)
{
	authsvc_context_t *ctx = arg;
	smb_lsa_msg_hdr_t	hdr;
	int sock = ctx->ctx_socket;
	int len, rc;

	if (setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO,
	    (char *)&send_tmo,  sizeof (send_tmo)) != 0) {
		smbd_report("authsvc_work: set set timeout: %m");
		goto out;
	}

	if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO,
	    (char *)&recv_tmo,  sizeof (recv_tmo)) != 0) {
		smbd_report("authsvc_work: set recv timeout: %m");
		goto out;
	}

	for (;;) {

		len = recv(sock, &hdr, sizeof (hdr), MSG_WAITALL);
		if (len <= 0) {
			/* normal termination */
			break;
		}
		if (len != sizeof (hdr)) {
			smbd_report("authsvc_work: read header failed");
			break;
		}

		if (hdr.lmh_msglen > smbd_authsvc_bufsize) {
			smbd_report("authsvc_work: msg too large");
			break;
		}

		if (hdr.lmh_msglen > 0) {
			len = recv(sock, ctx->ctx_irawbuf, hdr.lmh_msglen,
			    MSG_WAITALL);
			if (len != hdr.lmh_msglen) {
				smbd_report("authsvc_work: read mesg failed");
				break;
			}
		}
		ctx->ctx_irawtype = hdr.lmh_msgtype;
		ctx->ctx_irawlen = hdr.lmh_msglen;
		ctx->ctx_orawlen = smbd_authsvc_bufsize;
		ctx->ctx_ibodylen = smbd_authsvc_bufsize;
		ctx->ctx_obodylen = smbd_authsvc_bufsize;

		/*
		 * The real work happens here.
		 */
		rc = smbd_authsvc_dispatch(ctx);
		if (rc)
			break;

		hdr.lmh_msgtype = ctx->ctx_orawtype;
		hdr.lmh_msglen = ctx->ctx_orawlen;
		len = send(sock, &hdr, sizeof (hdr), 0);
		if (len != sizeof (hdr)) {
			smbd_report("authsvc_work: send failed");
			break;
		}

		if (ctx->ctx_orawlen > 0) {
			len = send(sock, ctx->ctx_orawbuf,
			    ctx->ctx_orawlen, 0);
			if (len != ctx->ctx_orawlen) {
				smbd_report("authsvc_work: send failed");
				break;
			}
		}
	}

out:
	if (ctx->ctx_mh_fini)
		(ctx->ctx_mh_fini)(ctx);

	smbd_authctx_destroy(ctx);

	(void) mutex_lock(&smbd_authsvc_mutex);
	smbd_authsvc_thrcnt--;
	(void) mutex_unlock(&smbd_authsvc_mutex);

	return (NULL);	/* implied pthread_exit() */
}

/*
 * Dispatch based on message type LSA_MTYPE_...
 * Non-zero return here ends the conversation.
 */
int
smbd_authsvc_dispatch(authsvc_context_t *ctx)
{
	int rc;

	switch (ctx->ctx_irawtype) {

	case LSA_MTYPE_OLDREQ:
#ifdef DEBUG
		if (smbd_authsvc_slowdown)
			(void) sleep(smbd_authsvc_slowdown);
#endif
		rc = smbd_authsvc_oldreq(ctx);
		break;

	case LSA_MTYPE_CLINFO:
		rc = smbd_authsvc_clinfo(ctx);
		break;

	case LSA_MTYPE_ESFIRST:
		rc = smbd_authsvc_esfirst(ctx);
		break;

	case LSA_MTYPE_ESNEXT:
#ifdef DEBUG
		if (smbd_authsvc_slowdown)
			(void) sleep(smbd_authsvc_slowdown);
#endif
		rc = smbd_authsvc_esnext(ctx);
		break;

	case LSA_MTYPE_GETTOK:
		rc = smbd_authsvc_gettoken(ctx);
		break;

		/* response types */
	case LSA_MTYPE_OK:
	case LSA_MTYPE_ERROR:
	case LSA_MTYPE_TOKEN:
	case LSA_MTYPE_ES_CONT:
	case LSA_MTYPE_ES_DONE:
	default:
		return (-1);
	}

	if (rc != 0) {
		smb_lsa_eresp_t *er = ctx->ctx_orawbuf;
		ctx->ctx_orawtype = LSA_MTYPE_ERROR;
		ctx->ctx_orawlen = sizeof (*er);
		er->ler_ntstatus = rc;
		er->ler_errclass = 0;
		er->ler_errcode = 0;
	}
	return (0);
}

static int
smbd_authsvc_oldreq(authsvc_context_t *ctx)
{
	smb_logon_t	user_info;
	XDR		xdrs;
	smb_token_t	*token = NULL;
	int		rc = 0;

	bzero(&user_info, sizeof (user_info));
	xdrmem_create(&xdrs, ctx->ctx_irawbuf, ctx->ctx_irawlen,
	    XDR_DECODE);
	if (!smb_logon_xdr(&xdrs, &user_info)) {
		xdr_destroy(&xdrs);
		return (NT_STATUS_INVALID_PARAMETER);
	}
	xdr_destroy(&xdrs);

	token = smbd_user_auth_logon(&user_info);
	xdr_free(smb_logon_xdr, (char *)&user_info);
	if (token == NULL)
		return (NT_STATUS_ACCESS_DENIED);

	ctx->ctx_token = token;

	return (rc);
}

static int
smbd_authsvc_clinfo(authsvc_context_t *ctx)
{

	if (ctx->ctx_irawlen != sizeof (smb_lsa_clinfo_t))
		return (NT_STATUS_INTERNAL_ERROR);
	(void) memcpy(&ctx->ctx_clinfo, ctx->ctx_irawbuf,
	    sizeof (smb_lsa_clinfo_t));

	ctx->ctx_orawtype = LSA_MTYPE_OK;
	ctx->ctx_orawlen = 0;
	return (0);
}

/*
 * Handle a security blob we've received from the client.
 * Incoming type: LSA_MTYPE_ESFIRST
 * Outgoing types: LSA_MTYPE_ES_CONT, LSA_MTYPE_ES_DONE,
 *   LSA_MTYPE_ERROR
 */
static int
smbd_authsvc_esfirst(authsvc_context_t *ctx)
{
	const spnego_mech_handler_t *mh;
	int idx, pref, rc;
	int best_pref = 1000;
	int best_mhidx = -1;

	/*
	 * NTLMSSP header is 8+, SPNEGO is 10+
	 */
	if (ctx->ctx_irawlen < 8) {
		smbd_report("authsvc: short blob");
		return (NT_STATUS_INVALID_PARAMETER);
	}

	/*
	 * We could have "Raw NTLMSSP" here intead of SPNEGO.
	 */
	if (bcmp(ctx->ctx_irawbuf, "NTLMSSP", 8) == 0) {
		rc = smbd_raw_ntlmssp_esfirst(ctx);
		return (rc);
	}

	/*
	 * Parse the SPNEGO token, check its type.
	 */
	rc = spnegoInitFromBinary(ctx->ctx_irawbuf,
	    ctx->ctx_irawlen, &ctx->ctx_itoken);
	if (rc != 0) {
		smbd_report("authsvc: spnego parse failed");
		return (NT_STATUS_INVALID_PARAMETER);
	}

	rc = spnegoGetTokenType(ctx->ctx_itoken, &ctx->ctx_itoktype);
	if (rc != 0) {
		smbd_report("authsvc: spnego get token type failed");
		return (NT_STATUS_INVALID_PARAMETER);
	}

	if (ctx->ctx_itoktype != SPNEGO_TOKEN_INIT) {
		smbd_report("authsvc: spnego wrong token type %d",
		    ctx->ctx_itoktype);
		return (NT_STATUS_INVALID_PARAMETER);
	}

	/*
	 * Figure out which mech type to use.  We want to use the
	 * first of the client's supported mechanisms that we also
	 * support.  Unfortunately, the spnego code does not have an
	 * interface to walk the token's mech list, so we have to
	 * ask about each mech type we know and keep track of which
	 * was earliest in the token's mech list.
	 *
	 * Also, skip the Kerberos mechanisms in workgroup mode.
	 */
	idx = 0;
	mh = mech_table;
	if (smb_config_get_secmode() != SMB_SECMODE_DOMAIN) {
		idx = MECH_TBL_IDX_NTLMSSP;
		mh = &mech_table[idx];
	}
	for (; mh->mh_init != NULL; idx++, mh++) {

		if (spnegoIsMechTypeAvailable(ctx->ctx_itoken,
		    mh->mh_oid, &pref) != 0)
			continue;

		if (pref < best_pref) {
			best_pref = pref;
			best_mhidx = idx;
		}
	}
	if (best_mhidx == -1) {
		smbd_report("authsvc: no supported spnego mechanism");
		return (NT_STATUS_INVALID_PARAMETER);
	}

	/* Found a mutually agreeable mech. */
	mh = &mech_table[best_mhidx];
	ctx->ctx_mech_oid = mh->mh_oid;
	ctx->ctx_mh_work = mh->mh_work;
	ctx->ctx_mh_fini = mh->mh_fini;
	rc = mh->mh_init(ctx);
	if (rc != 0) {
		smbd_report("authsvc: mech init failed");
		return (rc);
	}

	/*
	 * Common to LSA_MTYPE_ESFIRST, LSA_MTYPE_ESNEXT
	 */
	rc = smbd_authsvc_escmn(ctx);
	return (rc);
}

/*
 * Handle a security blob we've received from the client.
 * Incoming type: LSA_MTYPE_ESNEXT
 * Outgoing types: LSA_MTYPE_ES_CONT, LSA_MTYPE_ES_DONE,
 *   LSA_MTYPE_ERROR
 */
static int
smbd_authsvc_esnext(authsvc_context_t *ctx)
{
	int rc;

	/*
	 * Make sure LSA_MTYPE_ESFIRST was handled
	 * previously, so we have a work function.
	 */
	if (ctx->ctx_mh_work == NULL)
		return (NT_STATUS_INVALID_PARAMETER);

	if (ctx->ctx_mech_oid == special_mech_raw_NTLMSSP) {
		rc = smbd_raw_ntlmssp_esnext(ctx);
		return (rc);
	}

	/*
	 * Cleanup state from previous calls.
	 */
	if (ctx->ctx_itoken != NULL) {
		spnegoFreeData(ctx->ctx_itoken);
		ctx->ctx_itoken = NULL;
	}

	/*
	 * Parse the SPNEGO token, check its type.
	 */
	rc = spnegoInitFromBinary(ctx->ctx_irawbuf,
	    ctx->ctx_irawlen, &ctx->ctx_itoken);
	if (rc != 0)
		return (NT_STATUS_INVALID_PARAMETER);

	rc = spnegoGetTokenType(ctx->ctx_itoken, &ctx->ctx_itoktype);
	if (rc != 0)
		return (NT_STATUS_INVALID_PARAMETER);

	if (ctx->ctx_itoktype != SPNEGO_TOKEN_TARG)
		return (NT_STATUS_INVALID_PARAMETER);

	rc = smbd_authsvc_escmn(ctx);
	return (rc);
}

static int
smbd_authsvc_escmn(authsvc_context_t *ctx)
{
	SPNEGO_MECH_OID oid;
	ulong_t toklen;
	int rc;

	/*
	 * Cleanup state from previous calls.
	 */
	if (ctx->ctx_otoken != NULL) {
		spnegoFreeData(ctx->ctx_otoken);
		ctx->ctx_otoken = NULL;
	}

	/*
	 * Extract the payload (mech token).
	 */
	toklen = ctx->ctx_ibodylen;
	rc = spnegoGetMechToken(ctx->ctx_itoken,
	    ctx->ctx_ibodybuf, &toklen);
	switch (rc) {
	case SPNEGO_E_SUCCESS:
		break;
	case SPNEGO_E_ELEMENT_UNAVAILABLE:
		toklen = 0;
		break;
	case SPNEGO_E_BUFFER_TOO_SMALL:
		return (NT_STATUS_BUFFER_TOO_SMALL);
	default:
		return (NT_STATUS_INTERNAL_ERROR);
	}
	ctx->ctx_ibodylen = toklen;

	/*
	 * Now that we have the incoming "body" (mech. token),
	 * call the back-end mech-specific work function to
	 * create the outgoing "body" (mech. token).
	 *
	 * The worker must fill in:  ctx->ctx_negresult,
	 * and: ctx->ctx_obodylen, but ctx->ctx_obodybuf
	 * is optional, and is typically NULL after the
	 * final message of an auth sequence, where
	 * negresult == spnego_negresult_complete.
	 */
	rc = ctx->ctx_mh_work(ctx);
	if (rc != 0)
		return (rc);

	/*
	 * Wrap the outgoing body in a negTokenTarg SPNEGO token.
	 * The selected mech. OID is returned only when the
	 * incoming token was of type SPNEGO_TOKEN_INIT.
	 */
	if (ctx->ctx_itoktype == SPNEGO_TOKEN_INIT) {
		/* tell the client the selected mech. */
		oid = ctx->ctx_mech_oid;
	} else {
		/* Ommit the "supported mech." field. */
		oid = spnego_mech_oid_NotUsed;
	}

	/*
	 * Determine the spnego "negresult" from the
	 * reply message type (from the work func).
	 */
	switch (ctx->ctx_orawtype) {
	case LSA_MTYPE_ERROR:
		ctx->ctx_negresult = spnego_negresult_rejected;
		break;
	case LSA_MTYPE_ES_DONE:
		ctx->ctx_negresult = spnego_negresult_success;
		break;
	case LSA_MTYPE_ES_CONT:
		ctx->ctx_negresult = spnego_negresult_incomplete;
		break;
	default:
		return (-1);
	}

	rc = spnegoCreateNegTokenTarg(
	    oid,
	    ctx->ctx_negresult,
	    ctx->ctx_obodybuf, /* may be NULL */
	    ctx->ctx_obodylen,
	    NULL, 0,
	    &ctx->ctx_otoken);

	/*
	 * Convert the SPNEGO token into binary form,
	 * writing it to the output buffer.
	 */
	toklen = smbd_authsvc_bufsize;
	rc = spnegoTokenGetBinary(ctx->ctx_otoken,
	    (uchar_t *)ctx->ctx_orawbuf, &toklen);
	if (rc)
		rc = NT_STATUS_INTERNAL_ERROR;
	ctx->ctx_orawlen = (uint_t)toklen;

	return (rc);
}

/*
 * Wrapper for "Raw NTLMSSP", which is exactly like the
 * normal (SPNEGO-wrapped) NTLMSSP but without SPNEGO.
 * Setup back-end handler for: special_mech_raw_NTLMSSP
 * Compare with smbd_authsvc_esfirst().
 */
static int
smbd_raw_ntlmssp_esfirst(authsvc_context_t *ctx)
{
	const spnego_mech_handler_t *mh;
	int rc;

	mh = &smbd_auth_mech_raw_ntlmssp;
	rc = mh->mh_init(ctx);
	if (rc != 0)
		return (rc);

	ctx->ctx_mech_oid = mh->mh_oid;
	ctx->ctx_mh_work = mh->mh_work;
	ctx->ctx_mh_fini = mh->mh_fini;

	rc = smbd_raw_ntlmssp_esnext(ctx);

	return (rc);
}


/*
 * Wrapper for "Raw NTLMSSP", which is exactly like the
 * normal (SPNEGO-wrapped) NTLMSSP but without SPNEGO.
 * Just copy "raw" to "body", and vice versa.
 * Compare with smbd_authsvc_esnext, smbd_authsvc_escmn
 */
static int
smbd_raw_ntlmssp_esnext(authsvc_context_t *ctx)
{
	int rc;

	ctx->ctx_ibodylen = ctx->ctx_irawlen;
	(void) memcpy(ctx->ctx_ibodybuf,
	    ctx->ctx_irawbuf, ctx->ctx_irawlen);

	rc = ctx->ctx_mh_work(ctx);

	ctx->ctx_orawlen = ctx->ctx_obodylen;
	(void) memcpy(ctx->ctx_orawbuf,
	    ctx->ctx_obodybuf, ctx->ctx_obodylen);

	return (rc);
}


/*
 * After a successful authentication, request the access token.
 */
static int
smbd_authsvc_gettoken(authsvc_context_t *ctx)
{
	XDR		xdrs;
	smb_token_t	*token = NULL;
	int		rc = 0;
	int		len;

	if ((token = ctx->ctx_token) == NULL)
		return (NT_STATUS_ACCESS_DENIED);

	/*
	 * Encode the token response
	 */
	len = xdr_sizeof(smb_token_xdr, token);
	if (len > ctx->ctx_orawlen) {
		if ((ctx->ctx_orawbuf = realloc(ctx->ctx_orawbuf, len)) ==
		    NULL) {
			return (NT_STATUS_INTERNAL_ERROR);
		}
	}

	ctx->ctx_orawtype = LSA_MTYPE_TOKEN;
	ctx->ctx_orawlen = len;
	xdrmem_create(&xdrs, ctx->ctx_orawbuf, len, XDR_ENCODE);
	if (!smb_token_xdr(&xdrs, token))
		rc = NT_STATUS_INTERNAL_ERROR;
	xdr_destroy(&xdrs);

	return (rc);
}

/*
 * Initialization time code to figure out what mechanisms we support.
 * Careful with this table; the code below knows its format and may
 * skip the fist two entries to ommit Kerberos.
 */
static SPNEGO_MECH_OID MechTypeList[] = {
	spnego_mech_oid_Kerberos_V5,
	spnego_mech_oid_Kerberos_V5_Legacy,
#define	MECH_OID_IDX_NTLMSSP	2
	spnego_mech_oid_NTLMSSP,
};
static int MechTypeCnt = sizeof (MechTypeList) /
	sizeof (MechTypeList[0]);

/* This string is just like Windows. */
static char IgnoreSPN[] = "not_defined_in_RFC4178@please_ignore";

/*
 * Build the SPNEGO "hint" token based on the
 * configured authentication mechanisms.
 * (NTLMSSP, and maybe Kerberos)
 */
void
smbd_get_authconf(smb_kmod_cfg_t *kcfg)
{
	SPNEGO_MECH_OID *mechList = MechTypeList;
	int mechCnt = MechTypeCnt;
	SPNEGO_TOKEN_HANDLE hSpnegoToken = NULL;
	uchar_t *pBuf = kcfg->skc_negtok;
	uint32_t *pBufLen = &kcfg->skc_negtok_len;
	ulong_t tLen = sizeof (kcfg->skc_negtok);
	int rc;

	/*
	 * In workgroup mode, skip Kerberos.
	 */
	if (smb_config_get_secmode() != SMB_SECMODE_DOMAIN) {
		mechList += MECH_OID_IDX_NTLMSSP;
		mechCnt  -= MECH_OID_IDX_NTLMSSP;
	}

	rc = spnegoCreateNegTokenHint(mechList, mechCnt,
	    (uchar_t *)IgnoreSPN, &hSpnegoToken);
	if (rc != SPNEGO_E_SUCCESS) {
		syslog(LOG_DEBUG, "smb_config_get_negtok: "
		    "spnegoCreateNegTokenHint, rc=%d", rc);
		*pBufLen = 0;
		return;
	}
	rc = spnegoTokenGetBinary(hSpnegoToken, pBuf, &tLen);
	if (rc != SPNEGO_E_SUCCESS) {
		syslog(LOG_DEBUG, "smb_config_get_negtok: "
		    "spnegoTokenGetBinary, rc=%d", rc);
		*pBufLen = 0;
	} else {
		*pBufLen = (uint32_t)tLen;
	}
	spnegoFreeData(hSpnegoToken);
}
