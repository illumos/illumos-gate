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

#ifndef _SMBD_AUTHSVC_H
#define	_SMBD_AUTHSVC_H

/*
 * Declarations shared with authsvc modules.
 */

#include <sys/types.h>
#include <smbsrv/libsmb.h>

/*
 * This is the common authsvc_context shared by all back-ends.
 * Note that ctx_mech_oid is really SPNEGO_MECH_OID, and the
 * ctx_itoken, ctx_otoken members are SPNEGO_TOKEN_HANDLE,
 * but this is using the underlying types so as to avoid
 * dragging in spnego.h here.
 */
typedef struct authsvc_context {
	int			ctx_socket;
	int 			ctx_mech_oid;
	int (*ctx_mh_work)(struct authsvc_context *);
	void (*ctx_mh_fini)(struct authsvc_context *);
	int			ctx_itoktype;
	int			ctx_negresult;

	/* (in,out) SPNEGO token handles */
	void			*ctx_itoken;
	void			*ctx_otoken;

	/* (in,out) raw (buf,len,type) */
	void			*ctx_irawbuf;
	uint_t			ctx_irawlen;
	int			ctx_irawtype;
	void			*ctx_orawbuf;
	uint_t			ctx_orawlen;
	int			ctx_orawtype;

	/* (in,out) body (buf,len) */
	void			*ctx_ibodybuf;
	uint_t			ctx_ibodylen;
	void			*ctx_obodybuf;
	uint_t			ctx_obodylen;

	/* who is the client */
	smb_lsa_clinfo_t	ctx_clinfo;

	/* final authentication token */
	struct smb_token	*ctx_token;

	/* private data for the back-end */
	void			*ctx_backend;
} authsvc_context_t;

int smbd_krb5ssp_init(authsvc_context_t *);
int smbd_krb5ssp_work(authsvc_context_t *);
void smbd_krb5ssp_fini(authsvc_context_t *);

int smbd_ntlmssp_init(authsvc_context_t *);
int smbd_ntlmssp_work(authsvc_context_t *);
void smbd_ntlmssp_fini(authsvc_context_t *);

/* Exposed for unit tests. */
int smbd_authsvc_dispatch(authsvc_context_t *);
authsvc_context_t *smbd_authctx_create(void);
void smbd_authctx_destroy(authsvc_context_t *);

#endif /* _SMBD_AUTHSVC_H */
