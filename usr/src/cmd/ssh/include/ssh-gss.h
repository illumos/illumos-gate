/*
 * Copyright (c) 2001-2003 Simon Wilkinson. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR `AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SSH_GSS_H
#define	_SSH_GSS_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef GSSAPI

#include "kex.h"
#include "buffer.h"

#ifdef SUNW_GSSAPI
#include <gssapi/gssapi.h>
#include <gssapi/gssapi_ext.h>
#else
#ifdef GSS_KRB5
#ifndef HEIMDAL
#include <gssapi_generic.h>

/* MIT Kerberos doesn't seem to define GSS_NT_HOSTBASED_SERVICE */
#ifndef GSS_C_NT_HOSTBASED_SERVICE
#define	GSS_C_NT_HOSTBASED_SERVICE gss_nt_service_name
#endif /* GSS_C_NT_... */
#endif /* !HEIMDAL */
#endif /* GSS_KRB5 */
#endif /* SUNW_GSSAPI */

/* draft-ietf-secsh-gsskeyex-03 */
#define	SSH2_MSG_KEXGSS_INIT				30
#define	SSH2_MSG_KEXGSS_CONTINUE 			31
#define	SSH2_MSG_KEXGSS_COMPLETE 			32
#define	SSH2_MSG_KEXGSS_HOSTKEY				33
#define	SSH2_MSG_KEXGSS_ERROR				34
#define	SSH2_MSG_USERAUTH_GSSAPI_RESPONSE		60
#define	SSH2_MSG_USERAUTH_GSSAPI_TOKEN			61
#define	SSH2_MSG_USERAUTH_GSSAPI_EXCHANGE_COMPLETE	63
#define	SSH2_MSG_USERAUTH_GSSAPI_ERROR			64
#define	SSH2_MSG_USERAUTH_GSSAPI_ERRTOK			65
#define	SSH2_MSG_USERAUTH_GSSAPI_MIC			66

#define	KEX_GSS_SHA1					"gss-group1-sha1-"
#define	SSH_GSS_HOSTBASED_SERVICE			"host"

#ifndef HAVE_GSS_STORE_CRED
typedef struct ssh_gssapi_cred_store ssh_gssapi_cred_store; /* server-only */
#endif /* !HAVE_GSS_STORE_CRED */

typedef struct {
	OM_uint32		major;
	OM_uint32		minor;
	int			local; /* true on client, false on server */
	int			established;
	OM_uint32		flags;
	gss_ctx_id_t		context;
	gss_OID			desired_mech;	/* client-side only */
	gss_OID			actual_mech;
	gss_name_t		desired_name;   /* targ on both */
	gss_name_t		src_name;
	gss_name_t		dst_name;
	gss_cred_id_t		creds;		/* server-side only */
	gss_cred_id_t		deleg_creds;	/* server-side only */
	int			default_creds;	/* server-side only */
#ifndef HAVE_GSS_STORE_CRED
	ssh_gssapi_cred_store	*cred_store;	/* server-side only */
#endif /* !HAVE_GSS_STORE_CRED */
} Gssctxt;

/* Functions to get supported mech lists */
void ssh_gssapi_server_mechs(gss_OID_set *mechs);
void ssh_gssapi_client_mechs(const char *server_host, gss_OID_set *mechs);

/* Functions to get fix KEX proposals (needed for rekey cases) */
void ssh_gssapi_modify_kex(Kex *kex, gss_OID_set mechs, char **proposal);
void ssh_gssapi_server_kex_hook(Kex *kex, char **proposal);
void ssh_gssapi_client_kex_hook(Kex *kex, char **proposal);

/* Map an encoded mechanism keyex name to a mechanism OID */
void ssh_gssapi_mech_oid_to_kexname(const gss_OID mech, char **kexname);
void ssh_gssapi_mech_oids_to_kexnames(const gss_OID_set mechs,
    char **kexname_list);
/* dup oid? */
void ssh_gssapi_oid_of_kexname(const char *kexname, gss_OID *mech);

/*
 * Unfortunately, the GSS-API is not generic enough for some things --
 * see gss-serv.c and ssh-gss.c
 */
int  ssh_gssapi_is_spnego(gss_OID oid);
int  ssh_gssapi_is_krb5(gss_OID oid);
int  ssh_gssapi_is_gsi(gss_OID oid);
int  ssh_gssapi_is_dh(gss_OID oid);

/* GSS_Init/Accept_sec_context() and GSS_Acquire_cred() wrappers */
/* client-only */
OM_uint32 ssh_gssapi_init_ctx(Gssctxt *ctx, const char *server_host,
    int deleg_creds, gss_buffer_t recv_tok, gss_buffer_t send_tok);
/* server-only */
OM_uint32 ssh_gssapi_accept_ctx(Gssctxt *ctx, gss_buffer_t recv_tok,
    gss_buffer_t send_tok);
/* server-only */
OM_uint32 ssh_gssapi_acquire_cred(Gssctxt *ctx);

/* MIC wrappers */
OM_uint32 ssh_gssapi_get_mic(Gssctxt *ctx, gss_buffer_t buffer,
				gss_buffer_t hash);
OM_uint32 ssh_gssapi_verify_mic(Gssctxt *ctx, gss_buffer_t buffer,
				gss_buffer_t hash);

/* Gssctxt functions */
void	 ssh_gssapi_build_ctx(Gssctxt **ctx, int client, gss_OID mech);
void	 ssh_gssapi_delete_ctx(Gssctxt **ctx);
int	 ssh_gssapi_check_mech_oid(Gssctxt *ctx, void *data, size_t len);
void	 ssh_gssapi_error(Gssctxt *ctx, const char *where);
char	*ssh_gssapi_last_error(Gssctxt *ctxt, OM_uint32 *maj, OM_uint32 *min);

/* Server-side */
int	 ssh_gssapi_userok(Gssctxt *ctx, char *name);
char	*ssh_gssapi_localname(Gssctxt *ctx);

/* Server-side, if PAM and gss_store_cred() are available, ... */
struct Authctxt; /* needed to avoid conflicts between auth.h, sshconnect2.c */
void	ssh_gssapi_storecreds(Gssctxt *ctx, struct Authctxt *authctxt);

/* ... else, if other interfaces are available for GSS-API cred storing */
void	ssh_gssapi_do_child(Gssctxt *ctx, char ***envp, uint_t *envsizep);
void	ssh_gssapi_cleanup_creds(Gssctxt *ctx);

/* Misc */
int		 ssh_gssapi_import_name(Gssctxt *ctx, const char *server_host);
const char	*ssh_gssapi_oid_to_name(gss_OID oid);
char		*ssh_gssapi_oid_to_str(gss_OID oid);
gss_OID		 ssh_gssapi_dup_oid(gss_OID oid);
gss_OID		 ssh_gssapi_make_oid(size_t length, void *elements);
gss_OID		 ssh_gssapi_make_oid_ext(size_t length, void *elements,
		    int der_wrapped);
void		*ssh_gssapi_der_wrap(size_t, size_t *length);
size_t		 ssh_gssapi_der_wrap_size(size_t, size_t *length);
void		 ssh_gssapi_release_oid(gss_OID *oid);
#endif /* GSSAPI */

#endif /* _SSH_GSS_H */
