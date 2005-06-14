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
 *	dh_gssapi.h
 *
 *	Copyright (c) 1997, by Sun Microsystems, Inc.
 *	All rights reserved.
 *
 */

#ifndef _DH_GSSAPI_H_
#define	_DH_GSSAPI_H_

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <gssapi/gssapi.h>
#include <mechglueP.h>
#include <rpc/rpc.h>
#include <time.h>
#include <thread.h>
#include <synch.h>
#include "error.h"
#include "token.h"
#include "oid.h"
#include "crypto.h"

#define	New(T, n) ((T *)calloc(n, sizeof (T)))
#define	Free(p) free(p)

#define	DH_NO_SECRETKEY 1
#define	DH_NO_NETNAME 2
#define	DH_VALIDATE_FAILURE 3

#define	DH_MECH_QOP 0

/*
 * This structure defines the necessary operations that a mechanism
 * must provide for key management.
 */
typedef struct keyopts_desc {
	/*
	 * This function pointer will encrypt the set of supplied session keys
	 * with this principal and a remote principal. For algorithm 0
	 * A common key is used, that is calculated using the classic
	 * Diffie-Hellman key exchange. An RSA style algorithm would encrypt
	 * the session key with the public key of the remote.
	 */
	int (*key_encryptsessions)(const char *remotename,
	    des_block deskeys[], int no_keys);
	/*
	 * This function decrypts the set of session keys from remote. It
	 * is the inverse of the above entry point. The last parameter
	 * is an in/out parameter. If it is non-zero going in, it allows
	 * the underlying mechanism to get the public key for the remote
	 * out of a cache. If it is zero, it indicates that the mechanism
	 * should get a definitive copy of the public key because it may
	 * have changed. When returning from the entry point *key_cached
	 * will be set to non zero if the session keys were decrypted using
	 * a cached public key, otherwise zero will be return. Most mechanism
	 * will not need/want this and will always return *key_cached as zero.
	 */
	int (*key_decryptsessions)(const char *remotename,
	    des_block deskeys[], int no_keys, int *key_cached);
	/*
	 * This entry point is used to generate a block of session keys
	 */
	int (*key_gendeskeys)(des_block *deskeys, int no_keys);
	/*
	 * This entry point is used to see if the principal's credentials
	 * are available.
	 */
	int (*key_secretkey_is_set)(void);
	/*
	 * This entry point will return the netname of the calling principal.
	 */
	char *(*get_principal)(void);
} dh_keyopts_desc, *dh_keyopts_t;

/*
 * Diffie-Hellman principal names are just null terminated charater strings
 * that are ONC RPC netnames.
 */
typedef char *dh_principal;

/* Diffie-Hellman credentials */
typedef struct dh_cred_id_desc {
	uid_t uid;		/* The uid of this principal */
	gss_cred_usage_t usage; /* How this cred can be used */
	dh_principal  principal;    /* RPC netname */
	time_t expire;		/* When this cred expires */
} dh_cred_id_desc, *dh_cred_id_t;


/*
 * This is the structure that defines the mechanism specific context.
 * This allows a common backend to support a faimily of mechanism that
 * use different key lengths and algorithms. We know the particular mechanism
 * by that mechanism on initialization filling in the OID for that mechanaism
 * and suppling a set of keyopts that correspond to the key length and
 * algorithm used.
 */
typedef struct dh_context_desc {
	gss_OID mech;
	dh_keyopts_t keyopts;
} dh_context_desc, *dh_context_t;


/* This defines the size of the history for replay and out-of-seq detection */
#define	SSIZE 4
typedef unsigned long long seq_word_t;

/*
 * This structure holds the state for replay and detection. It contains the
 * bit array of the last seqence numbers that have been seen and the last
 * sequence number. The 0th bit represents the last sequence number receive.
 * The state contained in this structure in protected by a mutext so that
 * multiple threads can manipulate the history.
 */
typedef struct {
	mutex_t seq_arr_lock;   /* lock on this structure */
	seq_word_t arr[SSIZE];	/* Bit array of sequence history */
	OM_uint32 seqno;	/* Last seqno seen */
} seq_array, *seq_array_t;


typedef enum { INCOMPLETE, ESTABLISHED, BAD } DHState;

/*
 * The Diffie-Hellman context that corresponds to the gss_ctx_id_t.
 */
typedef struct dh_gss_context_desc {
	DHState state;		/* Context state */
	int initiate;		/* 1 intiates, 0 accepts */
	int proto_version;	/* DH protocol version */
	dh_principal remote;	/* Netname of remote */
	dh_principal local;	/* Netname of local */
	int no_keys;		/* Number of session keys (currently 3) */
	des_block *keys;	/* The session keys */
	OM_uint32 flags;	/* GSS context flags */
	seq_array hist;		/* Out-of-sequence, replay history */
	mutex_t seqno_lock;	/* Lock to protect next_seqno */
	OM_uint32 next_seqno;	/* Next seqno to send */
	time_t expire;		/* When this context expires */
	int debug;		/* Turn on debuging if non zero */
} dh_gss_context_desc, *dh_gss_context_t;


/* declarations of internal name mechanism functions */

gss_mechanism
__dh_generic_initialize(gss_mechanism, gss_OID_desc, dh_keyopts_t);

/*
 * The following routines are the entry points that libgss uses.
 * The have the same signature as the corresponding libgss functions
 * except they are passed an additinal first parameter that is a pointer
 * to the mechanaism specific context. In our case that void pointer is
 * actually pointing to a dh_context. See <gssapi/gssapi.h> or the
 * draft-ietf_cat_gssv2-cbind document for an explanation of the parameters.
 */
OM_uint32
__dh_gss_acquire_cred(void *, OM_uint32*, gss_name_t, OM_uint32, gss_OID_set,
    gss_cred_usage_t, gss_cred_id_t *, gss_OID_set *, OM_uint32 *);

OM_uint32
__dh_gss_release_cred(void *, OM_uint32 *, gss_cred_id_t *);

OM_uint32
__dh_gss_init_sec_context(void *, OM_uint32 *, gss_cred_id_t, gss_ctx_id_t *,
    gss_name_t, gss_OID, OM_uint32, OM_uint32, gss_channel_bindings_t,
    gss_buffer_t, gss_OID *, gss_buffer_t, OM_uint32 *, OM_uint32 *);

OM_uint32
__dh_gss_accept_sec_context(void *, OM_uint32 *, gss_ctx_id_t *, gss_cred_id_t,
    gss_buffer_t, gss_channel_bindings_t, gss_name_t *, gss_OID *,
    gss_buffer_t, OM_uint32 *, OM_uint32 *, gss_cred_id_t *);

OM_uint32
__dh_gss_process_context_token(void *, OM_uint32 *,
    gss_ctx_id_t, gss_buffer_t);

OM_uint32
__dh_gss_delete_sec_context(void *, OM_uint32 *, gss_ctx_id_t *, gss_buffer_t);

OM_uint32
__dh_gss_context_time(void *, OM_uint32 *, gss_ctx_id_t, OM_uint32 *);

OM_uint32
__dh_gss_sign(void *, OM_uint32 *, gss_ctx_id_t,
    int, gss_buffer_t, gss_buffer_t);

OM_uint32
__dh_gss_verify(void *, OM_uint32 *, gss_ctx_id_t,
    gss_buffer_t, gss_buffer_t, int *);

OM_uint32
__dh_gss_seal(void *, OM_uint32 *, gss_ctx_id_t,
    int, int, gss_buffer_t, int *, gss_buffer_t);

OM_uint32
__dh_gss_unseal(void *, OM_uint32 *, gss_ctx_id_t,
    gss_buffer_t, gss_buffer_t, int *, int *);

OM_uint32
__dh_gss_display_status(void *, OM_uint32 *, OM_uint32,
    int, gss_OID, OM_uint32 *, gss_buffer_t);

OM_uint32
__dh_gss_indicate_mechs(void *, OM_uint32 *, gss_OID_set *);

OM_uint32
__dh_gss_compare_name(void *, OM_uint32 *, gss_name_t, gss_name_t, int *);

OM_uint32
__dh_gss_display_name(void *, OM_uint32 *,
    gss_name_t, gss_buffer_t, gss_OID *);

OM_uint32
__dh_gss_import_name(void *, OM_uint32 *, gss_buffer_t, gss_OID, gss_name_t *);

OM_uint32
__dh_gss_release_name(void *, OM_uint32 *, gss_name_t *);

OM_uint32
__dh_gss_inquire_cred(void *, OM_uint32 *, gss_cred_id_t, gss_name_t *,
    OM_uint32 *, gss_cred_usage_t *, gss_OID_set *);

OM_uint32
__dh_gss_inquire_context(void *, OM_uint32 *, gss_ctx_id_t, gss_name_t *,
    gss_name_t *, OM_uint32 *, gss_OID *, OM_uint32 *, int *, int *);

/* New V2 entry points */
OM_uint32
__dh_gss_get_mic(void *, OM_uint32 *, gss_ctx_id_t,
    gss_qop_t, gss_buffer_t, gss_buffer_t);

OM_uint32
__dh_gss_verify_mic(void *, OM_uint32 *, gss_ctx_id_t, gss_buffer_t,
    gss_buffer_t, gss_qop_t *);

OM_uint32
__dh_gss_wrap(void *, OM_uint32 *, gss_ctx_id_t, int, gss_qop_t,
    gss_buffer_t, int *, gss_buffer_t);

OM_uint32
__dh_gss_unwrap(void *, OM_uint32 *, gss_ctx_id_t, gss_buffer_t,
    gss_buffer_t, int *, gss_qop_t *);

OM_uint32
__dh_gss_wrap_size_limit(void *, OM_uint32 *, gss_ctx_id_t, int,
    gss_qop_t, OM_uint32, OM_uint32 *);

OM_uint32
__dh_gss_import_name_object(void *, OM_uint32 *,
    void *, gss_OID, gss_name_t *);

OM_uint32
__dh_gss_export_name_object(void *, OM_uint32 *, gss_name_t, gss_OID, void **);

OM_uint32
__dh_gss_add_cred(void *, OM_uint32 *, gss_cred_id_t, gss_name_t, gss_OID,
    gss_cred_usage_t, OM_uint32, OM_uint32, gss_cred_id_t *, gss_OID_set *,
    OM_uint32 *, OM_uint32 *);

OM_uint32
__dh_gss_inquire_cred_by_mech(void *, OM_uint32  *, gss_cred_id_t, gss_OID,
    gss_name_t *, OM_uint32 *, OM_uint32 *, gss_cred_usage_t *);

OM_uint32
__dh_gss_export_sec_context(void *, OM_uint32 *, gss_ctx_id_t *, gss_buffer_t);

OM_uint32
__dh_gss_import_sec_context(void *, OM_uint32 *, gss_buffer_t, gss_ctx_id_t *);

OM_uint32
__dh_gss_internal_release_oid(void *, OM_uint32 *, gss_OID *);

OM_uint32
__dh_gss_inquire_names_for_mech(void *, OM_uint32 *, gss_OID, gss_OID_set *);

/* Principal to uid mapping */
OM_uint32
__dh_pname_to_uid(void *ctx, OM_uint32 *minor,
    const gss_name_t pname, uid_t *uid);

OM_uint32
__dh_gss_export_name(void *ctx, OM_uint32 *minor,
    const gss_name_t input_name, gss_buffer_t exported_name);

/* ====================== End of libgss entry points ======================= */

/* Routines to validate, install and remove contexts and credentials */
OM_uint32
__dh_validate_context(dh_gss_context_t);

OM_uint32
__dh_install_context(dh_gss_context_t);

OM_uint32
__dh_remove_context(dh_gss_context_t);

OM_uint32
__dh_validate_cred(dh_cred_id_t);

OM_uint32
__dh_install_cred(dh_cred_id_t);

OM_uint32
__dh_remove_cred(dh_cred_id_t);

OM_uint32
__dh_validate_principal(dh_principal);

/* Routines for out-of-sequence and replay detection */
OM_uint32 __dh_seq_detection(dh_gss_context_t, OM_uint32);

OM_uint32 __dh_next_seqno(dh_gss_context_t ctx);

void __dh_init_seq_hist(dh_gss_context_t);

void __dh_destroy_seq_hist(dh_gss_context_t ctx);

#ifdef __cplusplus
}
#endif

#endif /* _DH_GSSAPI_H_ */
