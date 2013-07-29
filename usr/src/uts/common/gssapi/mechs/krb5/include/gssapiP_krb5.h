/*
 * Copyright (c) 1999, 2010, Oracle and/or its affiliates. All rights reserved.
 */
/*
 * Copyright 2000 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * Export of this software from the United States of America may
 *   require a specific license from the United States Government.
 *   It is the responsibility of any person or organization contemplating
 *   export to obtain such a license before exporting.
 * 
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of M.I.T. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original M.I.T. software.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 * 
 */
/*
 * Copyright 1993 by OpenVision Technologies, Inc.
 * 
 * Permission to use, copy, modify, distribute, and sell this software
 * and its documentation for any purpose is hereby granted without fee,
 * provided that the above copyright notice appears in all copies and
 * that both that copyright notice and this permission notice appear in
 * supporting documentation, and that the name of OpenVision not be used
 * in advertising or publicity pertaining to distribution of the software
 * without specific, written prior permission. OpenVision makes no
 * representations about the suitability of this software for any
 * purpose.  It is provided "as is" without express or implied warranty.
 * 
 * OPENVISION DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE,
 * INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS, IN NO
 * EVENT SHALL OPENVISION BE LIABLE FOR ANY SPECIAL, INDIRECT OR
 * CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF
 * USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
 * OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 */

#ifndef _GSSAPIP_KRB5_H_
#define _GSSAPIP_KRB5_H_

#include <k5-int.h>

#ifdef HAVE_MEMORY_H
#include <memory.h>
#endif

/* work around sunos braindamage */
#ifdef major
#undef major
#endif
#ifdef minor
#undef minor
#endif

#include "gssapiP_generic.h"

/* The include of gssapi_krb5.h will dtrt with the above #defines in
 * effect.
 */
#include "gssapi_krb5.h"
#include "gssapi_err_krb5.h"
#include "gssapi_ext.h"

/* for debugging */
#undef CFX_EXERCISE

/** constants **/

#define GSS_MECH_KRB5_OID_LENGTH 9
#define GSS_MECH_KRB5_OID "\052\206\110\206\367\022\001\002\002"

#define GSS_MECH_KRB5_OLD_OID_LENGTH 5
#define GSS_MECH_KRB5_OLD_OID "\053\005\001\005\002"

/* Incorrect krb5 mech OID emitted by MS. */
#define GSS_MECH_KRB5_WRONG_OID_LENGTH 9
#define GSS_MECH_KRB5_WRONG_OID "\052\206\110\202\367\022\001\002\002"


#define CKSUMTYPE_KG_CB		0x8003

#define KG_TOK_CTX_AP_REQ	0x0100
#define KG_TOK_CTX_AP_REP	0x0200
#define KG_TOK_CTX_ERROR	0x0300
#define KG_TOK_SIGN_MSG		0x0101
#define KG_TOK_SEAL_MSG		0x0201
#define	KG_TOK_MIC_MSG		0x0101
#define	KG_TOK_WRAP_MSG		0x0201
#define KG_TOK_DEL_CTX		0x0102

#define KG2_TOK_INITIAL		0x0101
#define KG2_TOK_RESPONSE	0x0202
#define KG2_TOK_MIC		0x0303
#define KG2_TOK_WRAP_INTEG	0x0404
#define KG2_TOK_WRAP_PRIV	0x0505

#define KRB5_GSS_FOR_CREDS_OPTION 1

#define KG2_RESP_FLAG_ERROR		0x0001
#define KG2_RESP_FLAG_DELEG_OK		0x0002

/* These are to be stored in little-endian order, i.e., des-mac is
   stored as 02 00.  */
enum sgn_alg {
  SGN_ALG_DES_MAC_MD5           = 0x0000,
  SGN_ALG_MD2_5                 = 0x0001,
  SGN_ALG_DES_MAC               = 0x0002,
  SGN_ALG_3			= 0x0003, /* not published */
  SGN_ALG_HMAC_MD5              = 0x0011, /* microsoft w2k;  */
  SGN_ALG_HMAC_SHA1_DES3_KD     = 0x0004
};
enum seal_alg {
  SEAL_ALG_NONE            = 0xffff,
  SEAL_ALG_DES             = 0x0000,
  SEAL_ALG_1		   = 0x0001, /* not published */
  SEAL_ALG_MICROSOFT_RC4   = 0x0010, /* microsoft w2k;  */
  SEAL_ALG_DES3KD          = 0x0002
};

/* for 3DES */
#define KG_USAGE_SEAL 22
#define KG_USAGE_SIGN 23
#define KG_USAGE_SEQ  24

/* for draft-ietf-krb-wg-gssapi-cfx-01 */
#define KG_USAGE_ACCEPTOR_SEAL	22
#define KG_USAGE_ACCEPTOR_SIGN	23
#define KG_USAGE_INITIATOR_SEAL	24
#define KG_USAGE_INITIATOR_SIGN	25

enum qop {
  GSS_KRB5_INTEG_C_QOP_MD5       = 0x0001, /* *partial* MD5 = "MD2.5" */
  GSS_KRB5_INTEG_C_QOP_DES_MD5   = 0x0002,
  GSS_KRB5_INTEG_C_QOP_DES_MAC   = 0x0003,
  GSS_KRB5_INTEG_C_QOP_HMAC_SHA1 = 0x0004,
  GSS_KRB5_INTEG_C_QOP_MASK      = 0x00ff,
  GSS_KRB5_CONF_C_QOP_DES        = 0x0100,
  GSS_KRB5_CONF_C_QOP_DES3_KD    = 0x0200,
  GSS_KRB5_CONF_C_QOP_MASK       = 0xff00
};

/** internal types **/

typedef krb5_principal krb5_gss_name_t;

typedef struct _krb5_gss_cred_id_rec {
   /* protect against simultaneous accesses */
   k5_mutex_t lock;

   /* name/type of credential */
   gss_cred_usage_t usage;
   krb5_principal princ;	/* this is not interned as a gss_name_t */
   int prerfc_mech;
   int rfc_mech;

   /* keytab (accept) data */
   krb5_keytab keytab;
   krb5_rcache rcache;

   /* ccache (init) data */
   krb5_ccache ccache;
   krb5_timestamp tgt_expire;
   krb5_enctype *req_enctypes;	/* limit negotiated enctypes to this list */
} krb5_gss_cred_id_rec, *krb5_gss_cred_id_t; 

typedef struct _krb5_gss_ctx_id_rec {
   unsigned int initiate : 1;	/* nonzero if initiating, zero if accepting */
   unsigned int established : 1;
   unsigned int big_endian : 1;
   unsigned int have_acceptor_subkey : 1;
   unsigned int seed_init : 1;	/* XXX tested but never actually set */
   OM_uint32 gss_flags;
   unsigned char seed[16];
   krb5_principal here;
   krb5_principal there;
   krb5_keyblock *subkey;
   int signalg;
   size_t cksum_size;
   int sealalg;
   krb5_keyblock *enc;
   krb5_keyblock *seq;
   krb5_timestamp endtime;
   krb5_ticket_times krb_times;
   krb5_flags krb_flags;
   /* XXX these used to be signed.  the old spec is inspecific, and
      the new spec specifies unsigned.  I don't believe that the change
      affects the wire encoding. */
   gssint_uint64 seq_send;
   gssint_uint64 seq_recv;
   void *seqstate;
   krb5_context k5_context;
   krb5_auth_context auth_context;
   gss_OID_desc *mech_used;
    /* Protocol spec revision
       0 => RFC 1964 with 3DES and RC4 enhancements
       1 => draft-ietf-krb-wg-gssapi-cfx-01
       No others defined so far.  */
   int proto;
   krb5_cksumtype cksumtype;	/* for "main" subkey */
   krb5_keyblock *acceptor_subkey; /* CFX only */
   krb5_cksumtype acceptor_subkey_cksumtype;
   int cred_rcache;		/* did we get rcache from creds? */
   krb5_authdata **authdata;
} krb5_gss_ctx_id_rec, *krb5_gss_ctx_id_t;

extern g_set kg_vdb;

extern k5_mutex_t gssint_krb5_keytab_lock;

/* helper macros */

#define kg_save_name(name)		g_save_name(&kg_vdb,name)
#define kg_save_cred_id(cred)		g_save_cred_id(&kg_vdb,cred)
#define kg_save_ctx_id(ctx)		g_save_ctx_id(&kg_vdb,ctx)
#define kg_save_lucidctx_id(lctx)	g_save_lucidctx_id(&kg_vdb,lctx)

#define kg_validate_name(name)		g_validate_name(&kg_vdb,name)
#define kg_validate_cred_id(cred)	g_validate_cred_id(&kg_vdb,cred)
#define kg_validate_ctx_id(ctx)		g_validate_ctx_id(&kg_vdb,ctx)
#define kg_validate_lucidctx_id(lctx)	g_validate_lucidctx_id(&kg_vdb,lctx)

#define kg_delete_name(name)		g_delete_name(&kg_vdb,name)
#define kg_delete_cred_id(cred)		g_delete_cred_id(&kg_vdb,cred)
#define kg_delete_ctx_id(ctx)		g_delete_ctx_id(&kg_vdb,ctx)
#define kg_delete_lucidctx_id(lctx)	g_delete_lucidctx_id(&kg_vdb,lctx)

/** helper functions **/

OM_uint32 kg_get_defcred 
	(OM_uint32 *minor_status, 
		   gss_cred_id_t *cred);

krb5_error_code kg_checksum_channel_bindings
         (krb5_context context, gss_channel_bindings_t cb,
					     krb5_checksum *cksum,
					     int bigend);

krb5_error_code kg_make_seq_num (krb5_context context,
					   krb5_keyblock *key,
            int direction, krb5_ui_4 seqnum, unsigned char *cksum,
				unsigned char *buf);

krb5_error_code kg_get_seq_num (krb5_context context,
					  krb5_keyblock *key,
            unsigned char *cksum, unsigned char *buf, int *direction,
					  krb5_ui_4 *seqnum);

krb5_error_code kg_make_seed (krb5_context context,
					krb5_keyblock *key,
					unsigned char *seed);

int kg_confounder_size (krb5_context context, krb5_keyblock *key);

krb5_error_code kg_make_confounder (krb5_context context, 
	    krb5_keyblock *key, unsigned char *buf);

krb5_error_code kg_encrypt (krb5_context context, 
				      krb5_keyblock *key, int usage,
				      krb5_pointer iv,
				      krb5_const_pointer in,
				      krb5_pointer out,
				      unsigned int length);
krb5_error_code
kg_arcfour_docrypt (krb5_context,
		    const krb5_keyblock *longterm_key , int ms_usage,
		    const unsigned char *kd_data, size_t kd_data_len,
		    const unsigned char *input_buf, size_t input_len,
		    unsigned char *output_buf);

krb5_error_code kg_decrypt (krb5_context context,
				      krb5_keyblock *key,  int usage,
				      krb5_pointer iv,
				      krb5_const_pointer in,
				      krb5_pointer out,
				      unsigned int length);

OM_uint32 kg_seal (OM_uint32 *minor_status,
		  gss_ctx_id_t context_handle,
		  int conf_req_flag,
		  int qop_req,
		  gss_buffer_t input_message_buffer,
		  int *conf_state,
		  gss_buffer_t output_message_buffer,
		  int toktype);

OM_uint32 kg_unseal (OM_uint32 *minor_status,
		    gss_ctx_id_t context_handle,
		    gss_buffer_t input_token_buffer,
		    gss_buffer_t message_buffer,
		    int *conf_state,
		    int *qop_state,
		    int toktype);

OM_uint32 kg_seal_size (OM_uint32 *minor_status,
				  gss_ctx_id_t context_handle,
				  int conf_req_flag,
				  gss_qop_t qop_req,
				  OM_uint32 output_size,
				  OM_uint32 *input_size);

krb5_error_code kg_ctx_size (krb5_context kcontext,
				       krb5_pointer arg,
				       size_t *sizep);

krb5_error_code kg_ctx_externalize (krb5_context kcontext,
					      krb5_pointer arg,
					      krb5_octet **buffer,
					      size_t *lenremain);

krb5_error_code kg_ctx_internalize (krb5_context kcontext,
					      krb5_pointer *argp,
					      krb5_octet **buffer,
					      size_t *lenremain);

OM_uint32 kg_sync_ccache_name (krb5_context context, OM_uint32 *minor_status);

OM_uint32 kg_caller_provided_ccache_name (OM_uint32 *minor_status, 
                                          int *out_caller_provided_name);

OM_uint32 kg_get_ccache_name (OM_uint32 *minor_status, 
                              const char **out_name);

OM_uint32 kg_set_ccache_name (OM_uint32 *minor_status, 
                              const char *name);

/** declarations of internal name mechanism functions **/

OM_uint32 krb5_gss_acquire_cred
(OM_uint32*,       /* minor_status */
            gss_name_t,       /* desired_name */
            OM_uint32,        /* time_req */
            gss_OID_set,      /* desired_mechs */
            gss_cred_usage_t, /* cred_usage */
            gss_cred_id_t*,   /* output_cred_handle */
            gss_OID_set*,     /* actual_mechs */
            OM_uint32*        /* time_rec */
           );

OM_uint32 krb5_gss_release_cred
(OM_uint32*,       /* minor_status */
            gss_cred_id_t*    /* cred_handle */
           );

OM_uint32 krb5_gss_init_sec_context
(OM_uint32*,       /* minor_status */
            gss_cred_id_t,    /* claimant_cred_handle */
            gss_ctx_id_t*,    /* context_handle */
            gss_name_t,       /* target_name */
            gss_OID,          /* mech_type */
            OM_uint32,        /* req_flags */
            OM_uint32,        /* time_req */
            gss_channel_bindings_t,
                              /* input_chan_bindings */
            gss_buffer_t,     /* input_token */
            gss_OID*,         /* actual_mech_type */
            gss_buffer_t,     /* output_token */
            OM_uint32*,       /* ret_flags */
            OM_uint32*        /* time_rec */
           );

OM_uint32 krb5_gss_accept_sec_context
(OM_uint32*,       /* minor_status */
            gss_ctx_id_t*,    /* context_handle */
            gss_cred_id_t,    /* verifier_cred_handle */
            gss_buffer_t,     /* input_token_buffer */
            gss_channel_bindings_t,
                              /* input_chan_bindings */
            gss_name_t*,      /* src_name */
            gss_OID*,         /* mech_type */
            gss_buffer_t,     /* output_token */
            OM_uint32*,       /* ret_flags */
            OM_uint32*,       /* time_rec */
            gss_cred_id_t*    /* delegated_cred_handle */
           );

OM_uint32 krb5_gss_process_context_token
(OM_uint32*,       /* minor_status */
            gss_ctx_id_t,     /* context_handle */
            gss_buffer_t      /* token_buffer */
           );

OM_uint32 krb5_gss_delete_sec_context
(OM_uint32*,       /* minor_status */
            gss_ctx_id_t*,    /* context_handle */
            gss_buffer_t      /* output_token */
#ifdef	_KERNEL
            /* */, OM_uint32	/* context verifier */
#endif
           );

OM_uint32 krb5_gss_context_time
(OM_uint32*,       /* minor_status */
            gss_ctx_id_t,     /* context_handle */
            OM_uint32*        /* time_rec */
           );

OM_uint32 krb5_gss_sign
(OM_uint32*,       /* minor_status */
            gss_ctx_id_t,     /* context_handle */
            int,              /* qop_req */
            gss_buffer_t,     /* message_buffer */
            gss_buffer_t      /* message_token */
#ifdef	_KERNEL
            /* */, OM_uint32	/* context verifier */
#endif
           );

OM_uint32 krb5_gss_verify
(OM_uint32*,       /* minor_status */
            gss_ctx_id_t,     /* context_handle */
            gss_buffer_t,     /* message_buffer */
            gss_buffer_t,     /* token_buffer */
            int*              /* qop_state */
#ifdef	_KERNEL
            /* */, OM_uint32	/* context verifier */
#endif
           );

OM_uint32 krb5_gss_seal
(OM_uint32*,       /* minor_status */
            gss_ctx_id_t,     /* context_handle */
            int,              /* conf_req_flag */
            int,              /* qop_req */
            gss_buffer_t,     /* input_message_buffer */
            int*,             /* conf_state */
            gss_buffer_t      /* output_message_buffer */
#ifdef	_KERNEL
            /* */, OM_uint32	/* context verifier */
#endif
           );

OM_uint32 krb5_gss_unseal
(OM_uint32*,       /* minor_status */
            gss_ctx_id_t,     /* context_handle */
            gss_buffer_t,     /* input_message_buffer */
            gss_buffer_t,     /* output_message_buffer */
            int*,             /* conf_state */
            int*              /* qop_state */
#ifdef	_KERNEL
            /* */, OM_uint32	/* context verifier */
#endif
           );

OM_uint32 krb5_gss_display_status
(OM_uint32*,       /* minor_status */
            OM_uint32,        /* status_value */
            int,              /* status_type */
            gss_OID,          /* mech_type */
            OM_uint32*,       /* message_context */
            gss_buffer_t      /* status_string */
           );

OM_uint32 krb5_gss_indicate_mechs
(OM_uint32*,       /* minor_status */
            gss_OID_set*      /* mech_set */
           );

OM_uint32 krb5_gss_compare_name
(OM_uint32*,       /* minor_status */
            gss_name_t,       /* name1 */
            gss_name_t,       /* name2 */
            int*              /* name_equal */
           );

OM_uint32 krb5_gss_display_name
(OM_uint32*,      /* minor_status */
            gss_name_t,      /* input_name */
            gss_buffer_t,    /* output_name_buffer */
            gss_OID*         /* output_name_type */
           );

OM_uint32 krb5_gss_import_name
(OM_uint32*,       /* minor_status */
            gss_buffer_t,     /* input_name_buffer */
            gss_OID,          /* input_name_type */
            gss_name_t*       /* output_name */
           );

OM_uint32 krb5_gss_release_name
(OM_uint32*,       /* minor_status */
            gss_name_t*       /* input_name */
           );

OM_uint32 krb5_gss_inquire_cred
(OM_uint32 *,      /* minor_status */
            gss_cred_id_t,    /* cred_handle */
            gss_name_t *,     /* name */
            OM_uint32 *,      /* lifetime */
            gss_cred_usage_t*,/* cred_usage */
            gss_OID_set *     /* mechanisms */
           );

OM_uint32 krb5_gss_inquire_context
(OM_uint32*,       /* minor_status */
	    gss_ctx_id_t,     /* context_handle */
	    gss_name_t*,      /* initiator_name */
	    gss_name_t*,      /* acceptor_name */
	    OM_uint32*,       /* lifetime_rec */
	    gss_OID*,         /* mech_type */
	    OM_uint32*,       /* ret_flags */
	    int*,             /* locally_initiated */
	    int*              /* open */
	   );

/* New V2 entry points */
OM_uint32 krb5_gss_get_mic
(OM_uint32 *,		/* minor_status */
	    gss_ctx_id_t,		/* context_handle */
	    gss_qop_t,			/* qop_req */
	    gss_buffer_t,		/* message_buffer */
	    gss_buffer_t		/* message_token */
	   );

OM_uint32 krb5_gss_verify_mic
(OM_uint32 *,		/* minor_status */
	    gss_ctx_id_t,		/* context_handle */
	    gss_buffer_t,		/* message_buffer */
	    gss_buffer_t,		/* message_token */
	    gss_qop_t *			/* qop_state */
	   );

OM_uint32 krb5_gss_wrap
(OM_uint32 *,		/* minor_status */
	    gss_ctx_id_t,		/* context_handle */
	    int,			/* conf_req_flag */
	    gss_qop_t,			/* qop_req */
	    gss_buffer_t,		/* input_message_buffer */
	    int *,			/* conf_state */
	    gss_buffer_t		/* output_message_buffer */
	   );

OM_uint32 krb5_gss_unwrap
(OM_uint32 *,		/* minor_status */
	    gss_ctx_id_t,		/* context_handle */
	    gss_buffer_t,		/* input_message_buffer */
	    gss_buffer_t,		/* output_message_buffer */
	    int *,			/* conf_state */
	    gss_qop_t *			/* qop_state */
	   );

OM_uint32 krb5_gss_wrap_size_limit
(OM_uint32 *,		/* minor_status */
	    gss_ctx_id_t,		/* context_handle */
	    int,			/* conf_req_flag */
	    gss_qop_t,			/* qop_req */
	    OM_uint32,			/* req_output_size */
	    OM_uint32 *			/* max_input_size */
	   );

OM_uint32 krb5_gss_import_name_object
(OM_uint32 *,		/* minor_status */
	    void *,			/* input_name */
	    gss_OID,			/* input_name_type */
	    gss_name_t *		/* output_name */
	   );

OM_uint32 krb5_gss_export_name_object
(OM_uint32 *,		/* minor_status */
	    gss_name_t,			/* input_name */
	    gss_OID,			/* desired_name_type */
	    void * *			/* output_name */
	   );

OM_uint32 krb5_gss_add_cred
(OM_uint32 *,		/* minor_status */
	    gss_cred_id_t,		/* input_cred_handle */
	    gss_name_t,			/* desired_name */
	    gss_OID,			/* desired_mech */
	    gss_cred_usage_t,		/* cred_usage */
	    OM_uint32,			/* initiator_time_req */
	    OM_uint32,			/* acceptor_time_req */
	    gss_cred_id_t *,		/* output_cred_handle */
	    gss_OID_set *,		/* actual_mechs */
	    OM_uint32 *,		/* initiator_time_rec */
	    OM_uint32 *			/* acceptor_time_rec */
	   );

OM_uint32 krb5_gss_inquire_cred_by_mech
(OM_uint32  *,		/* minor_status */
	    gss_cred_id_t,		/* cred_handle */
	    gss_OID,			/* mech_type */
	    gss_name_t *,		/* name */
	    OM_uint32 *,		/* initiator_lifetime */
	    OM_uint32 *,		/* acceptor_lifetime */
	    gss_cred_usage_t * 		/* cred_usage */
	   );

OM_uint32 krb5_gss_export_sec_context
(OM_uint32 *,		/* minor_status */
	    gss_ctx_id_t *,		/* context_handle */
	    gss_buffer_t		/* interprocess_token */
	    );

OM_uint32 krb5_gss_import_sec_context
(OM_uint32 *,		/* minor_status */
	    gss_buffer_t,		/* interprocess_token */
	    gss_ctx_id_t *		/* context_handle */
            /* Note no _KERNEL context verifier */
	    );

krb5_error_code krb5_gss_ser_init(krb5_context);

OM_uint32 krb5_gss_release_oid
(OM_uint32 *,		/* minor_status */
	    gss_OID *			/* oid */
	   );

OM_uint32 krb5_gss_internal_release_oid
(OM_uint32 *,		/* minor_status */
	    gss_OID *			/* oid */
	   );

OM_uint32 krb5_gss_inquire_names_for_mech
(OM_uint32 *,		/* minor_status */
	    gss_OID,			/* mechanism */
	    gss_OID_set *		/* name_types */
	   );

/* SUNW15resync - XXX nullify? */
OM_uint32 krb5_gss_canonicalize_name
(OM_uint32  *,		/* minor_status */
	    const gss_name_t,		/* input_name */
	    const gss_OID,		/* mech_type */
	    gss_name_t *		/* output_name */
	 );
	
OM_uint32 krb5_gss_export_name
(OM_uint32  *,		/* minor_status */
	    const gss_name_t,		/* input_name */
	    gss_buffer_t		/* exported_name */
	 );

OM_uint32 krb5_gss_duplicate_name
(OM_uint32  *,		/* minor_status */
	    const gss_name_t,		/* input_name */
	    gss_name_t *		/* dest_name */
	 );

OM_uint32 krb5_gss_validate_cred
(OM_uint32 *,		/* minor_status */
	    gss_cred_id_t		/* cred */
         );

OM_uint32
krb5_gss_validate_cred_1(OM_uint32 * /* minor_status */,
			 gss_cred_id_t /* cred_handle */,
			 krb5_context /* context */);

gss_OID krb5_gss_convert_static_mech_oid(gss_OID oid);
	
krb5_error_code gss_krb5int_make_seal_token_v3(krb5_context,
					       krb5_gss_ctx_id_rec *,
					       const gss_buffer_desc *,
					       gss_buffer_t,
					       int, int);

OM_uint32 gss_krb5int_unseal_token_v3(krb5_context *contextptr,
				      OM_uint32 *minor_status,
				      krb5_gss_ctx_id_rec *ctx,
				      unsigned char *ptr, int bodysize,
				      gss_buffer_t message_buffer,
				      int *conf_state, int *qop_state, 
				      int toktype);

/*
 * SUNW15resync
 * Solaris specific interfaces start
 */

OM_uint32 krb5_gss_store_cred (
	    OM_uint32 *,            /* minor_status */
	    const gss_cred_id_t,    /* input_cred */
	    gss_cred_usage_t,       /* cred_usage */
	    const gss_OID,          /* desired_mech */
	    OM_uint32,              /* overwrite_cred */
	    OM_uint32,              /* default_cred */
	    gss_OID_set *,          /* elements_stored */
	    gss_cred_usage_t *      /* cred_usage_stored */
	   );

OM_uint32 krb5_pname_to_uid(
		OM_uint32 *,		/* minor status */
		const gss_name_t,	/* pname */
		uid_t *			/* uidOUt */
		);

OM_uint32 krb5_gss_userok(
	OM_uint32 *,		/* minor status */
	const gss_name_t,	/* remote user principal name */
	const char *,		/* local unix user name */
	int *			/* remote user ok to login w/out pw? */
	);


/*
 * SUNW15resync
 * Solaris specific interfaces end
 */


/*
 * These take unglued krb5-mech-specific contexts.
 */

#define GSS_KRB5_GET_TKT_FLAGS_OID_LENGTH 11
#define GSS_KRB5_GET_TKT_FLAGS_OID "\x2a\x86\x48\x86\xf7\x12\x01\x02\x02\x05\x01"

#ifndef _KERNEL
OM_uint32  gss_krb5int_get_tkt_flags
(OM_uint32 *minor_status,
 const gss_ctx_id_t context_handle,
 const gss_OID desired_object,
 gss_buffer_set_t *data_set);


OM_uint32 KRB5_CALLCONV gss_krb5int_copy_ccache
	(OM_uint32 *minor_status,
		   gss_cred_id_t cred_handle,
		   krb5_ccache out_ccache);

#define GSS_KRB5_SET_ALLOWABLE_ENCTYPES_OID_LENGTH 11
#define GSS_KRB5_SET_ALLOWABLE_ENCTYPES_OID "\x2a\x86\x48\x86\xf7\x12\x01\x02\x02\x05\x04"

struct krb5_gss_set_allowable_enctypes_req {
    OM_uint32 num_ktypes;
    krb5_enctype *ktypes;
};

#define GSS_KRB5_INQ_SSPI_SESSION_KEY_OID_LENGTH 11
#define GSS_KRB5_INQ_SSPI_SESSION_KEY_OID "\x2a\x86\x48\x86\xf7\x12\x01\x02\x02\x05\x05"

OM_uint32
gss_krb5int_inq_session_key(OM_uint32 *, const gss_ctx_id_t, const gss_OID, gss_buffer_set_t *);

OM_uint32 KRB5_CALLCONV
gss_krb5int_set_allowable_enctypes(OM_uint32 *minor_status, 
				   gss_cred_id_t cred,
				   OM_uint32 num_ktypes,
				   krb5_enctype *ktypes);

#endif /* _KERNEL */

#if 0
/*
 * SUNW17PACresync
 * These two functions not needed yet, revisit for full 1.7 resync.
 */
OM_uint32 KRB5_CALLCONV
gss_krb5int_set_allowable_enctypes(OM_uint32 *minor_status,
                                   gss_cred_id_t cred,
                                   const gss_OID desired_oid,
                                   const gss_buffer_t value);

OM_uint32 KRB5_CALLCONV
gss_krb5int_export_lucid_sec_context(OM_uint32 *minor_status,
				     gss_ctx_id_t *context_handle,
				     OM_uint32 version,
				     void **kctx);
#endif

#ifndef _KERNEL
#define GSS_KRB5_EXPORT_LUCID_SEC_CONTEXT_OID_LENGTH 11
#define GSS_KRB5_EXPORT_LUCID_SEC_CONTEXT_OID "\x2a\x86\x48\x86\xf7\x12\x01\x02\x02\x05\x06"

OM_uint32
gss_krb5int_export_lucid_sec_context(OM_uint32 *minor_status,
                                     const gss_ctx_id_t context_handle,
                                     const gss_OID desired_object,
                                     gss_buffer_set_t *data_set);

#define GSS_KRB5_FREE_LUCID_SEC_CONTEXT_OID_LENGTH 11
#define GSS_KRB5_FREE_LUCID_SEC_CONTEXT_OID "\x2a\x86\x48\x86\xf7\x12\x01\x02\x02\x05\x07"

OM_uint32
gss_krb5int_free_lucid_sec_context(OM_uint32 *, const gss_OID,
                                   const gss_OID, gss_buffer_t);


extern k5_mutex_t kg_kdc_flag_mutex;
krb5_error_code krb5_gss_init_context (krb5_context *ctxp);


#define GSS_KRB5_INQ_SSPI_SESSION_KEY_OID_LENGTH 11
#define GSS_KRB5_INQ_SSPI_SESSION_KEY_OID "\x2a\x86\x48\x86\xf7\x12\x01\x02\x02\x05\x05"

OM_uint32
gss_krb5int_inq_session_key(OM_uint32 *, const gss_ctx_id_t, const gss_OID, gss_buffer_set_t *);


#define GSS_KRB5_USE_KDC_CONTEXT_OID_LENGTH 11
#define GSS_KRB5_USE_KDC_CONTEXT_OID "\x2a\x86\x48\x86\xf7\x12\x01\x02\x02\x05\x08"

OM_uint32 krb5int_gss_use_kdc_context(OM_uint32 *, const gss_OID,
                                      const gss_OID, gss_buffer_t);

krb5_error_code krb5_gss_use_kdc_context(void);

#define GSS_KRB5_REGISTER_ACCEPTOR_IDENTITY_OID_LENGTH 11
#define GSS_KRB5_REGISTER_ACCEPTOR_IDENTITY_OID "\x2a\x86\x48\x86\xf7\x12\x01\x02\x02\x05\x09"

OM_uint32
gss_krb5int_register_acceptor_identity(OM_uint32 *, const gss_OID, const gss_OID, gss_buffer_t);

#define GSS_KRB5_EXTRACT_AUTHZ_DATA_FROM_SEC_CONTEXT_OID_LENGTH 11
#define GSS_KRB5_EXTRACT_AUTHZ_DATA_FROM_SEC_CONTEXT_OID "\x2a\x86\x48\x86\xf7\x12\x01\x02\x02\x05\x0a"

OM_uint32
gss_krb5int_extract_authz_data_from_sec_context(OM_uint32 *minor_status,
                                                const gss_ctx_id_t context_handle,
                                                const gss_OID desired_object,
                                                gss_buffer_set_t *ad_data);

#define GSS_KRB5_SET_CRED_RCACHE_OID_LENGTH 11
#define GSS_KRB5_SET_CRED_RCACHE_OID "\x2a\x86\x48\x86\xf7\x12\x01\x02\x02\x05\x0b"

OM_uint32
gss_krb5int_set_cred_rcache(OM_uint32 *, gss_cred_id_t, const gss_OID, const gss_buffer_t);

#define GSS_KRB5_EXTRACT_AUTHTIME_FROM_SEC_CONTEXT_OID_LENGTH 11
#define GSS_KRB5_EXTRACT_AUTHTIME_FROM_SEC_CONTEXT_OID "\x2a\x86\x48\x86\xf7\x12\x01\x02\x02\x05\x0c"

OM_uint32
gss_krb5int_extract_authtime_from_sec_context(OM_uint32 *,
                                              const gss_ctx_id_t,
                                              const gss_OID,
                                              gss_buffer_set_t *);
#endif /* _KERNEL */

OM_uint32 gss_krb5int_initialize_library(void);
void gss_krb5int_cleanup_library(void);

/* For error message handling.  */
/* Returns a shared string, not a private copy!  */
extern char *
krb5_gss_get_error_message(OM_uint32 minor_code);
extern void
krb5_gss_save_error_string(OM_uint32 minor_code, char *msg);
extern void
krb5_gss_save_error_message(OM_uint32 minor_code, const char *format, ...)
#if !defined(__cplusplus) && (__GNUC__ > 2)
    __attribute__((__format__(__printf__, 2, 3)))
#endif
    ;
    extern void
    krb5_gss_save_error_info(OM_uint32 minor_code, krb5_context ctx);
#define get_error_message krb5_gss_get_error_message
#define save_error_string krb5_gss_save_error_string
#define save_error_message krb5_gss_save_error_message


/* Solaris Kerberos */
#ifdef _KERNEL
#define save_error_info(m, ctx)
#else
#define save_error_info krb5_gss_save_error_info
#endif

extern void krb5_gss_delete_error_info(void *p);

/* Prefix concatenated with Kerberos encryption type */
#define GSS_KRB5_SESSION_KEY_ENCTYPE_OID_LENGTH 10
#define GSS_KRB5_SESSION_KEY_ENCTYPE_OID  "\x2a\x86\x48\x86\xf7\x12\x01\x02\x02\x04"

#endif /* _GSSAPIP_KRB5_H_ */
