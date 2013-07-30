/*
 * Copyright (c) 1999, 2010, Oracle and/or its affiliates. All rights reserved.
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

/*
 * $Id: krb5_gss_glue.c 18262 2006-06-29 04:38:48Z tlyu $
 */

#include "gssapiP_krb5.h"
#include "mglueP.h"
#include <syslog.h>

/** mechglue wrappers **/

static OM_uint32 k5glue_acquire_cred
(void *, OM_uint32*,       /* minor_status */
            gss_name_t,       /* desired_name */
            OM_uint32,        /* time_req */
            gss_OID_set,      /* desired_mechs */
            gss_cred_usage_t, /* cred_usage */
            gss_cred_id_t*,   /* output_cred_handle */
            gss_OID_set*,     /* actual_mechs */
            OM_uint32*        /* time_rec */
           );

static OM_uint32 k5glue_release_cred
(void *, OM_uint32*,       /* minor_status */
            gss_cred_id_t*    /* cred_handle */
           );

static OM_uint32 k5glue_init_sec_context
(void *, OM_uint32*,       /* minor_status */
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

static OM_uint32 k5glue_accept_sec_context
(void *, OM_uint32*,       /* minor_status */
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

static OM_uint32 k5glue_process_context_token
(void *, OM_uint32*,       /* minor_status */
            gss_ctx_id_t,     /* context_handle */
            gss_buffer_t      /* token_buffer */
           );

static OM_uint32 k5glue_delete_sec_context
(void *, OM_uint32*,       /* minor_status */
            gss_ctx_id_t*,    /* context_handle */
            gss_buffer_t      /* output_token */
           );

static OM_uint32 k5glue_context_time
(void *, OM_uint32*,       /* minor_status */
            gss_ctx_id_t,     /* context_handle */
            OM_uint32*        /* time_rec */
           );

static OM_uint32 k5glue_sign
(void *, OM_uint32*,       /* minor_status */
            gss_ctx_id_t,     /* context_handle */
            int,              /* qop_req */
            gss_buffer_t,     /* message_buffer */
            gss_buffer_t      /* message_token */
           );

static OM_uint32 k5glue_verify
(void *, OM_uint32*,       /* minor_status */
            gss_ctx_id_t,     /* context_handle */
            gss_buffer_t,     /* message_buffer */
            gss_buffer_t,     /* token_buffer */
            int*              /* qop_state */
           );

static OM_uint32 k5glue_seal
(void *, OM_uint32*,       /* minor_status */
            gss_ctx_id_t,     /* context_handle */
            int,              /* conf_req_flag */
            int,              /* qop_req */
            gss_buffer_t,     /* input_message_buffer */
            int*,             /* conf_state */
            gss_buffer_t      /* output_message_buffer */
           );

static OM_uint32 k5glue_unseal
(void *, OM_uint32*,       /* minor_status */
            gss_ctx_id_t,     /* context_handle */
            gss_buffer_t,     /* input_message_buffer */
            gss_buffer_t,     /* output_message_buffer */
            int*,             /* conf_state */
            int*              /* qop_state */
           );

static OM_uint32 k5glue_display_status
(void *, OM_uint32*,       /* minor_status */
            OM_uint32,        /* status_value */
            int,              /* status_type */
            gss_OID,          /* mech_type */
            OM_uint32*,       /* message_context */
            gss_buffer_t      /* status_string */
           );

static OM_uint32 k5glue_indicate_mechs
(void *, OM_uint32*,       /* minor_status */
            gss_OID_set*      /* mech_set */
           );

static OM_uint32 k5glue_compare_name
(void *, OM_uint32*,       /* minor_status */
            gss_name_t,       /* name1 */
            gss_name_t,       /* name2 */
            int*              /* name_equal */
           );

static OM_uint32 k5glue_display_name
(void *, OM_uint32*,      /* minor_status */
            gss_name_t,      /* input_name */
            gss_buffer_t,    /* output_name_buffer */
            gss_OID*         /* output_name_type */
           );

static OM_uint32 k5glue_import_name
(void *, OM_uint32*,       /* minor_status */
            gss_buffer_t,     /* input_name_buffer */
            gss_OID,          /* input_name_type */
            gss_name_t*       /* output_name */
           );

static OM_uint32 k5glue_release_name
(void *, OM_uint32*,       /* minor_status */
            gss_name_t*       /* input_name */
           );

static OM_uint32 k5glue_inquire_cred
(void *, OM_uint32 *,      /* minor_status */
            gss_cred_id_t,    /* cred_handle */
            gss_name_t *,     /* name */
            OM_uint32 *,      /* lifetime */
            gss_cred_usage_t*,/* cred_usage */
            gss_OID_set *     /* mechanisms */
           );

static OM_uint32 k5glue_inquire_context
(void *, OM_uint32*,       /* minor_status */
	    gss_ctx_id_t,     /* context_handle */
	    gss_name_t*,      /* initiator_name */
	    gss_name_t*,      /* acceptor_name */
	    OM_uint32*,       /* lifetime_rec */
	    gss_OID*,         /* mech_type */
	    OM_uint32*,       /* ret_flags */
	    int*,             /* locally_initiated */
	    int*              /* open */
	   );

#if 0
/* New V2 entry points */
static OM_uint32 k5glue_get_mic
(void *, OM_uint32 *,		/* minor_status */
	    gss_ctx_id_t,		/* context_handle */
	    gss_qop_t,			/* qop_req */
	    gss_buffer_t,		/* message_buffer */
	    gss_buffer_t		/* message_token */
	   );

static OM_uint32 k5glue_verify_mic
(void *, OM_uint32 *,		/* minor_status */
	    gss_ctx_id_t,		/* context_handle */
	    gss_buffer_t,		/* message_buffer */
	    gss_buffer_t,		/* message_token */
	    gss_qop_t *			/* qop_state */
	   );

static OM_uint32 k5glue_wrap
(void *, OM_uint32 *,		/* minor_status */
	    gss_ctx_id_t,		/* context_handle */
	    int,			/* conf_req_flag */
	    gss_qop_t,			/* qop_req */
	    gss_buffer_t,		/* input_message_buffer */
	    int *,			/* conf_state */
	    gss_buffer_t		/* output_message_buffer */
	   );

static OM_uint32 k5glue_unwrap
(void *, OM_uint32 *,		/* minor_status */
	    gss_ctx_id_t,		/* context_handle */
	    gss_buffer_t,		/* input_message_buffer */
	    gss_buffer_t,		/* output_message_buffer */
	    int *,			/* conf_state */
	    gss_qop_t *			/* qop_state */
	   );
#endif

static OM_uint32 k5glue_wrap_size_limit
(void *, OM_uint32 *,		/* minor_status */
	    gss_ctx_id_t,		/* context_handle */
	    int,			/* conf_req_flag */
	    gss_qop_t,			/* qop_req */
	    OM_uint32,			/* req_output_size */
	    OM_uint32 *			/* max_input_size */
	   );

#if 0
static OM_uint32 k5glue_import_name_object
(void *, OM_uint32 *,		/* minor_status */
	    void *,			/* input_name */
	    gss_OID,			/* input_name_type */
	    gss_name_t *		/* output_name */
	   );

static OM_uint32 k5glue_export_name_object
(void *, OM_uint32 *,		/* minor_status */
	    gss_name_t,			/* input_name */
	    gss_OID,			/* desired_name_type */
	    void * *			/* output_name */
	   );
#endif

static OM_uint32 k5glue_add_cred
(void *, OM_uint32 *,		/* minor_status */
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

static OM_uint32 k5glue_inquire_cred_by_mech
(void *, OM_uint32  *,		/* minor_status */
	    gss_cred_id_t,		/* cred_handle */
	    gss_OID,			/* mech_type */
	    gss_name_t *,		/* name */
	    OM_uint32 *,		/* initiator_lifetime */
	    OM_uint32 *,		/* acceptor_lifetime */
	    gss_cred_usage_t * 		/* cred_usage */
	   );

static OM_uint32 k5glue_export_sec_context
(void *, OM_uint32 *,		/* minor_status */
	    gss_ctx_id_t *,		/* context_handle */
	    gss_buffer_t		/* interprocess_token */
	    );

static OM_uint32 k5glue_import_sec_context
(void *, OM_uint32 *,		/* minor_status */
	    gss_buffer_t,		/* interprocess_token */
	    gss_ctx_id_t *		/* context_handle */
	    );

krb5_error_code k5glue_ser_init(krb5_context);

static OM_uint32 k5glue_internal_release_oid
(void *, OM_uint32 *,		/* minor_status */
	    gss_OID *			/* oid */
	   );

static OM_uint32 k5glue_inquire_names_for_mech
(void *, OM_uint32 *,		/* minor_status */
	    gss_OID,			/* mechanism */
	    gss_OID_set *		/* name_types */
	   );

#if 0
static OM_uint32 k5glue_canonicalize_name
(void *, OM_uint32  *,		/* minor_status */
	    const gss_name_t,		/* input_name */
	    const gss_OID,		/* mech_type */
	    gss_name_t *		/* output_name */
	 );
#endif

static OM_uint32 k5glue_export_name
(void *, OM_uint32  *,		/* minor_status */
	    const gss_name_t,		/* input_name */
	    gss_buffer_t		/* exported_name */
	 );

/* SUNW15resync - Solaris specific */
static OM_uint32 k5glue_store_cred (
	    void *,
	    OM_uint32 *,            /* minor_status */
	    const gss_cred_id_t,    /* input_cred */
	    gss_cred_usage_t,       /* cred_usage */
	    const gss_OID,          /* desired_mech */
	    OM_uint32,              /* overwrite_cred */
	    OM_uint32,              /* default_cred */
	    gss_OID_set *,          /* elements_stored */
	    gss_cred_usage_t *      /* cred_usage_stored */
	   );

/* SUNW17PACresync - this decl not needed in MIT but is for Sol */
/* Note code is in gsspi_krb5.c */
OM_uint32 krb5_gss_inquire_sec_context_by_oid(
	OM_uint32 *,
	const gss_ctx_id_t,
	const gss_OID,
	gss_buffer_set_t *);

static OM_uint32
k5glue_userok(
		    void *,		/* context */
		    OM_uint32 *,	/* minor_status */
		    const gss_name_t,	/* pname */
		    const char *,	/* local user */
		    int *		/* user ok? */
	/* */);

static OM_uint32
k5glue_pname_to_uid(
		    void *,		/* context */
		    OM_uint32 *,	/* minor_status */
		    const gss_name_t,	/* pname */
		    uid_t *		/* uid */
	/* */);




#if 0
static OM_uint32 k5glue_duplicate_name
(void *, OM_uint32  *,		/* minor_status */
	    const gss_name_t,		/* input_name */
	    gss_name_t *		/* dest_name */
	 );
#endif

#if 0
static OM_uint32 k5glue_validate_cred
(void *, OM_uint32 *,		/* minor_status */
	    gss_cred_id_t		/* cred */
         );
#endif

#if 0
/*
 * SUNW15resync
 * Solaris can't use the KRB5_GSS_CONFIG_INIT macro because of the src
 * slicing&dicing needs of the "nightly -SD" build.  When it goes away,
 * we should use it assuming MIT still uses it then.
 */

/*
 * The krb5 mechanism provides two mech OIDs; use this initializer to
 * ensure that both dispatch tables contain identical function
 * pointers.
 */
#define KRB5_GSS_CONFIG_INIT				\
    NULL,						\
    ...
#endif


static struct gss_config krb5_mechanism = {
#if 0 /* Solaris Kerberos */
    100, "kerberos_v5",
#endif
    { GSS_MECH_KRB5_OID_LENGTH, GSS_MECH_KRB5_OID },
    NULL,
    k5glue_acquire_cred,
    k5glue_release_cred,
    k5glue_init_sec_context,
    k5glue_accept_sec_context,
    k5glue_unseal,
    k5glue_process_context_token,
    k5glue_delete_sec_context,
    k5glue_context_time,
    k5glue_display_status,
    k5glue_indicate_mechs,
    k5glue_compare_name,
    k5glue_display_name,
    k5glue_import_name,
    k5glue_release_name,
    k5glue_inquire_cred,
    k5glue_add_cred,
    k5glue_seal,
    k5glue_export_sec_context,
    k5glue_import_sec_context,
    k5glue_inquire_cred_by_mech,
    k5glue_inquire_names_for_mech,
    k5glue_inquire_context,
    k5glue_internal_release_oid,
    k5glue_wrap_size_limit,
    k5glue_pname_to_uid,
    k5glue_userok,
    k5glue_export_name,
    k5glue_sign,
    k5glue_verify,
    k5glue_store_cred,
    krb5_gss_inquire_sec_context_by_oid
};

static struct gss_config krb5_mechanism_old = {
#if 0 /* Solaris Kerberos */
    200, "kerberos_v5 (pre-RFC OID)",
#endif
    { GSS_MECH_KRB5_OLD_OID_LENGTH, GSS_MECH_KRB5_OLD_OID },
    NULL,
    k5glue_acquire_cred,
    k5glue_release_cred,
    k5glue_init_sec_context,
    k5glue_accept_sec_context,
    k5glue_unseal,
    k5glue_process_context_token,
    k5glue_delete_sec_context,
    k5glue_context_time,
    k5glue_display_status,
    k5glue_indicate_mechs,
    k5glue_compare_name,
    k5glue_display_name,
    k5glue_import_name,
    k5glue_release_name,
    k5glue_inquire_cred,
    k5glue_add_cred,
    k5glue_seal,
    k5glue_export_sec_context,
    k5glue_import_sec_context,
    k5glue_inquire_cred_by_mech,
    k5glue_inquire_names_for_mech,
    k5glue_inquire_context,
    k5glue_internal_release_oid,
    k5glue_wrap_size_limit,
    k5glue_pname_to_uid,
    k5glue_userok,
    k5glue_export_name,
    k5glue_sign,
    k5glue_verify,
    k5glue_store_cred,
    krb5_gss_inquire_sec_context_by_oid
};

static struct gss_config krb5_mechanism_wrong = {
#if 0 /* Solaris Kerberos */
    300, "kerberos_v5 (wrong OID)",
#endif
    { GSS_MECH_KRB5_WRONG_OID_LENGTH, GSS_MECH_KRB5_WRONG_OID },
    NULL,
    k5glue_acquire_cred,
    k5glue_release_cred,
    k5glue_init_sec_context,
    k5glue_accept_sec_context,
    k5glue_unseal,
    k5glue_process_context_token,
    k5glue_delete_sec_context,
    k5glue_context_time,
    k5glue_display_status,
    k5glue_indicate_mechs,
    k5glue_compare_name,
    k5glue_display_name,
    k5glue_import_name,
    k5glue_release_name,
    k5glue_inquire_cred,
    k5glue_add_cred,
    k5glue_seal,
    k5glue_export_sec_context,
    k5glue_import_sec_context,
    k5glue_inquire_cred_by_mech,
    k5glue_inquire_names_for_mech,
    k5glue_inquire_context,
    k5glue_internal_release_oid,
    k5glue_wrap_size_limit,
    k5glue_pname_to_uid,
    k5glue_userok,
    k5glue_export_name,
    k5glue_sign,
    k5glue_verify,
    k5glue_store_cred,
    krb5_gss_inquire_sec_context_by_oid
};

static gss_mechanism krb5_mech_configs[] = {
    &krb5_mechanism, &krb5_mechanism_old, &krb5_mechanism_wrong, NULL
};

#ifdef MS_BUG_TEST
static gss_mechanism krb5_mech_configs_hack[] = {
    &krb5_mechanism, &krb5_mechanism_old, NULL
};
#endif

#if 1
#define gssint_get_mech_configs krb5_gss_get_mech_configs
#endif

gss_mechanism *
gssint_get_mech_configs(void)
{
#ifdef MS_BUG_TEST
    char *envstr = getenv("MS_FORCE_NO_MSOID");

    if (envstr != NULL && strcmp(envstr, "1") == 0) {
	return krb5_mech_configs_hack;
    }
#endif
    return krb5_mech_configs;
}

static OM_uint32
k5glue_accept_sec_context(ctx, minor_status, context_handle, verifier_cred_handle,
		       input_token, input_chan_bindings, src_name, mech_type, 
		       output_token, ret_flags, time_rec, delegated_cred_handle)
    void *ctx;
     OM_uint32 *minor_status;
     gss_ctx_id_t *context_handle;
     gss_cred_id_t verifier_cred_handle;
     gss_buffer_t input_token;
     gss_channel_bindings_t input_chan_bindings;
     gss_name_t *src_name;
     gss_OID *mech_type;
     gss_buffer_t output_token;
     OM_uint32 *ret_flags;
     OM_uint32 *time_rec;
     gss_cred_id_t *delegated_cred_handle;
{
   return(krb5_gss_accept_sec_context(minor_status,
				      context_handle,
				      verifier_cred_handle,
				      input_token,
				      input_chan_bindings,
				      src_name,
				      mech_type,
				      output_token,
				      ret_flags,
				      time_rec,
				      delegated_cred_handle));
}

static OM_uint32
k5glue_acquire_cred(ctx, minor_status, desired_name, time_req, desired_mechs,
		 cred_usage, output_cred_handle, actual_mechs, time_rec)
    void *ctx;
     OM_uint32 *minor_status;
     gss_name_t desired_name;
     OM_uint32 time_req;
     gss_OID_set desired_mechs;
     gss_cred_usage_t cred_usage;
     gss_cred_id_t *output_cred_handle;
     gss_OID_set *actual_mechs;
     OM_uint32 *time_rec;
{
   return(krb5_gss_acquire_cred(minor_status,
				desired_name,
				time_req,
				desired_mechs,
				cred_usage,
				output_cred_handle,
				actual_mechs,
				time_rec));
}

/* V2 */
static OM_uint32
k5glue_add_cred(ctx, minor_status, input_cred_handle, desired_name, desired_mech,
	     cred_usage, initiator_time_req, acceptor_time_req,
	     output_cred_handle, actual_mechs, initiator_time_rec,
	     acceptor_time_rec)
    void *ctx;
    OM_uint32		 *minor_status;
    gss_cred_id_t	input_cred_handle;
    gss_name_t		desired_name;
    gss_OID		desired_mech;
    gss_cred_usage_t	cred_usage;
    OM_uint32		initiator_time_req;
    OM_uint32		acceptor_time_req;
    gss_cred_id_t	 *output_cred_handle;
    gss_OID_set		 *actual_mechs;
    OM_uint32		 *initiator_time_rec;
    OM_uint32		 *acceptor_time_rec;
{
    return(krb5_gss_add_cred(minor_status, input_cred_handle, desired_name,
			     desired_mech, cred_usage, initiator_time_req,
			     acceptor_time_req, output_cred_handle,
			     actual_mechs, initiator_time_rec,
			     acceptor_time_rec));
}

#if 0
/* V2 */
static OM_uint32
k5glue_add_oid_set_member(ctx, minor_status, member_oid, oid_set)
    void *ctx;
    OM_uint32	 *minor_status;
    gss_OID	member_oid;
    gss_OID_set	 *oid_set;
{
    return(generic_gss_add_oid_set_member(minor_status, member_oid, oid_set));
}
#endif

static OM_uint32
k5glue_compare_name(ctx, minor_status, name1, name2, name_equal)
    void *ctx;
     OM_uint32 *minor_status;
     gss_name_t name1;
     gss_name_t name2;
     int *name_equal;
{
   return(krb5_gss_compare_name(minor_status, name1,
				name2, name_equal));
}

static OM_uint32
k5glue_context_time(ctx, minor_status, context_handle, time_rec)
    void *ctx;
     OM_uint32 *minor_status;
     gss_ctx_id_t context_handle;
     OM_uint32 *time_rec;
{
   return(krb5_gss_context_time(minor_status, context_handle,
				time_rec));
}

#if 0
/* V2 */
static OM_uint32
k5glue_create_empty_oid_set(ctx, minor_status, oid_set)
    void *ctx;
    OM_uint32	 *minor_status;
    gss_OID_set	 *oid_set;
{
    return(generic_gss_create_empty_oid_set(minor_status, oid_set));
}
#endif

static OM_uint32
k5glue_delete_sec_context(ctx, minor_status, context_handle, output_token)
    void *ctx;
     OM_uint32 *minor_status;
     gss_ctx_id_t *context_handle;
     gss_buffer_t output_token;
{
   return(krb5_gss_delete_sec_context(minor_status,
				      context_handle, output_token));
}

static OM_uint32
k5glue_display_name(ctx, minor_status, input_name, output_name_buffer, output_name_type)
    void *ctx;
     OM_uint32 *minor_status;
     gss_name_t input_name;
     gss_buffer_t output_name_buffer;
     gss_OID *output_name_type;
{
   return(krb5_gss_display_name(minor_status, input_name,
				output_name_buffer, output_name_type));
}

static OM_uint32
k5glue_display_status(ctx, minor_status, status_value, status_type,
		   mech_type, message_context, status_string)
    void *ctx;
     OM_uint32 *minor_status;
     OM_uint32 status_value;
     int status_type;
     gss_OID mech_type;
     OM_uint32 *message_context;
     gss_buffer_t status_string;
{
   return(krb5_gss_display_status(minor_status, status_value,
				  status_type, mech_type, message_context,
				  status_string));
}

/* V2 */
static OM_uint32
k5glue_export_sec_context(ctx, minor_status, context_handle, interprocess_token)
    void *ctx;
     OM_uint32		 *minor_status;
     gss_ctx_id_t	 *context_handle;
     gss_buffer_t	interprocess_token;
{
   return(krb5_gss_export_sec_context(minor_status,
				      context_handle,
				      interprocess_token));
}

#if 0
/* V2 */
static OM_uint32
k5glue_get_mic(ctx, minor_status, context_handle, qop_req,
	    message_buffer, message_token)
    void *ctx;
     OM_uint32		 *minor_status;
     gss_ctx_id_t	context_handle;
     gss_qop_t		qop_req;
     gss_buffer_t	message_buffer;
     gss_buffer_t	message_token;
{
    return(krb5_gss_get_mic(minor_status, context_handle,
			    qop_req, message_buffer, message_token));
}
#endif

static OM_uint32
k5glue_import_name(ctx, minor_status, input_name_buffer, input_name_type, output_name)
    void *ctx;
     OM_uint32 *minor_status;
     gss_buffer_t input_name_buffer;
     gss_OID input_name_type;
     gss_name_t *output_name;
{
#if 0
    OM_uint32 err;
    err = gssint_initialize_library();
    if (err) {
	*minor_status = err;
	return GSS_S_FAILURE;
    }
#endif
    return(krb5_gss_import_name(minor_status, input_name_buffer,
				input_name_type, output_name));
}

/* V2 */
static OM_uint32
k5glue_import_sec_context(ctx, minor_status, interprocess_token, context_handle)
    void *ctx;
     OM_uint32		 *minor_status;
     gss_buffer_t	interprocess_token;
     gss_ctx_id_t	 *context_handle;
{
   return(krb5_gss_import_sec_context(minor_status,
				      interprocess_token,
				      context_handle));
}

static OM_uint32
k5glue_indicate_mechs(ctx, minor_status, mech_set)
    void *ctx;
     OM_uint32 *minor_status;
     gss_OID_set *mech_set;
{
   return(krb5_gss_indicate_mechs(minor_status, mech_set));
}

static OM_uint32
k5glue_init_sec_context(ctx, minor_status, claimant_cred_handle, context_handle,
		     target_name, mech_type, req_flags, time_req,
		     input_chan_bindings, input_token, actual_mech_type,
		     output_token, ret_flags, time_rec)
    void *ctx;
     OM_uint32 *minor_status;
     gss_cred_id_t claimant_cred_handle;
     gss_ctx_id_t *context_handle;
     gss_name_t target_name;
     gss_OID mech_type;
     OM_uint32 req_flags;
     OM_uint32 time_req;
     gss_channel_bindings_t input_chan_bindings;
     gss_buffer_t input_token;
     gss_OID *actual_mech_type;
     gss_buffer_t output_token;
     OM_uint32 *ret_flags;
     OM_uint32 *time_rec;
{
   return(krb5_gss_init_sec_context(minor_status,
				    claimant_cred_handle, context_handle,
				    target_name, mech_type, req_flags,
				    time_req, input_chan_bindings, input_token,
				    actual_mech_type, output_token, ret_flags,
				    time_rec));
}

static OM_uint32
k5glue_inquire_context(ctx, minor_status, context_handle, initiator_name, acceptor_name,
		    lifetime_rec, mech_type, ret_flags,
		    locally_initiated, open)
    void *ctx;
     OM_uint32 *minor_status;
     gss_ctx_id_t context_handle;
     gss_name_t *initiator_name;
     gss_name_t *acceptor_name;
     OM_uint32 *lifetime_rec;
     gss_OID *mech_type;
     OM_uint32 *ret_flags;
     int *locally_initiated;
     int *open;
{
   return(krb5_gss_inquire_context(minor_status, context_handle,
				   initiator_name, acceptor_name, lifetime_rec,
				   mech_type, ret_flags, locally_initiated,
				   open));
}

static OM_uint32
k5glue_inquire_cred(ctx, minor_status, cred_handle, name, lifetime_ret,
		 cred_usage, mechanisms)
    void *ctx;
     OM_uint32 *minor_status;
     gss_cred_id_t cred_handle;
     gss_name_t *name;
     OM_uint32 *lifetime_ret;
     gss_cred_usage_t *cred_usage;
     gss_OID_set *mechanisms;
{
   return(krb5_gss_inquire_cred(minor_status, cred_handle,
				name, lifetime_ret, cred_usage, mechanisms));
}

/* V2 */
static OM_uint32
k5glue_inquire_cred_by_mech(ctx, minor_status, cred_handle, mech_type, name,
			 initiator_lifetime, acceptor_lifetime, cred_usage)
    void *ctx;
     OM_uint32		 *minor_status;
     gss_cred_id_t	cred_handle;
     gss_OID		mech_type;
     gss_name_t		 *name;
     OM_uint32		 *initiator_lifetime;
     OM_uint32		 *acceptor_lifetime;
     gss_cred_usage_t	 *cred_usage;
{
   return(krb5_gss_inquire_cred_by_mech(minor_status, cred_handle,
					mech_type, name, initiator_lifetime,
					acceptor_lifetime, cred_usage));
}

/* V2 */
static OM_uint32
k5glue_inquire_names_for_mech(ctx, minor_status, mechanism, name_types)
    void *ctx;
    OM_uint32	 *minor_status;
    gss_OID	mechanism;
    gss_OID_set	 *name_types;
{
    return(krb5_gss_inquire_names_for_mech(minor_status,
					   mechanism,
					   name_types));
}

#if 0
/* V2 */
static OM_uint32
k5glue_oid_to_str(ctx, minor_status, oid, oid_str)
    void *ctx;
    OM_uint32		 *minor_status;
    gss_OID		oid;
    gss_buffer_t	oid_str;
{
    return(generic_gss_oid_to_str(minor_status, oid, oid_str));
}
#endif

static OM_uint32
k5glue_process_context_token(ctx, minor_status, context_handle, token_buffer)
    void *ctx;
     OM_uint32 *minor_status;
     gss_ctx_id_t context_handle;
     gss_buffer_t token_buffer;
{
   return(krb5_gss_process_context_token(minor_status,
					 context_handle, token_buffer));
}

static OM_uint32
k5glue_release_cred(ctx, minor_status, cred_handle)
    void *ctx;
     OM_uint32 *minor_status;
     gss_cred_id_t *cred_handle;
{
   return(krb5_gss_release_cred(minor_status, cred_handle));
}

static OM_uint32
k5glue_release_name(ctx, minor_status, input_name)
    void *ctx;
     OM_uint32 *minor_status;
     gss_name_t *input_name;
{
   return(krb5_gss_release_name(minor_status, input_name));
}

#if 0
static OM_uint32
k5glue_release_buffer(ctx, minor_status, buffer)
    void *ctx;
     OM_uint32 *minor_status;
     gss_buffer_t buffer;
{
   return(generic_gss_release_buffer(minor_status,
				     buffer));
}
#endif

/* V2 */
static OM_uint32
k5glue_internal_release_oid(ctx, minor_status, oid)
    void *ctx;
     OM_uint32	 *minor_status;
     gss_OID	 *oid;
{
    return(krb5_gss_internal_release_oid(minor_status, oid));
}

#if 0
static OM_uint32
k5glue_release_oid_set(ctx, minor_status, set)
    void *ctx;
     OM_uint32 * minor_status;
     gss_OID_set *set;
{
   return(generic_gss_release_oid_set(minor_status, set));
}
#endif

/* V1 only */
static OM_uint32
k5glue_seal(ctx, minor_status, context_handle, conf_req_flag, qop_req,
	 input_message_buffer, conf_state, output_message_buffer)
    void *ctx;
     OM_uint32 *minor_status;
     gss_ctx_id_t context_handle;
     int conf_req_flag;
     int qop_req;
     gss_buffer_t input_message_buffer;
     int *conf_state;
     gss_buffer_t output_message_buffer;
{
   return(krb5_gss_seal(minor_status, context_handle,
			conf_req_flag, qop_req, input_message_buffer,
			conf_state, output_message_buffer));
}

static OM_uint32
k5glue_sign(ctx, minor_status, context_handle,
	      qop_req, message_buffer, 
	      message_token)
    void *ctx;
     OM_uint32 *minor_status;
     gss_ctx_id_t context_handle;
     int qop_req;
     gss_buffer_t message_buffer;
     gss_buffer_t message_token;
{
   return(krb5_gss_sign(minor_status, context_handle,
			qop_req, message_buffer, message_token));
}

#if 0
/* V2 */
static OM_uint32
k5glue_verify_mic(ctx, minor_status, context_handle,
	       message_buffer, token_buffer, qop_state)
    void *ctx;
     OM_uint32		 *minor_status;
     gss_ctx_id_t	context_handle;
     gss_buffer_t	message_buffer;
     gss_buffer_t	token_buffer;
     gss_qop_t		 *qop_state;
{
    return(krb5_gss_verify_mic(minor_status, context_handle,
			       message_buffer, token_buffer, qop_state));
}

/* V2 */
static OM_uint32
k5glue_wrap(ctx, minor_status, context_handle, conf_req_flag, qop_req,
	 input_message_buffer, conf_state, output_message_buffer)
    void *ctx;
    OM_uint32		 *minor_status;
    gss_ctx_id_t	context_handle;
    int			conf_req_flag;
    gss_qop_t		qop_req;
    gss_buffer_t	input_message_buffer;
    int			 *conf_state;
    gss_buffer_t	output_message_buffer;
{
    return(krb5_gss_wrap(minor_status, context_handle, conf_req_flag, qop_req,
			 input_message_buffer, conf_state,
			 output_message_buffer));
}

/* V2 */
static OM_uint32
k5glue_str_to_oid(ctx, minor_status, oid_str, oid)
    void *ctx;
    OM_uint32		 *minor_status;
    gss_buffer_t	oid_str;
    gss_OID		 *oid;
{
    return(generic_gss_str_to_oid(minor_status, oid_str, oid));
}

/* V2 */
static OM_uint32
k5glue_test_oid_set_member(ctx, minor_status, member, set, present)
    void *ctx;
    OM_uint32	 *minor_status;
    gss_OID	member;
    gss_OID_set	set;
    int		 *present;
{
    return(generic_gss_test_oid_set_member(minor_status, member, set,
					   present));
}
#endif

/* V1 only */
static OM_uint32
k5glue_unseal(ctx, minor_status, context_handle, input_message_buffer,
	   output_message_buffer, conf_state, qop_state)
    void *ctx;
     OM_uint32 *minor_status;
     gss_ctx_id_t context_handle;
     gss_buffer_t input_message_buffer;
     gss_buffer_t output_message_buffer;
     int *conf_state;
     int *qop_state;
{
   return(krb5_gss_unseal(minor_status, context_handle,
			  input_message_buffer, output_message_buffer,
			  conf_state, qop_state));
}

#if 0
/* V2 */
static OM_uint32
k5glue_unwrap(ctx, minor_status, context_handle, input_message_buffer, 
	   output_message_buffer, conf_state, qop_state)
    void *ctx;
    OM_uint32		 *minor_status;
    gss_ctx_id_t	context_handle;
    gss_buffer_t	input_message_buffer;
    gss_buffer_t	output_message_buffer;
    int			 *conf_state;
    gss_qop_t		 *qop_state;
{
    return(krb5_gss_unwrap(minor_status, context_handle, input_message_buffer,
			   output_message_buffer, conf_state, qop_state));
}
#endif

/* V1 only */
static OM_uint32
k5glue_verify(ctx, minor_status, context_handle, message_buffer,
	   token_buffer, qop_state)
    void *ctx;
     OM_uint32 *minor_status;
     gss_ctx_id_t context_handle;
     gss_buffer_t message_buffer;
     gss_buffer_t token_buffer;
     int *qop_state;
{
   return(krb5_gss_verify(minor_status,
			  context_handle,
			  message_buffer,
			  token_buffer,
			  qop_state));
}

/* V2 interface */
static OM_uint32
k5glue_wrap_size_limit(ctx, minor_status, context_handle, conf_req_flag,
		    qop_req, req_output_size, max_input_size)
    void *ctx;
    OM_uint32		 *minor_status;
    gss_ctx_id_t	context_handle;
    int			conf_req_flag;
    gss_qop_t		qop_req;
    OM_uint32		req_output_size;
    OM_uint32		 *max_input_size;
{
   return(krb5_gss_wrap_size_limit(minor_status, context_handle,
				   conf_req_flag, qop_req,
				   req_output_size, max_input_size));
}

#if 0
/* V2 interface */
static OM_uint32
k5glue_canonicalize_name(ctx, minor_status, input_name, mech_type, output_name)
    void *ctx;
	OM_uint32  *minor_status;
	const gss_name_t input_name;
	const gss_OID mech_type;
	gss_name_t *output_name;
{
	return krb5_gss_canonicalize_name(minor_status, input_name,
					  mech_type, output_name);
}
#endif

/* V2 interface */
static OM_uint32
k5glue_export_name(ctx, minor_status, input_name, exported_name)
    void *ctx;
	OM_uint32  *minor_status;
	const gss_name_t input_name;
	gss_buffer_t exported_name;
{
	return krb5_gss_export_name(minor_status, input_name, exported_name);
}

/* SUNW15resync - this is not in the MIT mech (lib) yet */
static OM_uint32
k5glue_store_cred(ctx, minor_status, input_cred, cred_usage, desired_mech,
			overwrite_cred, default_cred, elements_stored,
			cred_usage_stored)
void *ctx;
OM_uint32 *minor_status;
const gss_cred_id_t input_cred;
gss_cred_usage_t cred_usage;
gss_OID desired_mech;
OM_uint32 overwrite_cred;
OM_uint32 default_cred;
gss_OID_set *elements_stored;
gss_cred_usage_t *cred_usage_stored;
{
  return(krb5_gss_store_cred(minor_status, input_cred,
			    cred_usage, desired_mech,
			    overwrite_cred, default_cred, elements_stored,
			    cred_usage_stored));
}

static OM_uint32
k5glue_userok(
		    void *ctxt,		/* context */
		    OM_uint32 *minor,	/* minor_status */
		    const gss_name_t pname,	/* pname */
		    const char *user,	/* local user */
		    int *user_ok		/* user ok? */
	/* */)
{
  return(krb5_gss_userok(minor, pname, user, user_ok));
}

static OM_uint32
k5glue_pname_to_uid(
		    void *ctxt,		/* context */
		    OM_uint32 *minor,	/* minor_status */
		    const gss_name_t pname,	/* pname */
		    uid_t *uidOut		/* uid */
	/* */)
{
  return (krb5_pname_to_uid(minor, pname, uidOut));
}



#if 0
/* V2 interface */
static OM_uint32
k5glue_duplicate_name(ctx, minor_status, input_name, dest_name)
    void *ctx;
	OM_uint32  *minor_status;
	const gss_name_t input_name;
	gss_name_t *dest_name;
{
	return krb5_gss_duplicate_name(minor_status, input_name, dest_name);
}
#endif


OM_uint32 KRB5_CALLCONV 
gss_krb5_copy_ccache(
    OM_uint32 *minor_status,
    gss_cred_id_t cred_handle,
    krb5_ccache out_ccache)
{
    gss_union_cred_t ucred;
    gss_cred_id_t mcred;

    ucred = (gss_union_cred_t)cred_handle;

    mcred = gssint_get_mechanism_cred(ucred, &krb5_mechanism.mech_type);
    if (mcred != GSS_C_NO_CREDENTIAL)
	return gss_krb5int_copy_ccache(minor_status, mcred, out_ccache);

    mcred = gssint_get_mechanism_cred(ucred, &krb5_mechanism_old.mech_type);
    if (mcred != GSS_C_NO_CREDENTIAL)
	return gss_krb5int_copy_ccache(minor_status, mcred, out_ccache);

    return GSS_S_DEFECTIVE_CREDENTIAL;
}

OM_uint32 KRB5_CALLCONV
gss_krb5_set_allowable_enctypes(
    OM_uint32 *minor_status, 
    gss_cred_id_t cred,
    OM_uint32 num_ktypes,
    krb5_enctype *ktypes)
{
    gss_union_cred_t ucred;
    gss_cred_id_t mcred;

    ucred = (gss_union_cred_t)cred;
    mcred = gssint_get_mechanism_cred(ucred, &krb5_mechanism.mech_type);
    if (mcred != GSS_C_NO_CREDENTIAL)
	return gss_krb5int_set_allowable_enctypes(minor_status, mcred,
						  num_ktypes, ktypes);

    mcred = gssint_get_mechanism_cred(ucred, &krb5_mechanism_old.mech_type);
    if (mcred != GSS_C_NO_CREDENTIAL)
	return gss_krb5int_set_allowable_enctypes(minor_status, mcred,
						  num_ktypes, ktypes);

    return GSS_S_DEFECTIVE_CREDENTIAL;
}

/*
 * Glue routine for returning the mechanism-specific credential from a
 * external union credential.
 */
/* SUNW15resync - in MIT 1.5, it's in g_glue.c (libgss) but we don't
  want to link against libgss so we put it here since we need it in the mech */
gss_cred_id_t
gssint_get_mechanism_cred(union_cred, mech_type)
    gss_union_cred_t    union_cred;
    gss_OID             mech_type;
{
    int         i;

    if (union_cred == (gss_union_cred_t) GSS_C_NO_CREDENTIAL)
        return GSS_C_NO_CREDENTIAL;

    for (i=0; i < union_cred->count; i++) {
        if (g_OID_equal(mech_type, &union_cred->mechs_array[i]))
            return union_cred->cred_array[i];
    }
    return GSS_C_NO_CREDENTIAL;
}



/*
 * entry point for the gss layer,
 * called "krb5_gss_initialize()" in MIT 1.2.1
 */
/* SUNW15resync - this used to be in k5mech.c */
gss_mechanism
gss_mech_initialize(oid)
     const gss_OID oid;
{
    /*
     * Solaris Kerberos: We also want to use the same functions for KRB5 as
     * we do for the MS KRB5 (krb5_mechanism_wrong).  So both are valid.
     */
    /* ensure that the requested oid matches our oid */
    if (oid == NULL || (!g_OID_equal(oid, &krb5_mechanism.mech_type) &&
	!g_OID_equal(oid, &krb5_mechanism_wrong.mech_type))) {
      (void) syslog(LOG_INFO, "krb5mech: gss_mech_initialize: bad oid");
      return (NULL);
    }

#if 0 /* SUNW15resync - no longer needed(?) */
    if (krb5_gss_get_context(&(krb5_mechanism.context)) !=
	GSS_S_COMPLETE)
      return (NULL);
#endif

    return (&krb5_mechanism);
}

/*
 * This API should go away and be replaced with an accessor
 * into a gss_name_t.
 */
OM_uint32 KRB5_CALLCONV
gsskrb5_extract_authz_data_from_sec_context(
    OM_uint32 *minor_status,
    gss_ctx_id_t context_handle,
    int ad_type,
    gss_buffer_t ad_data)
{
    gss_OID_desc req_oid;
    unsigned char oid_buf[GSS_KRB5_EXTRACT_AUTHZ_DATA_FROM_SEC_CONTEXT_OID_LENGTH + 6];
    OM_uint32 major_status;
    gss_buffer_set_t data_set = GSS_C_NO_BUFFER_SET;

    if (ad_data == NULL)
        return GSS_S_CALL_INACCESSIBLE_WRITE;

    req_oid.elements = oid_buf;
    req_oid.length = sizeof(oid_buf);

    major_status = generic_gss_oid_compose(minor_status,
                                           GSS_KRB5_EXTRACT_AUTHZ_DATA_FROM_SEC_CONTEXT_OID,
                                           GSS_KRB5_EXTRACT_AUTHZ_DATA_FROM_SEC_CONTEXT_OID_LENGTH,
                                           ad_type,
                                           &req_oid);
    if (GSS_ERROR(major_status))
        return major_status;

    major_status = gss_inquire_sec_context_by_oid(minor_status,
                                                  context_handle,
                                                  (gss_OID)&req_oid,
                                                  &data_set);
    if (major_status != GSS_S_COMPLETE) {
        return major_status;
    }

    /*
     * SUNW17PACresync / Solaris Kerberos
     * MIT17 allows only count==1 which is correct for pre-Win2008 but
     * our testing with Win2008 shows count==2 and Win7 count==3.
     */
    if ((data_set == GSS_C_NO_BUFFER_SET) || (data_set->count == 0)) {
	    gss_release_buffer_set(minor_status, &data_set);
	    *minor_status = EINVAL;
	    return GSS_S_FAILURE;
    }

    ad_data->length = data_set->elements[0].length;
    ad_data->value = malloc(ad_data->length);
    if (!ad_data->value) {
	    gss_release_buffer_set(minor_status, &data_set);
	    return ENOMEM;
    }
    bcopy(data_set->elements[0].value, ad_data->value, ad_data->length);

    gss_release_buffer_set(minor_status, &data_set);

    return GSS_S_COMPLETE;
}


OM_uint32 KRB5_CALLCONV
gsskrb5_extract_authtime_from_sec_context(OM_uint32 *minor_status,
                                          gss_ctx_id_t context_handle,
                                          krb5_timestamp *authtime)
{
    static const gss_OID_desc req_oid = {
        GSS_KRB5_EXTRACT_AUTHTIME_FROM_SEC_CONTEXT_OID_LENGTH,
        GSS_KRB5_EXTRACT_AUTHTIME_FROM_SEC_CONTEXT_OID };
    OM_uint32 major_status;
    gss_buffer_set_t data_set = GSS_C_NO_BUFFER_SET;

    if (authtime == NULL)
        return GSS_S_CALL_INACCESSIBLE_WRITE;

    major_status = gss_inquire_sec_context_by_oid(minor_status,
                                                  context_handle,
                                                  (gss_OID)&req_oid,
                                                  &data_set);
    if (major_status != GSS_S_COMPLETE)
        return major_status;

    if (data_set == GSS_C_NO_BUFFER_SET ||
        data_set->count != 1 ||
        data_set->elements[0].length != sizeof(*authtime)) {
        *minor_status = EINVAL;
        return GSS_S_FAILURE;
    }

    *authtime = *((krb5_timestamp *)data_set->elements[0].value);

    gss_release_buffer_set(minor_status, &data_set);

    *minor_status = 0;

    return GSS_S_COMPLETE;
}
