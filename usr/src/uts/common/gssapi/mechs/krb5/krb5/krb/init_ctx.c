/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * lib/krb5/krb/init_ctx.c
 *
 * Copyright 1994,1999,2000, 2002, 2003  by the Massachusetts Institute of Technology.
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
 * krb5_init_contex()
 */

/*
 * Copyright (C) 1998 by the FundsXpress, INC.
 *
 * All rights reserved.
 *
 * Export of this software from the United States of America may require
 * a specific license from the United States Government.  It is the
 * responsibility of any person or organization contemplating export to
 * obtain such a license before exporting.
 *
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of FundsXpress. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  FundsXpress makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
 * WARRANTIES OF MERCHANTIBILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */

#include "k5-int.h"

/*
 * Solaris Kerberos: the code related to EF/pkcs11 and fork safety are mods Sun
 * has made to the MIT code.
 */

#ifndef _KERNEL
#include <ctype.h>

pid_t __krb5_current_pid; /* fork safety: contains the current process ID */
#endif

#ifndef _KERNEL
#include <krb5_libinit.h>
#endif

/* The des-mdX entries are last for now, because it's easy to
   configure KDCs to issue TGTs with des-mdX keys and then not accept
   them.  This'll be fixed, but for better compatibility, let's prefer
   des-crc for now.  */
/*
 * Solaris Kerberos:
 * Added arcfour-hmac-md5-exp as default enc type.
 * Changed des3-hmac-sha1 to des3-cbc-sha1-kd, as specified in RFC3961.
 */
#define DEFAULT_ETYPE_LIST	\
	"aes256-cts-hmac-sha1-96 " \
	"aes128-cts-hmac-sha1-96 " \
	"des3-cbc-sha1-kd " \
	"arcfour-hmac-md5 " \
	"arcfour-hmac-md5-exp " \
	"des-cbc-md5 " \
	"des-cbc-crc"


/* The only functions that are needed from this file when in kernel are
 * krb5_init_context and krb5_free_context.
 * In krb5_init_context we need only os_init_context since we don'it need the
 * profile info unless we do init/accept in kernel. Currently only mport,
 * delete , sign/verify, wrap/unwrap routines are ported to the kernel.
 */

#if (defined(_WIN32))
extern krb5_error_code krb5_vercheck();
extern void krb5_win_ccdll_load(krb5_context context);
#endif

static krb5_error_code init_common (krb5_context *, krb5_boolean, krb5_boolean);

krb5_error_code KRB5_CALLCONV
krb5_init_context(krb5_context *context)
{

	return init_common (context, FALSE, FALSE);
}

krb5_error_code KRB5_CALLCONV
krb5_init_secure_context(krb5_context *context)
{

#if 0 /* Solaris Kerberos */
        /* This is to make gcc -Wall happy */
        if(0) krb5_brand[0] = krb5_brand[0];
#endif
	return init_common (context, TRUE, FALSE);
}

#ifndef _KERNEL

krb5_error_code
krb5int_init_context_kdc(krb5_context *context)
{
    return init_common (context, FALSE, TRUE);
}

/* Solaris Kerberos */
krb5_error_code
krb5_open_pkcs11_session(CK_SESSION_HANDLE *hSession)
{
	krb5_error_code retval = 0;
	CK_RV rv;
	CK_SLOT_ID_PTR slotlist = NULL_PTR;
	CK_ULONG slotcount;
	CK_ULONG i;

	/* List of all Slots */
	rv = C_GetSlotList(FALSE, NULL_PTR, &slotcount);
	if (rv != CKR_OK) {
		KRB5_LOG(KRB5_ERR, "C_GetSlotList failed with 0x%x.", rv);
		retval = PKCS_ERR;
		goto cleanup;
	}

	if (slotcount == 0) {
		KRB5_LOG0(KRB5_ERR, "No slot is found in PKCS11.");
		retval = PKCS_ERR;
		goto cleanup;
	}

	slotlist = (CK_SLOT_ID_PTR)malloc(slotcount * sizeof(CK_SLOT_ID));
	if (slotlist == NULL) {
		KRB5_LOG0(KRB5_ERR, "malloc failed for slotcount.");
		retval = PKCS_ERR;
		goto cleanup;
	}

	rv = C_GetSlotList(FALSE, slotlist, &slotcount);
	if (rv != CKR_OK) {
		KRB5_LOG(KRB5_ERR, "C_GetSlotList failed with 0x%x", rv);
		retval = PKCS_ERR;
		goto cleanup;
	}
	for (i = 0; i < slotcount; i++) {
		if (slot_supports_krb5(slotlist + i))
			break;
	}
	if (i == slotcount){
		KRB5_LOG0(KRB5_ERR, "Could not find slot which supports "
		   "Kerberos");
		retval = PKCS_ERR;
		goto cleanup;
	}
	rv = C_OpenSession(slotlist[i], CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR,
	    hSession);
	if (rv != CKR_OK) {
		retval = PKCS_ERR;
	}
cleanup:
	if (slotlist != NULL)
		free(slotlist);
	return(retval);
}

/*
 * krb5_reinit_ef_handle()
 *
 * deal with fork safety issue regarding the krb ctx and the pkcs11 hSession
 * field.  This function is called if it is determined that the krb ctx hSession
 * is being accessed in a child process after a fork().  This function
 * re-initilizes the pkcs11 session and returns the session handle.
 */
CK_SESSION_HANDLE
krb5_reinit_ef_handle(krb5_context ctx)
{
    ctx->cryptoki_initialized = FALSE;

    if (krb5_init_ef_handle(ctx) != 0) {
	/*
	 * krb5_free_ef_handle() not needed here -- we assume that an equivalent
	 * of C_Finalize() was done in the child-side of the fork(), so all EF
	 * resources in this context will be invalid.
	 */
	return(CK_INVALID_HANDLE);
    }

    /* reset the ctx pid since we're in a new process (child) */
    ctx->pid = __krb5_current_pid;

    /* If the RC4 handles were initialized, reset them here */
    if (ctx->arcfour_ctx.initialized) {
	krb5_error_code ret;
	ret = krb5_open_pkcs11_session(&ctx->arcfour_ctx.eSession);
        if (ret) {
		ctx->arcfour_ctx.initialized = 0;
		ctx->arcfour_ctx.eSession = CK_INVALID_HANDLE;
		C_CloseSession(ctx->hSession);
		ctx->hSession = CK_INVALID_HANDLE;
	}
        ret = krb5_open_pkcs11_session(&ctx->arcfour_ctx.dSession);
        if (ret) {
		ctx->arcfour_ctx.initialized = 0;
		ctx->arcfour_ctx.eSession = CK_INVALID_HANDLE;
		ctx->arcfour_ctx.dSession = CK_INVALID_HANDLE;
		C_CloseSession(ctx->hSession);
		ctx->hSession = CK_INVALID_HANDLE;
	}
    }

    /*
     * It is safe for this function to access ctx->hSession directly.  Do
     * NOT use the krb_ctx_hSession() here.
     */
    return(ctx->hSession);
}

/*
 * krb5_pthread_atfork_child_handler() sets a global that indicates the current
 * PID.  This is an optimization to keep getpid() from being called a zillion
 * times.
 */
void
krb5_pthread_atfork_child_handler()
{
    /*
     * __krb5_current_pid should always be set to current process ID, see the
     * definition of krb_ctx_hSession() for more info
     */
    __krb5_current_pid = getpid();
}

/*
 * krb5_ld_init() contains code that will be executed at load time (via the
 * ld -zinitarray directive).
 */
void
krb5_ld_init()
{
    /*
     * fork safety: __krb5_current_pid should always be set to current process
     * ID, see the definition of krb_ctx_hSession() for more info
     */
    __krb5_current_pid = getpid();
    /*
     * The child handler below will help reduce the number of times getpid() is
     * called by updating a global PID var. with the current PID whenever a fork
     * occurrs.
     */
    (void) pthread_atfork(NULL, NULL, krb5_pthread_atfork_child_handler);
}
#endif /* !_KERNEL */

krb5_error_code
krb5_init_ef_handle(krb5_context ctx)
{
	krb5_error_code retval = 0;
#ifndef _KERNEL
	CK_RV rv = C_Initialize(NULL_PTR);
	if ((rv != CKR_OK) && (rv != CKR_CRYPTOKI_ALREADY_INITIALIZED)) {
		KRB5_LOG(KRB5_ERR, "C_Initialize failed with 0x%x.", rv);
		return (PKCS_ERR);

	}
	/*
	 * It is safe for this function to access ctx->hSession directly.  Do
	 * NOT use the krb_ctx_hSession() here.
	 */
	retval = krb5_open_pkcs11_session(&ctx->hSession);
	if (retval != 0)
		return (retval);

	ctx->cryptoki_initialized = TRUE;
#else /* ! _KERNEL */
	ctx->kef_cipher_mt = CRYPTO_MECH_INVALID;
	ctx->kef_hash_mt = CRYPTO_MECH_INVALID;
	ctx->kef_cksum_mt = CRYPTO_MECH_INVALID;

	setup_kef_keytypes();
	setup_kef_cksumtypes();

#endif /* ! _KERNEL */
	return(retval);
}

#ifndef _KERNEL
krb5_error_code
krb5_free_ef_handle(krb5_context ctx)
{
	/*
	 * fork safety: Don't free any PKCS state if we've forked since
	 * allocating the pkcs handles.
	 */
	if (ctx->cryptoki_initialized == TRUE &&
	    ctx->pid == __krb5_current_pid) {
		/*
		 * It is safe for this function to access ctx->hSession
		 * directly.  Do NOT use the krb_ctx_hSession() here.
		 */
		if (ctx->hSession) {
			C_CloseSession(ctx->hSession);
			ctx->hSession = 0;
		}
		if (ctx->arcfour_ctx.dKey) {
			C_DestroyObject(ctx->arcfour_ctx.dSession,
				ctx->arcfour_ctx.dKey);
			ctx->arcfour_ctx.dKey = 0;
		}
		if (ctx->arcfour_ctx.eKey) {
			C_DestroyObject(ctx->arcfour_ctx.eSession,
				ctx->arcfour_ctx.eKey);
			ctx->arcfour_ctx.eKey = 0;
		}
		if (ctx->arcfour_ctx.eSession) {
			C_CloseSession(ctx->arcfour_ctx.eSession);
			ctx->arcfour_ctx.eSession = 0;
		}
		if (ctx->arcfour_ctx.dSession) {
			C_CloseSession(ctx->arcfour_ctx.dSession);
			ctx->arcfour_ctx.eSession = 0;
		}
		ctx->arcfour_ctx.initialized = 0;

		ctx->cryptoki_initialized = FALSE;
	}
	return(0);
}
#endif /* !_KERNEL */

static krb5_error_code
init_common (krb5_context *context, krb5_boolean secure, krb5_boolean kdc)
{
	krb5_context ctx = 0;
	krb5_error_code retval;
#ifndef _KERNEL
	struct {
	    krb5_int32 now, now_usec;
	    long pid;
	} seed_data;
	krb5_data seed;
	int tmp;
/* Solaris Kerberos */
#if 0
	/* Verify some assumptions.  If the assumptions hold and the
	   compiler is optimizing, this should result in no code being
	   executed.  If we're guessing "unsigned long long" instead
	   of using uint64_t, the possibility does exist that we're
	   wrong.  */
	{
	    krb5_ui_8 i64;
	    assert(sizeof(i64) == 8);
	    i64 = 0, i64--, i64 >>= 62;
	    assert(i64 == 3);
	    i64 = 1, i64 <<= 31, i64 <<= 31, i64 <<= 1;
	    assert(i64 != 0);
	    i64 <<= 1;
	    assert(i64 == 0);
	}
#endif
	retval = krb5int_initialize_library();
	if (retval)
	    return retval;
#endif

#if (defined(_WIN32))
	/*
	 * Load the krbcc32.dll if necessary.  We do this here so that
	 * we know to use API: later on during initialization.
	 * The context being NULL is ok.
	 */
	krb5_win_ccdll_load(ctx);

	/*
	 * krb5_vercheck() is defined in win_glue.c, and this is
	 * where we handle the timebomb and version server checks.
	 */
	retval = krb5_vercheck();
	if (retval)
		return retval;
#endif

	*context = 0;

	ctx = MALLOC(sizeof(struct _krb5_context));
	if (!ctx)
		return ENOMEM;
	(void) memset(ctx, 0, sizeof(struct _krb5_context));
	ctx->magic = KV5M_CONTEXT;

	ctx->profile_secure = secure;

	if ((retval = krb5_os_init_context(ctx, kdc)))
		goto cleanup;

	/*
	 * Initialize the EF handle, its needed before doing
	 * the random seed.
	 */
	if ((retval = krb5_init_ef_handle(ctx)))
		goto cleanup;

#ifndef _KERNEL

	/* fork safety: set pid to current process ID for later checking */
	ctx->pid = __krb5_current_pid;

	/* Set the default encryption types, possible defined in krb5/conf */
	if ((retval = krb5_set_default_in_tkt_ktypes(ctx, NULL)))
		goto cleanup;

	if ((retval = krb5_set_default_tgs_ktypes(ctx, NULL)))
		goto cleanup;

	if (ctx->tgs_ktype_count != 0) {
		ctx->conf_tgs_ktypes = MALLOC(ctx->tgs_ktype_count *
					sizeof(krb5_enctype));
		if (ctx->conf_tgs_ktypes == NULL)
			goto cleanup;

		(void) memcpy(ctx->conf_tgs_ktypes, ctx->tgs_ktypes,
				sizeof(krb5_enctype) * ctx->tgs_ktype_count);
	}

	ctx->conf_tgs_ktypes_count = ctx->tgs_ktype_count;


	/* initialize the prng (not well, but passable) */
	if ((retval = krb5_crypto_us_timeofday(&seed_data.now, &seed_data.now_usec)))
		goto cleanup;
	seed_data.pid = getpid ();
	seed.length = sizeof(seed_data);
	seed.data = (char *) &seed_data;
	if ((retval = krb5_c_random_seed(ctx, &seed)))
		/*
		 * Solaris Kerberos: we use /dev/urandom, which is
		 * automatically seeded, so its OK if this fails.
		 */
		retval = 0;

	ctx->default_realm = 0;
	profile_get_integer(ctx->profile, "libdefaults", "clockskew",
			    0, 5 * 60, &tmp);
	ctx->clockskew = tmp;

#if 0
	/* Default ticket lifetime is currently not supported */
	profile_get_integer(ctx->profile, "libdefaults", "tkt_lifetime",
			    0, 10 * 60 * 60, &tmp);
	ctx->tkt_lifetime = tmp;
#endif

	/* DCE 1.1 and below only support CKSUMTYPE_RSA_MD4 (2)  */
	/* DCE add kdc_req_checksum_type = 2 to krb5.conf */
	profile_get_integer(ctx->profile, "libdefaults",
			    "kdc_req_checksum_type", 0, CKSUMTYPE_RSA_MD5,
			    &tmp);
	ctx->kdc_req_sumtype = tmp;

	profile_get_integer(ctx->profile, "libdefaults",
			    "ap_req_checksum_type", 0, CKSUMTYPE_RSA_MD5,
			    &tmp);
	ctx->default_ap_req_sumtype = tmp;

	profile_get_integer(ctx->profile, "libdefaults",
			    "safe_checksum_type", 0,
			    CKSUMTYPE_RSA_MD5_DES, &tmp);
	ctx->default_safe_sumtype = tmp;

	profile_get_integer(ctx->profile, "libdefaults",
			    "kdc_default_options", 0,
			    KDC_OPT_RENEWABLE_OK, &tmp);
	ctx->kdc_default_options = tmp;
#define DEFAULT_KDC_TIMESYNC 1
	profile_get_integer(ctx->profile, "libdefaults",
			    "kdc_timesync", 0, DEFAULT_KDC_TIMESYNC,
			    &tmp);
	ctx->library_options = tmp ? KRB5_LIBOPT_SYNC_KDCTIME : 0;

	/*
	 * We use a default file credentials cache of 3.  See
	 * lib/krb5/krb/ccache/file/fcc.h for a description of the
	 * credentials cache types.
	 *
	 * Note: DCE 1.0.3a only supports a cache type of 1
	 * 	DCE 1.1 supports a cache type of 2.
	 */
#define DEFAULT_CCACHE_TYPE 4
	profile_get_integer(ctx->profile, "libdefaults", "ccache_type",
			    0, DEFAULT_CCACHE_TYPE, &tmp);
	ctx->fcc_default_format = tmp + 0x0500;
	ctx->scc_default_format = tmp + 0x0500;
	ctx->prompt_types = 0;
	ctx->use_conf_ktypes = 0;

	ctx->udp_pref_limit = -1;

#endif  /* !_KERNEL */

	*context = ctx;
	return 0;

cleanup:
	krb5_free_context(ctx);
	return retval;
}

void KRB5_CALLCONV
krb5_free_context(krb5_context ctx)
{
	KRB5_LOG0(KRB5_INFO,"krb5_free_context() start");

#ifndef _KERNEL
	krb5_free_ef_handle(ctx);

     if (ctx->conf_tgs_ktypes) {
	 FREE(ctx->conf_tgs_ktypes, sizeof(krb5_enctype) *(ctx->conf_tgs_ktypes_count));
	 ctx->conf_tgs_ktypes = 0;
	 ctx->conf_tgs_ktypes_count = 0;
     }

     krb5_clear_error_message(ctx);

#endif
     krb5_os_free_context(ctx);

     if (ctx->in_tkt_ktypes) {
          FREE(ctx->in_tkt_ktypes, sizeof(krb5_enctype) *(ctx->in_tkt_ktype_count+1) );
	  ctx->in_tkt_ktypes = 0;
     }

     if (ctx->tgs_ktypes) {
          FREE(ctx->tgs_ktypes, sizeof(krb5_enctype) *(ctx->tgs_ktype_count+1));
	  ctx->tgs_ktypes = 0;
     }

     if (ctx->default_realm) {
	  FREE(ctx->default_realm, strlen(ctx->default_realm) + 1);
	  ctx->default_realm = 0;
     }

     if (ctx->ser_ctx_count && ctx->ser_ctx) {
	  FREE(ctx->ser_ctx,sizeof(krb5_ser_entry) * (ctx->ser_ctx_count) );
	  ctx->ser_ctx = 0;
	  ctx->ser_ctx_count = 0;
     }


     ctx->magic = 0;
     FREE(ctx, sizeof(struct _krb5_context));
}

#ifndef _KERNEL
/*
 * Set the desired default ktypes, making sure they are valid.
 */
krb5_error_code
krb5_set_default_in_tkt_ktypes(krb5_context context, const krb5_enctype *ktypes)
{
    krb5_enctype * new_ktypes;
    int i;

    if (ktypes) {
	for (i = 0; ktypes[i]; i++) {
	    if (!krb5_c_valid_enctype(ktypes[i]))
		return KRB5_PROG_ETYPE_NOSUPP;
	}

	/* Now copy the default ktypes into the context pointer */
	if ((new_ktypes = (krb5_enctype *)malloc(sizeof(krb5_enctype) * i)))
	    (void) memcpy(new_ktypes, ktypes, sizeof(krb5_enctype) * i);
	else
	    return ENOMEM;

    } else {
	i = 0;
	new_ktypes = 0;
    }

    if (context->in_tkt_ktypes)
        free(context->in_tkt_ktypes);
    context->in_tkt_ktypes = new_ktypes;
    context->in_tkt_ktype_count = i;
    return 0;
}

static krb5_error_code
get_profile_etype_list(krb5_context context, krb5_enctype **ktypes, char *profstr,
		       unsigned int ctx_count, krb5_enctype *ctx_list)
{
    krb5_enctype *old_ktypes = NULL;

    if (ctx_count) {
	/* application-set defaults */
	if ((old_ktypes =
	     (krb5_enctype *)malloc(sizeof(krb5_enctype) *
				    (ctx_count + 1)))) {
	    (void) memcpy(old_ktypes, ctx_list,
		sizeof(krb5_enctype) * ctx_count);
	    old_ktypes[ctx_count] = 0;
	} else {
	    return ENOMEM;
	}
    } else {
        /*
	   XXX - For now, we only support libdefaults
	   Perhaps this should be extended to allow for per-host / per-realm
	   session key types.
	 */

	char *retval = NULL;
	char *sp, *ep;
	int j, checked_enctypes, count;
	krb5_error_code code;

	code = profile_get_string(context->profile, "libdefaults", profstr,
				  NULL, DEFAULT_ETYPE_LIST, &retval);
	if (code)
	    return code;

	if (!retval)  /* SUNW14resync - just in case */
            return PROF_EINVAL;  /* XXX */

	count = 0;
	sp = retval;
	while (*sp) {
	    for (ep = sp; *ep && (*ep != ',') && !isspace((int) (*ep)); ep++)
		;
	    if (*ep) {
		*ep++ = '\0';
		while (isspace((int) (*ep)) || *ep == ',')
		    *ep++ = '\0';
	    }
	    count++;
	    sp = ep;
	}

	if ((old_ktypes =
	     (krb5_enctype *)malloc(sizeof(krb5_enctype) * (count + 1))) ==
	    (krb5_enctype *) NULL)
	    return ENOMEM;

	sp = retval;
	j = checked_enctypes = 0;
	/*CONSTCOND*/
	while (TRUE) {
	    checked_enctypes++;
	    if (krb5_string_to_enctype(sp, &old_ktypes[j]))
		old_ktypes[j] = (unsigned int)ENCTYPE_UNKNOWN;

	    /*
	     * If 'null' has been specified as a tkt_enctype in
	     * krb5.conf, we need to assign an ENCTYPE_UNKNOWN
	     * value to the corresponding old_ktypes[j] entry.
	     */
	    if (old_ktypes[j] == (unsigned int)ENCTYPE_NULL)
		old_ktypes[j] = (unsigned int)ENCTYPE_UNKNOWN;

	    /* Only include known/valid enctypes in the final list */
	    if (old_ktypes[j] != ENCTYPE_UNKNOWN) {
		j++;
	    }
	    /* If we checked all the enctypes, we are done */
	    if (checked_enctypes == count) {
		break;
	    }

	    /* skip to next token */
	    while (*sp) sp++;
	    while (! *sp) sp++;
	}

	old_ktypes[j] = (krb5_enctype) 0;
	profile_release_string(retval);
    }

    if (old_ktypes[0] == 0) {
	free (old_ktypes);
	*ktypes = 0;
	return KRB5_CONFIG_ETYPE_NOSUPP;
    }

    *ktypes = old_ktypes;
    return 0;
}

krb5_error_code
krb5_get_default_in_tkt_ktypes(krb5_context context, krb5_enctype **ktypes)
{
    return(get_profile_etype_list(context, ktypes, "default_tkt_enctypes",
				  context->in_tkt_ktype_count,
				  context->in_tkt_ktypes));
}

krb5_error_code KRB5_CALLCONV
krb5_set_default_tgs_enctypes (krb5_context context, const krb5_enctype *ktypes)
{
    krb5_enctype * new_ktypes;
    int i;

    if (ktypes) {
	for (i = 0; ktypes[i]; i++) {
	    if (!krb5_c_valid_enctype(ktypes[i]))
		return KRB5_PROG_ETYPE_NOSUPP;
	}

	/* Now copy the default ktypes into the context pointer */
	if ((new_ktypes = (krb5_enctype *)malloc(sizeof(krb5_enctype) * i)))
	    (void) memcpy(new_ktypes, ktypes, sizeof(krb5_enctype) * i);
	else
	    return ENOMEM;

    } else {
	i = 0;
	new_ktypes = (krb5_enctype *)NULL;
    }

    if (context->tgs_ktypes)
        krb5_free_ktypes(context, context->tgs_ktypes);
    context->tgs_ktypes = new_ktypes;
    context->tgs_ktype_count = i;
    return 0;
}

krb5_error_code krb5_set_default_tgs_ktypes
(krb5_context context, const krb5_enctype *etypes)
{
  return (krb5_set_default_tgs_enctypes (context, etypes));
}


/*ARGSUSED*/
void
KRB5_CALLCONV
krb5_free_ktypes (krb5_context context, krb5_enctype *val)
{
    free (val);
}

/*ARGSUSED*/
krb5_error_code
KRB5_CALLCONV
krb5_get_tgs_ktypes(krb5_context context, krb5_const_principal princ, krb5_enctype **ktypes)
{
    if (context->use_conf_ktypes)
	/* This one is set *only* by reading the config file; it's not
	   set by the application.  */
	return(get_profile_etype_list(context, ktypes, "default_tgs_enctypes",
                                      context->conf_tgs_ktypes_count,
                                      context->conf_tgs_ktypes));
    else
	return(get_profile_etype_list(context, ktypes, "default_tgs_enctypes",
				  context->tgs_ktype_count,
				  context->tgs_ktypes));
}

krb5_error_code
krb5_get_permitted_enctypes(krb5_context context, krb5_enctype **ktypes)
{
    return(get_profile_etype_list(context, ktypes, "permitted_enctypes",
				  context->tgs_ktype_count,
				  context->tgs_ktypes));
}

krb5_boolean
krb5_is_permitted_enctype(krb5_context context, krb5_enctype etype)
{
    krb5_enctype *list, *ptr;
    krb5_boolean ret;

    if (krb5_get_permitted_enctypes(context, &list))
	return(0);


    ret = 0;

    for (ptr = list; *ptr; ptr++)
	if (*ptr == etype)
	    ret = 1;

    krb5_free_ktypes (context, list);

    return(ret);
}

static krb5_error_code
copy_ktypes(krb5_context ctx,
	    unsigned int nktypes,
	    krb5_enctype *oldktypes,
	    krb5_enctype **newktypes)
{
    unsigned int i;

    *newktypes = NULL;
    if (!nktypes)
	return 0;

    *newktypes = MALLOC(nktypes * sizeof(krb5_enctype));
    if (*newktypes == NULL)
	return ENOMEM;
    for (i = 0; i < nktypes; i++)
	(*newktypes)[i] = oldktypes[i];
    return 0;
}

krb5_error_code KRB5_CALLCONV
krb5_copy_context(krb5_context ctx, krb5_context *nctx_out)
{
    krb5_error_code ret;
    krb5_context nctx;

    *nctx_out = NULL;
    if (ctx == NULL)
	return EINVAL;		/* XXX */

    nctx = MALLOC(sizeof(*nctx));
    if (nctx == NULL)
	return ENOMEM;

    *nctx = *ctx;

    nctx->in_tkt_ktypes = NULL;
    nctx->in_tkt_ktype_count = 0;
    nctx->tgs_ktypes = NULL;
    nctx->tgs_ktype_count = 0;
    nctx->default_realm = NULL;
    nctx->profile = NULL;
    nctx->db_context = NULL;
    nctx->ser_ctx_count = 0;
    nctx->ser_ctx = NULL;
    nctx->prompt_types = NULL;
    nctx->os_context->default_ccname = NULL;

    memset(&nctx->preauth_plugins, 0, sizeof(nctx->preauth_plugins));
    nctx->preauth_context = NULL;

    memset(&nctx->libkrb5_plugins, 0, sizeof(nctx->libkrb5_plugins));
    nctx->vtbl = NULL;
    nctx->locate_fptrs = NULL;

    memset(&nctx->err, 0, sizeof(nctx->err));

    ret = copy_ktypes(nctx, ctx->in_tkt_ktype_count,
		      ctx->in_tkt_ktypes, &nctx->in_tkt_ktypes);
    if (ret)
	goto errout;
    nctx->in_tkt_ktype_count = ctx->in_tkt_ktype_count;

    ret = copy_ktypes(nctx, ctx->tgs_ktype_count,
		      ctx->tgs_ktypes, &nctx->in_tkt_ktypes);
    if (ret)
	goto errout;
    nctx->tgs_ktype_count = ctx->tgs_ktype_count;

    if (ctx->os_context->default_ccname != NULL) {
	nctx->os_context->default_ccname =
	    strdup(ctx->os_context->default_ccname);
	if (nctx->os_context->default_ccname == NULL) {
	    ret = ENOMEM;
	    goto errout;
	}
    }
    ret = krb5_get_profile(ctx, &nctx->profile);
    if (ret)
	goto errout;

errout:
    if (ret) {
	krb5_free_context(nctx);
    } else {
	*nctx_out = nctx;
    }
    return ret;
}
#endif /* !KERNEL */


