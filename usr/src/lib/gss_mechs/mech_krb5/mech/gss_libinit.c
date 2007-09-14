/*
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <assert.h>

#include "gssapi_err_generic.h"
#include "gssapi_err_krb5.h"
#include "gssapiP_krb5.h"

#include "gss_libinit.h"
#include "k5-platform.h"

#include "mglueP.h"

/*
 * Initialize the GSSAPI library.
 */

MAKE_INIT_FUNCTION(gssint_lib_init);
MAKE_FINI_FUNCTION(gssint_lib_fini);

int gssint_lib_init(void)
{
    int err;

#ifdef SHOW_INITFINI_FUNCS
    printf("gssint_lib_init\n");
#endif

#if !USE_BUNDLE_ERROR_STRINGS
    add_error_table(&et_k5g_error_table);
    add_error_table(&et_ggss_error_table);
#endif
#if 0 /* SUNW15resync */
    err = gssint_mechglue_init();
    if (err)
	return err;
#endif
    err = k5_mutex_finish_init(&gssint_krb5_keytab_lock);
    if (err)
	return err;
    err = k5_key_register(K5_KEY_GSS_KRB5_SET_CCACHE_OLD_NAME, free);
    if (err)
	return err;
    err = k5_key_register(K5_KEY_GSS_KRB5_CCACHE_NAME, free);
    if (err)
	return err;
#if 0 /* SUNW15resync - revisit when mech resynced w/1.5 */
    err = k5_mutex_finish_init(&kg_kdc_flag_mutex);
    if (err)
	return err;
#endif
    return k5_mutex_finish_init(&kg_vdb.mutex);
}

void gssint_lib_fini(void)
{
    if (!INITIALIZER_RAN(gssint_lib_init) || PROGRAM_EXITING()) {
#ifdef SHOW_INITFINI_FUNCS
	printf("gssint_lib_fini: skipping\n");
#endif
	return;
    }
#ifdef SHOW_INITFINI_FUNCS
    printf("gssint_lib_fini\n");
#endif
#if !USE_BUNDLE_ERROR_STRINGS
    remove_error_table(&et_k5g_error_table);
    remove_error_table(&et_ggss_error_table);
#endif
    k5_key_delete(K5_KEY_GSS_KRB5_SET_CCACHE_OLD_NAME);
    k5_key_delete(K5_KEY_GSS_KRB5_CCACHE_NAME);
    k5_mutex_destroy(&kg_vdb.mutex);
#if 0 /* SUNW15resync - revisit when mech resynced w/1.5 */
    k5_mutex_destroy(&kg_kdc_flag_mutex);
#endif
    k5_mutex_destroy(&gssint_krb5_keytab_lock);
#if 0 /* SUNW15resync */
    gssint_mechglue_fini();
#endif
}

OM_uint32 gssint_initialize_library (void)
{
    return CALL_INIT_FUNCTION(gssint_lib_init);
}
