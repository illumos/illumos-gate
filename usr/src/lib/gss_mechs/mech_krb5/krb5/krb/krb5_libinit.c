/*
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <assert.h>

#include "autoconf.h"
#include "com_err.h"
#include "krb5.h"
#if 0 /* SUNW14resync */
#include "krb5_err.h"
#include "kv5m_err.h"
#include "asn1_err.h"
#include "kdb5_err.h"
#endif

#if defined(_WIN32) || defined(USE_CCAPI)
#include "stdcc.h"
#endif

#include "krb5_libinit.h"
#include "k5-platform.h"
#include "cc-int.h"
#include "kt-int.h"
#include "rc-int.h"
#include "os-proto.h"

/*
 * Initialize the Kerberos v5 library.
 */

MAKE_INIT_FUNCTION(krb5int_lib_init);
MAKE_FINI_FUNCTION(krb5int_lib_fini);

/* Possibly load-time initialization -- mutexes, etc.  */
int krb5int_lib_init(void)
{
    int err;

    krb5int_set_error_info_callout_fn (error_message);

#if !USE_BUNDLE_ERROR_STRINGS
    add_error_table(&et_krb5_error_table);
    add_error_table(&et_kv5m_error_table);
    add_error_table(&et_kdb5_error_table);
    add_error_table(&et_asn1_error_table);
    add_error_table(&et_k524_error_table);
#endif

    err = krb5int_rc_finish_init();
    if (err)
	return err;
    err = krb5int_kt_initialize();
    if (err)
	return err;
    err = krb5int_cc_initialize();
    if (err)
	return err;
    err = k5_mutex_finish_init(&krb5int_us_time_mutex);
    if (err)
	return err;
    return 0;
}

/* Always-delayed initialization -- error table linkage, etc.  */
krb5_error_code krb5int_initialize_library (void)
{
    return CALL_INIT_FUNCTION(krb5int_lib_init);
}

/*
 * Clean up the Kerberos v5 library state
 */

void krb5int_lib_fini(void)
{
    if (!INITIALIZER_RAN(krb5int_lib_init) || PROGRAM_EXITING())
	return;

    krb5int_rc_terminate();
    krb5int_kt_finalize();
    krb5int_cc_finalize();

#if defined(_WIN32) || defined(USE_CCAPI)
    krb5_stdcc_shutdown();
#endif

#if !USE_BUNDLE_ERROR_STRINGS
    remove_error_table(&et_krb5_error_table);
    remove_error_table(&et_kv5m_error_table);
    remove_error_table(&et_kdb5_error_table);
    remove_error_table(&et_asn1_error_table);
    remove_error_table(&et_k524_error_table);
#endif
    krb5int_set_error_info_callout_fn (0);
}

/* Still exists because it went into the export list on Windows.  But
   since the above function should be invoked at unload time, we don't
   actually want to do anything here.  */
void krb5int_cleanup_library (void)
{
}
