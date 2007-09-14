/*
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * XXX: I know where to find this header, but it really is using a
 * private interface.  I dont want to export the gss_mechanism
 * structure, so I hide it in a non-published header.  Thats ok,
 * we know where to find it.
 */
#include <mechglueP.h>

#include <gssapiP_krb5.h>
#include <syslog.h>
#include <libintl.h>
/*
 * These are the extern declarations, one group per mechanism. They are
 * contained in the files named <mech>_gssd_extern_srvr.conf.
 */

static OM_uint32
krb5_gss_get_context
	PROTOTYPE((void**));

/*
 * This is the declaration of the mechs_array table for Kerberos V5.
 * If the gss_mechanism structure changes, so should this array!  I
 * told you it was a private interface!
 */

static struct gss_config krb5_mechanism = {
	{9, "\052\206\110\206\367\022\001\002\002"},
	0,			/* context, to be filled */
	krb5_gss_acquire_cred,
	krb5_gss_release_cred,
	krb5_gss_init_sec_context,
	krb5_gss_accept_sec_context,
/* EXPORT DELETE START */ /* CRYPT DELETE START */
	krb5_gss_unseal,
/* EXPORT DELETE END */ /* CRYPT DELETE END */
	krb5_gss_process_context_token,
	krb5_gss_delete_sec_context,
	krb5_gss_context_time,
	krb5_gss_display_status,
	krb5_gss_indicate_mechs,
	krb5_gss_compare_name,
	krb5_gss_display_name,
	krb5_gss_import_name,
	krb5_gss_release_name,
	krb5_gss_inquire_cred,
	krb5_gss_add_cred,
/* EXPORT DELETE START */ /* CRYPT DELETE START */
        krb5_gss_seal,
/* EXPORT DELETE END */ /* CRYPT DELETE END */
	krb5_gss_export_sec_context,
	krb5_gss_import_sec_context,
	krb5_gss_inquire_cred_by_mech,
	krb5_gss_inquire_names_for_mech,
	krb5_gss_inquire_context,
	krb5_gss_internal_release_oid,
	krb5_gss_wrap_size_limit,
	krb5_pname_to_uid,
	krb5_gss_userok,
	NULL,	/* export_name */
/* EXPORT DELETE START */
/* CRYPT DELETE START */
#if 0
/* CRYPT DELETE END */
	krb5_gss_seal,
	krb5_gss_unseal,
/* CRYPT DELETE START */
#endif
/* CRYPT DELETE END */
/* EXPORT DELETE END */
	krb5_gss_sign,
	krb5_gss_verify,
	krb5_gss_store_cred,
	};

#include <k5-int.h>


OM_uint32
krb5_gss_get_context(context)
void **	context;
{
	/* Solaris Kerberos:  the following is a global variable declared
         * and initialized in gssapi_krb5.c */
	/* static krb5_context kg_context = NULL; */
	krb5_error_code errCode = 0;

	if (context == NULL)
		return (GSS_S_FAILURE);
	if (kg_context) {
		*context = kg_context;
		return (GSS_S_COMPLETE);
	}

	if ((errCode = krb5_init_context(&kg_context)))
		goto error;	

	if (((errCode = krb5_ser_context_init(kg_context)) != 0) ||
		((errCode = krb5_ser_auth_context_init(kg_context)) != 0) ||
		((errCode = krb5_ser_ccache_init(kg_context)) != 0) ||
		((errCode = krb5_ser_rcache_init(kg_context)) != 0) ||
		((errCode = krb5_ser_keytab_init(kg_context)) != 0) ||
		((errCode = krb5_ser_context_init(kg_context)) != 0)) {
		krb5_free_context(kg_context);
		kg_context = 0;
		goto error;
	}

	*context = kg_context;
	return (GSS_S_COMPLETE);

error:
	if (errCode != 0) {
		syslog(LOG_ERR,
			dgettext(TEXT_DOMAIN,
			
				"Kerberos mechanism library"
				" initialization error: %s."),
		    error_message((long)errCode));
	}
	return (GSS_S_FAILURE);
}

/*
 * entry point for the gss layer,
 * called "krb5_gss_initialize()" in MIT 1.2.1
 */
gss_mechanism
gss_mech_initialize(oid)
const gss_OID oid;
{
	/* ensure that the requested oid matches our oid */
	if (oid == NULL || !g_OID_equal(oid, &krb5_mechanism.mech_type))
		return (NULL);

	if (krb5_gss_get_context(&(krb5_mechanism.context)) !=
		GSS_S_COMPLETE)
		return (NULL);

	return (&krb5_mechanism);
}
