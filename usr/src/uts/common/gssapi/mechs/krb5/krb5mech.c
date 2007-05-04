/*
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * A module for Kerberos V5  security mechanism.
 *
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

char _depends_on[] = "misc/kgssapi crypto/md5";

#include <sys/types.h>
#include <sys/modctl.h>
#include <sys/errno.h>
#include <mechglueP.h>
#include <gssapiP_krb5.h>
#include <gssapi_err_generic.h>
#include <gssapi/kgssapi_defs.h>
#include <sys/debug.h>
#include <k5-int.h>

OM_uint32 krb5_gss_get_context(void ** context);

extern krb5_error_code krb5_ser_context_init
	(krb5_context);

extern	krb5_error_code	krb5_ser_auth_context_init
	(krb5_context);

static	struct	gss_config krb5_mechanism =
	{{9, "\052\206\110\206\367\022\001\002\002"},
	NULL,	/* context */
	NULL,	/* next */
	TRUE,	/* uses_kmod */
/* EXPORT DELETE START */ /* CRYPT DELETE START */
	krb5_gss_unseal,
/* EXPORT DELETE END */ /* CRYPT DELETE END */
	krb5_gss_delete_sec_context,
/* EXPORT DELETE START */ /* CRYPT DELETE START */
	krb5_gss_seal,
/* EXPORT DELETE END */ /* CRYPT DELETE END */
	krb5_gss_import_sec_context,
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
};

static gss_mechanism
	gss_mech_initialize()
{
	(void) krb5_gss_get_context(&(krb5_mechanism.context));
	return (&krb5_mechanism);
}


/*
 * Module linkage information for the kernel.
 */
extern struct mod_ops mod_miscops;

static struct modlmisc modlmisc = {
	&mod_miscops, "Krb5 GSS mechanism"
};

static struct modlinkage modlinkage = {
	MODREV_1,
	(void *)&modlmisc,
	NULL
};


static int krb5_fini_code = EBUSY;

int
_init()
{
	int retval;
	gss_mechanism mech, tmp;

	if ((retval = mod_install(&modlinkage)) != 0)
		return (retval);

	mech = gss_mech_initialize();

	mutex_enter(&__kgss_mech_lock);
	tmp = __kgss_get_mechanism(&mech->mech_type);
	if (tmp != NULL) {

		KRB5_LOG0(KRB5_INFO,
			"KRB5 GSS mechanism: mechanism already in table.\n");

		if (tmp->uses_kmod == TRUE) {
			KRB5_LOG0(KRB5_INFO, "KRB5 GSS mechanism: mechanism "
				"table supports kernel operations!\n");
		}
		/*
		 * keep us loaded, but let us be unloadable. This
		 * will give the developer time to trouble shoot
		 */
		krb5_fini_code = 0;
	} else {
		__kgss_add_mechanism(mech);
		ASSERT(__kgss_get_mechanism(&mech->mech_type) == mech);
	}
	mutex_exit(&__kgss_mech_lock);

	return (0);
}

int
_fini()
{
	int ret = krb5_fini_code;

	if (ret == 0) {
		ret = (mod_remove(&modlinkage));
	}
	return (ret);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

OM_uint32
krb5_gss_get_context(context)
void **	context;
{
	OM_uint32 major_status = 0;

	mutex_lock(&krb5_mutex);
	if (context == NULL)
	{
		major_status = GSS_S_FAILURE;
		goto unlock;
	}
	if (kg_context) {
		*context = kg_context;
		major_status = GSS_S_COMPLETE;
		goto unlock;
	}

	if (krb5_init_context(&kg_context))
	{
		major_status = GSS_S_FAILURE;
		goto unlock;
	}
	if (krb5_ser_auth_context_init(kg_context))
	{
		kg_context = 0;
		major_status = GSS_S_FAILURE;
		goto unlock;
	}

	*context = kg_context;
unlock:
	mutex_unlock(&krb5_mutex);
	return (major_status);
}
