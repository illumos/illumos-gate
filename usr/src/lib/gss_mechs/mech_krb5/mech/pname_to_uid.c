/*
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 *  krb5 mechanism specific routine for pname_to_uid
 */

#include <gssapiP_krb5.h>
#include <stdlib.h>
#include <string.h>
#include <pwd.h>

/*
 * This functions supplements the gsscred table.
 *
 * First, it provides the mapping for root principal
 * entries.  The uid mapping returned is that of 0.
 * The name must be of the form root/... or root@...
 * or host/... (no host@... mapped to 0 cuz host could
 * be the name of a normal user)
 * or in Kerberos terms, the first component must be root or host.
 *
 * Second, it provides the mapping for normal user principals
 * using the passwd tbl.  Thus, the gsscred table is not normally
 * needed for the krb5 mech (though libgss will use it if this
 * routine fails).
 *
 * GSS_S_COMPLETE is returned on success.
 * GSS_S_FAILURE is returned on failure.
 */
OM_uint32
krb5_pname_to_uid(ctxt, minor,  pname, uidOut)
void * ctxt;
OM_uint32 *minor;
const gss_name_t pname;
uid_t *uidOut;
{
	krb5_context context = (krb5_context)ctxt;
	char lname[256];
	struct passwd	*pw;
	krb5_error_code stat;

	mutex_lock(&krb5_mutex);
	if (! kg_validate_name(pname))
	{
		mutex_unlock(&krb5_mutex);
		*minor = (OM_uint32) G_VALIDATE_FAILED;
		return (GSS_S_CALL_BAD_STRUCTURE|GSS_S_BAD_NAME);
	}

	stat = krb5_aname_to_localname(context, (krb5_principal) pname,
				    sizeof (lname), lname);
	mutex_unlock(&krb5_mutex);

	if (stat)
		return (GSS_S_FAILURE);

	/* get the uid from the passwd tbl */
	if (pw = getpwnam(lname))
	{
		*uidOut = pw->pw_uid;
		return (GSS_S_COMPLETE);
	}

	return (GSS_S_FAILURE);
} /* krb5_pname_to_uid */
