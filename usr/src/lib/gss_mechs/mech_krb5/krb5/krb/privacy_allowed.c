/*
 * Copyright (c) 1998 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "k5-int.h"
#include "auth_con.h"

krb5_boolean
krb5_privacy_allowed(void)
{
#ifdef	KRB5_NO_PRIVACY
	return (FALSE);
#else
	return (TRUE);
#endif
}
