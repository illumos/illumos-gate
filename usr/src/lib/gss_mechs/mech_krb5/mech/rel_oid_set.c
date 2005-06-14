/*
 * Copyright 1996-2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 *  glue routine for gss_release_oid_set
 */

#include <gssapiP_generic.h>

#include <stdio.h>
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif

OM_uint32
generic_gss_release_oid_set (minor_status,
			     set)
     OM_uint32 *		minor_status;
     gss_OID_set *		set;
{
    size_t i;
    if (minor_status)
	*minor_status = 0;

    if (set == NULL)
	return(GSS_S_COMPLETE);

    if (*set == GSS_C_NULL_OID_SET)
	return(GSS_S_COMPLETE);

    for (i=0; i<(*set)->count; i++)
	free((*set)->elements[i].elements);

    free((*set)->elements);
    free(*set);

    *set = GSS_C_NULL_OID_SET;

    return(GSS_S_COMPLETE);
}
