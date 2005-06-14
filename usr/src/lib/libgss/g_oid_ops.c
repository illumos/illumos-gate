/*
 * Copyright (c) 1996,1997, by Sun Microsystems, Inc.
 * All rights reserved.
 */
#pragma ident	"%Z%%M%	%I%	%E% SMI"
/*
 * lib/gssapi/mechglue/g_oid_ops.c
 *
 * Copyright 1995 by the Massachusetts Institute of Technology.
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
 * permission.  M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 *
 */

/*
 * oid_ops.c - GSS-API V2 interfaces to manipulate OIDs
 */

#include <mechglueP.h>

/*
 * gss_release_oid has been moved to g_initialize, becasue it requires access
 * to the mechanism list.  All functions requiring direct access to the
 * mechanism list are now in g_initialize.c
 */

OM_uint32
gss_create_empty_oid_set(minor_status, oid_set)
	OM_uint32		*minor_status;
	gss_OID_set		*oid_set;
{
		return (generic_gss_create_empty_oid_set(minor_status,
				oid_set));
}

OM_uint32
gss_add_oid_set_member(minor_status, member_oid, oid_set)
	OM_uint32		*minor_status;
	const gss_OID		member_oid;
	gss_OID_set		*oid_set;
{
	return (generic_gss_add_oid_set_member(minor_status, member_oid,
				oid_set));
}

OM_uint32
gss_test_oid_set_member(minor_status, member, set, present)
	OM_uint32		*minor_status;
	const gss_OID		member;
	const gss_OID_set	set;
	int			*present;
{
	return (generic_gss_test_oid_set_member(minor_status, member, set,
				present));
}

OM_uint32
gss_oid_to_str(minor_status, oid, oid_str)
	OM_uint32		*minor_status;
	const gss_OID		oid;
	gss_buffer_t		oid_str;
{
	return (generic_gss_oid_to_str(minor_status, oid, oid_str));
}

OM_uint32
gss_str_to_oid(minor_status, oid_str, oid)
	OM_uint32		*minor_status;
	const gss_buffer_t	oid_str;
	gss_OID			*oid;
{
	return (generic_gss_str_to_oid(minor_status, oid_str, oid));
}
