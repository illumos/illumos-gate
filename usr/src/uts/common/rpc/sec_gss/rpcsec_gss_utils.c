/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright 1996-1997,2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/systm.h>
#include <sys/errno.h>
#include <sys/cmn_err.h>
#include <gssapi/gssapi.h>
#include <rpc/rpc.h>
#include <rpc/rpcsec_defs.h>

#ifdef RPCGSS_DEBUG
/*
 * Kernel rpcsec_gss module debugging aid. The global variable "rpcgss_log"
 * is a bit mask which allows various types of debugging messages to be printed
 * out.
 *
 *	  rpcgss_log & 1	will cause actual failures to be printed.
 *	  rpcgss_log & 2 	will cause informational messages to be
 *			printed on the client side of rpcsec_gss.
 *	  rpcgss_log & 4	will cause informational messages to be
 *			printed on the server side of rpcsec_gss.
 *	  rpcgss_log & 8	will cause informational messages to be
 *			printed on both client and server side of rpcsec_gss.
 */

uint_t rpcgss_log = 0;

#endif /* RPCGSS_DEBUG */

/*
 * Internal utility routines.
 */

/*
 *  Duplicate a gss_OID value.
 */
void
__rpc_gss_dup_oid(gss_OID oid, gss_OID *ret)
{
	gss_OID tmp;

	if (oid == GSS_C_NULL_OID || oid->length == 0) {
		*ret = NULL;
		return;
	}

	tmp = (gss_OID) kmem_alloc(sizeof (gss_OID_desc), KM_SLEEP);
	if (tmp) {
	    tmp->elements = kmem_alloc((oid->length), KM_SLEEP);
	    bcopy((char *)oid->elements, (char *)tmp->elements, oid->length);
	    tmp->length = oid->length;
	    *ret = tmp;
	} else {
	    *ret = NULL;
	}
}

/*
 *  Check if 2 gss_OID are the same.
 */
bool_t
__rpc_gss_oids_equal(oid1, oid2)
	gss_OID	oid1, oid2;
{
	if ((oid1->length == 0) && (oid2->length == 0))
		return (TRUE);

	if (oid1->length != oid2->length)
		return (FALSE);

	return (bcmp(oid1->elements, oid2->elements, oid1->length) == 0);
}

void
__rpc_gss_convert_name(principal, name, name_type)
	rpc_gss_principal_t	principal;
	gss_buffer_desc		*name;
	gss_OID			*name_type;
{
	char			*cp;

	cp = principal->name;
	if (*(int *)cp == 0)
		*name_type = GSS_C_NULL_OID;
	else {
		(*name_type)->length = *(int *)cp;
		(*name_type)->elements = (void *)(cp + sizeof (int));
	}
	cp += RNDUP(*(int *)cp) + sizeof (int);
	if ((name->length = *(int *)cp) == 0)
		name->value = NULL;
	else
		name->value = cp + sizeof (int);
}

/*
 *  Make a client principal name from a flat exported gss name.
 */
bool_t
__rpc_gss_make_principal(principal, name)
	rpc_gss_principal_t	*principal;
	gss_buffer_desc		*name;
{
	int			plen;
	char			*s;

	RPCGSS_LOG(8, "name-length = %lu\n", name->length);
	RPCGSS_LOG(8, "name-value = 0x%p\n", (void *)name->value);

	plen = RNDUP(name->length) + sizeof (int);
	(*principal) = (rpc_gss_principal_t)kmem_alloc(plen, KM_SLEEP);
	if ((*principal) == NULL)
		return (FALSE);
	bzero((caddr_t)(*principal), plen);
	(*principal)->len = RNDUP(name->length);
	s = (*principal)->name;
	bcopy(name->value, s, name->length);
	return (TRUE);
}


/*
 * Make a copy of a principal name.
 */
rpc_gss_principal_t
__rpc_gss_dup_principal(principal)
	rpc_gss_principal_t	principal;
{
	rpc_gss_principal_t	pdup;
	int			len;

	if (principal == NULL)
		return (NULL);
	len = principal->len + sizeof (int);
	if ((pdup = (rpc_gss_principal_t)mem_alloc(len)) == NULL)
		return (NULL);
	pdup->len = len;
	bcopy(principal->name, pdup->name, len);
	return (pdup);
}

/*
 * Returns highest and lowest versions of RPCSEC_GSS flavor supported.
 */
bool_t
rpc_gss_get_versions(vers_hi, vers_lo)
	uint_t	*vers_hi;
	uint_t	*vers_lo;
{
	*vers_hi = RPCSEC_GSS_VERSION;
	*vers_lo = RPCSEC_GSS_VERSION;
	return (TRUE);
}

void
rpc_gss_display_status(major, minor, mech_type,
		uid, gss_function_name)
	OM_uint32	major, minor;
	gss_OID		mech_type;
	uid_t		uid;
	char		*gss_function_name;

{
	int message_context;
	int major_stat;
	uint_t minor_stat;
	gss_buffer_desc status_string;

	/*
	 * Before we return let us see
	 * whether we can log more meaningful error
	 * string using kgss_display_status
	 * If we can not just log the gssstat in hex
	 * and return.
	 */
	message_context = 0;

	/*
	 * First get the status string out of gss_major_code
	 */

	do {
	    major_stat = kgss_display_status(&minor_stat, major,
		GSS_C_GSS_CODE, mech_type,
		&message_context, &status_string, uid);
		/*
		 * If we failed just log the original error codes
		 */
	    if (major_stat != GSS_S_COMPLETE &&
		major != GSS_S_CONTINUE_NEEDED) {

		RPCGSS_LOG1(1, "%s GSS major error 0x%x\n",
			gss_function_name, major);
		RPCGSS_LOG1(1, "%s GSS minor error 0x%x\n",
			gss_function_name, minor);

		return;
	    } else {
		RPCGSS_LOG1(1, "%s GSS Error %s\n",
			(char *)gss_function_name,
			(char *)status_string.value);
		(void) gss_release_buffer(&minor_stat, &status_string);
	    }
	} while (message_context != 0);
	/*
	 * Now get the status string out of gss_minor_code
	 * This is mechanism specific error which is most
	 * useful
	 */
	message_context = 0;
	do {
	    major_stat = kgss_display_status(&minor_stat, minor,
		GSS_C_MECH_CODE, mech_type,
		&message_context, &status_string, uid);
	    if (major_stat != GSS_S_COMPLETE &&
		major_stat != GSS_S_CONTINUE_NEEDED) {
		RPCGSS_LOG1(1, "%s GSS minor error 0x%x\n",
		gss_function_name, minor);
		return;
	    } else {
		RPCGSS_LOG1(1,
		    "%s GSS Minor Error %s\n",
		    (char *)gss_function_name, (char *)status_string.value);
		(void) gss_release_buffer(&minor_stat,
		    &status_string);
	    }
	} while (message_context != 0);
}
