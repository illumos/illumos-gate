/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 *	nisplus/netmasks.c -- "nisplus" backend for nsswitch "netmasks" database
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * All routines necessary to deal with the netmasks NIS+ table.  The table
 * contains mapping between 32 bit network internet addresses and their
 * corresponding 32 bit netmask internet addresses. The addresses are in
 * dotted internet notation.
 */

#include <stdlib.h>
#include <strings.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <nss_dbdefs.h>
#include "nisplus_common.h"
#include "nisplus_tables.h"

static nss_status_t
getbynet(be, a)
	nisplus_backend_ptr_t	be;
	void			*a;
{
	nss_XbyY_args_t		*argp = (nss_XbyY_args_t *)a;
	return (_nss_nisplus_lookup(be, argp, NETMASK_TAG_ADDR,
	    argp->key.name));
}

/*
 * Convert nisplus object to files format
 * Returns NSS_STR_PARSE_{SUCCESS, ERANGE, PARSE}
 */
/*ARGSUSED*/
static int
nis_object2str(nobj, obj, be, argp)
	int			nobj;
	nis_object		*obj;
	nisplus_backend_ptr_t	be;
	nss_XbyY_args_t		*argp;
{
	char			*mask;
	int			masklen;
	struct in_addr		addr;
	struct entry_col	*ecol;

	/*
	 * If we got more than one nis_object, we just ignore it.
	 * Although it should never have happened.
	 *
	 * ASSUMPTION: All the columns in the NIS+ tables are
	 * null terminated.
	 */

	if (obj->zo_data.zo_type != NIS_ENTRY_OBJ ||
		obj->EN_data.en_cols.en_cols_len < NETMASK_COL) {
		/* namespace/table/object is curdled */
		return (NSS_STR_PARSE_PARSE);
	}
	ecol = obj->EN_data.en_cols.en_cols_val;

	/* getnetmaskbynet */
	__NISPLUS_GETCOL_OR_RETURN(ecol, NETMASK_NDX_MASK, masklen, mask);
	/* addr is an IPv4 address, therefore will always be 32bits */
	addr.s_addr = inet_addr(mask);
	if (addr.s_addr == INADDR_NONE)
		return (NSS_STR_PARSE_PARSE);

	/* exclude trailing null from length */
	be->buflen = masklen;
	if ((be->buffer = calloc(1, be->buflen + 1)) == NULL)
		return (NSS_STR_PARSE_PARSE);
	(void) strlcpy(be->buffer, mask, be->buflen + 1);

#ifdef DEBUG
	(void) fprintf(stdout, "netmasks [%s]\n", be->buffer);
	(void) fflush(stdout);
#endif  /* DEBUG */
	return (NSS_STR_PARSE_SUCCESS);
}

static nisplus_backend_op_t netmasks_ops[] = {
	_nss_nisplus_destr,
	getbynet
};

/*ARGSUSED*/
nss_backend_t *
_nss_nisplus_netmasks_constr(dummy1, dummy2, dummy3)
	const char	*dummy1, *dummy2, *dummy3;
{
	return (_nss_nisplus_constr(netmasks_ops,
	    sizeof (netmasks_ops) / sizeof (netmasks_ops[0]), NETMASK_TBLNAME,
	    nis_object2str));
}
