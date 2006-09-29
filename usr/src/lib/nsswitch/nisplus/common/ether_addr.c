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
 * nisplus/ether_addr.c
 *
 * nisplus backend for nsswitch "ethers" database
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * All routines necessary to deal with the ethers NIS+ table.  The table
 * contains mapping between 48 bit ethernet addresses and their corresponding
 * hosts name.  The addresses have an ascii representation of the form
 * "x:x:x:x:x:x" where x is a hex number between 0x00 and 0xff;  the
 * bytes are always in network order.
 */

#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <net/if_arp.h>
#include <netinet/if_ether.h>
#include <strings.h>
#include <nss_dbdefs.h>
#include "nisplus_common.h"
#include "nisplus_tables.h"

static nss_status_t
getbyhost(be, a)
	nisplus_backend_ptr_t	be;
	void			*a;
{
	nss_XbyY_args_t		*argp = (nss_XbyY_args_t *)a;

	return (_nss_nisplus_lookup(be, argp, ETHER_TAG_NAME,
			argp->key.name));
}

static nss_status_t
getbyether(be, a)
	nisplus_backend_ptr_t	be;
	void			*a;
{
	nss_XbyY_args_t		*argp = (nss_XbyY_args_t *)a;
	char	etherstr[18];
	uchar_t	*e = argp->key.ether;

	(void) snprintf(etherstr, 18, "%x:%x:%x:%x:%x:%x",
		*e, *(e + 1), *(e + 2), *(e + 3), *(e + 4), *(e + 5));
	return (_nss_nisplus_lookup(be, argp, ETHER_TAG_ADDR,
			etherstr));
}

/*
 * Convert the ethers nisplus object into files format
 *
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
	char			*addr, *name;
	int			addrlen, namelen;
	struct entry_col	*ecol;

	/*
	 * If we got more than one nis_object, we just ignore it.
	 * Although it should never have happened.
	 *
	 * ASSUMPTION: All the columns in the NIS+ tables are
	 * null terminated.
	 */

	if (obj->zo_data.zo_type != NIS_ENTRY_OBJ ||
		obj->EN_data.en_cols.en_cols_len < ETHER_COL) {
		/* namespace/table/object is curdled */
		return (NSS_STR_PARSE_PARSE);
	}
	ecol = obj->EN_data.en_cols.en_cols_val;

	/* addr */
	__NISPLUS_GETCOL_OR_RETURN(ecol, ETHER_NDX_ADDR, addrlen, addr);

	/* name */
	__NISPLUS_GETCOL_OR_RETURN(ecol, ETHER_NDX_NAME, namelen, name);

	/* skip comment */

	/*
	 * can't use argp->buf.result == NULL test to determine if
	 * the caller is nscd or not.
	 *
	 * exclude trailing null from length
	 */
	be->buflen = addrlen + namelen + 1;
	if ((be->buffer = calloc(1, be->buflen + 1)) == NULL)
		return (NSS_STR_PARSE_PARSE);

	(void) snprintf(be->buffer, be->buflen + 1, "%s %s", addr, name);
#ifdef DEBUG
	(void) fprintf(stdout, "ethers [%s]\n", be->buffer);
	(void) fflush(stdout);
#endif  /* DEBUG */
	return (NSS_STR_PARSE_SUCCESS);
}

static nisplus_backend_op_t ethers_ops[] = {
	_nss_nisplus_destr,
	getbyhost,
	getbyether
};

/*ARGSUSED*/
nss_backend_t *
_nss_nisplus_ethers_constr(dummy1, dummy2, dummy3)
	const char	*dummy1, *dummy2, *dummy3;
{
	return (_nss_nisplus_constr(ethers_ops,
				sizeof (ethers_ops) / sizeof (ethers_ops[0]),
				ETHER_TBLNAME, nis_object2str));
}
