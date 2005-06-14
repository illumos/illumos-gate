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
 *	nisplus/ether_addr.c -- "nisplus" backend for nsswitch "ethers" database
 *
 * Copyright 1988-1992,2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * All routines necessary to deal with the ethers NIS+ table.  The table
 * contains mapping between 48 bit ethernet addresses and their corresponding
 * hosts name.  The addresses have an ascii representation of the form
 * "x:x:x:x:x:x" where x is a hex number between 0x00 and 0xff;  the
 * bytes are always in network order.
 */

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

	(void) sprintf(etherstr, "%x:%x:%x:%x:%x:%x",
		*e, *(e + 1), *(e + 2), *(e + 3), *(e + 4), *(e + 5));
	return (_nss_nisplus_lookup(be, argp, ETHER_TAG_ADDR,
			etherstr));
}

/*
 * Place the resulting struct ether_addr from the nis_object structure into
 * argp->buf.result only if argp->buf.result is initialized (not NULL).
 * I.e. it happens for the call ether_hostton.
 *
 * Place the resulting hostname into argp->buf.buffer only if
 * argp->buf.buffer is initialized. I.e. it happens for the call
 * ether_ntohost.
 *
 * Returns NSS_STR_PARSE_{SUCCESS, ERANGE, PARSE}
 */
/*ARGSUSED*/
static int
nis_object2ent(nobj, obj, argp)
	int		nobj;
	nis_object	*obj;
	nss_XbyY_args_t	*argp;
{
	uchar_t	*ether = (uchar_t *)argp->buf.result;
	char	*host = argp->buf.buffer;
	char	*val;
	struct	entry_col *ecol;
	int		len;

	/*
	 * argp->buf.buflen does not make sense for ethers. It
	 * is always set to 0 by the frontend. The caller only
	 * passes a hostname pointer in case of ether_ntohost,
	 * that is assumed to be big enough. For ether_hostton,
	 * the struct ether_addr passed is a fixed size.
	 *
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

	/*
	 * get ether addr
	 *
	 * ether_hostton
	 */
	if (ether) {
		int i;
		unsigned int t[6];

		EC_SET(ecol, ETHER_NDX_ADDR, len, val);
		if (len < 2)
			return (NSS_STR_PARSE_PARSE);
		i = sscanf(val, "%x:%x:%x:%x:%x:%x",
			&t[0], &t[1], &t[2], &t[3], &t[4], &t[5]);
		if (i != ETHERADDRL)
			return (NSS_STR_PARSE_PARSE);
		for (i = 0; i < ETHERADDRL; i++)
			*(ether + i) = (uchar_t)t[i];

	/*
	 * get hostname
	 *
	 * ether_ntohost
	 */
	} else if (host) {
		EC_SET(ecol, ETHER_NDX_NAME, len, val);
		if (len < 2)
			return (NSS_STR_PARSE_PARSE);
		/*
		 * The interface does not let the caller specify how long is
		 * the buffer pointed by host. We make a safe assumption that
		 * the callers will always give MAXHOSTNAMELEN. In any case,
		 * it is the only finite number we can lay our hands on in
		 * case of runaway strings, memory corruption etc.
		 */
		if (len > MAXHOSTNAMELEN)
			return (NSS_STR_PARSE_ERANGE);
		strcpy(host, val);
	}

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
				ETHER_TBLNAME, nis_object2ent));
}
