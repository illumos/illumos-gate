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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/types.h>
#include <sys/rwlock.h>
#include <mdb/mdb_modapi.h>
#include <sys/queue.h>
#include <sys/neti.h>


/*
 * PROT_LENGTH is the max length. If the true length is bigger
 * it is truncated.
 */
#define	PROT_LENGTH 32

/*
 * List pfhooks netinfo information.
 */
/*ARGSUSED*/
int
netinfolist(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	struct neti_stack *nts;
	struct netd_listhead nlh;
	struct net_data nd, *p;
	char str[PROT_LENGTH];

	if (argc)
		return (DCMD_USAGE);

	if (mdb_vread((void *)&nts, sizeof (nts),
	    (uintptr_t)(addr + OFFSETOF(netstack_t, netstack_neti))) == -1) {
		mdb_warn("couldn't read netstack_neti");
		return (DCMD_ERR);
	}

	if (mdb_vread((void *)&nlh, sizeof (nlh), (uintptr_t)((uintptr_t)nts +
	    OFFSETOF(neti_stack_t, nts_netd_head))) == -1) {
		mdb_warn("couldn't read netd list head");
		return (DCMD_ERR);
	}
	mdb_printf("%<u>%?s %?s %10s%</u>\n",
	    "ADDR(netinfo)", "ADDR(hookevent)", "netinfo");
	p = LIST_FIRST(&nlh);
	while (p) {
		if (mdb_vread((void *)&nd, sizeof (nd), (uintptr_t)p) == -1) {
			mdb_warn("couldn't read netinfo at %p", p);
			return (DCMD_ERR);
		}
		if (!nd.netd_info.netp_name) {
			mdb_warn("netinfo at %p has null protocol",
			    nd.netd_info.netp_name);
			return (DCMD_ERR);
		}
		if (mdb_readstr((char *)str, sizeof (str),
		    (uintptr_t)nd.netd_info.netp_name) == -1) {
			mdb_warn("couldn't read protocol at %p",
			    nd.netd_info.netp_name);
			return (DCMD_ERR);
		}

		mdb_printf("%0?p %0?p %10s\n",
		    (char *)p + (uintptr_t)&((struct net_data *)0)->netd_info,
		    nd.netd_hooks, str);

		p = LIST_NEXT(&nd, netd_list);
	}

	return (DCMD_OK);
}

static const mdb_dcmd_t dcmds[] = {
	{ "netinfolist", "", "display netinfo information",
		netinfolist, NULL },
	{ NULL }
};

static const mdb_modinfo_t modinfo = { MDB_API_VERSION, dcmds };

const mdb_modinfo_t *
_mdb_init(void)
{
	return (&modinfo);
}
