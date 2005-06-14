/*
 * Copyright (C) 2002 by Darren Reed.
 *
 * See the IPFILTER.LICENCE file for details on licencing.
 *
 * $Id: load_pool.c,v 1.12 2003/04/26 04:55:11 darrenr Exp $
 */

#include <fcntl.h>
#include <sys/ioctl.h>
#include "ipf.h"
#if SOLARIS2 >= 10
#include "ip_lookup.h"
#include "ip_pool.h"
#else
#include "netinet/ip_lookup.h"
#include "netinet/ip_pool.h"
#endif

static int poolfd = -1;


int load_pool(plp, iocfunc)
ip_pool_t *plp;
ioctlfunc_t iocfunc;
{
	iplookupop_t op;
	ip_pool_node_t *a;
	ip_pool_t pool;

	if ((poolfd == -1) && ((opts & OPT_DONOTHING) == 0))
		poolfd = open(IPLOOKUP_NAME, O_RDWR);
	if ((poolfd == -1) && ((opts & OPT_DONOTHING) == 0))
		return -1;

	op.iplo_unit = plp->ipo_unit;
	op.iplo_type = IPLT_POOL;
	op.iplo_arg = 0;
	strncpy(op.iplo_name, plp->ipo_name, sizeof(op.iplo_name));
	op.iplo_size = sizeof(pool);
	op.iplo_struct = &pool;
	bzero((char *)&pool, sizeof(pool));
	strncpy(pool.ipo_name, plp->ipo_name, sizeof(pool.ipo_name));
	if (*plp->ipo_name == '\0')
		op.iplo_arg |= IPOOL_ANON;

	if ((*iocfunc)(poolfd, SIOCLOOKUPADDTABLE, &op))
		if ((opts & OPT_DONOTHING) == 0) {
			perror("load_pool:SIOCLOOKUPADDTABLE");
			return -1;
		}

	if ((opts & OPT_VERBOSE) != 0) {
		pool.ipo_list = plp->ipo_list;
		printpool(&pool, bcopywrap, opts);
		pool.ipo_list = NULL;
	}

	for (a = plp->ipo_list; a != NULL; a = a->ipn_next)
		load_poolnode(plp->ipo_unit, plp->ipo_name, a, iocfunc);

	return 0;
}
