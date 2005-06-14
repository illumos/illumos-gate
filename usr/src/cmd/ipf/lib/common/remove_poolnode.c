/*
 * Copyright (C) 2002 by Darren Reed.
 *
 * See the IPFILTER.LICENCE file for details on licencing.
 *
 * $Id: remove_poolnode.c,v 1.1 2003/04/13 06:40:14 darrenr Exp $
 */

#include <fcntl.h>
#include <sys/ioctl.h>
#include "ipf.h"

#if SOLARIS2 >= 10
#include "ip_lookup.h"
#include "ip_htable.h"
#else
#include "netinet/ip_lookup.h"
#include "netinet/ip_htable.h"
#endif

static int poolfd = -1;


int remove_poolnode(unit, name, node, iocfunc)
int unit;
char *name;
ip_pool_node_t *node;
ioctlfunc_t iocfunc;
{
	ip_pool_node_t pn;
	iplookupop_t op;

	if ((poolfd == -1) && ((opts & OPT_DONOTHING) == 0))
		poolfd = open(IPLOOKUP_NAME, O_RDWR);
	if ((poolfd == -1) && ((opts & OPT_DONOTHING) == 0))
		return -1;

	op.iplo_unit = unit;
	op.iplo_type = IPLT_POOL;
	op.iplo_arg = 0;
	strncpy(op.iplo_name, name, sizeof(op.iplo_name));
	op.iplo_struct = &pn;
	op.iplo_size = sizeof(pn);

	bzero((char *)&pn, sizeof(pn));
	bcopy((char *)&node->ipn_addr, (char *)&pn.ipn_addr,
	      sizeof(pn.ipn_addr));
	bcopy((char *)&node->ipn_mask, (char *)&pn.ipn_mask,
	      sizeof(pn.ipn_mask));
	pn.ipn_info = node->ipn_info;
	strncpy(pn.ipn_name, node->ipn_name, sizeof(pn.ipn_name));

	if ((*iocfunc)(poolfd, SIOCLOOKUPDELNODE, &op)) {
		if ((opts & OPT_DONOTHING) == 0) {
			perror("remove_pool:SIOCLOOKUPDELNODE");
			return -1;
		}
	}

	return 0;
}
