/*
 * Copyright (C) 2002 by Darren Reed.
 *
 * See the IPFILTER.LICENCE file for details on licencing.
 *
 * $Id: load_poolnode.c,v 1.2 2003/04/26 04:55:11 darrenr Exp $
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


int load_poolnode(role, name, node, iocfunc)
int role;
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

	op.iplo_unit = role;
	op.iplo_type = IPLT_POOL;
	op.iplo_arg = 0;
	op.iplo_struct = &pn;
	op.iplo_size = sizeof(pn);
	strncpy(op.iplo_name, name, sizeof(op.iplo_name));

	bzero((char *)&pn, sizeof(pn));
	bcopy((char *)&node->ipn_addr, (char *)&pn.ipn_addr,
	      sizeof(pn.ipn_addr));
	bcopy((char *)&node->ipn_mask, (char *)&pn.ipn_mask,
	      sizeof(pn.ipn_mask));
	pn.ipn_info = node->ipn_info;
	strncpy(pn.ipn_name, node->ipn_name, sizeof(pn.ipn_name));

	if ((*iocfunc)(poolfd, SIOCLOOKUPADDNODE, &op)) {
		if ((opts & OPT_DONOTHING) == 0) {
			perror("load_pool:SIOCLOOKUPADDNODE");
			return -1;
		}
	}

	return 0;
}
