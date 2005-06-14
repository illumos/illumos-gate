/*
 * Copyright (C) 2002 by Darren Reed.
 *
 * See the IPFILTER.LICENCE file for details on licencing.
 *
 * $Id: load_hashnode.c,v 1.2 2003/04/26 04:55:11 darrenr Exp $
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

static int hashfd = -1;


int load_hashnode(unit, name, node, iocfunc)
int unit;
char *name;
iphtent_t *node;
ioctlfunc_t iocfunc;
{
	iplookupop_t op;
	iphtent_t ipe;

	if ((hashfd == -1) && ((opts & OPT_DONOTHING) == 0))
		hashfd = open(IPLOOKUP_NAME, O_RDWR);
	if ((hashfd == -1) && ((opts & OPT_DONOTHING) == 0))
		return -1;

	op.iplo_type = IPLT_HASH;
	op.iplo_unit = unit;
	op.iplo_arg = 0;
	op.iplo_size = sizeof(ipe);
	op.iplo_struct = &ipe;
	strncpy(op.iplo_name, name, sizeof(op.iplo_name));

	bzero((char *)&ipe, sizeof(ipe));
	bcopy((char *)&node->ipe_addr, (char *)&ipe.ipe_addr,
	      sizeof(ipe.ipe_addr));
	bcopy((char *)&node->ipe_mask, (char *)&ipe.ipe_mask,
	      sizeof(ipe.ipe_mask));
	bcopy((char *)&node->ipe_group, (char *)&ipe.ipe_group,
	      sizeof(ipe.ipe_group));

	if ((*iocfunc)(hashfd, SIOCLOOKUPADDNODE, &op))
		if (!(opts & OPT_DONOTHING)) {
			perror("load_hash:SIOCLOOKUPADDNODE");
			return -1;
		}
	return 0;
}
