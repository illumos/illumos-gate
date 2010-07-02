/*
 * This file contains definitions imported from the OFED rds header info.h.
 * Oracle elects to have and use the contents of info.h under and
 * governed by the OpenIB.org BSD license.
 */

/*
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 */

#ifndef _RDSV3_INFO_H
#define	_RDSV3_INFO_H

struct rdsv3_info_iterator {
	char *addr;
	unsigned long offset;
};

struct rdsv3_info_lengths {
	unsigned int	nr;
	unsigned int	each;
};

struct rdsv3_sock;

/*
 * These functions must fill in the fields of @lens to reflect the size
 * of the available info source.  If the snapshot fits in @len then it
 * should be copied using @iter.  The caller will deduce if it was copied
 * or not by comparing the lengths.
 */
typedef void (*rdsv3_info_func)(struct rsock *sock, unsigned int len,
    struct rdsv3_info_iterator *iter,
    struct rdsv3_info_lengths *lens);

#define	rdsv3_info_copy(iter, data, bytes)			\
	(void) ddi_copyout(data, iter->addr + iter->offset, bytes, 0);	\
	iter->offset += bytes

void rdsv3_info_register_func(int optname, rdsv3_info_func func);
void rdsv3_info_deregister_func(int optname, rdsv3_info_func func);
int rdsv3_info_ioctl(struct rsock *sock, int optname, char *optval,
    int32_t *rvalp);

#endif /* _RDSV3_INFO_H */
