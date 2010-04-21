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
	bcopy(data, iter->addr + iter->offset, bytes);		\
	iter->offset += bytes

void rdsv3_info_register_func(int optname, rdsv3_info_func func);
void rdsv3_info_deregister_func(int optname, rdsv3_info_func func);
int rdsv3_info_getsockopt(struct rsock *sock, int optname, char *optval,
    socklen_t *optlen);

#endif /* _RDSV3_INFO_H */
