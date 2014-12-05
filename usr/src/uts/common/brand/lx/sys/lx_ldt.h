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
 * Copyright 2014 Joyent, Inc.  All rights reserved.
 */

#ifndef _SYS_LINUX_LDT_H
#define	_SYS_LINUX_LDT_H

#include <sys/segments.h>

#ifdef	__cplusplus
extern "C" {
#endif

struct ldt_info {
	uint_t	entry_number;
	uint_t	base_addr;
	uint_t	limit;
	uint_t	seg_32bit:1,
		contents:2,
		read_exec_only:1,
		limit_in_pages:1,
		seg_not_present:1,
		useable:1;
};

#define	LDT_INFO_EMPTY(info)						\
	((info)->base_addr == 0 && (info)->limit == 0 &&		\
	(info)->contents == 0 && (info)->read_exec_only == 1 &&		\
	(info)->seg_32bit == 0 && (info)->limit_in_pages == 0 &&	\
	(info)->seg_not_present == 1 && (info)->useable == 0)

#if defined(__amd64)
#define	SETMODE(desc)	(desc)->usd_long = SDP_SHORT;
#else
#define	SETMODE(desc)
#endif

#define	LDT_INFO_TO_DESC(info, desc)	{				\
	USEGD_SETBASE(desc, (info)->base_addr);				\
	USEGD_SETLIMIT(desc, (info)->limit);				\
	(desc)->usd_type = ((info)->contents << 2) | 			\
	    ((info)->read_exec_only ^ 1) << 1 | 0x10;			\
	(desc)->usd_dpl = SEL_UPL;					\
	(desc)->usd_p = (info)->seg_not_present ^ 1;			\
	(desc)->usd_def32 = (info)->seg_32bit;				\
	(desc)->usd_gran = (info)->limit_in_pages;			\
	(desc)->usd_avl = (info)->useable;				\
	SETMODE(desc);							\
}

#define	DESC_TO_LDT_INFO(desc, info)	{				\
	bzero((info), sizeof (*(info)));				\
	(info)->base_addr = USEGD_GETBASE(desc);			\
	(info)->limit = USEGD_GETLIMIT(desc);				\
	(info)->seg_not_present = (desc)->usd_p ^ 1;			\
	(info)->contents = ((desc)->usd_type >> 2) & 3;			\
	(info)->read_exec_only = (((desc)->usd_type >> 1) & 1) ^ 1;	\
	(info)->seg_32bit = (desc)->usd_def32;				\
	(info)->limit_in_pages = (desc)->usd_gran;			\
	(info)->useable = (desc)->usd_avl;				\
}

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_LINUX_LDT_H */
