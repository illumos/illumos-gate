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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_BINDINGS_H
#define	_BINDINGS_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/lwp.h>

#ifdef	__cplusplus
extern "C" {
#endif

#define	BINDVERS	2
#define	BINDCURVERS	BINDVERS

#define	DEFFILE		"/tmp/bindings.data"
#define	FILEENV		"BT_BUFFER"
#define	BLKSIZE		0x4000
#define	STRBLKSIZE	0x1000
#define	DEFBKTS		3571			/* nice big prime number */

#define	MASK		(~(unsigned long)0<<28)

typedef struct _bind_entry {
	unsigned int	be_sym_name;
	unsigned int	be_lib_name;
	unsigned int	be_count;
	unsigned int	be_next;
} binding_entry;

typedef struct {
	unsigned int	bb_head;	/* first entry in bucket */
	unsigned int	bb_pad;		/* maintain alignment for 32/64bit */
	lwp_mutex_t	bb_lock;	/* bucket chain lock */
} binding_bucket;

typedef struct {
	unsigned int	bh_vers;
	unsigned int	bh_size;
	lwp_mutex_t	bh_lock;
	unsigned int	bh_end;
	unsigned int	bh_bktcnt;
	unsigned int	bh_strcur;		/* current strbuff ptr */
	unsigned int	bh_strend;		/* end of current strbuf */
	lwp_mutex_t	bh_strlock;		/* mutex to protect strings */
	binding_bucket	bh_bkts[DEFBKTS];
} bindhead;

#ifdef	__cplusplus
}
#endif

#endif	/* _BINDINGS_H */
