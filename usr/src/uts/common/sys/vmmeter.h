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
 * Copyright 1996 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * University Copyright- Copyright (c) 1982, 1986, 1988
 * The Regents of the University of California
 * All Rights Reserved
 *
 * University Acknowledgment- Portions of this document are derived from
 * software developed by the University of California, Berkeley, and its
 * contributors.
 */

#ifndef _SYS_VMMETER_H
#define	_SYS_VMMETER_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Virtual Address Cache flush instrumentation.
 *
 * Everything from f_first to f_last must be unsigned [int].
 */
struct flushmeter {
#define	f_first f_ctx
	unsigned f_ctx;		/* No. of context flushes */
	unsigned f_segment;	/* No. of segment flushes */
	unsigned f_page;	/* No. of complete page flushes */
	unsigned f_partial;	/* No. of partial page flushes */
	unsigned f_usr;		/* No. of non-supervisor flushes */
	unsigned f_region;	/* No. of region flushes */
#define	f_last	f_region
};

#ifdef _KERNEL
#ifdef VAC
/* cnt is 1 sec accum; rate is 5 sec avg; sum is grand total */
struct flushmeter	flush_cnt;
#endif /* VAC */
#endif /* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_VMMETER_H */
