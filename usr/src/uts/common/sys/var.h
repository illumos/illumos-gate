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
 * Copyright 1997 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

#ifndef _SYS_VAR_H
#define	_SYS_VAR_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * System Configuration Information
 */
struct var {
	int	v_buf;		/* Nbr of I/O buffers.			*/
	int	v_call;		/* Nbr of callout (timeout) entries.	*/
	int	v_proc;		/* Max processes system wide		*/
	int	v_maxupttl;	/* Max user processes system wide	*/
	int	v_nglobpris;	/* Nbr of global sched prios configured	*/
	int	v_maxsyspri;	/* Max global pri used by sys class.	*/
	int	v_clist;	/* Nbr of clists allocated.		*/
	int	v_maxup;	/* Max number of processes per user.	*/
	int	v_hbuf;		/* Nbr of hash buffers to allocate.	*/
	int	v_hmask;	/* Hash mask for buffers.		*/
	int	v_pbuf;		/* Nbr of physical I/O buffers.		*/
	int	v_sptmap;	/* Size of system virtual space		*/
				/* allocation map.			*/
	int	v_maxpmem;	/* The maximum physical memory to use.	*/
				/* If v_maxpmem == 0, then use all	*/
				/* available physical memory.		*/
				/* Otherwise, value is amount of mem to	*/
				/* use specified in pages.		*/
	int	v_autoup;	/* The age a delayed-write buffer must	*/
				/* be in seconds before bdflush will	*/
				/* write it out.			*/
	int	v_bufhwm;	/* high-water-mark of buffer cache	*/
				/* memory usage, in units of K Bytes	*/
};

extern struct var v;

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_VAR_H */
