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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved	*/

/*
 * Portions of this source code were derived from Berkeley 4.3 BSD
 * under license from the Regents of the University of California.
 */

#ifndef	_VM_SEG_ENUM_H
#define	_VM_SEG_ENUM_H

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * These enumerations are needed in both <vm/seg.h> and
 * <sys/vnode.h> in order to declare function prototypes.
 */

/*
 * Fault information passed to the seg fault handling routine.
 * The F_SOFTLOCK and F_SOFTUNLOCK are used by software
 * to lock and unlock pages for physical I/O.
 */
enum fault_type {
	F_INVAL,		/* invalid page */
	F_PROT,			/* protection fault */
	F_SOFTLOCK,		/* software requested locking */
	F_SOFTUNLOCK		/* software requested unlocking */
};

/*
 * Lock information passed to the seg pagelock handling routine.
 */
enum lock_type {
	L_PAGELOCK,		/* lock pages */
	L_PAGEUNLOCK		/* unlock pages */
};

/*
 * seg_rw gives the access type for a fault operation
 */
enum seg_rw {
	S_OTHER,		/* unknown or not touched */
	S_READ,			/* read access attempted */
	S_WRITE,		/* write access attempted */
	S_EXEC,			/* execution access attempted */
	S_CREATE,		/* create if page doesn't exist */
	S_READ_NOCOW		/* read access, don't do a copy on write */
};

/*
 * Capabilities for capability segment op.
 */
typedef enum {
	S_CAPABILITY_NOMINFLT	/* supports non-faulting page renaming */
} segcapability_t;

#ifdef	__cplusplus
}
#endif

#endif	/* _VM_SEG_ENUM_H */
