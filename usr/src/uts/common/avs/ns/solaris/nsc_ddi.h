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

#ifndef _NSC_DDI_H
#define	_NSC_DDI_H

#ifdef __cplusplus
extern "C" {
#endif

/*
 * before we redefine our thread calls we must be sure that solaris has its
 * thread stuff defined else we'll redefine it also.
 */

#include <sys/stat.h>			/* for S_IFCHR and friends */
#include <sys/ddi.h>
#include <sys/sunddi.h>

#ifdef _KERNEL

/*
 * Misc
 */

typedef	caddr_t	vaddr_t;

#ifndef _BLIND_T
#define	_BLIND_T
typedef void * blind_t;
#endif /* _BLIND_T */

typedef int (*blindfn_t)();
typedef uintptr_t mc_io_addr_t;

/*
 * You would think that sys/ddi.h would define these, as they are in the ddi.
 */
extern int copyout(const void *, void *, size_t);
extern int copyin(const void *, void *, size_t);

#endif	/* _KERNEL */

#ifdef __cplusplus
}
#endif

#endif /* _NSC_DDI_H */
