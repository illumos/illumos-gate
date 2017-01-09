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

#ifndef	_SYS_COPYOPS_H
#define	_SYS_COPYOPS_H

#include <sys/types.h>
#include <sys/thread.h>
#include <sys/buf.h>
#include <sys/aio_req.h>
#include <sys/uio.h>

#ifdef	__cplusplus
extern "C" {
#endif

#ifdef _KERNEL

/*
 * Copy in/out vector operations.  This structure is used to interpose
 * on the kernel copyin/copyout/etc. operations for various purposes
 * such as handling watchpoints in the affected user memory.  When one of the
 * copy operations causes a fault, the corresponding function in this vector is
 * called to handle it.
 *
 * The 64-bit operations in the structure fetch and store extended
 * words and are only used on platforms with 64 bit general
 * registers e.g. sun4u.
 *
 * Since the only users of these interfaces (watchpoints and pxfs) perform the
 * default action unless there is a page fault, we can save the overhead of
 * having to go through this indirection unless there is a page fault.  This
 * improves performance both in general and when watchpoints are enabled.  If,
 * in the future, a consumer relies on being able to interpose on all actions,
 * then this assumption will have to be undone.
 *
 * No consumers should call these functions directly.  They are automatically
 * handled by the generic versions.
 */
typedef struct copyops {
	/*
	 * unstructured byte copyin/out functions
	 */
	int	(*cp_copyin)(const void *, void *, size_t);
	int	(*cp_xcopyin)(const void *, void *, size_t);
	int	(*cp_copyout)(const void *, void *, size_t);
	int	(*cp_xcopyout)(const void *, void *, size_t);
	int	(*cp_copyinstr)(const char *, char *, size_t, size_t *);
	int	(*cp_copyoutstr)(const char *, char *, size_t, size_t *);

	/*
	 * fetch/store byte/halfword/word/extended word
	 */
	int	(*cp_fuword8)(const void *, uint8_t *);
	int	(*cp_fuword16)(const void *, uint16_t *);
	int	(*cp_fuword32)(const void *, uint32_t *);
	int	(*cp_fuword64)(const void *, uint64_t *);

	int	(*cp_suword8)(void *, uint8_t);
	int	(*cp_suword16)(void *, uint16_t);
	int	(*cp_suword32)(void *, uint32_t);
	int	(*cp_suword64)(void *, uint64_t);

	int	(*cp_physio)(int (*)(struct buf *), struct buf *, dev_t,
	    int, void (*)(struct buf *), struct uio *);
} copyops_t;

extern int	default_physio(int (*)(struct buf *), struct buf *,
    dev_t, int, void (*)(struct buf *), struct uio *);

/*
 * Interfaces for installing and removing copyops.
 */
extern void install_copyops(kthread_id_t tp, copyops_t *cp);
extern void remove_copyops(kthread_id_t tp);
extern int copyops_installed(kthread_id_t tp);

#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif /* _SYS_COPYOPS_H */
