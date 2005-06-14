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
 * Copyright (c) 1990-1998 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef	_SYS_STRREDIR_H
#define	_SYS_STRREDIR_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * strredir.h:	Declarations for the redirection driver and its matching
 *		STREAMS module.
 */

/*
 * The module's module id.
 *
 * XXX:	Since there's no authority responsible for administering this name
 *	space, there's no guarantee that this value is unique.  That wouldn't
 *	be so bad except that the DKI now suggests that ioctl cookie values
 *	should be based on module id to make them unique...
 */
#define	_STRREDIR_MODID	7326

/*
 * Redirection ioctls:
 */
#define	SRIOCSREDIR	((_STRREDIR_MODID<<16) | 1)	/* set redir target */
#define	SRIOCISREDIR	((_STRREDIR_MODID<<16) | 2)	/* is redir target? */


/*
 * Everything from here on is of interest only to the kernel.
 */
#ifdef	_KERNEL

#include <sys/types.h>
#include <sys/cred.h>
#include <sys/vnode.h>

/*
 * Per-open instance driver state information.
 *
 * The underlying device potentially can be opened through (at least) two
 * paths:  through this driver and through the underlying device's driver.  To
 * ensure that reference counts are meaningful and therefore that close
 * routines are called at the right time, it's important to make sure that the
 * snode for the underlying device instance never has a contribution of more
 * than one through this driver, regardless of how many times this driver's
 * been opened.  The wd_wsconsopen field keeps track of the necessary
 * information to ensure this property.
 *
 * The structure also contains copies of the flag and cred values supplied
 * when the device instance was first opened, so that it's possible to reopen
 * the underlying device in srreset.
 */
typedef struct wcd_data {
	struct wcd_data	*wd_next;	/* link to next open instance */
	minor_t		wd_unit;	/* minor device # for this instance */
	struct wcrlist	*wd_list;	/* the head of the redirection list */
	vnode_t		*wd_vp;		/* underlying device instance vnode */
	int		wd_wsconsopen;	/* see above */
	int		wd_flag;	/* see above */
	cred_t		*wd_cred;	/* see above */
} wcd_data_t;

/*
 * Per-open instance module state information.
 *
 * An invariant:  when wm_wd is non-NULL, wm_entry is also non-NULL and is on
 * the list rooted at wm_wd->wd_list.
 */
typedef struct wcm_data {
	struct wcd_data	*wm_wd;		/* Xref to redir driver data */
	struct wcrlist	*wm_entry;	/* Redir entry that refers to us */
} wcm_data_t;

/*
 * We record the list of redirections as a linked list of wcrlist
 * structures.
 *
 * We need to keep track of:
 * 1)	The target's vp, so that we can vector reads, writes, etc. off to the
 *	current designee.
 * 2)	The per-open instance private data structure of the redirmod module
 *	instance we push onto the target stream, so that we can clean up there
 *	when we go away.  (I'm not sure that this is actually necessary.)
 */
typedef struct wcrlist {
	struct wcrlist	*wl_next;	/* next entry */
	vnode_t		*wl_vp;		/* target's vnode */
	struct wcm_data	*wl_data;	/* target's redirmod private data */
} wcrlist_t;

/*
 * A given instance of the redirection driver must be able to open the
 * corresponding instance of the underlying device when the redirection list
 * empties.  To do so it needs a vnode for the underlying instance.  The
 * underlying driver is responsible for supplying routines for producing and
 * disposing of this vnode.  The get routine must return a held vnode, so that
 * it can't vanish while the redirecting driver is using it.
 */
typedef struct srvnops {
	int	(*svn_get)();	/* (minor #, vpp) --> errno value */
	void	(*svn_rele)();	/* (minor #, vp) */
} srvnops_t;

extern void srpop(wcm_data_t *, int, cred_t *);

#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_STRREDIR_H */
