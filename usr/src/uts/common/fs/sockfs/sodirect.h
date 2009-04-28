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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
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

#ifndef _SOCKFS_SODIRECT_H
#define	_SOCKFS_SODIRECT_H

/*
 * Sodirect; used to support asynchronous DMA hardware
 * (e.g. Intel's I/OAT).
 */

#ifdef	__cplusplus
extern "C" {
#endif

typedef struct sodirect_s {
	boolean_t	sod_enabled;	/* sodirect_t enabled */
	mblk_t		*sod_uioafh;	/* To be freed list head, or NULL */
	mblk_t		*sod_uioaft;	/* To be freed list tail */
	uioa_t		sod_uioa;	/* Pending uio_t for uioa_t use */
} sodirect_t;

/*
 * Usefull macros:
 */
#define	SOD_DISABLE(sodp) {		\
	(sodp)->sod_enabled = B_FALSE;	\
}

#define	SOD_SOTOSODP(so) ((sonode_t *)so)->so_direct

#define	SOD_UIOAFINI(sodp) {						\
	if ((sodp)->sod_uioa.uioa_state & UIOA_ENABLED) {		\
		(sodp)->sod_uioa.uioa_state &= UIOA_CLR;		\
		(sodp)->sod_uioa.uioa_state |= UIOA_FINI;		\
	}								\
}

struct sonode;
struct sodirect_s;

extern uio_t	*sod_rcv_init(struct sonode *, int, struct uio **);
extern int	sod_rcv_done(struct sonode *, struct uio *, struct uio *);

extern void	sod_uioa_mblk_init(struct sodirect_s *, mblk_t *, size_t);
extern void	sod_uioa_so_init(struct sonode *, struct sodirect_s *,
    struct uio *);
extern ssize_t	sod_uioa_mblk(struct sonode *, mblk_t *);
extern void	sod_uioa_mblk_done(struct sodirect_s *, mblk_t *);

extern int	sod_init(void);
extern void	sod_sock_init(struct sonode *);
extern void	sod_sock_fini(struct sonode *);

#ifdef	__cplusplus
}
#endif

#endif	/* _SOCKFS_SODIRECT_H */
