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

#ifndef _SOCKFS_SOCKTPI_IMPL_H
#define	_SOCKFS_SOCKTPI_IMPL_H

#include <sys/socketvar.h>
#include <fs/sockfs/socktpi.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * so_priv will always be set to &st_info
 */
typedef struct sotpi_sonode {
	struct sonode st_sonode;
	struct sotpi_info st_info;
} sotpi_sonode_t;

extern void	so_proc_tcapability_ack(struct sonode *,
		    struct T_capability_ack *);
extern void	so_basic_strinit(struct sonode *);
extern void 	so_alloc_addr(struct sonode *, t_uscalar_t);
extern int	so_set_events(struct sonode *, vnode_t *, cred_t *);
extern int	so_sock2stream(struct sonode *);
extern void	so_stream2sock(struct sonode *);

extern int	so_strinit(struct sonode *, struct sonode *);
extern void	so_update_attrs(struct sonode *, int);
extern int	sogetrderr(vnode_t *, int, int *);
extern int	sogetwrerr(vnode_t *, int, int *);
extern int	so_addr_verify(struct sonode *, const struct sockaddr *,
			socklen_t);
extern int	so_ux_addr_xlate(struct sonode *, struct sockaddr *,
			socklen_t, int, void **, socklen_t *);
extern void	so_unix_close(struct sonode *);

extern int	sowaitprim(struct sonode *, t_scalar_t, t_scalar_t,
			t_uscalar_t, mblk_t **, clock_t);
extern int	sowaitokack(struct sonode *, t_scalar_t);
extern int	sowaitack(struct sonode *, mblk_t **, clock_t);
extern void	soqueueack(struct sonode *, mblk_t *);
extern int	sowaitconnind(struct sonode *, int, mblk_t **);
extern void	soqueueconnind(struct sonode *, mblk_t *);
extern int	soflushconnind(struct sonode *, t_scalar_t);
extern void	so_drain_discon_ind(struct sonode *);
extern void	so_flush_discon_ind(struct sonode *);

extern mblk_t	*soallocproto(size_t, int);
extern mblk_t	*soallocproto1(const void *, ssize_t, ssize_t, int);
extern void	soappendmsg(mblk_t *, const void *, ssize_t);
extern mblk_t	*soallocproto2(const void *, ssize_t, const void *, ssize_t,
			ssize_t, int);
extern mblk_t	*soallocproto3(const void *, ssize_t, const void *, ssize_t,
			const void *, ssize_t, ssize_t, int);

extern int	so_set_asyncsigs(vnode_t *, pid_t, int, int, cred_t *);
extern int	so_flip_async(struct sonode *, vnode_t *, int, cred_t *);
extern int	so_set_siggrp(struct sonode *, vnode_t *, pid_t, int, cred_t *);

extern void	so_installhooks(struct sonode *);

extern int 	kstrwritemp(struct vnode *, mblk_t *, ushort_t);
extern int	sostream_direct(struct sonode *, struct uio *,
		    mblk_t *, cred_t *);
extern int	sosend_dgram(struct sonode *, struct sockaddr *,
		    socklen_t, struct uio *, int);
extern int	sosend_svc(struct sonode *, struct uio *, t_scalar_t, int, int);

#ifdef	__cplusplus
}
#endif

#endif /* _SOCKFS_SOCKTPI_IMPL_H */
