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
 * Copyright (c) 2000 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef _SYS_SBD_IO_H
#define	_SYS_SBD_IO_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * All definitions for sbd io should go here
 */

void		sbd_attach_io(sbd_handle_t *, sbderror_t *, dev_info_t *, int);
void		sbd_detach_io(sbd_handle_t *, sbderror_t *, dev_info_t *, int);
int		sbd_check_io_refs(sbd_handle_t *, sbd_devlist_t *, int);
int		sbd_check_io_attached(dev_info_t *, void *);
int		sbd_io_status(sbd_handle_t *, sbd_devset_t, sbd_dev_stat_t *);
void		sbd_init_io_unit(sbd_board_t *sbp, int);
int		sbd_pre_detach_io(sbd_handle_t *, sbd_devlist_t *, int);
int		sbd_post_detach_io(sbd_handle_t *, sbd_devlist_t *, int);
int		sbd_pre_attach_io(sbd_handle_t *, sbd_devlist_t *, int);
int		sbd_post_attach_io(sbd_handle_t *, sbd_devlist_t *, int);
int		sbd_io_cnt(sbd_handle_t *, sbd_devset_t);
int		sbd_pre_release_io(sbd_handle_t *, sbd_devlist_t *, int);


#ifdef	__cplusplus
}
#endif

#endif /* _SYS_SBD_IO_H */
