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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 *  Common Sun DLPI routines.
 */

#include	<sys/types.h>
#include	<sys/sysmacros.h>
#include	<sys/byteorder.h>
#include	<sys/systm.h>
#include	<sys/stream.h>
#include	<sys/strsun.h>
#include	<sys/dlpi.h>

#define		DLADDRL		(80)

void
dlbindack(
	queue_t		*wq,
	mblk_t		*mp,
	t_scalar_t	sap,
	void		*addrp,
	t_uscalar_t	addrlen,
	t_uscalar_t	maxconind,
	t_uscalar_t	xidtest)
{
	union DL_primitives	*dlp;
	size_t			size;

	size = sizeof (dl_bind_ack_t) + addrlen;
	if ((mp = mexchange(wq, mp, size, M_PCPROTO, DL_BIND_ACK)) == NULL)
		return;

	dlp = (union DL_primitives *)mp->b_rptr;
	dlp->bind_ack.dl_sap = sap;
	dlp->bind_ack.dl_addr_length = addrlen;
	dlp->bind_ack.dl_addr_offset = sizeof (dl_bind_ack_t);
	dlp->bind_ack.dl_max_conind = maxconind;
	dlp->bind_ack.dl_xidtest_flg = xidtest;
	if (addrlen != 0)
		bcopy(addrp, mp->b_rptr + sizeof (dl_bind_ack_t), addrlen);

	qreply(wq, mp);
}

void
dlokack(
	queue_t		*wq,
	mblk_t		*mp,
	t_uscalar_t	correct_primitive)
{
	union DL_primitives	*dlp;

	if ((mp = mexchange(wq, mp, sizeof (dl_ok_ack_t), M_PCPROTO,
	    DL_OK_ACK)) == NULL)
		return;
	dlp = (union DL_primitives *)mp->b_rptr;
	dlp->ok_ack.dl_correct_primitive = correct_primitive;
	qreply(wq, mp);
}

void
dlerrorack(
	queue_t		*wq,
	mblk_t		*mp,
	t_uscalar_t	error_primitive,
	t_uscalar_t	error,
	t_uscalar_t	unix_errno)
{
	union DL_primitives	*dlp;

	if ((mp = mexchange(wq, mp, sizeof (dl_error_ack_t), M_PCPROTO,
	    DL_ERROR_ACK)) == NULL)
		return;
	dlp = (union DL_primitives *)mp->b_rptr;
	dlp->error_ack.dl_error_primitive = error_primitive;
	dlp->error_ack.dl_errno = error;
	dlp->error_ack.dl_unix_errno = unix_errno;
	qreply(wq, mp);
}

void
dluderrorind(
	queue_t		*wq,
	mblk_t		*mp,
	void		*addrp,
	t_uscalar_t	addrlen,
	t_uscalar_t	error,
	t_uscalar_t	unix_errno)
{
	union DL_primitives	*dlp;
	char			buf[DLADDRL];
	size_t			size;

	if (addrlen > DLADDRL)
		addrlen = DLADDRL;

	bcopy(addrp, buf, addrlen);

	size = sizeof (dl_uderror_ind_t) + addrlen;

	if ((mp = mexchange(wq, mp, size, M_PCPROTO, DL_UDERROR_IND)) == NULL)
		return;

	dlp = (union DL_primitives *)mp->b_rptr;
	dlp->uderror_ind.dl_dest_addr_length = addrlen;
	dlp->uderror_ind.dl_dest_addr_offset = sizeof (dl_uderror_ind_t);
	dlp->uderror_ind.dl_unix_errno = unix_errno;
	dlp->uderror_ind.dl_errno = error;
	bcopy((caddr_t)buf,
	    (caddr_t)(mp->b_rptr + sizeof (dl_uderror_ind_t)), addrlen);
	qreply(wq, mp);
}

void
dlphysaddrack(
	queue_t		*wq,
	mblk_t		*mp,
	void		*addrp,
	t_uscalar_t	len)
{
	union DL_primitives	*dlp;
	size_t			size;

	size = sizeof (dl_phys_addr_ack_t) + len;
	if ((mp = mexchange(wq, mp, size, M_PCPROTO, DL_PHYS_ADDR_ACK)) == NULL)
		return;
	dlp = (union DL_primitives *)mp->b_rptr;
	dlp->physaddr_ack.dl_addr_length = len;
	dlp->physaddr_ack.dl_addr_offset = sizeof (dl_phys_addr_ack_t);
	if (len != 0)
		bcopy(addrp, mp->b_rptr + sizeof (dl_phys_addr_ack_t), len);
	qreply(wq, mp);
}

void
dlcapabsetqid(dl_mid_t *idp, const queue_t *q)
{
#ifndef _LP64
	idp->mid[0] = (t_uscalar_t)q;
#else
	idp->mid[0] = (t_uscalar_t)BMASK_32((uint64_t)q);
	idp->mid[1] = (t_uscalar_t)BMASK_32(((uint64_t)q) >> 32);
#endif
}

boolean_t
dlcapabcheckqid(const dl_mid_t *idp, const queue_t *q)
{
#ifndef _LP64
	return ((queue_t *)(idp->mid[0]) == q);
#else
	return ((queue_t *)
	    ((uint64_t)idp->mid[0] | ((uint64_t)idp->mid[1] << 32)) == q);
#endif
}

void
dlnotifyack(
	queue_t		*wq,
	mblk_t		*mp,
	uint32_t	notifications)
{
	union DL_primitives	*dlp;

	if ((mp = mexchange(wq, mp, sizeof (dl_notify_ack_t), M_PROTO,
	    DL_NOTIFY_ACK)) == NULL)
		return;
	dlp = (union DL_primitives *)mp->b_rptr;
	dlp->notify_ack.dl_notifications = notifications;
	qreply(wq, mp);
}
