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
#include	<sys/ddi.h>
#include	<sys/sunddi.h>
#include	<sys/sunldi.h>
#include	<sys/cmn_err.h>

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

static int
dl_op(ldi_handle_t lh, mblk_t **mpp, t_uscalar_t expprim, size_t minlen,
    dl_error_ack_t *dleap, timestruc_t *tvp)
{
	int		err;
	size_t		len;
	mblk_t		*mp = *mpp;
	t_uscalar_t	reqprim, ackprim, ackreqprim;
	union DL_primitives *dlp;

	reqprim = ((union DL_primitives *)mp->b_rptr)->dl_primitive;

	(void) ldi_putmsg(lh, mp);

	switch (err = ldi_getmsg(lh, &mp, tvp)) {
	case 0:
		break;
	case ETIME:
		cmn_err(CE_NOTE, "!dl_op: timed out waiting for %s to %s",
		    dl_primstr(reqprim), dl_primstr(expprim));
		return (ETIME);
	default:
		cmn_err(CE_NOTE, "!dl_op: ldi_getmsg() for %s failed: %d",
		    dl_primstr(expprim), err);
		return (err);
	}

	len = MBLKL(mp);
	if (len < sizeof (t_uscalar_t)) {
		cmn_err(CE_NOTE, "!dl_op: received runt DLPI message");
		freemsg(mp);
		return (EBADMSG);
	}

	dlp = (union DL_primitives *)mp->b_rptr;
	ackprim = dlp->dl_primitive;

	if (ackprim == expprim) {
		if (len < minlen)
			goto runt;

		if (ackprim == DL_OK_ACK) {
			if (dlp->ok_ack.dl_correct_primitive != reqprim) {
				ackreqprim = dlp->ok_ack.dl_correct_primitive;
				goto mixup;
			}
		}
		*mpp = mp;
		return (0);
	}

	if (ackprim == DL_ERROR_ACK) {
		if (len < DL_ERROR_ACK_SIZE)
			goto runt;

		if (dlp->error_ack.dl_error_primitive != reqprim) {
			ackreqprim = dlp->error_ack.dl_error_primitive;
			goto mixup;
		}

		/*
		 * Return a special error code (ENOTSUP) indicating that the
		 * caller has returned DL_ERROR_ACK.  Callers that want more
		 * details an pass a non-NULL dleap.
		 */
		if (dleap != NULL)
			*dleap = dlp->error_ack;

		freemsg(mp);
		return (ENOTSUP);
	}

	cmn_err(CE_NOTE, "!dl_op: expected %s but received %s",
	    dl_primstr(expprim), dl_primstr(ackprim));
	freemsg(mp);
	return (EBADMSG);
runt:
	cmn_err(CE_NOTE, "!dl_op: received runt %s", dl_primstr(ackprim));
	freemsg(mp);
	return (EBADMSG);
mixup:
	cmn_err(CE_NOTE, "!dl_op: received %s for %s instead of %s",
	    dl_primstr(ackprim), dl_primstr(ackreqprim), dl_primstr(reqprim));
	freemsg(mp);
	return (EBADMSG);
}

/*
 * Send a DL_ATTACH_REQ for `ppa' over `lh' and wait for the response.
 *
 * Returns an errno; ENOTSUP indicates a DL_ERROR_ACK response (and the
 * caller can get the contents by passing a non-NULL `dleap').
 */
int
dl_attach(ldi_handle_t lh, int ppa, dl_error_ack_t *dleap)
{
	mblk_t	*mp;
	int	err;

	mp = mexchange(NULL, NULL, DL_ATTACH_REQ_SIZE, M_PROTO, DL_ATTACH_REQ);
	if (mp == NULL)
		return (ENOMEM);

	((dl_attach_req_t *)mp->b_rptr)->dl_ppa = ppa;

	err = dl_op(lh, &mp, DL_OK_ACK, DL_OK_ACK_SIZE, dleap, NULL);
	if (err == 0)
		freemsg(mp);
	return (err);
}

/*
 * Send a DL_BIND_REQ for `sap' over `lh' and wait for the response.
 *
 * Returns an errno; ENOTSUP indicates a DL_ERROR_ACK response (and the
 * caller can get the contents by passing a non-NULL `dleap').
 */
int
dl_bind(ldi_handle_t lh, uint_t sap, dl_error_ack_t *dleap)
{
	dl_bind_req_t	*dlbrp;
	dl_bind_ack_t	*dlbap;
	mblk_t 		*mp;
	int		err;

	mp = mexchange(NULL, NULL, DL_BIND_REQ_SIZE, M_PROTO, DL_BIND_REQ);
	if (mp == NULL)
		return (ENOMEM);

	dlbrp = (dl_bind_req_t *)mp->b_rptr;
	dlbrp->dl_sap = sap;
	dlbrp->dl_conn_mgmt = 0;
	dlbrp->dl_max_conind = 0;
	dlbrp->dl_xidtest_flg = 0;
	dlbrp->dl_service_mode = DL_CLDLS;

	err = dl_op(lh, &mp, DL_BIND_ACK, DL_BIND_ACK_SIZE, dleap, NULL);
	if (err == 0) {
		dlbap = (dl_bind_ack_t *)mp->b_rptr;
		if (dlbap->dl_sap != sap) {
			cmn_err(CE_NOTE, "!dl_bind: DL_BIND_ACK: bad sap %u",
			    dlbap->dl_sap);
			err = EPROTO;
		}
		freemsg(mp);
	}
	return (err);
}

/*
 * Send a DL_PHYS_ADDR_REQ over `lh' and wait for the response.  The caller
 * must set `*physlenp' to the size of `physaddr' (both of which must be
 * non-NULL); upon success they will be updated to contain the actual physical
 * address and length.
 *
 * Returns an errno; ENOTSUP indicates a DL_ERROR_ACK response (and the
 * caller can get the contents by passing a non-NULL `dleap').
 */
int
dl_phys_addr(ldi_handle_t lh, uchar_t *physaddr, size_t *physlenp,
    dl_error_ack_t *dleap)
{
	dl_phys_addr_ack_t *dlpap;
	mblk_t		*mp;
	int		err;
	t_uscalar_t	paddrlen, paddroff;
	timestruc_t	tv;

	mp = mexchange(NULL, NULL, DL_PHYS_ADDR_REQ_SIZE, M_PROTO,
	    DL_PHYS_ADDR_REQ);
	if (mp == NULL)
		return (ENOMEM);

	((dl_phys_addr_req_t *)mp->b_rptr)->dl_addr_type = DL_CURR_PHYS_ADDR;

	/*
	 * In case some provider doesn't implement or NAK the
	 * request, just wait for 15 seconds.
	 */
	tv.tv_sec = 15;
	tv.tv_nsec = 0;

	err = dl_op(lh, &mp, DL_PHYS_ADDR_ACK, DL_PHYS_ADDR_ACK_SIZE, dleap,
	    &tv);
	if (err == 0) {
		dlpap = (dl_phys_addr_ack_t *)mp->b_rptr;
		paddrlen = dlpap->dl_addr_length;
		paddroff = dlpap->dl_addr_offset;
		if (paddroff == 0 || paddrlen == 0 || paddrlen > *physlenp ||
		    !MBLKIN(mp, paddroff, paddrlen)) {
			cmn_err(CE_NOTE, "!dl_phys_addr: DL_PHYS_ADDR_ACK: "
			    "bad length/offset %d/%d", paddrlen, paddroff);
			err = EBADMSG;
		} else {
			bcopy(mp->b_rptr + paddroff, physaddr, paddrlen);
			*physlenp = paddrlen;
		}
		freemsg(mp);
	}
	return (err);
}

/*
 * Send a DL_INFO_REQ over `lh' and wait for the response.  The caller must
 * pass a non-NULL `dliap', which upon success will contain the dl_info_ack_t
 * from the provider.  The caller may optionally get the provider's physical
 * address by passing a non-NULL `physaddr' and setting `*physlenp' to its
 * size; upon success they will be updated to contain the actual physical
 * address and its length.
 *
 * Returns an errno; ENOTSUP indicates a DL_ERROR_ACK response (and the
 * caller can get the contents by passing a non-NULL `dleap').
 */
int
dl_info(ldi_handle_t lh, dl_info_ack_t *dliap, uchar_t *physaddr,
    size_t *physlenp, dl_error_ack_t *dleap)
{
	mblk_t	*mp;
	int	err;
	int	addrlen, addroff;

	mp = mexchange(NULL, NULL, DL_INFO_REQ_SIZE, M_PCPROTO, DL_INFO_REQ);
	if (mp == NULL)
		return (ENOMEM);

	err = dl_op(lh, &mp, DL_INFO_ACK, DL_INFO_ACK_SIZE, dleap, NULL);
	if (err != 0)
		return (err);

	*dliap = *(dl_info_ack_t *)mp->b_rptr;
	if (physaddr != NULL) {
		addrlen = dliap->dl_addr_length - ABS(dliap->dl_sap_length);
		addroff = dliap->dl_addr_offset;
		if (addroff == 0 || addrlen <= 0 || addrlen > *physlenp ||
		    !MBLKIN(mp, addroff, dliap->dl_addr_length)) {
			cmn_err(CE_NOTE, "!dl_info: DL_INFO_ACK: "
			    "bad length/offset %d/%d", addrlen, addroff);
			freemsg(mp);
			return (EBADMSG);
		}

		if (dliap->dl_sap_length > 0)
			addroff += dliap->dl_sap_length;
		bcopy(mp->b_rptr + addroff, physaddr, addrlen);
		*physlenp = addrlen;
	}
	freemsg(mp);
	return (err);
}

/*
 * Send a DL_NOTIFY_REQ over `lh' and wait for the response.  The caller
 * should set `notesp' to the set of notifications they wish to enable;
 * upon success it will contain the notifications enabled by the provider.
 *
 * Returns an errno; ENOTSUP indicates a DL_ERROR_ACK response (and the
 * caller can get the contents by passing a non-NULL `dleap').
 */
int
dl_notify(ldi_handle_t lh, uint32_t *notesp, dl_error_ack_t *dleap)
{
	mblk_t	*mp;
	int	err;

	mp = mexchange(NULL, NULL, DL_NOTIFY_REQ_SIZE, M_PROTO, DL_NOTIFY_REQ);
	if (mp == NULL)
		return (ENOMEM);

	((dl_notify_req_t *)mp->b_rptr)->dl_notifications = *notesp;

	err = dl_op(lh, &mp, DL_NOTIFY_ACK, DL_NOTIFY_ACK_SIZE, dleap, NULL);
	if (err == 0) {
		*notesp = ((dl_notify_ack_t *)mp->b_rptr)->dl_notifications;
		freemsg(mp);
	}
	return (err);
}

const char *
dl_primstr(t_uscalar_t prim)
{
	switch (prim) {
	case DL_INFO_REQ:		return ("DL_INFO_REQ");
	case DL_INFO_ACK:		return ("DL_INFO_ACK");
	case DL_ATTACH_REQ:		return ("DL_ATTACH_REQ");
	case DL_DETACH_REQ:		return ("DL_DETACH_REQ");
	case DL_BIND_REQ:		return ("DL_BIND_REQ");
	case DL_BIND_ACK:		return ("DL_BIND_ACK");
	case DL_UNBIND_REQ:		return ("DL_UNBIND_REQ");
	case DL_OK_ACK:			return ("DL_OK_ACK");
	case DL_ERROR_ACK:		return ("DL_ERROR_ACK");
	case DL_ENABMULTI_REQ:		return ("DL_ENABMULTI_REQ");
	case DL_DISABMULTI_REQ:		return ("DL_DISABMULTI_REQ");
	case DL_PROMISCON_REQ:		return ("DL_PROMISCON_REQ");
	case DL_PROMISCOFF_REQ:		return ("DL_PROMISCOFF_REQ");
	case DL_UNITDATA_REQ:		return ("DL_UNITDATA_REQ");
	case DL_UNITDATA_IND:		return ("DL_UNITDATA_IND");
	case DL_UDERROR_IND:		return ("DL_UDERROR_IND");
	case DL_PHYS_ADDR_REQ:		return ("DL_PHYS_ADDR_REQ");
	case DL_PHYS_ADDR_ACK:		return ("DL_PHYS_ADDR_ACK");
	case DL_SET_PHYS_ADDR_REQ:	return ("DL_SET_PHYS_ADDR_REQ");
	case DL_NOTIFY_REQ:		return ("DL_NOTIFY_REQ");
	case DL_NOTIFY_ACK:		return ("DL_NOTIFY_ACK");
	case DL_NOTIFY_IND:		return ("DL_NOTIFY_IND");
	case DL_CAPABILITY_REQ:		return ("DL_CAPABILITY_REQ");
	case DL_CAPABILITY_ACK:		return ("DL_CAPABILITY_ACK");
	case DL_CONTROL_REQ:		return ("DL_CONTROL_REQ");
	case DL_CONTROL_ACK:		return ("DL_CONTROL_ACK");
	case DL_PASSIVE_REQ:		return ("DL_PASSIVE_REQ");
	case DL_INTR_MODE_REQ:		return ("DL_INTR_MODE_REQ");
	case DL_UDQOS_REQ:		return ("DL_UDQOS_REQ");
	default:			return ("<unknown primitive>");
	}
}

const char *
dl_errstr(t_uscalar_t err)
{
	switch (err) {
	case DL_ACCESS:			return ("DL_ACCESS");
	case DL_BADADDR:		return ("DL_BADADDR");
	case DL_BADCORR:		return ("DL_BADCORR");
	case DL_BADDATA:		return ("DL_BADDATA");
	case DL_BADPPA:			return ("DL_BADPPA");
	case DL_BADPRIM:		return ("DL_BADPRIM");
	case DL_BADQOSPARAM:		return ("DL_BADQOSPARAM");
	case DL_BADQOSTYPE:		return ("DL_BADQOSTYPE");
	case DL_BADSAP:			return ("DL_BADSAP");
	case DL_BADTOKEN:		return ("DL_BADTOKEN");
	case DL_BOUND:			return ("DL_BOUND");
	case DL_INITFAILED:		return ("DL_INITFAILED");
	case DL_NOADDR:			return ("DL_NOADDR");
	case DL_NOTINIT:		return ("DL_NOTINIT");
	case DL_OUTSTATE:		return ("DL_OUTSTATE");
	case DL_SYSERR:			return ("DL_SYSERR");
	case DL_UNSUPPORTED:		return ("DL_UNSUPPORTED");
	case DL_UNDELIVERABLE:		return ("DL_UNDELIVERABLE");
	case DL_NOTSUPPORTED:		return ("DL_NOTSUPPORTED ");
	case DL_TOOMANY:		return ("DL_TOOMANY");
	case DL_NOTENAB:		return ("DL_NOTENAB");
	case DL_BUSY:			return ("DL_BUSY");
	case DL_NOAUTO:			return ("DL_NOAUTO");
	case DL_NOXIDAUTO:		return ("DL_NOXIDAUTO");
	case DL_NOTESTAUTO:		return ("DL_NOTESTAUTO");
	case DL_XIDAUTO:		return ("DL_XIDAUTO");
	case DL_TESTAUTO:		return ("DL_TESTAUTO");
	case DL_PENDING:		return ("DL_PENDING");
	default:			return ("<unknown error>");
	}
}

const char *
dl_mactypestr(t_uscalar_t mactype)
{
	switch (mactype) {
	case DL_CSMACD:		return ("CSMA/CD");
	case DL_TPB:		return ("Token Bus");
	case DL_TPR:		return ("Token Ring");
	case DL_METRO:		return ("Metro Net");
	case DL_ETHER:		return ("Ethernet");
	case DL_HDLC:		return ("HDLC");
	case DL_CHAR:		return ("Sync Character");
	case DL_CTCA:		return ("CTCA");
	case DL_FDDI:		return ("FDDI");
	case DL_FRAME:		return ("Frame Relay (LAPF)");
	case DL_MPFRAME:	return ("MP Frame Relay");
	case DL_ASYNC:		return ("Async Character");
	case DL_IPX25:		return ("X.25 (Classic IP)");
	case DL_LOOP:		return ("Software Loopback");
	case DL_FC:		return ("Fiber Channel");
	case DL_ATM:		return ("ATM");
	case DL_IPATM:		return ("ATM (Classic IP)");
	case DL_X25:		return ("X.25 (LAPB)");
	case DL_ISDN:		return ("ISDN");
	case DL_HIPPI:		return ("HIPPI");
	case DL_100VG:		return ("100BaseVG Ethernet");
	case DL_100VGTPR:	return ("100BaseVG Token Ring");
	case DL_ETH_CSMA:	return ("Ethernet/IEEE 802.3");
	case DL_100BT:		return ("100BaseT");
	case DL_IB:		return ("Infiniband");
	case DL_IPV4:		return ("IPv4 Tunnel");
	case DL_IPV6:		return ("IPv6 Tunnel");
	case DL_WIFI:		return ("IEEE 802.11");
	default:		return ("<unknown mactype>");
	}
}
