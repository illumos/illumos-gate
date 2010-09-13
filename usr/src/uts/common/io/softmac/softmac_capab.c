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

#include <sys/types.h>
#include <sys/mac.h>
#include <sys/softmac_impl.h>

typedef struct softmac_capab_ops {
	int	(*sc_hcksum_ack)(void *, t_uscalar_t);
	int	(*sc_zcopy_ack)(void *, t_uscalar_t);
	int	(*sc_mdt_ack)(void *, dl_capab_mdt_t *);
} softmac_capab_ops_t;

static int	dl_capab(ldi_handle_t, mblk_t **);
static int	softmac_fill_hcksum_ack(void *, t_uscalar_t);
static int	softmac_fill_zcopy_ack(void *, t_uscalar_t);
static int	softmac_fill_mdt_ack(void *, dl_capab_mdt_t *);
static int	softmac_adv_hcksum_ack(void *, t_uscalar_t);
static int	softmac_adv_zcopy_ack(void *, t_uscalar_t);
static int	softmac_adv_mdt_ack(void *, dl_capab_mdt_t *);
static int	softmac_enable_hcksum_ack(void *, t_uscalar_t);
static int	softmac_enable_mdt_ack(void *, dl_capab_mdt_t *);
static int	softmac_capab_send(softmac_lower_t *, boolean_t);
static int	i_capab_ack(mblk_t *, queue_t *, softmac_capab_ops_t *, void *);
static int	i_capab_id_ack(mblk_t *, dl_capability_sub_t *, queue_t *,
    softmac_capab_ops_t *, void *);
static int	i_capab_sub_ack(mblk_t *, dl_capability_sub_t *, queue_t *,
    softmac_capab_ops_t *, void *);
static int	i_capab_hcksum_ack(dl_capab_hcksum_t *, queue_t *,
    softmac_capab_ops_t *, void *);
static int	i_capab_zcopy_ack(dl_capab_zerocopy_t *, queue_t *,
    softmac_capab_ops_t *, void *);
static int	i_capab_mdt_ack(dl_capab_mdt_t *, queue_t *,
    softmac_capab_ops_t *, void *);
static int	i_capab_hcksum_verify(dl_capab_hcksum_t *, queue_t *);
static int	i_capab_zcopy_verify(dl_capab_zerocopy_t *, queue_t *);
static int	i_capab_mdt_verify(dl_capab_mdt_t *, queue_t *);

static softmac_capab_ops_t softmac_fill_capab_ops =
{
	softmac_fill_hcksum_ack,
	softmac_fill_zcopy_ack,
	softmac_fill_mdt_ack,
};

static softmac_capab_ops_t softmac_adv_capab_ops =
{
	softmac_adv_hcksum_ack,
	softmac_adv_zcopy_ack,
	softmac_adv_mdt_ack
};

static softmac_capab_ops_t softmac_enable_capab_ops =
{
	softmac_enable_hcksum_ack,
	NULL,
	softmac_enable_mdt_ack
};

int
softmac_fill_capab(ldi_handle_t lh, softmac_t *softmac)
{
	mblk_t			*mp = NULL;
	union DL_primitives	*prim;
	int			err = 0;

	if ((err = dl_capab(lh, &mp)) != 0)
		goto exit;

	prim = (union DL_primitives *)mp->b_rptr;
	if (prim->dl_primitive == DL_ERROR_ACK) {
		err = -1;
		goto exit;
	}

	err = i_capab_ack(mp, NULL, &softmac_fill_capab_ops, softmac);

exit:
	freemsg(mp);
	return (err);
}

static int
dl_capab(ldi_handle_t lh, mblk_t **mpp)
{
	dl_capability_req_t	*capb;
	union DL_primitives	*dl_prim;
	mblk_t			*mp;
	int			err;

	if ((mp = allocb(sizeof (dl_capability_req_t), BPRI_MED)) == NULL)
		return (ENOMEM);
	mp->b_datap->db_type = M_PROTO;

	capb = (dl_capability_req_t *)mp->b_wptr;
	mp->b_wptr += sizeof (dl_capability_req_t);
	bzero(mp->b_rptr, sizeof (dl_capability_req_t));
	capb->dl_primitive = DL_CAPABILITY_REQ;

	(void) ldi_putmsg(lh, mp);
	if ((err = ldi_getmsg(lh, &mp, (timestruc_t *)NULL)) != 0)
		return (err);

	dl_prim = (union DL_primitives *)mp->b_rptr;
	switch (dl_prim->dl_primitive) {
	case DL_CAPABILITY_ACK:
		if (MBLKL(mp) < DL_CAPABILITY_ACK_SIZE) {
			printf("dl_capability: DL_CAPABILITY_ACK "
			    "protocol err\n");
			break;
		}
		*mpp = mp;
		return (0);

	case DL_ERROR_ACK:
		if (MBLKL(mp) < DL_ERROR_ACK_SIZE) {
			printf("dl_capability: DL_ERROR_ACK protocol err\n");
			break;
		}
		if (((dl_error_ack_t *)dl_prim)->dl_error_primitive !=
		    DL_CAPABILITY_REQ) {
			printf("dl_capability: DL_ERROR_ACK rtnd prim %u\n",
			    ((dl_error_ack_t *)dl_prim)->dl_error_primitive);
			break;
		}

		*mpp = mp;
		return (0);

	default:
		printf("dl_capability: bad ACK header %u\n",
		    dl_prim->dl_primitive);
		break;
	}

	freemsg(mp);
	return (-1);
}

static int
softmac_fill_hcksum_ack(void *arg, t_uscalar_t flags)
{
	softmac_t	*softmac = (softmac_t *)arg;

	/*
	 * There are two types of acks we process here:
	 * 1. acks in reply to a (first form) generic capability req
	 *    (no ENABLE flag set)
	 * 2. acks in reply to a ENABLE capability req.
	 *    (ENABLE flag set)
	 * Only the first type should be expected here.
	 */

	if (flags & HCKSUM_ENABLE) {
		cmn_err(CE_WARN, "softmac_fill_hcksum_ack: unexpected "
		    "HCKSUM_ENABLE flag in hardware checksum capability");
	} else if (flags & (HCKSUM_INET_PARTIAL | HCKSUM_INET_FULL_V4 |
	    HCKSUM_INET_FULL_V6 | HCKSUM_IPHDRCKSUM)) {
		softmac->smac_capab_flags |= MAC_CAPAB_HCKSUM;
		softmac->smac_hcksum_txflags = flags;
	}
	return (0);
}

static int
softmac_fill_zcopy_ack(void *arg, t_uscalar_t flags)
{
	softmac_t	*softmac = (softmac_t *)arg;

	ASSERT(flags == DL_CAPAB_VMSAFE_MEM);
	softmac->smac_capab_flags &= (~MAC_CAPAB_NO_ZCOPY);
	return (0);
}

static int
softmac_fill_mdt_ack(void *arg, dl_capab_mdt_t *mdt)
{
	softmac_t *softmac = (softmac_t *)arg;

	/*
	 * There are two types of acks we process here:
	 * 1. acks in reply to a (first form) generic capability req
	 *    (ENABLE flag might be set by some drivers)
	 * 2. acks in reply to a ENABLE capability req.
	 *    (ENABLE flag set)
	 */

	ASSERT(mdt->mdt_version == MDT_VERSION_2);
	softmac->smac_mdt = B_TRUE;
	softmac->smac_mdt_capab.mdt_hdr_head = mdt->mdt_hdr_head;
	softmac->smac_mdt_capab.mdt_hdr_tail = mdt->mdt_hdr_tail;
	softmac->smac_mdt_capab.mdt_max_pld = mdt->mdt_max_pld;
	softmac->smac_mdt_capab.mdt_span_limit = mdt->mdt_span_limit;
	return (0);
}

int
softmac_capab_enable(softmac_lower_t *slp)
{
	softmac_t	*softmac = slp->sl_softmac;
	int		err;

	if (softmac->smac_no_capability_req)
		return (0);

	/*
	 * Send DL_CAPABILITY_REQ to get capability advertisement.
	 */
	if ((err = softmac_capab_send(slp, B_FALSE)) != 0)
		return (err);

	/*
	 * Send DL_CAPABILITY_REQ to enable specific capabilities.
	 */
	if ((err = softmac_capab_send(slp, B_TRUE)) != 0)
		return (err);

	return (0);
}

static int
softmac_capab_send(softmac_lower_t *slp, boolean_t enable)
{
	softmac_t		*softmac;
	dl_capability_req_t	*capb;
	dl_capability_sub_t	*subcapb;
	mblk_t			*reqmp, *ackmp;
	int			err;
	size_t			size = 0;

	softmac = slp->sl_softmac;

	if (enable) {
		/* No need to enable DL_CAPAB_ZEROCOPY */
		if (softmac->smac_capab_flags & MAC_CAPAB_HCKSUM)
			size += sizeof (dl_capability_sub_t) +
			    sizeof (dl_capab_hcksum_t);

		if (softmac->smac_mdt) {
			if (!(softmac->smac_mdt_capab.mdt_flags &
			    DL_CAPAB_MDT_ENABLE)) {
				/*
				 * The MDT capability was not enabled for the
				 * first time, enable it now.
				 */
				size += sizeof (dl_capability_sub_t) +
				    sizeof (dl_capab_mdt_t);
			}
		}

		if (size == 0)
			return (0);
	}

	/*
	 * Create DL_CAPABILITY_REQ message and send it down
	 */
	reqmp = allocb(sizeof (dl_capability_req_t) + size, BPRI_MED);
	if (reqmp == NULL)
		return (ENOMEM);

	bzero(reqmp->b_rptr, sizeof (dl_capability_req_t) + size);

	DB_TYPE(reqmp) = M_PROTO;
	reqmp->b_wptr = reqmp->b_rptr + sizeof (dl_capability_req_t) + size;

	capb = (dl_capability_req_t *)reqmp->b_rptr;
	capb->dl_primitive = DL_CAPABILITY_REQ;

	if (!enable)
		goto output;

	capb->dl_sub_offset = sizeof (dl_capability_req_t);

	if (softmac->smac_capab_flags & MAC_CAPAB_HCKSUM) {
		dl_capab_hcksum_t *hck_subcapp;

		size = sizeof (dl_capability_sub_t) +
		    sizeof (dl_capab_hcksum_t);
		capb->dl_sub_length += size;

		subcapb = (dl_capability_sub_t *)(capb + 1);
		subcapb->dl_cap = DL_CAPAB_HCKSUM;
		subcapb->dl_length = sizeof (dl_capab_hcksum_t);
		hck_subcapp = (dl_capab_hcksum_t *)(subcapb + 1);
		hck_subcapp->hcksum_version = HCKSUM_VERSION_1;
		hck_subcapp->hcksum_txflags =
		    softmac->smac_hcksum_txflags | HCKSUM_ENABLE;
	}

	if (softmac->smac_mdt) {
		if (!(softmac->smac_mdt_capab.mdt_flags &
		    DL_CAPAB_MDT_ENABLE)) {
			dl_capab_mdt_t *mdt_subcapp;

			size = sizeof (dl_capability_sub_t) +
			    sizeof (dl_capab_mdt_t);
			capb->dl_sub_length += size;

			subcapb = (dl_capability_sub_t *)
			    ((uint8_t *)(subcapb + 1) + subcapb->dl_length);

			subcapb->dl_cap = DL_CAPAB_MDT;
			subcapb->dl_length = sizeof (dl_capab_mdt_t);
			mdt_subcapp = (dl_capab_mdt_t *)(subcapb + 1);
			mdt_subcapp->mdt_version = MDT_VERSION_2;
			mdt_subcapp->mdt_flags =
			    (softmac->smac_mdt_capab.mdt_flags |
			    DL_CAPAB_MDT_ENABLE);
			mdt_subcapp->mdt_hdr_head =
			    softmac->smac_mdt_capab.mdt_hdr_head;
			mdt_subcapp->mdt_hdr_tail =
			    softmac->smac_mdt_capab.mdt_hdr_tail;
			mdt_subcapp->mdt_max_pld =
			    softmac->smac_mdt_capab.mdt_max_pld;
			mdt_subcapp->mdt_span_limit =
			    softmac->smac_mdt_capab.mdt_span_limit;
		}
	}

output:
	err = softmac_proto_tx(slp, reqmp, &ackmp);
	if (err == 0) {
		if (enable) {
			err = i_capab_ack(ackmp, NULL,
			    &softmac_enable_capab_ops, softmac);
		} else {
			err = i_capab_ack(ackmp, NULL,
			    &softmac_adv_capab_ops, softmac);
		}
	}
	freemsg(ackmp);

	return (err);
}

static int
softmac_adv_hcksum_ack(void *arg, t_uscalar_t flags)
{
	softmac_t	*softmac = (softmac_t *)arg;

	/*
	 * There are two types of acks we process here:
	 * 1. acks in reply to a (first form) generic capability req
	 *    (no ENABLE flag set)
	 * 2. acks in reply to a ENABLE capability req.
	 *    (ENABLE flag set)
	 * Only the first type should be expected here.
	 */

	if (flags & HCKSUM_ENABLE) {
		cmn_err(CE_WARN, "softmac_adv_hcksum_ack: unexpected "
		    "HCKSUM_ENABLE flag in hardware checksum capability");
		return (-1);
	} else if (flags & (HCKSUM_INET_PARTIAL | HCKSUM_INET_FULL_V4 |
	    HCKSUM_INET_FULL_V6 | HCKSUM_IPHDRCKSUM)) {
		/*
		 * The acknowledgement should be the same as we got when
		 * the softmac is created.
		 */
		if (!(softmac->smac_capab_flags & MAC_CAPAB_HCKSUM)) {
			ASSERT(B_FALSE);
			return (-1);
		}
		if (softmac->smac_hcksum_txflags != flags) {
			ASSERT(B_FALSE);
			return (-1);
		}
	}

	return (0);
}

static int
softmac_adv_zcopy_ack(void *arg, t_uscalar_t flags)
{
	softmac_t	*softmac = (softmac_t *)arg;

	/*
	 * The acknowledgement should be the same as we got when
	 * the softmac is created.
	 */
	ASSERT(flags == DL_CAPAB_VMSAFE_MEM);
	if (softmac->smac_capab_flags & MAC_CAPAB_NO_ZCOPY) {
		ASSERT(B_FALSE);
		return (-1);
	}

	return (0);
}

static int
softmac_adv_mdt_ack(void *arg, dl_capab_mdt_t *mdt)
{
	softmac_t *softmac = (softmac_t *)arg;

	/*
	 * The acknowledgement should be the same as we got when
	 * the softmac is created.
	 */
	if (!softmac->smac_mdt) {
		ASSERT(B_FALSE);
		return (-1);
	}

	if ((softmac->smac_mdt_capab.mdt_hdr_head != mdt->mdt_hdr_head) ||
	    (softmac->smac_mdt_capab.mdt_hdr_tail != mdt->mdt_hdr_tail) ||
	    (softmac->smac_mdt_capab.mdt_max_pld != mdt->mdt_max_pld) ||
	    (softmac->smac_mdt_capab.mdt_span_limit != mdt->mdt_span_limit)) {
		ASSERT(B_FALSE);
		return (-1);
	}
	/*
	 * We need the mdt_flags field to know whether an additional
	 * DL_CAPAB_MDT_ENABLE is necessary.
	 */
	softmac->smac_mdt_capab.mdt_flags = mdt->mdt_flags;
	return (0);
}

static int
softmac_enable_hcksum_ack(void *arg, t_uscalar_t flags)
{
	softmac_t	*softmac = (softmac_t *)arg;

	/*
	 * There are two types of acks we process here:
	 * 1. acks in reply to a (first form) generic capability req
	 *    (no ENABLE flag set)
	 * 2. acks in reply to a ENABLE capability req.
	 *    (ENABLE flag set)
	 * Only the second type should be expected here.
	 */

	if (flags & HCKSUM_ENABLE) {
		if ((flags & ~HCKSUM_ENABLE) != softmac->smac_hcksum_txflags) {
			cmn_err(CE_WARN, "softmac_enable_hcksum_ack: unexpected"
			    " hardware capability flag value 0x%x", flags);
			return (-1);
		}
	} else {
		cmn_err(CE_WARN, "softmac_enable_hcksum_ack: "
		    "hardware checksum flag HCKSUM_ENABLE is not set");
		return (-1);
	}

	return (0);
}

static int
softmac_enable_mdt_ack(void *arg, dl_capab_mdt_t *mdt)
{
	softmac_t	*softmac = (softmac_t *)arg;

	/*
	 * There are two types of acks we process here:
	 * 1. acks in reply to a (first form) generic capability req
	 *    (no ENABLE flag set)
	 * 2. acks in reply to a ENABLE capability req.
	 *    (ENABLE flag set)
	 * Only the second type should be expected here.
	 */

	if (mdt->mdt_flags & DL_CAPAB_MDT_ENABLE) {
		if ((softmac->smac_mdt_capab.mdt_hdr_head !=
		    mdt->mdt_hdr_head) ||
		    (softmac->smac_mdt_capab.mdt_hdr_tail !=
		    mdt->mdt_hdr_tail) ||
		    (softmac->smac_mdt_capab.mdt_max_pld !=
		    mdt->mdt_max_pld) ||
		    (softmac->smac_mdt_capab.mdt_span_limit !=
		    mdt->mdt_span_limit)) {
			cmn_err(CE_WARN, "softmac_enable_mdt_ack: "
			    "unexpected MDT capability value");
			return (-1);
		}
		softmac->smac_mdt_capab.mdt_flags = mdt->mdt_flags;
	} else {
		cmn_err(CE_WARN, "softmac_enable_mdt_ack: "
		    "MDT flag DL_CAPAB_MDT_ENABLE is not set");
		return (-1);
	}

	return (0);
}

static int
i_capab_ack(mblk_t *mp, queue_t *q, softmac_capab_ops_t *op, void *arg)
{
	union DL_primitives	*prim;
	dl_capability_ack_t	*cap;
	dl_capability_sub_t	*sub, *end;
	int			err = 0;

	prim = (union DL_primitives *)mp->b_rptr;
	ASSERT(prim->dl_primitive == DL_CAPABILITY_ACK);

	cap = (dl_capability_ack_t *)prim;
	if (cap->dl_sub_length == 0)
		goto exit;

	/* Is dl_sub_length correct? */
	if ((sizeof (*cap) + cap->dl_sub_length) > MBLKL(mp)) {
		err = EINVAL;
		goto exit;
	}

	sub = (dl_capability_sub_t *)((caddr_t)cap + cap->dl_sub_offset);
	end = (dl_capability_sub_t *)((caddr_t)cap + cap->dl_sub_length
	    - sizeof (*sub));
	for (; (sub <= end) && (err == 0); ) {
		switch (sub->dl_cap) {
		case DL_CAPAB_ID_WRAPPER:
			err = i_capab_id_ack(mp, sub, q, op, arg);
			break;
		default:
			err = i_capab_sub_ack(mp, sub, q, op, arg);
			break;
		}
		sub = (dl_capability_sub_t *)((caddr_t)sub + sizeof (*sub)
		    + sub->dl_length);
	}

exit:
	return (err);
}

static int
i_capab_id_ack(mblk_t *mp, dl_capability_sub_t *outers,
    queue_t *q, softmac_capab_ops_t *op, void *arg)
{
	dl_capab_id_t		*capab_id;
	dl_capability_sub_t	*inners;
	caddr_t			capend;
	int			err = EINVAL;

	ASSERT(outers->dl_cap == DL_CAPAB_ID_WRAPPER);

	capend = (caddr_t)(outers + 1) + outers->dl_length;
	if (capend > (caddr_t)mp->b_wptr) {
		cmn_err(CE_WARN, "i_capab_id_ack: malformed "
		    "sub-capability too long");
		return (err);
	}

	capab_id = (dl_capab_id_t *)(outers + 1);

	if (outers->dl_length < sizeof (*capab_id) ||
	    (inners = &capab_id->id_subcap,
	    inners->dl_length > (outers->dl_length - sizeof (*inners)))) {
		cmn_err(CE_WARN, "i_capab_id_ack: malformed "
		    "encapsulated capab type %d too long",
		    inners->dl_cap);
		return (err);
	}

	if ((q != NULL) && (!dlcapabcheckqid(&capab_id->id_mid, q))) {
		cmn_err(CE_WARN, "i_capab_id_ack: pass-thru module(s) "
		    "detected, discarding capab type %d", inners->dl_cap);
		return (err);
	}

	/* Process the encapsulated sub-capability */
	return (i_capab_sub_ack(mp, inners, q, op, arg));
}

static int
i_capab_sub_ack(mblk_t *mp, dl_capability_sub_t *sub, queue_t *q,
    softmac_capab_ops_t *op, void *arg)
{
	caddr_t			capend;
	dl_capab_hcksum_t	*hcksum;
	dl_capab_zerocopy_t	*zcopy;
	dl_capab_mdt_t		*mdt;
	int			err = 0;

	capend = (caddr_t)(sub + 1) + sub->dl_length;
	if (capend > (caddr_t)mp->b_wptr) {
		cmn_err(CE_WARN, "i_capab_sub_ack: "
		    "malformed sub-capability too long");
		return (EINVAL);
	}

	switch (sub->dl_cap) {
	case DL_CAPAB_HCKSUM:
		hcksum = (dl_capab_hcksum_t *)(sub + 1);
		err = i_capab_hcksum_ack(hcksum, q, op, arg);
		break;

	case DL_CAPAB_ZEROCOPY:
		zcopy = (dl_capab_zerocopy_t *)(sub + 1);
		err = i_capab_zcopy_ack(zcopy, q, op, arg);
		break;

	case DL_CAPAB_MDT:
		mdt = (dl_capab_mdt_t *)(sub + 1);
		err = i_capab_mdt_ack(mdt, q, op, arg);
		break;

	default:
		cmn_err(CE_WARN, "i_capab_sub_ack: unknown capab type %d",
		    sub->dl_cap);
		err = EINVAL;
	}

	return (err);
}

static int
i_capab_hcksum_ack(dl_capab_hcksum_t *hcksum, queue_t *q,
    softmac_capab_ops_t *op, void *arg)
{
	t_uscalar_t		flags;
	int			err = 0;

	if ((err = i_capab_hcksum_verify(hcksum, q)) != 0)
		return (err);

	flags = hcksum->hcksum_txflags;

	if (!(flags & (HCKSUM_INET_PARTIAL | HCKSUM_INET_FULL_V4 |
	    HCKSUM_INET_FULL_V6 | HCKSUM_IPHDRCKSUM | HCKSUM_ENABLE))) {
		cmn_err(CE_WARN, "i_capab_hcksum_ack: invalid "
		    "hardware checksum capability flags 0x%x", flags);
		return (EINVAL);
	}

	if (op->sc_hcksum_ack)
		return (op->sc_hcksum_ack(arg, flags));
	else {
		cmn_err(CE_WARN, "i_capab_hcksum_ack: unexpected hardware "
		    "checksum acknowledgement");
		return (EINVAL);
	}
}

static int
i_capab_zcopy_ack(dl_capab_zerocopy_t *zcopy, queue_t *q,
    softmac_capab_ops_t *op, void *arg)
{
	t_uscalar_t		flags;
	int			err = 0;

	if ((err = i_capab_zcopy_verify(zcopy, q)) != 0)
		return (err);

	flags = zcopy->zerocopy_flags;
	if (!(flags & DL_CAPAB_VMSAFE_MEM)) {
		cmn_err(CE_WARN, "i_capab_zcopy_ack: invalid zcopy capability "
		    "flags 0x%x", flags);
		return (EINVAL);
	}
	if (op->sc_zcopy_ack)
		return (op->sc_zcopy_ack(arg, flags));
	else {
		cmn_err(CE_WARN, "i_capab_zcopy_ack: unexpected zcopy "
		    "acknowledgement");
		return (EINVAL);
	}
}

static int
i_capab_mdt_ack(dl_capab_mdt_t *mdt, queue_t *q,
    softmac_capab_ops_t *op, void *arg)
{
	int	err;

	if ((err = i_capab_mdt_verify(mdt, q)) != 0)
		return (err);

	if (op->sc_mdt_ack)
		return (op->sc_mdt_ack(arg, mdt));
	else {
		cmn_err(CE_WARN, "i_capab_mdt_ack: unexpected MDT "
		    "acknowledgement");
		return (EINVAL);
	}
}

static int
i_capab_hcksum_verify(dl_capab_hcksum_t *hcksum, queue_t *q)
{
	if (hcksum->hcksum_version != HCKSUM_VERSION_1) {
		cmn_err(CE_WARN, "i_capab_hcksum_verify: "
		    "unsupported hardware checksum capability (version %d, "
		    "expected %d)", hcksum->hcksum_version, HCKSUM_VERSION_1);
		return (-1);
	}

	if ((q != NULL) && !dlcapabcheckqid(&hcksum->hcksum_mid, q)) {
		cmn_err(CE_WARN, "i_capab_hcksum_verify: unexpected pass-thru "
		    "module detected; hardware checksum capability discarded");
		return (-1);
	}
	return (0);
}

static int
i_capab_zcopy_verify(dl_capab_zerocopy_t *zcopy, queue_t *q)
{
	if (zcopy->zerocopy_version != ZEROCOPY_VERSION_1) {
		cmn_err(CE_WARN, "i_capab_zcopy_verify: unsupported zcopy "
		    "capability (version %d, expected %d)",
		    zcopy->zerocopy_version, ZEROCOPY_VERSION_1);
		return (-1);
	}

	if ((q != NULL) && !dlcapabcheckqid(&zcopy->zerocopy_mid, q)) {
		cmn_err(CE_WARN, "i_capab_zcopy_verify: unexpected pass-thru "
		    "module detected; zcopy checksum capability discarded");
		return (-1);
	}
	return (0);
}

static int
i_capab_mdt_verify(dl_capab_mdt_t *mdt, queue_t *q)
{
	if (mdt->mdt_version != MDT_VERSION_2) {
		cmn_err(CE_WARN, "i_capab_mdt_verify: unsupported MDT "
		    "capability (version %d, expected %d)",
		    mdt->mdt_version, MDT_VERSION_2);
		return (-1);
	}

	if ((q != NULL) && !dlcapabcheckqid(&mdt->mdt_mid, q)) {
		cmn_err(CE_WARN, "i_capab_mdt_verify: unexpected pass-thru "
		    "module detected; MDT capability discarded");
		return (-1);
	}
	return (0);
}
