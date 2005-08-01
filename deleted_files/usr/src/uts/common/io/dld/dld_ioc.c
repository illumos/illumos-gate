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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Data-Link Driver
 */

#include	<sys/types.h>
#include	<sys/stream.h>
#include	<sys/strsubr.h>
#include	<sys/ddi.h>
#include	<sys/sunddi.h>
#include	<sys/strsun.h>
#include	<sys/dlpi.h>
#include	<sys/mac.h>
#include	<sys/dls.h>
#include	<sys/dld.h>
#include	<sys/dld_impl.h>

static void	ioc_excl(queue_t *, mblk_t *);
static void	ioc_raw(dld_str_t *, mblk_t *);
static void	ioc_fast(dld_str_t *,  mblk_t *);
static void	ioc_create(dld_str_t *, mblk_t *);
static void	ioc_destroy(dld_str_t *, mblk_t *);
static void	ioc_attr(dld_str_t *, mblk_t *);
static void	ioc(dld_str_t *, mblk_t *);

typedef struct ioc_info {
	int		i_cmd;
	const char	*i_txt;
	uint_t		i_type;
	void		(*i_fn)(dld_str_t *, mblk_t *);
} ioc_info_t;

/*
 * DLIOC category jump table.
 */
static ioc_info_t	ioc_i[] = {
	{ 0x00, "unknown", DLD_CONTROL | DLD_DLPI, ioc },
	{ DLIOCRAW, "DLIOCRAW", DLD_DLPI, ioc_raw },
	{ 0x02, "unknown", DLD_CONTROL | DLD_DLPI, ioc },
	{ 0x03, "unknown", DLD_CONTROL | DLD_DLPI, ioc },
	{ 0x04, "unknown", DLD_CONTROL | DLD_DLPI, ioc },
	{ 0x05, "unknown", DLD_CONTROL | DLD_DLPI, ioc },
	{ 0x06, "unknown", DLD_CONTROL | DLD_DLPI, ioc },
	{ 0x07, "unknown", DLD_CONTROL | DLD_DLPI, ioc },
	{ 0x08, "unknown", DLD_CONTROL | DLD_DLPI, ioc },
	{ 0x09, "unknown", DLD_CONTROL | DLD_DLPI, ioc },
	{ DLIOCHDRINFO, "DLIOCHDRINFO", DLD_DLPI, ioc_fast }
};

#define	IOC_I_COUNT	(sizeof (ioc_i) / sizeof (ioc_i[0]))

/*
 * DLDIOC category jump table.
 */
static ioc_info_t	ioc_li[] = {
	{ 0x00, "unknown", DLD_CONTROL | DLD_DLPI, ioc },
	{ DLDIOCCREATE, "DLDIOC_CREATE", DLD_CONTROL, ioc_create },
	{ DLDIOCDESTROY, "DLDIOC_DESTROY", DLD_CONTROL, ioc_destroy },
	{ DLDIOCATTR, "DLDIOC_ATTR", DLD_CONTROL, ioc_attr }
};

#define	IOC_LI_COUNT	(sizeof (ioc_li) / sizeof (ioc_li[0]))

/*
 * Process an M_IOCTL message.
 */
void
dld_ioc(dld_str_t *dsp, mblk_t *mp)
{
	/*
	 * We only have shared access and we need exclusive access.
	 */
	ASSERT(!PERIM_EXCL(dsp->ds_wq));

	qwriter(dsp->ds_wq, mp, ioc_excl, PERIM_INNER);
}

/*
 * Called via qwriter(9f).
 */
static void
ioc_excl(queue_t *q, mblk_t *mp)
{
	dld_str_t		*dsp = q->q_ptr;
	struct iocblk		*iocp;
	uint_t			cmd;
	ioc_info_t		*ip;
	uint_t			cat;

	iocp = (struct iocblk *)mp->b_rptr;
	cmd = iocp->ioc_cmd;

	/*
	 * We treat the least significate byte as the actual command and
	 * the rest of it as a category.
	 */
	cat = cmd & ~0xff;
	cmd &= 0xff;

	/*
	 * Select the jump table according to the category.
	 */
	switch (cat) {
	case DLIOC:
		if (cmd >= IOC_I_COUNT)
			goto unknown;

		ip = &ioc_i[cmd];
		break;

	case DLDIOC:
		if (cmd >= IOC_LI_COUNT)
			goto unknown;

		ip = &ioc_li[cmd];
		break;

	default:
		goto unknown;
	}

	ASSERT(ip->i_cmd == (cat | cmd));

	/*
	 * Different ioctls are restricted to different types of stream. (I.e.
	 * some ioctls are only for the control node, some are for provider
	 * nodes).
	 */
	if (!(dsp->ds_type & ip->i_type)) {
		miocnak(dsp->ds_wq, mp, 0, ENOTSUP);
		return;
	}

	ASSERT(ip->i_fn != NULL);

	ip->i_fn(dsp, mp);
	return;

unknown:
	ioc(dsp, mp);
}

/*
 * DLIOCRAW
 */
static void
ioc_raw(dld_str_t *dsp, mblk_t *mp)
{
	ASSERT(PERIM_EXCL(dsp->ds_wq));
	ASSERT(dsp->ds_type == DLD_DLPI);

	if (dsp->ds_polling) {
		miocnak(dsp->ds_wq, mp, 0, EPROTO);
		return;
	}

	if (dsp->ds_dlstate == DL_IDLE) {
		/*
		 * Set the receive callback.
		 */
		dls_rx_set(dsp->ds_dc, dld_str_rx_raw, dsp);

		/*
		 * Set the M_DATA handler.
		 */
		dld_str_tx_raw(dsp);
	}

	/*
	 * Note that raw mode is enabled.
	 */
	dsp->ds_mode = DLD_RAW;

	miocack(dsp->ds_wq, mp, 0, 0);
}

/*
 * DLIOCHDRINFO
 */
static void
ioc_fast(dld_str_t *dsp, mblk_t *mp)
{
	dl_unitdata_req_t	*dlp;
	off_t			off;
	size_t			len;
	const uint8_t		*addr;
	uint16_t		sap;
	mblk_t			*nmp;
	mblk_t			*hmp;
	const mac_info_t	*mip;
	uint_t			addr_length;

	ASSERT(PERIM_EXCL(dsp->ds_wq));
	ASSERT(dsp->ds_type == DLD_DLPI);

	if (dld_opt & DLD_OPT_NO_FASTPATH) {
		miocnak(dsp->ds_wq, mp, 0, ENOTSUP);
		return;
	}

	nmp = mp->b_cont;

	dlp = (dl_unitdata_req_t *)nmp->b_rptr;
	if (MBLKL(nmp) < sizeof (dl_unitdata_req_t) ||
	    dlp->dl_primitive != DL_UNITDATA_REQ) {
		miocnak(dsp->ds_wq, mp, 0, EINVAL);
		return;
	}

	off = dlp->dl_dest_addr_offset;
	len = dlp->dl_dest_addr_length;

	if (!MBLKIN(nmp, off, len)) {
		miocnak(dsp->ds_wq, mp, 0, EINVAL);
		return;
	}

	if (dsp->ds_dlstate != DL_IDLE) {
		miocnak(dsp->ds_wq, mp, 0, ENOTSUP);
		return;
	}

	mip = dsp->ds_mip;
	addr_length = mip->mi_addr_length;
	if (len != addr_length + sizeof (uint16_t)) {
		miocnak(dsp->ds_wq, mp, 0, EINVAL);
		return;
	}

	addr = nmp->b_rptr + off;
	sap = *(uint16_t *)(nmp->b_rptr + off + addr_length);

	if ((hmp = dls_header(dsp->ds_dc, addr, sap, dsp->ds_pri)) == NULL) {
		miocnak(dsp->ds_wq, mp, 0, ENOMEM);
		return;
	}

	freemsg(nmp->b_cont);
	nmp->b_cont = hmp;

	/*
	 * Set the receive callback (unless polling is enabled).
	 */
	if (!dsp->ds_polling)
		dls_rx_set(dsp->ds_dc, dld_str_rx_fastpath, (void *)dsp);

	/*
	 * Set the M_DATA handler.
	 */
	dld_str_tx_fastpath(dsp);

	/*
	 * Note that fast-path mode is enabled.
	 */
	dsp->ds_mode = DLD_FASTPATH;

	miocack(dsp->ds_wq, mp, MBLKL(nmp) + MBLKL(hmp), 0);
}

/*
 * DLDIOCCREATE
 */
static void
ioc_create(dld_str_t *dsp, mblk_t *mp)
{
	dld_ioc_create_t	*dicp;
	mblk_t			*nmp;
	int			err;

	ASSERT(PERIM_EXCL(dsp->ds_wq));
	ASSERT(dsp->ds_type == DLD_CONTROL);

	if ((err = miocpullup(mp, sizeof (dld_ioc_create_t))) != 0) {
		miocnak(dsp->ds_wq, mp, 0, err);
		return;
	}

	nmp = mp->b_cont;

	dicp = (dld_ioc_create_t *)nmp->b_rptr;
	if ((err = dld_ppa_create(dicp->dic_name, dicp->dic_dev,
	    dicp->dic_port, dicp->dic_vid)) != 0) {
		miocnak(dsp->ds_wq, mp, 0, err);
		return;
	}

	miocack(dsp->ds_wq, mp, 0, 0);
}

/*
 * DLDIOCDESTROY
 */
static void
ioc_destroy(dld_str_t *dsp, mblk_t *mp)
{
	dld_ioc_destroy_t	*didp;
	mblk_t			*nmp;
	int			err;

	ASSERT(PERIM_EXCL(dsp->ds_wq));
	ASSERT(dsp->ds_type == DLD_CONTROL);

	if ((err = miocpullup(mp, sizeof (dld_ioc_destroy_t))) != 0) {
		miocnak(dsp->ds_wq, mp, 0, err);
		return;
	}

	nmp = mp->b_cont;

	didp = (dld_ioc_destroy_t *)nmp->b_rptr;
	if ((err = dld_ppa_destroy(didp->did_name)) != 0) {
		miocnak(dsp->ds_wq, mp, 0, err);
		return;
	}

	miocack(dsp->ds_wq, mp, 0, 0);
}

/*
 * DLDIOCATTR
 */
static void
ioc_attr(dld_str_t *dsp, mblk_t *mp)
{
	dld_ioc_attr_t	*diap;
	mblk_t		*nmp;
	int		err;

	ASSERT(PERIM_EXCL(dsp->ds_wq));
	ASSERT(dsp->ds_type == DLD_CONTROL);

	if ((err = miocpullup(mp, sizeof (dld_ioc_attr_t))) != 0) {
		miocnak(dsp->ds_wq, mp, 0, err);
		return;
	}

	nmp = mp->b_cont;

	diap = (dld_ioc_attr_t *)nmp->b_rptr;
	if ((err = dld_ppa_attr(diap->dia_name, diap->dia_dev,
	    &diap->dia_port, &diap->dia_vid)) != 0) {
		miocnak(dsp->ds_wq, mp, 0, err);
		return;
	}

	miocack(dsp->ds_wq, mp, sizeof (dld_ioc_attr_t), 0);
}

/*
 * Catch-all handler.
 */
static void
ioc(dld_str_t *dsp, mblk_t *mp)
{
	ASSERT(PERIM_EXCL(dsp->ds_wq));

	if (dsp->ds_type == DLD_CONTROL) {
		miocnak(dsp->ds_wq, mp, 0, EINVAL);
		return;
	}

	if (dsp->ds_dlstate == DL_UNATTACHED) {
		miocnak(dsp->ds_wq, mp, 0, EINVAL);
		return;
	}

	ASSERT(dsp->ds_mh != NULL);
	mac_ioctl(dsp->ds_mh, dsp->ds_wq, mp);
}
