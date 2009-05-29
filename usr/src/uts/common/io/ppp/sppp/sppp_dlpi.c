/*
 * sppp_dlpi.c - Solaris STREAMS PPP multiplexing pseudo-driver DLPI handlers
 *
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Permission to use, copy, modify, and distribute this software and its
 * documentation is hereby granted, provided that the above copyright
 * notice appears in all copies.
 *
 * SUN MAKES NO REPRESENTATION OR WARRANTIES ABOUT THE SUITABILITY OF
 * THE SOFTWARE, EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED
 * TO THE IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
 * PARTICULAR PURPOSE, OR NON-INFRINGEMENT.  SUN SHALL NOT BE LIABLE FOR
 * ANY DAMAGES SUFFERED BY LICENSEE AS A RESULT OF USING, MODIFYING OR
 * DISTRIBUTING THIS SOFTWARE OR ITS DERIVATIVES
 *
 * Copyright (c) 1994 The Australian National University.
 * All rights reserved.
 *
 * Permission to use, copy, modify, and distribute this software and its
 * documentation is hereby granted, provided that the above copyright
 * notice appears in all copies.  This software is provided without any
 * warranty, express or implied. The Australian National University
 * makes no representations about the suitability of this software for
 * any purpose.
 *
 * IN NO EVENT SHALL THE AUSTRALIAN NATIONAL UNIVERSITY BE LIABLE TO ANY
 * PARTY FOR DIRECT, INDIRECT, SPECIAL, INCIDENTAL, OR CONSEQUENTIAL DAMAGES
 * ARISING OUT OF THE USE OF THIS SOFTWARE AND ITS DOCUMENTATION, EVEN IF
 * THE AUSTRALIAN NATIONAL UNIVERSITY HAS BEEN ADVISED OF THE POSSIBILITY
 * OF SUCH DAMAGE.
 *
 * THE AUSTRALIAN NATIONAL UNIVERSITY SPECIFICALLY DISCLAIMS ANY WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS FOR A PARTICULAR PURPOSE.  THE SOFTWARE PROVIDED HEREUNDER IS
 * ON AN "AS IS" BASIS, AND THE AUSTRALIAN NATIONAL UNIVERSITY HAS NO
 * OBLIGATION TO PROVIDE MAINTENANCE, SUPPORT, UPDATES, ENHANCEMENTS,
 * OR MODIFICATIONS.
 *
 * This driver is derived from the original SVR4 STREAMS PPP driver
 * originally written by Paul Mackerras <paul.mackerras@cs.anu.edu.au>.
 *
 * Adi Masputra <adi.masputra@sun.com> rewrote and restructured the code
 * for improved performance and scalability.
 */

#define	RCSID	"$Id: sppp_dlpi.c,v 1.0 2000/05/08 01:10:12 masputra Exp $"

#include <sys/types.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/stream.h>
#include <sys/stropts.h>
#include <sys/errno.h>
#include <sys/time.h>
#include <sys/cmn_err.h>
#include <sys/conf.h>
#include <sys/dlpi.h>
#include <sys/ddi.h>
#include <sys/kstat.h>
#include <sys/strsubr.h>
#include <sys/strsun.h>
#include <sys/ethernet.h>
#include <net/ppp_defs.h>
#include <netinet/in.h>
#include <net/pppio.h>
#include "s_common.h"
#include "sppp.h"

static int	sppp_dlattachreq(queue_t *, mblk_t *, spppstr_t *);
static int	sppp_dldetachreq(queue_t *, mblk_t *, spppstr_t *);
static int	sppp_dlbindreq(queue_t *, mblk_t *, spppstr_t *);
static int	sppp_dlunbindreq(queue_t *, mblk_t *, spppstr_t *);
static int	sppp_dlinforeq(queue_t *, mblk_t *, spppstr_t *);
static int	sppp_dlunitdatareq(queue_t *, mblk_t *, spppstr_t *);
static int	sppp_dlpromisconreq(queue_t *, mblk_t *, spppstr_t *);
static int	sppp_dlpromiscoffreq(queue_t *, mblk_t *, spppstr_t *);
static int	sppp_dlphyreq(queue_t *, mblk_t *, spppstr_t *);
static void	sppp_dl_attach_upper(queue_t *, mblk_t *);
static void	sppp_dl_detach_upper(queue_t *, mblk_t *);
static void	sppp_dl_bind(queue_t *, mblk_t *);
static void	sppp_dl_unbind(queue_t *, mblk_t *);
static void	sppp_dl_promiscon(queue_t *, mblk_t *);
static void	sppp_dl_promiscoff(queue_t *, mblk_t *);
static mblk_t	*sppp_dladdether(spppstr_t *, mblk_t *, t_scalar_t);

static struct sppp_dlpi_pinfo_t dl_pinfo[DL_MAXPRIM + 1];

#if 0
#define	DBGERROR(x)	cmn_err x
#else
#define	DBGERROR(x)	((void)0)
#endif

/* #define	DBG_DLPI	1 */

#ifdef DBG_DLPI
struct sppp_dlpi_entry {
	uint32_t sde_val;
	const char *sde_name;
};

static const struct sppp_dlpi_entry sppp_dlpi_list[] = {
	{ DL_INFO_REQ, "DL_INFO_REQ" },
	{ DL_INFO_ACK, "DL_INFO_ACK" },
	{ DL_ATTACH_REQ, "DL_ATTACH_REQ" },
	{ DL_DETACH_REQ, "DL_DETACH_REQ" },
	{ DL_BIND_REQ, "DL_BIND_REQ" },
	{ DL_BIND_ACK, "DL_BIND_ACK" },
	{ DL_UNBIND_REQ, "DL_UNBIND_REQ" },
	{ DL_OK_ACK, "DL_OK_ACK" },
	{ DL_ERROR_ACK, "DL_ERROR_ACK" },
	{ DL_SUBS_BIND_REQ, "DL_SUBS_BIND_REQ" },
	{ DL_SUBS_BIND_ACK, "DL_SUBS_BIND_ACK" },
	{ DL_SUBS_UNBIND_REQ, "DL_SUBS_UNBIND_REQ" },
	{ DL_ENABMULTI_REQ, "DL_ENABMULTI_REQ" },
	{ DL_DISABMULTI_REQ, "DL_DISABMULTI_REQ" },
	{ DL_PROMISCON_REQ, "DL_PROMISCON_REQ" },
	{ DL_PROMISCOFF_REQ, "DL_PROMISCOFF_REQ" },
	{ DL_UNITDATA_REQ, "DL_UNITDATA_REQ" },
	{ DL_UNITDATA_IND, "DL_UNITDATA_IND" },
	{ DL_UDERROR_IND, "DL_UDERROR_IND" },
	{ DL_UDQOS_REQ, "DL_UDQOS_REQ" },
	{ DL_CONNECT_REQ, "DL_CONNECT_REQ" },
	{ DL_CONNECT_IND, "DL_CONNECT_IND" },
	{ DL_CONNECT_RES, "DL_CONNECT_RES" },
	{ DL_CONNECT_CON, "DL_CONNECT_CON" },
	{ DL_TOKEN_REQ, "DL_TOKEN_REQ" },
	{ DL_TOKEN_ACK, "DL_TOKEN_ACK" },
	{ DL_DISCONNECT_REQ, "DL_DISCONNECT_REQ" },
	{ DL_DISCONNECT_IND, "DL_DISCONNECT_IND" },
	{ DL_RESET_REQ, "DL_RESET_REQ" },
	{ DL_RESET_IND, "DL_RESET_IND" },
	{ DL_RESET_RES, "DL_RESET_RES" },
	{ DL_RESET_CON, "DL_RESET_CON" },
	{ DL_DATA_ACK_REQ, "DL_DATA_ACK_REQ" },
	{ DL_DATA_ACK_IND, "DL_DATA_ACK_IND" },
	{ DL_DATA_ACK_STATUS_IND, "DL_DATA_ACK_STATUS_IND" },
	{ DL_REPLY_REQ, "DL_REPLY_REQ" },
	{ DL_REPLY_IND, "DL_REPLY_IND" },
	{ DL_REPLY_STATUS_IND, "DL_REPLY_STATUS_IND" },
	{ DL_REPLY_UPDATE_REQ, "DL_REPLY_UPDATE_REQ" },
	{ DL_REPLY_UPDATE_STATUS_IND, "DL_REPLY_UPDATE_STATUS_IND" },
	{ DL_XID_REQ, "DL_XID_REQ" },
	{ DL_XID_IND, "DL_XID_IND" },
	{ DL_XID_RES, "DL_XID_RES" },
	{ DL_XID_CON, "DL_XID_CON" },
	{ DL_TEST_REQ, "DL_TEST_REQ" },
	{ DL_TEST_IND, "DL_TEST_IND" },
	{ DL_TEST_RES, "DL_TEST_RES" },
	{ DL_TEST_CON, "DL_TEST_CON" },
	{ DL_PHYS_ADDR_REQ, "DL_PHYS_ADDR_REQ" },
	{ DL_PHYS_ADDR_ACK, "DL_PHYS_ADDR_ACK" },
	{ DL_SET_PHYS_ADDR_REQ, "DL_SET_PHYS_ADDR_REQ" },
	{ DL_GET_STATISTICS_REQ, "DL_GET_STATISTICS_REQ" },
	{ DL_GET_STATISTICS_ACK, "DL_GET_STATISTICS_ACK" },
	{ 0, NULL }
};

static const struct sppp_dlpi_entry sppp_state_list[] = {
	{ DL_UNBOUND, "DL_UNBOUND" },
	{ DL_BIND_PENDING, "DL_BIND_PENDING" },
	{ DL_UNBIND_PENDING, "DL_UNBIND_PENDING" },
	{ DL_IDLE, "DL_IDLE" },
	{ DL_UNATTACHED, "DL_UNATTACHED" },
	{ DL_ATTACH_PENDING, "DL_ATTACH_PENDING" },
	{ DL_DETACH_PENDING, "DL_DETACH_PENDING" },
	{ DL_UDQOS_PENDING, "DL_UDQOS_PENDING" },
	{ DL_OUTCON_PENDING, "DL_OUTCON_PENDING" },
	{ DL_INCON_PENDING, "DL_INCON_PENDING" },
	{ DL_CONN_RES_PENDING, "DL_CONN_RES_PENDING" },
	{ DL_DATAXFER, "DL_DATAXFER" },
	{ DL_USER_RESET_PENDING, "DL_USER_RESET_PENDING" },
	{ DL_PROV_RESET_PENDING, "DL_PROV_RESET_PENDING" },
	{ DL_RESET_RES_PENDING, "DL_RESET_RES_PENDING" },
	{ DL_DISCON8_PENDING, "DL_DISCON8_PENDING" },
	{ DL_DISCON9_PENDING, "DL_DISCON9_PENDING" },
	{ DL_DISCON11_PENDING, "DL_DISCON11_PENDING" },
	{ DL_DISCON12_PENDING, "DL_DISCON12_PENDING" },
	{ DL_DISCON13_PENDING, "DL_DISCON13_PENDING" },
	{ DL_SUBS_BIND_PND, "DL_SUBS_BIND_PND" },
	{ DL_SUBS_UNBIND_PND, "DL_SUBS_UNBIND_PND" },
	{ 0, NULL }
};

static const char *
prim2name(uint32_t prim)
{
	const struct sppp_dlpi_entry *sde;

	for (sde = sppp_dlpi_list; sde->sde_name != NULL; sde++)
		if (sde->sde_val == prim)
			break;
	return (sde->sde_name);
}

static const char *
state2name(uint32_t state)
{
	const struct sppp_dlpi_entry *sde;

	for (sde = sppp_state_list; sde->sde_name != NULL; sde++)
		if (sde->sde_val == state)
			break;
	return (sde->sde_name);
}

#define	DBGDLPI(x)	cmn_err x
#else
#define	DBGDLPI(x)	((void)0)
#endif /* DBG_DLPI */

/*
 * DL_INFO_ACK template for point-to-point interface.
 */
static dl_info_ack_t	sppp_infoack = {
	DL_INFO_ACK,			/* dl_primitive */
	PPP_MAXMTU,			/* dl_max_sdu */
	0,				/* dl_min_sdu */
	SPPP_ADDRL,			/* dl_addr_length */
	/*
	 * snoop et. al. don't know about DL_OTHER so this entry
	 * was changed to DL_ETHER so ethernet tracing/snooping
	 * facilities will work with PPP interfaces.
	 */
	DL_ETHER,			/* dl_mac_type */
	0,				/* dl_reserved */
	0,				/* dl_current_state */
	SPPP_SAPL,			/* dl_sap_length */
	DL_CLDLS,			/* dl_service_mode */
	0,				/* dl_qos_length */
	0,				/* dl_qos_offset */
	0,				/* dl_range_length */
	0,				/* dl_range_offset */
	DL_STYLE2,			/* dl_provider_style */
	sizeof (dl_info_ack_t),		/* dl_addr_offset */
	DL_VERSION_2,			/* dl_version */
	0,				/* dl_brdcst_addr_length */
	0,				/* dl_brdcst_addr_offset */
	0				/* dl_growth */
};

/*
 * sppp_dlpi_pinfoinit()
 *
 * Description:
 *    Initialize dl_pinfo[], called from sppp_attach.
 */
void
sppp_dlpi_pinfoinit(void)
{
	bzero(dl_pinfo, sizeof (dl_pinfo));	/* Just to be safe */

	dl_pinfo[DL_ATTACH_REQ].pi_minlen = sizeof (dl_attach_req_t);
	dl_pinfo[DL_ATTACH_REQ].pi_state = DL_UNATTACHED;
	dl_pinfo[DL_ATTACH_REQ].pi_funcp = sppp_dlattachreq;

	dl_pinfo[DL_DETACH_REQ].pi_minlen = sizeof (dl_detach_req_t);
	dl_pinfo[DL_DETACH_REQ].pi_state = DL_UNBOUND;
	dl_pinfo[DL_DETACH_REQ].pi_funcp = sppp_dldetachreq;

	dl_pinfo[DL_BIND_REQ].pi_minlen = sizeof (dl_bind_req_t);
	dl_pinfo[DL_BIND_REQ].pi_state = DL_UNBOUND;
	dl_pinfo[DL_BIND_REQ].pi_funcp = sppp_dlbindreq;

	dl_pinfo[DL_UNBIND_REQ].pi_minlen = sizeof (dl_unbind_req_t);
	dl_pinfo[DL_UNBIND_REQ].pi_state = DL_IDLE;
	dl_pinfo[DL_UNBIND_REQ].pi_funcp = sppp_dlunbindreq;

	dl_pinfo[DL_INFO_REQ].pi_minlen = sizeof (dl_info_req_t);
	dl_pinfo[DL_INFO_REQ].pi_state = -1;	/* special handling */
	dl_pinfo[DL_INFO_REQ].pi_funcp = sppp_dlinforeq;

	dl_pinfo[DL_UNITDATA_REQ].pi_minlen = sizeof (dl_unitdata_req_t);
	dl_pinfo[DL_UNITDATA_REQ].pi_state = DL_IDLE;
	dl_pinfo[DL_UNITDATA_REQ].pi_funcp = sppp_dlunitdatareq;

	dl_pinfo[DL_PROMISCON_REQ].pi_minlen = sizeof (dl_promiscon_req_t);
	dl_pinfo[DL_PROMISCON_REQ].pi_state = -1; /* special handling */
	dl_pinfo[DL_PROMISCON_REQ].pi_funcp = sppp_dlpromisconreq;

	dl_pinfo[DL_PROMISCOFF_REQ].pi_minlen = sizeof (dl_promiscoff_req_t);
	dl_pinfo[DL_PROMISCOFF_REQ].pi_state = -1; /* special handling */
	dl_pinfo[DL_PROMISCOFF_REQ].pi_funcp = sppp_dlpromiscoffreq;

	dl_pinfo[DL_PHYS_ADDR_REQ].pi_minlen = sizeof (dl_phys_addr_req_t);
	dl_pinfo[DL_PHYS_ADDR_REQ].pi_state = -1; /* special handling */
	dl_pinfo[DL_PHYS_ADDR_REQ].pi_funcp = sppp_dlphyreq;
}

/*
 * sppp_mproto()
 *
 * MT-Perimeters:
 *    shared inner, shared outer.
 *
 * Description:
 *    Handle M_PCPROTO/M_PROTO messages, called by sppp_uwput.
 */
int
sppp_mproto(queue_t *q, mblk_t *mp, spppstr_t *sps)
{
	union DL_primitives *dlp;
	struct sppp_dlpi_pinfo_t *dpi;
	t_uscalar_t	prim;
	int		len;
	int		error = 0;

	ASSERT(!IS_SPS_CONTROL(sps));
	if ((len = MBLKL(mp)) < sizeof (t_uscalar_t)) {
		DBGERROR((CE_CONT, "bad mproto: block length %d\n", len));
		merror(q, mp, EPROTO);
		return (0);
	}
	dlp = (union DL_primitives *)mp->b_rptr;
	prim = dlp->dl_primitive;
	if (prim > DL_MAXPRIM) {
		DBGERROR((CE_CONT, "bad mproto: primitive %d > %d\n", prim,
		    DL_MAXPRIM));
		error = DL_BADPRIM;
	} else {
		dpi = &dl_pinfo[prim];
		if (dpi->pi_funcp == NULL) {
			DBGERROR((CE_CONT,
			    "bad mproto: primitive %d not supported\n", prim));
			error = DL_NOTSUPPORTED;
		} else if (len < dpi->pi_minlen) {
			DBGERROR((CE_CONT,
			    "bad mproto: primitive len %d < %d\n", len,
			    dpi->pi_minlen));
			error = DL_BADPRIM;
		} else if (dpi->pi_state != -1 &&
		    sps->sps_dlstate != dpi->pi_state) {
			DBGERROR((CE_CONT,
			    "bad state %d != %d for primitive %d\n",
			    sps->sps_dlstate, dpi->pi_state, prim));
			error = DL_OUTSTATE;
		}
	}
	if (error != 0) {
		dlerrorack(q, mp, dlp->dl_primitive, error, 0);
		return (0);
	}
#ifdef DBG_DLPI
	{
		const char *cp = prim2name(prim);
		if (cp != NULL)
			cmn_err(CE_CONT, "/%d: Dispatching %s\n",
			    sps->sps_mn_id, cp);
		else
			cmn_err(CE_CONT,
			    "/%d: Dispatching unknown primitive %d\n",
			    sps->sps_mn_id, prim);
	}
#endif
	return ((*dpi->pi_funcp)(q, mp, sps));
}

/*
 * sppp_dlattachreq()
 *
 * MT-Perimeters:
 *    shared inner, shared outer.
 *
 * Description:
 *    Perform DL_ATTACH_REQ request, called by sppp_mproto.
 */
static int
sppp_dlattachreq(queue_t *q, mblk_t *mp, spppstr_t *sps)
{
	int	error = 0;
	union DL_primitives *dlp;

	ASSERT(q != NULL && q->q_ptr != NULL);
	ASSERT(mp != NULL && mp->b_rptr != NULL);
	dlp = (union DL_primitives *)mp->b_rptr;
	ASSERT(sps != NULL);
	ASSERT(sps->sps_dlstate == DL_UNATTACHED);

	if (IS_SPS_PIOATTACH(sps)) {
		DBGERROR((CE_CONT, "DLPI attach: already attached\n"));
		error = EINVAL;
	}
	if (error != 0) {
		dlerrorack(q, mp, dlp->dl_primitive, DL_OUTSTATE, error);
	} else {
		qwriter(q, mp, sppp_dl_attach_upper, PERIM_OUTER);
	}
	return (0);
}

/*
 * sppp_dl_attach_upper()
 *
 * MT-Perimeters:
 *    exclusive inner, exclusive outer.
 *
 * Description:
 *    Called by qwriter (INNER) from sppp_dlattachreq as the result of
 *    receiving a DL_ATTACH_REQ message.
 */
static void
sppp_dl_attach_upper(queue_t *q, mblk_t *mp)
{
	sppa_t		*ppa;
	spppstr_t	*sps = q->q_ptr;
	union DL_primitives *dlp;
	int		err = ENOMEM;
	cred_t		*cr;
	zoneid_t	zoneid;

	ASSERT(!IS_SPS_PIOATTACH(sps));
	dlp = (union DL_primitives *)mp->b_rptr;

	/* If there's something here, it's detached. */
	if (sps->sps_ppa != NULL) {
		sppp_remove_ppa(sps);
	}

	if ((cr = msg_getcred(mp, NULL)) == NULL)
		zoneid = sps->sps_zoneid;
	else
		zoneid = crgetzoneid(cr);

	ppa = sppp_find_ppa(dlp->attach_req.dl_ppa);
	if (ppa == NULL) {
		ppa = sppp_create_ppa(dlp->attach_req.dl_ppa, zoneid);
	} else if (ppa->ppa_zoneid != zoneid) {
		ppa = NULL;
		err = EPERM;
	}

	/*
	 * If we can't find or create it, then it's either because we're out of
	 * memory or because the requested PPA is owned by a different zone.
	 */
	if (ppa == NULL) {
		DBGERROR((CE_CONT, "DLPI attach: cannot create ppa %u\n",
		    dlp->attach_req.dl_ppa));
		dlerrorack(q, mp, dlp->dl_primitive, DL_SYSERR, err);
		return;
	}
	/*
	 * Preallocate the hangup message so that we're always able to
	 * send this upstream in the event of a catastrophic failure.
	 */
	if ((sps->sps_hangup = allocb(1, BPRI_MED)) == NULL) {
		DBGERROR((CE_CONT, "DLPI attach: cannot allocate hangup\n"));
		dlerrorack(q, mp, dlp->dl_primitive, DL_SYSERR, ENOSR);
		return;
	}
	sps->sps_dlstate = DL_UNBOUND;
	sps->sps_ppa = ppa;
	/*
	 * Add this stream to the head of the list of sibling streams
	 * which belong to the specified ppa.
	 */
	rw_enter(&ppa->ppa_sib_lock, RW_WRITER);
	ppa->ppa_refcnt++;
	sps->sps_nextsib = ppa->ppa_streams;
	ppa->ppa_streams = sps;
	/*
	 * And if this stream was marked as promiscuous (SPS_PROMISC), then we
	 * need to update the promiscuous streams count. This should only
	 * happen when DL_PROMISCON_REQ was issued prior to attachment.
	 */
	if (IS_SPS_PROMISC(sps)) {
		ppa->ppa_promicnt++;
	}
	rw_exit(&ppa->ppa_sib_lock);
	DBGDLPI((CE_CONT, "/%d: attached to ppa %d\n", sps->sps_mn_id,
	    ppa->ppa_ppa_id));
	dlokack(q, mp, DL_ATTACH_REQ);
}

/*
 * sppp_dldetachreq()
 *
 * MT-Perimeters:
 *    shared inner, shared outer.
 *
 * Description:
 *    Perform DL_DETACH_REQ request, called by sppp_mproto.
 */
/* ARGSUSED */
static int
sppp_dldetachreq(queue_t *q, mblk_t *mp, spppstr_t *sps)
{
	ASSERT(q != NULL && q->q_ptr != NULL);
	ASSERT(mp != NULL && mp->b_rptr != NULL);
	ASSERT(sps != NULL);
	ASSERT(sps->sps_dlstate == DL_UNBOUND);
	ASSERT(!IS_SPS_PIOATTACH(sps));

	qwriter(q, mp, sppp_dl_detach_upper, PERIM_INNER);
	return (0);
}

/*
 * sppp_dl_detach_upper()
 *
 * MT-Perimeters:
 *    exclusive inner, shared outer.
 *
 * Description:
 *    Called by qwriter (INNER) from sppp_dldetachreq as the result of
 *    receiving a DL_DETACH_REQ message.
 */
/* ARGSUSED */
static void
sppp_dl_detach_upper(queue_t *q, mblk_t *mp)
{
	spppstr_t	*sps;

	ASSERT(q != NULL && q->q_ptr != NULL);
	ASSERT(mp != NULL && mp->b_rptr != NULL);
	sps = (spppstr_t *)q->q_ptr;
	/*
	 * We don't actually detach from the PPA until closed or
	 * reattached.
	 */
	sps->sps_flags &= ~SPS_PROMISC;	/* clear flag anyway */
	sps->sps_dlstate = DL_UNATTACHED;
	dlokack(q, mp, DL_DETACH_REQ);
}

/*
 * sppp_dlbindreq()
 *
 * MT-Perimeters:
 *    shared inner, shared outer.
 *
 * Description:
 *    Perform DL_BIND_REQ request, called by sppp_mproto.
 */
static int
sppp_dlbindreq(queue_t *q, mblk_t *mp, spppstr_t *sps)
{
	sppa_t			*ppa;
	union DL_primitives	*dlp;
	spppreqsap_t		req_sap;
	int			error = 0;

	ASSERT(q != NULL && q->q_ptr != NULL);
	ASSERT(mp != NULL && mp->b_rptr != NULL);
	dlp = (union DL_primitives *)mp->b_rptr;
	req_sap = dlp->bind_req.dl_sap;
	ASSERT(sps != NULL);
	ASSERT(!IS_SPS_PIOATTACH(sps));
	ASSERT(sps->sps_dlstate == DL_UNBOUND);

	ppa = sps->sps_ppa;
	if (ppa == NULL) {
		DBGERROR((CE_CONT, "DLPI bind: no attached ppa\n"));
		error = DL_OUTSTATE;
	} else if ((req_sap != ETHERTYPE_IP) && (req_sap != ETHERTYPE_IPV6) &&
	    (req_sap != ETHERTYPE_ALLSAP)) {
		DBGERROR((CE_CONT, "DLPI bind: unknown SAP %x\n", req_sap));
		error = DL_BADADDR;
	}
	if (error != 0) {
		dlerrorack(q, mp, dlp->dl_primitive, error, 0);
	} else {
		qwriter(q, mp, sppp_dl_bind, PERIM_INNER);
	}
	return (0);
}

/*
 * sppp_dl_bind()
 *
 * MT-Perimeters:
 *    exclusive inner, shared outer.
 *
 * Description:
 *    Called by qwriter (INNER) from sppp_dlbindreq as the result of
 *    receiving a DL_BIND_REQ message.
 */
static void
sppp_dl_bind(queue_t *q, mblk_t *mp)
{
	spppstr_t		*sps;
	sppa_t			*ppa;
	union DL_primitives	*dlp;
	t_scalar_t		sap;
	spppreqsap_t		req_sap;
	mblk_t			*lsmp;

	ASSERT(q != NULL && q->q_ptr != NULL);
	sps = (spppstr_t *)q->q_ptr;
	ASSERT(mp != NULL && mp->b_rptr != NULL);
	dlp = (union DL_primitives *)mp->b_rptr;
	ppa = sps->sps_ppa;
	ASSERT(ppa != NULL);
	req_sap = dlp->bind_req.dl_sap;
	ASSERT((req_sap == ETHERTYPE_IP) || (req_sap == ETHERTYPE_IPV6) ||
	    (req_sap == ETHERTYPE_ALLSAP));

	if (req_sap == ETHERTYPE_IP) {
		sap = PPP_IP;
	} else if (req_sap == ETHERTYPE_IPV6) {
		sap = PPP_IPV6;
	} else if (req_sap == ETHERTYPE_ALLSAP) {
		sap = PPP_ALLSAP;
	}
	/*
	 * If there's another stream with the same sap has already been bound
	 * to the same ppa, then return with DL_NOADDR. However, we do make an
	 * exception for snoop (req_sap=0x00, sap=0xff) since multiple
	 * instances of snoop may execute an a given device.
	 */
	lsmp = NULL;
	if (sap != PPP_ALLSAP) {
		if ((sap == PPP_IP) && (ppa->ppa_ip_cache == NULL)) {
			ppa->ppa_ip_cache = sps;
			if (ppa->ppa_ctl != NULL) {
				lsmp = create_lsmsg(PPP_LINKSTAT_IPV4_BOUND);
			}
		} else if ((sap == PPP_IPV6) && (ppa->ppa_ip6_cache == NULL)) {
			ppa->ppa_ip6_cache = sps;
			if (ppa->ppa_ctl != NULL) {
				lsmp = create_lsmsg(PPP_LINKSTAT_IPV6_BOUND);
			}
		} else {
			DBGERROR((CE_CONT, "DLPI bind: bad SAP %x\n", sap));
			dlerrorack(q, mp, dlp->dl_primitive, DL_NOADDR,
			    EEXIST);
			return;
		}
		sps->sps_flags |= SPS_CACHED;
	}
	/*
	 * Tell the daemon that a DLPI bind has happened on this stream,
	 * and we'll only do this for PPP_IP or PPP_IPV6 sap (not snoop).
	 */
	if (lsmp != NULL && ppa->ppa_ctl != NULL) {
#ifdef DBG_DLPI
		cmn_err(CE_CONT, "sending up %s\n",
		    ((sap == PPP_IP) ? "PPP_LINKSTAT_IPV4_BOUND" :
		    "PPP_LINKSTAT_IPV6_BOUND"));
#endif
		putnext(ppa->ppa_ctl->sps_rq, lsmp);
	}
	DBGDLPI((CE_CONT, "/%d: bound to sap %X (req %X)\n", sps->sps_mn_id,
	    sap, req_sap));
	sps->sps_req_sap = req_sap;
	sps->sps_sap = sap;
	sps->sps_dlstate = DL_IDLE;
	dlbindack(q, mp, req_sap, &sap, sizeof (int32_t), 0, 0);
}

/*
 * sppp_dlunbindreq()
 *
 * MT-Perimeters:
 *    shared inner, shared outer.
 *
 * Description:
 *    Perform DL_UNBIND_REQ request, called by sppp_mproto.
 */
/* ARGSUSED */
static int
sppp_dlunbindreq(queue_t *q, mblk_t *mp, spppstr_t *sps)
{
	ASSERT(q != NULL && q->q_ptr != NULL);
	ASSERT(mp != NULL && mp->b_rptr != NULL);
	ASSERT(sps != NULL);
	ASSERT(!IS_SPS_PIOATTACH(sps));
	ASSERT(sps->sps_dlstate == DL_IDLE);

	qwriter(q, mp, sppp_dl_unbind, PERIM_INNER);
	return (0);
}

/*
 * sppp_dl_unbind()
 *
 * MT-Perimeters:
 *    exclusive inner, shared outer.
 *
 * Description:
 *    Called by qwriter (INNER) from sppp_dlunbindreq as the result of
 *    receiving a DL_UNBIND_REQ message.
 */
static void
sppp_dl_unbind(queue_t *q, mblk_t *mp)
{
	spppstr_t	*sps;
	sppa_t		*ppa;
	t_scalar_t	sap;
	mblk_t		*msg;
	boolean_t	saydown;

	ASSERT(q != NULL && q->q_ptr != NULL);
	sps = (spppstr_t *)q->q_ptr;
	ppa = sps->sps_ppa;
	ASSERT(mp != NULL && mp->b_rptr != NULL);
	sap = sps->sps_sap;
	ASSERT((sap == PPP_IP) || (sap == PPP_IPV6) || (sap == PPP_ALLSAP));

	/* Flush messages on unbind, per DLPI specification. */
	flushq(WR(q), FLUSHALL);
	flushq(RD(q), FLUSHALL);

	if ((ppa != NULL) && IS_SPS_CACHED(sps)) {
		sps->sps_flags &= ~SPS_CACHED;
		msg = NULL;
		saydown = (ppa->ppa_ctl != NULL &&
		    (sps->sps_npmode == NPMODE_PASS ||
		    sps->sps_npmode == NPMODE_QUEUE));
		if (sap == PPP_IP) {
			ppa->ppa_ip_cache = NULL;
			if (saydown)
				msg = create_lsmsg(PPP_LINKSTAT_IPV4_UNBOUND);
		} else if (sap == PPP_IPV6) {
			ppa->ppa_ip6_cache = NULL;
			if (saydown)
				msg = create_lsmsg(PPP_LINKSTAT_IPV6_UNBOUND);
		}
		if (msg != NULL) {
#ifdef DBG_DLPI
			cmn_err(CE_CONT, "sending up %s\n",
			    ((sap == PPP_IP) ? "PPP_LINKSTAT_IPV4_UNBOUND" :
			    "PPP_LINKSTAT_IPV6_UNBOUND"));
#endif
			putnext(ppa->ppa_ctl->sps_rq, msg);
		}
	}
	DBGDLPI((CE_CONT, "/%d: unbound from sap %X (req %X)\n", sps->sps_mn_id,
	    sps->sps_sap, sps->sps_req_sap));
	sps->sps_req_sap = 0;
	sps->sps_sap = -1;
	sps->sps_dlstate = DL_UNBOUND;

	dlokack(q, mp, DL_UNBIND_REQ);
}

/*
 * sppp_dlinforeq()
 *
 * MT-Perimeters:
 *    shared inner, shared outer.
 *
 * Description:
 *    Perform DL_INFO_REQ request, called by sppp_mproto.
 */
static int
sppp_dlinforeq(queue_t *q, mblk_t *mp, spppstr_t *sps)
{
	dl_info_ack_t	*dlip;
	uint32_t	size;
	uint32_t	addr_size;
	sppa_t		*ppa;

	ASSERT(q != NULL && q->q_ptr != NULL);
	ASSERT(mp != NULL && mp->b_rptr != NULL);
	ASSERT(sps != NULL);
	ppa = sps->sps_ppa;

	/* Exchange current msg for a DL_INFO_ACK. */
	addr_size = SPPP_ADDRL;
	size = sizeof (dl_info_ack_t) + addr_size;
	if ((mp = mexchange(q, mp, size, M_PCPROTO, DL_INFO_ACK)) == NULL) {
		DBGERROR((CE_CONT, "DLPI info: mexchange failed\n"));
		/* mexchange already sent up an merror ENOSR */
		return (0);
	}
	/* Fill in DL_INFO_ACK fields and reply */
	dlip = (dl_info_ack_t *)mp->b_rptr;
	*dlip = sppp_infoack;
	dlip->dl_current_state = sps->sps_dlstate;
	dlip->dl_max_sdu = ppa != NULL ? ppa->ppa_mtu : PPP_MAXMTU;
#ifdef DBG_DLPI
	{
		const char *cp = state2name(dlip->dl_current_state);
		if (cp != NULL)
			cmn_err(CE_CONT, "info returns state %s, max sdu %d\n",
			    cp, dlip->dl_max_sdu);
		else
			cmn_err(CE_CONT, "info returns state %d, max sdu %d\n",
			    dlip->dl_current_state, dlip->dl_max_sdu);
	}
#endif
	qreply(q, mp);
	return (0);
}

/*
 * sppp_dlunitdatareq()
 *
 * MT-Perimeters:
 *    shared inner, shared outer.
 *
 * Description:
 *    Handle DL_UNITDATA_REQ request, called by sppp_mproto. This procedure
 *    gets called for M_PROTO (DLPI) style of transmission. The fact that we
 *    have acknowledged IP's fastpath probing (DL_IOC_HDR_INFO) does not
 *    guarantee that IP will always transmit via M_DATA, and it merely implies
 *    that such situation _may_ happen. In other words, IP may decide to use
 *    M_PROTO (DLPI) for data transmission should it decide to do so.
 *    Therefore, we should never place any restrictions or checks against
 *    streams marked with SPS_FASTPATH, since it is legal for this procedure
 *    to be entered with or without the bit set.
 */
static int
sppp_dlunitdatareq(queue_t *q, mblk_t *mp, spppstr_t *sps)
{
	sppa_t		*ppa;
	mblk_t		*hdrmp;
	mblk_t		*pktmp;
	dl_unitdata_req_t *dludp;
	int		dladdroff;
	int		dladdrlen;
	int		msize;
	int		error = 0;
	boolean_t	is_promisc;

	ASSERT(q != NULL && q->q_ptr != NULL);
	ASSERT(mp != NULL && mp->b_rptr != NULL);
	ASSERT((MTYPE(mp) == M_PCPROTO) || (MTYPE(mp) == M_PROTO));
	dludp = (dl_unitdata_req_t *)mp->b_rptr;
	dladdroff = dludp->dl_dest_addr_offset;
	dladdrlen = dludp->dl_dest_addr_length;
	ASSERT(sps != NULL);
	ASSERT(!IS_SPS_PIOATTACH(sps));
	ASSERT(sps->sps_dlstate == DL_IDLE);
	ASSERT(q->q_ptr == sps);
	/*
	 * If this stream is not attached to any ppas, then discard data
	 * coming down through this stream.
	 */
	ppa = sps->sps_ppa;
	if (ppa == NULL) {
		DBGERROR((CE_CONT, "DLPI unitdata: no attached ppa\n"));
		error = ENOLINK;
	} else if (mp->b_cont == NULL) {
		DBGERROR((CE_CONT, "DLPI unitdata: missing data\n"));
		error = EPROTO;
	}
	if (error != 0) {
		dluderrorind(q, mp, mp->b_rptr + dladdroff, dladdrlen,
		    DL_BADDATA, error);
		return (0);
	}
	ASSERT(mp->b_cont->b_rptr != NULL);
	/*
	 * Check if outgoing packet size is larger than allowed. We use
	 * msgdsize to count all of M_DATA blocks in the message.
	 */
	msize = msgdsize(mp);
	if (msize > ppa->ppa_mtu) {
		/* Log, and send it anyway */
		mutex_enter(&ppa->ppa_sta_lock);
		ppa->ppa_otoolongs++;
		mutex_exit(&ppa->ppa_sta_lock);
	}
	if (IS_SPS_KDEBUG(sps)) {
		SPDEBUG(PPP_DRV_NAME
		    "/%d: DL_UNITDATA_REQ (%d bytes) sps=0x%p flags=0x%b "
		    "ppa=0x%p flags=0x%b\n", sps->sps_mn_id, msize,
		    (void *)sps, sps->sps_flags, SPS_FLAGS_STR,
		    (void *)ppa, ppa->ppa_flags, PPA_FLAGS_STR);
	}
	/* Allocate a message (M_DATA) to contain PPP header bytes. */
	if ((hdrmp = allocb(PPP_HDRLEN, BPRI_MED)) == NULL) {
		mutex_enter(&ppa->ppa_sta_lock);
		ppa->ppa_allocbfail++;
		mutex_exit(&ppa->ppa_sta_lock);
		DBGERROR((CE_CONT,
		    "DLPI unitdata: can't allocate header buffer\n"));
		dluderrorind(q, mp, mp->b_rptr + dladdroff, dladdrlen,
		    DL_SYSERR, ENOSR);
		return (0);
	}
	/*
	 * Should there be any promiscuous stream(s), send the data up
	 * for each promiscuous stream that we recognize.
	 */
	rw_enter(&ppa->ppa_sib_lock, RW_READER);
	is_promisc = ppa->ppa_promicnt;
	if (is_promisc) {
		ASSERT(ppa->ppa_streams != NULL);
		sppp_dlprsendup(ppa->ppa_streams, mp->b_cont, sps->sps_sap,
		    B_FALSE);
	}
	rw_exit(&ppa->ppa_sib_lock);
	/* Discard DLPI header and keep only IP payload (mp->b_cont). */
	pktmp = mp->b_cont;
	mp->b_cont = NULL;
	freemsg(mp);
	mp = hdrmp;

	*(uchar_t *)mp->b_wptr++ = PPP_ALLSTATIONS;
	*(uchar_t *)mp->b_wptr++ = PPP_UI;
	*(uchar_t *)mp->b_wptr++ = ((uint16_t)sps->sps_sap >> 8) & 0xff;
	*(uchar_t *)mp->b_wptr++ = ((uint16_t)sps->sps_sap) & 0xff;
	ASSERT(MBLKL(mp) == PPP_HDRLEN);

	linkb(mp, pktmp);
	/*
	 * Only time-stamp the packet with hrtime if the upper stream
	 * is configured to do so.
	 */
	if (IS_PPA_TIMESTAMP(ppa)) {
		ppa->ppa_lasttx = gethrtime();
	}
	/*
	 * Just put this back on the queue and allow the write service
	 * routine to handle it.  We're nested too deeply here to
	 * rewind the stack sufficiently to prevent overflow.  This is
	 * the slow path anyway.
	 */
	if (putq(q, mp) == 0) {
		mutex_enter(&ppa->ppa_sta_lock);
		ppa->ppa_oqdropped++;
		mutex_exit(&ppa->ppa_sta_lock);
		freemsg(mp);
	} else {
		qenable(q);
	}
	return (0);
}

/*
 * sppp_dlpromisconreq()
 *
 * MT-Perimeters:
 *    shared inner, shared outer.
 *
 * Description:
 *    Perform DL_PROMISCON_REQ request, called by sppp_mproto.
 */
static int
sppp_dlpromisconreq(queue_t *q, mblk_t *mp, spppstr_t *sps)
{
	t_uscalar_t	level;

	ASSERT(q != NULL && q->q_ptr != NULL);
	ASSERT(mp != NULL && mp->b_rptr != NULL);
	level = ((dl_promiscon_req_t *)mp->b_rptr)->dl_level;
	ASSERT(sps != NULL);

	/* snoop issues DL_PROMISCON_REQ more than once. */
	if (IS_SPS_PROMISC(sps)) {
		dlokack(q, mp, DL_PROMISCON_REQ);
	} else if ((level != DL_PROMISC_PHYS) && (level != DL_PROMISC_SAP) &&
	    (level != DL_PROMISC_MULTI)) {
		DBGERROR((CE_CONT, "DLPI promiscon: bad level %d\n", level));
		dlerrorack(q, mp, DL_PROMISCON_REQ, DL_NOTSUPPORTED, 0);
	} else {
		qwriter(q, mp, sppp_dl_promiscon, PERIM_INNER);
	}
	return (0);
}

/*
 * sppp_dl_promiscon()
 *
 * MT-Perimeters:
 *    exclusive inner, shared outer.
 *
 * Description:
 *    Called by qwriter (INNER) from sppp_dlpromisconreq as the result of
 *    receiving a DL_PROMISCON_REQ message.
 */
static void
sppp_dl_promiscon(queue_t *q, mblk_t *mp)
{
	spppstr_t	*sps;
	sppa_t		*ppa;

	ASSERT(q != NULL && q->q_ptr != NULL);
	sps = (spppstr_t *)q->q_ptr;
	ASSERT(!IS_SPS_PROMISC(sps));
	ASSERT(mp != NULL && mp->b_rptr != NULL);
	ppa = sps->sps_ppa;

	sps->sps_flags |= SPS_PROMISC;
	/*
	 * We can't be sure that the sps_ppa field is valid, since the DLPI
	 * spec says that DL_PROMISCON_REQ can be issued at any state, i.e.,
	 * the request can be issued even before DL_ATTACH_REQ or PPPIO_ATTACH
	 * be issued to associate this stream with a ppa.
	 */
	if (ppa != NULL) {
		rw_enter(&ppa->ppa_sib_lock, RW_WRITER);
		ppa->ppa_promicnt++;
		rw_exit(&ppa->ppa_sib_lock);
	}
	DBGDLPI((CE_CONT, "/%d: promiscuous mode on\n", sps->sps_mn_id));
	dlokack(q, mp, DL_PROMISCON_REQ);
}

/*
 * sppp_dlpromiscoffreq()
 *
 * MT-Perimeters:
 *    shared inner, shared outer.
 *
 * Description:
 *    Perform DL_PROMISCOFF_REQ request, called by sppp_mproto.
 */
static int
sppp_dlpromiscoffreq(queue_t *q, mblk_t *mp, spppstr_t *sps)
{
	t_uscalar_t	level;

	ASSERT(q != NULL && q->q_ptr != NULL);
	ASSERT(mp != NULL && mp->b_rptr != NULL);
	level = ((dl_promiscoff_req_t *)mp->b_rptr)->dl_level;
	ASSERT(sps != NULL);

	if (!IS_SPS_PROMISC(sps)) {
		DBGERROR((CE_CONT, "DLPI promiscoff: not promiscuous\n"));
		dlerrorack(q, mp, DL_PROMISCOFF_REQ, DL_NOTENAB, 0);
	} else if ((level != DL_PROMISC_PHYS) && (level != DL_PROMISC_SAP) &&
	    (level != DL_PROMISC_MULTI)) {
		dlerrorack(q, mp, DL_PROMISCOFF_REQ, DL_NOTSUPPORTED, 0);
		DBGERROR((CE_CONT, "DLPI promiscoff: bad level %d\n", level));
	} else {
		qwriter(q, mp, sppp_dl_promiscoff, PERIM_INNER);
	}
	return (0);

}

/*
 * sppp_dl_promiscoff()
 *
 * MT-Perimeters:
 *    exclusive inner, shared outer.
 *
 * Description:
 *    Called by qwriter (INNER) from sppp_dlpromiscoffreq as the result of
 *    receiving a DL_PROMISCOFF_REQ message.
 */
static void
sppp_dl_promiscoff(queue_t *q, mblk_t *mp)
{
	spppstr_t	*sps;
	sppa_t		*ppa;

	ASSERT(q != NULL && q->q_ptr != NULL);
	sps = (spppstr_t *)q->q_ptr;
	ASSERT(IS_SPS_PROMISC(sps));
	ASSERT(mp != NULL && mp->b_rptr != NULL);
	ppa = sps->sps_ppa;

	sps->sps_flags &= ~SPS_PROMISC;
	/*
	 * We can't be guaranteed that the sps_ppa field is still valid, since
	 * the control stream might have been closed earlier, in which case
	 * the close procedure would have NULL'd out the sps_ppa.
	 */
	if (ppa != NULL) {
		rw_enter(&ppa->ppa_sib_lock, RW_WRITER);
		ASSERT(ppa->ppa_promicnt > 0);
		ppa->ppa_promicnt--;
		rw_exit(&ppa->ppa_sib_lock);
	}
	DBGDLPI((CE_CONT, "/%d: promiscuous mode off\n", sps->sps_mn_id));
	dlokack(q, mp, DL_PROMISCOFF_REQ);
}

/*
 * sppp_dlphyreq()
 *
 * MT-Perimeters:
 *    shared inner, shared outer.
 *
 * Description:
 *    Perform DL_PHYS_ADDR_REQ request, called by sppp_mproto. This doesn't
 *    return anything useful, but it keeps ifconfig happy.
 */
/* ARGSUSED */
static int
sppp_dlphyreq(queue_t *q, mblk_t *mp, spppstr_t *us)
{
	static struct ether_addr addr = { 0 };

	dlphysaddrack(q, mp, (char *)&addr, ETHERADDRL);
	return (0);
}

/*
 * sppp_dladdether()
 *
 * Description:
 *    Prepend an empty Ethernet header to msg for snoop, et al. Free
 *    the original mblk if alloc fails. Only called for the purpose of sending
 *    packets up the promiscous stream.
 */
/* ARGSUSED */
static mblk_t *
sppp_dladdether(spppstr_t *sps, mblk_t *mp, t_scalar_t proto)
{
	mblk_t		*eh;
	t_scalar_t	type;

	if ((eh = allocb(sizeof (struct ether_header), BPRI_MED)) == NULL) {
		freemsg(mp);
		return (NULL);
	}
	if (proto == PPP_IP) {
		type = ETHERTYPE_IP;
	} else if (proto == PPP_IPV6) {
		type = ETHERTYPE_IPV6;
	} else {
		/*
		 * For all other protocols, end this up as an ETHERTYPE_PPP
		 * type of packet. Since we've skipped the PPP headers in the
		 * caller, make sure that we restore it. We know for sure that
		 * the PPP header still exists in the message (only skipped),
		 * since the sender of this message is pppd and it must have
		 * included the PPP header in front.
		 */
		type = ETHERTYPE_PPP;
		mp->b_rptr -= PPP_HDRLEN;
		ASSERT(mp->b_rptr >= mp->b_datap->db_base);
	}
	eh->b_wptr += sizeof (struct ether_header);
	bzero((caddr_t)eh->b_rptr, sizeof (struct ether_header));
	((struct ether_header *)eh->b_rptr)->ether_type = htons((int16_t)type);

	linkb(eh, mp);
	return (eh);
}

/*
 * sppp_dladdud()
 *
 * Description:
 *    Prepend DL_UNITDATA_IND mblk to msg, free original alloc fails.
 */
/* ARGSUSED */
mblk_t *
sppp_dladdud(spppstr_t *sps, mblk_t *mp, t_scalar_t proto, boolean_t promisc)
{
	dl_unitdata_ind_t *dlu;
	mblk_t		*dh;
	size_t		size;
	t_scalar_t	type;

	size = sizeof (dl_unitdata_ind_t) + (2 * SPPP_ADDRL);
	if ((dh = allocb(size, BPRI_MED)) == NULL) {
		freemsg(mp);
		return (NULL);
	}

	dh->b_datap->db_type = M_PROTO;
	dh->b_wptr = dh->b_datap->db_lim;
	dh->b_rptr = dh->b_wptr - size;

	dlu = (dl_unitdata_ind_t *)dh->b_rptr;
	dlu->dl_primitive = DL_UNITDATA_IND;
	dlu->dl_dest_addr_length = SPPP_ADDRL;
	dlu->dl_dest_addr_offset = sizeof (dl_unitdata_ind_t);
	dlu->dl_src_addr_length = SPPP_ADDRL;
	dlu->dl_src_addr_offset = sizeof (dl_unitdata_ind_t) + SPPP_ADDRL;
	dlu->dl_group_address = 0;

	if (promisc) {
		if (proto == PPP_IP) {
			type = ETHERTYPE_IP;
		} else if (proto == PPP_IPV6) {
			type = ETHERTYPE_IPV6;
		} else {
			/*
			 * For all other protocols, send this up as an
			 * ETHERTYPE_PPP type of packet. Since we've skipped
			 * the PPP headers in the caller, make sure that we
			 * restore it. We know for sure that the PPP header
			 * still exists in the message (only skipped), since
			 * the sender of this message is pppd and it must
			 * have included the PPP header in front.
			 */
			type = ETHERTYPE_PPP;
			mp->b_rptr -= PPP_HDRLEN;
			ASSERT(mp->b_rptr >= mp->b_datap->db_base);
		}
	} else {
		type = sps->sps_req_sap;
	}
	/*
	 * Send the DLPI client the data with the SAP they requested,
	 * (e.g. ETHERTYPE_IP) rather than the PPP protocol (e.g. PPP_IP).
	 */
	((spppreqsap_t *)(dlu + 1))[0] = type;
	((spppreqsap_t *)(dlu + 1))[1] = type;

	linkb(dh, mp);
	return (dh);
}

/*
 * sppp_dlprsendup()
 *
 * Description:
 *    For any valid promiscuous streams (marked with SPS_PROMISC and its
 *    sps_dlstate is DL_IDLE), send data upstream. The caller is expected
 *    to hold ppa_sib_lock when calling this procedure.
 */
void
sppp_dlprsendup(spppstr_t *sps, mblk_t *mp, t_scalar_t proto, boolean_t header)
{
	sppa_t	*ppa;
	mblk_t	*dmp;

	ASSERT(sps != NULL);
	ASSERT(mp != NULL && mp->b_rptr != NULL);
	ppa = sps->sps_ppa;
	ASSERT(ppa != NULL);

	/* NOTE: caller must hold ppa_sib_lock in RW_READER mode */
	ASSERT(RW_READ_HELD(&ppa->ppa_sib_lock));

	for (; sps != NULL; sps = sps->sps_nextsib) {
		/*
		 * We specifically test to ensure that the DLPI state for the
		 * promiscous stream is IDLE (DL_IDLE), since such state tells
		 * us that the promiscous stream has been bound to PPP_ALLSAP.
		 */
		if (IS_SPS_PROMISC(sps) && (sps->sps_dlstate == DL_IDLE) &&
		    canputnext(sps->sps_rq)) {
			if ((dmp = dupmsg(mp)) == NULL) {
				mutex_enter(&ppa->ppa_sta_lock);
				ppa->ppa_allocbfail++;
				mutex_exit(&ppa->ppa_sta_lock);
				continue;
			}
			if (header) {
				dmp->b_rptr += PPP_HDRLEN;
			}
			if (IS_SPS_RAWDATA(sps)) {
				/* function frees original message if fails */
				dmp = sppp_dladdether(sps, dmp, proto);
			} else {
				/* function frees original message if fails */
				dmp = sppp_dladdud(sps, dmp, proto, B_TRUE);
			}
			if (dmp != NULL) {
				putnext(sps->sps_rq, dmp);
			} else {
				mutex_enter(&ppa->ppa_sta_lock);
				ppa->ppa_allocbfail++;
				mutex_exit(&ppa->ppa_sta_lock);
			}
		}
	}
}
