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
 * Copyright (c) 2004, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include <sys/types.h>
#include <sys/systm.h>
#include <sys/stream.h>
#include <sys/cmn_err.h>
#include <sys/socket.h>
#include <sys/kmem.h>
#include <sys/strsubr.h>
#include <sys/strsun.h>

#include <netinet/in.h>
#include <netinet/ip6.h>
#include <netinet/sctp.h>

#include <inet/common.h>
#include <inet/ip.h>
#include <inet/ip6.h>
#include <inet/mib2.h>
#include <inet/ipclassifier.h>
#include "sctp_impl.h"
#include "sctp_asconf.h"
#include "sctp_addr.h"

typedef struct sctp_asconf_s {
	mblk_t		*head;
	uint32_t	cid;
} sctp_asconf_t;

/*
 * This is only used on a clustered node to maintain pre-allocated buffer info.
 * before sending an ASCONF chunk. The reason for pre-allocation is we don't
 * want to fail allocating memory when we get then ASCONF-ACK in order to
 * update the clustering subsystem's state for this assoc.
 */
typedef struct sctp_cl_ainfo_s {
	uchar_t	*sctp_cl_alist;
	size_t	sctp_cl_asize;
	uchar_t	*sctp_cl_dlist;
	size_t	sctp_cl_dsize;
} sctp_cl_ainfo_t;

/*
 * The ASCONF chunk per-parameter request interface. ph is the
 * parameter header for the parameter in the request, and cid
 * is the parameters correlation ID. cont should be set to 1
 * if the ASCONF framework should continue processing request
 * parameters following this one, or 0 if it should stop. If
 * cont is -1, this indicates complete memory depletion, which
 * will cause the ASCONF framework to abort building a reply. If
 * act is 1, the callback should take whatever action it needs
 * to fulfil this request. If act is 0, this request has already
 * been processed, so the callback should only verify and pass
 * back error parameters, and not take any action.
 *
 * The callback should return an mblk with any reply enclosed,
 * with the correlation ID in the first four bytes of the
 * message. A NULL return implies implicit success to the
 * requestor.
 */
typedef mblk_t *sctp_asconf_func_t(sctp_t *, sctp_parm_hdr_t *ph, uint32_t cid,
    sctp_faddr_t *, int *cont, int act, in6_addr_t *addr);

/*
 * The ASCONF chunk per-parameter ACK interface. ph is the parameter
 * header for the parameter returned in the ACK, and oph is the
 * original parameter sent out in the ASCONF request.
 * If the peer implicitly responded OK (by not including an
 * explicit OK for the request), ph will be NULL.
 * ph can also point to an Unrecognized Parameter parameter,
 * in which case the peer did not understand the request
 * parameter.
 *
 * ph and oph parameter headers are in host byte order. Encapsulated
 * parameters will still be in network byte order.
 */
typedef void sctp_asconf_ack_func_t(sctp_t *, sctp_parm_hdr_t *ph,
    sctp_parm_hdr_t *oph, sctp_faddr_t *, in6_addr_t *addr);

typedef struct {
	uint16_t id;
	sctp_asconf_func_t *asconf;
	sctp_asconf_ack_func_t *asconf_ack;
} dispatch_t;

static sctp_asconf_func_t sctp_addip_req, sctp_setprim_req,
    sctp_asconf_unrec_parm;

static sctp_asconf_ack_func_t sctp_addip_ack, sctp_setprim_ack,
    sctp_asconf_ack_unrec_parm;

static const dispatch_t sctp_asconf_dispatch_tbl[] = {
/*	ID			ASCONF			ASCONF_ACK */
	{ PARM_ADD_IP,		sctp_addip_req,		sctp_addip_ack },
	{ PARM_DEL_IP,		sctp_addip_req,		sctp_addip_ack },
	{ PARM_SET_PRIMARY,	sctp_setprim_req,	sctp_setprim_ack }
};

static const dispatch_t sctp_asconf_default_dispatch = {
	0, sctp_asconf_unrec_parm, sctp_asconf_ack_unrec_parm
};

/*
 * ASCONF framework
 */

static const dispatch_t *
sctp_lookup_asconf_dispatch(int id)
{
	int i;

	for (i = 0; i < A_CNT(sctp_asconf_dispatch_tbl); i++) {
		if (sctp_asconf_dispatch_tbl[i].id == id) {
			return (sctp_asconf_dispatch_tbl + i);
		}
	}

	return (&sctp_asconf_default_dispatch);
}

/*
 * Frees mp on failure
 */
static mblk_t *
sctp_asconf_prepend_errwrap(mblk_t *mp, uint32_t cid)
{
	mblk_t		*wmp;
	sctp_parm_hdr_t	*wph;

	/* Prepend a wrapper err cause ind param */
	wmp = allocb(sizeof (*wph) + sizeof (cid), BPRI_MED);
	if (wmp == NULL) {
		freemsg(mp);
		return (NULL);
	}
	wmp->b_wptr += sizeof (*wph) + sizeof (cid);
	wph = (sctp_parm_hdr_t *)wmp->b_rptr;
	wph->sph_type = htons(PARM_ERROR_IND);
	wph->sph_len = htons(msgdsize(mp) + sizeof (*wph) + sizeof (cid));
	bcopy(&cid, wph + 1, sizeof (uint32_t));

	wmp->b_cont = mp;
	return (wmp);
}

/*ARGSUSED*/
static mblk_t *
sctp_asconf_unrec_parm(sctp_t *sctp, sctp_parm_hdr_t *ph, uint32_t cid,
    sctp_faddr_t *fp, int *cont, int act, in6_addr_t *addr)
{
	mblk_t *mp = NULL;

	/* Unrecognized param; check the high order bits */
	if ((ph->sph_type & SCTP_UNREC_PARAM_MASK) ==
	    (SCTP_CONT_PROC_PARAMS | SCTP_REPORT_THIS_PARAM)) {
		/* report unrecognized param, and keep processing */
		sctp_add_unrec_parm(ph, &mp, B_FALSE);
		if (mp == NULL) {
			*cont = -1;
			return (NULL);
		}
		/* Prepend a the CID and a wrapper err cause ind param */
		mp = sctp_asconf_prepend_errwrap(mp, cid);
		if (mp == NULL) {
			*cont = -1;
			return (NULL);
		}

		*cont = 1;
		return (mp);
	}
	if (ph->sph_type & SCTP_REPORT_THIS_PARAM) {
		/* Stop processing and drop; report unrecognized param */
		sctp_add_unrec_parm(ph, &mp, B_FALSE);
		if (mp == NULL) {
			*cont = -1;
			return (NULL);
		}
		/* Prepend a the CID and a wrapper err cause ind param */
		mp = sctp_asconf_prepend_errwrap(mp, cid);
		if (mp == NULL) {
			*cont = -1;
			return (NULL);
		}

		*cont = 0;
		return (mp);
	}
	if (ph->sph_type & SCTP_CONT_PROC_PARAMS) {
		/* skip and continue processing */
		*cont = 1;
		return (NULL);
	}

	/* 2 high bits are clear; stop processing and drop packet */
	*cont = 0;
	return (NULL);
}

/*ARGSUSED*/
static void
sctp_asconf_ack_unrec_parm(sctp_t *sctp, sctp_parm_hdr_t *ph,
    sctp_parm_hdr_t *oph, sctp_faddr_t *fp, in6_addr_t *laddr)
{
	ASSERT(ph);
	sctp_error_event(sctp, (sctp_chunk_hdr_t *)ph, B_TRUE);
}

static void
sctp_asconf_init(sctp_asconf_t *asc)
{
	ASSERT(asc != NULL);

	asc->head = NULL;
	asc->cid = 0;
}

static int
sctp_asconf_add(sctp_asconf_t *asc, mblk_t *mp)
{
	uint32_t *cp;

	/* XXX can't exceed MTU */

	cp = (uint32_t *)(mp->b_rptr + sizeof (sctp_parm_hdr_t));
	*cp = asc->cid++;

	if (asc->head == NULL)
		asc->head = mp;
	else
		linkb(asc->head, mp);

	return (0);
}

static void
sctp_asconf_destroy(sctp_asconf_t *asc)
{
	if (asc->head != NULL) {
		freemsg(asc->head);
		asc->head = NULL;
	}
	asc->cid = 0;
}

static int
sctp_asconf_send(sctp_t *sctp, sctp_asconf_t *asc, sctp_faddr_t *fp,
    sctp_cl_ainfo_t *ainfo)
{
	mblk_t			*mp, *nmp;
	sctp_chunk_hdr_t	*ch;
	boolean_t		isv4;
	size_t			msgsize;

	ASSERT(asc != NULL && asc->head != NULL);

	isv4 = (fp != NULL) ? fp->sf_isv4 : sctp->sctp_current->sf_isv4;

	/* SCTP chunk header + Serial Number + Address Param TLV */
	msgsize = sizeof (*ch) + sizeof (uint32_t) +
	    (isv4 ? PARM_ADDR4_LEN : PARM_ADDR6_LEN);

	mp = allocb(msgsize, BPRI_MED);
	if (mp == NULL)
		return (ENOMEM);

	mp->b_wptr += msgsize;
	mp->b_cont = asc->head;

	ch = (sctp_chunk_hdr_t *)mp->b_rptr;
	ch->sch_id = CHUNK_ASCONF;
	ch->sch_flags = 0;
	ch->sch_len = htons(msgdsize(mp));

	nmp = msgpullup(mp, -1);
	if (nmp == NULL) {
		freeb(mp);
		return (ENOMEM);
	}

	/*
	 * Stash the address list and the count so that when the operation
	 * completes, i.e. when as get an ACK, we can update the clustering's
	 * state for this association.
	 */
	if (ainfo != NULL) {
		ASSERT(cl_sctp_assoc_change != NULL);
		ASSERT(nmp->b_prev == NULL);
		nmp->b_prev = (mblk_t *)ainfo;
	}
	/* Clean up the temporary mblk chain */
	freemsg(mp);
	asc->head = NULL;
	asc->cid = 0;

	/* Queue it ... */
	if (sctp->sctp_cxmit_list == NULL) {
		sctp->sctp_cxmit_list = nmp;
	} else {
		linkb(sctp->sctp_cxmit_list, nmp);
	}

	BUMP_LOCAL(sctp->sctp_obchunks);

	/* And try to send it. */
	sctp_wput_asconf(sctp, fp);

	return (0);
}

/*
 * If the peer does not understand an ASCONF chunk, we simply
 * clear out the cxmit_list, since we can send nothing further
 * that the peer will understand.
 *
 * Assumes chunk length has already been checked.
 */
/*ARGSUSED*/
void
sctp_asconf_free_cxmit(sctp_t *sctp, sctp_chunk_hdr_t *ch)
{
	mblk_t		*mp;
	mblk_t		*mp1;
	sctp_cl_ainfo_t	*ainfo;

	if (sctp->sctp_cxmit_list == NULL) {
		/* Nothing pending */
		return;
	}

	mp = sctp->sctp_cxmit_list;
	while (mp != NULL) {
		mp1 = mp->b_cont;
		mp->b_cont = NULL;
		if (mp->b_prev != NULL) {
			ainfo = (sctp_cl_ainfo_t *)mp->b_prev;
			mp->b_prev = NULL;
			kmem_free(ainfo->sctp_cl_alist, ainfo->sctp_cl_asize);
			kmem_free(ainfo->sctp_cl_dlist, ainfo->sctp_cl_dsize);
			kmem_free(ainfo, sizeof (*ainfo));
		}
		freeb(mp);
		mp = mp1;
	}
	sctp->sctp_cxmit_list = NULL;
}

void
sctp_input_asconf(sctp_t *sctp, sctp_chunk_hdr_t *ch, sctp_faddr_t *fp)
{
	const dispatch_t	*dp;
	mblk_t			*hmp;
	mblk_t			*mp;
	uint32_t		*idp;
	uint32_t		*hidp;
	ssize_t			rlen;
	sctp_parm_hdr_t		*ph;
	sctp_chunk_hdr_t	*ach;
	int			cont;
	int			act;
	uint16_t		plen;
	uchar_t			*alist = NULL;
	size_t			asize = 0;
	uchar_t			*dlist = NULL;
	size_t			dsize = 0;
	uchar_t			*aptr = NULL;
	uchar_t			*dptr = NULL;
	int			acount = 0;
	int			dcount = 0;
	sctp_stack_t		*sctps = sctp->sctp_sctps;

	ASSERT(ch->sch_id == CHUNK_ASCONF);

	idp = (uint32_t *)(ch + 1);
	rlen = ntohs(ch->sch_len) - sizeof (*ch) - sizeof (*idp);

	if (rlen < 0 || rlen < sizeof (*idp)) {
		/* nothing there; bail out */
		return;
	}

	/* Check for duplicates */
	*idp = ntohl(*idp);
	if (*idp == (sctp->sctp_fcsn + 1)) {
		act = 1;
	} else if (*idp == sctp->sctp_fcsn) {
		act = 0;
	} else {
		/* stale or malicious packet; drop */
		return;
	}

	/* Create the ASCONF_ACK header */
	hmp = sctp_make_mp(sctp, fp, sizeof (*ach) + sizeof (*idp));
	if (hmp == NULL) {
		/* Let the peer retransmit */
		SCTP_KSTAT(sctps, sctp_send_asconf_ack_failed);
		return;
	}
	ach = (sctp_chunk_hdr_t *)hmp->b_wptr;
	ach->sch_id = CHUNK_ASCONF_ACK;
	ach->sch_flags = 0;
	/* Set the length later */
	hidp = (uint32_t *)(ach + 1);
	*hidp = htonl(*idp);
	hmp->b_wptr = (uchar_t *)(hidp + 1);

	/* Move to the Address Parameter */
	ph = (sctp_parm_hdr_t *)(idp + 1);
	if (rlen <= ntohs(ph->sph_len)) {
		freeb(hmp);
		return;
	}

	/*
	 * We already have the association here, so this address parameter
	 * doesn't seem to be very useful, should we make sure this is part
	 * of the association and send an error, if not?
	 * Ignore it for now.
	 */
	rlen -= ntohs(ph->sph_len);
	ph = (sctp_parm_hdr_t *)((char *)ph + ntohs(ph->sph_len));

	/*
	 * We need to pre-allocate buffer before processing the ASCONF
	 * chunk. We don't want to fail allocating buffers after processing
	 * the ASCONF chunk. So, we walk the list and get the number of
	 * addresses added and/or deleted.
	 */
	if (cl_sctp_assoc_change != NULL) {
		sctp_parm_hdr_t	*oph = ph;
		ssize_t		orlen = rlen;

		/*
		 * This not very efficient, but there is no better way of
		 * doing it.  It should be fine since normally the param list
		 * will not be very long.
		 */
		while (orlen > 0) {
			/* Sanity checks */
			if (orlen < sizeof (*oph))
				break;
			plen = ntohs(oph->sph_len);
			if (plen < sizeof (*oph) || plen > orlen)
				break;
			if (oph->sph_type == htons(PARM_ADD_IP))
				acount++;
			if (oph->sph_type == htons(PARM_DEL_IP))
				dcount++;
			oph = sctp_next_parm(oph, &orlen);
			if (oph == NULL)
				break;
		}
		if (acount > 0 || dcount > 0) {
			if (acount > 0) {
				asize = sizeof (in6_addr_t) * acount;
				alist = kmem_alloc(asize, KM_NOSLEEP);
				if (alist == NULL) {
					freeb(hmp);
					SCTP_KSTAT(sctps, sctp_cl_assoc_change);
					return;
				}
			}
			if (dcount > 0) {
				dsize = sizeof (in6_addr_t) * dcount;
				dlist = kmem_alloc(dsize, KM_NOSLEEP);
				if (dlist == NULL) {
					if (acount > 0)
						kmem_free(alist, asize);
					freeb(hmp);
					SCTP_KSTAT(sctps, sctp_cl_assoc_change);
					return;
				}
			}
			aptr = alist;
			dptr = dlist;
			/*
			 * We will get the actual count when we process
			 * the chunk.
			 */
			acount = 0;
			dcount = 0;
		}
	}
	cont = 1;
	while (rlen > 0 && cont) {
		in6_addr_t	addr;

		/* Sanity checks */
		if (rlen < sizeof (*ph))
			break;
		plen = ntohs(ph->sph_len);
		if (plen < sizeof (*ph) || plen > rlen) {
			break;
		}
		idp = (uint32_t *)(ph + 1);
		dp = sctp_lookup_asconf_dispatch(ntohs(ph->sph_type));
		ASSERT(dp);
		if (dp->asconf) {
			mp = dp->asconf(sctp, ph, *idp, fp, &cont, act, &addr);
			if (cont == -1) {
				/*
				 * Not even enough memory to create
				 * an out-of-resources error. Free
				 * everything and return; the peer
				 * should retransmit.
				 */
				freemsg(hmp);
				if (alist != NULL)
					kmem_free(alist, asize);
				if (dlist != NULL)
					kmem_free(dlist, dsize);
				return;
			}
			if (mp != NULL) {
				linkb(hmp, mp);
			} else if (act != 0) {
				/* update the add/delete list */
				if (cl_sctp_assoc_change != NULL) {
					if (ph->sph_type ==
					    htons(PARM_ADD_IP)) {
						ASSERT(alist != NULL);
						bcopy(&addr, aptr,
						    sizeof (addr));
						aptr += sizeof (addr);
						acount++;
					} else if (ph->sph_type ==
					    htons(PARM_DEL_IP)) {
						ASSERT(dlist != NULL);
						bcopy(&addr, dptr,
						    sizeof (addr));
						dptr += sizeof (addr);
						dcount++;
					}
				}
			}
		}
		ph = sctp_next_parm(ph, &rlen);
		if (ph == NULL)
			break;
	}

	/*
	 * Update clustering's state for this assoc. Note acount/dcount
	 * could be zero (i.e. if the add/delete address(es) were not
	 * processed successfully). Regardless, if the ?size is > 0,
	 * it is the clustering module's responsibility to free the lists.
	 */
	if (cl_sctp_assoc_change != NULL) {
		(*cl_sctp_assoc_change)(sctp->sctp_connp->conn_family,
		    alist, asize,
		    acount, dlist, dsize, dcount, SCTP_CL_PADDR,
		    (cl_sctp_handle_t)sctp);
		/* alist and dlist will be freed by the clustering module */
	}
	/* Now that the params have been processed, increment the fcsn */
	if (act) {
		sctp->sctp_fcsn++;
	}
	BUMP_LOCAL(sctp->sctp_obchunks);

	if (fp->sf_isv4)
		ach->sch_len = htons(msgdsize(hmp) - sctp->sctp_hdr_len);
	else
		ach->sch_len = htons(msgdsize(hmp) - sctp->sctp_hdr6_len);

	sctp_set_iplen(sctp, hmp, fp->sf_ixa);
	(void) conn_ip_output(hmp, fp->sf_ixa);
	BUMP_LOCAL(sctp->sctp_opkts);
	sctp_validate_peer(sctp);
}

static sctp_parm_hdr_t *
sctp_lookup_asconf_param(sctp_parm_hdr_t *ph, uint32_t cid, ssize_t rlen)
{
	uint32_t *idp;

	while (rlen > 0) {
		idp = (uint32_t *)(ph + 1);
		if (*idp == cid) {
			return (ph);
		}
		ph = sctp_next_parm(ph, &rlen);
		if (ph == NULL)
			break;
	}
	return (NULL);
}

void
sctp_input_asconf_ack(sctp_t *sctp, sctp_chunk_hdr_t *ch, sctp_faddr_t *fp)
{
	const dispatch_t	*dp;
	uint32_t		*idp;
	uint32_t		*snp;
	ssize_t			rlen;
	ssize_t			plen;
	sctp_parm_hdr_t		*ph;
	sctp_parm_hdr_t		*oph;
	sctp_parm_hdr_t		*fph;
	mblk_t			*mp;
	sctp_chunk_hdr_t	*och;
	int			redosrcs = 0;
	uint16_t		param_len;
	uchar_t			*alist;
	uchar_t			*dlist;
	uint_t			acount = 0;
	uint_t			dcount = 0;
	uchar_t			*aptr;
	uchar_t			*dptr;
	sctp_cl_ainfo_t		*ainfo;
	in6_addr_t		addr;

	ASSERT(ch->sch_id == CHUNK_ASCONF_ACK);

	ainfo = NULL;
	alist = NULL;
	dlist = NULL;
	aptr = NULL;
	dptr = NULL;

	snp = (uint32_t *)(ch + 1);
	rlen = ntohs(ch->sch_len) - sizeof (*ch) - sizeof (*snp);
	if (rlen < 0) {
		return;
	}

	/* Accept only an ACK for the current serial number */
	*snp = ntohl(*snp);
	if (sctp->sctp_cxmit_list == NULL || *snp != (sctp->sctp_lcsn - 1)) {
		/* Need to send an abort */
		return;
	}
	sctp->sctp_cchunk_pend = 0;
	SCTP_FADDR_RC_TIMER_STOP(fp);

	mp = sctp->sctp_cxmit_list;
	/*
	 * We fill in the addresses here to update the clustering's state for
	 * this assoc.
	 */
	if (mp != NULL && cl_sctp_assoc_change != NULL) {
		ASSERT(mp->b_prev != NULL);
		ainfo = (sctp_cl_ainfo_t *)mp->b_prev;
		alist = ainfo->sctp_cl_alist;
		dlist = ainfo->sctp_cl_dlist;
		aptr = alist;
		dptr = dlist;
	}

	/*
	 * Pass explicit replies to callbacks:
	 * For each reply in the ACK, look up the corresponding
	 * original parameter in the request using the correlation
	 * ID, and pass it to the right callback.
	 */
	och = (sctp_chunk_hdr_t *)sctp->sctp_cxmit_list->b_rptr;

	plen = ntohs(och->sch_len) - sizeof (*och) - sizeof (*idp);
	idp = (uint32_t *)(och + 1);

	/* Get to the 1st ASCONF param, need to skip Address TLV parm */
	fph = (sctp_parm_hdr_t *)(idp + 1);
	plen -= ntohs(fph->sph_len);
	fph = (sctp_parm_hdr_t *)((char *)fph + ntohs(fph->sph_len));
	ph = (sctp_parm_hdr_t *)(snp + 1);
	while (rlen > 0) {
		/* Sanity checks */
		if (rlen < sizeof (*ph)) {
			break;
		}
		param_len = ntohs(ph->sph_len);
		if (param_len < sizeof (*ph) || param_len > rlen) {
			break;
		}
		idp = (uint32_t *)(ph + 1);
		oph = sctp_lookup_asconf_param(fph, *idp, plen);
		if (oph != NULL) {
			dp = sctp_lookup_asconf_dispatch(ntohs(oph->sph_type));
			ASSERT(dp);
			if (dp->asconf_ack) {
				dp->asconf_ack(sctp, ph, oph, fp, &addr);

				/* hack. see below */
				if (oph->sph_type == htons(PARM_ADD_IP) ||
				    oph->sph_type == htons(PARM_DEL_IP)) {
					redosrcs = 1;
					/*
					 * If the address was sucessfully
					 * processed, add it to the add/delete
					 * list to send to the clustering
					 * module.
					 */
					if (cl_sctp_assoc_change != NULL &&
					    !SCTP_IS_ADDR_UNSPEC(
					    IN6_IS_ADDR_V4MAPPED(&addr),
					    addr)) {
						if (oph->sph_type ==
						    htons(PARM_ADD_IP)) {
							bcopy(&addr, aptr,
							    sizeof (addr));
							aptr += sizeof (addr);
							acount++;
						} else {
							bcopy(&addr, dptr,
							    sizeof (addr));
							dptr += sizeof (addr);
							dcount++;
						}
					}
				}
			}
		}

		ph = sctp_next_parm(ph, &rlen);
		if (ph == NULL)
			break;
	}

	/*
	 * Pass implicit replies to callbacks:
	 * For each original request, look up its parameter
	 * in the ACK. If there is no corresponding reply,
	 * call the callback with a NULL parameter, indicating
	 * success.
	 */
	rlen = plen;
	plen = ntohs(ch->sch_len) - sizeof (*ch) - sizeof (*idp);
	oph = fph;
	fph = (sctp_parm_hdr_t *)((char *)ch + sizeof (sctp_chunk_hdr_t) +
	    sizeof (uint32_t));
	while (rlen > 0) {
		idp = (uint32_t *)(oph + 1);
		ph = sctp_lookup_asconf_param(fph, *idp, plen);
		if (ph == NULL) {
			dp = sctp_lookup_asconf_dispatch(ntohs(oph->sph_type));
			ASSERT(dp);
			if (dp->asconf_ack) {
				dp->asconf_ack(sctp, NULL, oph, fp, &addr);

				/* hack. see below */
				if (oph->sph_type == htons(PARM_ADD_IP) ||
				    oph->sph_type == htons(PARM_DEL_IP)) {
					redosrcs = 1;
					/*
					 * If the address was sucessfully
					 * processed, add it to the add/delete
					 * list to send to the clustering
					 * module.
					 */
					if (cl_sctp_assoc_change != NULL &&
					    !SCTP_IS_ADDR_UNSPEC(
					    IN6_IS_ADDR_V4MAPPED(&addr),
					    addr)) {
						if (oph->sph_type ==
						    htons(PARM_ADD_IP)) {
							bcopy(&addr, aptr,
							    sizeof (addr));
							aptr += sizeof (addr);
							acount++;
						} else {
							bcopy(&addr, dptr,
							    sizeof (addr));
							dptr += sizeof (addr);
							dcount++;
						}
					}
				}
			}
		}
		oph = sctp_next_parm(oph, &rlen);
		if (oph == NULL) {
			break;
		}
	}

	/* We can now free up the first chunk in the cxmit list */
	sctp->sctp_cxmit_list = mp->b_cont;
	mp->b_cont = NULL;

	fp = SCTP_CHUNK_DEST(mp);
	ASSERT(fp != NULL && fp->sf_suna >= MBLKL(mp));
	fp->sf_suna -= MBLKL(mp);

	/*
	 * Update clustering's state for this assoc. Note acount/dcount
	 * could be zero (i.e. if the add/delete address(es) did not
	 * succeed). Regardless, if the ?size is > 0, it is the clustering
	 * module's responsibility to free the lists.
	 */
	if (cl_sctp_assoc_change != NULL) {
		ASSERT(mp->b_prev != NULL);
		mp->b_prev = NULL;
		ainfo->sctp_cl_alist = NULL;
		ainfo->sctp_cl_dlist = NULL;
		(*cl_sctp_assoc_change)(sctp->sctp_connp->conn_family, alist,
		    ainfo->sctp_cl_asize, acount, dlist, ainfo->sctp_cl_dsize,
		    dcount, SCTP_CL_LADDR, (cl_sctp_handle_t)sctp);
		/* alist and dlist will be freed by the clustering module */
		ainfo->sctp_cl_asize = 0;
		ainfo->sctp_cl_dsize = 0;
		kmem_free(ainfo, sizeof (*ainfo));
	}
	freeb(mp);

	/* can now send the next control chunk */
	if (sctp->sctp_cxmit_list != NULL)
		sctp_wput_asconf(sctp, NULL);

	/*
	 * If an add-ip or del-ip has completed (successfully or
	 * unsuccessfully), the pool of available source addresses
	 * may have changed, so we need to redo faddr source
	 * address selections. This is a bit of a hack since
	 * this really belongs in the add/del-ip code. However,
	 * that code consists of callbacks called for *each*
	 * add/del-ip parameter, and sctp_redo_faddr_srcs() is
	 * expensive enough that we really don't want to be
	 * doing it for each one. So we do it once here.
	 */
	if (redosrcs)
		sctp_redo_faddr_srcs(sctp);
}

static void
sctp_rc_timer(sctp_t *sctp, sctp_faddr_t *fp)
{
#define	SCTP_CLR_SENT_FLAG(mp)	((mp)->b_flag &= ~SCTP_CHUNK_FLAG_SENT)
	sctp_faddr_t	*nfp;
	sctp_faddr_t	*ofp;
	sctp_stack_t	*sctps = sctp->sctp_sctps;

	ASSERT(fp != NULL);

	fp->sf_rc_timer_running = 0;

	if (sctp->sctp_state != SCTPS_ESTABLISHED ||
	    sctp->sctp_cxmit_list == NULL) {
		return;
	}
	/*
	 * Not a retransmission, this was deferred due to some error
	 * condition
	 */
	if (!SCTP_CHUNK_ISSENT(sctp->sctp_cxmit_list)) {
		sctp_wput_asconf(sctp, fp);
		return;
	}
	/*
	 * The sent flag indicates if the msg has been sent on this fp.
	 */
	SCTP_CLR_SENT_FLAG(sctp->sctp_cxmit_list);
	/* Retransmission */
	if (sctp->sctp_strikes >= sctp->sctp_pa_max_rxt) {
		/* time to give up */
		SCTPS_BUMP_MIB(sctps, sctpAborted);
		sctp_assoc_event(sctp, SCTP_COMM_LOST, 0, NULL);
		sctp_clean_death(sctp, ETIMEDOUT);
		return;
	}
	if (fp->sf_strikes >= fp->sf_max_retr) {
		if (sctp_faddr_dead(sctp, fp, SCTP_FADDRS_DOWN) == -1)
			return;
	}

	fp->sf_strikes++;
	sctp->sctp_strikes++;
	SCTP_CALC_RXT(sctp, fp, sctp->sctp_rto_max);

	nfp = sctp_rotate_faddr(sctp, fp);
	sctp->sctp_cchunk_pend = 0;
	ofp = SCTP_CHUNK_DEST(sctp->sctp_cxmit_list);
	SCTP_SET_CHUNK_DEST(sctp->sctp_cxmit_list, NULL);
	ASSERT(ofp != NULL && ofp == fp);
	ASSERT(ofp->sf_suna >= MBLKL(sctp->sctp_cxmit_list));
	/*
	 * Enter slow start for this destination.
	 * XXX anything in the data path that needs to be considered?
	 */
	ofp->sf_ssthresh = ofp->sf_cwnd / 2;
	if (ofp->sf_ssthresh < 2 * ofp->sf_pmss)
		ofp->sf_ssthresh = 2 * ofp->sf_pmss;
	ofp->sf_cwnd = ofp->sf_pmss;
	ofp->sf_pba = 0;
	ofp->sf_suna -= MBLKL(sctp->sctp_cxmit_list);
	/*
	 * The rexmit flags is used to determine if a serial number needs to
	 * be assigned or not, so once set we leave it there.
	 */
	if (!SCTP_CHUNK_WANT_REXMIT(sctp->sctp_cxmit_list))
		SCTP_CHUNK_REXMIT(sctp, sctp->sctp_cxmit_list);
	sctp_wput_asconf(sctp, nfp);
#undef	SCTP_CLR_SENT_FLAG
}

void
sctp_wput_asconf(sctp_t *sctp, sctp_faddr_t *fp)
{
#define	SCTP_SET_SENT_FLAG(mp)	((mp)->b_flag = SCTP_CHUNK_FLAG_SENT)

	mblk_t			*mp;
	mblk_t			*ipmp;
	uint32_t		*snp;
	sctp_parm_hdr_t		*ph;
	boolean_t		isv4;
	sctp_stack_t		*sctps = sctp->sctp_sctps;
	boolean_t		saddr_set;

	if (sctp->sctp_cchunk_pend || sctp->sctp_cxmit_list == NULL ||
	    /* Queue it for later transmission if not yet established */
	    sctp->sctp_state < SCTPS_ESTABLISHED) {
		ip2dbg(("sctp_wput_asconf: cchunk pending? (%d) or null "\
		    "sctp_cxmit_list? (%s) or incorrect state? (%x)\n",
		    sctp->sctp_cchunk_pend, sctp->sctp_cxmit_list == NULL ?
		    "yes" : "no", sctp->sctp_state));
		return;
	}

	if (fp == NULL)
		fp = sctp->sctp_current;

	/* OK to send */
	ipmp = sctp_make_mp(sctp, fp, 0);
	if (ipmp == NULL) {
		SCTP_FADDR_RC_TIMER_RESTART(sctp, fp, fp->sf_rto);
		SCTP_KSTAT(sctps, sctp_send_asconf_failed);
		return;
	}
	mp = sctp->sctp_cxmit_list;
	/* Fill in the mandatory  Address Parameter TLV */
	isv4 = (fp != NULL) ? fp->sf_isv4 : sctp->sctp_current->sf_isv4;
	ph = (sctp_parm_hdr_t *)(mp->b_rptr + sizeof (sctp_chunk_hdr_t) +
	    sizeof (uint32_t));
	if (isv4) {
		ipha_t		*ipha = (ipha_t *)ipmp->b_rptr;
		in6_addr_t	ipaddr;
		ipaddr_t	addr4;

		ph->sph_type = htons(PARM_ADDR4);
		ph->sph_len = htons(PARM_ADDR4_LEN);
		if (ipha->ipha_src != INADDR_ANY) {
			bcopy(&ipha->ipha_src, ph + 1, IP_ADDR_LEN);
		} else {
			ipaddr = sctp_get_valid_addr(sctp, B_FALSE, &saddr_set);
			/*
			 * All the addresses are down.
			 * Maybe we might have better luck next time.
			 */
			if (!saddr_set) {
				SCTP_FADDR_RC_TIMER_RESTART(sctp, fp,
				    fp->sf_rto);
				freeb(ipmp);
				return;
			}
			IN6_V4MAPPED_TO_IPADDR(&ipaddr, addr4);
			bcopy(&addr4, ph + 1, IP_ADDR_LEN);
		}
	} else {
		ip6_t		*ip6 = (ip6_t *)ipmp->b_rptr;
		in6_addr_t	ipaddr;

		ph->sph_type = htons(PARM_ADDR6);
		ph->sph_len = htons(PARM_ADDR6_LEN);
		if (!IN6_IS_ADDR_UNSPECIFIED(&ip6->ip6_src)) {
			bcopy(&ip6->ip6_src, ph + 1, IPV6_ADDR_LEN);
		} else {
			ipaddr = sctp_get_valid_addr(sctp, B_TRUE, &saddr_set);
			/*
			 * All the addresses are down.
			 * Maybe we might have better luck next time.
			 */
			if (!saddr_set) {
				SCTP_FADDR_RC_TIMER_RESTART(sctp, fp,
				    fp->sf_rto);
				freeb(ipmp);
				return;
			}
			bcopy(&ipaddr, ph + 1, IPV6_ADDR_LEN);
		}
	}

	/* Don't exceed CWND */
	if ((MBLKL(mp) > (fp->sf_cwnd - fp->sf_suna)) ||
	    ((mp = dupb(sctp->sctp_cxmit_list)) == NULL)) {
		SCTP_FADDR_RC_TIMER_RESTART(sctp, fp, fp->sf_rto);
		freeb(ipmp);
		return;
	}

	/* Set the serial number now, if sending for the first time */
	if (!SCTP_CHUNK_WANT_REXMIT(mp)) {
		snp = (uint32_t *)(mp->b_rptr + sizeof (sctp_chunk_hdr_t));
		*snp = htonl(sctp->sctp_lcsn++);
	}
	SCTP_CHUNK_CLEAR_FLAGS(mp);
	fp->sf_suna += MBLKL(mp);
	/* Attach the header and send the chunk */
	ipmp->b_cont = mp;
	sctp->sctp_cchunk_pend = 1;

	SCTP_SET_SENT_FLAG(sctp->sctp_cxmit_list);
	SCTP_SET_CHUNK_DEST(sctp->sctp_cxmit_list, fp);
	sctp_set_iplen(sctp, ipmp, fp->sf_ixa);
	(void) conn_ip_output(ipmp, fp->sf_ixa);
	BUMP_LOCAL(sctp->sctp_opkts);
	SCTP_FADDR_RC_TIMER_RESTART(sctp, fp, fp->sf_rto);
#undef	SCTP_SET_SENT_FLAG
}

/*
 * Generate ASCONF error param, include errph, if present.
 */
static mblk_t *
sctp_asconf_adderr(int err, sctp_parm_hdr_t *errph, uint32_t cid)
{
	mblk_t		*mp;
	sctp_parm_hdr_t	*eph;
	sctp_parm_hdr_t	*wph;
	size_t		len;
	size_t		elen = 0;

	len = sizeof (*wph) + sizeof (*eph) + sizeof (cid);
	if (errph != NULL) {
		elen = ntohs(errph->sph_len);
		len += elen;
	}
	mp = allocb(len, BPRI_MED);
	if (mp == NULL) {
		return (NULL);
	}
	wph = (sctp_parm_hdr_t *)mp->b_rptr;
	/* error cause wrapper */
	wph->sph_type = htons(PARM_ERROR_IND);
	wph->sph_len = htons(len);
	bcopy(&cid, wph + 1, sizeof (uint32_t));

	/* error cause */
	eph = (sctp_parm_hdr_t *)((char *)wph + sizeof (sctp_parm_hdr_t) +
	    sizeof (cid));
	eph->sph_type = htons(err);
	eph->sph_len = htons(len - sizeof (*wph) - sizeof (cid));
	mp->b_wptr = (uchar_t *)(eph + 1);

	/* details */
	if (elen > 0) {
		bcopy(errph, mp->b_wptr, elen);
		mp->b_wptr += elen;
	}
	return (mp);
}

static mblk_t *
sctp_check_addip_addr(sctp_parm_hdr_t *ph, sctp_parm_hdr_t *oph, int *cont,
    uint32_t cid, in6_addr_t *raddr)
{
	uint16_t	atype;
	uint16_t	alen;
	mblk_t		*mp;
	in6_addr_t	addr;
	ipaddr_t	*addr4;

	atype = ntohs(ph->sph_type);
	alen = ntohs(ph->sph_len);

	if (atype != PARM_ADDR4 && atype != PARM_ADDR6) {
		mp = sctp_asconf_adderr(SCTP_ERR_BAD_MANDPARM, oph, cid);
		if (mp == NULL) {
			*cont = -1;
		}
		return (mp);
	}
	if ((atype == PARM_ADDR4 && alen < PARM_ADDR4_LEN) ||
	    (atype == PARM_ADDR6 && alen < PARM_ADDR6_LEN)) {
		mp = sctp_asconf_adderr(SCTP_ERR_BAD_MANDPARM, oph, cid);
		if (mp == NULL) {
			*cont = -1;
		}
		return (mp);
	}

	/* Address parameter is present; extract and screen it */
	if (atype == PARM_ADDR4) {
		addr4 = (ipaddr_t *)(ph + 1);
		IN6_IPADDR_TO_V4MAPPED(*addr4, &addr);

		/* screen XXX loopback to scoping */
		if (*addr4 == 0 || *addr4 == INADDR_BROADCAST ||
		    *addr4 == htonl(INADDR_LOOPBACK) || CLASSD(*addr4)) {
			dprint(1, ("addip: addr not unicast: %x:%x:%x:%x\n",
			    SCTP_PRINTADDR(addr)));
			mp = sctp_asconf_adderr(SCTP_ERR_BAD_MANDPARM, oph,
			    cid);
			if (mp == NULL) {
				*cont = -1;
			}
			return (mp);
		}
		/*
		 * XXX also need to check for subnet
		 * broadcasts. This should probably
		 * wait until we have full access
		 * to the ILL tables.
		 */

	} else {
		bcopy(ph + 1, &addr, sizeof (addr));

		/* screen XXX loopback to scoping */
		if (IN6_IS_ADDR_LINKLOCAL(&addr) ||
		    IN6_IS_ADDR_MULTICAST(&addr) ||
		    IN6_IS_ADDR_LOOPBACK(&addr)) {
			dprint(1, ("addip: addr not unicast: %x:%x:%x:%x\n",
			    SCTP_PRINTADDR(addr)));
			mp = sctp_asconf_adderr(SCTP_ERR_BAD_MANDPARM, oph,
			    cid);
			if (mp == NULL) {
				*cont = -1;
			}
			return (mp);
		}

	}

	/* OK */
	*raddr = addr;
	return (NULL);
}

/*
 * Handles both add and delete address requests.
 */
static mblk_t *
sctp_addip_req(sctp_t *sctp, sctp_parm_hdr_t *ph, uint32_t cid,
    sctp_faddr_t *fp, int *cont, int act, in6_addr_t *raddr)
{
	in6_addr_t	addr;
	uint16_t	type;
	mblk_t		*mp;
	sctp_faddr_t	*nfp;
	sctp_parm_hdr_t	*oph = ph;
	int		err;
	sctp_stack_t	*sctps = sctp->sctp_sctps;

	*cont = 1;

	/* Send back an authorization error if addip is disabled */
	if (!sctps->sctps_addip_enabled) {
		err = SCTP_ERR_UNAUTHORIZED;
		goto error_handler;
	}
	/* Check input */
	if (ntohs(ph->sph_len) < (sizeof (*ph) * 2)) {
		err = SCTP_ERR_BAD_MANDPARM;
		goto error_handler;
	}

	type = ntohs(ph->sph_type);
	ph = (sctp_parm_hdr_t *)((char *)ph + sizeof (sctp_parm_hdr_t) +
	    sizeof (cid));
	mp = sctp_check_addip_addr(ph, oph, cont, cid, &addr);
	if (mp != NULL)
		return (mp);
	if (raddr != NULL)
		*raddr = addr;
	if (type == PARM_ADD_IP) {
		if (sctp_lookup_faddr(sctp, &addr) != NULL) {
			/* Address is already part of association */
			dprint(1, ("addip: addr already here: %x:%x:%x:%x\n",
			    SCTP_PRINTADDR(addr)));
			err = SCTP_ERR_BAD_MANDPARM;
			goto error_handler;
		}

		if (!act) {
			return (NULL);
		}
		/* Add the new address */
		mutex_enter(&sctp->sctp_conn_tfp->tf_lock);
		err = sctp_add_faddr(sctp, &addr, KM_NOSLEEP, B_FALSE);
		mutex_exit(&sctp->sctp_conn_tfp->tf_lock);
		if (err == ENOMEM) {
			/* no memory */
			*cont = -1;
			return (NULL);
		}
		if (err != 0) {
			err = SCTP_ERR_BAD_MANDPARM;
			goto error_handler;
		}
		sctp_intf_event(sctp, addr, SCTP_ADDR_ADDED, 0);
	} else if (type == PARM_DEL_IP) {
		nfp = sctp_lookup_faddr(sctp, &addr);
		if (nfp == NULL) {
			/*
			 * Peer is trying to delete an address that is not
			 * part of the association.
			 */
			dprint(1, ("delip: addr not here: %x:%x:%x:%x\n",
			    SCTP_PRINTADDR(addr)));
			err = SCTP_ERR_BAD_MANDPARM;
			goto error_handler;
		}
		if (sctp->sctp_faddrs == nfp && nfp->sf_next == NULL) {
			/* Peer is trying to delete last address */
			dprint(1, ("delip: del last addr: %x:%x:%x:%x\n",
			    SCTP_PRINTADDR(addr)));
			err = SCTP_ERR_DEL_LAST_ADDR;
			goto error_handler;
		}
		if (nfp == fp) {
			/* Peer is trying to delete source address */
			dprint(1, ("delip: del src addr: %x:%x:%x:%x\n",
			    SCTP_PRINTADDR(addr)));
			err = SCTP_ERR_DEL_SRC_ADDR;
			goto error_handler;
		}
		if (!act) {
			return (NULL);
		}

		sctp_unlink_faddr(sctp, nfp);
		/* Update all references to the deleted faddr */
		if (sctp->sctp_primary == nfp) {
			sctp->sctp_primary = fp;
		}
		if (sctp->sctp_current == nfp) {
			sctp_set_faddr_current(sctp, fp);
		}
		if (sctp->sctp_lastdata == nfp) {
			sctp->sctp_lastdata = fp;
		}
		if (sctp->sctp_shutdown_faddr == nfp) {
			sctp->sctp_shutdown_faddr = nfp;
		}
		if (sctp->sctp_lastfaddr == nfp) {
			for (fp = sctp->sctp_faddrs; fp->sf_next;
			    fp = fp->sf_next)
				;
			sctp->sctp_lastfaddr = fp;
		}
		sctp_intf_event(sctp, addr, SCTP_ADDR_REMOVED, 0);
	} else {
		ASSERT(0);
	}

	/* Successful, don't need to return anything. */
	return (NULL);

error_handler:
	mp = sctp_asconf_adderr(err, oph, cid);
	if (mp == NULL)
		*cont = -1;
	return (mp);
}

/*
 * Handles both add and delete IP ACKs.
 */
/*ARGSUSED*/
static void
sctp_addip_ack(sctp_t *sctp, sctp_parm_hdr_t *ph, sctp_parm_hdr_t *oph,
    sctp_faddr_t *fp, in6_addr_t *laddr)
{
	in6_addr_t		addr;
	sctp_saddr_ipif_t	*sp;
	ipaddr_t		*addr4;
	boolean_t		backout = B_FALSE;
	uint16_t		type;
	uint32_t		*cid;

	/* could be an ASSERT */
	if (laddr != NULL)
		IN6_IPADDR_TO_V4MAPPED(0, laddr);

	/* If the peer doesn't understand Add-IP, remember it */
	if (ph != NULL && ph->sph_type == htons(PARM_UNRECOGNIZED)) {
		sctp->sctp_understands_addip = B_FALSE;
		backout = B_TRUE;
	}

	/*
	 * If OK, continue with the add / delete action, otherwise
	 * back out the action.
	 */
	if (ph != NULL && ph->sph_type != htons(PARM_SUCCESS)) {
		backout = B_TRUE;
		sctp_error_event(sctp, (sctp_chunk_hdr_t *)ph, B_TRUE);
	}

	type = ntohs(oph->sph_type);
	cid = (uint32_t *)(oph + 1);
	oph = (sctp_parm_hdr_t *)(cid + 1);
	if (oph->sph_type == htons(PARM_ADDR4)) {
		addr4 = (ipaddr_t *)(oph + 1);
		IN6_IPADDR_TO_V4MAPPED(*addr4, &addr);
	} else {
		bcopy(oph + 1, &addr, sizeof (addr));
	}

	/* Signifies that the address was sucessfully processed */
	if (!backout && laddr != NULL)
		*laddr = addr;

	sp = sctp_saddr_lookup(sctp, &addr, 0);
	ASSERT(sp != NULL);

	if (type == PARM_ADD_IP) {
		if (backout) {
			sctp_del_saddr(sctp, sp);
		} else {
			sp->saddr_ipif_dontsrc = 0;
		}
	} else if (type == PARM_DEL_IP) {
		if (backout) {
			sp->saddr_ipif_delete_pending = 0;
			sp->saddr_ipif_dontsrc = 0;
		} else {
			sctp_del_saddr(sctp, sp);
		}
	} else {
		/* Must be either PARM_ADD_IP or PARM_DEL_IP */
		ASSERT(0);
	}
}

/*ARGSUSED*/
static mblk_t *
sctp_setprim_req(sctp_t *sctp, sctp_parm_hdr_t *ph, uint32_t cid,
    sctp_faddr_t *fp, int *cont, int act, in6_addr_t *raddr)
{
	mblk_t *mp;
	sctp_parm_hdr_t *oph;
	sctp_faddr_t *nfp;
	in6_addr_t addr;

	*cont = 1;

	/* Does the peer understand ASCONF and Add-IP? */
	if (!sctp->sctp_understands_asconf || !sctp->sctp_understands_addip) {
		mp = sctp_asconf_adderr(SCTP_ERR_UNAUTHORIZED, ph, cid);
		if (mp == NULL) {
			*cont = -1;
		}
		return (mp);
	}

	/* Check input */
	if (ntohs(ph->sph_len) < (sizeof (*ph) * 2)) {
		mp = sctp_asconf_adderr(SCTP_ERR_BAD_MANDPARM, ph, cid);
		if (mp == NULL) {
			*cont = -1;
		}
		return (mp);
	}

	oph = ph;
	ph = (sctp_parm_hdr_t *)((char *)ph + sizeof (sctp_parm_hdr_t) +
	    sizeof (cid));
	mp = sctp_check_addip_addr(ph, oph, cont, cid, &addr);
	if (mp != NULL) {
		return (mp);
	}

	nfp = sctp_lookup_faddr(sctp, &addr);
	if (nfp == NULL) {
		/*
		 * Peer is trying to set an address that is not
		 * part of the association.
		 */
		dprint(1, ("setprim: addr not here: %x:%x:%x:%x\n",
		    SCTP_PRINTADDR(addr)));
		mp = sctp_asconf_adderr(SCTP_ERR_BAD_MANDPARM, oph, cid);
		if (mp == NULL) {
			*cont = -1;
		}
		return (mp);
	}

	sctp_intf_event(sctp, addr, SCTP_ADDR_MADE_PRIM, 0);
	sctp->sctp_primary = nfp;
	if (nfp->sf_state != SCTP_FADDRS_ALIVE || nfp == sctp->sctp_current) {
		return (NULL);
	}
	sctp_set_faddr_current(sctp, nfp);
	return (NULL);
}

/*ARGSUSED*/
static void
sctp_setprim_ack(sctp_t *sctp, sctp_parm_hdr_t *ph, sctp_parm_hdr_t *oph,
    sctp_faddr_t *fp, in6_addr_t *laddr)
{
	if (ph != NULL && ph->sph_type != htons(PARM_SUCCESS)) {
		/* If the peer doesn't understand Add-IP, remember it */
		if (ph->sph_type == htons(PARM_UNRECOGNIZED)) {
			sctp->sctp_understands_addip = B_FALSE;
		}
		sctp_error_event(sctp, (sctp_chunk_hdr_t *)ph, B_TRUE);
	}

	/* On success we do nothing */
}

int
sctp_add_ip(sctp_t *sctp, const void *addrs, uint32_t cnt)
{
	struct sockaddr_in	*sin4;
	struct sockaddr_in6	*sin6;
	mblk_t			*mp;
	int			error = 0;
	int			i;
	sctp_addip4_t		*ad4;
	sctp_addip6_t		*ad6;
	sctp_asconf_t		asc[1];
	uint16_t		type = htons(PARM_ADD_IP);
	boolean_t		v4mapped = B_FALSE;
	sctp_cl_ainfo_t		*ainfo = NULL;
	conn_t			*connp = sctp->sctp_connp;

	/* Does the peer understand ASCONF and Add-IP? */
	if (!sctp->sctp_understands_asconf || !sctp->sctp_understands_addip)
		return (EOPNOTSUPP);

	/*
	 * On a clustered node, we need to pass this list when
	 * we get an ASCONF-ACK. We only pre-allocate memory for the
	 * list, but fill in the addresses when it is processed
	 * successfully after we get an ASCONF-ACK.
	 */
	if (cl_sctp_assoc_change != NULL) {
		ainfo = kmem_zalloc(sizeof (*ainfo), KM_SLEEP);
		/*
		 * Reserve space for the list of new addresses
		 */
		ainfo->sctp_cl_asize = sizeof (in6_addr_t) * cnt;
		ainfo->sctp_cl_alist = kmem_alloc(ainfo->sctp_cl_asize,
		    KM_SLEEP);
	}

	sctp_asconf_init(asc);

	/*
	 * Screen addresses:
	 * If adding:
	 *   o Must not already be a part of the association
	 *   o Must be AF_INET or AF_INET6
	 *   o XXX Must be valid source address for this node
	 *   o Must be unicast
	 *   o XXX Must fit scoping rules
	 * If deleting:
	 *   o Must be part of the association
	 */
	sin6 = NULL;
	for (i = 0; i < cnt; i++) {
		switch (connp->conn_family) {
		case AF_INET:
			sin4 = (struct sockaddr_in *)addrs + i;
			v4mapped = B_TRUE;
			break;

		case AF_INET6:
			sin6 = (struct sockaddr_in6 *)addrs + i;
			break;
		}

		if (v4mapped) {
			mp = allocb(sizeof (*ad4), BPRI_MED);
			if (mp == NULL) {
				error = ENOMEM;
				goto fail;
			}
			mp->b_wptr += sizeof (*ad4);
			ad4 = (sctp_addip4_t *)mp->b_rptr;
			ad4->sad4_addip_ph.sph_type = type;
			ad4->sad4_addip_ph.sph_len =
			    htons(sizeof (sctp_parm_hdr_t) +
			    PARM_ADDR4_LEN + sizeof (ad4->asconf_req_cid));
			ad4->sad4_addr4_ph.sph_type = htons(PARM_ADDR4);
			ad4->sad4_addr4_ph.sph_len = htons(PARM_ADDR4_LEN);
			ad4->sad4_addr = sin4->sin_addr.s_addr;
		} else {
			mp = allocb(sizeof (*ad6), BPRI_MED);
			if (mp == NULL) {
				error = ENOMEM;
				goto fail;
			}
			mp->b_wptr += sizeof (*ad6);
			ad6 = (sctp_addip6_t *)mp->b_rptr;
			ad6->sad6_addip_ph.sph_type = type;
			ad6->sad6_addip_ph.sph_len =
			    htons(sizeof (sctp_parm_hdr_t) +
			    PARM_ADDR6_LEN + sizeof (ad6->asconf_req_cid));
			ad6->sad6_addr6_ph.sph_type = htons(PARM_ADDR6);
			ad6->sad6_addr6_ph.sph_len = htons(PARM_ADDR6_LEN);
			ad6->sad6_addr = sin6->sin6_addr;
		}
		error = sctp_asconf_add(asc, mp);
		if (error != 0)
			goto fail;
	}
	error = sctp_asconf_send(sctp, asc, sctp->sctp_current, ainfo);
	if (error != 0)
		goto fail;

	return (0);

fail:
	if (ainfo != NULL) {
		kmem_free(ainfo->sctp_cl_alist, ainfo->sctp_cl_asize);
		ainfo->sctp_cl_asize = 0;
		kmem_free(ainfo, sizeof (*ainfo));
	}
	sctp_asconf_destroy(asc);
	return (error);
}

int
sctp_del_ip(sctp_t *sctp, const void *addrs, uint32_t cnt, uchar_t *ulist,
    size_t usize)
{
	struct sockaddr_in	*sin4;
	struct sockaddr_in6	*sin6;
	mblk_t			*mp;
	int			error = 0;
	int			i;
	int			addrcnt = 0;
	sctp_addip4_t		*ad4;
	sctp_addip6_t		*ad6;
	sctp_asconf_t		asc[1];
	sctp_saddr_ipif_t	*nsp;
	uint16_t		type = htons(PARM_DEL_IP);
	boolean_t		v4mapped = B_FALSE;
	in6_addr_t		addr;
	boolean_t		asconf = B_TRUE;
	uint_t			ifindex;
	sctp_cl_ainfo_t		*ainfo = NULL;
	uchar_t			*p = ulist;
	boolean_t		check_lport = B_FALSE;
	sctp_stack_t		*sctps = sctp->sctp_sctps;
	conn_t			*connp = sctp->sctp_connp;

	/* Does the peer understand ASCONF and Add-IP? */
	if (sctp->sctp_state <= SCTPS_LISTEN || !sctps->sctps_addip_enabled ||
	    !sctp->sctp_understands_asconf || !sctp->sctp_understands_addip) {
		asconf = B_FALSE;
	}

	if (sctp->sctp_state > SCTPS_BOUND)
		check_lport = B_TRUE;

	if (asconf) {
		/*
		 * On a clustered node, we need to pass this list when
		 * we get an ASCONF-ACK. We only pre-allocate memory for the
		 * list, but fill in the addresses when it is processed
		 * successfully after we get an ASCONF-ACK.
		 */
		if (cl_sctp_assoc_change != NULL) {
			ainfo = kmem_alloc(sizeof (*ainfo), KM_SLEEP);
			ainfo->sctp_cl_dsize = sizeof (in6_addr_t) * cnt;
			ainfo->sctp_cl_dlist = kmem_alloc(ainfo->sctp_cl_dsize,
			    KM_SLEEP);
		}
		sctp_asconf_init(asc);
	}
	/*
	 * Screen addresses:
	 * If adding:
	 *   o Must not already be a part of the association
	 *   o Must be AF_INET or AF_INET6
	 *   o XXX Must be valid source address for this node
	 *   o Must be unicast
	 *   o XXX Must fit scoping rules
	 * If deleting:
	 *   o Must be part of the association
	 */
	for (i = 0; i < cnt; i++) {
		ifindex = 0;

		switch (connp->conn_family) {
		case AF_INET:
			sin4 = (struct sockaddr_in *)addrs + i;
			if (check_lport &&
			    sin4->sin_port != connp->conn_lport) {
				error = EINVAL;
				goto fail;
			}
			v4mapped = B_TRUE;
			IN6_IPADDR_TO_V4MAPPED(sin4->sin_addr.s_addr, &addr);
			break;

		case AF_INET6:
			sin6 = (struct sockaddr_in6 *)addrs + i;
			if (check_lport &&
			    sin6->sin6_port != connp->conn_lport) {
				error = EINVAL;
				goto fail;
			}
			addr = sin6->sin6_addr;
			ifindex = sin6->sin6_scope_id;
			break;
		}
		nsp = sctp_saddr_lookup(sctp, &addr, ifindex);
		if (nsp == NULL) {
			error = EADDRNOTAVAIL;
			goto fail;
		}

		/* Collect the list of addresses, if required */
		if (usize >= sizeof (addr)) {
			bcopy(&addr, p, sizeof (addr));
			p += sizeof (addr);
			usize -= sizeof (addr);
		}
		if (!asconf)
			continue;

		nsp->saddr_ipif_delete_pending = 1;
		nsp->saddr_ipif_dontsrc = 1;
		addrcnt++;
		if (v4mapped) {
			mp = allocb(sizeof (*ad4), BPRI_MED);
			if (mp == NULL) {
				error = ENOMEM;
				goto fail;
			}
			mp->b_wptr += sizeof (*ad4);
			ad4 = (sctp_addip4_t *)mp->b_rptr;
			ad4->sad4_addip_ph.sph_type = type;
			ad4->sad4_addip_ph.sph_len =
			    htons(sizeof (sctp_parm_hdr_t) +
			    PARM_ADDR4_LEN + sizeof (ad4->asconf_req_cid));
			ad4->sad4_addr4_ph.sph_type = htons(PARM_ADDR4);
			ad4->sad4_addr4_ph.sph_len = htons(PARM_ADDR4_LEN);
			ad4->sad4_addr = sin4->sin_addr.s_addr;
		} else {
			mp = allocb(sizeof (*ad6), BPRI_MED);
			if (mp == NULL) {
				error = ENOMEM;
				goto fail;
			}
			mp->b_wptr += sizeof (*ad6);
			ad6 = (sctp_addip6_t *)mp->b_rptr;
			ad6->sad6_addip_ph.sph_type = type;
			ad6->sad6_addip_ph.sph_len =
			    htons(sizeof (sctp_parm_hdr_t) + PARM_ADDR6_LEN +
			    sizeof (ad6->asconf_req_cid));
			ad6->sad6_addr6_ph.sph_type = htons(PARM_ADDR6);
			ad6->sad6_addr6_ph.sph_len = htons(PARM_ADDR6_LEN);
			ad6->sad6_addr = addr;
		}

		error = sctp_asconf_add(asc, mp);
		if (error != 0)
			goto fail;
	}

	if (!asconf) {
		sctp_del_saddr_list(sctp, addrs, cnt, B_FALSE);
		return (0);
	}
	error = sctp_asconf_send(sctp, asc, sctp->sctp_current, ainfo);
	if (error != 0)
		goto fail;
	sctp_redo_faddr_srcs(sctp);
	return (0);

fail:
	if (ainfo != NULL) {
		kmem_free(ainfo->sctp_cl_dlist, ainfo->sctp_cl_dsize);
		ainfo->sctp_cl_dsize = 0;
		kmem_free(ainfo, sizeof (*ainfo));
	}
	if (!asconf)
		return (error);
	for (i = 0; i < addrcnt; i++) {
		ifindex = 0;

		switch (connp->conn_family) {
		case AF_INET:
			sin4 = (struct sockaddr_in *)addrs + i;
			IN6_INADDR_TO_V4MAPPED(&(sin4->sin_addr), &addr);
			break;
		case AF_INET6:
			sin6 = (struct sockaddr_in6 *)addrs + i;
			addr = sin6->sin6_addr;
			ifindex = sin6->sin6_scope_id;
			break;
		}
		nsp = sctp_saddr_lookup(sctp, &addr, ifindex);
		ASSERT(nsp != NULL);
		nsp->saddr_ipif_delete_pending = 0;
		nsp->saddr_ipif_dontsrc = 0;
	}
	sctp_asconf_destroy(asc);

	return (error);
}

int
sctp_set_peerprim(sctp_t *sctp, const void *inp)
{
	const struct sctp_setprim	*prim = inp;
	const struct sockaddr_storage	*ss;
	struct sockaddr_in *sin;
	struct sockaddr_in6 *sin6;
	in6_addr_t addr;
	mblk_t *mp;
	sctp_saddr_ipif_t *sp;
	sctp_addip4_t *ad4;
	sctp_addip6_t *ad6;
	sctp_asconf_t asc[1];
	int error = 0;
	uint_t	ifindex = 0;

	/* Does the peer understand ASCONF and Add-IP? */
	if (!sctp->sctp_understands_asconf || !sctp->sctp_understands_addip) {
		return (EOPNOTSUPP);
	}

	/* Don't do anything if we are not connected */
	if (sctp->sctp_state != SCTPS_ESTABLISHED)
		return (EINVAL);

	ss = &prim->ssp_addr;
	sin = NULL;
	sin6 = NULL;
	if (ss->ss_family == AF_INET) {
		sin = (struct sockaddr_in *)ss;
		IN6_IPADDR_TO_V4MAPPED(sin->sin_addr.s_addr, &addr);
	} else if (ss->ss_family == AF_INET6) {
		sin6 = (struct sockaddr_in6 *)ss;
		addr = sin6->sin6_addr;
		ifindex = sin6->sin6_scope_id;
	} else {
		return (EAFNOSUPPORT);
	}
	sp = sctp_saddr_lookup(sctp, &addr, ifindex);
	if (sp == NULL)
		return (EADDRNOTAVAIL);
	sctp_asconf_init(asc);
	if (sin) {
		mp = allocb(sizeof (*ad4), BPRI_MED);
		if (mp == NULL) {
			error = ENOMEM;
			goto fail;
		}
		mp->b_wptr += sizeof (*ad4);
		ad4 = (sctp_addip4_t *)mp->b_rptr;
		ad4->sad4_addip_ph.sph_type = htons(PARM_SET_PRIMARY);
		ad4->sad4_addip_ph.sph_len = htons(sizeof (sctp_parm_hdr_t) +
		    PARM_ADDR4_LEN + sizeof (ad4->asconf_req_cid));
		ad4->sad4_addr4_ph.sph_type = htons(PARM_ADDR4);
		ad4->sad4_addr4_ph.sph_len = htons(PARM_ADDR4_LEN);
		ad4->sad4_addr = sin->sin_addr.s_addr;
	} else {
		mp = allocb(sizeof (*ad6), BPRI_MED);
		if (mp == NULL) {
			error = ENOMEM;
			goto fail;
		}
		mp->b_wptr += sizeof (*ad6);
		ad6 = (sctp_addip6_t *)mp->b_rptr;
		ad6->sad6_addip_ph.sph_type = htons(PARM_SET_PRIMARY);
		ad6->sad6_addip_ph.sph_len = htons(sizeof (sctp_parm_hdr_t) +
		    PARM_ADDR6_LEN + sizeof (ad6->asconf_req_cid));
		ad6->sad6_addr6_ph.sph_type = htons(PARM_ADDR6);
		ad6->sad6_addr6_ph.sph_len = htons(PARM_ADDR6_LEN);
		ad6->sad6_addr = sin6->sin6_addr;
	}

	error = sctp_asconf_add(asc, mp);
	if (error != 0) {
		goto fail;
	}

	error = sctp_asconf_send(sctp, asc, sctp->sctp_current, NULL);
	if (error == 0) {
		return (0);
	}

fail:
	sctp_asconf_destroy(asc);
	return (error);
}
