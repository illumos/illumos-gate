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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/systm.h>
#include <sys/stream.h>
#include <sys/cmn_err.h>
#include <sys/ddi.h>
#include <sys/strsubr.h>
#include <sys/tsol/tnet.h>

#include <netinet/in.h>
#include <netinet/ip6.h>

#include <inet/common.h>
#include <inet/ip.h>
#include <inet/ip6.h>
#include <inet/mib2.h>
#include <inet/sctp_ip.h>
#include <inet/ipclassifier.h>
#include <inet/ip_ire.h>
#include "sctp_impl.h"
#include "sctp_asconf.h"

ssize_t
sctp_link_abort(mblk_t *mp, uint16_t serror, char *details, size_t len,
    int iserror, boolean_t tbit)
{
	size_t alen;
	mblk_t *amp;
	sctp_chunk_hdr_t *acp;
	sctp_parm_hdr_t *eph;

	ASSERT(mp != NULL && mp->b_cont == NULL);

	alen = sizeof (*acp) + (serror != 0 ? (sizeof (*eph) + len) : 0);

	amp = allocb(alen, BPRI_MED);
	if (amp == NULL) {
		return (-1);
	}

	amp->b_wptr = amp->b_rptr + alen;

	/* Chunk header */
	acp = (sctp_chunk_hdr_t *)amp->b_rptr;
	acp->sch_id = iserror ? CHUNK_ERROR : CHUNK_ABORT;
	acp->sch_flags = 0;
	acp->sch_len = htons(alen);
	if (tbit)
		SCTP_SET_TBIT(acp);

	linkb(mp, amp);

	if (serror == 0) {
		return (alen);
	}

	eph = (sctp_parm_hdr_t *)(acp + 1);
	eph->sph_type = htons(serror);
	eph->sph_len = htons(len + sizeof (*eph));

	if (len > 0) {
		bcopy(details, eph + 1, len);
	}

	/* XXX pad */

	return (alen);
}

void
sctp_user_abort(sctp_t *sctp, mblk_t *data, boolean_t tbit)
{
	mblk_t *mp;
	int len, hdrlen;
	char *cause;
	sctp_faddr_t *fp = sctp->sctp_current;

	mp = sctp_make_mp(sctp, fp, 0);
	if (mp == NULL)
		return;
	/*
	 * Create abort chunk.
	 */
	if (data) {
		if (fp->isv4) {
			hdrlen = sctp->sctp_hdr_len;
		} else {
			hdrlen = sctp->sctp_hdr6_len;
		}
		hdrlen += sizeof (sctp_chunk_hdr_t) + sizeof (sctp_parm_hdr_t);
		cause = (char *)data->b_rptr;
		len = data->b_wptr - data->b_rptr;

		if (len + hdrlen > fp->sfa_pmss) {
			len = fp->sfa_pmss - hdrlen;
		}
	} else {
		cause = NULL;
		len = 0;
	}
	if ((len = sctp_link_abort(mp, SCTP_ERR_USER_ABORT, cause, len, 0,
		tbit)) < 0) {
		freemsg(mp);
		return;
	}
	sctp_set_iplen(sctp, mp);
	BUMP_MIB(&sctp_mib, sctpAborted);
	BUMP_LOCAL(sctp->sctp_opkts);
	BUMP_LOCAL(sctp->sctp_obchunks);

	CONN_INC_REF(sctp->sctp_connp);
	mp->b_flag |= MSGHASREF;
	IP_PUT(mp, sctp->sctp_connp, fp->isv4);
}

/*
 * If iserror == 0, sends an abort. If iserror != 0, sends an error.
 */
void
sctp_send_abort(sctp_t *sctp, uint32_t vtag, uint16_t serror, char *details,
    size_t len, mblk_t *inmp, int iserror, boolean_t tbit)
{

	mblk_t		*hmp;
	uint32_t	ip_hdr_len;
	ipha_t		*iniph;
	ipha_t		*ahiph;
	ip6_t		*inip6h;
	ip6_t		*ahip6h;
	sctp_hdr_t	*sh;
	sctp_hdr_t	*insh;
	size_t		ahlen;
	uchar_t		*p;
	ssize_t		alen;
	int		isv4;
	ire_t		*ire;
	irb_t		*irb;
	ts_label_t	*tsl;
	conn_t		*connp;
	cred_t		*cr = NULL;

	isv4 = (IPH_HDR_VERSION(inmp->b_rptr) == IPV4_VERSION);
	if (isv4) {
		ahlen = sctp->sctp_hdr_len;
	} else {
		ahlen = sctp->sctp_hdr6_len;
	}

	/*
	 * If this is a labeled system, then check to see if we're allowed to
	 * send a response to this particular sender.  If not, then just drop.
	 */
	if (is_system_labeled() && !tsol_can_reply_error(inmp))
		return;

	hmp = allocb_cred(sctp_wroff_xtra + ahlen, CONN_CRED(sctp->sctp_connp));
	if (hmp == NULL) {
		/* XXX no resources */
		return;
	}

	/* copy in the IP / SCTP header */
	p = hmp->b_rptr + sctp_wroff_xtra;
	hmp->b_rptr = p;
	hmp->b_wptr = p + ahlen;
	if (isv4) {
		bcopy(sctp->sctp_iphc, p, sctp->sctp_hdr_len);
		/*
		 * Composite is likely incomplete at this point, so pull
		 * info from the incoming IP / SCTP headers.
		 */
		ahiph = (ipha_t *)p;
		iniph = (ipha_t *)inmp->b_rptr;
		ip_hdr_len = IPH_HDR_LENGTH(inmp->b_rptr);

		sh = (sctp_hdr_t *)(p + sctp->sctp_ip_hdr_len);
		ASSERT(OK_32PTR(sh));

		insh = (sctp_hdr_t *)((uchar_t *)iniph + ip_hdr_len);
		ASSERT(OK_32PTR(insh));

		/* Copy in the peer's IP addr */
		ahiph->ipha_dst = iniph->ipha_src;
		ahiph->ipha_src = iniph->ipha_dst;
	} else {
		bcopy(sctp->sctp_iphc6, p, sctp->sctp_hdr6_len);
		ahip6h = (ip6_t *)p;
		inip6h = (ip6_t *)inmp->b_rptr;
		ip_hdr_len = sizeof (ip6_t);

		sh = (sctp_hdr_t *)(p + sctp->sctp_ip_hdr6_len);
		ASSERT(OK_32PTR(sh));

		insh = (sctp_hdr_t *)((uchar_t *)inip6h + ip_hdr_len);
		ASSERT(OK_32PTR(insh));

		/* Copy in the peer's IP addr */
		ahip6h->ip6_dst = inip6h->ip6_src;
		ahip6h->ip6_src = inip6h->ip6_dst;
	}

	/* Fill in the holes in the SCTP common header */
	sh->sh_sport = insh->sh_dport;
	sh->sh_dport = insh->sh_sport;
	sh->sh_verf = vtag;

	/* Link in the abort chunk */
	if ((alen = sctp_link_abort(hmp, serror, details, len, iserror, tbit))
	    < 0) {
		freemsg(hmp);
		return;
	}

	if (isv4) {
		ahiph->ipha_length = htons(ahlen + alen);
	} else {
		ahip6h->ip6_plen = htons(alen + sizeof (*sh));
	}

	BUMP_MIB(&sctp_mib, sctpAborted);
	BUMP_LOCAL(sctp->sctp_obchunks);

	connp = sctp->sctp_connp;
	if (is_system_labeled() && (cr = DB_CRED(inmp)) != NULL &&
	    crgetlabel(cr) != NULL) {
		int err, adjust;

		if (isv4)
			err = tsol_check_label(cr, &hmp, &adjust,
			    connp->conn_mac_exempt);
		else
			err = tsol_check_label_v6(cr, &hmp, &adjust,
			    connp->conn_mac_exempt);
		if (err != 0) {
			freemsg(hmp);
			return;
		}
		if (isv4) {
			ahiph = (ipha_t *)hmp->b_rptr;
			adjust += ntohs(ahiph->ipha_length);
			ahiph->ipha_length = htons(adjust);
		}
	}

	/* Stash the conn ptr info. for IP */
	SCTP_STASH_IPINFO(hmp, NULL);

	CONN_INC_REF(connp);
	hmp->b_flag |= MSGHASREF;
	IP_PUT(hmp, connp, sctp->sctp_current == NULL ? B_TRUE :
	    sctp->sctp_current->isv4);
	/*
	 * Let's just mark the IRE for this destination as temporary
	 * to prevent any DoS attack.
	 */
	tsl = cr == NULL ? NULL : crgetlabel(cr);
	if (isv4)
		ire = ire_cache_lookup(iniph->ipha_src, sctp->sctp_zoneid, tsl);
	else
		ire = ire_cache_lookup_v6(&inip6h->ip6_src, sctp->sctp_zoneid,
		    tsl);
	/*
	 * In the normal case the ire would be non-null, however it could be
	 * null, say, if IP needs to resolve the gateway for this address. We
	 * only care about IRE_CACHE.
	 */
	if (ire == NULL)
		return;
	if (ire->ire_type != IRE_CACHE) {
		ire_refrele(ire);
		return;
	}
	irb = ire->ire_bucket;
	/* ire_lock is not needed, as ire_marks is protected by irb_lock */
	rw_enter(&irb->irb_lock, RW_WRITER);
	/*
	 * Only increment the temporary IRE count if the original
	 * IRE is not already marked temporary.
	 */
	if (!(ire->ire_marks & IRE_MARK_TEMPORARY)) {
		irb->irb_tmp_ire_cnt++;
		ire->ire_marks |= IRE_MARK_TEMPORARY;
	}
	rw_exit(&irb->irb_lock);
	ire_refrele(ire);
}

/*ARGSUSED*/
mblk_t *
sctp_make_err(sctp_t *sctp, uint16_t serror, void *details, size_t len)
{

	mblk_t *emp;
	size_t elen;
	sctp_chunk_hdr_t *ecp;
	sctp_parm_hdr_t *eph;
	int pad;

	if ((pad = len % 4) != 0) {
		pad = 4 - pad;
	}

	elen = sizeof (*ecp) + sizeof (*eph) + len;
	emp = allocb(elen + pad, BPRI_MED);
	if (emp == NULL) {
		return (NULL);
	}

	emp->b_wptr = emp->b_rptr + elen + pad;

	/* Chunk header */
	ecp = (sctp_chunk_hdr_t *)emp->b_rptr;
	ecp->sch_id = CHUNK_ERROR;
	ecp->sch_flags = 0;
	ecp->sch_len = htons(elen);

	eph = (sctp_parm_hdr_t *)(ecp + 1);
	eph->sph_type = htons(serror);
	eph->sph_len = htons(len + sizeof (*eph));

	if (len > 0) {
		bcopy(details, eph + 1, len);
	}

	if (pad != 0) {
		bzero((uchar_t *)(eph + 1) + len, pad);
	}

	return (emp);
}

void
sctp_send_err(sctp_t *sctp, mblk_t *emp, sctp_faddr_t *dest)
{
	mblk_t	*sendmp;

	sendmp = sctp_make_sack(sctp, dest, NULL);
	if (sendmp != NULL) {
		linkb(sendmp, emp);
	} else {
		sendmp = sctp_make_mp(sctp, dest, 0);
		if (sendmp == NULL) {
			freemsg(emp);
			return;
		}
		sendmp->b_cont = emp;
	}
	BUMP_LOCAL(sctp->sctp_obchunks);

	sctp_set_iplen(sctp, sendmp);
	sctp_add_sendq(sctp, sendmp);
}

/*
 * Returns 0 on non-fatal error, otherwise a system error on fatal
 * error.
 */
int
sctp_handle_error(sctp_t *sctp, sctp_hdr_t *sctph, sctp_chunk_hdr_t *ch,
    mblk_t *mp)
{
	sctp_parm_hdr_t *errh;
	sctp_chunk_hdr_t *uch;

	if (ch->sch_len == htons(sizeof (*ch))) {
		/* no error cause given */
		return (0);
	}
	errh = (sctp_parm_hdr_t *)(ch + 1);
	sctp_error_event(sctp, ch);

	switch (errh->sph_type) {
	/*
	 * Both BAD_SID and NO_USR_DATA errors
	 * indicate a serious bug in our stack,
	 * so complain and abort the association.
	 */
	case SCTP_ERR_BAD_SID:
		cmn_err(CE_WARN, "BUG! send to invalid SID");
		sctp_send_abort(sctp, sctph->sh_verf, 0, NULL, 0, mp, 0, 0);
		return (ECONNABORTED);
	case SCTP_ERR_NO_USR_DATA:
		cmn_err(CE_WARN, "BUG! no usr data");
		sctp_send_abort(sctp, sctph->sh_verf, 0, NULL, 0, mp, 0, 0);
		return (ECONNABORTED);
	case SCTP_ERR_UNREC_CHUNK:
		/* Pull out the unrecognized chunk type */
		if (ntohs(errh->sph_len) < (sizeof (*errh) + sizeof (*uch))) {
			/* Not enough to process */
			return (0);
		}
		uch = (sctp_chunk_hdr_t *)(errh + 1);
		if (uch->sch_id == CHUNK_ASCONF) {
			/* Turn on ASCONF sending */
			sctp->sctp_understands_asconf = B_FALSE;
			/*
			 * Hand off to asconf to clear out the unacked
			 * asconf chunk.
			 */
			if (ntohs(uch->sch_len) !=
			    (ntohs(errh->sph_len) - sizeof (*errh))) {
				/* malformed */
				dprint(0, ("Malformed Unrec Chunk error\n"));
				return (0);
			}
			sctp_asconf_free_cxmit(sctp, uch);
			return (0);
		}
		/* Else drop it */
		break;
	default:
		break;
	}

	return (0);
}
