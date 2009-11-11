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

#include <sys/types.h>
#include <sys/systm.h>
#include <sys/stream.h>
#include <sys/cmn_err.h>
#include <sys/ddi.h>
#include <sys/strsubr.h>
#include <sys/tsol/tnet.h>

#include <netinet/in.h>
#include <netinet/ip6.h>

#include <inet/ipsec_impl.h>
#include <inet/common.h>
#include <inet/ip.h>
#include <inet/ip6.h>
#include <inet/ipsec_impl.h>
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
sctp_user_abort(sctp_t *sctp, mblk_t *data)
{
	mblk_t *mp;
	int len, hdrlen;
	char *cause;
	sctp_faddr_t *fp = sctp->sctp_current;
	ip_xmit_attr_t	*ixa = fp->ixa;
	sctp_stack_t	*sctps = sctp->sctp_sctps;

	/*
	 * Don't need notification if connection is not yet setup,
	 * call sctp_clean_death() to reclaim resources.
	 * Any pending connect call(s) will error out.
	 */
	if (sctp->sctp_state < SCTPS_COOKIE_WAIT) {
		sctp_clean_death(sctp, ECONNABORTED);
		return;
	}

	mp = sctp_make_mp(sctp, fp, 0);
	if (mp == NULL) {
		SCTP_KSTAT(sctps, sctp_send_user_abort_failed);
		return;
	}

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
	/*
	 * Since it is a user abort, we should have the sctp_t and hence
	 * the correct verification tag.  So we should not set the T-bit
	 * in the ABORT.
	 */
	if ((len = sctp_link_abort(mp, SCTP_ERR_USER_ABORT, cause, len, 0,
	    B_FALSE)) < 0) {
		freemsg(mp);
		return;
	}
	BUMP_MIB(&sctps->sctps_mib, sctpAborted);
	BUMP_LOCAL(sctp->sctp_opkts);
	BUMP_LOCAL(sctp->sctp_obchunks);

	sctp_set_iplen(sctp, mp, ixa);
	ASSERT(ixa->ixa_ire != NULL);
	ASSERT(ixa->ixa_cred != NULL);

	(void) conn_ip_output(mp, ixa);

	sctp_assoc_event(sctp, SCTP_COMM_LOST, 0, NULL);
	sctp_clean_death(sctp, ECONNABORTED);
}

/*
 * If iserror == 0, sends an abort. If iserror != 0, sends an error.
 */
void
sctp_send_abort(sctp_t *sctp, uint32_t vtag, uint16_t serror, char *details,
    size_t len, mblk_t *inmp, int iserror, boolean_t tbit, ip_recv_attr_t *ira)
{

	mblk_t		*hmp;
	uint32_t	ip_hdr_len;
	ipha_t		*iniph;
	ipha_t		*ahiph = NULL;
	ip6_t		*inip6h;
	ip6_t		*ahip6h = NULL;
	sctp_hdr_t	*sh;
	sctp_hdr_t	*insh;
	size_t		ahlen;
	uchar_t		*p;
	ssize_t		alen;
	int		isv4;
	conn_t		*connp = sctp->sctp_connp;
	sctp_stack_t	*sctps = sctp->sctp_sctps;
	ip_xmit_attr_t	*ixa;

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
	if (is_system_labeled() && !tsol_can_reply_error(inmp, ira))
		return;

	hmp = allocb(sctps->sctps_wroff_xtra + ahlen, BPRI_MED);
	if (hmp == NULL) {
		/* XXX no resources */
		return;
	}

	/* copy in the IP / SCTP header */
	p = hmp->b_rptr + sctps->sctps_wroff_xtra;
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
		ip_hdr_len = ip_hdr_length_v6(inmp, inip6h);

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

	/*
	 * Base the transmission on any routing-related socket options
	 * that have been set on the listener/connection.
	 */
	ixa = conn_get_ixa_exclusive(connp);
	if (ixa == NULL) {
		freemsg(hmp);
		return;
	}
	ixa->ixa_flags &= ~IXAF_VERIFY_PMTU;

	ixa->ixa_pktlen = ahlen + alen;
	if (isv4) {
		ixa->ixa_flags |= IXAF_IS_IPV4;
		ahiph->ipha_length = htons(ixa->ixa_pktlen);
		ixa->ixa_ip_hdr_length = sctp->sctp_ip_hdr_len;
	} else {
		ixa->ixa_flags &= ~IXAF_IS_IPV4;
		ahip6h->ip6_plen = htons(ixa->ixa_pktlen - IPV6_HDR_LEN);
		ixa->ixa_ip_hdr_length = sctp->sctp_ip_hdr6_len;
	}

	BUMP_MIB(&sctps->sctps_mib, sctpAborted);
	BUMP_LOCAL(sctp->sctp_obchunks);

	if (is_system_labeled() && ixa->ixa_tsl != NULL) {
		ASSERT(ira->ira_tsl != NULL);

		ixa->ixa_tsl = ira->ira_tsl;	/* A multi-level responder */
	}

	if (ira->ira_flags & IRAF_IPSEC_SECURE) {
		/*
		 * Apply IPsec based on how IPsec was applied to
		 * the packet that caused the abort.
		 */
		if (!ipsec_in_to_out(ira, ixa, hmp, ahiph, ahip6h)) {
			ip_stack_t *ipst = sctps->sctps_netstack->netstack_ip;

			BUMP_MIB(&ipst->ips_ip_mib, ipIfStatsOutDiscards);
			/* Note: mp already consumed and ip_drop_packet done */
			ixa_refrele(ixa);
			return;
		}
	} else {
		ixa->ixa_flags |= IXAF_NO_IPSEC;
	}

	BUMP_LOCAL(sctp->sctp_opkts);
	BUMP_LOCAL(sctp->sctp_obchunks);

	(void) ip_output_simple(hmp, ixa);
	ixa_refrele(ixa);
}

/*
 * OOTB version of the above.
 * If iserror == 0, sends an abort. If iserror != 0, sends an error.
 */
void
sctp_ootb_send_abort(uint32_t vtag, uint16_t serror, char *details,
    size_t len, const mblk_t *inmp, int iserror, boolean_t tbit,
    ip_recv_attr_t *ira, ip_stack_t *ipst)
{
	uint32_t	ip_hdr_len;
	size_t		ahlen;
	ipha_t		*ipha = NULL;
	ip6_t		*ip6h = NULL;
	sctp_hdr_t	*insctph;
	int		i;
	uint16_t	port;
	ssize_t		alen;
	int		isv4;
	mblk_t		*mp;
	netstack_t	*ns = ipst->ips_netstack;
	sctp_stack_t	*sctps = ns->netstack_sctp;
	ip_xmit_attr_t	ixas;

	bzero(&ixas, sizeof (ixas));

	isv4 = (IPH_HDR_VERSION(inmp->b_rptr) == IPV4_VERSION);
	ip_hdr_len = ira->ira_ip_hdr_length;
	ahlen = ip_hdr_len + sizeof (sctp_hdr_t);

	/*
	 * If this is a labeled system, then check to see if we're allowed to
	 * send a response to this particular sender.  If not, then just drop.
	 */
	if (is_system_labeled() && !tsol_can_reply_error(inmp, ira))
		return;

	mp = allocb(ahlen + sctps->sctps_wroff_xtra, BPRI_MED);
	if (mp == NULL) {
		return;
	}
	mp->b_rptr += sctps->sctps_wroff_xtra;
	mp->b_wptr = mp->b_rptr + ahlen;
	bcopy(inmp->b_rptr, mp->b_rptr, ahlen);

	/*
	 * We follow the logic in tcp_xmit_early_reset() in that we skip
	 * reversing source route (i.e. replace all IP options with EOL).
	 */
	if (isv4) {
		ipaddr_t	v4addr;

		ipha = (ipha_t *)mp->b_rptr;
		for (i = IP_SIMPLE_HDR_LENGTH; i < (int)ip_hdr_len; i++)
			mp->b_rptr[i] = IPOPT_EOL;
		/* Swap addresses */
		ipha->ipha_length = htons(ahlen);
		v4addr = ipha->ipha_src;
		ipha->ipha_src = ipha->ipha_dst;
		ipha->ipha_dst = v4addr;
		ipha->ipha_ident = 0;
		ipha->ipha_ttl = (uchar_t)sctps->sctps_ipv4_ttl;

		ixas.ixa_flags = IXAF_BASIC_SIMPLE_V4;
	} else {
		in6_addr_t	v6addr;

		ip6h = (ip6_t *)mp->b_rptr;
		/* Remove any extension headers assuming partial overlay */
		if (ip_hdr_len > IPV6_HDR_LEN) {
			uint8_t	*to;

			to = mp->b_rptr + ip_hdr_len - IPV6_HDR_LEN;
			ovbcopy(ip6h, to, IPV6_HDR_LEN);
			mp->b_rptr += ip_hdr_len - IPV6_HDR_LEN;
			ip_hdr_len = IPV6_HDR_LEN;
			ip6h = (ip6_t *)mp->b_rptr;
			ip6h->ip6_nxt = IPPROTO_SCTP;
			ahlen = ip_hdr_len + sizeof (sctp_hdr_t);
		}
		ip6h->ip6_plen = htons(ahlen - IPV6_HDR_LEN);
		v6addr = ip6h->ip6_src;
		ip6h->ip6_src = ip6h->ip6_dst;
		ip6h->ip6_dst = v6addr;
		ip6h->ip6_hops = (uchar_t)sctps->sctps_ipv6_hoplimit;

		ixas.ixa_flags = IXAF_BASIC_SIMPLE_V6;
		if (IN6_IS_ADDR_LINKSCOPE(&ip6h->ip6_dst)) {
			ixas.ixa_flags |= IXAF_SCOPEID_SET;
			ixas.ixa_scopeid = ira->ira_ruifindex;
		}
	}
	insctph = (sctp_hdr_t *)(mp->b_rptr + ip_hdr_len);

	/* Swap ports.  Verification tag is reused. */
	port = insctph->sh_sport;
	insctph->sh_sport = insctph->sh_dport;
	insctph->sh_dport = port;
	insctph->sh_verf = vtag;

	/* Link in the abort chunk */
	if ((alen = sctp_link_abort(mp, serror, details, len, iserror, tbit))
	    < 0) {
		freemsg(mp);
		return;
	}

	ixas.ixa_pktlen = ahlen + alen;
	ixas.ixa_ip_hdr_length = ip_hdr_len;

	if (isv4) {
		ipha->ipha_length = htons(ixas.ixa_pktlen);
	} else {
		ip6h->ip6_plen = htons(ixas.ixa_pktlen - IPV6_HDR_LEN);
	}

	ixas.ixa_protocol = IPPROTO_SCTP;
	ixas.ixa_zoneid = ira->ira_zoneid;
	ixas.ixa_ipst = ipst;
	ixas.ixa_ifindex = 0;

	BUMP_MIB(&sctps->sctps_mib, sctpAborted);

	if (is_system_labeled()) {
		ASSERT(ira->ira_tsl != NULL);

		ixas.ixa_tsl = ira->ira_tsl;	/* A multi-level responder */
	}

	if (ira->ira_flags & IRAF_IPSEC_SECURE) {
		/*
		 * Apply IPsec based on how IPsec was applied to
		 * the packet that was out of the blue.
		 */
		if (!ipsec_in_to_out(ira, &ixas, mp, ipha, ip6h)) {
			BUMP_MIB(&ipst->ips_ip_mib, ipIfStatsOutDiscards);
			/* Note: mp already consumed and ip_drop_packet done */
			return;
		}
	} else {
		/*
		 * This is in clear. The abort message we are building
		 * here should go out in clear, independent of our policy.
		 */
		ixas.ixa_flags |= IXAF_NO_IPSEC;
	}

	(void) ip_output_simple(mp, &ixas);
	ixa_cleanup(&ixas);
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

	if ((pad = len % SCTP_ALIGN) != 0) {
		pad = SCTP_ALIGN - pad;
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

/*
 * Called from sctp_input_data() to add one error chunk to the error
 * chunks list.  The error chunks list will be processed at the end
 * of sctp_input_data() by calling sctp_process_err().
 */
void
sctp_add_err(sctp_t *sctp, uint16_t serror, void *details, size_t len,
    sctp_faddr_t *dest)
{
	sctp_stack_t *sctps = sctp->sctp_sctps;
	mblk_t *emp;
	uint32_t emp_len;
	uint32_t mss;
	mblk_t *sendmp;
	sctp_faddr_t *fp;

	emp = sctp_make_err(sctp, serror, details, len);
	if (emp == NULL)
		return;
	emp_len = MBLKL(emp);
	if (sctp->sctp_err_chunks != NULL) {
		fp = SCTP_CHUNK_DEST(sctp->sctp_err_chunks);
	} else {
		fp = dest;
		SCTP_SET_CHUNK_DEST(emp, dest);
	}
	mss = fp->sfa_pmss;

	/*
	 * If the current output packet cannot include the new error chunk,
	 * send out the current packet and then add the new error chunk
	 * to the new output packet.
	 */
	if (sctp->sctp_err_len + emp_len > mss) {
		if ((sendmp = sctp_make_mp(sctp, fp, 0)) == NULL) {
			SCTP_KSTAT(sctps, sctp_send_err_failed);
			/* Just free the latest error chunk. */
			freeb(emp);
			return;
		}
		sendmp->b_cont = sctp->sctp_err_chunks;
		sctp_set_iplen(sctp, sendmp, fp->ixa);
		(void) conn_ip_output(sendmp, fp->ixa);
		BUMP_LOCAL(sctp->sctp_opkts);

		sctp->sctp_err_chunks = emp;
		sctp->sctp_err_len = emp_len;
		SCTP_SET_CHUNK_DEST(emp, dest);
	} else {
		if (sctp->sctp_err_chunks != NULL)
			linkb(sctp->sctp_err_chunks, emp);
		else
			sctp->sctp_err_chunks = emp;
		sctp->sctp_err_len += emp_len;
	}
	/* Assume that we will send it out... */
	BUMP_LOCAL(sctp->sctp_obchunks);
}

/*
 * Called from sctp_input_data() to send out error chunks created during
 * the processing of all the chunks in an incoming packet.
 */
void
sctp_process_err(sctp_t *sctp)
{
	sctp_stack_t *sctps = sctp->sctp_sctps;
	mblk_t *errmp;
	mblk_t *sendmp;
	sctp_faddr_t *fp;

	ASSERT(sctp->sctp_err_chunks != NULL);
	errmp = sctp->sctp_err_chunks;
	fp = SCTP_CHUNK_DEST(errmp);
	if ((sendmp = sctp_make_mp(sctp, fp, 0)) == NULL) {
		SCTP_KSTAT(sctps, sctp_send_err_failed);
		freemsg(errmp);
		goto done;
	}
	sendmp->b_cont = errmp;
	sctp_set_iplen(sctp, sendmp, fp->ixa);
	(void) conn_ip_output(sendmp, fp->ixa);
	BUMP_LOCAL(sctp->sctp_opkts);
done:
	sctp->sctp_err_chunks = NULL;
	sctp->sctp_err_len = 0;
}

/*
 * Returns 0 on non-fatal error, otherwise a system error on fatal
 * error.
 */
int
sctp_handle_error(sctp_t *sctp, sctp_hdr_t *sctph, sctp_chunk_hdr_t *ch,
    mblk_t *mp, ip_recv_attr_t *ira)
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
		sctp_send_abort(sctp, sctph->sh_verf, 0, NULL, 0, mp, 0, 0,
		    ira);
		return (ECONNABORTED);
	case SCTP_ERR_NO_USR_DATA:
		cmn_err(CE_WARN, "BUG! no usr data");
		sctp_send_abort(sctp, sctph->sh_verf, 0, NULL, 0, mp, 0, 0,
		    ira);
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
