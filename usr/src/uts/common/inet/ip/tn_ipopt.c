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
#include <sys/systm.h>
#include <sys/kmem.h>
#include <sys/disp.h>
#include <sys/stream.h>
#include <sys/strsubr.h>
#include <sys/strsun.h>
#include <sys/policy.h>
#include <sys/tsol/label_macro.h>
#include <sys/tsol/tndb.h>
#include <sys/tsol/tnet.h>
#include <inet/ip.h>
#include <inet/ip6.h>
#include <inet/tcp.h>
#include <inet/ipclassifier.h>
#include <inet/ip_ire.h>
#include <inet/ip_ftable.h>

/*
 * This routine takes a sensitivity label as input and creates a CIPSO
 * option in the specified buffer.  It returns the size of the CIPSO option.
 * If the sensitivity label is too large for the CIPSO option, then 0
 * is returned.
 *
 * tsol2cipso_tt1 returns 0 for failure and greater than 0 for success
 * (more accurately, success means a return value between 10 and 40).
 */

static int
tsol2cipso_tt1(const bslabel_t *sl, unsigned char *cop, uint32_t doi)
{
	struct cipso_tag_type_1 *tt1;
	const _bslabel_impl_t *bsl;
	const uchar_t *ucp;
	int i;

	if (doi == 0)
		return (0);

	/* check for Admin High sensitivity label */
	if (blequal(sl, label2bslabel(l_admin_high)))
		return (0);

	/* check whether classification will fit in one octet */
	bsl = (const _bslabel_impl_t *)sl;
	if (LCLASS(bsl) & 0xFF00)
		return (0);

	/*
	 * Check whether compartments will fit in 30 octets.
	 * Compartments 241 - 256 are not allowed.
	 */
	if (ntohl(bsl->compartments.c8) & 0x0000FFFF)
		return (0);

	/*
	 * Compute option length and tag length.
	 * 'p' points to the last two bytes in the Sensitivity Label's
	 * compartments; these cannot be mapped into CIPSO compartments.
	 */
	ucp = (const uchar_t *)&bsl->compartments.c8 + 2;
	while (--ucp >= (const uchar_t *)&bsl->compartments.c1)
		if (*ucp != 0)
			break;

	i =  ucp - (const uchar_t *)&bsl->compartments.c1 + 1;

	if (cop == NULL)
		return (10 + i);

	doi = htonl(doi);
	ucp = (const uchar_t *)&doi;
	cop[IPOPT_OPTVAL] = IPOPT_COMSEC;
	cop[IPOPT_OLEN] = 10 + i;
	cop[IPOPT_OLEN+1] = ucp[0];
	cop[IPOPT_OLEN+2] = ucp[1];
	cop[IPOPT_OLEN+3] = ucp[2];
	cop[IPOPT_OLEN+4] = ucp[3];
	tt1 = (struct cipso_tag_type_1 *)&cop[IPOPT_OLEN + 5];
	tt1->tag_type = 1;
	tt1->tag_align = 0;
	tt1->tag_sl = LCLASS(bsl);
	tt1->tag_length = 4 + i;

	bcopy(&bsl->compartments.c1, tt1->tag_cat, i);

	return (cop[IPOPT_OLEN]);
}

/*
 * The following routine copies a datagram's option into the specified buffer
 * (if buffer pointer is non-null), or returns a pointer to the label within
 * the streams message (if buffer is null).  In both cases, tsol_get_option
 * returns the option's type.
 *
 * tsol_get_option assumes that the specified buffer is large enough to
 * hold the largest valid CIPSO option.  Since the total number of
 * IP header options cannot exceed 40 bytes, a 40 byte buffer is a good choice.
 */

tsol_ip_label_t
tsol_get_option(mblk_t *mp, uchar_t **buffer)
{
	ipha_t	*ipha;
	uchar_t	*opt;
	uint32_t	totallen;
	uint32_t	optval;
	uint32_t	optlen;

	ipha = (ipha_t *)mp->b_rptr;

	/*
	 * Get length (in 4 byte octets) of IP header options.
	 * If header doesn't contain options, then return OPT_NONE.
	 */
	totallen = ipha->ipha_version_and_hdr_length -
	    (uint8_t)((IP_VERSION << 4) + IP_SIMPLE_HDR_LENGTH_IN_WORDS);

	if (totallen == 0)
		return (OPT_NONE);

	totallen <<= 2;

	/*
	 * Search for CIPSO option.
	 * If no such option is present, then return OPT_NONE.
	 */
	opt = (uchar_t *)&ipha[1];
	while (totallen != 0) {
		switch (optval = opt[IPOPT_OPTVAL]) {
		case IPOPT_EOL:
			return (OPT_NONE);
		case IPOPT_NOP:
			optlen = 1;
			break;
		default:
			if (totallen <= IPOPT_OLEN)
				return (OPT_NONE);
			optlen = opt[IPOPT_OLEN];
			if (optlen < 2)
				return (OPT_NONE);
		}
		if (optlen > totallen)
			return (OPT_NONE);
		/*
		 * Copy pointer to option into '*buffer' and
		 * return the option type.
		 */
		switch (optval) {
		case IPOPT_COMSEC:
			*buffer = opt;
			if (TSOL_CIPSO_TAG_OFFSET < optlen &&
			    opt[TSOL_CIPSO_TAG_OFFSET] == 1)
				return (OPT_CIPSO);
			return (OPT_NONE);
		}
		totallen -= optlen;
		opt += optlen;
	}
	return (OPT_NONE);
}

/*
 * tsol_compute_label()
 *
 * This routine computes the IP label that should be on a packet based on the
 * connection and destination information.
 *
 * Returns:
 *      0		Fetched label
 *      EACCES		The packet failed the remote host accreditation
 *      ENOMEM		Memory allocation failure
 *	EINVAL		Label cannot be computed
 */
int
tsol_compute_label(const cred_t *credp, ipaddr_t dst, uchar_t *opt_storage,
    boolean_t isexempt, ip_stack_t *ipst)
{
	uint_t		sec_opt_len;
	ts_label_t	*tsl;
	tsol_tpc_t	*dst_rhtp;
	ire_t		*ire, *sire = NULL;
	boolean_t	compute_label = B_FALSE;
	tsol_ire_gw_secattr_t *attrp;
	zoneid_t	zoneid, ip_zoneid;

	if (opt_storage != NULL)
		opt_storage[IPOPT_OLEN] = 0;

	if ((tsl = crgetlabel(credp)) == NULL)
		return (0);

	/* always pass multicast */
	if (CLASSD(dst))
		return (0);

	if ((dst_rhtp = find_tpc(&dst, IPV4_VERSION, B_FALSE)) == NULL) {
		DTRACE_PROBE3(tx__tnopt__log__info__labeling__lookupdst__v4,
		    char *, "destination ip(1) not in database (with creds(2))",
		    ipaddr_t, dst, cred_t *, credp);
		return (EINVAL);
	}

	zoneid = crgetzoneid(credp);

	/*
	 * For exclusive stacks we set the zoneid to zero
	 * to operate as if in the global zone for IRE and conn_t comparisons.
	 */
	if (ipst->ips_netstack->netstack_stackid != GLOBAL_NETSTACKID)
		ip_zoneid = GLOBAL_ZONEID;
	else
		ip_zoneid = zoneid;

	switch (dst_rhtp->tpc_tp.host_type) {
	case UNLABELED:
		/*
		 * Only add a label if the unlabeled destination is
		 * not broadcast/local/loopback address, that it is
		 * not on the same subnet, and that the next-hop
		 * gateway is labeled.
		 */
		ire = ire_cache_lookup(dst, ip_zoneid, tsl, ipst);

		if (ire != NULL && (ire->ire_type & (IRE_BROADCAST | IRE_LOCAL |
		    IRE_LOOPBACK | IRE_INTERFACE)) != 0) {
			IRE_REFRELE(ire);
			TPC_RELE(dst_rhtp);
			return (0);
		} else if (ire == NULL) {
			ire = ire_ftable_lookup(dst, 0, 0, 0, NULL, &sire,
			    ip_zoneid, 0, tsl, (MATCH_IRE_RECURSIVE |
			    MATCH_IRE_DEFAULT | MATCH_IRE_SECATTR), ipst);
		}

		/* no route to destination */
		if (ire == NULL) {
			DTRACE_PROBE4(
			    tx__tnopt__log__info__labeling__routedst__v4,
			    char *, "No route to unlabeled dest ip(1)/tpc(2) "
			    "with creds(3).", ipaddr_t, dst, tsol_tpc_t *,
			    dst_rhtp, cred_t *, credp);
			TPC_RELE(dst_rhtp);
			return (EINVAL);
		}

		/*
		 * Prefix IRE from f-table lookup means that the destination
		 * is not directly connected; check the next-hop attributes.
		 */
		if (sire != NULL) {
			ASSERT(ire != NULL);
			IRE_REFRELE(ire);
			ire = sire;
		}

		attrp = ire->ire_gw_secattr;
		if (attrp != NULL && attrp->igsa_rhc != NULL &&
		    attrp->igsa_rhc->rhc_tpc->tpc_tp.host_type != UNLABELED)
			compute_label = B_TRUE;

		/*
		 * Can talk to unlabeled hosts if
		 * (1) zone's label matches the default label, or
		 * (2) SO_MAC_EXEMPT is on and we dominate the peer's label
		 * (3) SO_MAC_EXEMPT is on and this is the global zone
		 */
		if (dst_rhtp->tpc_tp.tp_doi != tsl->tsl_doi ||
		    (!blequal(&dst_rhtp->tpc_tp.tp_def_label,
		    &tsl->tsl_label) && (!isexempt ||
		    (zoneid != GLOBAL_ZONEID && !bldominates(&tsl->tsl_label,
		    &dst_rhtp->tpc_tp.tp_def_label))))) {
			DTRACE_PROBE4(tx__tnopt__log__info__labeling__mac__v4,
			    char *, "unlabeled dest ip(1)/tpc(2) "
			    "non-matching creds(3).", ipaddr_t, dst,
			    tsol_tpc_t *, dst_rhtp, cred_t *, credp);
			IRE_REFRELE(ire);
			TPC_RELE(dst_rhtp);
			return (EACCES);
		}

		IRE_REFRELE(ire);
		break;

	case SUN_CIPSO:
		/*
		 * Can talk to labeled hosts if zone's label is within target's
		 * label range or set.
		 */
		if (dst_rhtp->tpc_tp.tp_cipso_doi_cipso != tsl->tsl_doi ||
		    (!_blinrange(&tsl->tsl_label,
		    &dst_rhtp->tpc_tp.tp_sl_range_cipso) &&
		    !blinlset(&tsl->tsl_label,
		    dst_rhtp->tpc_tp.tp_sl_set_cipso))) {
			DTRACE_PROBE4(tx__tnopt__log__info__labeling__mac__v4,
			    char *, "labeled dest ip(1)/tpc(2) "
			    "non-matching creds(3).", ipaddr_t, dst,
			    tsol_tpc_t *, dst_rhtp, cred_t *, credp);
			TPC_RELE(dst_rhtp);
			return (EACCES);
		}
		compute_label = B_TRUE;
		break;

	default:
		TPC_RELE(dst_rhtp);
		return (EACCES);
	}

	if (!compute_label) {
		TPC_RELE(dst_rhtp);
		return (0);
	}

	/* compute the CIPSO option */
	if (dst_rhtp->tpc_tp.host_type != UNLABELED)
		sec_opt_len = tsol2cipso_tt1(&tsl->tsl_label, opt_storage,
		    tsl->tsl_doi);
	else
		sec_opt_len = tsol2cipso_tt1(&dst_rhtp->tpc_tp.tp_def_label,
		    opt_storage, tsl->tsl_doi);
	TPC_RELE(dst_rhtp);

	if (sec_opt_len == 0) {
		DTRACE_PROBE4(tx__tnopt__log__error__labeling__lostops__v4,
		    char *,
		    "options lack length for dest ip(1)/tpc(2) with creds(3).",
		    ipaddr_t, dst, tsol_tpc_t *, dst_rhtp, cred_t *, credp);
		return (EINVAL);
	}

	return (0);
}

/*
 * Remove any existing security option (CIPSO) from the given IP
 * header, move the 'buflen' bytes back to fill the gap, and return the number
 * of bytes removed (as zero or negative number).  Assumes that the headers are
 * sane.
 */
int
tsol_remove_secopt(ipha_t *ipha, int buflen)
{
	int remlen, olen, oval, delta;
	uchar_t *fptr, *tptr;
	boolean_t noop_keep;

	remlen = IPH_HDR_LENGTH(ipha) - IP_SIMPLE_HDR_LENGTH;
	fptr = tptr = (uchar_t *)(ipha + 1);
	noop_keep = B_TRUE;
	while (remlen > 0) {
		oval = fptr[IPOPT_OPTVAL];

		/* terminate on end of list */
		if (oval == IPOPT_EOL)
			break;

		/*
		 * Delete any no-ops following a deleted option, at least up
		 * to a 4 octet alignment; copy others.
		 */
		if (oval == IPOPT_NOP) {
			if (((fptr - (uchar_t *)ipha) & 3) == 0)
				noop_keep = B_TRUE;
			if (noop_keep)
				*tptr++ = oval;
			fptr++;
			remlen--;
			continue;
		}

		/* stop on corrupted list; just do nothing. */
		if (remlen < 2)
			return (0);
		olen = fptr[IPOPT_OLEN];
		if (olen < 2 || olen > remlen)
			return (0);

		/* skip over security options to delete them */
		if (oval == IPOPT_COMSEC || oval == IPOPT_SECURITY) {
			noop_keep = B_FALSE;
			fptr += olen;
			remlen -= olen;
			continue;
		}

		/* copy the rest */
		noop_keep = B_TRUE;
		if (tptr != fptr)
			ovbcopy(fptr, tptr, olen);
		fptr += olen;
		tptr += olen;
		remlen -= olen;
	}

	fptr += remlen;

	/* figure how much padding we'll need for header alignment */
	olen = (tptr - (uchar_t *)ipha) & 3;
	if (olen > 0) {
		olen = 4 - olen;
		/* pad with end-of-list */
		bzero(tptr, olen);
		tptr += olen;
	}

	/* slide back the headers that follow and update the IP header */
	delta = fptr - tptr;
	if (delta != 0) {
		ovbcopy(fptr, tptr, ((uchar_t *)ipha + buflen) - fptr);
		ipha->ipha_version_and_hdr_length -= delta / 4;
	}
	return (-delta);
}

/*
 * Insert the option in 'optbuf' into the IP header pointed to by 'ipha', and
 * move the data following the IP header (up to buflen) to accomodate the new
 * option.  Assumes that up to IP_MAX_OPT_LENGTH bytes are available (in total)
 * for IP options.  Returns the number of bytes actually inserted, or -1 if the
 * option cannot be inserted.  (Note that negative return values are possible
 * when noops must be compressed, and that only -1 indicates error.  Successful
 * return value is always evenly divisible by 4, by definition.)
 */
int
tsol_prepend_option(uchar_t *optbuf, ipha_t *ipha, int buflen)
{
	int remlen, padding, lastpad, totlen;
	int oval, olen;
	int delta;
	uchar_t *optr;
	uchar_t tempopt[IP_MAX_OPT_LENGTH], *toptr;

	if (optbuf[IPOPT_OPTVAL] == IPOPT_EOL ||
	    optbuf[IPOPT_OPTVAL] == IPOPT_NOP ||
	    optbuf[IPOPT_OLEN] == 0)
		return (0);

	ASSERT(optbuf[IPOPT_OLEN] >= 2 &&
	    optbuf[IPOPT_OLEN] <= IP_MAX_OPT_LENGTH);

	/* first find the real (unpadded) length of the existing options */
	remlen = IPH_HDR_LENGTH(ipha) - IP_SIMPLE_HDR_LENGTH;
	padding = totlen = lastpad = 0;
	optr = (uchar_t *)(ipha + 1);
	while (remlen > 0) {
		oval = optr[IPOPT_OPTVAL];

		/* stop at end of list */
		if (oval == IPOPT_EOL)
			break;

		/* skip no-ops, noting that length byte isn't present */
		if (oval == IPOPT_NOP) {
			optr++;
			padding++;
			lastpad++;
			totlen++;
			remlen--;
			continue;
		}

		/* give up on a corrupted list; report failure */
		if (remlen < 2)
			return (-1);
		olen = optr[IPOPT_OLEN];
		if (olen < 2 || olen > remlen)
			return (-1);

		lastpad = 0;
		optr += olen;
		totlen += olen;
		remlen -= olen;
	}

	/* completely ignore any trailing padding */
	totlen -= lastpad;
	padding -= lastpad;

	/*
	 * If some sort of inter-option alignment was present, try to preserve
	 * that alignment.  If alignment pushes us out past the maximum, then
	 * discard it and try to compress to fit.  (We just "assume" that any
	 * padding added was attempting to get 32 bit alignment.  If that's
	 * wrong, that's just too bad.)
	 */
	if (padding > 0) {
		olen = (optbuf[IPOPT_OLEN] + 3) & ~3;
		if (olen + totlen > IP_MAX_OPT_LENGTH) {
			totlen -= padding;
			if (olen + totlen > IP_MAX_OPT_LENGTH)
				return (-1);
			padding = 0;
		}
	}

	/*
	 * Since we may need to compress or expand the option list, we write to
	 * a temporary buffer and then copy the results back to the IP header.
	 */
	toptr = tempopt;

	/* compute actual option to insert */
	olen = optbuf[IPOPT_OLEN];
	bcopy(optbuf, toptr, olen);
	toptr += olen;
	if (padding > 0) {
		while ((olen & 3) != 0) {
			*toptr++ = IPOPT_NOP;
			olen++;
		}
	}

	/* copy over the existing options */
	optr = (uchar_t *)(ipha + 1);
	while (totlen > 0) {
		oval = optr[IPOPT_OPTVAL];

		/* totlen doesn't include end-of-list marker */
		ASSERT(oval != IPOPT_EOL);

		/* handle no-ops; copy if desired, ignore otherwise */
		if (oval == IPOPT_NOP) {
			if (padding > 0) {
				/* note: cannot overflow due to checks above */
				ASSERT(toptr < tempopt + IP_MAX_OPT_LENGTH);
				*toptr++ = oval;
			}
			optr++;
			totlen--;
			continue;
		}

		/* list cannot be corrupt at this point */
		ASSERT(totlen >= 2);
		olen = optr[IPOPT_OLEN];
		ASSERT(olen >= 2 && olen <= totlen);

		/* cannot run out of room due to tests above */
		ASSERT(toptr + olen <= tempopt + IP_MAX_OPT_LENGTH);

		bcopy(optr, toptr, olen);
		optr += olen;
		toptr += olen;
		totlen -= olen;
	}

	/* figure how much padding we'll need for header alignment */
	olen = (toptr - tempopt) & 3;
	if (olen > 0) {
		olen = 4 - olen;
		ASSERT(toptr + olen <= tempopt + IP_MAX_OPT_LENGTH);
		/* pad with end-of-list value */
		bzero(toptr, olen);
		toptr += olen;
	}

	/* move the headers as needed and update IP header */
	olen = (toptr - tempopt) + IP_SIMPLE_HDR_LENGTH;
	remlen = IPH_HDR_LENGTH(ipha);
	delta = olen - remlen;
	if (delta != 0) {
		ovbcopy((uchar_t *)ipha + remlen, (uchar_t *)ipha + olen,
		    buflen - remlen);
		ipha->ipha_version_and_hdr_length += delta / 4;
	}

	/* slap in the new options */
	bcopy(tempopt, ipha + 1, olen - IP_SIMPLE_HDR_LENGTH);

	return (delta);
}

/*
 * tsol_check_label()
 *
 * This routine computes the IP label that should be on the packet based on the
 * connection and destination information.  If the label is there, it returns
 * zero, so the caller knows that the label is syncronized, and further calls
 * are not required.  If the label isn't right, then the right one is inserted.
 *
 * The packet's header is clear before entering IPsec's engine.
 *
 * Returns:
 *      0		Label on packet (was|is now) correct
 *      EACCES		The packet failed the remote host accreditation.
 *      ENOMEM		Memory allocation failure.
 *	EINVAL		Label cannot be computed
 */
int
tsol_check_label(const cred_t *credp, mblk_t **mpp, boolean_t isexempt,
    ip_stack_t *ipst)
{
	mblk_t *mp = *mpp;
	ipha_t  *ipha;
	uchar_t opt_storage[IP_MAX_OPT_LENGTH];
	uint_t hlen;
	uint_t sec_opt_len;
	uchar_t *optr;
	int delta_remove = 0, delta_add, adjust;
	int retv;

	opt_storage[IPOPT_OPTVAL] = 0;

	ipha = (ipha_t *)mp->b_rptr;

	retv = tsol_compute_label(credp, ipha->ipha_dst, opt_storage, isexempt,
	    ipst);
	if (retv != 0)
		return (retv);

	optr = (uchar_t *)(ipha + 1);
	hlen = IPH_HDR_LENGTH(ipha) - IP_SIMPLE_HDR_LENGTH;
	sec_opt_len = opt_storage[IPOPT_OLEN];

	if (hlen >= sec_opt_len) {
		/* If no option is supposed to be there, make sure it's not */
		if (sec_opt_len == 0 && hlen > 0 &&
		    optr[IPOPT_OPTVAL] != IPOPT_COMSEC &&
		    optr[IPOPT_OPTVAL] != IPOPT_SECURITY)
			return (0);
		/* if the option is there, it's always first */
		if (sec_opt_len != 0 &&
		    bcmp(opt_storage, optr, sec_opt_len) == 0)
			return (0);
	}

	/*
	 * If there is an option there, then it must be the wrong one; delete.
	 */
	if (hlen > 0) {
		delta_remove = tsol_remove_secopt(ipha, MBLKL(mp));
		mp->b_wptr += delta_remove;
	}

	/* Make sure we have room for the worst-case addition */
	hlen = IPH_HDR_LENGTH(ipha) + opt_storage[IPOPT_OLEN];
	hlen = (hlen + 3) & ~3;
	if (hlen > IP_MAX_HDR_LENGTH)
		hlen = IP_MAX_HDR_LENGTH;
	hlen -= IPH_HDR_LENGTH(ipha);
	if (mp->b_wptr + hlen > mp->b_datap->db_lim) {
		int copylen;
		mblk_t *new_mp;

		/* allocate enough to be meaningful, but not *too* much */
		copylen = MBLKL(mp);
		if (copylen > 256)
			copylen = 256;
		new_mp = allocb_cred(hlen + copylen +
		    (mp->b_rptr - mp->b_datap->db_base), DB_CRED(mp));
		if (new_mp == NULL)
			return (ENOMEM);

		/* keep the bias */
		new_mp->b_rptr += mp->b_rptr - mp->b_datap->db_base;
		new_mp->b_wptr = new_mp->b_rptr + copylen;
		bcopy(mp->b_rptr, new_mp->b_rptr, copylen);
		new_mp->b_cont = mp;
		if ((mp->b_rptr += copylen) >= mp->b_wptr) {
			new_mp->b_cont = mp->b_cont;
			freeb(mp);
		}
		*mpp = mp = new_mp;
		ipha = (ipha_t *)mp->b_rptr;
	}

	delta_add = tsol_prepend_option(opt_storage, ipha, MBLKL(mp));
	if (delta_add == -1)
		goto param_prob;

	ASSERT((mp->b_wptr + delta_add) <= DB_LIM(mp));
	mp->b_wptr += delta_add;

	adjust = delta_remove + delta_add;
	adjust += ntohs(ipha->ipha_length);
	ipha->ipha_length = htons(adjust);

	return (0);

param_prob:
	return (EINVAL);
}

/*
 * IPv6 HopOpt extension header for the label option layout:
 *	- One octet giving the type of the 'next extension header'
 *	- Header extension length in 8-byte words, not including the
 *	  1st 8 bytes, but including any pad bytes at the end.
 *	  Eg. A value of 2 means 16 bytes not including the 1st 8 bytes.
 *	- Followed by TLV encoded IPv6 label option. Option layout is
 *		* One octet, IP6OPT_LS
 *		* One octet option length in bytes of the option data following
 *		  the length, but not including any pad bytes at the end.
 *		* Four-octet DOI (IP6LS_DOI_V4)
 *		* One octet suboption, IP6LS_TT_V4
 *		* One octet suboption length in bytes of the suboption
 *		  following the suboption length, including the suboption
 *		  header length, but not including any pad bytes at the end.
 *	- Pad to make the extension header a multiple of 8 bytes.
 *
 * This function returns the contents of 'IPv6 option structure' in the above.
 * i.e starting from the IP6OPT_LS but not including the pad at the end.
 * The user must prepend two octets (either padding or next header / length)
 * and append padding out to the next 8 octet boundary.
 */
int
tsol_compute_label_v6(const cred_t *credp, const in6_addr_t *dst,
    uchar_t *opt_storage, boolean_t isexempt, ip_stack_t *ipst)
{
	tsol_tpc_t	*dst_rhtp;
	ts_label_t	*tsl;
	uint_t		sec_opt_len;
	uint32_t	doi;
	zoneid_t	zoneid, ip_zoneid;
	ire_t		*ire, *sire;
	tsol_ire_gw_secattr_t *attrp;
	boolean_t	compute_label;

	if (ip6opt_ls == 0)
		return (EINVAL);

	if (opt_storage != NULL)
		opt_storage[IPOPT_OLEN] = 0;

	if ((tsl = crgetlabel(credp)) == NULL)
		return (0);

	/* Always pass multicast */
	if (IN6_IS_ADDR_MULTICAST(dst))
		return (0);

	if ((dst_rhtp = find_tpc(dst, IPV6_VERSION, B_FALSE)) == NULL) {
		DTRACE_PROBE3(tx__tnopt__log__info__labeling__lookupdst__v6,
		    char *, "destination ip6(1) not in database with creds(2)",
		    in6_addr_t *, dst, cred_t *, credp);
		return (EINVAL);
	}

	zoneid = crgetzoneid(credp);

	/*
	 * For exclusive stacks we set the zoneid to zero
	 * to operate as if in the global zone for IRE and conn_t comparisons.
	 */
	if (ipst->ips_netstack->netstack_stackid != GLOBAL_NETSTACKID)
		ip_zoneid = GLOBAL_ZONEID;
	else
		ip_zoneid = zoneid;

	/*
	 * Fill in a V6 label.  If a new format is added here, make certain
	 * that the maximum size of this label is reflected in sys/tsol/tnet.h
	 * as TSOL_MAX_IPV6_OPTION.
	 */
	compute_label = B_FALSE;
	switch (dst_rhtp->tpc_tp.host_type) {
	case UNLABELED:
		/*
		 * Only add a label if the unlabeled destination is
		 * not local or loopback address, that it is
		 * not on the same subnet, and that the next-hop
		 * gateway is labeled.
		 */
		sire = NULL;
		ire = ire_cache_lookup_v6(dst, ip_zoneid, tsl, ipst);

		if (ire != NULL && (ire->ire_type & (IRE_LOCAL |
		    IRE_LOOPBACK | IRE_INTERFACE)) != 0) {
			IRE_REFRELE(ire);
			TPC_RELE(dst_rhtp);
			return (0);
		} else if (ire == NULL) {
			ire = ire_ftable_lookup_v6(dst, NULL, NULL, 0, NULL,
			    &sire, ip_zoneid, 0, tsl, (MATCH_IRE_RECURSIVE |
			    MATCH_IRE_DEFAULT | MATCH_IRE_SECATTR), ipst);
		}

		/* no route to destination */
		if (ire == NULL) {
			DTRACE_PROBE4(
			    tx__tnopt__log__info__labeling__routedst__v6,
			    char *, "No route to unlabeled dest ip6(1)/tpc(2) "
			    "with creds(3).", in6_addr_t *, dst, tsol_tpc_t *,
			    dst_rhtp, cred_t *, credp);
			TPC_RELE(dst_rhtp);
			return (EINVAL);
		}

		/*
		 * Prefix IRE from f-table lookup means that the destination
		 * is not directly connected; check the next-hop attributes.
		 */
		if (sire != NULL) {
			ASSERT(ire != NULL);
			IRE_REFRELE(ire);
			ire = sire;
		}

		attrp = ire->ire_gw_secattr;
		if (attrp != NULL && attrp->igsa_rhc != NULL &&
		    attrp->igsa_rhc->rhc_tpc->tpc_tp.host_type != UNLABELED)
			compute_label = B_TRUE;

		if (dst_rhtp->tpc_tp.tp_doi != tsl->tsl_doi ||
		    (!blequal(&dst_rhtp->tpc_tp.tp_def_label,
		    &tsl->tsl_label) && (!isexempt ||
		    (zoneid != GLOBAL_ZONEID && !bldominates(&tsl->tsl_label,
		    &dst_rhtp->tpc_tp.tp_def_label))))) {
			DTRACE_PROBE4(tx__tnopt__log__info__labeling__mac__v6,
			    char *, "unlabeled dest ip6(1)/tpc(2) "
			    "non-matching creds(3)", in6_addr_t *, dst,
			    tsol_tpc_t *, dst_rhtp, cred_t *, credp);
			IRE_REFRELE(ire);
			TPC_RELE(dst_rhtp);
			return (EACCES);
		}

		IRE_REFRELE(ire);
		break;

	case SUN_CIPSO:
		if (dst_rhtp->tpc_tp.tp_cipso_doi_cipso != tsl->tsl_doi ||
		    (!_blinrange(&tsl->tsl_label,
		    &dst_rhtp->tpc_tp.tp_sl_range_cipso) &&
		    !blinlset(&tsl->tsl_label,
		    dst_rhtp->tpc_tp.tp_sl_set_cipso))) {
			DTRACE_PROBE4(tx__tnopt__log__info__labeling__mac__v6,
			    char *,
			    "labeled dest ip6(1)/tpc(2) non-matching creds(3).",
			    in6_addr_t *, dst, tsol_tpc_t *, dst_rhtp,
			    cred_t *, credp);
			TPC_RELE(dst_rhtp);
			return (EACCES);
		}
		compute_label = B_TRUE;
		break;

	default:
		TPC_RELE(dst_rhtp);
		return (EACCES);
	}

	if (!compute_label) {
		TPC_RELE(dst_rhtp);
		return (0);
	}

	/* compute the CIPSO option */
	if (opt_storage != NULL)
		opt_storage += 8;
	if (dst_rhtp->tpc_tp.host_type != UNLABELED) {
		sec_opt_len = tsol2cipso_tt1(&tsl->tsl_label, opt_storage,
		    tsl->tsl_doi);
	} else {
		sec_opt_len = tsol2cipso_tt1(&dst_rhtp->tpc_tp.tp_def_label,
		    opt_storage, tsl->tsl_doi);
	}
	TPC_RELE(dst_rhtp);

	if (sec_opt_len == 0) {
		DTRACE_PROBE4(tx__tnopt__log__error__labeling__lostops__v6,
		    char *,
		    "options lack length for dest ip6(1)/tpc(2) with creds(3).",
		    in6_addr_t *, dst, tsol_tpc_t *, dst_rhtp, cred_t *, credp);
		return (EINVAL);
	}

	if (opt_storage == NULL)
		return (0);

	if (sec_opt_len < IP_MAX_OPT_LENGTH)
		opt_storage[sec_opt_len] = IPOPT_EOL;

	/*
	 * Just in case the option length is odd, round it up to the next even
	 * multiple.  The IPv6 option definition doesn't like odd numbers for
	 * some reason.
	 *
	 * Length in the overall option header (IP6OPT_LS) does not include the
	 * option header itself, but the length in the suboption does include
	 * the suboption header.  Thus, when there's just one suboption, the
	 * length in the option header is the suboption length plus 4 (for the
	 * DOI value).
	 */
	opt_storage[-2] = IP6LS_TT_V4;
	opt_storage[-1] = (sec_opt_len + 2 + 1) & ~1;
	opt_storage[-8] = ip6opt_ls;
	opt_storage[-7] = opt_storage[-1] + 4;
	doi = htons(IP6LS_DOI_V4);
	bcopy(&doi, opt_storage - 6, 4);

	return (0);
}

/*
 * Locate the start of the IP6OPT_LS label option and return it.
 * Also return the start of the next non-pad option in after_secoptp.
 * Usually the label option is the first option at least when packets
 * are generated, but for generality we don't assume that on received packets.
 */
uchar_t *
tsol_find_secopt_v6(
    const uchar_t *ip6hbh,	/* Start of the hop-by-hop extension header */
    uint_t hbhlen,		/* Length of the hop-by-hop extension header */
    uchar_t **after_secoptp,	/* Non-pad option following the label option */
    boolean_t *hbh_needed)	/* Is hop-by-hop hdr needed w/o label */
{
	uint_t	optlen;
	uint_t	optused;
	const uchar_t *optptr;
	uchar_t	opt_type;
	const uchar_t *secopt = NULL;

	*hbh_needed = B_FALSE;
	*after_secoptp = NULL;
	optlen = hbhlen - 2;
	optptr = ip6hbh + 2;
	while (optlen != 0) {
		opt_type = *optptr;
		if (opt_type == IP6OPT_PAD1) {
			optptr++;
			optlen--;
			continue;
		}
		if (optlen == 1)
			break;
		optused = 2 + optptr[1];
		if (optused > optlen)
			break;
		/*
		 * if we get here, ip6opt_ls can
		 * not be 0 because it will always
		 * match the IP6OPT_PAD1 above.
		 * Therefore ip6opt_ls == 0 forces
		 * this test to always fail here.
		 */
		if (opt_type == ip6opt_ls)
			secopt = optptr;
		else switch (opt_type) {
		case IP6OPT_PADN:
			break;
		default:
			/*
			 * There is at least 1 option other than
			 * the label option. So the hop-by-hop header is needed
			 */
			*hbh_needed = B_TRUE;
			if (secopt != NULL) {
				*after_secoptp = (uchar_t *)optptr;
				return ((uchar_t *)secopt);
			}
			break;
		}
		optlen -= optused;
		optptr += optused;
	}
	return ((uchar_t *)secopt);
}

/*
 * Remove the label option from the hop-by-hop options header if it exists.
 * 'buflen' is the total length of the packet typically b_wptr - b_rptr.
 * Header and data following the label option that is deleted are copied
 * (i.e. slid backward) to the right position, and returns the number
 * of bytes removed (as zero or negative number.)
 */
int
tsol_remove_secopt_v6(ip6_t *ip6h, int buflen)
{
	uchar_t	*ip6hbh;	/* hop-by-hop header */
	uint_t	hbhlen;		/* hop-by-hop extension header length */
	uchar_t *secopt = NULL;
	uchar_t *after_secopt;
	uint_t	pad;
	uint_t	delta;
	boolean_t hbh_needed;

	/*
	 * hop-by-hop extension header must appear first, if it does not
	 * exist, there is no label option.
	 */
	if (ip6h->ip6_nxt != IPPROTO_HOPOPTS)
		return (0);

	ip6hbh = (uchar_t *)&ip6h[1];
	hbhlen = (ip6hbh[1] + 1) << 3;
	/*
	 * Locate the start of the label option if it exists and the end
	 * of the label option including pads if any.
	 */
	secopt = tsol_find_secopt_v6(ip6hbh, hbhlen, &after_secopt,
	    &hbh_needed);
	if (secopt == NULL)
		return (0);
	if (!hbh_needed) {
		uchar_t	next_hdr;
		/*
		 * The label option was the only option in the hop-by-hop
		 * header. We don't need the hop-by-hop header itself any
		 * longer.
		 */
		next_hdr = ip6hbh[0];
		ovbcopy(ip6hbh + hbhlen, ip6hbh,
		    buflen - (IPV6_HDR_LEN + hbhlen));
		ip6h->ip6_plen = htons(ntohs(ip6h->ip6_plen) - hbhlen);
		ip6h->ip6_nxt = next_hdr;
		return (-hbhlen);
	}

	if (after_secopt == NULL) {
		/* There is no option following the label option */
		after_secopt = ip6hbh + hbhlen;
	}

	/*
	 * After deleting the label option, we need to slide the headers
	 * and data back, while still maintaining the same alignment (module 8)
	 * for the other options. So we slide the headers and data back only
	 * by an integral multiple of 8 bytes, and fill the remaining bytes
	 * with pads.
	 */
	delta = after_secopt - secopt;
	pad = delta % 8;
	if (pad == 1) {
		secopt[0] = IP6OPT_PAD1;
	} else if (pad > 1) {
		secopt[0] = IP6OPT_PADN;
		secopt[1] = pad - 2;
		if (pad > 2)
			bzero(&secopt[2], pad - 2);
	}
	secopt += pad;
	delta -= pad;
	ovbcopy(after_secopt, secopt,
	    (uchar_t *)ip6h + buflen - after_secopt);
	ip6hbh[1] -= delta/8;
	ip6h->ip6_plen = htons(ntohs(ip6h->ip6_plen) - delta);

	return (-delta);
}

/*
 * 'optbuf' contains a CIPSO label embedded in an IPv6 hop-by-hop option,
 * starting with the IP6OPT_LS option type. The format of this hop-by-hop
 * option is described in the block comment above tsol_compute_label_v6.
 * This function prepends this hop-by-hop option before any other hop-by-hop
 * options in the hop-by-hop header if one already exists, else a new
 * hop-by-hop header is created and stuffed into the packet following
 * the IPv6 header. 'buflen' is the total length of the packet i.e.
 * b_wptr - b_rptr. The caller ensures that there is enough space for the
 * extra option being added. Header and data following the position where
 * the label option is inserted are copied (i.e. slid forward) to the right
 * position.
 */
int
tsol_prepend_option_v6(uchar_t *optbuf, ip6_t *ip6h, int buflen)
{
	/*
	 * rawlen is the length of the label option in bytes, not including
	 * any pads, starting from the IP6OPT_LS (option type) byte.
	 */
	uint_t	rawlen;

	uint_t	optlen;		/* rawlen rounded to an 8 byte multiple */
	uchar_t	*ip6hbh;	/* start of the hop-by-hop extension header */
	uint_t	hbhlen;		/* Length of the hop-by-hop extension header */
	uint_t	pad_len;
	uchar_t	*pad_position;
	int	delta;		/* Actual number of bytes inserted */

	rawlen = optbuf[1] + 2;	/* Add 2 for the option type, option length */
	ip6hbh = (uchar_t *)&ip6h[1];
	if (ip6h->ip6_nxt == IPPROTO_HOPOPTS) {
		/*
		 * There is a hop-by-hop header present already. In order to
		 * preserve the alignment of the other options at the existing
		 * value (modulo 8) we need to pad the label option to a
		 * multiple of 8 bytes before prepending it to the other
		 * options. Slide the extension headers and data forward to
		 * accomodate the label option at the start of the hop-by-hop
		 * header
		 */
		delta = optlen = (rawlen + 7) & ~7;
		pad_len = optlen - rawlen;
		pad_position = ip6hbh + 2 + rawlen;
		ovbcopy(ip6hbh + 2, ip6hbh + 2 + optlen,
		    buflen - (IPV6_HDR_LEN + 2));
		/*
		 * Bump up the hop-by-hop extension header length by
		 * the number of 8-byte words added
		 */
		optlen >>= 3;
		if (ip6hbh[1] + optlen > 255)
			return (-1);
		ip6hbh[1] += optlen;
	} else {
		/*
		 * There is no hop-by-hop header in the packet. Construct a
		 * new Hop-by-hop extension header (a multiple of 8 bytes).
		 * Slide any other extension headers and data forward to
		 * accomodate this hop-by-hop header
		 */
		delta = hbhlen = (2 + rawlen + 7) & ~7; /* +2 for nxthdr, len */
		pad_len = hbhlen - (2 + rawlen);
		pad_position = ip6hbh + 2 + rawlen;
		ovbcopy(ip6hbh, ip6hbh + hbhlen, buflen - IPV6_HDR_LEN);
		ip6hbh[0] = ip6h->ip6_nxt;
		/*
		 * hop-by-hop extension header length in 8-byte words, not
		 * including the 1st 8 bytes of the hop-by-hop header.
		 */
		ip6hbh[1] = (hbhlen >> 3) - 1;
		ip6h->ip6_nxt = IPPROTO_HOPOPTS;
	}
	/*
	 * Copy the label option into the hop-by-hop header and insert any
	 * needed pads
	 */
	bcopy(optbuf, ip6hbh + 2, rawlen);
	if (pad_len == 1) {
		pad_position[0] = IP6OPT_PAD1;
	} else if (pad_len > 1) {
		pad_position[0] = IP6OPT_PADN;
		pad_position[1] = pad_len - 2;
		if (pad_len > 2)
			bzero(pad_position + 2, pad_len - 2);
	}
	ip6h->ip6_plen = htons(ntohs(ip6h->ip6_plen) + delta);
	return (delta);
}

/*
 * tsol_check_label_v6()
 *
 * This routine computes the IP label that should be on the packet based on the
 * connection and destination information.  It's called only by the IP
 * forwarding logic, because all internal modules atop IP know how to generate
 * their own labels.
 *
 * Returns:
 *      0		Label on packet was already correct
 *      EACCESS		The packet failed the remote host accreditation.
 *      ENOMEM		Memory allocation failure.
 */
int
tsol_check_label_v6(const cred_t *credp, mblk_t **mpp, boolean_t isexempt,
    ip_stack_t *ipst)
{
	mblk_t *mp = *mpp;
	ip6_t  *ip6h;
	/*
	 * Label option length is limited to IP_MAX_OPT_LENGTH for
	 * symmetry with IPv4. Can be relaxed if needed
	 */
	uchar_t opt_storage[TSOL_MAX_IPV6_OPTION];
	uint_t hlen;
	uint_t sec_opt_len; /* label option length not including type, len */
	int delta_remove = 0, delta_add;
	int retv;
	uchar_t	*after_secopt;
	uchar_t	*secopt = NULL;
	uchar_t	*ip6hbh;
	uint_t	hbhlen;
	boolean_t hbh_needed;

	ip6h = (ip6_t *)mp->b_rptr;
	retv = tsol_compute_label_v6(credp, &ip6h->ip6_dst, opt_storage,
	    isexempt, ipst);
	if (retv != 0)
		return (retv);

	sec_opt_len = opt_storage[1];

	if (ip6h->ip6_nxt == IPPROTO_HOPOPTS) {
		ip6hbh = (uchar_t *)&ip6h[1];
		hbhlen = (ip6hbh[1] + 1) << 3;
		secopt = tsol_find_secopt_v6(ip6hbh, hbhlen, &after_secopt,
		    &hbh_needed);
	}

	if (sec_opt_len == 0 && secopt == NULL) {
		/*
		 * The packet is not supposed to have a label, and it
		 * does not have one currently
		 */
		return (0);
	}
	if (secopt != NULL && sec_opt_len != 0 &&
	    (bcmp(opt_storage, secopt, sec_opt_len + 2) == 0)) {
		/* The packet has the correct label already */
		return (0);
	}

	/*
	 * If there is an option there, then it must be the wrong one; delete.
	 */
	if (secopt != NULL) {
		delta_remove = tsol_remove_secopt_v6(ip6h, MBLKL(mp));
		mp->b_wptr += delta_remove;
	}

	/*
	 * Make sure we have room for the worst-case addition. Add 2 bytes for
	 * the hop-by-hop ext header's next header and length fields. Add
	 * another 2 bytes for the label option type, len and then round
	 * up to the next 8-byte multiple.
	 */
	hlen = (4 + sec_opt_len + 7) & ~7;
	if (mp->b_wptr + hlen > mp->b_datap->db_lim) {
		int copylen;
		mblk_t *new_mp;
		uint16_t hdr_len;

		hdr_len = ip_hdr_length_v6(mp, ip6h);
		/*
		 * Allocate enough to be meaningful, but not *too* much.
		 * Also all the IPv6 extension headers must be in the same mblk
		 */
		copylen = MBLKL(mp);
		if (copylen > 256)
			copylen = 256;
		if (copylen < hdr_len)
			copylen = hdr_len;
		new_mp = allocb_cred(hlen + copylen +
		    (mp->b_rptr - mp->b_datap->db_base), DB_CRED(mp));
		if (new_mp == NULL)
			return (ENOMEM);

		/* keep the bias */
		new_mp->b_rptr += mp->b_rptr - mp->b_datap->db_base;
		new_mp->b_wptr = new_mp->b_rptr + copylen;
		bcopy(mp->b_rptr, new_mp->b_rptr, copylen);
		new_mp->b_cont = mp;
		if ((mp->b_rptr += copylen) >= mp->b_wptr) {
			new_mp->b_cont = mp->b_cont;
			freeb(mp);
		}
		*mpp = mp = new_mp;
		ip6h = (ip6_t *)mp->b_rptr;
	}

	delta_add = tsol_prepend_option_v6(opt_storage, ip6h, MBLKL(mp));
	if (delta_add == -1)
		goto param_prob;

	ASSERT(mp->b_wptr + delta_add <= DB_LIM(mp));
	mp->b_wptr += delta_add;

	return (0);

param_prob:
	return (EINVAL);
}

/*
 * Update the given IPv6 "sticky options" structure to contain the provided
 * label, which is encoded as an IPv6 option.  Existing label is removed if
 * necessary, and storage is allocated/freed/resized.
 *
 * Returns 0 on success, errno on failure.
 */
int
tsol_update_sticky(ip6_pkt_t *ipp, uint_t *labellen, const uchar_t *labelopt)
{
	int rawlen, optlen, newlen;
	uchar_t *newopts;

	/*
	 * rawlen is the size of the IPv6 label to be inserted from labelopt.
	 * optlen is the total length of that option, including any necessary
	 * headers and padding.  newlen is the new size of the total hop-by-hop
	 * options buffer, including user options.
	 */
	ASSERT(*labellen <= ipp->ipp_hopoptslen);
	ASSERT((ipp->ipp_hopopts == NULL && ipp->ipp_hopoptslen == 0) ||
	    (ipp->ipp_hopopts != NULL && ipp->ipp_hopoptslen != 0));

	if ((rawlen = labelopt[1]) != 0) {
		rawlen += 2;	/* add in header size */
		optlen = (2 + rawlen + 7) & ~7;
	} else {
		optlen = 0;
	}
	newlen = ipp->ipp_hopoptslen + optlen - *labellen;
	if (newlen == 0 && ipp->ipp_hopopts != NULL) {
		/* Deleting all existing hop-by-hop options */
		kmem_free(ipp->ipp_hopopts, ipp->ipp_hopoptslen);
		ipp->ipp_hopopts = NULL;
		ipp->ipp_fields &= ~IPPF_HOPOPTS;
	} else if (optlen != *labellen) {
		/* If the label not same size as last time, then reallocate */
		if (newlen > IP6_MAX_OPT_LENGTH)
			return (EHOSTUNREACH);
		newopts = kmem_alloc(newlen, KM_NOSLEEP);
		if (newopts == NULL)
			return (ENOMEM);
		/*
		 * If the user has hop-by-hop stickyoptions set, then copy his
		 * options in after the security label.
		 */
		if (ipp->ipp_hopoptslen > *labellen) {
			bcopy(ipp->ipp_hopopts + *labellen, newopts + optlen,
			    ipp->ipp_hopoptslen - *labellen);
			/*
			 * Stomp out any header gunk here - this was the
			 * previous next-header and option length field.
			 */
			newopts[optlen] = IP6OPT_PADN;
			newopts[optlen + 1] = 0;
		}
		if (ipp->ipp_hopopts != NULL)
			kmem_free(ipp->ipp_hopopts, ipp->ipp_hopoptslen);
		ipp->ipp_hopopts = (ip6_hbh_t *)newopts;
	}
	ipp->ipp_hopoptslen = newlen;
	*labellen = optlen;

	newopts = (uchar_t *)ipp->ipp_hopopts;

	/* If there are any options, then fix up reported length */
	if (newlen > 0) {
		newopts[1] = (newlen + 7) / 8 - 1;
		ipp->ipp_fields |= IPPF_HOPOPTS;
	}

	/* If there's a label, then insert it now */
	if (optlen > 0) {
		/* skip next-header and length fields */
		newopts += 2;
		bcopy(labelopt, newopts, rawlen);
		newopts += rawlen;
		/* make sure padding comes out right */
		optlen -= 2 + rawlen;
		if (optlen == 1) {
			newopts[0] = IP6OPT_PAD1;
		} else if (optlen > 1) {
			newopts[0] = IP6OPT_PADN;
			optlen -=  2;
			newopts[1] = optlen;
			if (optlen > 0)
				bzero(newopts + 2, optlen);
		}
	}
	return (0);
}

int
tsol_update_options(uchar_t **opts, uint_t *totlen, uint_t *labellen,
    const uchar_t *labelopt)
{
	int optlen, newlen;
	uchar_t *newopts;

	optlen = (labelopt[IPOPT_OLEN] + 3) & ~3;
	newlen = *totlen + optlen - *labellen;
	if (optlen > *labellen) {
		if (newlen > IP_MAX_OPT_LENGTH)
			return (EHOSTUNREACH);
		newopts = (uchar_t *)mi_alloc(newlen, BPRI_HI);
		if (newopts == NULL)
			return (ENOMEM);
		if (*totlen > *labellen) {
			bcopy(*opts + *labellen, newopts + optlen,
			    *totlen - *labellen);
		}
		if (*opts != NULL)
			mi_free((char *)*opts);
		*opts = newopts;
	} else if (optlen < *labellen) {
		if (newlen == 0 && *opts != NULL) {
			mi_free((char *)*opts);
			*opts = NULL;
		}
		if (*totlen > *labellen) {
			ovbcopy(*opts + *labellen, *opts + optlen,
			    *totlen - *labellen);
		}
	}
	*totlen = newlen;
	*labellen = optlen;
	if (optlen > 0) {
		newopts = *opts;
		bcopy(labelopt, newopts, optlen);
		/* check if there are user-supplied options that follow */
		if (optlen < newlen) {
			/* compute amount of embedded alignment needed */
			optlen -= newopts[IPOPT_OLEN];
			newopts += newopts[IPOPT_OLEN];
			while (--optlen >= 0)
				*newopts++ = IPOPT_NOP;
		} else if (optlen != newopts[IPOPT_OLEN]) {
			/*
			 * The label option is the only option and it is
			 * not a multiple of 4 bytes.
			 */
			optlen -= newopts[IPOPT_OLEN];
			newopts += newopts[IPOPT_OLEN];
			while (--optlen >= 0)
				*newopts++ = IPOPT_EOL;
		}
	}
	return (0);
}

/*
 * This does the bulk of the processing for setting IPPROTO_IP {T_,}IP_OPTIONS.
 */
boolean_t
tsol_option_set(uchar_t **opts, uint_t *optlen, uint_t labellen,
    const uchar_t *useropts, uint_t userlen)
{
	int newlen;
	uchar_t *newopts;

	newlen = userlen + labellen;
	if (newlen > *optlen) {
		/* need more room */
		newopts = (uchar_t *)mi_alloc(newlen, BPRI_HI);
		if (newopts == NULL)
			return (B_FALSE);
		/*
		 * The supplied *opts can't be NULL in this case,
		 * since there's an existing label.
		 */
		if (labellen > 0)
			bcopy(*opts, newopts, labellen);
		if (*opts != NULL)
			mi_free((char *)*opts);
		*opts = newopts;
	}

	if (newlen == 0) {
		/* special case -- no remaining IP options at all */
		if (*opts != NULL) {
			mi_free((char *)*opts);
			*opts = NULL;
		}
	} else if (userlen > 0) {
		/* merge in the user's options */
		newopts = *opts;
		if (labellen > 0) {
			int extra = labellen - newopts[IPOPT_OLEN];

			newopts += newopts[IPOPT_OLEN];
			while (--extra >= 0)
				*newopts++ = IPOPT_NOP;
		}
		bcopy(useropts, newopts, userlen);
	}

	*optlen = newlen;
	return (B_TRUE);
}
