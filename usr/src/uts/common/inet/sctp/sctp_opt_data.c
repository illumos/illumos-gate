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

#include <sys/types.h>
#include <sys/stream.h>
#define	_SUN_TPI_VERSION 2
#include <sys/tihdr.h>
#include <sys/socket.h>
#include <sys/xti_inet.h>
#include <sys/systm.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/kmem.h>
#include <sys/strsubr.h>
#include <sys/strsun.h>
#include <sys/policy.h>

#include <inet/common.h>
#include <netinet/ip6.h>
#include <inet/ip.h>
#include <inet/ip_ire.h>
#include <inet/ip_if.h>
#include <inet/ipclassifier.h>
#include <inet/ipsec_impl.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#include <inet/common.h>
#include <inet/ip.h>
#include <inet/ip6.h>
#include <inet/sctp_itf.h>
#include "sctp_impl.h"
#include "sctp_asconf.h"
#include "sctp_addr.h"

static int	sctp_getpeeraddrs(sctp_t *, void *, int *);

/*
 * Copy the standard header into its new location,
 * lay in the new options and then update the relevant
 * fields in both sctp_t and the standard header.
 * Returns 0 on success, errno otherwise.
 */
static int
sctp_opt_set_header(sctp_t *sctp, const void *ptr, uint_t len)
{
	uint8_t *ip_optp;
	sctp_hdr_t *new_sctph;

	if ((len > SCTP_MAX_IP_OPTIONS_LENGTH) || (len & 0x3))
		return (EINVAL);

	if (len > IP_MAX_OPT_LENGTH - sctp->sctp_v4label_len)
		return (EINVAL);

	ip_optp = (uint8_t *)sctp->sctp_ipha + IP_SIMPLE_HDR_LENGTH;

	if (sctp->sctp_v4label_len > 0) {
		int padlen;
		uint8_t opt;

		/* convert list termination to no-ops as needed */
		padlen = sctp->sctp_v4label_len - ip_optp[IPOPT_OLEN];
		ip_optp += ip_optp[IPOPT_OLEN];
		opt = len > 0 ? IPOPT_NOP : IPOPT_EOL;
		while (--padlen >= 0)
			*ip_optp++ = opt;
		ASSERT(ip_optp == (uint8_t *)sctp->sctp_ipha +
		    IP_SIMPLE_HDR_LENGTH + sctp->sctp_v4label_len);
	}

	/*
	 * Move the existing SCTP header out where it belongs.
	 */
	new_sctph = (sctp_hdr_t *)(ip_optp + len);
	ovbcopy(sctp->sctp_sctph, new_sctph, sizeof (sctp_hdr_t));
	sctp->sctp_sctph = new_sctph;

	/*
	 * Insert the new user-supplied IP options.
	 */
	if (len > 0)
		bcopy(ptr, ip_optp, len);

	len += sctp->sctp_v4label_len;
	sctp->sctp_ip_hdr_len = len;
	sctp->sctp_ipha->ipha_version_and_hdr_length =
	    (IP_VERSION << 4) | (len >> 2);
	sctp->sctp_hdr_len = len + sizeof (sctp_hdr_t);

	if (sctp->sctp_current) {
		/*
		 * Could be setting options before setting up connection.
		 */
		sctp_set_ulp_prop(sctp);
	}
	return (0);
}

static int
sctp_get_status(sctp_t *sctp, void *ptr)
{
	struct sctp_status *sstat = ptr;
	sctp_faddr_t *fp;
	struct sockaddr_in *sin;
	struct sockaddr_in6 *sin6;
	struct sctp_paddrinfo *sp;
	mblk_t *meta, *mp;
	int i;

	sstat->sstat_state = sctp->sctp_state;
	sstat->sstat_rwnd = sctp->sctp_frwnd;

	sp = &sstat->sstat_primary;
	if (!sctp->sctp_primary) {
		bzero(sp, sizeof (*sp));
		goto noprim;
	}
	fp = sctp->sctp_primary;

	if (fp->isv4) {
		sin = (struct sockaddr_in *)&sp->spinfo_address;
		sin->sin_family = AF_INET;
		sin->sin_port = sctp->sctp_fport;
		IN6_V4MAPPED_TO_INADDR(&fp->faddr, &sin->sin_addr);
		sp->spinfo_mtu = sctp->sctp_hdr_len;
	} else {
		sin6 = (struct sockaddr_in6 *)&sp->spinfo_address;
		sin6->sin6_family = AF_INET6;
		sin6->sin6_port = sctp->sctp_fport;
		sin6->sin6_addr = fp->faddr;
		sp->spinfo_mtu = sctp->sctp_hdr6_len;
	}
	sp->spinfo_state = fp->state == SCTP_FADDRS_ALIVE ? SCTP_ACTIVE :
	    SCTP_INACTIVE;
	sp->spinfo_cwnd = fp->cwnd;
	sp->spinfo_srtt = fp->srtt;
	sp->spinfo_rto = fp->rto;
	sp->spinfo_mtu += fp->sfa_pmss;

noprim:
	sstat->sstat_unackdata = 0;
	sstat->sstat_penddata = 0;
	sstat->sstat_instrms = sctp->sctp_num_istr;
	sstat->sstat_outstrms = sctp->sctp_num_ostr;
	sstat->sstat_fragmentation_point = sctp->sctp_mss -
	    sizeof (sctp_data_hdr_t);

	/* count unack'd */
	for (meta = sctp->sctp_xmit_head; meta; meta = meta->b_next) {
		for (mp = meta->b_cont; mp; mp = mp->b_next) {
			if (!SCTP_CHUNK_ISSENT(mp)) {
				break;
			}
			if (!SCTP_CHUNK_ISACKED(mp)) {
				sstat->sstat_unackdata++;
			}
		}
	}

	/*
	 * Count penddata chunks. We can only count chunks in SCTP (not
	 * data already delivered to socket layer).
	 */
	if (sctp->sctp_instr != NULL) {
		for (i = 0; i < sctp->sctp_num_istr; i++) {
			for (meta = sctp->sctp_instr[i].istr_reass;
			    meta != NULL; meta = meta->b_next) {
				for (mp = meta->b_cont; mp; mp = mp->b_cont) {
					if (DB_TYPE(mp) != M_CTL) {
						sstat->sstat_penddata++;
					}
				}
			}
		}
	}
	/* Un-Ordered Frag list */
	for (meta = sctp->sctp_uo_frags; meta != NULL; meta = meta->b_next)
		sstat->sstat_penddata++;

	return (sizeof (*sstat));
}

/*
 * SCTP_GET_PEER_ADDR_INFO
 */
static int
sctp_get_paddrinfo(sctp_t *sctp, void *ptr, socklen_t *optlen)
{
	struct sctp_paddrinfo	*infop = ptr;
	struct sockaddr_in	*sin4;
	struct sockaddr_in6	*sin6;
	in6_addr_t		faddr;
	sctp_faddr_t		*fp;

	switch (infop->spinfo_address.ss_family) {
	case AF_INET:
		sin4 = (struct sockaddr_in *)&infop->spinfo_address;
		IN6_INADDR_TO_V4MAPPED(&sin4->sin_addr, &faddr);
		break;
	case AF_INET6:
		sin6 = (struct sockaddr_in6 *)&infop->spinfo_address;
		faddr = sin6->sin6_addr;
		break;
	default:
		return (EAFNOSUPPORT);
	}

	if ((fp = sctp_lookup_faddr(sctp, &faddr)) == NULL)
		return (EINVAL);

	infop->spinfo_state = (fp->state == SCTP_FADDRS_ALIVE) ? SCTP_ACTIVE :
	    SCTP_INACTIVE;
	infop->spinfo_cwnd = fp->cwnd;
	infop->spinfo_srtt = TICK_TO_MSEC(fp->srtt);
	infop->spinfo_rto = TICK_TO_MSEC(fp->rto);
	infop->spinfo_mtu = fp->sfa_pmss;

	*optlen = sizeof (struct sctp_paddrinfo);
	return (0);
}

/*
 * SCTP_RTOINFO
 */
static int
sctp_get_rtoinfo(sctp_t *sctp, void *ptr)
{
	struct sctp_rtoinfo *srto = ptr;

	srto->srto_initial = TICK_TO_MSEC(sctp->sctp_rto_initial);
	srto->srto_max = TICK_TO_MSEC(sctp->sctp_rto_max);
	srto->srto_min = TICK_TO_MSEC(sctp->sctp_rto_min);

	return (sizeof (*srto));
}

static int
sctp_set_rtoinfo(sctp_t *sctp, const void *invalp, uint_t inlen)
{
	const struct sctp_rtoinfo *srto;
	boolean_t ispriv;
	sctp_stack_t	*sctps = sctp->sctp_sctps;

	if (inlen < sizeof (*srto)) {
		return (EINVAL);
	}
	srto = invalp;

	ispriv = secpolicy_ip_config(sctp->sctp_credp, B_TRUE) == 0;

	/*
	 * Bounds checking.  Priviledged user can set the RTO initial
	 * outside the ndd boundary.
	 */
	if (srto->srto_initial != 0 &&
	    (!ispriv && (srto->srto_initial < sctps->sctps_rto_initialg_low ||
	    srto->srto_initial > sctps->sctps_rto_initialg_high))) {
		return (EINVAL);
	}
	if (srto->srto_max != 0 &&
	    (!ispriv && (srto->srto_max < sctps->sctps_rto_maxg_low ||
	    srto->srto_max > sctps->sctps_rto_maxg_high))) {
		return (EINVAL);
	}
	if (srto->srto_min != 0 &&
	    (!ispriv && (srto->srto_min < sctps->sctps_rto_ming_low ||
	    srto->srto_min > sctps->sctps_rto_ming_high))) {
		return (EINVAL);
	}

	if (srto->srto_initial != 0) {
		sctp->sctp_rto_initial = MSEC_TO_TICK(srto->srto_initial);
	}
	if (srto->srto_max != 0) {
		sctp->sctp_rto_max = MSEC_TO_TICK(srto->srto_max);
	}
	if (srto->srto_min != 0) {
		sctp->sctp_rto_min = MSEC_TO_TICK(srto->srto_min);
	}

	return (0);
}

/*
 * SCTP_ASSOCINFO
 */
static int
sctp_get_assocparams(sctp_t *sctp, void *ptr)
{
	struct sctp_assocparams *sap = ptr;
	sctp_faddr_t *fp;
	uint16_t i;

	sap->sasoc_asocmaxrxt = sctp->sctp_pa_max_rxt;

	/*
	 * Count the number of peer addresses
	 */
	for (i = 0, fp = sctp->sctp_faddrs; fp != NULL; fp = fp->next) {
		i++;
	}
	sap->sasoc_number_peer_destinations = i;
	sap->sasoc_peer_rwnd = sctp->sctp_frwnd;
	sap->sasoc_local_rwnd = sctp->sctp_rwnd;
	sap->sasoc_cookie_life = TICK_TO_MSEC(sctp->sctp_cookie_lifetime);

	return (sizeof (*sap));
}

static int
sctp_set_assocparams(sctp_t *sctp, const void *invalp, uint_t inlen)
{
	const struct sctp_assocparams *sap = invalp;
	uint32_t sum = 0;
	sctp_faddr_t *fp;
	sctp_stack_t	*sctps = sctp->sctp_sctps;

	if (inlen < sizeof (*sap)) {
		return (EINVAL);
	}

	if (sap->sasoc_asocmaxrxt) {
		if (sctp->sctp_faddrs) {
			/*
			 * Bounds check: as per rfc2960, assoc max retr cannot
			 * exceed the sum of all individual path max retr's.
			 */
			for (fp = sctp->sctp_faddrs; fp; fp = fp->next) {
				sum += fp->max_retr;
			}
			if (sap->sasoc_asocmaxrxt > sum) {
				return (EINVAL);
			}
		}
		if (sap->sasoc_asocmaxrxt < sctps->sctps_pa_max_retr_low ||
		    sap->sasoc_asocmaxrxt > sctps->sctps_pa_max_retr_high) {
			/*
			 * Out of bounds.
			 */
			return (EINVAL);
		}
	}
	if (sap->sasoc_cookie_life != 0 &&
	    (sap->sasoc_cookie_life < sctps->sctps_cookie_life_low ||
	    sap->sasoc_cookie_life > sctps->sctps_cookie_life_high)) {
		return (EINVAL);
	}

	if (sap->sasoc_asocmaxrxt > 0) {
		sctp->sctp_pa_max_rxt = sap->sasoc_asocmaxrxt;
	}
	if (sap->sasoc_cookie_life > 0) {
		sctp->sctp_cookie_lifetime = MSEC_TO_TICK(
		    sap->sasoc_cookie_life);
	}
	return (0);
}

/*
 * SCTP_INITMSG
 */
static int
sctp_get_initmsg(sctp_t *sctp, void *ptr)
{
	struct sctp_initmsg *si = ptr;

	si->sinit_num_ostreams = sctp->sctp_num_ostr;
	si->sinit_max_instreams = sctp->sctp_num_istr;
	si->sinit_max_attempts = sctp->sctp_max_init_rxt;
	si->sinit_max_init_timeo = TICK_TO_MSEC(sctp->sctp_init_rto_max);

	return (sizeof (*si));
}

static int
sctp_set_initmsg(sctp_t *sctp, const void *invalp, uint_t inlen)
{
	const struct sctp_initmsg *si = invalp;
	sctp_stack_t	*sctps = sctp->sctp_sctps;

	if (sctp->sctp_state > SCTPS_LISTEN) {
		return (EINVAL);
	}
	if (inlen < sizeof (*si)) {
		return (EINVAL);
	}
	if (si->sinit_num_ostreams != 0 &&
	    (si->sinit_num_ostreams < sctps->sctps_initial_out_streams_low ||
	    si->sinit_num_ostreams >
	    sctps->sctps_initial_out_streams_high)) {
		/*
		 * Out of bounds.
		 */
		return (EINVAL);
	}
	if (si->sinit_max_instreams != 0 &&
	    (si->sinit_max_instreams < sctps->sctps_max_in_streams_low ||
	    si->sinit_max_instreams > sctps->sctps_max_in_streams_high)) {
		return (EINVAL);
	}
	if (si->sinit_max_attempts != 0 &&
	    (si->sinit_max_attempts < sctps->sctps_max_init_retr_low ||
	    si->sinit_max_attempts > sctps->sctps_max_init_retr_high)) {
		return (EINVAL);
	}
	if (si->sinit_max_init_timeo != 0 &&
	    (secpolicy_ip_config(sctp->sctp_credp, B_TRUE) != 0 &&
	    (si->sinit_max_init_timeo < sctps->sctps_rto_maxg_low ||
	    si->sinit_max_init_timeo > sctps->sctps_rto_maxg_high))) {
		return (EINVAL);
	}
	if (si->sinit_num_ostreams != 0)
		sctp->sctp_num_ostr = si->sinit_num_ostreams;

	if (si->sinit_max_instreams != 0)
		sctp->sctp_num_istr = si->sinit_max_instreams;

	if (si->sinit_max_attempts != 0)
		sctp->sctp_max_init_rxt = si->sinit_max_attempts;

	if (si->sinit_max_init_timeo != 0) {
		sctp->sctp_init_rto_max =
		    MSEC_TO_TICK(si->sinit_max_init_timeo);
	}
	return (0);
}

/*
 * SCTP_PEER_ADDR_PARAMS
 */
static int
sctp_find_peer_fp(sctp_t *sctp, const struct sockaddr_storage *ss,
    sctp_faddr_t **fpp)
{
	struct sockaddr_in *sin;
	struct sockaddr_in6 *sin6;
	in6_addr_t addr;

	if (ss->ss_family == AF_INET) {
		sin = (struct sockaddr_in *)ss;
		IN6_IPADDR_TO_V4MAPPED(sin->sin_addr.s_addr, &addr);
	} else if (ss->ss_family == AF_INET6) {
		sin6 = (struct sockaddr_in6 *)ss;
		addr = sin6->sin6_addr;
	} else if (ss->ss_family) {
		return (EAFNOSUPPORT);
	}

	if (!ss->ss_family ||
	    SCTP_IS_ADDR_UNSPEC(IN6_IS_ADDR_V4MAPPED(&addr), addr)) {
		*fpp = NULL;
	} else {
		*fpp = sctp_lookup_faddr(sctp, &addr);
		if (*fpp == NULL) {
			return (EINVAL);
		}
	}
	return (0);
}

static int
sctp_get_peer_addr_params(sctp_t *sctp, void *ptr)
{
	struct sctp_paddrparams *spp = ptr;
	sctp_faddr_t *fp;
	int retval;

	retval = sctp_find_peer_fp(sctp, &spp->spp_address, &fp);
	if (retval) {
		return (retval);
	}
	if (fp) {
		spp->spp_hbinterval = TICK_TO_MSEC(fp->hb_interval);
		spp->spp_pathmaxrxt = fp->max_retr;
	} else {
		spp->spp_hbinterval = TICK_TO_MSEC(sctp->sctp_hb_interval);
		spp->spp_pathmaxrxt = sctp->sctp_pp_max_rxt;
	}
	return (sizeof (*spp));
}

static int
sctp_set_peer_addr_params(sctp_t *sctp, const void *invalp, uint_t inlen)
{
	const struct sctp_paddrparams *spp = invalp;
	sctp_faddr_t *fp, *fp2;
	int retval;
	uint32_t sum = 0;
	int64_t now;
	sctp_stack_t	*sctps = sctp->sctp_sctps;

	if (inlen < sizeof (*spp)) {
		return (EINVAL);
	}

	retval = sctp_find_peer_fp(sctp, &spp->spp_address, &fp);
	if (retval != 0) {
		return (retval);
	}

	if (spp->spp_hbinterval && spp->spp_hbinterval != UINT32_MAX &&
	    (spp->spp_hbinterval < sctps->sctps_heartbeat_interval_low ||
	    spp->spp_hbinterval > sctps->sctps_heartbeat_interval_high)) {
		return (EINVAL);
	}
	if (spp->spp_pathmaxrxt &&
	    (spp->spp_pathmaxrxt < sctps->sctps_pp_max_retr_low ||
	    spp->spp_pathmaxrxt > sctps->sctps_pp_max_retr_high)) {
		return (EINVAL);
	}
	if (spp->spp_pathmaxrxt && sctp->sctp_faddrs) {
		for (fp2 = sctp->sctp_faddrs; fp2; fp2 = fp2->next) {
			if (!fp || fp2 == fp) {
				sum += spp->spp_pathmaxrxt;
			} else {
				sum += fp2->max_retr;
			}
		}
		if (sctp->sctp_pa_max_rxt > sum) {
			return (EINVAL);
		}
	}

	now = lbolt64;
	if (fp != NULL) {
		if (spp->spp_hbinterval == UINT32_MAX) {
			/*
			 * Send heartbeat immediatelly, don't modify the
			 * current setting.
			 */
			sctp_send_heartbeat(sctp, fp);
		} else {
			fp->hb_interval = MSEC_TO_TICK(spp->spp_hbinterval);
			fp->hb_expiry = now + SET_HB_INTVL(fp);
			/*
			 * Restart the heartbeat timer using the new intrvl.
			 * We need to call sctp_heartbeat_timer() to set
			 * the earliest heartbeat expiry time.
			 */
			sctp_heartbeat_timer(sctp);
		}
		if (spp->spp_pathmaxrxt) {
			fp->max_retr = spp->spp_pathmaxrxt;
		}
	} else {
		for (fp2 = sctp->sctp_faddrs; fp2 != NULL; fp2 = fp2->next) {
			if (spp->spp_hbinterval == UINT32_MAX) {
				/*
				 * Send heartbeat immediatelly, don't modify
				 * the current setting.
				 */
				sctp_send_heartbeat(sctp, fp2);
			} else {
				fp2->hb_interval = MSEC_TO_TICK(
				    spp->spp_hbinterval);
				fp2->hb_expiry = now + SET_HB_INTVL(fp2);
			}
			if (spp->spp_pathmaxrxt) {
				fp2->max_retr = spp->spp_pathmaxrxt;
			}
		}
		if (spp->spp_hbinterval != UINT32_MAX) {
			sctp->sctp_hb_interval = MSEC_TO_TICK(
			    spp->spp_hbinterval);
			/* Restart the heartbeat timer using the new intrvl. */
			sctp_timer(sctp, sctp->sctp_heartbeat_mp,
			    sctp->sctp_hb_interval);
		}
		if (spp->spp_pathmaxrxt) {
			sctp->sctp_pp_max_rxt = spp->spp_pathmaxrxt;
		}
	}
	return (0);
}

/*
 * SCTP_DEFAULT_SEND_PARAM
 */
static int
sctp_get_def_send_params(sctp_t *sctp, void *ptr)
{
	struct sctp_sndrcvinfo *sinfo = ptr;

	sinfo->sinfo_stream = sctp->sctp_def_stream;
	sinfo->sinfo_ssn = 0;
	sinfo->sinfo_flags = sctp->sctp_def_flags;
	sinfo->sinfo_ppid = sctp->sctp_def_ppid;
	sinfo->sinfo_context = sctp->sctp_def_context;
	sinfo->sinfo_timetolive = sctp->sctp_def_timetolive;
	sinfo->sinfo_tsn = 0;
	sinfo->sinfo_cumtsn = 0;

	return (sizeof (*sinfo));
}

static int
sctp_set_def_send_params(sctp_t *sctp, const void *invalp, uint_t inlen)
{
	const struct sctp_sndrcvinfo *sinfo = invalp;

	if (inlen < sizeof (*sinfo)) {
		return (EINVAL);
	}
	if (sinfo->sinfo_stream >= sctp->sctp_num_ostr) {
		return (EINVAL);
	}

	sctp->sctp_def_stream = sinfo->sinfo_stream;
	sctp->sctp_def_flags = sinfo->sinfo_flags;
	sctp->sctp_def_ppid = sinfo->sinfo_ppid;
	sctp->sctp_def_context = sinfo->sinfo_context;
	sctp->sctp_def_timetolive = sinfo->sinfo_timetolive;

	return (0);
}

static int
sctp_set_prim(sctp_t *sctp, const void *invalp, uint_t inlen)
{
	const struct	sctp_setpeerprim *pp = invalp;
	int		retval;
	sctp_faddr_t	*fp;

	if (inlen < sizeof (*pp)) {
		return (EINVAL);
	}

	retval = sctp_find_peer_fp(sctp, &pp->sspp_addr, &fp);
	if (retval)
		return (retval);

	if (fp == NULL)
		return (EINVAL);
	if (fp == sctp->sctp_primary)
		return (0);
	sctp->sctp_primary = fp;

	/* Only switch current if fp is alive */
	if (fp->state != SCTP_FADDRS_ALIVE || fp == sctp->sctp_current) {
		return (0);
	}
	sctp_set_faddr_current(sctp, fp);

	return (0);
}

/* Handy on off switch for socket option processing. */
#define	ONOFF(x)	((x) == 0 ? 0 : 1)

/*
 * SCTP routine to get the values of options.
 */
int
sctp_get_opt(sctp_t *sctp, int level, int name, void *ptr, socklen_t *optlen)
{
	int	*i1 = (int *)ptr;
	int	retval = 0;
	int	buflen = *optlen;
	conn_t		*connp = sctp->sctp_connp;
	ip6_pkt_t	*ipp = &sctp->sctp_sticky_ipp;

	/* In most cases, the return buffer is just an int */
	*optlen = sizeof (int32_t);

	RUN_SCTP(sctp);

	if (connp->conn_state_flags & CONN_CLOSING) {
		WAKE_SCTP(sctp);
		return (EINVAL);
	}

	switch (level) {
	case SOL_SOCKET:
		switch (name) {
		case SO_LINGER:	{
			struct linger *lgr = (struct linger *)ptr;

			lgr->l_onoff = sctp->sctp_linger ? SO_LINGER : 0;
			lgr->l_linger = TICK_TO_MSEC(sctp->sctp_lingertime);
			*optlen = sizeof (struct linger);
			break;
		}
		case SO_DEBUG:
			*i1 = sctp->sctp_debug ? SO_DEBUG : 0;
			break;
		case SO_DONTROUTE:
			*i1 = connp->conn_dontroute ? SO_DONTROUTE : 0;
			break;
		case SO_USELOOPBACK:
			*i1 = connp->conn_loopback ? SO_USELOOPBACK : 0;
			break;
		case SO_BROADCAST:
			*i1 = connp->conn_broadcast ? SO_BROADCAST : 0;
			break;
		case SO_REUSEADDR:
			*i1 = connp->conn_reuseaddr ? SO_REUSEADDR : 0;
			break;
		case SO_DGRAM_ERRIND:
			*i1 = sctp->sctp_dgram_errind ? SO_DGRAM_ERRIND : 0;
			break;
		case SO_SNDBUF:
			*i1 = sctp->sctp_xmit_hiwater;
			break;
		case SO_RCVBUF:
			*i1 = sctp->sctp_rwnd;
			break;
		case SO_ALLZONES:
			*i1 = connp->conn_allzones;
			break;
		case SO_MAC_EXEMPT:
			*i1 = connp->conn_mac_exempt;
			break;
		case SO_PROTOTYPE:
			*i1 = IPPROTO_SCTP;
			break;
		case SO_DOMAIN:
			*i1 = sctp->sctp_family;
			break;
		default:
			retval = ENOPROTOOPT;
			break;
		}
		break;

	case IPPROTO_SCTP:
		switch (name) {
		case SCTP_RTOINFO:
			if (buflen < sizeof (struct sctp_rtoinfo)) {
				retval = EINVAL;
				break;
			}
			*optlen = sctp_get_rtoinfo(sctp, ptr);
			break;
		case SCTP_ASSOCINFO:
			if (buflen < sizeof (struct sctp_assocparams)) {
				retval = EINVAL;
				break;
			}
			*optlen = sctp_get_assocparams(sctp, ptr);
			break;
		case SCTP_INITMSG:
			if (buflen < sizeof (struct sctp_initmsg)) {
				retval = EINVAL;
				break;
			}
			*optlen = sctp_get_initmsg(sctp, ptr);
			break;
		case SCTP_NODELAY:
			*i1 = sctp->sctp_ndelay;
			break;
		case SCTP_AUTOCLOSE:
			*i1 = TICK_TO_SEC(sctp->sctp_autoclose);
			break;
		case SCTP_ADAPTION_LAYER:
			if (buflen < sizeof (struct sctp_setadaption)) {
				retval = EINVAL;
				break;
			}
			((struct sctp_setadaption *)ptr)->ssb_adaption_ind =
			    sctp->sctp_tx_adaption_code;
			break;
		case SCTP_PEER_ADDR_PARAMS:
			if (buflen < sizeof (struct sctp_paddrparams)) {
				retval = EINVAL;
				break;
			}
			*optlen = sctp_get_peer_addr_params(sctp, ptr);
			break;
		case SCTP_DEFAULT_SEND_PARAM:
			if (buflen < sizeof (struct sctp_sndrcvinfo)) {
				retval = EINVAL;
				break;
			}
			*optlen = sctp_get_def_send_params(sctp, ptr);
			break;
		case SCTP_EVENTS: {
			struct sctp_event_subscribe *ev;

			if (buflen < sizeof (struct sctp_event_subscribe)) {
				retval = EINVAL;
				break;
			}
			ev = (struct sctp_event_subscribe *)ptr;
			ev->sctp_data_io_event =
			    ONOFF(sctp->sctp_recvsndrcvinfo);
			ev->sctp_association_event =
			    ONOFF(sctp->sctp_recvassocevnt);
			ev->sctp_address_event =
			    ONOFF(sctp->sctp_recvpathevnt);
			ev->sctp_send_failure_event =
			    ONOFF(sctp->sctp_recvsendfailevnt);
			ev->sctp_peer_error_event =
			    ONOFF(sctp->sctp_recvpeererr);
			ev->sctp_shutdown_event =
			    ONOFF(sctp->sctp_recvshutdownevnt);
			ev->sctp_partial_delivery_event =
			    ONOFF(sctp->sctp_recvpdevnt);
			ev->sctp_adaption_layer_event =
			    ONOFF(sctp->sctp_recvalevnt);
			*optlen = sizeof (struct sctp_event_subscribe);
			break;
		}
		case SCTP_STATUS:
			if (buflen < sizeof (struct sctp_status)) {
				retval = EINVAL;
				break;
			}
			*optlen = sctp_get_status(sctp, ptr);
			break;
		case SCTP_GET_PEER_ADDR_INFO:
			if (buflen < sizeof (struct sctp_paddrinfo)) {
				retval = EINVAL;
				break;
			}
			retval = sctp_get_paddrinfo(sctp, ptr, optlen);
			break;
		case SCTP_GET_NLADDRS:
			*(int32_t *)ptr = sctp->sctp_nsaddrs;
			break;
		case SCTP_GET_LADDRS: {
			int addr_cnt;
			int addr_size;

			if (sctp->sctp_family == AF_INET)
				addr_size = sizeof (struct sockaddr_in);
			else
				addr_size = sizeof (struct sockaddr_in6);
			addr_cnt = buflen / addr_size;
			retval = sctp_getmyaddrs(sctp, ptr, &addr_cnt);
			if (retval == 0)
				*optlen = addr_cnt * addr_size;
			break;
		}
		case SCTP_GET_NPADDRS: {
			int i;
			sctp_faddr_t *fp;

			for (i = 0, fp = sctp->sctp_faddrs; fp != NULL;
			    i++, fp = fp->next)
				;
			*(int32_t *)ptr = i;
			break;
		}
		case SCTP_GET_PADDRS: {
			int addr_cnt;
			int addr_size;

			if (sctp->sctp_family == AF_INET)
				addr_size = sizeof (struct sockaddr_in);
			else
				addr_size = sizeof (struct sockaddr_in6);
			addr_cnt = buflen / addr_size;
			retval = sctp_getpeeraddrs(sctp, ptr, &addr_cnt);
			if (retval == 0)
				*optlen = addr_cnt * addr_size;
			break;
		}
		case SCTP_PRSCTP:
			*i1 = sctp->sctp_prsctp_aware ? 1 : 0;
			break;
		case SCTP_I_WANT_MAPPED_V4_ADDR:
		case SCTP_MAXSEG:
		case SCTP_DISABLE_FRAGMENTS:
			/* Not yet supported. */
		default:
			retval = ENOPROTOOPT;
			break;
		}
		break;

	case IPPROTO_IP:
		if (sctp->sctp_family != AF_INET) {
			retval = EINVAL;
			break;
		}
		switch (name) {
		case IP_OPTIONS:
		case T_IP_OPTIONS: {
			/*
			 * This is compatible with BSD in that in only return
			 * the reverse source route with the final destination
			 * as the last entry. The first 4 bytes of the option
			 * will contain the final destination. Allocate a
			 * buffer large enough to hold all the options, we
			 * add IP_ADDR_LEN to SCTP_MAX_IP_OPTIONS_LENGTH since
			 * ip_opt_get_user() adds the final destination
			 * at the start.
			 */
			char	*opt_ptr;
			int	opt_len;
			uchar_t	obuf[SCTP_MAX_IP_OPTIONS_LENGTH + IP_ADDR_LEN];

			opt_ptr = (char *)sctp->sctp_ipha +
			    IP_SIMPLE_HDR_LENGTH;
			opt_len = (char *)sctp->sctp_sctph - opt_ptr;
			/* Caller ensures enough space */
			if (opt_len > 0) {
				/*
				 * TODO: Do we have to handle getsockopt on an
				 * initiator as well?
				 */
				opt_len = ip_opt_get_user(sctp->sctp_ipha,
				    obuf);
				ASSERT(opt_len <= sizeof (obuf));
			} else {
				opt_len = 0;
			}
			if (buflen < opt_len) {
				/* Silently truncate */
				opt_len = buflen;
			}
			*optlen = opt_len;
			bcopy(obuf, ptr, opt_len);
			break;
		}
		case IP_TOS:
		case T_IP_TOS:
			*i1 = (int)sctp->sctp_ipha->ipha_type_of_service;
			break;
		case IP_TTL:
			*i1 = (int)sctp->sctp_ipha->ipha_ttl;
			break;
		case IP_NEXTHOP:
			if (connp->conn_nexthop_set) {
				*(ipaddr_t *)ptr = connp->conn_nexthop_v4;
				*optlen = sizeof (ipaddr_t);
			} else {
				*optlen = 0;
			}
			break;
		default:
			retval = ENOPROTOOPT;
			break;
		}
		break;
	case IPPROTO_IPV6:
		if (sctp->sctp_family != AF_INET6) {
			retval = EINVAL;
			break;
		}
		switch (name) {
		case IPV6_UNICAST_HOPS:
			*i1 = (unsigned int) sctp->sctp_ip6h->ip6_hops;
			break;	/* goto sizeof (int) option return */
		case IPV6_RECVPKTINFO:
			if (sctp->sctp_ipv6_recvancillary &
			    SCTP_IPV6_RECVPKTINFO) {
				*i1 = 1;
			} else {
				*i1 = 0;
			}
			break;	/* goto sizeof (int) option return */
		case IPV6_RECVHOPLIMIT:
			if (sctp->sctp_ipv6_recvancillary &
			    SCTP_IPV6_RECVHOPLIMIT) {
				*i1 = 1;
			} else {
				*i1 = 0;
			}
			break;	/* goto sizeof (int) option return */
		case IPV6_RECVHOPOPTS:
			if (sctp->sctp_ipv6_recvancillary &
			    SCTP_IPV6_RECVHOPOPTS) {
				*i1 = 1;
			} else {
				*i1 = 0;
			}
			break;	/* goto sizeof (int) option return */
		case IPV6_RECVDSTOPTS:
			if (sctp->sctp_ipv6_recvancillary &
			    SCTP_IPV6_RECVDSTOPTS) {
				*i1 = 1;
			} else {
				*i1 = 0;
			}
			break;	/* goto sizeof (int) option return */
		case IPV6_RECVRTHDR:
			if (sctp->sctp_ipv6_recvancillary &
			    SCTP_IPV6_RECVRTHDR) {
				*i1 = 1;
			} else {
				*i1 = 0;
			}
			break;	/* goto sizeof (int) option return */
		case IPV6_RECVRTHDRDSTOPTS:
			if (sctp->sctp_ipv6_recvancillary &
			    SCTP_IPV6_RECVRTDSTOPTS) {
				*i1 = 1;
			} else {
				*i1 = 0;
			}
			break;	/* goto sizeof (int) option return */
		case IPV6_PKTINFO: {
			struct in6_pktinfo *pkti;

			if (buflen < sizeof (struct in6_pktinfo)) {
				retval = EINVAL;
				break;
			}
			pkti = (struct in6_pktinfo *)ptr;
			if (ipp->ipp_fields & IPPF_IFINDEX)
				pkti->ipi6_ifindex = ipp->ipp_ifindex;
			else
				pkti->ipi6_ifindex = 0;
			if (ipp->ipp_fields & IPPF_ADDR)
				pkti->ipi6_addr = ipp->ipp_addr;
			else
				pkti->ipi6_addr = ipv6_all_zeros;
			*optlen = sizeof (struct in6_pktinfo);
			break;
		}
		case IPV6_NEXTHOP: {
			sin6_t *sin6;

			if (buflen < sizeof (sin6_t)) {
				retval = EINVAL;
				break;
			}
			sin6 = (sin6_t *)ptr;
			if (!(ipp->ipp_fields & IPPF_NEXTHOP))
				break;
			*sin6 = sctp_sin6_null;
			sin6->sin6_family = AF_INET6;
			sin6->sin6_addr = ipp->ipp_nexthop;
			*optlen = sizeof (sin6_t);
			break;
		}
		case IPV6_HOPOPTS: {
			int len;

			if (!(ipp->ipp_fields & IPPF_HOPOPTS))
				break;
			len = ipp->ipp_hopoptslen - sctp->sctp_v6label_len;
			if (len <= 0)
				break;
			if (buflen < len) {
				retval = EINVAL;
				break;
			}
			bcopy((char *)ipp->ipp_hopopts +
			    sctp->sctp_v6label_len, ptr, len);
			if (sctp->sctp_v6label_len > 0) {
				char *cptr = ptr;

				/*
				 * If the label length is greater than zero,
				 * then we need to hide the label from user.
				 * Make it look as though a normal Hop-By-Hop
				 * Options Header is present here.
				 */
				cptr[0] = ((char *)ipp->ipp_hopopts)[0];
				cptr[1] = (len + 7) / 8 - 1;
			}
			*optlen = len;
			break;
		}
		case IPV6_RTHDRDSTOPTS:
			if (!(ipp->ipp_fields & IPPF_RTDSTOPTS))
				break;
			if (buflen < ipp->ipp_rtdstoptslen) {
				retval = EINVAL;
				break;
			}
			bcopy(ipp->ipp_rtdstopts, ptr, ipp->ipp_rtdstoptslen);
			*optlen  = ipp->ipp_rtdstoptslen;
			break;
		case IPV6_RTHDR:
			if (!(ipp->ipp_fields & IPPF_RTHDR))
				break;
			if (buflen < ipp->ipp_rthdrlen) {
				retval = EINVAL;
				break;
			}
			bcopy(ipp->ipp_rthdr, ptr, ipp->ipp_rthdrlen);
			*optlen = ipp->ipp_rthdrlen;
			break;
		case IPV6_DSTOPTS:
			if (!(ipp->ipp_fields & IPPF_DSTOPTS))
				break;
			if (buflen < ipp->ipp_dstoptslen) {
				retval = EINVAL;
				break;
			}
			bcopy(ipp->ipp_dstopts, ptr, ipp->ipp_dstoptslen);
			*optlen  = ipp->ipp_dstoptslen;
			break;
		case IPV6_V6ONLY:
			*i1 = sctp->sctp_connp->conn_ipv6_v6only;
			break;
		default:
			retval = ENOPROTOOPT;
			break;
		}
		break;

	default:
		retval = ENOPROTOOPT;
		break;
	}
	WAKE_SCTP(sctp);
	return (retval);
}

int
sctp_set_opt(sctp_t *sctp, int level, int name, const void *invalp,
    socklen_t inlen)
{
	ip6_pkt_t	*ipp = &sctp->sctp_sticky_ipp;
	int		*i1 = (int *)invalp;
	boolean_t	onoff;
	int		retval = 0, addrcnt;
	conn_t		*connp = sctp->sctp_connp;
	sctp_stack_t	*sctps = sctp->sctp_sctps;

	/* In all cases, the size of the option must be bigger than int */
	if (inlen >= sizeof (int32_t)) {
		onoff = ONOFF(*i1);
	}
	retval = 0;

	RUN_SCTP(sctp);

	if (connp->conn_state_flags & CONN_CLOSING) {
		WAKE_SCTP(sctp);
		return (EINVAL);
	}

	switch (level) {
	case SOL_SOCKET:
		if (inlen < sizeof (int32_t)) {
			retval = EINVAL;
			break;
		}
		switch (name) {
		case SO_LINGER: {
			struct linger *lgr;

			if (inlen != sizeof (struct linger)) {
				retval = EINVAL;
				break;
			}
			lgr = (struct linger *)invalp;
			if (lgr->l_onoff != 0) {
				sctp->sctp_linger = 1;
				sctp->sctp_lingertime = MSEC_TO_TICK(
				    lgr->l_linger);
			} else {
				sctp->sctp_linger = 0;
				sctp->sctp_lingertime = 0;
			}
			break;
		}
		case SO_DEBUG:
			sctp->sctp_debug = onoff;
			break;
		case SO_KEEPALIVE:
			break;
		case SO_DONTROUTE:
			/*
			 * SO_DONTROUTE, SO_USELOOPBACK and SO_BROADCAST are
			 * only of interest to IP.
			 */
			connp->conn_dontroute = onoff;
			break;
		case SO_USELOOPBACK:
			connp->conn_loopback = onoff;
			break;
		case SO_BROADCAST:
			connp->conn_broadcast = onoff;
			break;
		case SO_REUSEADDR:
			connp->conn_reuseaddr = onoff;
			break;
		case SO_DGRAM_ERRIND:
			sctp->sctp_dgram_errind = onoff;
			break;
		case SO_SNDBUF:
			if (*i1 > sctps->sctps_max_buf) {
				retval = ENOBUFS;
				break;
			}
			if (*i1 < 0) {
				retval = EINVAL;
				break;
			}
			sctp->sctp_xmit_hiwater = *i1;
			if (sctps->sctps_snd_lowat_fraction != 0)
				sctp->sctp_xmit_lowater =
				    sctp->sctp_xmit_hiwater /
				    sctps->sctps_snd_lowat_fraction;
			break;
		case SO_RCVBUF:
			if (*i1 > sctps->sctps_max_buf) {
				retval = ENOBUFS;
				break;
			}
			/* Silently ignore zero */
			if (*i1 != 0) {
				/*
				 * Insist on a receive window that is at least
				 * sctp_recv_hiwat_minmss * MSS (default 4*MSS)
				 * to avoid funny interactions of Nagle
				 * algorithm, SWS avoidance and delayed
				 * acknowledgement.
				 */
				*i1 = MAX(*i1,
				    sctps->sctps_recv_hiwat_minmss *
				    sctp->sctp_mss);
				sctp->sctp_rwnd = *i1;
				sctp->sctp_irwnd = sctp->sctp_rwnd;
				sctp->sctp_pd_point = sctp->sctp_rwnd;
			}
			/*
			 * XXX should we return the rwnd here
			 * and sctp_opt_get ?
			 */
			break;
		case SO_ALLZONES:
			if (secpolicy_ip(sctp->sctp_credp, OP_CONFIG,
			    B_TRUE)) {
				retval = EACCES;
				break;
			}
			if (sctp->sctp_state >= SCTPS_BOUND) {
				retval = EINVAL;
				break;
			}
			sctp->sctp_allzones = onoff;
			break;
		case SO_MAC_EXEMPT:
			if (secpolicy_net_mac_aware(sctp->sctp_credp) != 0) {
				retval = EACCES;
				break;
			}
			if (sctp->sctp_state >= SCTPS_BOUND) {
				retval = EINVAL;
				break;
			}
			connp->conn_mac_exempt = onoff;
			break;
		default:
			retval = ENOPROTOOPT;
			break;
		}
		break;

	case IPPROTO_SCTP:
		if (inlen < sizeof (int32_t)) {
			retval = EINVAL;
			break;
		}
		switch (name) {
		case SCTP_RTOINFO:
			retval = sctp_set_rtoinfo(sctp, invalp, inlen);
			break;
		case SCTP_ASSOCINFO:
			retval = sctp_set_assocparams(sctp, invalp, inlen);
			break;
		case SCTP_INITMSG:
			retval = sctp_set_initmsg(sctp, invalp, inlen);
			break;
		case SCTP_NODELAY:
			sctp->sctp_ndelay = ONOFF(*i1);
			break;
		case SCTP_AUTOCLOSE:
			if (SEC_TO_TICK(*i1) < 0) {
				retval = EINVAL;
				break;
			}
			/* Convert the number of seconds to ticks. */
			sctp->sctp_autoclose = SEC_TO_TICK(*i1);
			sctp_heartbeat_timer(sctp);
			break;
		case SCTP_SET_PEER_PRIMARY_ADDR:
			retval = sctp_set_peerprim(sctp, invalp, inlen);
			break;
		case SCTP_PRIMARY_ADDR:
			retval = sctp_set_prim(sctp, invalp, inlen);
			break;
		case SCTP_ADAPTION_LAYER: {
			struct sctp_setadaption *ssb;

			if (inlen < sizeof (struct sctp_setadaption)) {
				retval = EINVAL;
				break;
			}
			ssb = (struct sctp_setadaption *)invalp;
			sctp->sctp_send_adaption = 1;
			sctp->sctp_tx_adaption_code = ssb->ssb_adaption_ind;
			break;
		}
		case SCTP_PEER_ADDR_PARAMS:
			retval = sctp_set_peer_addr_params(sctp, invalp,
			    inlen);
			break;
		case SCTP_DEFAULT_SEND_PARAM:
			retval = sctp_set_def_send_params(sctp, invalp, inlen);
			break;
		case SCTP_EVENTS: {
			struct sctp_event_subscribe *ev;

			if (inlen < sizeof (struct sctp_event_subscribe)) {
				retval = EINVAL;
				break;
			}
			ev = (struct sctp_event_subscribe *)invalp;
			sctp->sctp_recvsndrcvinfo =
			    ONOFF(ev->sctp_data_io_event);
			sctp->sctp_recvassocevnt =
			    ONOFF(ev->sctp_association_event);
			sctp->sctp_recvpathevnt =
			    ONOFF(ev->sctp_address_event);
			sctp->sctp_recvsendfailevnt =
			    ONOFF(ev->sctp_send_failure_event);
			sctp->sctp_recvpeererr =
			    ONOFF(ev->sctp_peer_error_event);
			sctp->sctp_recvshutdownevnt =
			    ONOFF(ev->sctp_shutdown_event);
			sctp->sctp_recvpdevnt =
			    ONOFF(ev->sctp_partial_delivery_event);
			sctp->sctp_recvalevnt =
			    ONOFF(ev->sctp_adaption_layer_event);
			break;
		}
		case SCTP_ADD_ADDR:
		case SCTP_REM_ADDR:
			/*
			 * The sctp_t has to be bound first before
			 * the address list can be changed.
			 */
			if (sctp->sctp_state < SCTPS_BOUND) {
				retval = EINVAL;
				break;
			}
			if (sctp->sctp_family == AF_INET) {
				addrcnt = inlen / sizeof (struct sockaddr_in);
			} else {
				ASSERT(sctp->sctp_family == AF_INET6);
				addrcnt = inlen / sizeof (struct sockaddr_in6);
			}
			if (name == SCTP_ADD_ADDR) {
				retval = sctp_bind_add(sctp, invalp, addrcnt,
				    B_TRUE, sctp->sctp_lport);
			} else {
				retval = sctp_bind_del(sctp, invalp, addrcnt,
				    B_TRUE);
			}
			break;
		case SCTP_UC_SWAP: {
			struct sctp_uc_swap *us;

			/*
			 * Change handle & upcalls.
			 */
			if (inlen < sizeof (*us)) {
				retval = EINVAL;
				break;
			}
			us = (struct sctp_uc_swap *)invalp;
			sctp->sctp_ulpd = us->sus_handle;
			bcopy(us->sus_upcalls, &sctp->sctp_upcalls,
			    sizeof (sctp_upcalls_t));
			break;
		}
		case SCTP_PRSCTP:
			sctp->sctp_prsctp_aware = onoff;
			break;
		case SCTP_I_WANT_MAPPED_V4_ADDR:
		case SCTP_MAXSEG:
		case SCTP_DISABLE_FRAGMENTS:
			/* Not yet supported. */
		default:
			retval = ENOPROTOOPT;
			break;
		}
		break;

	case IPPROTO_IP:
		if (sctp->sctp_family != AF_INET) {
			retval = ENOPROTOOPT;
			break;
		}
		if ((name != IP_OPTIONS) && (inlen < sizeof (int32_t))) {
			retval = EINVAL;
			break;
		}
		switch (name) {
		case IP_OPTIONS:
		case T_IP_OPTIONS:
			retval = sctp_opt_set_header(sctp, invalp, inlen);
			break;
		case IP_TOS:
		case T_IP_TOS:
			sctp->sctp_ipha->ipha_type_of_service = (uchar_t)*i1;
			break;
		case IP_TTL:
			sctp->sctp_ipha->ipha_ttl = (uchar_t)*i1;
			break;
		case IP_SEC_OPT:
			/*
			 * We should not allow policy setting after
			 * we start listening for connections.
			 */
			if (sctp->sctp_state >= SCTPS_LISTEN) {
				retval = EINVAL;
			} else {
				retval = ipsec_set_req(sctp->sctp_credp,
				    sctp->sctp_connp, (ipsec_req_t *)invalp);
			}
			break;
		/* IP level options */
		case IP_UNSPEC_SRC:
			connp->conn_unspec_src = onoff;
			break;
		case IP_NEXTHOP: {
			ipaddr_t addr = *i1;
			ipif_t *ipif = NULL;
			ill_t *ill;
			ip_stack_t *ipst = sctps->sctps_netstack->netstack_ip;

			if (secpolicy_ip(sctp->sctp_credp, OP_CONFIG,
			    B_TRUE) == 0) {
				ipif = ipif_lookup_onlink_addr(addr,
				    connp->conn_zoneid, ipst);
				if (ipif == NULL) {
					retval = EHOSTUNREACH;
					break;
				}
				ill = ipif->ipif_ill;
				mutex_enter(&ill->ill_lock);
				if ((ill->ill_state_flags & ILL_CONDEMNED) ||
				    (ipif->ipif_state_flags & IPIF_CONDEMNED)) {
					mutex_exit(&ill->ill_lock);
					ipif_refrele(ipif);
					retval =  EHOSTUNREACH;
					break;
				}
				mutex_exit(&ill->ill_lock);
				ipif_refrele(ipif);
				mutex_enter(&connp->conn_lock);
				connp->conn_nexthop_v4 = addr;
				connp->conn_nexthop_set = B_TRUE;
				mutex_exit(&connp->conn_lock);
			}
			break;
		}
		default:
			retval = ENOPROTOOPT;
			break;
		}
		break;
	case IPPROTO_IPV6: {
		if (sctp->sctp_family != AF_INET6) {
			retval = ENOPROTOOPT;
			break;
		}

		switch (name) {
		case IPV6_UNICAST_HOPS:
			if (inlen < sizeof (int32_t)) {
				retval = EINVAL;
				break;
			}
			if (*i1 < -1 || *i1 > IPV6_MAX_HOPS) {
				retval = EINVAL;
				break;
			}
			if (*i1 == -1) {
				ipp->ipp_unicast_hops =
				    sctps->sctps_ipv6_hoplimit;
				ipp->ipp_fields &= ~IPPF_UNICAST_HOPS;
			} else {
				ipp->ipp_unicast_hops = (uint8_t)*i1;
				ipp->ipp_fields |= IPPF_UNICAST_HOPS;
			}
			retval = sctp_build_hdrs(sctp);
			break;
		case IPV6_UNSPEC_SRC:
			if (inlen < sizeof (int32_t)) {
				retval = EINVAL;
				break;
			}
			connp->conn_unspec_src = onoff;
			break;
		case IPV6_RECVPKTINFO:
			if (inlen < sizeof (int32_t)) {
				retval = EINVAL;
				break;
			}
			if (onoff)
				sctp->sctp_ipv6_recvancillary |=
				    SCTP_IPV6_RECVPKTINFO;
			else
				sctp->sctp_ipv6_recvancillary &=
				    ~SCTP_IPV6_RECVPKTINFO;
			/* Send it with the next msg */
			sctp->sctp_recvifindex = 0;
			connp->conn_ip_recvpktinfo = onoff;
			break;
		case IPV6_RECVHOPLIMIT:
			if (inlen < sizeof (int32_t)) {
				retval = EINVAL;
				break;
			}
			if (onoff)
				sctp->sctp_ipv6_recvancillary |=
				    SCTP_IPV6_RECVHOPLIMIT;
			else
				sctp->sctp_ipv6_recvancillary &=
				    ~SCTP_IPV6_RECVHOPLIMIT;
			sctp->sctp_recvhops = 0xffffffffU;
			connp->conn_ipv6_recvhoplimit = onoff;
			break;
		case IPV6_RECVHOPOPTS:
			if (inlen < sizeof (int32_t)) {
				retval = EINVAL;
				break;
			}
			if (onoff)
				sctp->sctp_ipv6_recvancillary |=
				    SCTP_IPV6_RECVHOPOPTS;
			else
				sctp->sctp_ipv6_recvancillary &=
				    ~SCTP_IPV6_RECVHOPOPTS;
			connp->conn_ipv6_recvhopopts = onoff;
			break;
		case IPV6_RECVDSTOPTS:
			if (inlen < sizeof (int32_t)) {
				retval = EINVAL;
				break;
			}
			if (onoff)
				sctp->sctp_ipv6_recvancillary |=
				    SCTP_IPV6_RECVDSTOPTS;
			else
				sctp->sctp_ipv6_recvancillary &=
				    ~SCTP_IPV6_RECVDSTOPTS;
			connp->conn_ipv6_recvdstopts = onoff;
			break;
		case IPV6_RECVRTHDR:
			if (inlen < sizeof (int32_t)) {
				retval = EINVAL;
				break;
			}
			if (onoff)
				sctp->sctp_ipv6_recvancillary |=
				    SCTP_IPV6_RECVRTHDR;
			else
				sctp->sctp_ipv6_recvancillary &=
				    ~SCTP_IPV6_RECVRTHDR;
			connp->conn_ipv6_recvrthdr = onoff;
			break;
		case IPV6_RECVRTHDRDSTOPTS:
			if (inlen < sizeof (int32_t)) {
				retval = EINVAL;
				break;
			}
			if (onoff)
				sctp->sctp_ipv6_recvancillary |=
				    SCTP_IPV6_RECVRTDSTOPTS;
			else
				sctp->sctp_ipv6_recvancillary &=
				    ~SCTP_IPV6_RECVRTDSTOPTS;
			connp->conn_ipv6_recvrtdstopts = onoff;
			break;
		case IPV6_PKTINFO:
			if (inlen != 0 &&
			    inlen != sizeof (struct in6_pktinfo)) {
				retval = EINVAL;
				break;
			}

			if (inlen == 0) {
				ipp->ipp_fields &= ~(IPPF_IFINDEX |IPPF_ADDR);
			} else  {
				struct in6_pktinfo *pkti;

				pkti = (struct in6_pktinfo *)invalp;
				/* XXX Need to check if the index exists */
				ipp->ipp_ifindex = pkti->ipi6_ifindex;
				ipp->ipp_addr = pkti->ipi6_addr;
				if (ipp->ipp_ifindex != 0)
					ipp->ipp_fields |= IPPF_IFINDEX;
				else
					ipp->ipp_fields &= ~IPPF_IFINDEX;
				if (!IN6_IS_ADDR_UNSPECIFIED(&ipp->ipp_addr))
					ipp->ipp_fields |= IPPF_ADDR;
				else
					ipp->ipp_fields &= ~IPPF_ADDR;
			}
			retval = sctp_build_hdrs(sctp);
			break;
		case IPV6_NEXTHOP: {
			struct sockaddr_in6 *sin6;
			ip_stack_t *ipst = sctps->sctps_netstack->netstack_ip;

			if (inlen != 0 && inlen != sizeof (sin6_t)) {
				retval = EINVAL;
				break;
			}

			if (inlen == 0) {
				ipp->ipp_fields &= ~IPPF_NEXTHOP;
			} else {
				sin6 = (struct sockaddr_in6 *)invalp;
				if (sin6->sin6_family != AF_INET6) {
					retval = EAFNOSUPPORT;
					break;
				}
				if (IN6_IS_ADDR_V4MAPPED(&sin6->sin6_addr)) {
					retval = EADDRNOTAVAIL;
					break;
				}
				ipp->ipp_nexthop = sin6->sin6_addr;
				if (IN6_IS_ADDR_UNSPECIFIED(&sin6->sin6_addr)) {
					ipp->ipp_fields &= ~IPPF_NEXTHOP;
				} else {
					ire_t	*ire;

					ire = ire_route_lookup_v6(
					    &sin6->sin6_addr, NULL, NULL, 0,
					    NULL, NULL, ALL_ZONES, NULL,
					    MATCH_IRE_DEFAULT, ipst);
					if (ire == NULL) {
						retval = EHOSTUNREACH;
						break;
					}
					ire_refrele(ire);
					ipp->ipp_fields |= IPPF_NEXTHOP;
				}
			}
			retval = sctp_build_hdrs(sctp);
			break;
		}
		case IPV6_HOPOPTS: {
			ip6_hbh_t *hopts = (ip6_hbh_t *)invalp;

			if (inlen != 0 &&
			    inlen != (8 * (hopts->ip6h_len + 1))) {
				retval = EINVAL;
				break;
			}

			retval = optcom_pkt_set((uchar_t *)invalp, inlen,
			    B_TRUE, (uchar_t **)&ipp->ipp_hopopts,
			    &ipp->ipp_hopoptslen, sctp->sctp_v6label_len);
			if (retval != 0)
				break;
			if (ipp->ipp_hopoptslen == 0)
				ipp->ipp_fields &= ~IPPF_HOPOPTS;
			else
				ipp->ipp_fields |= IPPF_HOPOPTS;
			retval = sctp_build_hdrs(sctp);
			break;
		}
		case IPV6_RTHDRDSTOPTS: {
			ip6_dest_t *dopts = (ip6_dest_t *)invalp;

			if (inlen != 0 &&
			    inlen != (8 * (dopts->ip6d_len + 1))) {
				retval = EINVAL;
				break;
			}

			retval = optcom_pkt_set((uchar_t *)invalp, inlen,
			    B_TRUE, (uchar_t **)&ipp->ipp_rtdstopts,
			    &ipp->ipp_rtdstoptslen, 0);
			if (retval != 0)
				break;
			if (ipp->ipp_rtdstoptslen == 0)
				ipp->ipp_fields &= ~IPPF_RTDSTOPTS;
			else
				ipp->ipp_fields |= IPPF_RTDSTOPTS;
			retval = sctp_build_hdrs(sctp);
			break;
		}
		case IPV6_DSTOPTS: {
			ip6_dest_t *dopts = (ip6_dest_t *)invalp;

			if (inlen != 0 &&
			    inlen != (8 * (dopts->ip6d_len + 1))) {
				retval = EINVAL;
				break;
			}

			retval = optcom_pkt_set((uchar_t *)invalp, inlen,
			    B_TRUE, (uchar_t **)&ipp->ipp_dstopts,
			    &ipp->ipp_dstoptslen, 0);
			if (retval != 0)
				break;
			if (ipp->ipp_dstoptslen == 0)
				ipp->ipp_fields &= ~IPPF_DSTOPTS;
			else
				ipp->ipp_fields |= IPPF_DSTOPTS;
			retval = sctp_build_hdrs(sctp);
			break;
		}
		case IPV6_RTHDR: {
			ip6_rthdr_t *rt = (ip6_rthdr_t *)invalp;

			if (inlen != 0 &&
			    inlen != (8 * (rt->ip6r_len + 1))) {
				retval = EINVAL;
				break;
			}

			retval = optcom_pkt_set((uchar_t *)invalp, inlen,
			    B_TRUE, (uchar_t **)&ipp->ipp_rthdr,
			    &ipp->ipp_rthdrlen, 0);
			if (retval != 0)
				break;
			if (ipp->ipp_rthdrlen == 0)
				ipp->ipp_fields &= ~IPPF_RTHDR;
			else
				ipp->ipp_fields |= IPPF_RTHDR;
			retval = sctp_build_hdrs(sctp);
			break;
		}
		case IPV6_SEC_OPT:
			/*
			 * We should not allow policy setting after
			 * we start listening for connections.
			 */
			if (sctp->sctp_state >= SCTPS_LISTEN) {
				retval = EINVAL;
			} else {
				retval = ipsec_set_req(sctp->sctp_credp,
				    sctp->sctp_connp, (ipsec_req_t *)invalp);
			}
			break;
		case IPV6_V6ONLY:
			/*
			 * After the bound state, setting the v6only option
			 * is too late.
			 */
			if (sctp->sctp_state >= SCTPS_BOUND) {
				retval = EINVAL;
			} else {
				sctp->sctp_connp->conn_ipv6_v6only = onoff;
			}
			break;
		default:
			retval = ENOPROTOOPT;
			break;
		}
		break;
	}
	default:
		retval = ENOPROTOOPT;
		break;
	}

	WAKE_SCTP(sctp);
	return (retval);
}

/*
 * SCTP exported kernel interface for geting the first source address of
 * a sctp_t.  The parameter addr is assumed to have enough space to hold
 * one socket address.
 */
int
sctp_getsockname(sctp_t *sctp, struct sockaddr *addr, socklen_t *addrlen)
{
	int	err = 0;
	int	addrcnt = 1;
	sin_t	*sin4;
	sin6_t	*sin6;

	ASSERT(sctp != NULL);

	RUN_SCTP(sctp);
	addr->sa_family = sctp->sctp_family;
	switch (sctp->sctp_family) {
	case AF_INET:
		sin4 = (sin_t *)addr;
		if ((sctp->sctp_state <= SCTPS_LISTEN) &&
		    sctp->sctp_bound_to_all) {
			sin4->sin_addr.s_addr = INADDR_ANY;
			sin4->sin_port = sctp->sctp_lport;
		} else {
			err = sctp_getmyaddrs(sctp, sin4, &addrcnt);
			if (err != 0) {
				*addrlen = 0;
				break;
			}
		}
		*addrlen = sizeof (struct sockaddr_in);
		break;
	case AF_INET6:
		sin6 = (sin6_t *)addr;
		if ((sctp->sctp_state <= SCTPS_LISTEN) &&
		    sctp->sctp_bound_to_all) {
			bzero(&sin6->sin6_addr, sizeof (sin6->sin6_addr));
			sin6->sin6_port = sctp->sctp_lport;
		} else {
			err = sctp_getmyaddrs(sctp, sin6, &addrcnt);
			if (err != 0) {
				*addrlen = 0;
				break;
			}
		}
		*addrlen = sizeof (struct sockaddr_in6);
		sin6->sin6_flowinfo = sctp->sctp_ip6h->ip6_vcf &
		    ~IPV6_VERS_AND_FLOW_MASK;
		sin6->sin6_scope_id = 0;
		sin6->__sin6_src_id = 0;
		break;
	}
	WAKE_SCTP(sctp);
	return (err);
}

/*
 * SCTP exported kernel interface for geting the primary peer address of
 * a sctp_t.  The parameter addr is assumed to have enough space to hold
 * one socket address.
 */
int
sctp_getpeername(sctp_t *sctp, struct sockaddr *addr, socklen_t *addrlen)
{
	int	err = 0;
	int	addrcnt = 1;
	sin6_t	*sin6;

	ASSERT(sctp != NULL);

	RUN_SCTP(sctp);
	addr->sa_family = sctp->sctp_family;
	switch (sctp->sctp_family) {
	case AF_INET:
		err = sctp_getpeeraddrs(sctp, addr, &addrcnt);
		if (err != 0) {
			*addrlen = 0;
			break;
		}
		*addrlen = sizeof (struct sockaddr_in);
		break;
	case AF_INET6:
		sin6 = (sin6_t *)addr;
		err = sctp_getpeeraddrs(sctp, sin6, &addrcnt);
		if (err != 0) {
			*addrlen = 0;
			break;
		}
		*addrlen = sizeof (struct sockaddr_in6);
		sin6->sin6_flowinfo = 0;
		sin6->sin6_scope_id = 0;
		sin6->__sin6_src_id = 0;
		break;
	}
	WAKE_SCTP(sctp);
	return (err);
}

/*
 * Return a list of IP addresses of the peer endpoint of this sctp_t.
 * The parameter paddrs is supposed to be either (struct sockaddr_in *) or
 * (struct sockaddr_in6 *) depending on the address family of the sctp_t.
 */
int
sctp_getpeeraddrs(sctp_t *sctp, void *paddrs, int *addrcnt)
{
	int			family;
	struct sockaddr_in	*sin4;
	struct sockaddr_in6	*sin6;
	int			max;
	int			cnt;
	sctp_faddr_t		*fp = sctp->sctp_faddrs;
	in6_addr_t		addr;

	ASSERT(sctp != NULL);

	if (sctp->sctp_faddrs == NULL)
		return (ENOTCONN);

	family = sctp->sctp_family;
	max = *addrcnt;

	/* If we want only one, give the primary */
	if (max == 1) {
		addr = sctp->sctp_primary->faddr;
		switch (family) {
		case AF_INET:
			sin4 = paddrs;
			IN6_V4MAPPED_TO_INADDR(&addr, &sin4->sin_addr);
			sin4->sin_port = sctp->sctp_fport;
			sin4->sin_family = AF_INET;
			break;

		case AF_INET6:
			sin6 = paddrs;
			sin6->sin6_addr = addr;
			sin6->sin6_port = sctp->sctp_fport;
			sin6->sin6_family = AF_INET6;
			break;
		}
		return (0);
	}

	for (cnt = 0; cnt < max && fp != NULL; cnt++, fp = fp->next) {
		addr = fp->faddr;
		switch (family) {
		case AF_INET:
			ASSERT(IN6_IS_ADDR_V4MAPPED(&addr));
			sin4 = (struct sockaddr_in *)paddrs + cnt;
			IN6_V4MAPPED_TO_INADDR(&addr, &sin4->sin_addr);
			sin4->sin_port = sctp->sctp_fport;
			sin4->sin_family = AF_INET;
			break;
		case AF_INET6:
			sin6 = (struct sockaddr_in6 *)paddrs + cnt;
			sin6->sin6_addr = addr;
			sin6->sin6_port = sctp->sctp_fport;
			sin6->sin6_family = AF_INET6;
			break;
		}
	}
	*addrcnt = cnt;
	return (0);
}
