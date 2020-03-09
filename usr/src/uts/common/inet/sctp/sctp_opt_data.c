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

/*
 * Copyright (c) 2018, Joyent, Inc.
 */

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
#include <inet/proto_set.h>
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
	conn_t	*connp = sctp->sctp_connp;

	sstat->sstat_state = sctp->sctp_state;
	sstat->sstat_rwnd = sctp->sctp_frwnd;

	sp = &sstat->sstat_primary;
	if (!sctp->sctp_primary) {
		bzero(sp, sizeof (*sp));
		goto noprim;
	}
	fp = sctp->sctp_primary;

	if (fp->sf_isv4) {
		sin = (struct sockaddr_in *)&sp->spinfo_address;
		sin->sin_family = AF_INET;
		sin->sin_port = connp->conn_fport;
		IN6_V4MAPPED_TO_INADDR(&fp->sf_faddr, &sin->sin_addr);
		sp->spinfo_mtu = sctp->sctp_hdr_len;
	} else {
		sin6 = (struct sockaddr_in6 *)&sp->spinfo_address;
		sin6->sin6_family = AF_INET6;
		sin6->sin6_port = connp->conn_fport;
		sin6->sin6_addr = fp->sf_faddr;
		sp->spinfo_mtu = sctp->sctp_hdr6_len;
	}
	sp->spinfo_state = fp->sf_state == SCTP_FADDRS_ALIVE ? SCTP_ACTIVE :
	    SCTP_INACTIVE;
	sp->spinfo_cwnd = fp->sf_cwnd;
	sp->spinfo_srtt = fp->sf_srtt;
	sp->spinfo_rto = fp->sf_rto;
	sp->spinfo_mtu += fp->sf_pmss;

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

	infop->spinfo_state = (fp->sf_state == SCTP_FADDRS_ALIVE) ?
	    SCTP_ACTIVE : SCTP_INACTIVE;
	infop->spinfo_cwnd = fp->sf_cwnd;
	infop->spinfo_srtt = TICK_TO_MSEC(fp->sf_srtt);
	infop->spinfo_rto = TICK_TO_MSEC(fp->sf_rto);
	infop->spinfo_mtu = fp->sf_pmss;

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
sctp_set_rtoinfo(sctp_t *sctp, const void *invalp)
{
	const struct sctp_rtoinfo *srto;
	boolean_t ispriv;
	sctp_stack_t	*sctps = sctp->sctp_sctps;
	conn_t		*connp = sctp->sctp_connp;
	uint32_t	new_min, new_max;

	srto = invalp;

	ispriv = secpolicy_ip_config(connp->conn_cred, B_TRUE) == 0;

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

	new_min = (srto->srto_min != 0) ? srto->srto_min : sctp->sctp_rto_min;
	new_max = (srto->srto_max != 0) ? srto->srto_max : sctp->sctp_rto_max;
	if (new_max < new_min) {
		return (EINVAL);
	}

	if (srto->srto_initial != 0) {
		sctp->sctp_rto_initial = MSEC_TO_TICK(srto->srto_initial);
	}

	/* Ensure that sctp_rto_max will never be zero. */
	if (srto->srto_max != 0) {
		sctp->sctp_rto_max = MAX(MSEC_TO_TICK(srto->srto_max), 1);
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
	for (i = 0, fp = sctp->sctp_faddrs; fp != NULL; fp = fp->sf_next) {
		i++;
	}
	sap->sasoc_number_peer_destinations = i;
	sap->sasoc_peer_rwnd = sctp->sctp_frwnd;
	sap->sasoc_local_rwnd = sctp->sctp_rwnd;
	sap->sasoc_cookie_life = TICK_TO_MSEC(sctp->sctp_cookie_lifetime);

	return (sizeof (*sap));
}

static int
sctp_set_assocparams(sctp_t *sctp, const void *invalp)
{
	const struct sctp_assocparams *sap = invalp;
	uint32_t sum = 0;
	sctp_faddr_t *fp;
	sctp_stack_t	*sctps = sctp->sctp_sctps;

	if (sap->sasoc_asocmaxrxt) {
		if (sctp->sctp_faddrs) {
			/*
			 * Bounds check: as per rfc2960, assoc max retr cannot
			 * exceed the sum of all individual path max retr's.
			 */
			for (fp = sctp->sctp_faddrs; fp; fp = fp->sf_next) {
				sum += fp->sf_max_retr;
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
	si->sinit_max_init_timeo = TICK_TO_MSEC(sctp->sctp_rto_max_init);

	return (sizeof (*si));
}

static int
sctp_set_initmsg(sctp_t *sctp, const void *invalp, uint_t inlen)
{
	const struct sctp_initmsg *si = invalp;
	sctp_stack_t	*sctps = sctp->sctp_sctps;
	conn_t		*connp = sctp->sctp_connp;

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
	    (secpolicy_ip_config(connp->conn_cred, B_TRUE) != 0 &&
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
		sctp->sctp_rto_max_init =
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
		spp->spp_hbinterval = TICK_TO_MSEC(fp->sf_hb_interval);
		spp->spp_pathmaxrxt = fp->sf_max_retr;
	} else {
		spp->spp_hbinterval = TICK_TO_MSEC(sctp->sctp_hb_interval);
		spp->spp_pathmaxrxt = sctp->sctp_pp_max_rxt;
	}
	return (sizeof (*spp));
}

static int
sctp_set_peer_addr_params(sctp_t *sctp, const void *invalp)
{
	const struct sctp_paddrparams *spp = invalp;
	sctp_faddr_t *fp, *fp2;
	int retval;
	uint32_t sum = 0;
	int64_t now;
	sctp_stack_t	*sctps = sctp->sctp_sctps;

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
		for (fp2 = sctp->sctp_faddrs; fp2; fp2 = fp2->sf_next) {
			if (!fp || fp2 == fp) {
				sum += spp->spp_pathmaxrxt;
			} else {
				sum += fp2->sf_max_retr;
			}
		}
		if (sctp->sctp_pa_max_rxt > sum) {
			return (EINVAL);
		}
	}

	now = ddi_get_lbolt64();
	if (fp != NULL) {
		if (spp->spp_hbinterval == UINT32_MAX) {
			/*
			 * Send heartbeat immediatelly, don't modify the
			 * current setting.
			 */
			sctp_send_heartbeat(sctp, fp);
		} else {
			fp->sf_hb_interval = MSEC_TO_TICK(spp->spp_hbinterval);
			fp->sf_hb_expiry = now + SET_HB_INTVL(fp);
			/*
			 * Restart the heartbeat timer using the new intrvl.
			 * We need to call sctp_heartbeat_timer() to set
			 * the earliest heartbeat expiry time.
			 */
			sctp_heartbeat_timer(sctp);
		}
		if (spp->spp_pathmaxrxt) {
			fp->sf_max_retr = spp->spp_pathmaxrxt;
		}
	} else {
		for (fp2 = sctp->sctp_faddrs; fp2 != NULL; fp2 = fp2->sf_next) {
			if (spp->spp_hbinterval == UINT32_MAX) {
				/*
				 * Send heartbeat immediatelly, don't modify
				 * the current setting.
				 */
				sctp_send_heartbeat(sctp, fp2);
			} else {
				fp2->sf_hb_interval = MSEC_TO_TICK(
				    spp->spp_hbinterval);
				fp2->sf_hb_expiry = now + SET_HB_INTVL(fp2);
			}
			if (spp->spp_pathmaxrxt) {
				fp2->sf_max_retr = spp->spp_pathmaxrxt;
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
sctp_set_def_send_params(sctp_t *sctp, const void *invalp)
{
	const struct sctp_sndrcvinfo *sinfo = invalp;

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
sctp_set_prim(sctp_t *sctp, const void *invalp)
{
	const struct	sctp_setpeerprim *pp = invalp;
	int		retval;
	sctp_faddr_t	*fp;

	retval = sctp_find_peer_fp(sctp, &pp->sspp_addr, &fp);
	if (retval)
		return (retval);

	if (fp == NULL)
		return (EINVAL);
	if (fp == sctp->sctp_primary)
		return (0);
	sctp->sctp_primary = fp;

	/* Only switch current if fp is alive */
	if (fp->sf_state != SCTP_FADDRS_ALIVE || fp == sctp->sctp_current) {
		return (0);
	}
	sctp_set_faddr_current(sctp, fp);

	return (0);
}

/*
 * Table of all known options handled on a SCTP protocol stack.
 *
 * Note: This table contains options processed by both SCTP and IP levels
 *       and is the superset of options that can be performed on a SCTP and IP
 *       stack.
 */
opdes_t	sctp_opt_arr[] = {

{ SO_LINGER,	SOL_SOCKET, OA_RW, OA_RW, OP_NP, 0,
	sizeof (struct linger), 0 },

{ SO_DEBUG,	SOL_SOCKET, OA_RW, OA_RW, OP_NP, 0, sizeof (int), 0 },
{ SO_KEEPALIVE,	SOL_SOCKET, OA_RW, OA_RW, OP_NP, 0, sizeof (int), 0 },
{ SO_DONTROUTE,	SOL_SOCKET, OA_RW, OA_RW, OP_NP, 0, sizeof (int), 0 },
{ SO_USELOOPBACK, SOL_SOCKET, OA_RW, OA_RW, OP_NP, 0, sizeof (int), 0
	},
{ SO_BROADCAST,	SOL_SOCKET, OA_RW, OA_RW, OP_NP, 0, sizeof (int), 0 },
{ SO_REUSEADDR, SOL_SOCKET, OA_RW, OA_RW, OP_NP, 0, sizeof (int), 0 },
{ SO_OOBINLINE, SOL_SOCKET, OA_RW, OA_RW, OP_NP, 0, sizeof (int), 0 },
{ SO_TYPE,	SOL_SOCKET, OA_R, OA_R, OP_NP, 0, sizeof (int), 0 },
{ SO_SNDBUF,	SOL_SOCKET, OA_RW, OA_RW, OP_NP, 0, sizeof (int), 0 },
{ SO_RCVBUF,	SOL_SOCKET, OA_RW, OA_RW, OP_NP, 0, sizeof (int), 0 },
{ SO_DGRAM_ERRIND, SOL_SOCKET, OA_RW, OA_RW, OP_NP, 0, sizeof (int), 0
	},
{ SO_SND_COPYAVOID, SOL_SOCKET, OA_RW, OA_RW, OP_NP, 0, sizeof (int), 0 },
{ SO_ANON_MLP, SOL_SOCKET, OA_RW, OA_RW, OP_NP, 0, sizeof (int),
	0 },
{ SO_MAC_EXEMPT, SOL_SOCKET, OA_RW, OA_RW, OP_NP, 0, sizeof (int),
	0 },
{ SO_ALLZONES, SOL_SOCKET, OA_R, OA_RW, OP_CONFIG, 0, sizeof (int),
	0 },
{ SO_EXCLBIND, SOL_SOCKET, OA_RW, OA_RW, OP_NP, 0, sizeof (int), 0 },

{ SO_DOMAIN,	SOL_SOCKET, OA_R, OA_R, OP_NP, 0, sizeof (int), 0 },

{ SO_PROTOTYPE,	SOL_SOCKET, OA_R, OA_R, OP_NP, 0, sizeof (int), 0 },

{ SCTP_ADAPTATION_LAYER, IPPROTO_SCTP, OA_RW, OA_RW, OP_NP, 0,
	sizeof (struct sctp_setadaptation), 0 },
{ SCTP_ADD_ADDR, IPPROTO_SCTP, OA_RW, OA_RW, OP_NP, OP_VARLEN,
	sizeof (int), 0 },
{ SCTP_ASSOCINFO, IPPROTO_SCTP, OA_RW, OA_RW, OP_NP, 0,
	sizeof (struct sctp_assocparams), 0 },
{ SCTP_AUTOCLOSE, IPPROTO_SCTP, OA_RW, OA_RW, OP_NP, 0, sizeof (int), 0 },
{ SCTP_DEFAULT_SEND_PARAM, IPPROTO_SCTP, OA_RW, OA_RW, OP_NP, 0,
	sizeof (struct sctp_sndrcvinfo), 0 },
{ SCTP_DISABLE_FRAGMENTS, IPPROTO_SCTP, OA_RW, OA_RW, OP_NP, 0,
	sizeof (int), 0 },
{ SCTP_EVENTS, IPPROTO_SCTP, OA_RW, OA_RW, OP_NP, 0,
	sizeof (struct sctp_event_subscribe), 0 },
{ SCTP_GET_LADDRS, IPPROTO_SCTP, OA_R, OA_R, OP_NP, OP_VARLEN,
	sizeof (int), 0 },
{ SCTP_GET_NLADDRS, IPPROTO_SCTP, OA_R, OA_R, OP_NP, 0, sizeof (int), 0 },
{ SCTP_GET_NPADDRS, IPPROTO_SCTP, OA_R, OA_R, OP_NP, 0, sizeof (int), 0 },
{ SCTP_GET_PADDRS, IPPROTO_SCTP, OA_R, OA_R, OP_NP, OP_VARLEN,
	sizeof (int), 0 },
{ SCTP_GET_PEER_ADDR_INFO, IPPROTO_SCTP, OA_R, OA_R, OP_NP, 0,
	sizeof (struct sctp_paddrinfo), 0 },
{ SCTP_INITMSG, IPPROTO_SCTP, OA_RW, OA_RW, OP_NP, 0,
	sizeof (struct sctp_initmsg), 0 },
{ SCTP_I_WANT_MAPPED_V4_ADDR, IPPROTO_SCTP, OA_RW, OA_RW, OP_NP, 0,
	sizeof (int), 0 },
{ SCTP_MAXSEG, IPPROTO_SCTP, OA_RW, OA_RW, OP_NP, 0, sizeof (int), 0 },
{ SCTP_NODELAY, IPPROTO_SCTP, OA_RW, OA_RW, OP_NP, 0, sizeof (int), 0 },
{ SCTP_PEER_ADDR_PARAMS, IPPROTO_SCTP, OA_RW, OA_RW, OP_NP, 0,
	sizeof (struct sctp_paddrparams), 0 },
{ SCTP_PRIMARY_ADDR, IPPROTO_SCTP, OA_W, OA_W, OP_NP, 0,
	sizeof (struct sctp_setpeerprim), 0 },
{ SCTP_PRSCTP, IPPROTO_SCTP, OA_RW, OA_RW, OP_NP, 0, sizeof (int), 0 },
{ SCTP_GET_ASSOC_STATS, IPPROTO_SCTP, OA_R, OA_R, OP_NP, 0,
	sizeof (sctp_assoc_stats_t), 0 },
{ SCTP_REM_ADDR, IPPROTO_SCTP, OA_RW, OA_RW, OP_NP, OP_VARLEN,
	sizeof (int), 0 },
{ SCTP_RTOINFO, IPPROTO_SCTP, OA_RW, OA_RW, OP_NP, 0,
	sizeof (struct sctp_rtoinfo), 0 },
{ SCTP_SET_PEER_PRIMARY_ADDR, IPPROTO_SCTP, OA_W, OA_W, OP_NP, 0,
	sizeof (struct sctp_setprim), 0 },
{ SCTP_STATUS, IPPROTO_SCTP, OA_R, OA_R, OP_NP, 0,
	sizeof (struct sctp_status), 0 },
{ SCTP_UC_SWAP, IPPROTO_SCTP, OA_W, OA_W, OP_NP, 0,
	sizeof (struct sctp_uc_swap), 0 },

{ IP_OPTIONS,	IPPROTO_IP, OA_RW, OA_RW, OP_NP,
	(OP_VARLEN|OP_NODEFAULT),
	40, -1 /* not initialized */ },
{ T_IP_OPTIONS,	IPPROTO_IP, OA_RW, OA_RW, OP_NP,
	(OP_VARLEN|OP_NODEFAULT),
	40, -1 /* not initialized */ },

{ IP_TOS,	IPPROTO_IP, OA_RW, OA_RW, OP_NP, 0, sizeof (int), 0 },
{ T_IP_TOS,	IPPROTO_IP, OA_RW, OA_RW, OP_NP, 0, sizeof (int), 0 },
{ IP_TTL,	IPPROTO_IP, OA_RW, OA_RW, OP_NP, OP_DEF_FN,
	sizeof (int), -1 /* not initialized */ },

{ IP_SEC_OPT, IPPROTO_IP, OA_RW, OA_RW, OP_NP, OP_NODEFAULT,
	sizeof (ipsec_req_t), -1 /* not initialized */ },

{ IP_BOUND_IF, IPPROTO_IP, OA_RW, OA_RW, OP_NP, 0,
	sizeof (int),	0 /* no ifindex */ },

{ IP_UNSPEC_SRC, IPPROTO_IP, OA_R, OA_RW, OP_RAW, 0,
	sizeof (int), 0 },

{ IPV6_UNICAST_HOPS, IPPROTO_IPV6, OA_RW, OA_RW, OP_NP, OP_DEF_FN,
	sizeof (int), -1 /* not initialized */ },

{ IPV6_BOUND_IF, IPPROTO_IPV6, OA_RW, OA_RW, OP_NP, 0,
	sizeof (int),	0 /* no ifindex */ },

{ IP_DONTFRAG, IPPROTO_IP, OA_RW, OA_RW, OP_NP, 0, sizeof (int), 0 },

{ IP_NEXTHOP, IPPROTO_IP, OA_R, OA_RW, OP_CONFIG, 0,
	sizeof (in_addr_t),	-1 /* not initialized  */ },

{ IPV6_UNSPEC_SRC, IPPROTO_IPV6, OA_R, OA_RW, OP_RAW, 0,
	sizeof (int), 0 },

{ IPV6_PKTINFO, IPPROTO_IPV6, OA_RW, OA_RW, OP_NP,
	(OP_NODEFAULT|OP_VARLEN),
	sizeof (struct in6_pktinfo), -1 /* not initialized */ },
{ IPV6_NEXTHOP, IPPROTO_IPV6, OA_RW, OA_RW, OP_NP,
	OP_NODEFAULT,
	sizeof (sin6_t), -1 /* not initialized */ },
{ IPV6_HOPOPTS, IPPROTO_IPV6, OA_RW, OA_RW, OP_NP,
	(OP_VARLEN|OP_NODEFAULT), 255*8,
	-1 /* not initialized */ },
{ IPV6_DSTOPTS, IPPROTO_IPV6, OA_RW, OA_RW, OP_NP,
	(OP_VARLEN|OP_NODEFAULT), 255*8,
	-1 /* not initialized */ },
{ IPV6_RTHDRDSTOPTS, IPPROTO_IPV6, OA_RW, OA_RW, OP_NP,
	(OP_VARLEN|OP_NODEFAULT), 255*8,
	-1 /* not initialized */ },
{ IPV6_RTHDR, IPPROTO_IPV6, OA_RW, OA_RW, OP_NP,
	(OP_VARLEN|OP_NODEFAULT), 255*8,
	-1 /* not initialized */ },
{ IPV6_TCLASS, IPPROTO_IPV6, OA_RW, OA_RW, OP_NP,
	OP_NODEFAULT,
	sizeof (int), -1 /* not initialized */ },
{ IPV6_PATHMTU, IPPROTO_IPV6, OA_RW, OA_RW, OP_NP,
	OP_NODEFAULT,
	sizeof (struct ip6_mtuinfo), -1 /* not initialized */ },
{ IPV6_DONTFRAG, IPPROTO_IPV6, OA_RW, OA_RW, OP_NP, 0,
	sizeof (int), 0 },
{ IPV6_USE_MIN_MTU, IPPROTO_IPV6, OA_RW, OA_RW, OP_NP, 0,
	sizeof (int), 0 },
{ IPV6_V6ONLY, IPPROTO_IPV6, OA_RW, OA_RW, OP_NP, 0,
	sizeof (int), 0 },

/* Enable receipt of ancillary data */
{ IPV6_RECVPKTINFO, IPPROTO_IPV6, OA_RW, OA_RW, OP_NP, 0,
	sizeof (int), 0 },
{ IPV6_RECVHOPLIMIT, IPPROTO_IPV6, OA_RW, OA_RW, OP_NP, 0,
	sizeof (int), 0 },
{ IPV6_RECVTCLASS, IPPROTO_IPV6, OA_RW, OA_RW, OP_NP, 0,
	sizeof (int), 0 },
{ IPV6_RECVHOPOPTS, IPPROTO_IPV6, OA_RW, OA_RW, OP_NP, 0,
	sizeof (int), 0 },
{ _OLD_IPV6_RECVDSTOPTS, IPPROTO_IPV6, OA_RW, OA_RW, OP_NP, 0,
	sizeof (int), 0 },
{ IPV6_RECVDSTOPTS, IPPROTO_IPV6, OA_RW, OA_RW, OP_NP, 0,
	sizeof (int), 0 },
{ IPV6_RECVRTHDR, IPPROTO_IPV6, OA_RW, OA_RW, OP_NP, 0,
	sizeof (int), 0 },
{ IPV6_RECVRTHDRDSTOPTS, IPPROTO_IPV6, OA_RW, OA_RW, OP_NP, 0,
	sizeof (int), 0 },
{ IPV6_RECVTCLASS, IPPROTO_IPV6, OA_RW, OA_RW, OP_NP, 0,
	sizeof (int), 0 },

{ IPV6_SEC_OPT, IPPROTO_IPV6, OA_RW, OA_RW, OP_NP, OP_NODEFAULT,
	sizeof (ipsec_req_t), -1 /* not initialized */ },
{ IPV6_SRC_PREFERENCES, IPPROTO_IPV6, OA_RW, OA_RW, OP_NP, 0,
	sizeof (uint32_t), IPV6_PREFER_SRC_DEFAULT },
};

uint_t sctp_opt_arr_size = A_CNT(sctp_opt_arr);

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
	conn_t	*connp = sctp->sctp_connp;
	conn_opt_arg_t	coas;

	coas.coa_connp = connp;
	coas.coa_ixa = connp->conn_ixa;
	coas.coa_ipp = &connp->conn_xmit_ipp;

	/* In most cases, the return buffer is just an int */
	*optlen = sizeof (int32_t);

	RUN_SCTP(sctp);

	if (connp->conn_state_flags & CONN_CLOSING) {
		WAKE_SCTP(sctp);
		return (EINVAL);
	}

	/*
	 * Check that the level and name are supported by SCTP, and that
	 * the length and credentials are ok.
	 */
	retval = proto_opt_check(level, name, buflen, NULL, sctp_opt_arr,
	    sctp_opt_arr_size, B_FALSE, B_TRUE, connp->conn_cred);
	if (retval != 0) {
		WAKE_SCTP(sctp);
		if (retval < 0) {
			retval = proto_tlitosyserr(-retval);
		}
		return (retval);
	}

	switch (level) {
	case IPPROTO_SCTP:
		switch (name) {
		case SCTP_RTOINFO:
			*optlen = sctp_get_rtoinfo(sctp, ptr);
			break;
		case SCTP_ASSOCINFO:
			*optlen = sctp_get_assocparams(sctp, ptr);
			break;
		case SCTP_INITMSG:
			*optlen = sctp_get_initmsg(sctp, ptr);
			break;
		case SCTP_NODELAY:
			*i1 = sctp->sctp_ndelay;
			break;
		case SCTP_AUTOCLOSE:
			*i1 = TICK_TO_SEC(sctp->sctp_autoclose);
			break;
		case SCTP_ADAPTATION_LAYER:
			((struct sctp_setadaptation *)ptr)->ssb_adaptation_ind =
			    sctp->sctp_tx_adaptation_code;
			break;
		case SCTP_PEER_ADDR_PARAMS:
			*optlen = sctp_get_peer_addr_params(sctp, ptr);
			break;
		case SCTP_DEFAULT_SEND_PARAM:
			*optlen = sctp_get_def_send_params(sctp, ptr);
			break;
		case SCTP_EVENTS: {
			struct sctp_event_subscribe *ev;

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
			ev->sctp_adaptation_layer_event =
			    ONOFF(sctp->sctp_recvalevnt);
			*optlen = sizeof (struct sctp_event_subscribe);
			break;
		}
		case SCTP_STATUS:
			*optlen = sctp_get_status(sctp, ptr);
			break;
		case SCTP_GET_PEER_ADDR_INFO:
			retval = sctp_get_paddrinfo(sctp, ptr, optlen);
			break;
		case SCTP_GET_NLADDRS:
			*(int32_t *)ptr = sctp->sctp_nsaddrs;
			break;
		case SCTP_GET_LADDRS: {
			int addr_cnt;
			int addr_size;

			if (connp->conn_family == AF_INET)
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
			    i++, fp = fp->sf_next)
				;
			*(int32_t *)ptr = i;
			break;
		}
		case SCTP_GET_PADDRS: {
			int addr_cnt;
			int addr_size;

			if (connp->conn_family == AF_INET)
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

		case SCTP_GET_ASSOC_STATS: {
			sctp_assoc_stats_t *sas;

			sas = (sctp_assoc_stats_t *)ptr;

			/*
			 * Copy the current stats to the stats struct.
			 * For stats which can be reset by snmp users
			 * add the cumulative and current stats for
			 * the raw totals to output to the user.
			 */
			sas->sas_gapcnt = sctp->sctp_gapcnt;
			sas->sas_outseqtsns = sctp->sctp_outseqtsns;
			sas->sas_osacks = sctp->sctp_osacks;
			sas->sas_isacks = sctp->sctp_isacks;
			sas->sas_idupchunks = sctp->sctp_idupchunks;
			sas->sas_rtxchunks =  sctp->sctp_rxtchunks +
			    sctp->sctp_cum_rxtchunks;
			sas->sas_octrlchunks = sctp->sctp_obchunks +
			    sctp->sctp_cum_obchunks;
			sas->sas_ictrlchunks = sctp->sctp_ibchunks +
			    sctp->sctp_cum_ibchunks;
			sas->sas_oodchunks = sctp->sctp_odchunks +
			    sctp->sctp_cum_odchunks;
			sas->sas_iodchunks = sctp->sctp_idchunks +
			    sctp->sctp_cum_idchunks;
			sas->sas_ouodchunks = sctp->sctp_oudchunks +
			    sctp->sctp_cum_oudchunks;
			sas->sas_iuodchunks = sctp->sctp_iudchunks +
			    sctp->sctp_cum_iudchunks;

			/*
			 * Copy out the maximum observed RTO since the
			 * time this data was last requested
			 */
			if (sctp->sctp_maxrto == 0) {
				/* unchanged during obervation period */
				sas->sas_maxrto = sctp->sctp_prev_maxrto;
			} else {
				/* record new period maximum */
				sas->sas_maxrto = sctp->sctp_maxrto;
			}
			/* Record the value sent to the user this period */
			sctp->sctp_prev_maxrto = sas->sas_maxrto;

			/* Mark beginning of a new observation period */
			sctp->sctp_maxrto = 0;

			*optlen = sizeof (sctp_assoc_stats_t);
			break;
		}
		case SCTP_I_WANT_MAPPED_V4_ADDR:
		case SCTP_MAXSEG:
		case SCTP_DISABLE_FRAGMENTS:
		default:
			/* Not yet supported. */
			retval = ENOPROTOOPT;
			break;
		}
		WAKE_SCTP(sctp);
		return (retval);
	case IPPROTO_IP:
		if (connp->conn_family != AF_INET) {
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
			int	opt_len;
			uchar_t	obuf[SCTP_MAX_IP_OPTIONS_LENGTH + IP_ADDR_LEN];

			opt_len = ip_opt_get_user(connp, obuf);
			ASSERT(opt_len <= sizeof (obuf));

			if (buflen < opt_len) {
				/* Silently truncate */
				opt_len = buflen;
			}
			*optlen = opt_len;
			bcopy(obuf, ptr, opt_len);
			WAKE_SCTP(sctp);
			return (0);
		}
		default:
			break;
		}
		break;
	}
	mutex_enter(&connp->conn_lock);
	retval = conn_opt_get(&coas, level, name, ptr);
	mutex_exit(&connp->conn_lock);
	WAKE_SCTP(sctp);
	if (retval == -1)
		return (EINVAL);
	*optlen = retval;
	return (0);
}

int
sctp_set_opt(sctp_t *sctp, int level, int name, const void *invalp,
    socklen_t inlen)
{
	int		*i1 = (int *)invalp;
	boolean_t	onoff;
	int		retval = 0, addrcnt;
	conn_t		*connp = sctp->sctp_connp;
	sctp_stack_t	*sctps = sctp->sctp_sctps;
	conn_opt_arg_t	coas;

	coas.coa_connp = connp;
	coas.coa_ixa = connp->conn_ixa;
	coas.coa_ipp = &connp->conn_xmit_ipp;
	coas.coa_ancillary = B_FALSE;
	coas.coa_changed = 0;

	/* In all cases, the size of the option must be bigger than int */
	if (inlen >= sizeof (int32_t)) {
		onoff = ONOFF(*i1);
	} else {
		return (EINVAL);
	}

	retval = 0;

	RUN_SCTP(sctp);

	if (connp->conn_state_flags & CONN_CLOSING) {
		WAKE_SCTP(sctp);
		return (EINVAL);
	}

	/*
	 * Check that the level and name are supported by SCTP, and that
	 * the length an credentials are ok.
	 */
	retval = proto_opt_check(level, name, inlen, NULL, sctp_opt_arr,
	    sctp_opt_arr_size, B_TRUE, B_FALSE, connp->conn_cred);
	if (retval != 0) {
		if (retval < 0) {
			retval = proto_tlitosyserr(-retval);
		}
		goto done;
	}

	/* Note: both SCTP and TCP interpret l_linger as being in seconds */
	switch (level) {
	case SOL_SOCKET:
		switch (name) {
		case SO_SNDBUF:
			if (*i1 > sctps->sctps_max_buf) {
				retval = ENOBUFS;
				goto done;
			}
			if (*i1 < 0) {
				retval = EINVAL;
				goto done;
			}
			connp->conn_sndbuf = *i1;
			if (sctps->sctps_snd_lowat_fraction != 0) {
				connp->conn_sndlowat = connp->conn_sndbuf /
				    sctps->sctps_snd_lowat_fraction;
			}
			goto done;
		case SO_RCVBUF:
			if (*i1 > sctps->sctps_max_buf) {
				retval = ENOBUFS;
				goto done;
			}
			/* Silently ignore zero */
			if (*i1 != 0) {
				struct sock_proto_props sopp;

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
				/*
				 * Note that sctp_rwnd is modified by the
				 * protocol and here we just whack it.
				 */
				connp->conn_rcvbuf = sctp->sctp_rwnd = *i1;
				sctp->sctp_arwnd = sctp->sctp_rwnd;
				sctp->sctp_pd_point = sctp->sctp_rwnd;

				sopp.sopp_flags = SOCKOPT_RCVHIWAT;
				sopp.sopp_rxhiwat = connp->conn_rcvbuf;
				sctp->sctp_ulp_prop(sctp->sctp_ulpd, &sopp);

			}
			/*
			 * XXX should we return the rwnd here
			 * and sctp_opt_get ?
			 */
			goto done;
		case SO_ALLZONES:
			if (sctp->sctp_state >= SCTPS_BOUND) {
				retval = EINVAL;
				goto done;
			}
			break;
		case SO_MAC_EXEMPT:
			if (sctp->sctp_state >= SCTPS_BOUND) {
				retval = EINVAL;
				goto done;
			}
			break;
		}
		break;

	case IPPROTO_SCTP:
		switch (name) {
		case SCTP_RTOINFO:
			retval = sctp_set_rtoinfo(sctp, invalp);
			break;
		case SCTP_ASSOCINFO:
			retval = sctp_set_assocparams(sctp, invalp);
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
			retval = sctp_set_peerprim(sctp, invalp);
			break;
		case SCTP_PRIMARY_ADDR:
			retval = sctp_set_prim(sctp, invalp);
			break;
		case SCTP_ADAPTATION_LAYER: {
			struct sctp_setadaptation *ssb;

			ssb = (struct sctp_setadaptation *)invalp;
			sctp->sctp_send_adaptation = 1;
			sctp->sctp_tx_adaptation_code = ssb->ssb_adaptation_ind;
			break;
		}
		case SCTP_PEER_ADDR_PARAMS:
			retval = sctp_set_peer_addr_params(sctp, invalp);
			break;
		case SCTP_DEFAULT_SEND_PARAM:
			retval = sctp_set_def_send_params(sctp, invalp);
			break;
		case SCTP_EVENTS: {
			struct sctp_event_subscribe *ev;

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
			    ONOFF(ev->sctp_adaptation_layer_event);
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
			if (connp->conn_family == AF_INET) {
				addrcnt = inlen / sizeof (struct sockaddr_in);
			} else {
				ASSERT(connp->conn_family == AF_INET6);
				addrcnt = inlen / sizeof (struct sockaddr_in6);
			}
			if (name == SCTP_ADD_ADDR) {
				retval = sctp_bind_add(sctp, invalp, addrcnt,
				    B_TRUE, connp->conn_lport);
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
			us = (struct sctp_uc_swap *)invalp;
			sctp->sctp_ulpd = us->sus_handle;
			sctp->sctp_upcalls = us->sus_upcalls;
			break;
		}
		case SCTP_PRSCTP:
			sctp->sctp_prsctp_aware = onoff;
			break;
		case SCTP_I_WANT_MAPPED_V4_ADDR:
		case SCTP_MAXSEG:
		case SCTP_DISABLE_FRAGMENTS:
			/* Not yet supported. */
			retval = ENOPROTOOPT;
			break;
		}
		goto done;

	case IPPROTO_IP:
		if (connp->conn_family != AF_INET) {
			retval = ENOPROTOOPT;
			goto done;
		}
		switch (name) {
		case IP_SEC_OPT:
			/*
			 * We should not allow policy setting after
			 * we start listening for connections.
			 */
			if (sctp->sctp_state >= SCTPS_LISTEN) {
				retval = EINVAL;
				goto done;
			}
			break;
		}
		break;
	case IPPROTO_IPV6:
		if (connp->conn_family != AF_INET6) {
			retval = EINVAL;
			goto done;
		}

		switch (name) {
		case IPV6_RECVPKTINFO:
			/* Send it with the next msg */
			sctp->sctp_recvifindex = 0;
			break;
		case IPV6_RECVTCLASS:
			/* Force it to be sent up with the next msg */
			sctp->sctp_recvtclass = 0xffffffffU;
			break;
		case IPV6_RECVHOPLIMIT:
			/* Force it to be sent up with the next msg */
			sctp->sctp_recvhops = 0xffffffffU;
			break;
		case IPV6_SEC_OPT:
			/*
			 * We should not allow policy setting after
			 * we start listening for connections.
			 */
			if (sctp->sctp_state >= SCTPS_LISTEN) {
				retval = EINVAL;
				goto done;
			}
			break;
		case IPV6_V6ONLY:
			/*
			 * After the bound state, setting the v6only option
			 * is too late.
			 */
			if (sctp->sctp_state >= SCTPS_BOUND) {
				retval = EINVAL;
				goto done;
			}
			break;
		}
		break;
	}

	retval = conn_opt_set(&coas, level, name, inlen, (uchar_t *)invalp,
	    B_FALSE, connp->conn_cred);
	if (retval != 0)
		goto done;

	if (coas.coa_changed & COA_ROUTE_CHANGED) {
		sctp_faddr_t *fp;
		/*
		 * We recache the information which might pick a different
		 * source and redo IPsec as a result.
		 */
		for (fp = sctp->sctp_faddrs; fp != NULL; fp = fp->sf_next)
			sctp_get_dest(sctp, fp);
	}
	if (coas.coa_changed & COA_HEADER_CHANGED) {
		retval = sctp_build_hdrs(sctp, KM_NOSLEEP);
		if (retval != 0)
			goto done;
	}
	if (coas.coa_changed & COA_WROFF_CHANGED) {
		connp->conn_wroff = connp->conn_ht_iphc_allocated +
		    sctps->sctps_wroff_xtra;
		if (sctp->sctp_current != NULL) {
			/*
			 * Could be setting options before setting up
			 * connection.
			 */
			sctp_set_ulp_prop(sctp);
		}
	}
done:
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
	conn_t	*connp = sctp->sctp_connp;

	ASSERT(sctp != NULL);

	RUN_SCTP(sctp);
	addr->sa_family = connp->conn_family;
	switch (connp->conn_family) {
	case AF_INET:
		sin4 = (sin_t *)addr;
		if ((sctp->sctp_state <= SCTPS_LISTEN) &&
		    sctp->sctp_bound_to_all) {
			sin4->sin_addr.s_addr = INADDR_ANY;
			sin4->sin_port = connp->conn_lport;
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
			sin6->sin6_port = connp->conn_lport;
		} else {
			err = sctp_getmyaddrs(sctp, sin6, &addrcnt);
			if (err != 0) {
				*addrlen = 0;
				break;
			}
		}
		*addrlen = sizeof (struct sockaddr_in6);
		/* Note that flowinfo is only returned for getpeername */
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
	conn_t	*connp = sctp->sctp_connp;

	ASSERT(sctp != NULL);

	RUN_SCTP(sctp);
	addr->sa_family = connp->conn_family;
	switch (connp->conn_family) {
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
	conn_t			*connp = sctp->sctp_connp;

	ASSERT(sctp != NULL);

	if (sctp->sctp_faddrs == NULL)
		return (ENOTCONN);

	family = connp->conn_family;
	max = *addrcnt;

	/* If we want only one, give the primary */
	if (max == 1) {
		addr = sctp->sctp_primary->sf_faddr;
		switch (family) {
		case AF_INET:
			sin4 = paddrs;
			IN6_V4MAPPED_TO_INADDR(&addr, &sin4->sin_addr);
			sin4->sin_port = connp->conn_fport;
			sin4->sin_family = AF_INET;
			break;

		case AF_INET6:
			sin6 = paddrs;
			sin6->sin6_addr = addr;
			sin6->sin6_port = connp->conn_fport;
			sin6->sin6_family = AF_INET6;
			sin6->sin6_flowinfo = connp->conn_flowinfo;
			if (IN6_IS_ADDR_LINKSCOPE(&addr) &&
			    (sctp->sctp_primary->sf_ixa->ixa_flags &
			    IXAF_SCOPEID_SET)) {
				sin6->sin6_scope_id =
				    sctp->sctp_primary->sf_ixa->ixa_scopeid;
			} else {
				sin6->sin6_scope_id = 0;
			}
			sin6->__sin6_src_id = 0;
			break;
		}
		return (0);
	}

	for (cnt = 0; cnt < max && fp != NULL; cnt++, fp = fp->sf_next) {
		addr = fp->sf_faddr;
		switch (family) {
		case AF_INET:
			ASSERT(IN6_IS_ADDR_V4MAPPED(&addr));
			sin4 = (struct sockaddr_in *)paddrs + cnt;
			IN6_V4MAPPED_TO_INADDR(&addr, &sin4->sin_addr);
			sin4->sin_port = connp->conn_fport;
			sin4->sin_family = AF_INET;
			break;
		case AF_INET6:
			sin6 = (struct sockaddr_in6 *)paddrs + cnt;
			sin6->sin6_addr = addr;
			sin6->sin6_port = connp->conn_fport;
			sin6->sin6_family = AF_INET6;
			sin6->sin6_flowinfo = connp->conn_flowinfo;
			if (IN6_IS_ADDR_LINKSCOPE(&addr) &&
			    (fp->sf_ixa->ixa_flags & IXAF_SCOPEID_SET))
				sin6->sin6_scope_id = fp->sf_ixa->ixa_scopeid;
			else
				sin6->sin6_scope_id = 0;
			sin6->__sin6_src_id = 0;
			break;
		}
	}
	*addrcnt = cnt;
	return (0);
}
