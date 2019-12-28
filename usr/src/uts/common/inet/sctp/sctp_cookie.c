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
#include <sys/md5.h>
#include <sys/kmem.h>
#include <sys/strsubr.h>
#include <sys/random.h>
#include <sys/tsol/tnet.h>

#include <netinet/in.h>
#include <netinet/ip6.h>

#include <inet/common.h>
#include <inet/ip.h>
#include <inet/ip6.h>
#include <inet/ipsec_impl.h>
#include <inet/sctp_ip.h>
#include <inet/ipclassifier.h>
#include "sctp_impl.h"

/*
 * Helper function for SunCluster (PSARC/2005/602) to get the original source
 * address from the COOKIE
 */
int cl_sctp_cookie_paddr(sctp_chunk_hdr_t *, in6_addr_t *);

/*
 * From RFC 2104. This should probably go into libmd5 (and while
 * we're at it, maybe we should make a libdigest so we can later
 * add SHA1 and others, esp. since some weaknesses have been found
 * with MD5).
 *
 * text		IN			pointer to data stream
 * text_len	IN			length of data stream
 * key		IN			pointer to authentication key
 * key_len	IN			length of authentication key
 * digest	OUT			caller digest to be filled in
 */
static void
hmac_md5(uchar_t *text, size_t text_len, uchar_t *key, size_t key_len,
    uchar_t *digest)
{
	MD5_CTX context;
	uchar_t k_ipad[65];	/* inner padding - key XORd with ipad */
	uchar_t k_opad[65];	/* outer padding - key XORd with opad */
	uchar_t tk[16];
	int i;

	/* if key is longer than 64 bytes reset it to key=MD5(key) */
	if (key_len > 64) {
		MD5_CTX tctx;

		MD5Init(&tctx);
		MD5Update(&tctx, key, key_len);
		MD5Final(tk, &tctx);

		key = tk;
		key_len = 16;
	}

	/*
	 * the HMAC_MD5 transform looks like:
	 *
	 * MD5(K XOR opad, MD5(K XOR ipad, text))
	 *
	 * where K is an n byte key
	 * ipad is the byte 0x36 repeated 64 times
	 * opad is the byte 0x5c repeated 64 times
	 * and text is the data being protected
	 */

	/* start out by storing key in pads */
	bzero(k_ipad, sizeof (k_ipad));
	bzero(k_opad, sizeof (k_opad));
	bcopy(key, k_ipad, key_len);
	bcopy(key, k_opad, key_len);

	/* XOR key with ipad and opad values */
	for (i = 0; i < 64; i++) {
		k_ipad[i] ^= 0x36;
		k_opad[i] ^= 0x5c;
	}
	/*
	 * perform inner MD5
	 */
	MD5Init(&context);			/* init context for 1st */
						/* pass */
	MD5Update(&context, k_ipad, 64);	/* start with inner pad */
	MD5Update(&context, text, text_len);	/* then text of datagram */
	MD5Final(digest, &context);		/* finish up 1st pass */
	/*
	 * perform outer MD5
	 */
	MD5Init(&context);			/* init context for 2nd */
						/* pass */
	MD5Update(&context, k_opad, 64);	/* start with outer pad */
	MD5Update(&context, digest, 16);	/* then results of 1st */
						/* hash */
	MD5Final(digest, &context);		/* finish up 2nd pass */
}

/*
 * If inmp is non-NULL, and we need to abort, it will use the IP/SCTP
 * info in initmp to send the abort. Otherwise, no abort will be sent.
 *
 * When called from stcp_send_initack() while processing parameters
 * from a received INIT_CHUNK want_cookie will be NULL.
 *
 * When called from sctp_send_cookie_echo() while processing an INIT_ACK,
 * want_cookie contains a pointer to a pointer of type *sctp_parm_hdr_t.
 * However, this last pointer will be NULL until the cookie is processed
 * at which time it will be set to point to a sctp_parm_hdr_t that contains
 * the cookie info.
 *
 * Note: an INIT_ACK is expected to contain a cookie.
 *
 * When processing an INIT_ACK, an ERROR chunk and chain of one or more
 * error CAUSE blocks will be created if unrecognized parameters marked by
 * the sender as reportable are found.
 *
 * When processing an INIT chunk, a chain of one or more error CAUSE blocks
 * will be created if unrecognized parameters marked by the sender as
 * reportable are found. These are appended directly to the INIT_ACK chunk.
 *
 * In both cases the error chain is visible to the caller via *errmp.
 *
 * Returns 1 if the parameters are OK (or if there are no optional
 * parameters), returns 0 otherwise.
 */
static int
validate_init_params(sctp_t *sctp, sctp_chunk_hdr_t *ch,
    sctp_init_chunk_t *init, mblk_t *inmp, sctp_parm_hdr_t **want_cookie,
    mblk_t **errmp, int *supp_af, uint_t *sctp_options, ip_recv_attr_t *ira)
{
	sctp_parm_hdr_t		*cph;
	sctp_init_chunk_t	*ic;
	ssize_t			remaining;
	uint16_t		serror = 0;
	char			*details = NULL;
	size_t			errlen = 0;
	boolean_t		got_cookie = B_FALSE;
	boolean_t		got_errchunk = B_FALSE;
	uint16_t		ptype;
	sctp_mpc_t		mpc;
	conn_t			*connp = sctp->sctp_connp;


	ASSERT(errmp != NULL);

	if (sctp_options != NULL)
		*sctp_options = 0;

	/* First validate stream parameters */
	if (init->sic_instr == 0 || init->sic_outstr == 0) {
		serror = SCTP_ERR_BAD_MANDPARM;
		dprint(1, ("validate_init_params: bad sid, is=%d os=%d\n",
		    htons(init->sic_instr), htons(init->sic_outstr)));
		goto abort;
	}
	if (ntohl(init->sic_inittag) == 0) {
		serror = SCTP_ERR_BAD_MANDPARM;
		dprint(1, ("validate_init_params: inittag = 0\n"));
		goto abort;
	}

	remaining = ntohs(ch->sch_len) - sizeof (*ch);
	ic = (sctp_init_chunk_t *)(ch + 1);
	remaining -= sizeof (*ic);
	if (remaining < sizeof (*cph)) {
		/*
		 * When processing a received INIT_ACK, a cookie is
		 * expected, if missing there is nothing to validate.
		 */
		if (want_cookie != NULL)
			goto cookie_abort;
		return (1);
	}

	cph = (sctp_parm_hdr_t *)(ic + 1);

	while (cph != NULL) {
		ptype = ntohs(cph->sph_type);
		switch (ptype) {
		case PARM_HBINFO:
		case PARM_UNRECOGNIZED:
		case PARM_ECN:
			/* just ignore them */
			break;
		case PARM_FORWARD_TSN:
			if (sctp_options != NULL)
				*sctp_options |= SCTP_PRSCTP_OPTION;
			break;
		case PARM_COOKIE:
			got_cookie = B_TRUE;
			/*
			 * Processing a received INIT_ACK, we have a cookie
			 * and a valid pointer in our caller to attach it to.
			 */
			if (want_cookie != NULL) {
				*want_cookie = cph;
			}
			break;
		case PARM_ADDR4:
			*supp_af |= PARM_SUPP_V4;
			break;
		case PARM_ADDR6:
			*supp_af |= PARM_SUPP_V6;
			break;
		case PARM_COOKIE_PRESERVE:
		case PARM_ADAPT_LAYER_IND:
			/* These are OK */
			break;
		case PARM_ADDR_HOST_NAME:
			/* Don't support this; abort the association */
			serror = SCTP_ERR_BAD_ADDR;
			details = (char *)cph;
			errlen = ntohs(cph->sph_len);
			dprint(1, ("sctp:validate_init_params: host addr\n"));
			goto abort;
		case PARM_SUPP_ADDRS: {
			/* Make sure we have a supported addr intersection */
			uint16_t *p, addrtype;
			int plen;

			plen = ntohs(cph->sph_len);
			p = (uint16_t *)(cph + 1);
			while (plen > 0) {
				addrtype = ntohs(*p);
				switch (addrtype) {
				case PARM_ADDR6:
					*supp_af |= PARM_SUPP_V6;
					break;
				case PARM_ADDR4:
					*supp_af |= PARM_SUPP_V4;
					break;
				default:
					/*
					 * Do nothing, silently ignore hostname
					 * address.
					 */
					break;
				}
				p++;
				plen -= sizeof (*p);
			}
			break;
		}
		default:
			/*
			 * Handle any unrecognized params, the two high order
			 * bits of ptype define how the remote wants them
			 * handled.
			 * Top bit:
			 *    1. Continue processing other params in the chunk
			 *    0. Stop processing params after this one.
			 * 2nd bit:
			 *    1. Must report this unrecognized param to remote
			 *    0. Obey the top bit silently.
			 */
			if (ptype & SCTP_REPORT_THIS_PARAM) {
				if (!got_errchunk && want_cookie != NULL) {
					/*
					 * The incoming pointer want_cookie is
					 * NULL so processing an INIT_ACK.
					 * This is the first reportable param,
					 * create an ERROR chunk and populate
					 * it with a CAUSE block for this parm.
					 */
					*errmp = sctp_make_err(sctp,
					    PARM_UNRECOGNIZED,
					    (void *)cph,
					    ntohs(cph->sph_len));
					got_errchunk = B_TRUE;
				} else {
					/*
					 * If processing an INIT_ACK, we already
					 * have an ERROR chunk, just add a new
					 * CAUSE block and update ERROR chunk
					 * length.
					 * If processing an INIT chunk add a new
					 * CAUSE block to the INIT_ACK, in this
					 * case there is no ERROR chunk thus
					 * got_errchunk will be B_FALSE. Chunk
					 * length is computed by our caller.
					 */
					sctp_add_unrec_parm(cph, errmp,
					    got_errchunk);
				}
			}
			if (ptype & SCTP_CONT_PROC_PARAMS) {
				/*
				 * Continue processing params after this
				 * parameter.
				 */
				break;
			}

			/*
			 * Stop processing params, report any reportable
			 * unrecognized params found so far.
			 */
			goto done;
		}

		cph = sctp_next_parm(cph, &remaining);
	}
done:
	/*
	 * Some sanity checks.  The following should not fail unless the
	 * other side is broken.
	 *
	 * 1. If this is a V4 endpoint but V4 address is not
	 * supported, abort.
	 * 2. If this is a V6 only endpoint but V6 address is
	 * not supported, abort.  This assumes that a V6
	 * endpoint can use both V4 and V6 addresses.
	 * We only care about supp_af when processing INIT, i.e want_cookie
	 * is NULL.
	 */
	if (want_cookie == NULL &&
	    ((connp->conn_family == AF_INET && !(*supp_af & PARM_SUPP_V4)) ||
	    (connp->conn_family == AF_INET6 && !(*supp_af & PARM_SUPP_V6) &&
	    sctp->sctp_connp->conn_ipv6_v6only))) {
		dprint(1, ("sctp:validate_init_params: supp addr\n"));
		serror = SCTP_ERR_BAD_ADDR;
		goto abort;
	}

	if (want_cookie != NULL && !got_cookie) {
cookie_abort:
		/* Will populate the CAUSE block in the ABORT chunk. */
		mpc.mpc_num =  htons(1);
		mpc.mpc_param = htons(PARM_COOKIE);
		mpc.mpc_pad = 0;

		dprint(1, ("validate_init_params: cookie absent\n"));
		sctp_send_abort(sctp, sctp_init2vtag(ch), SCTP_ERR_MISSING_PARM,
		    (char *)&mpc, sizeof (sctp_mpc_t), inmp, 0, B_FALSE, ira);
		return (0);
	}

	/* OK */
	return (1);

abort:
	if (want_cookie != NULL)
		return (0);

	sctp_send_abort(sctp, sctp_init2vtag(ch), serror, details,
	    errlen, inmp, 0, B_FALSE, ira);
	return (0);
}

/*
 * Initialize params from the INIT and INIT-ACK when the assoc. is
 * established.
 */
boolean_t
sctp_initialize_params(sctp_t *sctp, sctp_init_chunk_t *init,
    sctp_init_chunk_t *iack)
{
	/* Get initial TSN */
	sctp->sctp_ftsn = ntohl(init->sic_inittsn);
	sctp->sctp_lastacked = sctp->sctp_ftsn - 1;

	/* Serial number is initialized to the same value as the TSN */
	sctp->sctp_fcsn = sctp->sctp_lastacked;

	/*
	 * Get verification tags; no byteordering is necessary, since
	 * verfication tags are never processed except for byte-by-byte
	 * comparisons.
	 */
	sctp->sctp_fvtag = init->sic_inittag;
	sctp->sctp_sctph->sh_verf = init->sic_inittag;
	sctp->sctp_sctph6->sh_verf = init->sic_inittag;
	sctp->sctp_lvtag = iack->sic_inittag;

	/* Get the peer's rwnd */
	sctp->sctp_frwnd = ntohl(init->sic_a_rwnd);

	/* Allocate the in/out-stream counters */
	sctp->sctp_num_ostr = iack->sic_outstr;
	sctp->sctp_ostrcntrs = kmem_zalloc(sizeof (uint16_t) *
	    sctp->sctp_num_ostr, KM_NOSLEEP);
	if (sctp->sctp_ostrcntrs == NULL)
		return (B_FALSE);

	sctp->sctp_num_istr = iack->sic_instr;
	sctp->sctp_instr = kmem_zalloc(sizeof (*sctp->sctp_instr) *
	    sctp->sctp_num_istr, KM_NOSLEEP);
	if (sctp->sctp_instr == NULL) {
		kmem_free(sctp->sctp_ostrcntrs, sizeof (uint16_t) *
		    sctp->sctp_num_ostr);
		sctp->sctp_ostrcntrs = NULL;
		return (B_FALSE);
	}
	return (B_TRUE);
}

/*
 * Copy the peer's original source address into addr. This relies on the
 * following format (see sctp_send_initack() below):
 *	relative timestamp for the cookie (int64_t) +
 *	cookie lifetime (uint32_t) +
 *	local tie-tag (uint32_t) +  peer tie-tag (uint32_t) +
 *	Peer's original src ...
 */
int
cl_sctp_cookie_paddr(sctp_chunk_hdr_t *ch, in6_addr_t *addr)
{
	uchar_t	*off;

	ASSERT(addr != NULL);

	if (ch->sch_id != CHUNK_COOKIE)
		return (EINVAL);

	off = (uchar_t *)ch + sizeof (*ch) + sizeof (int64_t) +
	    sizeof (uint32_t) + sizeof (uint32_t) + sizeof (uint32_t);

	bcopy(off, addr, sizeof (*addr));

	return (0);
}

#define	SCTP_CALC_COOKIE_LEN(initcp) \
	sizeof (int64_t) +		/* timestamp */			\
	sizeof (uint32_t) +		/* cookie lifetime */		\
	sizeof (sctp_init_chunk_t) +	/* INIT ACK */			\
	sizeof (in6_addr_t) +		/* peer's original source */	\
	ntohs((initcp)->sch_len) +	/* peer's INIT */		\
	sizeof (uint32_t) +		/* local tie-tag */		\
	sizeof (uint32_t) +		/* peer tie-tag */		\
	sizeof (sctp_parm_hdr_t) +	/* param header */		\
	16				/* MD5 hash */

/*
 * Note that sctp is the listener, hence we shouldn't modify it.
 */
void
sctp_send_initack(sctp_t *sctp, sctp_hdr_t *initsh, sctp_chunk_hdr_t *ch,
    mblk_t *initmp, ip_recv_attr_t *ira)
{
	ipha_t			*initiph;
	ip6_t			*initip6h;
	ipha_t			*iackiph = NULL;
	ip6_t			*iackip6h = NULL;
	sctp_chunk_hdr_t	*iack_ch;
	sctp_init_chunk_t	*iack;
	sctp_init_chunk_t	*init;
	sctp_hdr_t		*iacksh;
	size_t			cookielen;
	size_t			iacklen;
	size_t			ipsctplen;
	size_t			errlen = 0;
	sctp_parm_hdr_t		*cookieph;
	mblk_t			*iackmp;
	uint32_t		itag;
	uint32_t		itsn;
	int64_t			*now;
	int64_t			nowt;
	uint32_t		*lifetime;
	char			*p;
	boolean_t		 isv4;
	int			supp_af = 0;
	uint_t			sctp_options;
	uint32_t		*ttag;
	int			pad;
	mblk_t			*errmp = NULL;
	boolean_t		initcollision = B_FALSE;
	boolean_t		linklocal = B_FALSE;
	sctp_stack_t		*sctps = sctp->sctp_sctps;
	conn_t			*connp = sctp->sctp_connp;
	int			err;
	ip_xmit_attr_t		*ixa = NULL;

	BUMP_LOCAL(sctp->sctp_ibchunks);
	isv4 = (IPH_HDR_VERSION(initmp->b_rptr) == IPV4_VERSION);

	/* Extract the INIT chunk */
	if (isv4) {
		initiph = (ipha_t *)initmp->b_rptr;
		ipsctplen = sctp->sctp_ip_hdr_len;
		supp_af |= PARM_SUPP_V4;
	} else {
		initip6h = (ip6_t *)initmp->b_rptr;
		ipsctplen = sctp->sctp_ip_hdr6_len;
		if (IN6_IS_ADDR_LINKLOCAL(&initip6h->ip6_src) ||
		    IN6_IS_ADDR_LINKLOCAL(&initip6h->ip6_dst))
			linklocal = B_TRUE;
		supp_af |= PARM_SUPP_V6;
		if (!sctp->sctp_connp->conn_ipv6_v6only)
			supp_af |= PARM_SUPP_V4;
	}
	ASSERT(OK_32PTR(initsh));
	init = (sctp_init_chunk_t *)((char *)(initsh + 1) + sizeof (*iack_ch));

	/* Make sure we like the peer's parameters */
	if (validate_init_params(sctp, ch, init, initmp, NULL, &errmp,
	    &supp_af, &sctp_options, ira) == 0) {
		return;
	}
	if (errmp != NULL)
		errlen = msgdsize(errmp);
	if (connp->conn_family == AF_INET) {
		/*
		 * Regardless of the supported address in the INIT, v4
		 * must be supported.
		 */
		supp_af = PARM_SUPP_V4;
	}
	if (sctp->sctp_state <= SCTPS_LISTEN) {
		/* normal, expected INIT: generate new vtag and itsn */
		(void) random_get_pseudo_bytes((uint8_t *)&itag, sizeof (itag));
		if (itag == 0)
			itag = (uint32_t)gethrtime();
		itsn = itag + 1;
		itag = htonl(itag);
	} else if (sctp->sctp_state == SCTPS_COOKIE_WAIT ||
	    sctp->sctp_state == SCTPS_COOKIE_ECHOED) {
		/* init collision; copy vtag and itsn from sctp */
		itag = sctp->sctp_lvtag;
		itsn = sctp->sctp_ltsn;
		/*
		 * In addition we need to send all the params that was sent
		 * in our INIT chunk. Essentially, it is only the supported
		 * address params that we need to add.
		 */
		initcollision = B_TRUE;
		/*
		 * When we sent the INIT, we should have set linklocal in
		 * the sctp which should be good enough.
		 */
		if (linklocal)
			linklocal = B_FALSE;
	} else {
		/* peer restart; generate new vtag but keep everything else */
		(void) random_get_pseudo_bytes((uint8_t *)&itag, sizeof (itag));
		if (itag == 0)
			itag = (uint32_t)gethrtime();
		itag = htonl(itag);
		itsn = sctp->sctp_ltsn;
	}

	/*
	 * Allocate a mblk for the INIT ACK, consisting of the link layer
	 * header, the IP header, the SCTP common header, and INIT ACK chunk,
	 * and finally the COOKIE parameter.
	 */
	cookielen = SCTP_CALC_COOKIE_LEN(ch);
	iacklen = sizeof (*iack_ch) + sizeof (*iack) + cookielen;
	if (sctp->sctp_send_adaptation)
		iacklen += (sizeof (sctp_parm_hdr_t) + sizeof (uint32_t));
	if (((sctp_options & SCTP_PRSCTP_OPTION) || initcollision) &&
	    sctp->sctp_prsctp_aware && sctps->sctps_prsctp_enabled) {
		iacklen += sctp_options_param_len(sctp, SCTP_PRSCTP_OPTION);
	}
	if (initcollision)
		iacklen += sctp_supaddr_param_len(sctp);
	if (!linklocal)
		iacklen += sctp_addr_params(sctp, supp_af, NULL, B_FALSE);
	ipsctplen += sizeof (*iacksh) + iacklen;
	iacklen += errlen;
	/*
	 * Padding is applied after the cookie which is the end of chunk
	 * unless CAUSE blocks are appended when the pad must also be
	 * accounted for in iacklen.
	 */
	if ((pad = ipsctplen % SCTP_ALIGN) != 0) {
		pad = SCTP_ALIGN - pad;
		ipsctplen += pad;
		if (errmp != NULL)
			iacklen += pad;
	}

	/*
	 * Base the transmission on any routing-related socket options
	 * that have been set on the listener.
	 */
	ixa = conn_get_ixa_exclusive(connp);
	if (ixa == NULL) {
		sctp_send_abort(sctp, sctp_init2vtag(ch),
		    SCTP_ERR_NO_RESOURCES, NULL, 0, initmp, 0, B_FALSE, ira);
		return;
	}
	ixa->ixa_flags &= ~IXAF_VERIFY_PMTU;

	if (isv4)
		ixa->ixa_flags |= IXAF_IS_IPV4;
	else
		ixa->ixa_flags &= ~IXAF_IS_IPV4;

	/*
	 * If the listen socket is bound to a trusted extensions multi-label
	 * port, a MAC-Exempt connection with an unlabeled node, we use the
	 * the security label of the received INIT packet.
	 * If not a multi-label port, attach the unmodified
	 * listener's label directly.
	 *
	 * We expect Sun developed kernel modules to properly set
	 * cred labels for sctp connections. We can't be so sure this
	 * will be done correctly when 3rd party kernel modules
	 * directly use sctp. We check for a NULL ira_tsl to cover this
	 * possibility.
	 */
	if (is_system_labeled()) {
		/* Discard any old label */
		if (ixa->ixa_free_flags & IXA_FREE_TSL) {
			ASSERT(ixa->ixa_tsl != NULL);
			label_rele(ixa->ixa_tsl);
			ixa->ixa_free_flags &= ~IXA_FREE_TSL;
			ixa->ixa_tsl = NULL;
		}

		if (connp->conn_mlp_type != mlptSingle ||
		    connp->conn_mac_mode != CONN_MAC_DEFAULT) {
			if (ira->ira_tsl == NULL) {
				sctp_send_abort(sctp, sctp_init2vtag(ch),
				    SCTP_ERR_UNKNOWN, NULL, 0, initmp, 0,
				    B_FALSE, ira);
				ixa_refrele(ixa);
				return;
			}
			label_hold(ira->ira_tsl);
			ip_xmit_attr_replace_tsl(ixa, ira->ira_tsl);
		} else {
			ixa->ixa_tsl = crgetlabel(connp->conn_cred);
		}
	}

	iackmp = allocb(ipsctplen + sctps->sctps_wroff_xtra, BPRI_MED);
	if (iackmp == NULL) {
		sctp_send_abort(sctp, sctp_init2vtag(ch),
		    SCTP_ERR_NO_RESOURCES, NULL, 0, initmp, 0, B_FALSE, ira);
		ixa_refrele(ixa);
		return;
	}

	/* Copy in the [imcomplete] IP/SCTP composite header */
	p = (char *)(iackmp->b_rptr + sctps->sctps_wroff_xtra);
	iackmp->b_rptr = (uchar_t *)p;
	if (isv4) {
		bcopy(sctp->sctp_iphc, p, sctp->sctp_hdr_len);
		iackiph = (ipha_t *)p;

		/* Copy the peer's IP addr */
		iackiph->ipha_dst = initiph->ipha_src;
		iackiph->ipha_src = initiph->ipha_dst;
		iackiph->ipha_length = htons(ipsctplen + errlen);
		iacksh = (sctp_hdr_t *)(p + sctp->sctp_ip_hdr_len);
		ixa->ixa_ip_hdr_length = sctp->sctp_ip_hdr_len;
	} else {
		bcopy(sctp->sctp_iphc6, p, sctp->sctp_hdr6_len);
		iackip6h = (ip6_t *)p;

		/* Copy the peer's IP addr */
		iackip6h->ip6_dst = initip6h->ip6_src;
		iackip6h->ip6_src = initip6h->ip6_dst;
		iackip6h->ip6_plen = htons(ipsctplen + errlen - IPV6_HDR_LEN);
		iacksh = (sctp_hdr_t *)(p + sctp->sctp_ip_hdr6_len);
		ixa->ixa_ip_hdr_length = sctp->sctp_ip_hdr6_len;
	}
	ixa->ixa_pktlen = ipsctplen + errlen;

	ASSERT(OK_32PTR(iacksh));

	/* Fill in the holes in the SCTP common header */
	iacksh->sh_sport = initsh->sh_dport;
	iacksh->sh_dport = initsh->sh_sport;
	iacksh->sh_verf = init->sic_inittag;

	/* INIT ACK chunk header */
	iack_ch = (sctp_chunk_hdr_t *)(iacksh + 1);
	iack_ch->sch_id = CHUNK_INIT_ACK;
	iack_ch->sch_flags = 0;
	iack_ch->sch_len = htons(iacklen);

	/* The INIT ACK itself */
	iack = (sctp_init_chunk_t *)(iack_ch + 1);
	iack->sic_inittag = itag;	/* already in network byteorder */
	iack->sic_inittsn = htonl(itsn);

	iack->sic_a_rwnd = htonl(sctp->sctp_rwnd);
	/* Advertise what we would want to have as stream #'s */
	iack->sic_outstr = htons(MIN(sctp->sctp_num_ostr,
	    ntohs(init->sic_instr)));
	iack->sic_instr = htons(sctp->sctp_num_istr);

	p = (char *)(iack + 1);
	p += sctp_adaptation_code_param(sctp, (uchar_t *)p);
	if (initcollision)
		p += sctp_supaddr_param(sctp, (uchar_t *)p);
	if (!linklocal)
		p += sctp_addr_params(sctp, supp_af, (uchar_t *)p, B_FALSE);
	if (((sctp_options & SCTP_PRSCTP_OPTION) || initcollision) &&
	    sctp->sctp_prsctp_aware && sctps->sctps_prsctp_enabled) {
		p += sctp_options_param(sctp, p, SCTP_PRSCTP_OPTION);
	}
	/*
	 * Generate and lay in the COOKIE parameter.
	 *
	 * Any change here that results in a change of location for
	 * the peer's orig source address must be propagated to the fn
	 * cl_sctp_cookie_paddr() above.
	 *
	 * The cookie consists of:
	 * 1. The relative timestamp for the cookie (lbolt64)
	 * 2. The cookie lifetime (uint32_t) in tick
	 * 3. The local tie-tag
	 * 4. The peer tie-tag
	 * 5. Peer's original src, used to confirm the validity of address.
	 * 6. Our INIT ACK chunk, less any parameters
	 * 7. The INIT chunk (may contain parameters)
	 * 8. 128-bit MD5 signature.
	 *
	 * Since the timestamp values will only be evaluated locally, we
	 * don't need to worry about byte-ordering them.
	 */
	cookieph = (sctp_parm_hdr_t *)p;
	cookieph->sph_type = htons(PARM_COOKIE);
	cookieph->sph_len = htons(cookielen);

	/* timestamp */
	now = (int64_t *)(cookieph + 1);
	nowt = LBOLT_FASTPATH64;
	bcopy(&nowt, now, sizeof (*now));

	/* cookie lifetime -- need configuration */
	lifetime = (uint32_t *)(now + 1);
	*lifetime = sctp->sctp_cookie_lifetime;

	/* Set the tie-tags */
	ttag = (uint32_t *)(lifetime + 1);
	if (sctp->sctp_state <= SCTPS_COOKIE_WAIT) {
		*ttag = 0;
		ttag++;
		*ttag = 0;
		ttag++;
	} else {
		/* local tie-tag (network byte-order) */
		*ttag = sctp->sctp_lvtag;
		ttag++;
		/* peer tie-tag (network byte-order) */
		*ttag = sctp->sctp_fvtag;
		ttag++;
	}
	/*
	 * Copy in peer's original source address so that we can confirm
	 * the reachability later.
	 */
	p = (char *)ttag;
	if (isv4) {
		in6_addr_t peer_addr;

		IN6_IPADDR_TO_V4MAPPED(iackiph->ipha_dst, &peer_addr);
		bcopy(&peer_addr, p, sizeof (in6_addr_t));
	} else {
		bcopy(&iackip6h->ip6_dst, p, sizeof (in6_addr_t));
	}
	p += sizeof (in6_addr_t);
	/* Copy in our INIT ACK chunk */
	bcopy(iack, p, sizeof (*iack));
	iack = (sctp_init_chunk_t *)p;
	/* Set the # of streams we'll end up using */
	iack->sic_outstr = MIN(sctp->sctp_num_ostr, ntohs(init->sic_instr));
	iack->sic_instr = MIN(sctp->sctp_num_istr, ntohs(init->sic_outstr));
	p += sizeof (*iack);

	/* Copy in the peer's INIT chunk */
	bcopy(ch, p, ntohs(ch->sch_len));
	p += ntohs(ch->sch_len);

	/*
	 * Calculate the HMAC ICV into the digest slot in buf.
	 * First, generate a new secret if the current secret is
	 * older than the new secret lifetime parameter permits,
	 * copying the current secret to sctp_old_secret.
	 */
	if (sctps->sctps_new_secret_interval > 0 &&
	    (sctp->sctp_last_secret_update +
	    MSEC_TO_TICK(sctps->sctps_new_secret_interval)) <= nowt) {
		bcopy(sctp->sctp_secret, sctp->sctp_old_secret,
		    SCTP_SECRET_LEN);
		(void) random_get_pseudo_bytes(sctp->sctp_secret,
		    SCTP_SECRET_LEN);
		sctp->sctp_last_secret_update = nowt;
	}

	hmac_md5((uchar_t *)now, cookielen - sizeof (*cookieph) - 16,
	    (uchar_t *)sctp->sctp_secret, SCTP_SECRET_LEN, (uchar_t *)p);

	iackmp->b_wptr = iackmp->b_rptr + ipsctplen;
	if (pad != 0)
		bzero((iackmp->b_wptr - pad), pad);

	iackmp->b_cont = errmp;		/*  OK if NULL */

	if (is_system_labeled()) {
		ts_label_t *effective_tsl = NULL;

		ASSERT(ira->ira_tsl != NULL);

		/* Discard any old label */
		if (ixa->ixa_free_flags & IXA_FREE_TSL) {
			ASSERT(ixa->ixa_tsl != NULL);
			label_rele(ixa->ixa_tsl);
			ixa->ixa_free_flags &= ~IXA_FREE_TSL;
		}
		ixa->ixa_tsl = ira->ira_tsl;	/* A multi-level responder */

		/*
		 * We need to check for label-related failures which implies
		 * an extra call to tsol_check_dest (as ip_output_simple
		 * also does a tsol_check_dest as part of computing the
		 * label for the packet, but ip_output_simple doesn't return
		 * a specific errno for that case so we can't rely on its
		 * check.)
		 */
		if (isv4) {
			err = tsol_check_dest(ixa->ixa_tsl, &iackiph->ipha_dst,
			    IPV4_VERSION, connp->conn_mac_mode,
			    connp->conn_zone_is_global, &effective_tsl);
		} else {
			err = tsol_check_dest(ixa->ixa_tsl, &iackip6h->ip6_dst,
			    IPV6_VERSION, connp->conn_mac_mode,
			    connp->conn_zone_is_global, &effective_tsl);
		}
		if (err != 0) {
			sctp_send_abort(sctp, sctp_init2vtag(ch),
			    SCTP_ERR_AUTH_ERR, NULL, 0, initmp, 0, B_FALSE,
			    ira);
			ixa_refrele(ixa);
			freemsg(iackmp);
			return;
		}
		if (effective_tsl != NULL) {
			/*
			 * Since ip_output_simple will redo the
			 * tsol_check_dest, we just drop the ref.
			 */
			label_rele(effective_tsl);
		}
	}

	BUMP_LOCAL(sctp->sctp_opkts);
	BUMP_LOCAL(sctp->sctp_obchunks);

	(void) ip_output_simple(iackmp, ixa);
	ixa_refrele(ixa);
}

void
sctp_send_cookie_ack(sctp_t *sctp)
{
	sctp_chunk_hdr_t *cach;
	mblk_t *camp;
	sctp_stack_t	*sctps = sctp->sctp_sctps;

	camp = sctp_make_mp(sctp, sctp->sctp_current, sizeof (*cach));
	if (camp == NULL) {
		/* XXX should abort, but don't have the inmp anymore */
		SCTP_KSTAT(sctps, sctp_send_cookie_ack_failed);
		return;
	}

	cach = (sctp_chunk_hdr_t *)camp->b_wptr;
	camp->b_wptr = (uchar_t *)(cach + 1);
	cach->sch_id = CHUNK_COOKIE_ACK;
	cach->sch_flags = 0;
	cach->sch_len = htons(sizeof (*cach));

	BUMP_LOCAL(sctp->sctp_obchunks);

	sctp_set_iplen(sctp, camp, sctp->sctp_current->sf_ixa);
	(void) conn_ip_output(camp, sctp->sctp_current->sf_ixa);
	BUMP_LOCAL(sctp->sctp_opkts);
}

static int
sctp_find_al_ind(sctp_parm_hdr_t *sph, ssize_t len, uint32_t *adaptation_code)
{

	if (len < sizeof (*sph))
		return (-1);
	while (sph != NULL) {
		if (sph->sph_type == htons(PARM_ADAPT_LAYER_IND) &&
		    ntohs(sph->sph_len) >= (sizeof (*sph) +
		    sizeof (uint32_t))) {
			*adaptation_code = *(uint32_t *)(sph + 1);
			return (0);
		}
		sph = sctp_next_parm(sph, &len);
	}
	return (-1);
}

void
sctp_send_cookie_echo(sctp_t *sctp, sctp_chunk_hdr_t *iackch, mblk_t *iackmp,
    ip_recv_attr_t *ira)
{
	mblk_t			*cemp;
	mblk_t			*mp = NULL;
	mblk_t			*head;
	mblk_t			*meta;
	sctp_faddr_t		*fp;
	sctp_chunk_hdr_t	*cech;
	sctp_init_chunk_t	 *iack;
	int32_t			cansend;
	int32_t			seglen;
	size_t			ceclen;
	sctp_parm_hdr_t		*cph;
	sctp_data_hdr_t		*sdc;
	sctp_tf_t		*tf;
	int			pad = 0;
	int			hdrlen;
	mblk_t			*errmp = NULL;
	uint_t			sctp_options;
	int			error;
	uint16_t		old_num_str;
	sctp_stack_t		*sctps = sctp->sctp_sctps;

	sdc = NULL;
	seglen = 0;
	iack = (sctp_init_chunk_t *)(iackch + 1);

	cph = NULL;
	if (validate_init_params(sctp, iackch, iack, iackmp, &cph, &errmp,
	    &pad, &sctp_options, ira) == 0) { /* result in 'pad' ignored */
		SCTPS_BUMP_MIB(sctps, sctpAborted);
		sctp_assoc_event(sctp, SCTP_CANT_STR_ASSOC, 0, NULL);
		sctp_clean_death(sctp, ECONNABORTED);
		return;
	}
	ASSERT(cph != NULL);

	ASSERT(sctp->sctp_cookie_mp == NULL);

	/* Got a cookie to echo back; allocate an mblk */
	ceclen = sizeof (*cech) + ntohs(cph->sph_len) - sizeof (*cph);
	if ((pad = ceclen & (SCTP_ALIGN - 1)) != 0)
		pad = SCTP_ALIGN - pad;

	if (IPH_HDR_VERSION(iackmp->b_rptr) == IPV4_VERSION)
		hdrlen = sctp->sctp_hdr_len;
	else
		hdrlen = sctp->sctp_hdr6_len;

	cemp = allocb(sctps->sctps_wroff_xtra + hdrlen + ceclen + pad,
	    BPRI_MED);
	if (cemp == NULL) {
		SCTP_FADDR_TIMER_RESTART(sctp, sctp->sctp_current,
		    sctp->sctp_current->sf_rto);
		if (errmp != NULL)
			freeb(errmp);
		return;
	}
	cemp->b_rptr += (sctps->sctps_wroff_xtra + hdrlen);

	/* Process the INIT ACK */
	sctp->sctp_sctph->sh_verf = iack->sic_inittag;
	sctp->sctp_sctph6->sh_verf = iack->sic_inittag;
	sctp->sctp_fvtag = iack->sic_inittag;
	sctp->sctp_ftsn = ntohl(iack->sic_inittsn);
	sctp->sctp_lastacked = sctp->sctp_ftsn - 1;
	sctp->sctp_fcsn = sctp->sctp_lastacked;
	sctp->sctp_frwnd = ntohl(iack->sic_a_rwnd);

	/*
	 * Populate sctp with addresses given in the INIT ACK or IP header.
	 * Need to set the df bit in the current fp as it has been cleared
	 * in sctp_connect().
	 */
	sctp->sctp_current->sf_df = B_TRUE;
	sctp->sctp_ipha->ipha_fragment_offset_and_flags |= IPH_DF_HTONS;

	/*
	 * Since IP uses this info during the fanout process, we need to hold
	 * the lock for this hash line while performing this operation.
	 */
	/* XXX sctp_conn_fanout + SCTP_CONN_HASH(sctps, connp->conn_ports); */
	ASSERT(sctp->sctp_conn_tfp != NULL);
	tf = sctp->sctp_conn_tfp;
	/* sctp isn't a listener so only need to hold conn fanout lock */
	mutex_enter(&tf->tf_lock);
	if (sctp_get_addrparams(sctp, NULL, iackmp, iackch, NULL) != 0) {
		mutex_exit(&tf->tf_lock);
		freeb(cemp);
		SCTP_FADDR_TIMER_RESTART(sctp, sctp->sctp_current,
		    sctp->sctp_current->sf_rto);
		if (errmp != NULL)
			freeb(errmp);
		return;
	}
	mutex_exit(&tf->tf_lock);

	fp = sctp->sctp_current;

	/*
	 * There could be a case when we get an INIT-ACK again, if the INIT
	 * is re-transmitted, for e.g., which means we would have already
	 * allocated this resource earlier (also for sctp_instr). In this
	 * case we check and re-allocate, if necessary.
	 */
	old_num_str = sctp->sctp_num_ostr;
	if (ntohs(iack->sic_instr) < sctp->sctp_num_ostr)
		sctp->sctp_num_ostr = ntohs(iack->sic_instr);
	if (sctp->sctp_ostrcntrs == NULL) {
		sctp->sctp_ostrcntrs = kmem_zalloc(sizeof (uint16_t) *
		    sctp->sctp_num_ostr, KM_NOSLEEP);
	} else {
		ASSERT(old_num_str > 0);
		if (old_num_str != sctp->sctp_num_ostr) {
			kmem_free(sctp->sctp_ostrcntrs, sizeof (uint16_t) *
			    old_num_str);
			sctp->sctp_ostrcntrs = kmem_zalloc(sizeof (uint16_t) *
			    sctp->sctp_num_ostr, KM_NOSLEEP);
		}
	}
	if (sctp->sctp_ostrcntrs == NULL) {
		freeb(cemp);
		SCTP_FADDR_TIMER_RESTART(sctp, fp, fp->sf_rto);
		if (errmp != NULL)
			freeb(errmp);
		return;
	}

	/*
	 * Allocate the in stream tracking array. Comments for sctp_ostrcntrs
	 * hold here too.
	 */
	old_num_str = sctp->sctp_num_istr;
	if (ntohs(iack->sic_outstr) < sctp->sctp_num_istr)
		sctp->sctp_num_istr = ntohs(iack->sic_outstr);
	if (sctp->sctp_instr == NULL) {
		sctp->sctp_instr = kmem_zalloc(sizeof (*sctp->sctp_instr) *
		    sctp->sctp_num_istr, KM_NOSLEEP);
	} else {
		ASSERT(old_num_str > 0);
		if (old_num_str != sctp->sctp_num_istr) {
			kmem_free(sctp->sctp_instr,
			    sizeof (*sctp->sctp_instr) * old_num_str);
			sctp->sctp_instr = kmem_zalloc(
			    sizeof (*sctp->sctp_instr) * sctp->sctp_num_istr,
			    KM_NOSLEEP);
		}
	}
	if (sctp->sctp_instr == NULL) {
		kmem_free(sctp->sctp_ostrcntrs,
		    sizeof (uint16_t) * sctp->sctp_num_ostr);
		freeb(cemp);
		SCTP_FADDR_TIMER_RESTART(sctp, fp, fp->sf_rto);
		if (errmp != NULL)
			freeb(errmp);
		return;
	}

	if (!(sctp_options & SCTP_PRSCTP_OPTION) && sctp->sctp_prsctp_aware)
		sctp->sctp_prsctp_aware = B_FALSE;

	if (sctp_find_al_ind((sctp_parm_hdr_t *)(iack + 1),
	    ntohs(iackch->sch_len) - (sizeof (*iackch) + sizeof (*iack)),
	    &sctp->sctp_rx_adaptation_code) == 0) {
		sctp->sctp_recv_adaptation = 1;
	}

	cech = (sctp_chunk_hdr_t *)cemp->b_rptr;
	ASSERT(OK_32PTR(cech));
	cech->sch_id = CHUNK_COOKIE;
	cech->sch_flags = 0;
	cech->sch_len = htons(ceclen);

	/* Copy the cookie (less the parm hdr) to the chunk */
	bcopy(cph + 1, cech + 1, ceclen - sizeof (*cph));

	cemp->b_wptr = cemp->b_rptr + ceclen;

	if (sctp->sctp_unsent > 0) {
		sctp_msg_hdr_t	*smh;
		mblk_t		*prev = NULL;
		uint32_t	unsent = 0;

		mp = sctp->sctp_xmit_unsent;
		do {
			smh = (sctp_msg_hdr_t *)mp->b_rptr;
			if (smh->smh_sid >= sctp->sctp_num_ostr) {
				unsent += smh->smh_msglen;
				if (prev != NULL)
					prev->b_next = mp->b_next;
				else
					sctp->sctp_xmit_unsent = mp->b_next;
				mp->b_next = NULL;
				sctp_sendfail_event(sctp, mp, SCTP_ERR_BAD_SID,
				    B_FALSE);
				if (prev != NULL)
					mp = prev->b_next;
				else
					mp = sctp->sctp_xmit_unsent;
			} else {
				prev = mp;
				mp = mp->b_next;
			}
		} while (mp != NULL);
		if (unsent > 0) {
			ASSERT(sctp->sctp_unsent >= unsent);
			sctp->sctp_unsent -= unsent;
			/*
			 * Update ULP the amount of queued data, which is
			 * sent-unack'ed + unsent.
			 * This is not necessary, but doesn't harm, we
			 * just use unsent instead of sent-unack'ed +
			 * unsent, since there won't be any sent-unack'ed
			 * here.
			 */
			if (!SCTP_IS_DETACHED(sctp))
				SCTP_TXQ_UPDATE(sctp);
		}
		if (sctp->sctp_xmit_unsent == NULL)
			sctp->sctp_xmit_unsent_tail = NULL;
	}
	ceclen += pad;
	cansend = MIN(sctp->sctp_unsent, sctp->sctp_frwnd);
	meta = sctp_get_msg_to_send(sctp, &mp, NULL, &error, ceclen,
	    cansend,  NULL);
	/*
	 * The error cannot be anything else since we could have an non-zero
	 * error only if sctp_get_msg_to_send() tries to send a Forward
	 * TSN which will not happen here.
	 */
	ASSERT(error == 0);
	if (meta == NULL)
		goto sendcookie;
	sctp->sctp_xmit_tail = meta;
	sdc = (sctp_data_hdr_t *)mp->b_rptr;
	seglen = ntohs(sdc->sdh_len);
	if ((ceclen + seglen) > fp->sf_pmss ||
	    (seglen - sizeof (*sdc)) > cansend) {
		goto sendcookie;
	}
	/* OK, if this fails */
	cemp->b_cont = dupmsg(mp);
sendcookie:
	head = sctp_add_proto_hdr(sctp, fp, cemp, 0, NULL);
	if (head == NULL) {
		freemsg(cemp);
		SCTP_FADDR_TIMER_RESTART(sctp, fp, fp->sf_rto);
		if (errmp != NULL)
			freeb(errmp);
		SCTP_KSTAT(sctps, sctp_send_cookie_failed);
		return;
	}
	/*
	 * Even if cookie-echo exceeds MTU for one of the hops, it'll
	 * have a chance of getting there.
	 */
	if (fp->sf_isv4) {
		ipha_t *iph = (ipha_t *)head->b_rptr;
		iph->ipha_fragment_offset_and_flags = 0;
	}
	BUMP_LOCAL(sctp->sctp_obchunks);

	sctp->sctp_cookie_mp = dupmsg(head);
	/* Don't bundle, we will just resend init if this cookie is lost. */
	if (sctp->sctp_cookie_mp == NULL) {
		if (cemp->b_cont != NULL) {
			freemsg(cemp->b_cont);
			cemp->b_cont = NULL;
		}
	} else if (cemp->b_cont != NULL) {
		ASSERT(mp != NULL && mp == meta->b_cont);
		SCTP_CHUNK_CLEAR_FLAGS(cemp->b_cont);
		cemp->b_wptr += pad;
		seglen -= sizeof (*sdc);
		SCTP_CHUNK_SENT(sctp, mp, sdc, fp, seglen, meta);
	}
	if (errmp != NULL) {
		if (cemp->b_cont == NULL)
			cemp->b_wptr += pad;
		linkb(head, errmp);
	}
	sctp->sctp_state = SCTPS_COOKIE_ECHOED;
	SCTP_FADDR_TIMER_RESTART(sctp, fp, fp->sf_rto);

	sctp_set_iplen(sctp, head, fp->sf_ixa);
	(void) conn_ip_output(head, fp->sf_ixa);
	BUMP_LOCAL(sctp->sctp_opkts);
}

int
sctp_process_cookie(sctp_t *sctp, sctp_chunk_hdr_t *ch, mblk_t *cmp,
    sctp_init_chunk_t **iackpp, sctp_hdr_t *insctph, int *recv_adaptation,
    in6_addr_t *peer_addr, ip_recv_attr_t *ira)
{
	int32_t			clen;
	size_t			initplen;
	uchar_t			*p;
	uchar_t			*given_hash;
	uchar_t			needed_hash[16];
	int64_t			ts;
	int64_t			diff;
	uint32_t		*lt;
	sctp_init_chunk_t	*iack;
	sctp_chunk_hdr_t	*initch;
	sctp_init_chunk_t	*init;
	uint32_t		*lttag;
	uint32_t		*fttag;
	uint32_t		ports;
	sctp_stack_t		*sctps = sctp->sctp_sctps;
	conn_t			*connp = sctp->sctp_connp;

	BUMP_LOCAL(sctp->sctp_ibchunks);
	/* Verify the ICV */
	clen = ntohs(ch->sch_len) - sizeof (*ch) - 16;
	if (clen < 0) {
		dprint(1, ("invalid cookie chunk length %d\n",
		    ntohs(ch->sch_len)));

		return (-1);
	}
	p = (uchar_t *)(ch + 1);

	hmac_md5(p, clen, (uchar_t *)sctp->sctp_secret, SCTP_SECRET_LEN,
	    needed_hash);

	/* The given hash follows the cookie data */
	given_hash = p + clen;

	if (bcmp(given_hash, needed_hash, 16) != 0) {
		/* The secret may have changed; try the old secret */
		hmac_md5(p, clen, (uchar_t *)sctp->sctp_old_secret,
		    SCTP_SECRET_LEN, needed_hash);
		if (bcmp(given_hash, needed_hash, 16) != 0) {
			return (-1);
		}
	}

	/* Timestamp is int64_t, and we only guarantee 32-bit alignment */
	bcopy(p, &ts, sizeof (ts));
	/* Cookie life time, uint32_t */
	lt = (uint32_t *)(p + sizeof (ts));

	/*
	 * To quote PRC, "this is our baby", so let's continue.
	 * We need to pull out the encapsulated INIT ACK and
	 * INIT chunks. Note that we don't process these until
	 * we have verified the timestamp, but we need them before
	 * processing the timestamp since if the time check fails,
	 * we need to get the verification tag from the INIT in order
	 * to send a stale cookie error.
	 */
	lttag = (uint32_t *)(lt + 1);
	fttag = lttag + 1;
	if (peer_addr != NULL)
		bcopy(fttag + 1, peer_addr, sizeof (in6_addr_t));
	iack = (sctp_init_chunk_t *)((char *)(fttag + 1) + sizeof (in6_addr_t));
	initch = (sctp_chunk_hdr_t *)(iack + 1);
	init = (sctp_init_chunk_t *)(initch + 1);
	initplen = ntohs(initch->sch_len) - (sizeof (*init) + sizeof (*initch));
	*iackpp = iack;
	*recv_adaptation = 0;

	/*
	 * Check the staleness of the Cookie, specified in 3.3.10.3 of
	 * RFC 2960.
	 *
	 * The mesaure of staleness is the difference, in microseconds,
	 * between the current time and the time the State Cookie expires.
	 * So it is lbolt64 - (ts + *lt).  If it is positive, it means
	 * that the Cookie has expired.
	 */
	diff = LBOLT_FASTPATH64 - (ts + *lt);
	if (diff > 0 && (init->sic_inittag != sctp->sctp_fvtag ||
	    iack->sic_inittag != sctp->sctp_lvtag)) {
		uint32_t staleness;

		staleness = TICK_TO_USEC(diff);
		staleness = htonl(staleness);
		sctp_send_abort(sctp, init->sic_inittag, SCTP_ERR_STALE_COOKIE,
		    (char *)&staleness, sizeof (staleness), cmp, 1, B_FALSE,
		    ira);

		dprint(1, ("stale cookie %d\n", staleness));

		return (-1);
	}

	/* Check for attack by adding addresses to a restart */
	bcopy(insctph, &ports, sizeof (ports));
	if (sctp_secure_restart_check(cmp, initch, ports, KM_NOSLEEP,
	    sctps, ira) != 1) {
		return (-1);
	}

	/* Look for adaptation code if there any parms in the INIT chunk */
	if ((initplen >= sizeof (sctp_parm_hdr_t)) &&
	    (sctp_find_al_ind((sctp_parm_hdr_t *)(init + 1), initplen,
	    &sctp->sctp_rx_adaptation_code) == 0)) {
		*recv_adaptation = 1;
	}

	/* Examine tie-tags */

	if (sctp->sctp_state >= SCTPS_COOKIE_WAIT) {
		if (sctp->sctp_state == SCTPS_ESTABLISHED &&
		    init->sic_inittag == sctp->sctp_fvtag &&
		    iack->sic_inittag == sctp->sctp_lvtag &&
		    *fttag == 0 && *lttag == 0) {

			dprint(1, ("duplicate cookie from %x:%x:%x:%x (%d)\n",
			    SCTP_PRINTADDR(sctp->sctp_current->sf_faddr),
			    (int)(connp->conn_fport)));
			return (-1);
		}

		if (init->sic_inittag != sctp->sctp_fvtag &&
		    iack->sic_inittag != sctp->sctp_lvtag &&
		    *fttag == sctp->sctp_fvtag &&
		    *lttag == sctp->sctp_lvtag) {
			int i;

			/* Section 5.2.4 case A: restart */
			sctp->sctp_fvtag = init->sic_inittag;
			sctp->sctp_lvtag = iack->sic_inittag;

			sctp->sctp_sctph->sh_verf = init->sic_inittag;
			sctp->sctp_sctph6->sh_verf = init->sic_inittag;

			sctp->sctp_ftsn = ntohl(init->sic_inittsn);
			sctp->sctp_lastacked = sctp->sctp_ftsn - 1;
			sctp->sctp_frwnd = ntohl(init->sic_a_rwnd);
			sctp->sctp_fcsn = sctp->sctp_lastacked;

			if (sctp->sctp_state < SCTPS_ESTABLISHED)
				SCTP_ASSOC_EST(sctps, sctp);

			dprint(1, ("sctp peer %x:%x:%x:%x (%d) restarted\n",
			    SCTP_PRINTADDR(sctp->sctp_current->sf_faddr),
			    (int)(connp->conn_fport)));
			/* reset parameters */
			sctp_congest_reset(sctp);

			/* reset stream bookkeeping */
			sctp_instream_cleanup(sctp, B_FALSE);

			sctp->sctp_istr_nmsgs = 0;
			sctp->sctp_rxqueued = 0;
			for (i = 0; i < sctp->sctp_num_ostr; i++) {
				sctp->sctp_ostrcntrs[i] = 0;
			}
			/* XXX flush xmit_list? */

			return (0);
		} else if (init->sic_inittag != sctp->sctp_fvtag &&
		    iack->sic_inittag == sctp->sctp_lvtag) {

			/* Section 5.2.4 case B: INIT collision */
			if (sctp->sctp_state < SCTPS_ESTABLISHED) {
				if (!sctp_initialize_params(sctp, init, iack))
					return (-1);	/* Drop? */
				SCTP_ASSOC_EST(sctps, sctp);
			}

			dprint(1, ("init collision with %x:%x:%x:%x (%d)\n",
			    SCTP_PRINTADDR(sctp->sctp_current->sf_faddr),
			    (int)(connp->conn_fport)));

			return (0);
		} else if (iack->sic_inittag != sctp->sctp_lvtag &&
		    init->sic_inittag == sctp->sctp_fvtag &&
		    *fttag == 0 && *lttag == 0) {

			/* Section 5.2.4 case C: late COOKIE */
			dprint(1, ("late cookie from %x:%x:%x:%x (%d)\n",
			    SCTP_PRINTADDR(sctp->sctp_current->sf_faddr),
			    (int)(connp->conn_fport)));
			return (-1);
		} else if (init->sic_inittag == sctp->sctp_fvtag &&
		    iack->sic_inittag == sctp->sctp_lvtag) {

			/*
			 * Section 5.2.4 case D: COOKIE ECHO retransmit
			 * Don't check cookie lifetime
			 */
			dprint(1, ("cookie tags match from %x:%x:%x:%x (%d)\n",
			    SCTP_PRINTADDR(sctp->sctp_current->sf_faddr),
			    (int)(connp->conn_fport)));
			if (sctp->sctp_state < SCTPS_ESTABLISHED) {
				if (!sctp_initialize_params(sctp, init, iack))
					return (-1);	/* Drop? */
				SCTP_ASSOC_EST(sctps, sctp);
			}
			return (0);
		} else {
			/* unrecognized case -- silently drop it */
			return (-1);
		}
	}

	return (0);
}

/*
 * Similar to ip_fanout_sctp, except that the src addr(s) are drawn
 * from address parameters in an INIT ACK's address list. This
 * function is used when an INIT ACK is received but IP's fanout
 * function could not find a sctp via the normal lookup routine.
 * This can happen when a host sends an INIT ACK from a different
 * address than the INIT was sent to.
 *
 * Returns the sctp_t if found, or NULL if not found.
 */
sctp_t *
sctp_addrlist2sctp(mblk_t *mp, sctp_hdr_t *sctph, sctp_chunk_hdr_t *ich,
    zoneid_t zoneid, sctp_stack_t *sctps)
{
	int isv4;
	ipha_t *iph;
	ip6_t *ip6h;
	in6_addr_t dst;
	in6_addr_t src, *srcp = &src;
	sctp_parm_hdr_t *ph;
	ssize_t remaining;
	sctp_init_chunk_t *iack;
	uint32_t ports;
	sctp_t *sctp = NULL;

	ASSERT(ich->sch_id == CHUNK_INIT_ACK);

	isv4 = (IPH_HDR_VERSION(mp->b_rptr) == IPV4_VERSION);
	if (isv4) {
		iph = (ipha_t *)mp->b_rptr;
		IN6_IPADDR_TO_V4MAPPED(iph->ipha_dst, &dst);
	} else {
		ip6h = (ip6_t *)mp->b_rptr;
		dst = ip6h->ip6_dst;
	}

	ports = *(uint32_t *)sctph;

	dprint(1, ("sctp_addrlist2sctp: ports=%u, dst = %x:%x:%x:%x\n",
	    ports, SCTP_PRINTADDR(dst)));

	/* pull out any address parameters */
	remaining = ntohs(ich->sch_len) - sizeof (*ich) - sizeof (*iack);
	if (remaining < sizeof (*ph)) {
		return (NULL);
	}

	iack = (sctp_init_chunk_t *)(ich + 1);
	ph = (sctp_parm_hdr_t *)(iack + 1);

	while (ph != NULL) {
		/*
		 * params have been verified in sctp_check_input(),
		 * so no need to do it again here.
		 *
		 * For labeled systems, there's no need to check the
		 * label here.  It's known to be good as we checked
		 * before allowing the connection to become bound.
		 *
		 * According to RFC4960 :
		 * All integer fields in an SCTP packet MUST be transmitted
		 * in network byte order, unless otherwise stated.
		 * Therefore convert the param type to network byte order.
		 */
		if (ph->sph_type == htons(PARM_ADDR4)) {
			IN6_INADDR_TO_V4MAPPED((struct in_addr *)(ph + 1),
			    srcp);

			sctp = sctp_conn_match(&srcp, 1, &dst, ports, zoneid,
			    0, sctps);

			dprint(1,
			    ("sctp_addrlist2sctp: src=%x:%x:%x:%x, sctp=%p\n",
			    SCTP_PRINTADDR(src), (void *)sctp));


			if (sctp != NULL) {
				return (sctp);
			}
		} else if (ph->sph_type == htons(PARM_ADDR6)) {
			srcp = (in6_addr_t *)(ph + 1);
			sctp = sctp_conn_match(&srcp, 1, &dst, ports, zoneid,
			    0, sctps);

			dprint(1,
			    ("sctp_addrlist2sctp: src=%x:%x:%x:%x, sctp=%p\n",
			    SCTP_PRINTADDR(src), (void *)sctp));

			if (sctp != NULL) {
				return (sctp);
			}
		}

		ph = sctp_next_parm(ph, &remaining);
	}

	return (NULL);
}
