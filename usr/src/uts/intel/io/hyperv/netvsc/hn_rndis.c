/*
 * Copyright (c) 2009-2012,2016 Microsoft Corp.
 * Copyright (c) 2010-2012 Citrix Inc.
 * Copyright (c) 2012 NetApp Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice unmodified, this list of conditions, and the following
 *    disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright (c) 2017 by Delphix. All rights reserved.
 */

#include <sys/sysmacros.h>
#include <sys/socket.h>
#include <sys/mutex.h>
#include <inet/ip.h>

#include <sys/ethernet.h>
#include <sys/atomic.h>

#include <sys/hyperv.h>
#include <sys/vmbus_xact.h>

#include "hn_rndis.h"
#include "if_hnvar.h"
#include "if_hnreg.h"
#include "ndis.h"
#include "hn_nvs.h"

#define	HN_RNDIS_RID_COMPAT_MASK	0xffff
#define	HN_RNDIS_RID_COMPAT_MAX		HN_RNDIS_RID_COMPAT_MASK

#define	HN_RNDIS_XFER_SIZE		2048

#define	HN_NDIS_TXCSUM_CAP_IP4		\
	(NDIS_TXCSUM_CAP_IP4 | NDIS_TXCSUM_CAP_IP4OPT)
#define	HN_NDIS_TXCSUM_CAP_TCP4		\
	(NDIS_TXCSUM_CAP_TCP4 | NDIS_TXCSUM_CAP_TCP4OPT)
#define	HN_NDIS_TXCSUM_CAP_TCP6		\
	(NDIS_TXCSUM_CAP_TCP6 | NDIS_TXCSUM_CAP_TCP6OPT | \
	NDIS_TXCSUM_CAP_IP6EXT)
#define	HN_NDIS_TXCSUM_CAP_UDP6		\
	(NDIS_TXCSUM_CAP_UDP6 | NDIS_TXCSUM_CAP_IP6EXT)
#define	HN_NDIS_LSOV2_CAP_IP6		\
	(NDIS_LSOV2_CAP_IP6EXT | NDIS_LSOV2_CAP_TCP6OPT)

static const void	*hn_rndis_xact_exec1(struct hn_softc *,
			    struct vmbus_xact *, size_t,
			    struct hn_nvs_sendctx *, size_t *);
static const void	*hn_rndis_xact_execute(struct hn_softc *,
			    struct vmbus_xact *, uint32_t, size_t, size_t *,
			    uint32_t);
static int		hn_rndis_query(struct hn_softc *, uint32_t,
			    const void *, size_t, void *, size_t *);
static int		hn_rndis_query2(struct hn_softc *, uint32_t,
			    const void *, size_t, void *, size_t *, size_t);
static int		hn_rndis_set(struct hn_softc *, uint32_t,
			    const void *, size_t);
static int		hn_rndis_init(struct hn_softc *);
static int		hn_rndis_halt(struct hn_softc *);
static int		hn_rndis_conf_offload(struct hn_softc *, int);
static int		hn_rndis_query_hwcaps(struct hn_softc *,
			    struct ndis_offload *);

static inline uint32_t
hn_rndis_rid(struct hn_softc *sc)
{
	uint32_t rid;

again:
	rid = atomic_inc_32_nv(&sc->hn_rndis_rid) - 1;
	if (rid == 0)
		goto again;

	/* Use upper 16 bits for non-compat RNDIS messages. */
	return ((rid & 0xffff) << 16);
}

void
hn_rndis_rx_ctrl(struct hn_softc *sc, const void *data, int dlen)
{
	const struct rndis_comp_hdr *comp;
	const struct rndis_msghdr *hdr;

	ASSERT3U(dlen, >=, sizeof (*hdr));
	hdr = data;

	switch (hdr->rm_type) {
	case REMOTE_NDIS_INITIALIZE_CMPLT:
	case REMOTE_NDIS_QUERY_CMPLT:
	case REMOTE_NDIS_SET_CMPLT:
	case REMOTE_NDIS_KEEPALIVE_CMPLT:	/* unused */
		if (dlen < sizeof (*comp)) {
			HN_WARN(sc, "invalid RNDIS cmplt");
			return;
		}
		comp = data;

		ASSERT3U(comp->rm_rid, >, HN_RNDIS_RID_COMPAT_MAX);
		vmbus_xact_ctx_wakeup(sc->hn_xact, comp, dlen);
		break;

	case REMOTE_NDIS_RESET_CMPLT:
		/*
		 * Reset completed, no rid.
		 *
		 * NOTE:
		 * RESET is not issued by hn(4), so this message should
		 * _not_ be observed.
		 */
		HN_WARN(sc, "RESET cmplt received");
		break;

	default:
		HN_WARN(sc, "unknown RNDIS msg 0x%x", hdr->rm_type);
		break;
	}
}

int
hn_rndis_get_eaddr(struct hn_softc *sc, uint8_t *eaddr)
{
	size_t eaddr_len;
	int error;

	eaddr_len = ETHERADDRL;
	error = hn_rndis_query(sc, OID_802_3_PERMANENT_ADDRESS, NULL, 0,
	    eaddr, &eaddr_len);
	if (error)
		return (error);
	if (eaddr_len != ETHERADDRL) {
		HN_WARN(sc, "invalid eaddr len %lu", eaddr_len);
		return (EINVAL);
	}
	return (0);
}

int
hn_rndis_get_linkstatus(struct hn_softc *sc, uint32_t *link_status)
{
	size_t size;
	int error;

	size = sizeof (*link_status);
	error = hn_rndis_query(sc, OID_GEN_MEDIA_CONNECT_STATUS, NULL, 0,
	    link_status, &size);
	if (error)
		return (error);
	if (size != sizeof (uint32_t)) {
		HN_WARN(sc, "invalid link status len %lu", size);
		return (EINVAL);
	}
	return (0);
}

static const void *
hn_rndis_xact_exec1(struct hn_softc *sc, struct vmbus_xact *xact, size_t reqlen,
    struct hn_nvs_sendctx *sndc, size_t *comp_len)
{
	struct vmbus_gpa gpa[HN_XACT_REQ_PGCNT];
	int gpa_cnt, error;
	paddr_t paddr;

	ASSERT3U(reqlen, <=, HN_XACT_REQ_SIZE);
	ASSERT(reqlen > 0);

	/*
	 * Setup the SG list.
	 */
	paddr = vmbus_xact_req_paddr(xact);
	ASSERT0(paddr & PAGEOFFSET);
	for (gpa_cnt = 0; gpa_cnt < HN_XACT_REQ_PGCNT; ++gpa_cnt) {
		int len = PAGESIZE;

		if (reqlen == 0)
			break;
		if (reqlen < len)
			len = reqlen;

		gpa[gpa_cnt].gpa_page = btop(paddr) + gpa_cnt;
		gpa[gpa_cnt].gpa_len = len;
		gpa[gpa_cnt].gpa_ofs = 0;

		reqlen -= len;
	}
	/*
	 * The length of the data must match the total length of all buffers
	 */
	ASSERT0(reqlen);

	/*
	 * Send this RNDIS control message and wait for its completion
	 * message.
	 */
	vmbus_xact_activate(xact);
	error = hn_nvs_send_rndis_ctrl(sc->hn_prichan, sndc, gpa, gpa_cnt);
	if (error) {
		vmbus_xact_deactivate(xact);
		HN_WARN(sc, "RNDIS ctrl send failed: %d", error);
		return (NULL);
	}
	return (vmbus_chan_xact_wait(sc->hn_prichan, xact, comp_len,
	    B_TRUE));
}

static const void *
hn_rndis_xact_execute(struct hn_softc *sc, struct vmbus_xact *xact,
    uint32_t rid, size_t reqlen, size_t *comp_len0, uint32_t comp_type)
{
	const struct rndis_comp_hdr *comp;
	size_t comp_len, min_complen = *comp_len0;

	ASSERT3U(rid, >, HN_RNDIS_RID_COMPAT_MAX);
	ASSERT3U(min_complen, >=, sizeof (*comp));

	/*
	 * Execute the xact setup by the caller.
	 */
	comp = hn_rndis_xact_exec1(sc, xact, reqlen, &hn_nvs_sendctx_none,
	    &comp_len);
	if (comp == NULL)
		return (NULL);

	/*
	 * Check this RNDIS complete message.
	 */
	if (comp_len < min_complen) {
		if (comp_len >= sizeof (*comp)) {
			/* rm_status field is valid */
			HN_WARN(sc, "invalid RNDIS comp len %lu, "
			    "status 0x%08x", comp_len, comp->rm_status);
		} else {
			HN_WARN(sc, "invalid RNDIS comp len %lu", comp_len);
		}
		return (NULL);
	}
	if (comp->rm_len < min_complen) {
		HN_WARN(sc, "invalid RNDIS comp msglen %u", comp->rm_len);
		return (NULL);
	}
	if (comp->rm_type != comp_type) {
		HN_WARN(sc, "unexpected RNDIS comp 0x%08x, "
		    "expect 0x%08x", comp->rm_type, comp_type);
		return (NULL);
	}
	if (comp->rm_rid != rid) {
		HN_WARN(sc, "RNDIS comp rid mismatch %u, "
		    "expect %u", comp->rm_rid, rid);
		return (NULL);
	}
	/* All pass! */
	*comp_len0 = comp_len;
	return (comp);
}

static int
hn_rndis_query(struct hn_softc *sc, uint32_t oid,
    const void *idata, size_t idlen, void *odata, size_t *odlen0)
{

	return (hn_rndis_query2(sc, oid, idata, idlen, odata, odlen0, *odlen0));
}

static int
hn_rndis_query2(struct hn_softc *sc, uint32_t oid,
    const void *idata, size_t idlen, void *odata, size_t *odlen0,
    size_t min_odlen)
{
	struct rndis_query_req *req;
	const struct rndis_query_comp *comp;
	struct vmbus_xact *xact;
	size_t reqlen, odlen = *odlen0, comp_len;
	int error, ofs;
	uint32_t rid;

	reqlen = sizeof (*req) + idlen;
	xact = vmbus_xact_get(sc->hn_xact, reqlen);
	if (xact == NULL) {
		HN_WARN(sc, "no xact for RNDIS query 0x%08x", oid);
		return (ENXIO);
	}
	rid = hn_rndis_rid(sc);
	req = vmbus_xact_req_data(xact);
	req->rm_type = REMOTE_NDIS_QUERY_MSG;
	req->rm_len = reqlen;
	req->rm_rid = rid;
	req->rm_oid = oid;
	/*
	 * XXX
	 * This is _not_ RNDIS Spec conforming:
	 * "This MUST be set to 0 when there is no input data
	 *  associated with the OID."
	 *
	 * If this field was set to 0 according to the RNDIS Spec,
	 * Hyper-V would set non-SUCCESS status in the query
	 * completion.
	 */
	req->rm_infobufoffset = RNDIS_QUERY_REQ_INFOBUFOFFSET;

	if (idlen > 0) {
		req->rm_infobuflen = idlen;
		/* Input data immediately follows RNDIS query. */
		(void) memcpy(req + 1, idata, idlen);
	}

	comp_len = sizeof (*comp) + min_odlen;
	comp = hn_rndis_xact_execute(sc, xact, rid, reqlen, &comp_len,
	    REMOTE_NDIS_QUERY_CMPLT);
	if (comp == NULL) {
		HN_WARN(sc, "exec RNDIS query 0x%08x failed", oid);
		error = EIO;
		goto done;
	}

	if (comp->rm_status != RNDIS_STATUS_SUCCESS) {
		HN_WARN(sc, "RNDIS query 0x%08x failed: "
		    "status 0x%08x", oid, comp->rm_status);
		error = EIO;
		goto done;
	}
	if (comp->rm_infobuflen == 0 || comp->rm_infobufoffset == 0) {
		/* No output data! */
		HN_WARN(sc, "RNDIS query 0x%08x, no data", oid);
		*odlen0 = 0;
		error = 0;
		goto done;
	}

	/*
	 * Check output data length and offset.
	 */
	/* ofs is the offset from the beginning of comp. */
	ofs = RNDIS_QUERY_COMP_INFOBUFOFFSET_ABS(comp->rm_infobufoffset);
	if (ofs < sizeof (*comp) || ofs + comp->rm_infobuflen > comp_len) {
		HN_WARN(sc, "RNDIS query invalid comp ib off/len, "
		    "%u/%u", comp->rm_infobufoffset, comp->rm_infobuflen);
		error = EINVAL;
		goto done;
	}

	/*
	 * Save output data.
	 */
	if (comp->rm_infobuflen < odlen)
		odlen = comp->rm_infobuflen;
	(void) memcpy(odata, ((const uint8_t *)comp) + ofs, odlen);
	*odlen0 = odlen;

	error = 0;
done:
	vmbus_xact_put(xact);
	return (error);
}

int
hn_rndis_query_rsscaps(struct hn_softc *sc, int *rxr_cnt0)
{
	struct ndis_rss_caps in, caps;
	size_t caps_len;
	int error, indsz, rxr_cnt, hash_fnidx;
	uint32_t hash_func = 0, hash_types = 0;

	*rxr_cnt0 = 0;

	if (sc->hn_ndis_ver < HN_NDIS_VERSION_6_20)
		return (EOPNOTSUPP);

	(void) memset(&in, 0, sizeof (in));
	in.ndis_hdr.ndis_type = NDIS_OBJTYPE_RSS_CAPS;
	in.ndis_hdr.ndis_rev = NDIS_RSS_CAPS_REV_2;
	in.ndis_hdr.ndis_size = NDIS_RSS_CAPS_SIZE;

	caps_len = NDIS_RSS_CAPS_SIZE;
	error = hn_rndis_query2(sc, OID_GEN_RECEIVE_SCALE_CAPABILITIES,
	    &in, NDIS_RSS_CAPS_SIZE, &caps, &caps_len, NDIS_RSS_CAPS_SIZE_6_0);
	if (error)
		return (error);

	/*
	 * Preliminary verification.
	 */
	if (caps.ndis_hdr.ndis_type != NDIS_OBJTYPE_RSS_CAPS) {
		HN_WARN(sc, "invalid NDIS objtype 0x%02x",
		    caps.ndis_hdr.ndis_type);
		return (EINVAL);
	}
	if (caps.ndis_hdr.ndis_rev < NDIS_RSS_CAPS_REV_1) {
		HN_WARN(sc, "invalid NDIS objrev 0x%02x",
		    caps.ndis_hdr.ndis_rev);
		return (EINVAL);
	}
	if (caps.ndis_hdr.ndis_size > caps_len) {
		HN_WARN(sc, "invalid NDIS objsize %u, "
		    "data size %lu", caps.ndis_hdr.ndis_size, caps_len);
		return (EINVAL);
	} else if (caps.ndis_hdr.ndis_size < NDIS_RSS_CAPS_SIZE_6_0) {
		HN_WARN(sc, "invalid NDIS objsize %u",
		    caps.ndis_hdr.ndis_size);
		return (EINVAL);
	}

	/*
	 * Save information for later RSS configuration.
	 */
	if (caps.ndis_nrxr == 0) {
		HN_WARN(sc, "0 RX rings!?");
		return (EINVAL);
	}
	HN_DEBUG(sc, 1, "%u RX rings", caps.ndis_nrxr);
	rxr_cnt = caps.ndis_nrxr;

	if (caps.ndis_hdr.ndis_size == NDIS_RSS_CAPS_SIZE &&
	    caps.ndis_hdr.ndis_rev >= NDIS_RSS_CAPS_REV_2) {
		if (caps.ndis_nind > NDIS_HASH_INDCNT) {
			HN_WARN(sc, "too many RSS indirect table entries %u",
			    caps.ndis_nind);
			return (EOPNOTSUPP);
		}
		if (!ISP2(caps.ndis_nind)) {
			HN_WARN(sc, "RSS indirect table size is not "
			    "power-of-2 %u", caps.ndis_nind);
		}

		HN_DEBUG(sc, 1, "RSS indirect table size %u", caps.ndis_nind);
		indsz = caps.ndis_nind;
	} else {
		indsz = NDIS_HASH_INDCNT;
	}
	if (indsz < rxr_cnt) {
		HN_WARN(sc, "# of RX rings (%d) > "
		    "RSS indirect table size %d", rxr_cnt, indsz);
		rxr_cnt = indsz;
	}

	/*
	 * NOTE:
	 * Toeplitz is at the lowest bit, and it is prefered; so ffs(),
	 * instead of fls(), is used here.
	 */
	hash_fnidx = ffs(caps.ndis_caps & NDIS_RSS_CAP_HASHFUNC_MASK);
	if (hash_fnidx == 0) {
		HN_WARN(sc, "no hash functions, caps 0x%08x", caps.ndis_caps);
		return (EOPNOTSUPP);
	}
	hash_func = 1 << (hash_fnidx - 1); /* ffs is 1-based */

	if (caps.ndis_caps & NDIS_RSS_CAP_IPV4)
		hash_types |= NDIS_HASH_IPV4 | NDIS_HASH_TCP_IPV4;
	if (caps.ndis_caps & NDIS_RSS_CAP_IPV6)
		hash_types |= NDIS_HASH_IPV6 | NDIS_HASH_TCP_IPV6;
	if (caps.ndis_caps & NDIS_RSS_CAP_IPV6_EX)
		hash_types |= NDIS_HASH_IPV6_EX | NDIS_HASH_TCP_IPV6_EX;
	if (hash_types == 0) {
		HN_WARN(sc, "no hash types, caps 0x%08x", caps.ndis_caps);
		return (EOPNOTSUPP);
	}

	/* Commit! */
	sc->hn_rss_ind_size = indsz;
	sc->hn_rss_hash = hash_func | hash_types;
	*rxr_cnt0 = rxr_cnt;
	return (0);
}

static int
hn_rndis_set(struct hn_softc *sc, uint32_t oid, const void *data, size_t dlen)
{
	struct rndis_set_req *req;
	const struct rndis_set_comp *comp;
	struct vmbus_xact *xact;
	size_t reqlen, comp_len;
	uint32_t rid;
	int error;

	ASSERT(dlen > 0);

	reqlen = sizeof (*req) + dlen;
	xact = vmbus_xact_get(sc->hn_xact, reqlen);
	if (xact == NULL) {
		HN_WARN(sc, "no xact for RNDIS set 0x%08x", oid);
		return (ENXIO);
	}
	rid = hn_rndis_rid(sc);
	req = vmbus_xact_req_data(xact);
	req->rm_type = REMOTE_NDIS_SET_MSG;
	req->rm_len = reqlen;
	req->rm_rid = rid;
	req->rm_oid = oid;
	req->rm_infobuflen = dlen;
	req->rm_infobufoffset = RNDIS_SET_REQ_INFOBUFOFFSET;
	/* Data immediately follows RNDIS set. */
	(void) memcpy(req + 1, data, dlen);

	comp_len = sizeof (*comp);
	comp = hn_rndis_xact_execute(sc, xact, rid, reqlen, &comp_len,
	    REMOTE_NDIS_SET_CMPLT);
	if (comp == NULL) {
		HN_WARN(sc, "exec RNDIS set 0x%08x failed", oid);
		error = EIO;
		goto done;
	}

	if (comp->rm_status != RNDIS_STATUS_SUCCESS) {
		HN_WARN(sc, "RNDIS set 0x%08x failed: "
		    "status 0x%08x", oid, comp->rm_status);
		error = EIO;
		goto done;
	}
	error = 0;
done:
	vmbus_xact_put(xact);
	return (error);
}

static int
hn_rndis_conf_offload(struct hn_softc *sc, int mtu)
{
	struct ndis_offload hwcaps;
	struct ndis_offload_params params;
	uint32_t caps = 0;
	size_t paramsz;
	int error, tso_maxsz, tso_minsg;

	error = hn_rndis_query_hwcaps(sc, &hwcaps);
	if (error) {
		HN_WARN(sc, "hwcaps query failed: %d", error);
		return (error);
	}

	/* NOTE: 0 means "no change" */
	(void) memset(&params, 0, sizeof (params));

	params.ndis_hdr.ndis_type = NDIS_OBJTYPE_DEFAULT;
	if (sc->hn_ndis_ver < HN_NDIS_VERSION_6_30) {
		params.ndis_hdr.ndis_rev = NDIS_OFFLOAD_PARAMS_REV_2;
		paramsz = NDIS_OFFLOAD_PARAMS_SIZE_6_1;
	} else {
		params.ndis_hdr.ndis_rev = NDIS_OFFLOAD_PARAMS_REV_3;
		paramsz = NDIS_OFFLOAD_PARAMS_SIZE;
	}
	params.ndis_hdr.ndis_size = paramsz;

	/*
	 * TSO4/TSO6 setup.
	 */
	tso_maxsz = IP_MAXPACKET;
	tso_minsg = 2;
	if (hwcaps.ndis_lsov2.ndis_ip4_encap & NDIS_OFFLOAD_ENCAP_8023) {
		caps |= HN_CAP_TSO4;
		params.ndis_lsov2_ip4 = NDIS_OFFLOAD_LSOV2_ON;

		if (hwcaps.ndis_lsov2.ndis_ip4_maxsz < tso_maxsz)
			tso_maxsz = hwcaps.ndis_lsov2.ndis_ip4_maxsz;
		if (hwcaps.ndis_lsov2.ndis_ip4_minsg > tso_minsg)
			tso_minsg = hwcaps.ndis_lsov2.ndis_ip4_minsg;
	}
#ifdef notyet
	if ((hwcaps.ndis_lsov2.ndis_ip6_encap & NDIS_OFFLOAD_ENCAP_8023) &&
	    (hwcaps.ndis_lsov2.ndis_ip6_opts & HN_NDIS_LSOV2_CAP_IP6) ==
	    HN_NDIS_LSOV2_CAP_IP6) {
		caps |= HN_CAP_TSO6;
		params.ndis_lsov2_ip6 = NDIS_OFFLOAD_LSOV2_ON;

		if (hwcaps.ndis_lsov2.ndis_ip6_maxsz < tso_maxsz)
			tso_maxsz = hwcaps.ndis_lsov2.ndis_ip6_maxsz;
		if (hwcaps.ndis_lsov2.ndis_ip6_minsg > tso_minsg)
			tso_minsg = hwcaps.ndis_lsov2.ndis_ip6_minsg;
	}
#endif
	sc->hn_ndis_tso_szmax = 0;
	sc->hn_ndis_tso_sgmin = 0;
	if (caps & (HN_CAP_TSO4 | HN_CAP_TSO6)) {
		ASSERT3U(tso_maxsz, <=, IP_MAXPACKET);
		ASSERT3U(tso_minsg, >=, 2);
		if (tso_maxsz < tso_minsg * mtu) {
			HN_WARN(sc, "invalid NDIS TSO config: "
			    "maxsz %d, minsg %d, mtu %d; "
			    "disable TSO4 and TSO6",
			    tso_maxsz, tso_minsg, mtu);
			caps &= ~(HN_CAP_TSO4 | HN_CAP_TSO6);
			params.ndis_lsov2_ip4 = NDIS_OFFLOAD_LSOV2_OFF;
			params.ndis_lsov2_ip6 = NDIS_OFFLOAD_LSOV2_OFF;
		} else {
			sc->hn_ndis_tso_szmax = tso_maxsz;
			sc->hn_ndis_tso_sgmin = tso_minsg;
			HN_DEBUG(sc, 1, "NDIS TSO szmax %d sgmin %d",
			    sc->hn_ndis_tso_szmax, sc->hn_ndis_tso_sgmin);
		}
	}

	/* IPv4 checksum */
	if ((hwcaps.ndis_csum.ndis_ip4_txcsum & HN_NDIS_TXCSUM_CAP_IP4) ==
	    HN_NDIS_TXCSUM_CAP_IP4) {
		caps |= HN_CAP_IPCS;
		params.ndis_ip4csum = NDIS_OFFLOAD_PARAM_TX;
	}
	if (hwcaps.ndis_csum.ndis_ip4_rxcsum & NDIS_RXCSUM_CAP_IP4) {
		if (params.ndis_ip4csum == NDIS_OFFLOAD_PARAM_TX)
			params.ndis_ip4csum = NDIS_OFFLOAD_PARAM_TXRX;
		else
			params.ndis_ip4csum = NDIS_OFFLOAD_PARAM_RX;
	}

	/* TCP4 checksum */
	if ((hwcaps.ndis_csum.ndis_ip4_txcsum & HN_NDIS_TXCSUM_CAP_TCP4) ==
	    HN_NDIS_TXCSUM_CAP_TCP4) {
		caps |= HN_CAP_TCP4CS;
		params.ndis_tcp4csum = NDIS_OFFLOAD_PARAM_TX;
	}
	if (hwcaps.ndis_csum.ndis_ip4_rxcsum & NDIS_RXCSUM_CAP_TCP4) {
		if (params.ndis_tcp4csum == NDIS_OFFLOAD_PARAM_TX)
			params.ndis_tcp4csum = NDIS_OFFLOAD_PARAM_TXRX;
		else
			params.ndis_tcp4csum = NDIS_OFFLOAD_PARAM_RX;
	}

	/* UDP4 checksum */
	if (hwcaps.ndis_csum.ndis_ip4_txcsum & NDIS_TXCSUM_CAP_UDP4) {
		caps |= HN_CAP_UDP4CS;
		params.ndis_udp4csum = NDIS_OFFLOAD_PARAM_TX;
	}
	if (hwcaps.ndis_csum.ndis_ip4_rxcsum & NDIS_RXCSUM_CAP_UDP4) {
		if (params.ndis_udp4csum == NDIS_OFFLOAD_PARAM_TX)
			params.ndis_udp4csum = NDIS_OFFLOAD_PARAM_TXRX;
		else
			params.ndis_udp4csum = NDIS_OFFLOAD_PARAM_RX;
	}

	/* TCP6 checksum */
	if ((hwcaps.ndis_csum.ndis_ip6_txcsum & HN_NDIS_TXCSUM_CAP_TCP6) ==
	    HN_NDIS_TXCSUM_CAP_TCP6) {
		caps |= HN_CAP_TCP6CS;
		params.ndis_tcp6csum = NDIS_OFFLOAD_PARAM_TX;
	}
	if (hwcaps.ndis_csum.ndis_ip6_rxcsum & NDIS_RXCSUM_CAP_TCP6) {
		if (params.ndis_tcp6csum == NDIS_OFFLOAD_PARAM_TX)
			params.ndis_tcp6csum = NDIS_OFFLOAD_PARAM_TXRX;
		else
			params.ndis_tcp6csum = NDIS_OFFLOAD_PARAM_RX;
	}

	/* UDP6 checksum */
	if ((hwcaps.ndis_csum.ndis_ip6_txcsum & HN_NDIS_TXCSUM_CAP_UDP6) ==
	    HN_NDIS_TXCSUM_CAP_UDP6) {
		caps |= HN_CAP_UDP6CS;
		params.ndis_udp6csum = NDIS_OFFLOAD_PARAM_TX;
	}
	if (hwcaps.ndis_csum.ndis_ip6_rxcsum & NDIS_RXCSUM_CAP_UDP6) {
		if (params.ndis_udp6csum == NDIS_OFFLOAD_PARAM_TX)
			params.ndis_udp6csum = NDIS_OFFLOAD_PARAM_TXRX;
		else
			params.ndis_udp6csum = NDIS_OFFLOAD_PARAM_RX;
	}

	HN_DEBUG(sc, 1, "offload csum: "
	    "ip4 %u, tcp4 %u, udp4 %u, tcp6 %u, udp6 %u",
	    params.ndis_ip4csum,
	    params.ndis_tcp4csum,
	    params.ndis_udp4csum,
	    params.ndis_tcp6csum,
	    params.ndis_udp6csum);
	HN_DEBUG(sc, 1, "offload lsov2: ip4 %u, ip6 %u",
	    params.ndis_lsov2_ip4, params.ndis_lsov2_ip6);

	error = hn_rndis_set(sc, OID_TCP_OFFLOAD_PARAMETERS, &params, paramsz);
	if (error) {
		HN_WARN(sc, "offload config failed: %d", error);
		return (error);
	}

	HN_DEBUG(sc, 1, "offload config done");
	sc->hn_caps |= caps;
	return (0);
}

int
hn_rndis_conf_rss(struct hn_softc *sc, uint16_t flags)
{
	struct ndis_rssprm_toeplitz *rss = &sc->hn_rss;
	struct ndis_rss_params *prm = &rss->rss_params;
	int error, rss_size;

	/*
	 * Only NDIS 6.20+ is supported:
	 * We only support 4bytes element in indirect table, which has been
	 * adopted since NDIS 6.20.
	 */
	ASSERT3U(sc->hn_ndis_ver, >=, HN_NDIS_VERSION_6_20);

	/* XXX only one can be specified through, popcnt? */
	ASSERT(sc->hn_rss_hash & NDIS_HASH_FUNCTION_MASK);
	ASSERT(sc->hn_rss_hash & NDIS_HASH_TYPE_MASK);
	ASSERT3S(sc->hn_rss_ind_size, >, 0);

	HN_DEBUG(sc, 1, "RSS indirect table size %d, hash 0x%08x",
	    sc->hn_rss_ind_size, sc->hn_rss_hash);

	/*
	 * NOTE:
	 * DO NOT whack rss_key and rss_ind, which are setup by the caller.
	 */
	(void) memset(prm, 0, sizeof (*prm));
	rss_size = NDIS_RSSPRM_TOEPLITZ_SIZE(sc->hn_rss_ind_size);

	prm->ndis_hdr.ndis_type = NDIS_OBJTYPE_RSS_PARAMS;
	prm->ndis_hdr.ndis_rev = NDIS_RSS_PARAMS_REV_2;
	prm->ndis_hdr.ndis_size = rss_size;
	prm->ndis_flags = flags;
	prm->ndis_hash = sc->hn_rss_hash;
	prm->ndis_indsize = sizeof (rss->rss_ind[0]) * sc->hn_rss_ind_size;
	prm->ndis_indoffset =
	    offsetof(struct ndis_rssprm_toeplitz, rss_ind[0]);
	prm->ndis_keysize = sizeof (rss->rss_key);
	prm->ndis_keyoffset =
	    offsetof(struct ndis_rssprm_toeplitz, rss_key[0]);

	error = hn_rndis_set(sc, OID_GEN_RECEIVE_SCALE_PARAMETERS,
	    rss, rss_size);
	if (error) {
		HN_WARN(sc, "RSS config failed: %d", error);
	} else {
		HN_DEBUG(sc, 1, "RSS config done");
	}
	return (error);
}

int
hn_rndis_set_rxfilter(struct hn_softc *sc, uint32_t filter)
{
	int error;

	error = hn_rndis_set(sc, OID_GEN_CURRENT_PACKET_FILTER,
	    &filter, sizeof (filter));
	if (error) {
		HN_WARN(sc, "set RX filter 0x%08x failed: %d",
		    filter, error);
	} else {
		HN_DEBUG(sc, 1, "set RX filter 0x%08x done", filter);
	}
	return (error);
}

/*
 * Helper function to convert basic ascii (first 128 characters) to utf16LE
 */
static void
basic_ascii_2_utf16(const char *src, char *dst, int src_len)
{
	for (int i = 0, j = 0; i < src_len; i++, j += 2) {
		dst[j] = src[i];
		dst[j + 1] = 0;
	}
}

#define	EADDR_CONFIG_STR "NetworkAddress"
#define	EADDR_CONFIG_STRLEN 14

/*
 * Note: for this feature to work properly, MAC address spoofing must be
 * enabled in Hyper-V.
 */
int
hn_rndis_set_eaddr(struct hn_softc *sc, const uint8_t *mac_addr)
{
	int error;
	char data[sizeof (struct rndis_set_parameter) +
	    EADDR_CONFIG_STRLEN * 2 + ETHERADDRL * 4];
	struct rndis_set_parameter *rsp = (void *)data;

	rsp->rm_type = REMOTE_NDIS_SET_PARAM_STRING;
	/* Twice the length because we convert string to utf16 */
	rsp->rm_namelen = EADDR_CONFIG_STRLEN * 2;
	rsp->rm_nameoffset = sizeof (struct rndis_set_parameter);
	/*
	 * Four times the length because we use 2 hex chars for each MAC byte
	 * and then convert string to utf16
	 */
	rsp->rm_valuelen = ETHERADDRL * 4;
	rsp->rm_valueoffset = rsp->rm_nameoffset + rsp->rm_namelen;

	char *name_utf16 = &data[rsp->rm_nameoffset];
	char *value_utf16 = &data[rsp->rm_valueoffset];

	ASSERT3P(&data[sizeof (data)], ==, &value_utf16[rsp->rm_valuelen]);

	basic_ascii_2_utf16(EADDR_CONFIG_STR, name_utf16, EADDR_CONFIG_STRLEN);

	char mac_addr_str[ETHERADDRL * 2 + 1];
	(void) snprintf(mac_addr_str, sizeof (mac_addr_str), MACADDR_FMT,
	    MACADDR_FMT_ARGS(mac_addr));

	basic_ascii_2_utf16(mac_addr_str, value_utf16, ETHERADDRL * 2);

	/*
	 * Note: we cannot use OID_802_3_PERMANENT_ADDRESS or
	 * OID_802_3_CURRENT_ADDRESS to set the mac address, only to get it.
	 */
	error = hn_rndis_set(sc, OID_GEN_RNDIS_CONFIG_PARAMETER,
	    data, sizeof (data));
	if (error) {
		HN_WARN(sc, "set MAC addr to %s failed: %d",
		    mac_addr_str, error);
	}

	return (error);
}

static int
hn_rndis_init(struct hn_softc *sc)
{
	struct rndis_init_req *req;
	const struct rndis_init_comp *comp;
	struct vmbus_xact *xact;
	size_t comp_len;
	uint32_t rid;
	int error;

	xact = vmbus_xact_get(sc->hn_xact, sizeof (*req));
	if (xact == NULL) {
		HN_WARN(sc, "no xact for RNDIS init");
		return (ENXIO);
	}
	rid = hn_rndis_rid(sc);
	req = vmbus_xact_req_data(xact);
	req->rm_type = REMOTE_NDIS_INITIALIZE_MSG;
	req->rm_len = sizeof (*req);
	req->rm_rid = rid;
	req->rm_ver_major = RNDIS_VERSION_MAJOR;
	req->rm_ver_minor = RNDIS_VERSION_MINOR;
	req->rm_max_xfersz = HN_RNDIS_XFER_SIZE;

	comp_len = RNDIS_INIT_COMP_SIZE_MIN;
	comp = hn_rndis_xact_execute(sc, xact, rid, sizeof (*req), &comp_len,
	    REMOTE_NDIS_INITIALIZE_CMPLT);
	if (comp == NULL) {
		HN_WARN(sc, "exec RNDIS init failed");
		error = EIO;
		goto done;
	}

	if (comp->rm_status != RNDIS_STATUS_SUCCESS) {
		HN_WARN(sc, "RNDIS init failed: status 0x%08x",
		    comp->rm_status);
		error = EIO;
		goto done;
	}
	HN_DEBUG(sc, 1, "RNDIS ver %u.%u, pktsz %u, pktcnt %u, "
	    "align %u", comp->rm_ver_major, comp->rm_ver_minor,
	    comp->rm_pktmaxsz, comp->rm_pktmaxcnt,
	    1U << comp->rm_align);
	error = 0;
done:
	vmbus_xact_put(xact);
	return (error);
}

static int
hn_rndis_halt(struct hn_softc *sc)
{
	struct vmbus_xact *xact;
	struct rndis_halt_req *halt;
	struct hn_nvs_sendctx sndc;
	size_t comp_len;

	xact = vmbus_xact_get(sc->hn_xact, sizeof (*halt));
	if (xact == NULL) {
		HN_WARN(sc, "no xact for RNDIS halt");
		return (ENXIO);
	}
	halt = vmbus_xact_req_data(xact);
	halt->rm_type = REMOTE_NDIS_HALT_MSG;
	halt->rm_len = sizeof (*halt);
	halt->rm_rid = hn_rndis_rid(sc);

	/* No RNDIS completion; rely on NVS message send completion */
	hn_nvs_sendctx_init(&sndc, hn_nvs_sent_xact, xact);
	(void) hn_rndis_xact_exec1(sc, xact, sizeof (*halt), &sndc, &comp_len);

	vmbus_xact_put(xact);
	HN_DEBUG(sc, 1, "RNDIS halt done");
	return (0);
}

static int
hn_rndis_query_hwcaps(struct hn_softc *sc, struct ndis_offload *caps)
{
	struct ndis_offload in;
	size_t caps_len, size;
	int error;

	(void) memset(&in, 0, sizeof (in));
	in.ndis_hdr.ndis_type = NDIS_OBJTYPE_OFFLOAD;
	if (sc->hn_ndis_ver >= HN_NDIS_VERSION_6_30) {
		in.ndis_hdr.ndis_rev = NDIS_OFFLOAD_REV_3;
		size = NDIS_OFFLOAD_SIZE;
	} else if (sc->hn_ndis_ver >= HN_NDIS_VERSION_6_1) {
		in.ndis_hdr.ndis_rev = NDIS_OFFLOAD_REV_2;
		size = NDIS_OFFLOAD_SIZE_6_1;
	} else {
		in.ndis_hdr.ndis_rev = NDIS_OFFLOAD_REV_1;
		size = NDIS_OFFLOAD_SIZE_6_0;
	}
	in.ndis_hdr.ndis_size = size;

	caps_len = NDIS_OFFLOAD_SIZE;
	error = hn_rndis_query2(sc, OID_TCP_OFFLOAD_HARDWARE_CAPABILITIES,
	    &in, size, caps, &caps_len, NDIS_OFFLOAD_SIZE_6_0);
	if (error)
		return (error);

	/*
	 * Preliminary verification.
	 */
	if (caps->ndis_hdr.ndis_type != NDIS_OBJTYPE_OFFLOAD) {
		HN_WARN(sc, "invalid NDIS objtype 0x%02x",
		    caps->ndis_hdr.ndis_type);
		return (EINVAL);
	}
	if (caps->ndis_hdr.ndis_rev < NDIS_OFFLOAD_REV_1) {
		HN_WARN(sc, "invalid NDIS objrev 0x%02x",
		    caps->ndis_hdr.ndis_rev);
		return (EINVAL);
	}
	if (caps->ndis_hdr.ndis_size > caps_len) {
		HN_WARN(sc, "invalid NDIS objsize %u, "
		    "data size %lu", caps->ndis_hdr.ndis_size, caps_len);
		return (EINVAL);
	} else if (caps->ndis_hdr.ndis_size < NDIS_OFFLOAD_SIZE_6_0) {
		HN_WARN(sc, "invalid NDIS objsize %u",
		    caps->ndis_hdr.ndis_size);
		return (EINVAL);
	}

	/*
	 * NOTE:
	 * caps->ndis_hdr.ndis_size MUST be checked before accessing
	 * NDIS 6.1+ specific fields.
	 */
	HN_DEBUG(sc, 1, "hwcaps rev %u",
	    caps->ndis_hdr.ndis_rev);

	HN_DEBUG(sc, 1, "hwcaps csum: "
	    "ip4 tx 0x%x/0x%x rx 0x%x/0x%x, "
	    "ip6 tx 0x%x/0x%x rx 0x%x/0x%x",
	    caps->ndis_csum.ndis_ip4_txcsum,
	    caps->ndis_csum.ndis_ip4_txenc,
	    caps->ndis_csum.ndis_ip4_rxcsum,
	    caps->ndis_csum.ndis_ip4_rxenc,
	    caps->ndis_csum.ndis_ip6_txcsum,
	    caps->ndis_csum.ndis_ip6_txenc,
	    caps->ndis_csum.ndis_ip6_rxcsum,
	    caps->ndis_csum.ndis_ip6_rxenc);
	HN_DEBUG(sc, 1, "hwcaps lsov2: "
	    "ip4 maxsz %u minsg %u encap 0x%x, "
	    "ip6 maxsz %u minsg %u encap 0x%x opts 0x%x",
	    caps->ndis_lsov2.ndis_ip4_maxsz,
	    caps->ndis_lsov2.ndis_ip4_minsg,
	    caps->ndis_lsov2.ndis_ip4_encap,
	    caps->ndis_lsov2.ndis_ip6_maxsz,
	    caps->ndis_lsov2.ndis_ip6_minsg,
	    caps->ndis_lsov2.ndis_ip6_encap,
	    caps->ndis_lsov2.ndis_ip6_opts);

	return (0);
}

int
hn_rndis_attach(struct hn_softc *sc, int mtu)
{
	int error;

	/*
	 * Initialize RNDIS.
	 */
	error = hn_rndis_init(sc);
	if (error)
		return (error);

	/*
	 * Configure NDIS offload settings.
	 */
	(void) hn_rndis_conf_offload(sc, mtu);
	return (0);
}

void
hn_rndis_detach(struct hn_softc *sc)
{

	/* Halt the RNDIS. */
	(void) hn_rndis_halt(sc);
}
