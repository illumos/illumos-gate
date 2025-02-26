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
 * Copyright 2025 Oxide Computer Company
 * Copyright 2024 Ryan Zezeski
 */

/*
 * A test module for various mac routines.
 */
#include <inet/ip.h>
#include <inet/ip_impl.h>
#include <inet/sctp_ip.h>
#include <inet/tcp.h>
#include <inet/udp_impl.h>
#include <sys/dlpi.h>
#include <sys/ethernet.h>
#include <sys/ktest.h>
#include <sys/mac_provider.h>
#include <sys/pattr.h>
#include <sys/strsun.h>

typedef mblk_t *(*mac_sw_cksum_t)(mblk_t *, mac_emul_t);

typedef struct cksum_test_params {
	mblk_t		*ctp_mp;
	uchar_t		*ctp_raw;
	uint_t		ctp_raw_sz;
	boolean_t	ctp_do_partial;
	boolean_t	ctp_do_full;
	boolean_t	ctp_do_ipv4;
} cksum_test_params_t;

/* Arbitrary limit to padding allowed for cksum tests */
#define	PADDING_MAX	32

static boolean_t
cksum_test_parse_input(ktest_ctx_hdl_t *ctx, cksum_test_params_t *ctp)
{
	uchar_t *bytes;
	size_t num_bytes = 0;

	ktest_get_input(ctx, &bytes, &num_bytes);
	bzero(ctp, sizeof (*ctp));

	nvlist_t *params = NULL;
	if (nvlist_unpack((char *)bytes, num_bytes, &params, KM_SLEEP) != 0) {
		KT_ERROR(ctx, "Invalid nvlist input");
		return (B_FALSE);
	}

	uchar_t *pkt_bytes;
	uint_t pkt_sz;

	if (nvlist_lookup_byte_array(params, "pkt_bytes", &pkt_bytes,
	    &pkt_sz) != 0) {
		KT_ERROR(ctx, "Input missing pkt_bytes field");
		return (B_FALSE);
	}
	if (pkt_sz == 0) {
		KT_ERROR(ctx, "Packet must not be 0-length");
		return (B_FALSE);
	}

	uint32_t padding = 0;
	(void) nvlist_lookup_uint32(params, "padding", &padding);
	if (padding & 1) {
		KT_ERROR(ctx, "padding must be even");
		return (B_FALSE);
	} else if (padding > PADDING_MAX) {
		KT_ERROR(ctx, "padding greater than max of %u", PADDING_MAX);
		return (B_FALSE);
	}

	ctp->ctp_do_ipv4 = fnvlist_lookup_boolean(params, "cksum_ipv4");
	ctp->ctp_do_partial = fnvlist_lookup_boolean(params, "cksum_partial");
	ctp->ctp_do_full = fnvlist_lookup_boolean(params, "cksum_full");

	if (ctp->ctp_do_partial && ctp->ctp_do_full) {
		KT_ERROR(ctx, "Cannot request full and partial cksum");
		return (B_FALSE);
	}

	mblk_t *mp = allocb(pkt_sz + padding, 0);
	if (mp == NULL) {
		KT_ERROR(ctx, "Could not allocate mblk");
		return (B_FALSE);
	}
	if (padding != 0) {
		bzero(mp->b_rptr, padding);
		mp->b_rptr += padding;
		mp->b_wptr += padding;
	}
	bcopy(pkt_bytes, mp->b_rptr, pkt_sz);
	mp->b_wptr += pkt_sz;
	ctp->ctp_mp = mp;

	ctp->ctp_raw = kmem_alloc(pkt_sz, KM_SLEEP);
	bcopy(pkt_bytes, ctp->ctp_raw, pkt_sz);
	ctp->ctp_raw_sz = pkt_sz;

	nvlist_free(params);
	return (B_TRUE);
}

/* Calculate pseudo-header checksum for a packet */
static uint16_t
cksum_calc_pseudo(ktest_ctx_hdl_t *ctx, mblk_t *mp,
    const mac_ether_offload_info_t *meoi)
{
	if ((meoi->meoi_flags & MEOI_L4INFO_SET) == 0) {
		KT_ERROR(ctx, "MEOI lacks L4 info");
		return (0);
	}

	const uint16_t *iphs =
	    (const uint16_t *)(mp->b_rptr + meoi->meoi_l2hlen);
	uint32_t cksum = 0;

	/* Copied from ip_input_cksum_pseudo_v[46]() */
	if (meoi->meoi_l3proto == ETHERTYPE_IP) {
		cksum += iphs[6] + iphs[7] + iphs[8] + iphs[9];
	} else if (meoi->meoi_l3proto == ETHERTYPE_IPV6) {
		cksum += iphs[4] + iphs[5] + iphs[6] + iphs[7] +
		    iphs[8] + iphs[9] + iphs[10] + iphs[11] +
		    iphs[12] + iphs[13] + iphs[14] + iphs[15] +
		    iphs[16] + iphs[17] + iphs[18] + iphs[19];
	} else {
		KT_ERROR(ctx, "unexpected proto %u", meoi->meoi_l3proto);
		return (0);
	}

	switch (meoi->meoi_l4proto) {
	case IPPROTO_TCP:
		cksum += IP_TCP_CSUM_COMP;
		break;
	case IPPROTO_UDP:
		cksum += IP_UDP_CSUM_COMP;
		break;
	case IPPROTO_ICMPV6:
		cksum += IP_ICMPV6_CSUM_COMP;
		break;
	default:
		KT_ERROR(ctx, "unexpected l4 proto %u", meoi->meoi_l4proto);
		return (0);
	}

	uint16_t ulp_len =
	    meoi->meoi_len - ((uint16_t)meoi->meoi_l2hlen + meoi->meoi_l3hlen);
	if (meoi->meoi_l3proto == ETHERTYPE_IP) {
		/*
		 * IPv4 packets can fall below the 60-byte minimum for ethernet,
		 * resulting in padding which makes the "easy" means of
		 * determining ULP length potentially inaccurate.
		 *
		 * Reach into the v4 header to make that calculation.
		 */
		const ipha_t *ipha =
		    (const ipha_t *)(mp->b_rptr + meoi->meoi_l2hlen);
		ulp_len = ntohs(ipha->ipha_length) - meoi->meoi_l3hlen;
	}

	cksum += htons(ulp_len);

	cksum = (cksum >> 16) + (cksum & 0xffff);
	cksum = (cksum >> 16) + (cksum & 0xffff);
	return (cksum);
}

/*
 * Verify mac_sw_cksum() emulation against an arbitrary input packet.  If the
 * packet is of a support protocol, any L3 and L4 checksums are cleared, and
 * then mac_sw_cksum() is called to perform the offload emulation.  Afterwards,
 * the packet is compared to see if it equasl the input, which is assumed to
 * have correct checksums.
 *
 * This can request either emulation via HCK_PARTIALCKSUM or HCK_FULLCKSUM.
 */
static void
mac_sw_cksum_test(ktest_ctx_hdl_t *ctx)
{
	ddi_modhandle_t hdl = NULL;
	mac_sw_cksum_t mac_sw_cksum = NULL;

	if (ktest_hold_mod("mac", &hdl) != 0) {
		KT_ERROR(ctx, "failed to hold 'mac' module");
		return;
	}
	if (ktest_get_fn(hdl, "mac_sw_cksum", (void **)&mac_sw_cksum) != 0) {
		KT_ERROR(ctx, "failed to resolve symbol mac`mac_sw_cksum");
		goto cleanup;
	}

	cksum_test_params_t ctp;
	if (!cksum_test_parse_input(ctx, &ctp)) {
		goto cleanup;
	}
	mblk_t *mp = ctp.ctp_mp;

	mac_ether_offload_info_t meoi;
	mac_ether_offload_info(mp, &meoi);

	if ((meoi.meoi_flags & MEOI_L3INFO_SET) == 0 ||
	    (meoi.meoi_l3proto != ETHERTYPE_IP &&
	    meoi.meoi_l3proto != ETHERTYPE_IPV6)) {
		KT_SKIP(ctx, "l3 protocol not recognized/supported");
		goto cleanup;
	}

	mac_emul_t emul_flags = 0;
	uint_t hck_flags = 0, hck_start = 0, hck_stuff = 0, hck_end = 0;
	if (meoi.meoi_l3proto == ETHERTYPE_IP && ctp.ctp_do_ipv4) {
		ipha_t *ipha = (ipha_t *)(mp->b_rptr + meoi.meoi_l2hlen);

		ipha->ipha_hdr_checksum = 0;
		emul_flags |= MAC_IPCKSUM_EMUL;
		hck_flags |= HCK_IPV4_HDRCKSUM;
	}

	const boolean_t do_l4 = ctp.ctp_do_partial || ctp.ctp_do_full;
	if ((meoi.meoi_flags & MEOI_L4INFO_SET) != 0 && do_l4) {
		boolean_t valid_proto = B_FALSE;
		hck_start = meoi.meoi_l2hlen + meoi.meoi_l3hlen;
		hck_stuff = hck_start;
		hck_end = meoi.meoi_len;

		switch (meoi.meoi_l4proto) {
		case IPPROTO_TCP:
			hck_stuff += offsetof(tcpha_t, tha_sum);
			valid_proto = B_TRUE;
			break;
		case IPPROTO_UDP:
			hck_stuff += offsetof(udpha_t, uha_checksum);
			valid_proto = B_TRUE;
			break;
		case IPPROTO_ICMPV6:
			hck_stuff += offsetof(icmp6_t, icmp6_cksum);
			valid_proto = B_TRUE;
			break;
		case IPPROTO_SCTP:
			/*
			 * Only full checksums are supported for SCTP, and the
			 * test logic for clearing the existing sum needs to
			 * account for its increased width.
			 */
			hck_stuff += offsetof(sctp_hdr_t, sh_chksum);
			if (ctp.ctp_do_full) {
				uint32_t *lckp =
				    (uint32_t *)(mp->b_rptr + hck_stuff);
				*lckp = 0;
				/*
				 * Set the emulation flags ourself, and skip the
				 * logic below by leaving valid_proto as false.
				 */
				hck_flags |= HCK_FULLCKSUM;
				emul_flags |= MAC_HWCKSUM_EMUL;
			}
			break;
		default:
			break;
		}

		if (valid_proto) {
			uint16_t *ckp = (uint16_t *)(mp->b_rptr + hck_stuff);

			emul_flags |= MAC_HWCKSUM_EMUL;
			if (ctp.ctp_do_partial) {
				hck_flags |= HCK_PARTIALCKSUM;
				/* Populate L4 pseudo-header cksum */
				*ckp = cksum_calc_pseudo(ctx, mp, &meoi);
			} else {
				hck_flags |= HCK_FULLCKSUM;
				/* Zero out the L4 cksum */
				*ckp = 0;
			}
		}
	}
	if (do_l4 && (hck_flags & (HCK_FULLCKSUM|HCK_PARTIALCKSUM)) == 0) {
		KT_SKIP(ctx, "L4 checksum not support for packet");
		goto cleanup;
	}

	if (emul_flags != 0) {
		if ((hck_flags & HCK_PARTIALCKSUM) == 0) {
			hck_start = hck_stuff = hck_end = 0;
		} else {
			/*
			 * The offsets for mac_hcksum_set are all relative to
			 * the start of the L3 header.  Prior to here, these
			 * values were relative to the start of the packet.
			 */
			hck_start -= meoi.meoi_l2hlen;
			hck_stuff -= meoi.meoi_l2hlen;
			hck_end -= meoi.meoi_l2hlen;
		}
		mac_hcksum_set(mp, hck_start, hck_stuff, hck_end, 0, hck_flags);
		ctp.ctp_mp = mp = mac_sw_cksum(mp, emul_flags);

		KT_ASSERT3UG(mp, !=, NULL, ctx, cleanup);
		const uint_t input_pkt_sz = ctp.ctp_raw_sz;
		KT_ASSERT3UG(MBLKL(mp), ==, input_pkt_sz, ctx, cleanup);

		for (uint_t i = 0; i < input_pkt_sz; i++) {
			/*
			 * If there is any mismatch from the expected output,
			 * print the contents of the first "bad" byte.
			 */
			if (mp->b_rptr[i] != ctp.ctp_raw[i]) {
				if (i + 2 < input_pkt_sz) {
					KT_FAIL(ctx, "mp[%x] %04X != %04X",
					    i,
					    *(uint16_t *)&mp->b_rptr[i],
					    *(uint16_t *)&ctp.ctp_raw[i]);
				} else {
					KT_FAIL(ctx, "mp[%x] %02X != %02X",
					    i, mp->b_rptr[i], ctp.ctp_raw[i]);
				}
				goto cleanup;
			}
		}
	} else {
		KT_SKIP(ctx, "no checksums supported for packet");
		goto cleanup;
	}

	KT_PASS(ctx);

cleanup:
	if (hdl != NULL) {
		ktest_release_mod(hdl);
	}
	if (ctp.ctp_mp != NULL) {
		freeb(ctp.ctp_mp);
	}
	if (ctp.ctp_raw != NULL) {
		kmem_free(ctp.ctp_raw, ctp.ctp_raw_sz);
	}
}

typedef struct meoi_test_params {
	mblk_t				*mtp_mp;
	mac_ether_offload_info_t	mtp_partial;
	mac_ether_offload_info_t	mtp_results;
	uint_t				mtp_offset;
} meoi_test_params_t;

static void
nvlist_to_meoi(nvlist_t *results, mac_ether_offload_info_t *meoi)
{
	uint64_t u64_val;
	int int_val;
	uint16_t u16_val;
	uint8_t u8_val;

	bzero(meoi, sizeof (*meoi));
	if (nvlist_lookup_int32(results, "meoi_flags", &int_val) == 0) {
		meoi->meoi_flags = int_val;
	}
	if (nvlist_lookup_uint64(results, "meoi_len", &u64_val) == 0) {
		meoi->meoi_len = u64_val;
	}
	if (nvlist_lookup_uint8(results, "meoi_l2hlen", &u8_val) == 0) {
		meoi->meoi_l2hlen = u8_val;
	}
	if (nvlist_lookup_uint16(results, "meoi_l3proto", &u16_val) == 0) {
		meoi->meoi_l3proto = u16_val;
	}
	if (nvlist_lookup_uint16(results, "meoi_l3hlen", &u16_val) == 0) {
		meoi->meoi_l3hlen = u16_val;
	}
	if (nvlist_lookup_uint8(results, "meoi_l4proto", &u8_val) == 0) {
		meoi->meoi_l4proto = u8_val;
	}
	if (nvlist_lookup_uint8(results, "meoi_l4hlen", &u8_val) == 0) {
		meoi->meoi_l4hlen = u8_val;
	}
}

static mblk_t *
alloc_split_pkt(ktest_ctx_hdl_t *ctx, nvlist_t *nvl, const char *pkt_field)
{
	uchar_t *pkt_bytes;
	uint_t pkt_sz;

	if (nvlist_lookup_byte_array(nvl, pkt_field, &pkt_bytes,
	    &pkt_sz) != 0) {
		KT_ERROR(ctx, "Input missing %s field", pkt_field);
		return (NULL);
	}

	const uint32_t *splits = NULL;
	uint_t num_splits = 0;
	(void) nvlist_lookup_uint32_array(nvl, "splits", (uint32_t **)&splits,
	    &num_splits);

	uint_t split_idx = 0;
	mblk_t *result = NULL, *tail = NULL;

	do {
		uint_t block_sz = pkt_sz;
		if (split_idx < num_splits) {
			block_sz = MIN(block_sz, splits[split_idx]);
		}

		mblk_t *mp = allocb(block_sz, 0);
		if (mp == NULL) {
			KT_ERROR(ctx, "mblk alloc failure");
			freemsg(result);
			return (NULL);
		}

		if (result == NULL) {
			result = mp;
		} else {
			tail->b_cont = mp;
		}
		tail = mp;

		if (block_sz != 0) {
			bcopy(pkt_bytes, mp->b_wptr, block_sz);
			mp->b_wptr += block_sz;
		}
		pkt_sz -= block_sz;
		pkt_bytes += block_sz;
		split_idx++;
	} while (pkt_sz > 0);

	return (result);
}

/*
 * mac_ether_offload_info tests expect the following as input (via packed
 * nvlist)
 *
 * - pkt_bytes (byte array): packet bytes to parse
 * - splits (uint32 array, optional): byte sizes to split packet into mblks
 * - results (nvlist): mac_ether_offload_info result struct to compare
 *   - Field names and types should match those in the mac_ether_offload_info
 *     struct. Any fields not specified will be assumed to be zero.
 *
 * For mac_partial_offload_info tests, two additional fields are parsed:
 *
 * - offset (uint32, optional): offset into the packet at which the parsing
 *   should begin
 * - partial (nvlist): mac_ether_offload_info input struct to be used as
 *   starting point for partial parsing
 */
static boolean_t
meoi_test_parse_input(ktest_ctx_hdl_t *ctx, meoi_test_params_t *mtp,
    boolean_t test_partial)
{
	uchar_t *bytes;
	size_t num_bytes = 0;

	ktest_get_input(ctx, &bytes, &num_bytes);
	bzero(mtp, sizeof (*mtp));

	nvlist_t *params = NULL;
	if (nvlist_unpack((char *)bytes, num_bytes, &params, KM_SLEEP) != 0) {
		KT_ERROR(ctx, "Invalid nvlist input");
		return (B_FALSE);
	}

	nvlist_t *results;
	if (nvlist_lookup_nvlist(params, "results", &results) != 0) {
		KT_ERROR(ctx, "Input missing results field");
		nvlist_free(params);
		return (B_FALSE);
	}

	if (test_partial) {
		nvlist_t *partial;
		if (nvlist_lookup_nvlist(params, "partial", &partial) != 0) {
			KT_ERROR(ctx, "Input missing partial field");
			nvlist_free(params);
			return (B_FALSE);
		} else {
			nvlist_to_meoi(partial, &mtp->mtp_partial);
		}

		(void) nvlist_lookup_uint32(params, "offset", &mtp->mtp_offset);
	}

	mtp->mtp_mp = alloc_split_pkt(ctx, params, "pkt_bytes");
	if (mtp->mtp_mp == NULL) {
		nvlist_free(params);
		return (B_FALSE);
	}

	nvlist_to_meoi(results, &mtp->mtp_results);

	nvlist_free(params);
	return (B_TRUE);
}

void
mac_ether_offload_info_test(ktest_ctx_hdl_t *ctx)
{
	meoi_test_params_t mtp = { 0 };

	if (!meoi_test_parse_input(ctx, &mtp, B_FALSE)) {
		return;
	}

	mac_ether_offload_info_t result;
	mac_ether_offload_info(mtp.mtp_mp, &result);

	const mac_ether_offload_info_t *expect = &mtp.mtp_results;
	KT_ASSERT3UG(result.meoi_flags, ==, expect->meoi_flags, ctx, done);
	KT_ASSERT3UG(result.meoi_l2hlen, ==, expect->meoi_l2hlen, ctx, done);
	KT_ASSERT3UG(result.meoi_l3proto, ==, expect->meoi_l3proto, ctx, done);
	KT_ASSERT3UG(result.meoi_l3hlen, ==, expect->meoi_l3hlen, ctx, done);
	KT_ASSERT3UG(result.meoi_l4proto, ==, expect->meoi_l4proto, ctx, done);
	KT_ASSERT3UG(result.meoi_l4hlen, ==, expect->meoi_l4hlen, ctx, done);

	KT_PASS(ctx);

done:
	freemsg(mtp.mtp_mp);
}

void
mac_partial_offload_info_test(ktest_ctx_hdl_t *ctx)
{
	meoi_test_params_t mtp = { 0 };

	if (!meoi_test_parse_input(ctx, &mtp, B_TRUE)) {
		return;
	}

	mac_ether_offload_info_t *result = &mtp.mtp_partial;
	mac_partial_offload_info(mtp.mtp_mp, mtp.mtp_offset, result);

	const mac_ether_offload_info_t *expect = &mtp.mtp_results;
	KT_ASSERT3UG(result->meoi_flags, ==, expect->meoi_flags, ctx, done);
	KT_ASSERT3UG(result->meoi_l2hlen, ==, expect->meoi_l2hlen, ctx, done);
	KT_ASSERT3UG(result->meoi_l3proto, ==, expect->meoi_l3proto, ctx, done);
	KT_ASSERT3UG(result->meoi_l3hlen, ==, expect->meoi_l3hlen, ctx, done);
	KT_ASSERT3UG(result->meoi_l4proto, ==, expect->meoi_l4proto, ctx, done);
	KT_ASSERT3UG(result->meoi_l4hlen, ==, expect->meoi_l4hlen, ctx, done);

	KT_PASS(ctx);

done:
	freemsg(mtp.mtp_mp);
}

typedef struct ether_test_params {
	mblk_t		*etp_mp;
	uint32_t	etp_tci;
	uint8_t		etp_dstaddr[ETHERADDRL];
	boolean_t	etp_is_err;
} ether_test_params_t;

/*
 * mac_ether_l2_info tests expect the following as input (via packed nvlist)
 *
 * - pkt_bytes (byte array): packet bytes to parse
 * - splits (uint32 array, optional): byte sizes to split packet into mblks
 * - tci (uint32): VLAN TCI result value to compare
 * - dstaddr (byte array): MAC addr result value to compare
 * - is_err (boolean): if test function should return error
 */
static boolean_t
ether_parse_input(ktest_ctx_hdl_t *ctx, ether_test_params_t *etp)
{
	uchar_t *bytes;
	size_t num_bytes = 0;

	ktest_get_input(ctx, &bytes, &num_bytes);
	bzero(etp, sizeof (*etp));

	nvlist_t *params = NULL;
	if (nvlist_unpack((char *)bytes, num_bytes, &params, KM_SLEEP) != 0) {
		KT_ERROR(ctx, "Invalid nvlist input");
		return (B_FALSE);
	}

	etp->etp_mp = alloc_split_pkt(ctx, params, "pkt_bytes");
	if (etp->etp_mp == NULL) {
		nvlist_free(params);
		return (B_FALSE);
	}

	if (nvlist_lookup_uint32(params, "tci", &etp->etp_tci) != 0) {
		KT_ERROR(ctx, "Input missing tci field");
		nvlist_free(params);
		return (B_FALSE);
	}

	uchar_t *dstaddr;
	uint_t dstaddr_sz;
	if (nvlist_lookup_byte_array(params, "dstaddr", &dstaddr,
	    &dstaddr_sz) != 0) {
		KT_ERROR(ctx, "Input missing dstaddr field");
		nvlist_free(params);
		return (B_FALSE);
	} else if (dstaddr_sz != ETHERADDRL) {
		KT_ERROR(ctx, "bad dstaddr size %u != %u", dstaddr_sz,
		    ETHERADDRL);
		nvlist_free(params);
		return (B_FALSE);
	}
	bcopy(dstaddr, &etp->etp_dstaddr, ETHERADDRL);

	etp->etp_is_err = nvlist_lookup_boolean(params, "is_err") == 0;

	nvlist_free(params);
	return (B_TRUE);
}

void
mac_ether_l2_info_test(ktest_ctx_hdl_t *ctx)
{
	ether_test_params_t etp = { 0 };

	if (!ether_parse_input(ctx, &etp)) {
		return;
	}

	uint8_t dstaddr[ETHERADDRL];
	uint32_t vlan_tci = 0;
	const boolean_t is_err =
	    !mac_ether_l2_info(etp.etp_mp, dstaddr, &vlan_tci);

	KT_ASSERTG(is_err == etp.etp_is_err, ctx, done);
	KT_ASSERTG(bcmp(dstaddr, etp.etp_dstaddr, ETHERADDRL) == 0, ctx,
	    done);
	KT_ASSERT3UG(vlan_tci, ==, etp.etp_tci, ctx, done);

	KT_PASS(ctx);

done:
	freemsg(etp.etp_mp);
}


static struct modlmisc mac_ktest_modlmisc = {
	.misc_modops = &mod_miscops,
	.misc_linkinfo = "mac ktest module"
};

static struct modlinkage mac_ktest_modlinkage = {
	.ml_rev = MODREV_1,
	.ml_linkage = { &mac_ktest_modlmisc, NULL }
};

int
_init()
{
	int ret;
	ktest_module_hdl_t *km = NULL;
	ktest_suite_hdl_t *ks = NULL;

	VERIFY0(ktest_create_module("mac", &km));
	VERIFY0(ktest_add_suite(km, "checksum", &ks));
	VERIFY0(ktest_add_test(ks, "mac_sw_cksum_test",
	    mac_sw_cksum_test, KTEST_FLAG_INPUT));

	ks = NULL;
	VERIFY0(ktest_add_suite(km, "parsing", &ks));
	VERIFY0(ktest_add_test(ks, "mac_ether_offload_info_test",
	    mac_ether_offload_info_test, KTEST_FLAG_INPUT));
	VERIFY0(ktest_add_test(ks, "mac_partial_offload_info_test",
	    mac_partial_offload_info_test, KTEST_FLAG_INPUT));
	VERIFY0(ktest_add_test(ks, "mac_ether_l2_info_test",
	    mac_ether_l2_info_test, KTEST_FLAG_INPUT));

	if ((ret = ktest_register_module(km)) != 0) {
		ktest_free_module(km);
		return (ret);
	}

	if ((ret = mod_install(&mac_ktest_modlinkage)) != 0) {
		ktest_unregister_module("mac");
		return (ret);
	}

	return (0);
}

int
_fini(void)
{
	ktest_unregister_module("mac");
	return (mod_remove(&mac_ktest_modlinkage));
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&mac_ktest_modlinkage, modinfop));
}
