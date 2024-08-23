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
 * Copyright 2023 Oxide Computer Company
 * Copyright 2024 Ryan Zezeski
 */

/*
 * A test module for various mac routines.
 */
#include <inet/ip.h>
#include <inet/ip_impl.h>
#include <inet/tcp.h>
#include <sys/dlpi.h>
#include <sys/ethernet.h>
#include <sys/ktest.h>

static uint32_t
mt_pseudo_sum(const uint8_t proto, ipha_t *ip)
{
	const uint32_t ip_hdr_sz = IPH_HDR_LENGTH(ip);
	const ipaddr_t src = ip->ipha_src;
	const ipaddr_t dst = ip->ipha_dst;
	uint16_t len;
	uint32_t sum = 0;

	switch (proto) {
	case IPPROTO_TCP:
		sum = IP_TCP_CSUM_COMP;
		break;

	case IPPROTO_UDP:
		sum = IP_UDP_CSUM_COMP;
		break;
	}

	len = ntohs(ip->ipha_length) - ip_hdr_sz;
	sum += (dst >> 16) + (dst & 0xFFFF) + (src >> 16) + (src & 0xFFFF);
	sum += htons(len);
	return (sum);
}

/*
 * An implementation of the internet checksum inspired by RFC 1071.
 * This implementation is as naive as possible. It serves as the
 * reference point for testing the optimized versions in the rest of
 * our stack. This is no place for optimization or cleverness.
 *
 * Arguments
 *
 *     initial: The initial sum value.
 *
 *     addr: Pointer to the beginning of the byte stream to sum.
 *
 *     len: The number of bytes to sum.
 *
 * Return
 *
 *     The resulting internet checksum.
 */
static uint32_t
mt_rfc1071_sum(uint32_t initial, uint16_t *addr, size_t len)
{
	uint32_t sum = initial;

	while (len > 1) {
		sum += *addr;
		addr++;
		len -= 2;
	}

	if (len == 1) {
		sum += *((uint8_t *)addr);
	}

	while ((sum >> 16) != 0) {
		sum = (sum >> 16) + (sum & 0xFFFF);
	}

	return (~sum & 0xFFFF);
}

typedef boolean_t (*mac_sw_cksum_ipv4_t)(mblk_t *, uint32_t, ipha_t *,
    const char **);

/*
 * Fill out a basic TCP header in the given mblk at the given offset.
 * A TCP header should never straddle an mblk boundary.
 */
static tcpha_t *
mt_tcp_basic_hdr(mblk_t *mp, uint16_t offset, uint16_t lport, uint16_t fport,
    uint32_t seq, uint32_t ack, uint8_t flags, uint16_t win)
{
	tcpha_t *tcp = (tcpha_t *)(mp->b_rptr + offset);

	VERIFY3U((uintptr_t)tcp + sizeof (*tcp), <=, mp->b_wptr);
	tcp->tha_lport = htons(lport);
	tcp->tha_fport = htons(fport);
	tcp->tha_seq = htonl(seq);
	tcp->tha_ack = htonl(ack);
	tcp->tha_offset_and_reserved = 0x5 << 4;
	tcp->tha_flags = flags;
	tcp->tha_win = htons(win);
	tcp->tha_sum = 0x0;
	tcp->tha_urp = 0x0;

	return (tcp);
}

static ipha_t *
mt_ipv4_simple_hdr(mblk_t *mp, uint16_t offset, uint16_t datum_length,
    uint16_t ident, uint8_t proto, char *src, char *dst)
{
	uint32_t srcaddr, dstaddr;
	ipha_t *ip = (ipha_t *)(mp->b_rptr + offset);

	VERIFY3U((uintptr_t)ip + sizeof (*ip), <=, mp->b_wptr);

	VERIFY(inet_pton(AF_INET, src, &srcaddr));
	VERIFY(inet_pton(AF_INET, dst, &dstaddr));
	ip->ipha_version_and_hdr_length = IP_SIMPLE_HDR_VERSION;
	ip->ipha_type_of_service = 0x0;
	ip->ipha_length = htons(sizeof (*ip) + datum_length);
	ip->ipha_ident = htons(ident);
	ip->ipha_fragment_offset_and_flags = IPH_DF_HTONS;
	ip->ipha_ttl = 255;
	ip->ipha_protocol = proto;
	ip->ipha_hdr_checksum = 0x0;
	ip->ipha_src = srcaddr;
	ip->ipha_dst = dstaddr;

	return (ip);
}

static struct ether_header *
mt_ether_hdr(mblk_t *mp, uint16_t offset, char *dst, char *src, uint16_t etype)
{
	char *byte = dst;
	unsigned long tmp;
	struct ether_header *eh = (struct ether_header *)(mp->b_rptr + offset);

	VERIFY3U((uintptr_t)eh + sizeof (*eh), <=, mp->b_wptr);

	/* No strtok in these here parts. */
	for (uint_t i = 0; i < 6; i++) {
		char *end = strchr(dst, ':');
		VERIFY3P(end, !=, NULL);
		VERIFY0(ddi_strtoul(byte, NULL, 16, &tmp));
		VERIFY3U(tmp, <=, 255);
		eh->ether_dhost.ether_addr_octet[i] = tmp;
		byte = end + 1;
	}

	byte = src;
	for (uint_t i = 0; i < 6; i++) {
		char *end = strchr(dst, ':');
		VERIFY3P(end, !=, NULL);
		VERIFY0(ddi_strtoul(byte, NULL, 16, &tmp));
		VERIFY3U(tmp, <=, 255);
		eh->ether_shost.ether_addr_octet[i] = tmp;
		byte = end + 1;
	}

	eh->ether_type = etype;
	return (eh);
}

void
mac_sw_cksum_ipv4_tcp_test(ktest_ctx_hdl_t *ctx)
{
	ddi_modhandle_t hdl = NULL;
	mac_sw_cksum_ipv4_t mac_sw_cksum_ipv4 = NULL;
	tcpha_t *tcp;
	ipha_t *ip;
	struct ether_header *eh;
	mblk_t *mp = NULL;
	char *msg = "...when it's not your turn";
	size_t msglen = strlen(msg) + 1;
	size_t mplen;
	const char *err = "";
	uint32_t sum;
	size_t ehsz = sizeof (*eh);
	size_t ipsz = sizeof (*ip);
	size_t tcpsz = sizeof (*tcp);

	if (ktest_hold_mod("mac", &hdl) != 0) {
		KT_ERROR(ctx, "failed to hold 'mac' module");
		return;
	}

	if (ktest_get_fn(hdl, "mac_sw_cksum_ipv4",
	    (void **)&mac_sw_cksum_ipv4) != 0) {
		KT_ERROR(ctx, "failed to resolve symbol %s`%s", "mac",
		    "mac_sw_cksum_ipv4");
		goto cleanup;
	}

	mplen = ehsz + ipsz + tcpsz + msglen;
	mp = allocb(mplen, 0);
	KT_EASSERT3P(mp, !=, NULL, ctx);
	mp->b_wptr = mp->b_rptr + mplen;
	tcp = mt_tcp_basic_hdr(mp, ehsz + ipsz, 2002, 2008, 1, 166, 0, 32000);
	ip = mt_ipv4_simple_hdr(mp, ehsz, tcpsz + msglen, 410, IPPROTO_TCP,
	    "192.168.2.4", "192.168.2.5");
	eh = mt_ether_hdr(mp, 0, "f2:35:c2:72:26:57", "92:ce:5a:29:46:9d",
	    ETHERTYPE_IP);

	bcopy(msg, mp->b_rptr + ehsz + ipsz + tcpsz, msglen);

	/*
	 * It's important that we calculate the reference checksum
	 * first, because mac_sw_cksum_ipv4() populates the checksum
	 * field.
	 */
	sum = mt_pseudo_sum(IPPROTO_TCP, ip);
	sum = mt_rfc1071_sum(sum, (uint16_t *)(mp->b_rptr + ehsz + ipsz),
	    tcpsz + msglen);

	/*
	 * The internet checksum can never be 0xFFFF, as that would
	 * indicate an input of all zeros.
	 */
	KT_ASSERT3UG(sum, !=, 0xFFFF, ctx, cleanup);
	KT_ASSERTG(mac_sw_cksum_ipv4(mp, ehsz, ip, &err), ctx, cleanup);
	KT_ASSERT3UG(tcp->tha_sum, !=, 0xFFFF, ctx, cleanup);
	KT_ASSERT3UG(sum, ==, tcp->tha_sum, ctx, cleanup);
	KT_PASS(ctx);

cleanup:
	if (hdl != NULL) {
		ktest_release_mod(hdl);
	}

	if (mp != NULL) {
		freeb(mp);
	}
}

/*
 * Verify that an unexpected IP protocol results in the expect
 * failure.
 */
void
mac_sw_cksum_ipv4_bad_proto_test(ktest_ctx_hdl_t *ctx)
{
	ddi_modhandle_t hdl = NULL;
	mac_sw_cksum_ipv4_t mac_sw_cksum_ipv4 = NULL;
	tcpha_t *tcp;
	ipha_t *ip;
	struct ether_header *eh;
	mblk_t *mp = NULL;
	char *msg = "...when it's not your turn";
	size_t msglen = strlen(msg) + 1;
	size_t mplen;
	const char *err = "";
	size_t ehsz = sizeof (*eh);
	size_t ipsz = sizeof (*ip);
	size_t tcpsz = sizeof (*tcp);

	if (ktest_hold_mod("mac", &hdl) != 0) {
		KT_ERROR(ctx, "failed to hold 'mac' module");
		return;
	}

	if (ktest_get_fn(hdl, "mac_sw_cksum_ipv4",
	    (void **)&mac_sw_cksum_ipv4) != 0) {
		KT_ERROR(ctx, "failed to resolve symbol mac`mac_sw_cksum_ipv4");
		goto cleanup;
	}

	mplen = ehsz + ipsz + tcpsz + msglen;
	mp = allocb(mplen, 0);
	KT_EASSERT3P(mp, !=, NULL, ctx);
	mp->b_wptr = mp->b_rptr + mplen;
	tcp = mt_tcp_basic_hdr(mp, ehsz + ipsz, 2002, 2008, 1, 166, 0, 32000);
	ip = mt_ipv4_simple_hdr(mp, ehsz, tcpsz + msglen, 410, IPPROTO_ENCAP,
	    "192.168.2.4", "192.168.2.5");
	eh = mt_ether_hdr(mp, 0, "f2:35:c2:72:26:57", "92:ce:5a:29:46:9d",
	    ETHERTYPE_IP);
	bcopy(msg, mp->b_rptr + ehsz + ipsz + tcpsz, msglen);
	KT_ASSERT0G(mac_sw_cksum_ipv4(mp, ehsz, ip, &err), ctx, cleanup);
	KT_PASS(ctx);

cleanup:
	if (hdl != NULL) {
		ktest_release_mod(hdl);
	}

	if (mp != NULL) {
		freeb(mp);
	}
}

typedef struct snoop_pkt_record_hdr {
	uint32_t	spr_orig_len;
	uint32_t	spr_include_len;
	uint32_t	spr_record_len;
	uint32_t	spr_cumulative_drops;
	uint32_t	spr_ts_secs;
	uint32_t	spr_ts_micros;
} snoop_pkt_record_hdr_t;

typedef struct snoop_pkt {
	uchar_t *sp_bytes;
	uint16_t sp_len;
} snoop_pkt_t;

typedef struct snoop_iter {
	uchar_t *sic_input;	/* beginning of stream */
	uintptr_t sic_end;	/* end of stream */
	uchar_t *sic_pos;	/* current position in stream */
	uint_t sic_pkt_num;	/* current packet number, 1-based */
	snoop_pkt_record_hdr_t *sic_pkt_hdr; /* current packet record header */
} snoop_iter_t;

#define	PAST_END(itr, len)	\
	(((uintptr_t)(itr)->sic_pos + len) > itr->sic_end)

/*
 * Get the next packet in the snoop stream iterator returned by
 * mt_snoop_iter_get(). A copy of the packet is returned via the pkt
 * pointer. The caller provides the snoop_pkt_t, and this function
 * allocates a new buffer inside it to hold a copy of the packet's
 * bytes. It is the responsibility of the caller to free the copy. It
 * is recommended the caller make use of desballoc(9F) along with the
 * snoop_pkt_free() callback. When all the packets in the stream have
 * been read all subsequent calls to this function will set sp_bytes
 * to NULL and sp_len to 0.
 *
 * The caller may optionally specify an rhdr argument in order to
 * receive a pointer to the packet record header (unlike the packet
 * bytes this is a pointer into the stream, not a copy).
 */
static int
mt_snoop_iter_next(ktest_ctx_hdl_t *ctx, snoop_iter_t *itr, snoop_pkt_t *pkt,
    snoop_pkt_record_hdr_t **rhdr)
{
	uchar_t *pkt_start;

	/*
	 * We've read exactly the number of bytes expected, this is
	 * the end.
	 */
	if ((uintptr_t)(itr->sic_pos) == itr->sic_end) {
		pkt->sp_bytes = NULL;
		pkt->sp_len = 0;

		if (rhdr != NULL)
			*rhdr = NULL;

		return (0);
	}

	/*
	 * A corrupted record or truncated stream could point us past
	 * the end of the stream.
	 */
	if (PAST_END(itr, sizeof (snoop_pkt_record_hdr_t))) {
		KT_ERROR(ctx, "record corrupted or stream truncated, read past "
		    "end of stream for record header #%d: 0x%p + %u > 0x%p",
		    itr->sic_pkt_num, itr->sic_pos,
		    sizeof (snoop_pkt_record_hdr_t), itr->sic_end);
		return (EIO);
	}

	itr->sic_pkt_hdr = (snoop_pkt_record_hdr_t *)itr->sic_pos;
	pkt_start = itr->sic_pos + sizeof (snoop_pkt_record_hdr_t);

	/*
	 * A corrupted record or truncated stream could point us past
	 * the end of the stream.
	 */
	if (PAST_END(itr, ntohl(itr->sic_pkt_hdr->spr_record_len))) {
		KT_ERROR(ctx, "record corrupted or stream truncated, read past "
		    "end of stream for record #%d: 0x%p + %u > 0x%p",
		    itr->sic_pkt_num, itr->sic_pos,
		    ntohl(itr->sic_pkt_hdr->spr_record_len), itr->sic_end);
		return (EIO);
	}

	pkt->sp_len = ntohl(itr->sic_pkt_hdr->spr_include_len);
	pkt->sp_bytes = kmem_zalloc(pkt->sp_len, KM_SLEEP);
	bcopy(pkt_start, pkt->sp_bytes, pkt->sp_len);
	itr->sic_pos += ntohl(itr->sic_pkt_hdr->spr_record_len);
	itr->sic_pkt_num++;

	if (rhdr != NULL) {
		*rhdr = itr->sic_pkt_hdr;
	}

	return (0);
}

/*
 * Parse a snoop data stream (RFC 1761) provided by input and return
 * a packet iterator to be used by mt_snoop_iter_next().
 */
static int
mt_snoop_iter_get(ktest_ctx_hdl_t *ctx, uchar_t *input, const uint_t input_len,
    snoop_iter_t **itr_out)
{
	const uchar_t id[8] = { 's', 'n', 'o', 'o', 'p', '\0', '\0', '\0' };
	uint32_t version;
	uint32_t datalink;
	snoop_iter_t *itr;

	*itr_out = NULL;

	if (input_len < 16) {
		KT_ERROR(ctx, "snoop stream truncated at file header: %u < %u ",
		    input_len, 16);
		return (ENOBUFS);
	}

	if (memcmp(input, &id, sizeof (id)) != 0) {
		KT_ERROR(ctx, "snoop stream malformed identification: %x %x %x "
		    "%x %x %x %x %x", input[0], input[1], input[2], input[3],
		    input[4], input[5], input[6], input[7]);
		return (EINVAL);
	}

	itr = kmem_zalloc(sizeof (*itr), KM_SLEEP);
	itr->sic_input = input;
	itr->sic_end = (uintptr_t)input + input_len;
	itr->sic_pos = input + sizeof (id);
	itr->sic_pkt_num = 1;
	itr->sic_pkt_hdr = NULL;
	version = ntohl(*(uint32_t *)itr->sic_pos);

	if (version != 2) {
		KT_ERROR(ctx, "snoop stream bad version: %u != %u", version, 2);
		return (EINVAL);
	}

	itr->sic_pos += sizeof (version);
	datalink = ntohl(*(uint32_t *)itr->sic_pos);

	/* We expect only Ethernet. */
	if (datalink != DL_ETHER) {
		KT_ERROR(ctx, "snoop stream bad datalink type: %u != %u",
		    datalink, DL_ETHER);
		kmem_free(itr, sizeof (*itr));
		return (EINVAL);
	}

	itr->sic_pos += sizeof (datalink);
	*itr_out = itr;
	return (0);
}

static void
snoop_pkt_free(snoop_pkt_t *pkt)
{
	kmem_free(pkt->sp_bytes, pkt->sp_len);
}

/*
 * Verify mac_sw_cksum_ipv4() against an arbitrary TCP stream read
 * from the snoop capture given as input. In order to verify the
 * checksum all TCP/IPv4 packets must be captured in full. The snoop
 * capture may contain non-TCP/IPv4 packets, which will be skipped
 * over. If not a single TCP/IPv4 packet is found, the test will
 * report an error.
 */
void
mac_sw_cksum_ipv4_snoop_test(ktest_ctx_hdl_t *ctx)
{
	ddi_modhandle_t hdl = NULL;
	mac_sw_cksum_ipv4_t mac_sw_cksum_ipv4 = NULL;
	uchar_t *bytes;
	size_t num_bytes = 0;
	uint_t pkt_num = 0;
	tcpha_t *tcp;
	ipha_t *ip;
	struct ether_header *eh;
	mblk_t *mp = NULL;
	const char *err = "";
	uint32_t csum;
	size_t ehsz, ipsz, tcpsz, msglen;
	snoop_iter_t *itr = NULL;
	snoop_pkt_record_hdr_t *hdr = NULL;
	boolean_t at_least_one = B_FALSE;
	snoop_pkt_t pkt;
	int ret;

	if (ktest_hold_mod("mac", &hdl) != 0) {
		KT_ERROR(ctx, "failed to hold 'mac' module");
		return;
	}

	if (ktest_get_fn(hdl, "mac_sw_cksum_ipv4",
	    (void **)&mac_sw_cksum_ipv4) != 0) {
		KT_ERROR(ctx, "failed to resolve symbol mac`mac_sw_cksum_ipv4");
		return;
	}

	ktest_get_input(ctx, &bytes, &num_bytes);
	ret = mt_snoop_iter_get(ctx, bytes, num_bytes, &itr);
	if (ret != 0) {
		/* mt_snoop_iter_get() already set error context. */
		goto cleanup;
	}

	bzero(&pkt, sizeof (pkt));

	while ((ret = mt_snoop_iter_next(ctx, itr, &pkt, &hdr)) == 0) {
		frtn_t frtn;

		if (pkt.sp_len == 0) {
			break;
		}

		pkt_num++;

		/*
		 * Prepend the packet record number to any
		 * fail/skip/error message so the user knows which
		 * record in the snoop stream to inspect.
		 */
		ktest_msg_prepend(ctx, "pkt #%u: ", pkt_num);

		/* IPv4 only */
		if (hdr->spr_include_len < (sizeof (*eh) + sizeof (*ip))) {
			continue;
		}

		/* fully recorded packets only */
		if (hdr->spr_include_len != hdr->spr_orig_len) {
			continue;
		}

		frtn.free_func = snoop_pkt_free;
		frtn.free_arg = (caddr_t)&pkt;
		mp = desballoc(pkt.sp_bytes, pkt.sp_len, 0, &frtn);
		KT_EASSERT3PG(mp, !=, NULL, ctx, cleanup);
		mp->b_wptr += pkt.sp_len;
		eh = (struct ether_header *)mp->b_rptr;
		ehsz = sizeof (*eh);

		/* IPv4 only */
		if (ntohs(eh->ether_type) != ETHERTYPE_IP) {
			freeb(mp);
			mp = NULL;
			continue;
		}

		ip = (ipha_t *)(mp->b_rptr + ehsz);
		ipsz = sizeof (*ip);

		if (ip->ipha_protocol == IPPROTO_TCP) {
			tcp = (tcpha_t *)(mp->b_rptr + sizeof (*eh) +
			    sizeof (*ip));
			tcpsz = TCP_HDR_LENGTH(tcp);
			msglen = ntohs(ip->ipha_length) - (ipsz + tcpsz);

			/* Let's make sure we don't run off into space. */
			if ((tcpsz + msglen) > (pkt.sp_len - (ehsz + ipsz))) {
				KT_ERROR(ctx, "(tcpsz=%lu + msglen=%lu) > "
				    "(pkt_len=%lu - (ehsz=%lu + ipsz=%lu))",
				    tcpsz, msglen, pkt.sp_len, ehsz, ipsz);
				goto cleanup;
			}

			/*
			 * As we are reading a snoop input stream we
			 * need to make sure to zero out any existing
			 * checksum.
			 */
			tcp->tha_sum = 0;
			csum = mt_pseudo_sum(IPPROTO_TCP, ip);
			csum = mt_rfc1071_sum(csum,
			    (uint16_t *)(mp->b_rptr + ehsz + ipsz),
			    tcpsz + msglen);
		} else {
			freeb(mp);
			mp = NULL;
			continue;
		}

		/*
		 * The internet checksum can never be 0xFFFF, as that
		 * would indicate an input of all zeros.
		 */
		KT_ASSERT3UG(csum, !=, 0xFFFF, ctx, cleanup);
		KT_ASSERTG(mac_sw_cksum_ipv4(mp, ehsz, ip, &err), ctx, cleanup);
		KT_ASSERT3UG(tcp->tha_sum, !=, 0xFFFF, ctx, cleanup);
		KT_ASSERT3UG(tcp->tha_sum, ==, csum, ctx, cleanup);
		at_least_one = B_TRUE;
		freeb(mp);
		mp = NULL;

		/*
		 * Clear the prepended message for the iterator call
		 * as it already includes the current record number
		 * (and pkt_num is not incremented, thus incorrect,
		 * until after a successful call).
		 */
		ktest_msg_clear(ctx);
	}

	if (ret != 0) {
		/* mt_snoop_next() already set error context. */
		goto cleanup;
	}

	if (at_least_one) {
		KT_PASS(ctx);
	} else {
		ktest_msg_clear(ctx);
		KT_ERROR(ctx, "at least one TCP/IPv4 packet expected");
	}

cleanup:
	if (hdl != NULL) {
		ktest_release_mod(hdl);
	}

	if (mp != NULL) {
		freeb(mp);
	}

	if (itr != NULL) {
		kmem_free(itr, sizeof (*itr));
	}
}

static struct modlmisc mac_test_modlmisc = {
	.misc_modops = &mod_miscops,
	.misc_linkinfo = "mac ktest module"
};

static struct modlinkage mac_test_modlinkage = {
	.ml_rev = MODREV_1,
	.ml_linkage = { &mac_test_modlmisc, NULL }
};

int
_init()
{
	int ret;
	ktest_module_hdl_t *km = NULL;
	ktest_suite_hdl_t *ks = NULL;

	VERIFY0(ktest_create_module("mac", &km));
	VERIFY0(ktest_add_suite(km, "checksum", &ks));
	VERIFY0(ktest_add_test(ks, "mac_sw_cksum_ipv4_tcp_test",
	    mac_sw_cksum_ipv4_tcp_test, KTEST_FLAG_NONE));
	VERIFY0(ktest_add_test(ks, "mac_sw_cksum_ipv4_bad_proto_test",
	    mac_sw_cksum_ipv4_bad_proto_test, KTEST_FLAG_NONE));
	VERIFY0(ktest_add_test(ks, "mac_sw_cksum_ipv4_snoop_test",
	    mac_sw_cksum_ipv4_snoop_test, KTEST_FLAG_INPUT));

	if ((ret = ktest_register_module(km)) != 0) {
		ktest_free_module(km);
		return (ret);
	}

	if ((ret = mod_install(&mac_test_modlinkage)) != 0) {
		ktest_unregister_module("mac");
		return (ret);
	}

	return (0);
}

int
_fini(void)
{
	ktest_unregister_module("mac");
	return (mod_remove(&mac_test_modlinkage));
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&mac_test_modlinkage, modinfop));
}
