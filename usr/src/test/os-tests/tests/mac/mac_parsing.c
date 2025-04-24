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
 * Copyright 2025 Oxide Computer Compnay
 */

/*
 * Driver for mac ktests
 *
 * This generates input payloads for the packet-parsing tests in the mac_test
 * module.  Prior to calling this program, that module (`mac_test`) must be
 * loaded so we can execute those tests with our payloads.  Since that manual
 * step of loading the module is required, this test is currently omitted from
 * the default runfile.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <fcntl.h>
#include <strings.h>
#include <spawn.h>
#include <wait.h>
#include <errno.h>
#include <err.h>
#include <sys/debug.h>
#include <sys/sysmacros.h>

#include <libnvpair.h>
#include <libktest.h>
#include <sys/ethernet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>

static ktest_hdl_t *kthdl = NULL;

static bool print_raw_pkts = false;

/*
 * Clones of in-kernel types to specify desired results.
 * N.B. These must be kept in sync with those in mac_provider.h
 */
typedef enum mac_ether_offload_flags {
	MEOI_L2INFO_SET		= 1 << 0,
	MEOI_L3INFO_SET		= 1 << 1,
	MEOI_L4INFO_SET		= 1 << 2,
	MEOI_VLAN_TAGGED	= 1 << 3,
	MEOI_L3_FRAG_MORE	= 1 << 4,
	MEOI_L3_FRAG_OFFSET	= 1 << 5
} mac_ether_offload_flags_t;

typedef struct mac_ether_offload_info {
	mac_ether_offload_flags_t	meoi_flags;	/* What's valid? */
	size_t		meoi_len;	/* Total message length */
	uint8_t		meoi_l2hlen;	/* How long is the Ethernet header? */
	uint16_t	meoi_l3proto;	/* What's the Ethertype */
	uint16_t	meoi_l3hlen;	/* How long is the header? */
	uint8_t		meoi_l4proto;	/* What is the payload type? */
	uint8_t		meoi_l4hlen;	/* How long is the L4 header */
} mac_ether_offload_info_t;


typedef struct test_pkt {
	size_t tp_sz;
	uint8_t *tp_bytes;
} test_pkt_t;

static test_pkt_t *
tp_alloc(void)
{
	void *buf = calloc(1, sizeof (test_pkt_t));
	VERIFY(buf != NULL);
	return (buf);
}

static void
tp_free(test_pkt_t *tp)
{
	if (tp->tp_bytes != NULL) {
		free(tp->tp_bytes);
	}
	free(tp);
}

static void
tp_append(test_pkt_t *tp, const void *bytes, size_t sz)
{
	if (tp->tp_bytes == NULL) {
		VERIFY(tp->tp_sz == 0);

		tp->tp_bytes = malloc(sz);
		VERIFY(tp->tp_bytes != NULL);
		bcopy(bytes, tp->tp_bytes, sz);
		tp->tp_sz = sz;
	} else {
		const size_t new_sz = tp->tp_sz + sz;

		tp->tp_bytes = realloc(tp->tp_bytes, new_sz);
		VERIFY(tp->tp_bytes != NULL);
		bcopy(bytes, &tp->tp_bytes[tp->tp_sz], sz);
		tp->tp_sz = new_sz;
	}
}

static void
append_ether(test_pkt_t *tp, uint16_t ethertype)
{
	struct ether_header hdr_ether = {
		.ether_type = htons(ethertype),
	};

	tp_append(tp, &hdr_ether, sizeof (hdr_ether));
}

static void
append_ip4(test_pkt_t *tp, uint8_t ipproto)
{
	struct ip hdr_ip = {
		.ip_v = 4,
		.ip_hl = 5,
		.ip_p = ipproto,
	};

	tp_append(tp, &hdr_ip, sizeof (hdr_ip));
}

static void
append_ip6(test_pkt_t *tp, uint8_t ipproto)
{
	struct ip6_hdr hdr_ip6 = { 0 };
	hdr_ip6.ip6_vfc = 0x60;
	hdr_ip6.ip6_nxt = ipproto;

	tp_append(tp, &hdr_ip6, sizeof (hdr_ip6));
}

static void
append_tcp(test_pkt_t *tp)
{
	struct tcphdr hdr_tcp = {
		.th_off = 5
	};
	tp_append(tp, &hdr_tcp, sizeof (hdr_tcp));
}

static test_pkt_t *
build_tcp4(mac_ether_offload_info_t *meoi)
{
	test_pkt_t *tp = tp_alloc();
	append_ether(tp, ETHERTYPE_IP);
	append_ip4(tp, IPPROTO_TCP);
	append_tcp(tp);

	mac_ether_offload_info_t expected = {
		.meoi_flags =
		    MEOI_L2INFO_SET | MEOI_L3INFO_SET | MEOI_L4INFO_SET,
		.meoi_len = tp->tp_sz,
		.meoi_l2hlen = sizeof (struct ether_header),
		.meoi_l3proto = ETHERTYPE_IP,
		.meoi_l3hlen = sizeof (struct ip),
		.meoi_l4proto = IPPROTO_TCP,
		.meoi_l4hlen = sizeof (struct tcphdr),
	};
	*meoi = expected;

	return (tp);
}

static test_pkt_t *
build_tcp6(mac_ether_offload_info_t *meoi)
{
	test_pkt_t *tp = tp_alloc();
	append_ether(tp, ETHERTYPE_IPV6);
	append_ip6(tp, IPPROTO_TCP);
	append_tcp(tp);

	mac_ether_offload_info_t expected = {
		.meoi_flags =
		    MEOI_L2INFO_SET | MEOI_L3INFO_SET | MEOI_L4INFO_SET,
		.meoi_len = tp->tp_sz,
		.meoi_l2hlen = sizeof (struct ether_header),
		.meoi_l3proto = ETHERTYPE_IPV6,
		.meoi_l3hlen = sizeof (struct ip6_hdr),
		.meoi_l4proto = IPPROTO_TCP,
		.meoi_l4hlen = sizeof (struct tcphdr),
	};
	*meoi = expected;

	return (tp);
}

static test_pkt_t *
build_frag_v4(mac_ether_offload_info_t *meoi)
{
	test_pkt_t *tp = tp_alloc();
	append_ether(tp, ETHERTYPE_IP);

	struct ip hdr_ip = {
		.ip_v = 4,
		.ip_hl = 5,
		.ip_off = htons(IP_MF),
		.ip_p = IPPROTO_TCP,
	};
	tp_append(tp, &hdr_ip, sizeof (hdr_ip));

	append_tcp(tp);

	mac_ether_offload_info_t expected = {
		.meoi_flags = MEOI_L2INFO_SET | MEOI_L3INFO_SET |
		    MEOI_L4INFO_SET | MEOI_L3_FRAG_MORE,
		.meoi_l2hlen = sizeof (struct ether_header),
		.meoi_l3hlen = sizeof (struct ip),
		.meoi_l4hlen = sizeof (struct tcphdr),
		.meoi_l3proto = ETHERTYPE_IP,
		.meoi_l4proto = IPPROTO_TCP
	};
	*meoi = expected;

	return (tp);
}

static test_pkt_t *
build_frag_v6(mac_ether_offload_info_t *meoi)
{
	test_pkt_t *tp = tp_alloc();
	append_ether(tp, ETHERTYPE_IPV6);

	struct ip6_hdr hdr_ip6 = { 0 };
	hdr_ip6.ip6_vfc = 0x60;
	hdr_ip6.ip6_nxt = IPPROTO_ROUTING;

	struct ip6_rthdr0 eh_route = {
		.ip6r0_nxt = IPPROTO_FRAGMENT,
		.ip6r0_len = 0,
		/* Has padding for len=0 8-byte boundary */
	};
	struct ip6_frag eh_frag = {
		.ip6f_nxt = IPPROTO_DSTOPTS,
		.ip6f_offlg = IP6F_MORE_FRAG,
	};
	struct ip6_dstopt {
		struct ip6_opt ip6dst_hdr;
		/* pad out to required 8-byte boundary */
		uint8_t ip6dst_data[6];
	} eh_dstopts = {
		.ip6dst_hdr = {
			.ip6o_type = IPPROTO_TCP,
			.ip6o_len = 0,
		}
	};

	/*
	 * Mark the packet for fragmentation, but do so in the middle of the EHs
	 * as a more contrived case.
	 */
	VERIFY(tp->tp_sz == sizeof (struct ether_header));
	tp_append(tp, &hdr_ip6, sizeof (hdr_ip6));
	tp_append(tp, &eh_route, sizeof (eh_route));
	tp_append(tp, &eh_frag, sizeof (eh_frag));
	tp_append(tp, &eh_dstopts, sizeof (eh_dstopts));
	const size_t l3sz = tp->tp_sz - sizeof (struct ether_header);

	append_tcp(tp);

	mac_ether_offload_info_t expected = {
		.meoi_flags = MEOI_L2INFO_SET | MEOI_L3INFO_SET |
		    MEOI_L4INFO_SET | MEOI_L3_FRAG_MORE,
		.meoi_l2hlen = sizeof (struct ether_header),
		.meoi_l3hlen = l3sz,
		.meoi_l4hlen = sizeof (struct tcphdr),
		.meoi_l3proto = ETHERTYPE_IPV6,
		.meoi_l4proto = IPPROTO_TCP
	};
	*meoi = expected;

	return (tp);
}

static test_pkt_t *
build_frag_off_v4(mac_ether_offload_info_t *meoi)
{
	test_pkt_t *tp = tp_alloc();
	append_ether(tp, ETHERTYPE_IP);

	struct ip hdr_ip = {
		.ip_v = 4,
		.ip_hl = 5,
		.ip_off = htons(0xff << 3),
		.ip_p = IPPROTO_TCP,
	};
	tp_append(tp, &hdr_ip, sizeof (hdr_ip));

	append_tcp(tp);

	mac_ether_offload_info_t expected = {
		.meoi_flags = MEOI_L2INFO_SET | MEOI_L3INFO_SET |
		    MEOI_L3_FRAG_OFFSET,
		.meoi_l2hlen = sizeof (struct ether_header),
		.meoi_l3hlen = sizeof (struct ip),
		.meoi_l3proto = ETHERTYPE_IP,
		.meoi_l4proto = IPPROTO_TCP,
	};
	*meoi = expected;

	return (tp);
}

static test_pkt_t *
build_frag_off_v6(mac_ether_offload_info_t *meoi)
{
	test_pkt_t *tp = tp_alloc();
	append_ether(tp, ETHERTYPE_IPV6);

	struct ip6_hdr hdr_ip6 = { 0 };
	hdr_ip6.ip6_vfc = 0x60;
	hdr_ip6.ip6_nxt = IPPROTO_ROUTING;

	struct ip6_rthdr0 eh_route = {
		.ip6r0_nxt = IPPROTO_FRAGMENT,
		.ip6r0_len = 0,
		/* Has padding for len=0 8-byte boundary */
	};
	struct ip6_frag eh_frag = {
		.ip6f_nxt = IPPROTO_DSTOPTS,
		.ip6f_offlg = htons(0xff << 3),
	};
	struct ip6_dstopt {
		struct ip6_opt ip6dst_hdr;
		/* pad out to required 8-byte boundary */
		uint8_t ip6dst_data[6];
	} eh_dstopts = {
		.ip6dst_hdr = {
			.ip6o_type = IPPROTO_TCP,
			.ip6o_len = 0,
		}
	};

	/*
	 * Mark the packet for fragmentation, but do so in the middle of the EHs
	 * as a more contrived case.
	 */
	VERIFY(tp->tp_sz == sizeof (struct ether_header));
	tp_append(tp, &hdr_ip6, sizeof (hdr_ip6));
	tp_append(tp, &eh_route, sizeof (eh_route));
	tp_append(tp, &eh_frag, sizeof (eh_frag));
	tp_append(tp, &eh_dstopts, sizeof (eh_dstopts));
	const size_t l3sz = tp->tp_sz - sizeof (struct ether_header);

	append_tcp(tp);

	mac_ether_offload_info_t expected = {
		.meoi_flags = MEOI_L2INFO_SET | MEOI_L3INFO_SET |
		    MEOI_L3_FRAG_OFFSET,
		.meoi_l2hlen = sizeof (struct ether_header),
		.meoi_l3hlen = l3sz,
		.meoi_l3proto = ETHERTYPE_IPV6,
		.meoi_l4proto = IPPROTO_TCP,
	};
	*meoi = expected;

	return (tp);
}

static nvlist_t *
meoi_to_nvlist(const mac_ether_offload_info_t *meoi)
{
	nvlist_t *out = fnvlist_alloc();
	fnvlist_add_int32(out, "meoi_flags", meoi->meoi_flags);
	fnvlist_add_uint64(out, "meoi_len", meoi->meoi_len);
	fnvlist_add_uint8(out, "meoi_l2hlen", meoi->meoi_l2hlen);
	fnvlist_add_uint16(out, "meoi_l3proto", meoi->meoi_l3proto);
	fnvlist_add_uint16(out, "meoi_l3hlen", meoi->meoi_l3hlen);
	fnvlist_add_uint8(out, "meoi_l4proto", meoi->meoi_l4proto);
	fnvlist_add_uint8(out, "meoi_l4hlen", meoi->meoi_l4hlen);

	return (out);
}

static nvlist_t *
build_meoi_payload(test_pkt_t *tp, const mac_ether_offload_info_t *results,
    uint32_t *splits, uint_t num_splits)
{
	nvlist_t *nvl_results = meoi_to_nvlist(results);

	nvlist_t *payload = fnvlist_alloc();
	fnvlist_add_byte_array(payload, "pkt_bytes", tp->tp_bytes, tp->tp_sz);
	if (num_splits != 0 && splits != NULL) {
		fnvlist_add_uint32_array(payload, "splits", splits,
		    num_splits);
	}
	fnvlist_add_nvlist(payload, "results", nvl_results);

	nvlist_free(nvl_results);

	return (payload);
}

static nvlist_t *
build_partial_payload(test_pkt_t *tp, uint_t offset,
    const mac_ether_offload_info_t *partial,
    const mac_ether_offload_info_t *results,
    uint32_t *splits, uint_t num_splits)
{
	nvlist_t *nvl_partial = meoi_to_nvlist(partial);
	nvlist_t *nvl_results = meoi_to_nvlist(results);

	nvlist_t *payload = fnvlist_alloc();
	fnvlist_add_byte_array(payload, "pkt_bytes", tp->tp_bytes, tp->tp_sz);
	if (num_splits != 0 && splits != NULL) {
		fnvlist_add_uint32_array(payload, "splits", splits,
		    num_splits);
	}
	fnvlist_add_nvlist(payload, "results", nvl_results);
	fnvlist_add_nvlist(payload, "partial", nvl_partial);
	fnvlist_add_uint32(payload, "offset", offset);

	nvlist_free(nvl_partial);
	nvlist_free(nvl_results);

	return (payload);
}

static nvlist_t *
build_ether_payload(test_pkt_t *tp, uint8_t *dstaddr, uint32_t tci,
    uint32_t *splits, uint_t num_splits)
{
	nvlist_t *payload = fnvlist_alloc();
	fnvlist_add_byte_array(payload, "pkt_bytes", tp->tp_bytes, tp->tp_sz);
	if (num_splits != 0 && splits != NULL) {
		fnvlist_add_uint32_array(payload, "splits", splits,
		    num_splits);
	}
	fnvlist_add_byte_array(payload, "dstaddr", dstaddr, ETHERADDRL);
	fnvlist_add_uint32(payload, "tci", tci);

	return (payload);
}

struct test_tuple {
	const char *tt_module;
	const char *tt_suite;
	const char *tt_test;
};
const struct test_tuple tuple_meoi = {
	.tt_module = "mac",
	.tt_suite = "parsing",
	.tt_test = "mac_ether_offload_info_test"
};
const struct test_tuple tuple_partial_meoi = {
	.tt_module = "mac",
	.tt_suite = "parsing",
	.tt_test = "mac_partial_offload_info_test"
};
const struct test_tuple tuple_l2info = {
	.tt_module = "mac",
	.tt_suite = "parsing",
	.tt_test = "mac_ether_l2_info_test"
};

static bool
run_test(nvlist_t *payload, const struct test_tuple *tuple)
{
	size_t payload_sz;
	char *payload_packed = fnvlist_pack(payload, &payload_sz);
	VERIFY(payload_packed != NULL);
	nvlist_free(payload);

	ktest_run_req_t req = {
		.krq_module = tuple->tt_module,
		.krq_suite = tuple->tt_suite,
		.krq_test = tuple->tt_test,
		.krq_input = (uchar_t *)payload_packed,
		.krq_input_len = payload_sz,
	};
	ktest_run_result_t result = { 0 };

	if (!ktest_run(kthdl, &req, &result)) {
		err(EXIT_FAILURE, "error while attempting ktest_run()");
	}

	const char *cname = ktest_code_name(result.krr_code);
	if (result.krr_code == KTEST_CODE_PASS) {
		(void) printf("%s: %s\n", tuple->tt_test, cname);
		free(result.krr_msg);
		return (true);
	} else {
		(void) printf("%s: %s @ line %u\n",
		    tuple->tt_test, cname, result.krr_line);
		(void) printf("\tmsg: %s\n", result.krr_msg);
		free(result.krr_msg);
		return (false);
	}
}

static uint32_t *
split_gen_single(uint_t num_bytes)
{
	uint32_t *splits = calloc(num_bytes, sizeof (uint32_t));
	VERIFY(splits != NULL);
	for (uint_t i = 0; i < num_bytes; i++) {
		splits[i] = 1;
	}
	return (splits);
}
static uint32_t *
split_gen_random(uint_t num_bytes, uint_t *num_splits)
{
	/*
	 * Generate split points between 0-10 bytes in size.  Assuming an
	 * average size of 5 when allocating a fixed buffer, with any remaining
	 * bytes going into one large trailing mblk.
	 */
	*num_splits = num_bytes / 5;

	uint32_t *splits = calloc(*num_splits, sizeof (uint32_t));
	VERIFY(splits != NULL);
	for (uint_t i = 0; i < *num_splits; i++) {
		/*
		 * This uses random() rather than something like
		 * arc4random_uniform() so we can have deterministic splits for
		 * the test case.  This is achieved with a prior srand() call
		 * with a fixed seed.
		 */
		splits[i] = random() % 11;
	}

	return (splits);
}
static void
split_print(const uint32_t *splits, uint_t num_splits)
{
	if (num_splits == 0) {
		(void) printf("\tsplits: []\n");
	} else {
		(void) printf("\tsplits: [");
		for (uint_t i = 0; i < num_splits; i++) {
			(void) printf("%s%u", i == 0 ? "" : ", ", splits[i]);
		}
		(void) printf("]\n");
	}
}

static void
pkt_print(const test_pkt_t *tp)
{
	if (!print_raw_pkts) {
		return;
	}

	for (uint_t i = 0; i < tp->tp_sz; i++) {
		const bool begin_line = (i % 16) == 0;
		const bool end_line = (i % 16) == 15 || i == (tp->tp_sz - 1);
		if (begin_line) {
			(void) printf("%04x\t", i);
		}
		(void) printf("%s%02x%s", begin_line ? "" : " ",
		    tp->tp_bytes[i], end_line ? "\n" : "");
	}
	(void) fflush(stdout);
}

/*
 * Run variations of mac_ether_offload_info() test against packet/meoi pair.
 * Returns true if any variation failed.
 */
static bool
run_meoi_variants(const char *prefix, test_pkt_t *tp,
    const mac_ether_offload_info_t *meoi)
{
	nvlist_t *payload;
	bool any_failed = false;
	uint32_t *splits = NULL;
	uint_t num_splits;

	pkt_print(tp);

	(void) printf("%s - simple - ", prefix);
	payload = build_meoi_payload(tp, meoi, NULL, 0);
	any_failed |= !run_test(payload, &tuple_meoi);

	(void) printf("%s - split-single-bytes - ", prefix);
	splits = split_gen_single(tp->tp_sz);
	payload = build_meoi_payload(tp, meoi, splits, tp->tp_sz);
	any_failed |= !run_test(payload, &tuple_meoi);
	free(splits);

	(void) printf("%s - split-random - ", prefix);
	splits = split_gen_random(tp->tp_sz, &num_splits);
	payload = build_meoi_payload(tp, meoi, splits, num_splits);
	any_failed |= !run_test(payload, &tuple_meoi);
	split_print(splits, num_splits);
	free(splits);

	return (any_failed);
}

/*
 * Run variations of mac_partial_offload_info() test against packet/meoi pair.
 * Returns true if any variation failed.
 */
static bool
run_partial_variants(const char *prefix, test_pkt_t *tp,
    const mac_ether_offload_info_t *meoi)
{
	nvlist_t *payload;
	bool any_failed = false;
	uint32_t *splits = NULL;
	uint_t num_splits;

	/* skip over the l2 header but ask for the rest to be filled */
	uint32_t offset = meoi->meoi_l2hlen;
	mac_ether_offload_info_t partial = {
		.meoi_flags = MEOI_L2INFO_SET,
		.meoi_l3proto = meoi->meoi_l3proto,
	};
	/* And the result should reflect that ignored l2 header */
	mac_ether_offload_info_t result;
	bcopy(meoi, &result, sizeof (result));
	result.meoi_l2hlen = 0;

	pkt_print(tp);

	(void) printf("%s - simple - ", prefix);
	payload = build_partial_payload(tp, offset, &partial, &result, NULL, 0);
	any_failed |= !run_test(payload, &tuple_partial_meoi);

	(void) printf("%s - split-single-bytes - ", prefix);
	splits = split_gen_single(tp->tp_sz);
	payload = build_partial_payload(tp, offset, &partial, &result, splits,
	    tp->tp_sz);
	any_failed |= !run_test(payload, &tuple_partial_meoi);
	free(splits);

	(void) printf("%s - split-random - ", prefix);
	splits = split_gen_random(tp->tp_sz, &num_splits);
	payload = build_partial_payload(tp, offset, &partial, &result, splits,
	    num_splits);
	any_failed |= !run_test(payload, &tuple_partial_meoi);
	split_print(splits, num_splits);
	free(splits);

	return (any_failed);
}

/*
 * Run variations of mac_ether_l2_info() test against packet/data pairing.
 * Returns true if any variation failed.
 */
static bool
run_ether_variants(const char *prefix, test_pkt_t *tp, uint8_t *dstaddr,
    uint32_t tci)
{
	nvlist_t *payload;
	bool any_failed = false;
	uint32_t *splits = NULL;

	pkt_print(tp);

	(void) printf("%s - simple - ", prefix);
	payload = build_ether_payload(tp, dstaddr, tci, NULL, 0);
	any_failed |= !run_test(payload, &tuple_l2info);

	(void) printf("%s - split-single-bytes - ", prefix);
	splits = split_gen_single(tp->tp_sz);
	payload = build_ether_payload(tp, dstaddr, tci, splits, tp->tp_sz);
	any_failed |= !run_test(payload, &tuple_l2info);
	free(splits);

	/* intentionally split dstaddr, tpid, tci, and ethertype */
	uint32_t intentional_splits[] = { 4, 9, 2, 2 };
	(void) printf("%s - split-intentional - ", prefix);
	payload = build_ether_payload(tp, dstaddr, tci, intentional_splits,
	    ARRAY_SIZE(intentional_splits));
	any_failed |= !run_test(payload, &tuple_l2info);
	split_print(intentional_splits, ARRAY_SIZE(intentional_splits));

	return (any_failed);
}

int
main(int argc, char *argv[])
{
	if (!ktest_mod_load("mac")) {
		err(EXIT_FAILURE, "could not load mac ktest module");
	}
	if ((kthdl = ktest_init()) == NULL) {
		err(EXIT_FAILURE, "could not initialize libktest");
	}

	if (getenv("PRINT_RAW") != NULL) {
		print_raw_pkts = true;
	} else {
		(void) printf("Set PRINT_RAW env var for raw pkt output\n");
	}

	bool any_failed = false;

	/* Use fixed seed for deterministic "random" output */
	srandom(0x1badbeef);

	mac_ether_offload_info_t meoi_tcp4 = { 0 };
	test_pkt_t *tp_tcp4 = build_tcp4(&meoi_tcp4);

	mac_ether_offload_info_t meoi_tcp6 = { 0 };
	test_pkt_t *tp_tcp6 = build_tcp6(&meoi_tcp6);

	any_failed |=
	    run_meoi_variants("basic tcp4", tp_tcp4, &meoi_tcp4);
	any_failed |=
	    run_meoi_variants("basic tcp6", tp_tcp6, &meoi_tcp6);
	any_failed |= run_partial_variants("basic tcp4", tp_tcp4, &meoi_tcp4);
	any_failed |= run_partial_variants("basic tcp6", tp_tcp6, &meoi_tcp6);

	/*
	 * Truncate the tcp header to induce a parse failure, but expect that
	 * the packet info is still populated
	 */
	tp_tcp4->tp_sz -= 4;
	tp_tcp6->tp_sz -= 4;
	meoi_tcp4.meoi_flags &= ~MEOI_L4INFO_SET;
	meoi_tcp6.meoi_flags &= ~MEOI_L4INFO_SET;

	any_failed |=
	    run_meoi_variants("truncated tcp4", tp_tcp4, &meoi_tcp4);
	any_failed |=
	    run_meoi_variants("truncated tcp6", tp_tcp6, &meoi_tcp6);

	mac_ether_offload_info_t meoi_frag_v4 = { 0 };
	mac_ether_offload_info_t meoi_frag_v6 = { 0 };
	test_pkt_t *tp_frag_v4 = build_frag_v4(&meoi_frag_v4);
	test_pkt_t *tp_frag_v6 = build_frag_v6(&meoi_frag_v6);

	any_failed |= run_meoi_variants("fragment ipv4", tp_frag_v4,
	    &meoi_frag_v4);
	any_failed |= run_meoi_variants("fragment ipv6", tp_frag_v6,
	    &meoi_frag_v6);

	mac_ether_offload_info_t meoi_frag_off_v4 = { 0 };
	mac_ether_offload_info_t meoi_frag_off_v6 = { 0 };
	test_pkt_t *tp_frag_off_v4 = build_frag_off_v4(&meoi_frag_off_v4);
	test_pkt_t *tp_frag_off_v6 = build_frag_off_v6(&meoi_frag_off_v6);

	any_failed |= run_meoi_variants("fragment offset ipv4", tp_frag_off_v4,
	    &meoi_frag_off_v4);
	any_failed |= run_meoi_variants("fragment offset ipv6", tp_frag_off_v6,
	    &meoi_frag_off_v6);


	test_pkt_t *tp_ether_plain = tp_alloc();
	struct ether_header hdr_l2_plain = {
		.ether_dhost = { 0x86, 0x1d, 0xe0, 0x11, 0x22, 0x33},
		.ether_type = htons(ETHERTYPE_IP),
	};
	tp_append(tp_ether_plain, &hdr_l2_plain, sizeof (hdr_l2_plain));

	test_pkt_t *tp_ether_vlan = tp_alloc();
	const uint16_t arb_vlan = 201;
	struct ether_vlan_header hdr_l2_vlan = {
		.ether_dhost = { 0x86, 0x1d, 0xe0, 0x11, 0x22, 0x33},
		.ether_tpid = htons(ETHERTYPE_VLAN),
		.ether_tci = htons(arb_vlan),
		.ether_type = htons(ETHERTYPE_IP),
	};
	tp_append(tp_ether_vlan, &hdr_l2_vlan, sizeof (hdr_l2_vlan));

	any_failed |= run_ether_variants("ether plain", tp_ether_plain,
	    hdr_l2_plain.ether_dhost.ether_addr_octet, UINT32_MAX);
	any_failed |= run_ether_variants("ether vlan", tp_ether_vlan,
	    hdr_l2_vlan.ether_dhost.ether_addr_octet, arb_vlan);

	tp_free(tp_tcp4);
	tp_free(tp_tcp6);
	tp_free(tp_frag_v4);
	tp_free(tp_frag_v6);
	tp_free(tp_frag_off_v4);
	tp_free(tp_frag_off_v6);
	tp_free(tp_ether_plain);
	tp_free(tp_ether_vlan);

	ktest_fini(kthdl);
	return (any_failed ? EXIT_FAILURE : EXIT_SUCCESS);
}
