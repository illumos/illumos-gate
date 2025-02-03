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
 * Executor for mac_sw_cksum() ktests.
 *
 * This program builds up the packed nvlist payloads expected by the ktest for
 * mac_sw_cksum().  The caller provides a snoop(1) with one or more packets
 * bearing valid checksums.  Along with the checksum types selected (via option
 * flags), it is passed into the ktest, where it is stripped of its checksums
 * and then run through mac_sw_cksum().  The resulting mblk is compared
 * byte-for-byte with the original input to determine if the emulation generated
 * the correct checksums.
 */

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <err.h>
#include <errno.h>
#include <strings.h>
#include <netinet/in.h>
#include <sys/mman.h>
#include <sys/dlpi.h>
#include <sys/types.h>
#include <sys/types32.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/ethernet.h>

#include <libnvpair.h>
#include <libktest.h>

typedef struct snoop_pkt_hdr {
	uint_t			sph_origlen;
	uint_t			sph_msglen;
	uint_t			sph_totlen;
	uint_t			sph_drops;
#if defined(_LP64)
	struct timeval32	sph_timestamp;
#else
#error	"ktest is expected to be 64-bit for now"
#endif
} snoop_pkt_hdr_t;

typedef struct snoop_file_hdr {
	char		sfh_magic[8];
	uint32_t	sfh_vers;
	uint32_t	sfh_mac_type;
} snoop_file_hdr_t;

static const char snoop_magic[8] = "snoop\0\0\0";
static const uint_t snoop_acceptable_vers = 2;

typedef struct pkt_cap_iter {
	int		pci_fd;
	const char	*pci_base;
	size_t		pci_map_sz;
	size_t		pci_sz;
	size_t		pci_offset;
} pkt_cap_iter_t;

static pkt_cap_iter_t *
pkt_cap_open(int fd)
{
	struct stat info;
	if (fstat(fd, &info) != 0) {
		return (NULL);
	}
	if (info.st_size < sizeof (snoop_file_hdr_t)) {
		errno = EINVAL;
		return (NULL);
	}

	const size_t page_sz = (size_t)sysconf(_SC_PAGESIZE);
	const size_t map_sz = P2ROUNDUP(info.st_size, page_sz);
	void *map = mmap(NULL, map_sz, PROT_READ, MAP_PRIVATE, fd, 0);
	if (map == NULL) {
		return (NULL);
	}

	const snoop_file_hdr_t *hdr = (const snoop_file_hdr_t *)map;
	if (bcmp(&hdr->sfh_magic, snoop_magic, sizeof (hdr->sfh_magic)) != 0 ||
	    ntohl(hdr->sfh_vers) != snoop_acceptable_vers ||
	    ntohl(hdr->sfh_mac_type) != DL_ETHER) {
		(void) munmap(map, map_sz);
		errno = EINVAL;
		return (NULL);
	}

	struct pkt_cap_iter *iter = malloc(sizeof (struct pkt_cap_iter));
	if (iter == NULL) {
		(void) munmap(map, map_sz);
		errno = ENOMEM;
		return (NULL);
	}

	iter->pci_fd = fd;
	iter->pci_base = (const char *)map;
	iter->pci_map_sz = map_sz;
	iter->pci_sz = info.st_size;
	iter->pci_offset = sizeof (*hdr);

	return (iter);
}

static void
pkt_cap_close(pkt_cap_iter_t *iter)
{
	(void) munmap((void *)iter->pci_base, iter->pci_map_sz);
	(void) close(iter->pci_fd);
	free(iter);
}

static bool
pkt_cap_next(pkt_cap_iter_t *iter, const void **pkt_buf, uint_t *sizep)
{
	size_t remain = iter->pci_sz - iter->pci_offset;

	if (remain < sizeof (snoop_pkt_hdr_t)) {
		return (false);
	}

	const snoop_pkt_hdr_t *hdr =
	    (const snoop_pkt_hdr_t *)&iter->pci_base[iter->pci_offset];

	const uint_t msg_sz = ntohl(hdr->sph_msglen);
	const uint_t total_sz = ntohl(hdr->sph_totlen);
	if (remain < total_sz || remain < msg_sz) {
		return (false);
	}

	*pkt_buf = (const void *)&hdr[1];
	*sizep = msg_sz;
	iter->pci_offset += total_sz;
	return (true);
}

static ktest_hdl_t *kthdl = NULL;
const char *mac_cksum_cmd = "";

struct payload_opts {
	uint_t		po_padding;
	boolean_t	po_cksum_partial;
	boolean_t	po_cksum_full;
	boolean_t	po_cksum_ipv4;
	boolean_t	po_split_ether;
	uint_t		po_split_manual;
};

static char *
build_payload(const void *pkt_buf, uint_t pkt_sz,
    const struct payload_opts *popts, size_t *payload_sz)
{
	nvlist_t *payload = fnvlist_alloc();
	fnvlist_add_byte_array(payload, "pkt_bytes",
	    (uchar_t *)pkt_buf, pkt_sz);
	if (popts->po_padding) {
		fnvlist_add_uint32(payload, "padding", popts->po_padding);
	}
	if (popts->po_cksum_partial) {
		fnvlist_add_boolean(payload, "cksum_partial");
	}
	if (popts->po_cksum_full) {
		fnvlist_add_boolean(payload, "cksum_full");
	}
	if (popts->po_cksum_ipv4) {
		fnvlist_add_boolean(payload, "cksum_ipv4");
	}

	uint_t nsplit = 0;
	uint32_t splits[2];
	if (popts->po_split_ether) {
		splits[nsplit++] = sizeof (struct ether_header);
	}
	if (popts->po_split_manual != 0) {
		splits[nsplit++] = popts->po_split_manual;
	}
	if (nsplit > 0) {
		fnvlist_add_uint32_array(payload, "cksum_splits", splits,
		    nsplit);
	}

	char *packed = fnvlist_pack(payload, payload_sz);
	nvlist_free(payload);

	return (packed);
}

static void
mac_cksum_usage(void)
{
	(void) fprintf(stderr, "usage: %s [flags] [opts] <cap_file>\n\n"
	    "Flags:\n"
	    "\t-4\temulate HCK_IPV4_HDRCKSUM\n"
	    "\t-f\temulate HCK_FULLCKSUM\t(cannot be used with -p)\n"
	    "\t-p\temulate HCK_PARTIALCKSUM\t(cannot be used with -f)\n"
	    "\t-e\tsplit mblk after Ethernet header\n"
	    "Options:\n"
	    "\t-b <len>\tpad mblk with <len> bytes (must be even)\n"
	    "\t-s <len>\tsplit mblk after len bytes (must be even)\n"
	    "\t\t\tif -e is specified, will be applied after that split\n"
	    "Arguments:\n"
	    "\t<cap_file> is a snoop capture of packets to test.\n"
	    "\tAny TCP or UDP packets (or plain IPv4) are expected to have\n"
	    "\tcorrect checksums.  The emulated results will be compared\n"
	    "\tagainst those sums in the packet (assuming them proper)\n",
	    mac_cksum_cmd);
	exit(EXIT_FAILURE);
}

int
main(int argc, char *argv[])
{
	/* Peel off command name for usage */
	mac_cksum_cmd = argv[0];
	argc--;
	argv++;
	optind = 0;

	struct payload_opts popts = { 0 };
	int c;
	while ((c = getopt(argc, argv, "4fpeb:s:")) != -1) {
		switch (c) {
		case 'p':
			popts.po_cksum_partial = B_TRUE;
			break;
		case 'f':
			popts.po_cksum_full = B_TRUE;
			break;
		case '4':
			popts.po_cksum_ipv4 = B_TRUE;
			break;
		case 'b':
			errno = 0;
			popts.po_padding = strtoul(optarg, NULL, 0);
			if (errno != 0) {
				err(EXIT_FAILURE,
				    "invalid padding value %s", optarg);
			}
			break;
		case 'e':
			popts.po_split_ether = B_TRUE;
			break;
		case 's':
			errno = 0;
			popts.po_split_manual = strtoul(optarg, NULL, 0);
			if (errno != 0) {
				err(EXIT_FAILURE,
				    "invalid split value %s", optarg);
			}
			break;

		case '?':
			warnx("unknown run option: -%c", optopt);
			mac_cksum_usage();
		}
	}
	argc -= optind;
	argv += optind;

	if (argc != 1) {
		mac_cksum_usage();
	}

	int fd = open(argv[0], O_RDONLY, 0);
	if (fd < 0) {
		err(EXIT_FAILURE, "could not open cap file %s", argv[0]);
	}

	pkt_cap_iter_t *iter = pkt_cap_open(fd);
	if (iter == NULL) {
		err(EXIT_FAILURE, "unrecognized cap file %s", argv[0]);
	}

	if (!ktest_mod_load("mac")) {
		err(EXIT_FAILURE, "could not load mac ktest module");
	}
	if ((kthdl = ktest_init()) == NULL) {
		err(EXIT_FAILURE, "could not initialize libktest");
	}

	const void *pkt_buf;
	uint_t pkt_sz;
	uint_t count_pass = 0, count_fail = 0, count_skip = 0, idx = 0;
	while (pkt_cap_next(iter, &pkt_buf, &pkt_sz)) {
		ktest_run_req_t req = {
			.krq_module = "mac",
			.krq_suite = "checksum",
			.krq_test = "mac_sw_cksum_test",
		};
		size_t payload_sz;
		char *payload =
		    build_payload(pkt_buf, pkt_sz, &popts, &payload_sz);
		req.krq_input = (uchar_t *)payload;
		req.krq_input_len = (uint_t)payload_sz;

		ktest_run_result_t result = { 0 };
		if (!ktest_run(kthdl, &req, &result)) {
			err(EXIT_FAILURE, "failure while attempting ktest run");
		}
		free(payload);

		const char *code_name = ktest_code_name(result.krr_code);
		switch (result.krr_code) {
		case KTEST_CODE_PASS:
			count_pass++;
			break;
		case KTEST_CODE_SKIP:
			count_skip++;
			break;
		default:
			count_fail++;
			break;
		}
		(void) printf("%4u\t%s\t(len: %u)\n", idx, code_name, pkt_sz);
		if (result.krr_msg != NULL) {
			if (result.krr_code != KTEST_CODE_PASS) {
				(void) printf("MSG: %s\n", result.krr_msg);
			}
			free(result.krr_msg);
		}
		idx++;
	}
	if (idx == 0) {
		errx(EXIT_FAILURE, "No valid packets found");
	} else if (idx != 1) {
		/* Summarize for > 1 packet */
		(void) printf("SUMMARY: %u PASS, %u SKIP, %u FAIL\n",
		    count_pass, count_skip, count_fail);
	}

	pkt_cap_close(iter);
	ktest_fini(kthdl);

	return (idx == count_pass ? EXIT_SUCCESS : EXIT_FAILURE);
}
