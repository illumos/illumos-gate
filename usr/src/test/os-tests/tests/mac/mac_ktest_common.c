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
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/ethernet.h>

#include <libnvpair.h>

#include "mac_ktest_common.h"

static const char snoop_magic[8] = "snoop\0\0\0";
static const uint_t snoop_acceptable_vers = 2;

pkt_cap_iter_t *
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

void
pkt_cap_close(pkt_cap_iter_t *iter)
{
	(void) munmap((void *)iter->pci_base, iter->pci_map_sz);
	(void) close(iter->pci_fd);
	free(iter);
}

void
pkt_cap_reset(pkt_cap_iter_t *iter)
{
	iter->pci_offset = sizeof (snoop_file_hdr_t);
}

bool
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

char *
serialize_pkt_chain(pkt_cap_iter_t *iter, uint_t *sizep)
{
	/*
	 * First, figure out how many bytes are needed. We're serializing
	 * down to `uint32_t` (len) + <bytes> for each packet.
	 */
	const void *pkt_buf = NULL;
	*sizep = 0;
	uint_t pkt_sz;
	while (pkt_cap_next(iter, &pkt_buf, &pkt_sz)) {
		*sizep += sizeof (uint32_t) + pkt_sz;
	}

	/*
	 * Rewalk, and copy all the bytes out.
	 */
	char *out = malloc(*sizep);
	pkt_cap_reset(iter);

	if (out == NULL)
		return (out);
	char *cur = out;
	while (pkt_cap_next(iter, &pkt_buf, &pkt_sz)) {
		uint32_t ps = pkt_sz;
		bcopy(&ps, cur, sizeof (ps));
		cur += sizeof (ps);
		bcopy(pkt_buf, cur, pkt_sz);
		cur += pkt_sz;
	}

	return (out);
}

char *
build_payload(const void *pkt_buf, uint_t pkt_sz,
    const void *out_pkt_buf, uint_t out_pkt_sz,
    const struct payload_opts *popts, size_t *payload_sz)
{
	nvlist_t *payload = fnvlist_alloc();
	fnvlist_add_byte_array(payload, "pkt_bytes",
	    (uchar_t *)pkt_buf, pkt_sz);
	if (out_pkt_buf != NULL) {
		fnvlist_add_byte_array(payload, "out_pkt_bytes",
		    (uchar_t *)out_pkt_buf, out_pkt_sz);
	}
	if (popts->po_mss) {
		fnvlist_add_uint32(payload, "mss", popts->po_mss);
	}
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
