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

#ifndef _MAC_KTEST_COMMON_H
#define	_MAC_KTEST_COMMON_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/stdbool.h>
#include <sys/types.h>
#include <sys/types32.h>

typedef struct snoop_pkt_hdr {
	uint32_t		sph_origlen;
	uint32_t		sph_msglen;
	uint32_t		sph_totlen;
	uint32_t		sph_drops;
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

typedef struct pkt_cap_iter {
	int		pci_fd;
	const char	*pci_base;
	size_t		pci_map_sz;
	size_t		pci_sz;
	size_t		pci_offset;
} pkt_cap_iter_t;

extern pkt_cap_iter_t *pkt_cap_open(int);
extern void pkt_cap_close(pkt_cap_iter_t *);
extern void pkt_cap_reset(pkt_cap_iter_t *);
extern bool pkt_cap_next(pkt_cap_iter_t *, const void **, uint_t *);

struct payload_opts {
	uint_t		po_padding;
	boolean_t	po_cksum_partial;
	boolean_t	po_cksum_full;
	boolean_t	po_cksum_ipv4;
	boolean_t	po_split_ether;
	uint_t		po_split_manual;
	uint_t		po_mss;
};

extern char *build_payload(const void *, uint_t, const void *, uint_t,
    const struct payload_opts *, size_t *);
extern char *serialize_pkt_chain(pkt_cap_iter_t *iter, uint_t *sizep);

#ifdef	__cplusplus
}
#endif

#endif /* _MAC_KTEST_COMMON_H */
