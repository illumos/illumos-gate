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
 * Copyright 2015 Nexenta Systems, Inc.  All rights reserved.
 */

/*
 * Support functions for dumping SMB request and response data from a
 * crash dump as a pcap file.  This allows using tools like wireshark
 * to examine the request we were working on when we crashed.
 *
 * This feature is only available in mdb (not in kmdb).
 */

#ifdef _KMDB
#error "Makefile should have excluded this file."
#endif

#include <mdb/mdb_modapi.h>
#include <mdb/mdb_ks.h>
#include <sys/thread.h>
#include <sys/taskq.h>
#include <smbsrv/smb_vops.h>
#include <smbsrv/smb.h>
#include <smbsrv/smb_ktypes.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <inet/tcp.h>

#include <fcntl.h>
#include <unistd.h>

#include "smbsrv_pcap.h"

/* Not sure why this isn't declared... */
extern int fstat(int, struct stat *);

/*
 * In the capture file, packets are truncated at 64k.
 * The SMB len is shorter so that after we add the
 * (faked up) headers we're still below PCAP_SNAPLEN.
 */
#define	PCAP_SNAPLEN	(1<<16)
#define	MAX_SMB_LEN	(PCAP_SNAPLEN - 0x40)

/*
 * pcap file format stuff, mostly from:
 * wiki.wireshark.org/Development/LibpcapFileFormat
 */

#define	PCAP_MAGIC	0xa1b2c3d4
#define	PCAP_VMAJOR	2
#define	PCAP_VMINOR	4
#define	PCAP_DLT_RAW	0xc

struct pcap_file_hdr {
	uint32_t magic_number;
	uint16_t version_major;
	uint16_t version_minor;
	uint32_t thiszone;	/* TZ correction */
	uint32_t sigflags;	/* accuracy of timestamps */
	uint32_t snaplen;	/* max legnth of captured packets */
	uint32_t network;	/* data link type */
};

struct pcap_frame_hdr {
	uint32_t ts_sec;	/* timestamp seconds */
	uint32_t ts_usec;	/* timestamp microseconds */
	uint32_t incl_len;	/* number of octets of packet saved in file */
	uint32_t orig_len;	/* actual length of packet */
};

struct my_ip6_hdr {
	uint8_t  ip6_vers;	/* 6 */
	uint8_t  ip6_class;
	uint16_t ip6_xflow;
	uint16_t ip6_paylen;
	uint8_t  ip6_nexthdr;
	uint8_t  ip6_hoplim;
	in6_addr_t ip6_src;
	in6_addr_t ip6_dst;
};

static int pcap_fd = -1;

/* For faking TCP sequence numbers. */
static uint32_t call_seqno;
static uint32_t reply_seqno;

static int pcap_file_header(char *, int);
static int smb_req_pcap_m(uintptr_t, const void *, void *);

void
smbsrv_pcap_close(void)
{
	if (pcap_fd != -1) {
		close(pcap_fd);
		pcap_fd = -1;
	}
}

int
smbsrv_pcap_open(char *outfile)
{
	int fd;

	fd = open(outfile, O_RDWR | O_CREAT | O_NOFOLLOW, 0644);
	if (fd < 0) {
		mdb_warn("Can't open pcap output file: %s\n", outfile);
		return (DCMD_ERR);
	}
	if (pcap_file_header(outfile, fd) < 0) {
		close(fd);
		return (DCMD_ERR);
	}
	pcap_fd = fd;
	call_seqno = 1;
	reply_seqno = 1;

	return (DCMD_OK);
}

/*
 * Check or create a pcap file header
 */
static int
pcap_file_header(char *outfile, int fd)
{
	struct stat st;
	struct pcap_file_hdr hdr;
	int n;

	if (fstat(fd, &st) < 0) {
		mdb_warn("Can't stat pcap output file: %s\n", outfile);
		return (-1);
	}
	if (st.st_size < sizeof (hdr))
		goto create;

	n = read(fd, &hdr, sizeof (hdr));
	if (n != sizeof (hdr))
		goto create;

	/*
	 * This only supports appending to files we created,
	 * so the file headers should all be native endian
	 * and have the values we write when creating.
	 */
	if (hdr.magic_number != PCAP_MAGIC ||
	    hdr.version_major != PCAP_VMAJOR ||
	    hdr.version_minor != PCAP_VMINOR ||
	    hdr.snaplen != PCAP_SNAPLEN ||
	    hdr.network != PCAP_DLT_RAW) {
		mdb_warn("Existing file not pcap: %s\n", outfile);
		return (-1);
	}

	/* We will append to this file. */
	(void) lseek(fd, st.st_size, SEEK_SET);
	return (0);

create:
	hdr.magic_number = PCAP_MAGIC;
	hdr.version_major = PCAP_VMAJOR;
	hdr.version_minor = PCAP_VMINOR;
	hdr.thiszone = 0;
	hdr.sigflags = 0;
	hdr.snaplen = PCAP_SNAPLEN;
	hdr.network = PCAP_DLT_RAW;

	(void) lseek(fd, (off_t)0, SEEK_SET);
	n = write(fd, &hdr, sizeof (hdr));
	if (n != sizeof (hdr)) {
		mdb_warn("Can't write output file: %s\n", outfile);
		return (-1);
	}
	(void) ftruncate(fd, (off_t)sizeof (hdr));
	return (0);
}

struct req_dump_state {
	int32_t rem_len;
	int tbuf_size;
	char *tbuf;
};

/*
 * Simlar to smb_req_dump, but write a pcap frame.
 * The headers are faked up, intended only to be
 * good enough so wireshark will display this.
 * These NEVER go over any network.
 */
int
smbsrv_pcap_dump(struct mbuf_chain *mbc, int32_t smb_len,
    smb_inaddr_t *src_ip, uint16_t src_port,
    smb_inaddr_t *dst_ip, uint16_t dst_port,
    hrtime_t rqtime, boolean_t is_reply)
{
	struct req_dump_state dump_state;
	struct pcap_frame_hdr phdr;
	struct my_ip6_hdr ip6_hdr;
	struct ipha_s ip_hdr;
	tcpha_t tcp_hdr;
	uint32_t nb_hdr;
	uint32_t *seqno;
	uint32_t *ackno;
	void *ip_hdr_p;
	int ip_hdr_len;
	int len_w_hdrs;
	int truncated;
	int n, rc;
	off_t pkt_off;

	if (smb_len < sizeof (nb_hdr))
		return (DCMD_OK);
	if (mbc->chain == NULL)
		return (DCMD_ERR);

	/*
	 * This code is not making fragments (for now), so just
	 * limit SMB frames to 64k - header(s) size.
	 */
	if (smb_len > MAX_SMB_LEN) {
		truncated = smb_len - MAX_SMB_LEN;
		smb_len = MAX_SMB_LEN;
	} else {
		truncated = 0;
	}

	switch (src_ip->a_family) {
	case AF_INET:
		ip_hdr_len = sizeof (ip_hdr);
		break;
	case AF_INET6:
		ip_hdr_len = sizeof (ip6_hdr);
		break;
	default:
		mdb_warn("unknown network addr family\n");
		return (DCMD_ERR);
	}

	/* Which is seq/ack? */
	if (is_reply) {
		/* it's a reply */
		seqno = &reply_seqno;
		ackno = &call_seqno;
	} else {
		/* it's a call */
		seqno = &call_seqno;
		ackno = &reply_seqno;
	}

	/*
	 * Build & dump the (faked up) frame headers:
	 *	pcap packet header
	 *	IP header (v4 or v6)
	 *	TCP header
	 *	NetBIOS header
	 *
	 * Build back to front, computing lengths,
	 * then write them all out.
	 */

	/* NetBIOS (just a 32-bit payload len) */
	nb_hdr = htonl(smb_len);
	len_w_hdrs = smb_len + sizeof (nb_hdr);

	/* TCP (w/ faked seq. numbers) */
	tcp_hdr.tha_lport = htons(src_port);
	tcp_hdr.tha_fport = htons(dst_port);
	tcp_hdr.tha_seq = htonl(*seqno);
	tcp_hdr.tha_ack = htonl(*ackno);
	tcp_hdr.tha_offset_and_reserved = 0x50;
	tcp_hdr.tha_flags = 0x10; /* ACK */
	tcp_hdr.tha_win = htons(0xFF00);
	tcp_hdr.tha_sum = 0;
	tcp_hdr.tha_urp = 0;
	(*seqno) += len_w_hdrs;
	len_w_hdrs += sizeof (tcp_hdr);

	/* IP header */
	switch (src_ip->a_family) {
	case AF_INET:
		ip_hdr_p = &ip_hdr;
		ip_hdr_len = sizeof (ip_hdr);
		/* IPv4 len includes the IP4 header */
		len_w_hdrs += ip_hdr_len;
		ip_hdr.ipha_version_and_hdr_length = 0x45;
		ip_hdr.ipha_type_of_service = 0;
		if (len_w_hdrs > 0xFFFF)
			ip_hdr.ipha_length = 0xFFFF;
		else
			ip_hdr.ipha_length = htons(len_w_hdrs);
		ip_hdr.ipha_ident = 0;
		ip_hdr.ipha_fragment_offset_and_flags = 0;
		ip_hdr.ipha_ttl = 60;
		ip_hdr.ipha_protocol = 6; /* TCP */
		ip_hdr.ipha_hdr_checksum = 0;
		ip_hdr.ipha_src = src_ip->a_ipv4;
		ip_hdr.ipha_dst = dst_ip->a_ipv4;
		break;

	case AF_INET6:
		ip_hdr_p = &ip_hdr;
		ip_hdr_len = sizeof (ip6_hdr);
		ip6_hdr.ip6_vers = 6;
		ip6_hdr.ip6_class = 0;
		ip6_hdr.ip6_xflow = 0;
		if (len_w_hdrs > 0xFFFF)
			ip6_hdr.ip6_paylen = 0xFFFF;
		else
			ip6_hdr.ip6_paylen = htons(len_w_hdrs);
		ip6_hdr.ip6_nexthdr = 6; /* TCP */
		ip6_hdr.ip6_hoplim = 64;
		bcopy(&src_ip->a_ipv6, &ip6_hdr.ip6_src,
		    sizeof (ip6_hdr.ip6_src));
		bcopy(&dst_ip->a_ipv6, &ip6_hdr.ip6_dst,
		    sizeof (ip6_hdr.ip6_dst));
		len_w_hdrs += ip_hdr_len;
		break;
	default:
		ip_hdr_p = NULL;
		ip_hdr_len = 0;
		break;
	}

	/* pcap header */
	phdr.ts_sec = rqtime / NANOSEC;
	phdr.ts_usec = (rqtime / 1000) % MICROSEC;
	phdr.incl_len = len_w_hdrs; /* not incl. pcap header */
	phdr.orig_len = len_w_hdrs + truncated;
	len_w_hdrs += sizeof (phdr);

	/*
	 * Write out all the headers:
	 * pcap, IP, TCP, NetBIOS
	 *
	 * To avoid any possibility of scrambling the
	 * pcap file, save the offset here and seek to
	 * where we should be when done writing.
	 */
	pkt_off = lseek(pcap_fd, (off_t)0, SEEK_CUR);
	n = write(pcap_fd, &phdr, sizeof (phdr));
	if (n != sizeof (phdr)) {
		mdb_warn("failed to write pcap hdr\n");
		goto errout;
	}
	n = write(pcap_fd, ip_hdr_p, ip_hdr_len);
	if (n != ip_hdr_len) {
		mdb_warn("failed to write IP hdr\n");
		goto errout;
	}
	n = write(pcap_fd, &tcp_hdr, sizeof (tcp_hdr));
	if (n != sizeof (tcp_hdr)) {
		mdb_warn("failed to write TCP hdr\n");
		goto errout;
	}
	n = write(pcap_fd, &nb_hdr, sizeof (nb_hdr));
	if (n != sizeof (nb_hdr)) {
		mdb_warn("failed to write NBT hdr\n");
		goto errout;
	}

	/*
	 * Finally, walk the mbuf chain writing SMB data
	 * to the pcap file, for exactly smb_len bytes.
	 */
	dump_state.rem_len = smb_len;
	dump_state.tbuf_size = MCLBYTES;
	dump_state.tbuf = mdb_alloc(dump_state.tbuf_size, UM_SLEEP);
	rc = mdb_pwalk("smb_mbuf_walker", smb_req_pcap_m,
	    &dump_state, (uintptr_t)mbc->chain);
	mdb_free(dump_state.tbuf, dump_state.tbuf_size);
	if (rc < 0) {
		mdb_warn("cannot walk smb_req mbuf_chain");
		goto errout;
	}

	pkt_off += len_w_hdrs;
	(void) lseek(pcap_fd, pkt_off, SEEK_SET);
	return (DCMD_OK);

errout:
	(void) lseek(pcap_fd, pkt_off, SEEK_SET);
	(void) ftruncate(pcap_fd, pkt_off);
	return (DCMD_ERR);
}

/*
 * Call-back function, called for each mbuf_t in a chain.
 * Copy data from this mbuf to the pcap file.
 */
static int
smb_req_pcap_m(uintptr_t mbuf_addr, const void *data, void *arg)
{
	struct req_dump_state *st = arg;
	const struct mbuf *m = data;
	uintptr_t addr;
	int cnt, mlen, n, x;

	addr = (uintptr_t)m->m_data;
	mlen = m->m_len;
	if (mlen > st->rem_len)
		mlen = st->rem_len;
	if (mlen <= 0)
		return (WALK_DONE);

	cnt = mlen;
	while (cnt > 0) {
		x = MIN(cnt, st->tbuf_size);
		n = mdb_vread(st->tbuf, x, addr);
		if (n != x) {
			mdb_warn("failed copying mbuf %p\n", mbuf_addr);
			return (WALK_ERR);
		}
		n = write(pcap_fd, st->tbuf, x);
		if (n != x) {
			mdb_warn("failed writing pcap data\n");
			return (WALK_ERR);
		}
		addr += x;
		cnt -= x;
	}

	st->rem_len -= mlen;
	return (WALK_NEXT);
}
