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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright 2012 Milan Jurik. All rights reserved.
 */

#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <setjmp.h>
#include <sys/types.h>
#include <sys/signal.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <sys/pfmod.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/bufmod.h>

#include <unistd.h>
#include <stropts.h>
#include <stdlib.h>
#include <ctype.h>
#include <values.h>
#include <libdlpi.h>

#include "snoop.h"

/*
 * Old header format.
 * Actually two concatenated structs:  nit_bufhdr + nit_head
 */
struct ohdr {
	/* nit_bufhdr */
	int	o_msglen;
	int	o_totlen;
	/* nit_head */
	struct timeval o_time;
	int	o_drops;
	int	o_len;
};

static void scan(char *, int, int, int, int, void (*)(), int, int, int);
void convert_to_network();
void convert_from_network();
static void convert_old(struct ohdr *);
extern sigjmp_buf jmp_env, ojmp_env;
static char *bufp;	/* pointer to read buffer */

static int strioctl(int, int, int, int, void *);

enum { DWA_NONE, DWA_EXISTS, DWA_PLUMBED };

typedef struct dlpi_walk_arg {
	char	dwa_linkname[MAXLINKNAMELEN];
	int	dwa_type;	/* preference type above */
	int	dwa_s4;		/* IPv4 socket */
	int	dwa_s6;		/* IPv6 socket */
} dlpi_walk_arg_t;

static boolean_t
select_datalink(const char *linkname, void *arg)
{
	struct lifreq lifr;
	dlpi_walk_arg_t *dwap = arg;
	int s4 = dwap->dwa_s4;
	int s6 = dwap->dwa_s6;

	(void) strlcpy(dwap->dwa_linkname, linkname, MAXLINKNAMELEN);
	dwap->dwa_type = DWA_EXISTS;

	/*
	 * See if it's plumbed by IP.  We prefer such links because they're
	 * more likely to have interesting traffic.
	 */
	bzero(&lifr, sizeof (lifr));
	(void) strlcpy(lifr.lifr_name, linkname, LIFNAMSIZ);
	if ((s4 != -1 && ioctl(s4, SIOCGLIFFLAGS, &lifr) != -1) ||
	    (s6 != -1 && ioctl(s6, SIOCGLIFFLAGS, &lifr) != -1)) {
		dwap->dwa_type = DWA_PLUMBED;
		return (B_TRUE);
	}
	return (B_FALSE);
}

/*
 * Open `linkname' in raw/passive mode (see dlpi_open(3DLPI)).  If `linkname'
 * is NULL, pick a datalink as per snoop(1M).  Also gather some information
 * about the datalink useful for building the proper packet filters.
 */
boolean_t
open_datalink(dlpi_handle_t *dhp, const char *linkname, const char *zonename)
{
	int retval;
	int flags = DLPI_PASSIVE | DLPI_RAW;
	dlpi_walk_arg_t dwa;
	dlpi_info_t dlinfo;

	if (linkname == NULL) {
		if (zonename != NULL)
			pr_err("a datalink must be specified with a zone name");

		/*
		 * Select a datalink to use by default.  Prefer datalinks that
		 * are plumbed by IP.
		 */
		bzero(&dwa, sizeof (dwa));
		dwa.dwa_s4 = socket(AF_INET, SOCK_DGRAM, 0);
		dwa.dwa_s6 = socket(AF_INET6, SOCK_DGRAM, 0);
		dlpi_walk(select_datalink, &dwa, 0);
		(void) close(dwa.dwa_s4);
		(void) close(dwa.dwa_s6);

		if (dwa.dwa_type == DWA_NONE)
			pr_err("no datalinks found");
		if (dwa.dwa_type == DWA_EXISTS) {
			(void) fprintf(stderr, "snoop: WARNING: "
			    "no datalinks plumbed for IP traffic\n");
		}
		linkname = dwa.dwa_linkname;
	}
	if (Iflg)
		flags |= DLPI_DEVIPNET;
	if (Iflg || strcmp(linkname, "lo0") == 0)
		flags |= DLPI_IPNETINFO;
	if ((retval = dlpi_open_zone(linkname, zonename, dhp,
	    flags)) != DLPI_SUCCESS) {
		pr_err("cannot open \"%s\": %s", linkname,
		    dlpi_strerror(retval));
	}

	if ((retval = dlpi_info(*dhp, &dlinfo, 0)) != DLPI_SUCCESS)
		pr_errdlpi(*dhp, "dlpi_info failed", retval);

	for (interface = &INTERFACES[0]; interface->mac_type != -1; interface++)
		if (interface->mac_type == dlinfo.di_mactype)
			break;

	/* allow limited functionality even if interface isn't known */
	if (interface->mac_type == -1) {
		(void) fprintf(stderr, "snoop: WARNING: Mac Type = %x "
		    "not supported\n", dlinfo.di_mactype);
	}

	return (interface->try_kernel_filter);
}

/*
 * Initialize `dh' for packet capture using the provided arguments.
 */
void
init_datalink(dlpi_handle_t dh, ulong_t snaplen, ulong_t chunksize,
    struct timeval *timeout, struct Pf_ext_packetfilt *fp)
{
	int 	retv;
	int 	netfd;

	retv = dlpi_bind(dh, DLPI_ANY_SAP, NULL);
	if (retv != DLPI_SUCCESS)
		pr_errdlpi(dh, "cannot bind on", retv);

	if (Iflg) {
		(void) fprintf(stderr, "Using device ipnet/%s ",
		    dlpi_linkname(dh));
	} else {
		(void) fprintf(stderr, "Using device %s ", dlpi_linkname(dh));
	}

	/*
	 * If Pflg not set - use physical level
	 * promiscuous mode.  Otherwise - just SAP level.
	 */
	if (!Pflg) {
		(void) fprintf(stderr, "(promiscuous mode)\n");
		retv = dlpi_promiscon(dh, DL_PROMISC_PHYS);
		if (retv != DLPI_SUCCESS) {
			pr_errdlpi(dh, "promiscuous mode(physical) failed",
			    retv);
		}
	} else {
		(void) fprintf(stderr, "(non promiscuous)\n");
		retv = dlpi_promiscon(dh, DL_PROMISC_MULTI);
		if (retv != DLPI_SUCCESS) {
			pr_errdlpi(dh, "promiscuous mode(multicast) failed",
			    retv);
		}
	}

	retv = dlpi_promiscon(dh, DL_PROMISC_SAP);
	if (retv != DLPI_SUCCESS)
		pr_errdlpi(dh, "promiscuous mode(SAP) failed", retv);

	netfd = dlpi_fd(dh);

	if (fp) {
		/*
		 * push and configure the packet filtering module
		 */
		if (ioctl(netfd, I_PUSH, "pfmod") < 0)
			pr_errdlpi(dh, "cannot push \"pfmod\"", DL_SYSERR);

		if (strioctl(netfd, PFIOCSETF, -1, sizeof (*fp),
		    (char *)fp) < 0)
			pr_errdlpi(dh, "PFIOCSETF", DL_SYSERR);
	}

	if (ioctl(netfd, I_PUSH, "bufmod") < 0)
		pr_errdlpi(dh, "cannot push \"bufmod\"", DL_SYSERR);

	if (strioctl(netfd, SBIOCSTIME, -1, sizeof (struct timeval),
	    (char *)timeout) < 0)
		pr_errdlpi(dh, "SBIOCSTIME", DL_SYSERR);

	if (strioctl(netfd, SBIOCSCHUNK, -1, sizeof (uint_t),
	    (char *)&chunksize) < 0)
		pr_errdlpi(dh, "SBIOCGCHUNK", DL_SYSERR);

	if (strioctl(netfd, SBIOCSSNAP, -1, sizeof (uint_t),
	    (char *)&snaplen) < 0)
		pr_errdlpi(dh, "SBIOCSSNAP", DL_SYSERR);

	/*
	 * Flush the read queue, to get rid of anything that
	 * accumulated before the device reached its final configuration.
	 */
	if (ioctl(netfd, I_FLUSH, FLUSHR) < 0)
		pr_errdlpi(dh, "cannot flush \"I_FLUSH\"", DL_SYSERR);
}

/*
 * Read packets from the network.  init_datalink() is called in
 * here to set up the network interface for reading of
 * raw ethernet packets in promiscuous mode into a buffer.
 * Packets are read and either written directly to a file
 * or interpreted for display on the fly.
 */
void
net_read(dlpi_handle_t dh, size_t chunksize, int filter, void (*proc)(),
    int flags)
{
	int 	retval;
	extern int count;
	size_t	msglen;

	count = 0;

	/* allocate a read buffer */
	bufp = malloc(chunksize);
	if (bufp == NULL)
		pr_err("no memory for %d buffer", chunksize);

	/*
	 * read frames
	 */
	for (;;) {
		msglen = chunksize;
		retval = dlpi_recv(dh, NULL, NULL, bufp, &msglen, -1, NULL);

		if (retval != DLPI_SUCCESS || quitting)
			break;

		if (msglen != 0)
			scan(bufp, msglen, filter, 0, 0, proc, 0, 0, flags);
	}

	free(bufp);

	if (!quitting)
		pr_errdlpi(dh, "network read failed", retval);
}

#ifdef DEBUG
/*
 * corrupt: simulate packet corruption for debugging interpreters
 */
void
corrupt(volatile char *pktp, volatile char *pstop, char *buf,
	volatile char *bufstop)
{
	int c;
	int i;
	int p;
	int li = rand() % (pstop - pktp - 1) + 1;
	volatile char *pp = pktp;
	volatile char *pe = bufstop < pstop ? bufstop : pstop;

	if (pktp < buf || pktp > bufstop)
		return;

	for (pp = pktp; pp < pe; pp += li) {
		c = ((pe - pp) < li ? pe - pp : li);
		i = (rand() % c)>>1;
		while (--i > 0) {
			p = (rand() % c);
			pp[p] = (unsigned char)(rand() & 0xFF);
		}
	}
}
#endif /* DEBUG */

static void
scan(char *buf, int len, int filter, int cap, int old, void (*proc)(),
    int first, int last, int flags)
{
	volatile char *bp, *bufstop;
	volatile struct sb_hdr *hdrp;
	volatile struct sb_hdr nhdr, *nhdrp;
	volatile char *pktp;
	volatile struct timeval last_timestamp;
	volatile int header_okay;
	extern int count, maxcount;
	extern int snoop_nrecover;
#ifdef	DEBUG
	extern int zflg;
#endif	/* DEBUG */

	proc(0, 0, 0);
	bufstop = buf + len;

	/*
	 *
	 * Loop through each packet in the buffer
	 */
	last_timestamp.tv_sec = 0;
	(void) memcpy((char *)ojmp_env, (char *)jmp_env, sizeof (jmp_env));
	for (bp = buf; bp < bufstop; bp += nhdrp->sbh_totlen) {
		/*
		 * Gracefully exit if user terminates
		 */
		if (quitting)
			break;
		/*
		 * Global error recocery: Prepare to continue when a corrupt
		 * packet or header is encountered.
		 */
		if (sigsetjmp(jmp_env, 1)) {
			goto err;
		}

		header_okay = 0;
		hdrp = (struct sb_hdr *)bp;
		nhdrp = hdrp;
		pktp = (char *)hdrp + sizeof (*hdrp);

		/*
		 * If reading a capture file
		 * convert the headers from network
		 * byte order (for little-endians like X86)
		 */
		if (cap) {
			/*
			 * If the packets come from an old
			 * capture file, convert the header.
			 */
			if (old) {
				convert_old((struct ohdr *)hdrp);
			}

			nhdrp = &nhdr;

			nhdrp->sbh_origlen = ntohl(hdrp->sbh_origlen);
			nhdrp->sbh_msglen = ntohl(hdrp->sbh_msglen);
			nhdrp->sbh_totlen = ntohl(hdrp->sbh_totlen);
			nhdrp->sbh_drops = ntohl(hdrp->sbh_drops);
			nhdrp->sbh_timestamp.tv_sec =
			    ntohl(hdrp->sbh_timestamp.tv_sec);
			nhdrp->sbh_timestamp.tv_usec =
			    ntohl(hdrp->sbh_timestamp.tv_usec);
		}

		/* Enhanced check for valid header */

		if ((nhdrp->sbh_totlen == 0) ||
		    (bp + nhdrp->sbh_totlen) < bp ||
		    (bp + nhdrp->sbh_totlen) > bufstop ||
		    (nhdrp->sbh_origlen == 0) ||
		    (bp + nhdrp->sbh_origlen) < bp ||
		    (nhdrp->sbh_msglen == 0) ||
		    (bp + nhdrp->sbh_msglen) < bp ||
		    (bp + nhdrp->sbh_msglen) > bufstop ||
		    (nhdrp->sbh_msglen > nhdrp->sbh_origlen) ||
		    (nhdrp->sbh_totlen < nhdrp->sbh_msglen) ||
		    (nhdrp->sbh_timestamp.tv_sec == 0)) {
			if (cap) {
				(void) fprintf(stderr, "(warning) bad packet "
				    "header in capture file");
			} else {
				(void) fprintf(stderr, "(warning) bad packet "
				    "header in buffer");
			}
			(void) fprintf(stderr, " offset %d: length=%d\n",
			    bp - buf, nhdrp->sbh_totlen);
			goto err;
		}

		/*
		 * Check for incomplete packet.  We are conservative here,
		 * since we don't know how good the checking is in other
		 * parts of the code.  We pass a partial packet, with
		 * a warning.
		 */
		if (pktp + nhdrp->sbh_msglen > bufstop) {
			(void) fprintf(stderr, "truncated packet buffer\n");
			nhdrp->sbh_msglen = bufstop - pktp;
		}

#ifdef DEBUG
		if (zflg)
			corrupt(pktp, pktp + nhdrp->sbh_msglen, buf, bufstop);
#endif /* DEBUG */

		header_okay = 1;
		if (!filter ||
		    want_packet((uchar_t *)pktp,
		    nhdrp->sbh_msglen,
		    nhdrp->sbh_origlen)) {
			count++;

			/*
			 * Start deadman timer for interpreter processing
			 */
			(void) snoop_alarm(SNOOP_ALARM_GRAN*SNOOP_MAXRECOVER,
			    NULL);

			encap_levels = 0;
			if (!cap || count >= first)
				proc(nhdrp, pktp, count, flags);

			if (cap && count >= last) {
				(void) snoop_alarm(0, NULL);
				break;
			}

			if (maxcount && count >= maxcount) {
				(void) fprintf(stderr, "%d packets captured\n",
				    count);
				exit(0);
			}

			snoop_nrecover = 0;			/* success */
			(void) snoop_alarm(0, NULL);
			last_timestamp = hdrp->sbh_timestamp;	/* save stamp */
		}
		continue;
err:
		/*
		 * Corruption has been detected. Reset errors.
		 */
		snoop_recover();

		/*
		 * packet header was apparently okay. Continue.
		 */
		if (header_okay)
			continue;

		/*
		 * Otherwise try to scan forward to the next packet, using
		 * the last known timestamp if it is available.
		 */
		nhdrp = &nhdr;
		nhdrp->sbh_totlen = 0;
		if (last_timestamp.tv_sec == 0) {
			bp += sizeof (int);
		} else {
			for (bp += sizeof (int); bp <= bufstop;
			    bp += sizeof (int)) {
				hdrp = (struct sb_hdr *)bp;
				/* An approximate timestamp located */
				if ((hdrp->sbh_timestamp.tv_sec >> 8) ==
				    (last_timestamp.tv_sec >> 8))
					break;
			}
		}
	}
	/* reset jmp_env for program exit */
	(void) memcpy((char *)jmp_env, (char *)ojmp_env, sizeof (jmp_env));
	proc(0, -1, 0);
}

/*
 * Called if nwrite() encounters write problems.
 */
static void
cap_write_error(const char *msgtype)
{
	(void) fprintf(stderr,
	    "snoop: cannot write %s to capture file: %s\n",
	    msgtype, strerror(errno));
	exit(1);
}

/*
 * Writes target buffer to the open file descriptor. Upon detection of a short
 * write, an attempt to process the remaining bytes occurs until all anticipated
 * bytes are written. An error status is returned to indicate any serious write
 * failures.
 */
static int
nwrite(int fd, const void *buffer, size_t buflen)
{
	size_t nwritten;
	ssize_t nbytes = 0;
	const char *buf = buffer;

	for (nwritten = 0; nwritten < buflen; nwritten += nbytes) {
		nbytes = write(fd, &buf[nwritten], buflen - nwritten);
		if (nbytes == -1)
			return (-1);
		if (nbytes == 0) {
			errno = EIO;
			return (-1);
		}
	}
	return (0);
}

/*
 * Routines for opening, closing, reading and writing
 * a capture file of packets saved with the -o option.
 */
static int capfile_out;

/*
 * The snoop capture file has a header to identify
 * it as a capture file and record its version.
 * A file without this header is assumed to be an
 * old format snoop file.
 *
 * A version 1 header looks like this:
 *
 *   0   1   2   3   4   5   6   7   8   9  10  11
 * +---+---+---+---+---+---+---+---+---+---+---+---+---+
 * | s | n | o | o | p | \0| \0| \0|    version    |  data
 * +---+---+---+---+---+---+---+---+---+---+---+---+---+
 * |	 word 0	   |	 word 1	   |	 word 2	   |
 *
 *
 * A version 2 header adds a word that identifies the MAC type.
 * This allows for capture files from FDDI etc.
 *
 *   0   1   2   3   4   5   6   7   8   9  10  11  12  13  14  15
 * +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
 * | s | n | o | o | p | \0| \0| \0|    version    |    MAC type   | data
 * +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
 * |	 word 0	   |	 word 1	   |	 word 2	   |	 word 3
 *
 */
static const char *snoop_id = "snoop\0\0\0";
static const int snoop_idlen = 8;
static const int snoop_version = 2;

void
cap_open_write(const char *name)
{
	int vers;

	capfile_out = open(name, O_CREAT | O_TRUNC | O_RDWR, 0666);
	if (capfile_out < 0)
		pr_err("%s: %m", name);

	vers = htonl(snoop_version);
	if (nwrite(capfile_out, snoop_id, snoop_idlen) == -1)
		cap_write_error("snoop_id");

	if (nwrite(capfile_out, &vers, sizeof (int)) == -1)
		cap_write_error("version");
}


void
cap_close(void)
{
	(void) close(capfile_out);
}

static char *cap_buffp = NULL;
static int cap_len = 0;
static int cap_new;

void
cap_open_read(const char *name)
{
	struct stat st;
	int cap_vers;
	int *word;
	int device_mac_type = -1;
	int capfile_in;

	capfile_in = open(name, O_RDONLY);
	if (capfile_in < 0)
		pr_err("couldn't open %s: %m", name);

	if (fstat(capfile_in, &st) < 0)
		pr_err("couldn't stat %s: %m", name);
	if (st.st_size > INT_MAX)
		pr_err("input file size (%llu bytes) exceeds maximum "
		    "supported size (%d bytes)",
		    (unsigned long long)st.st_size, INT_MAX);
	cap_len = st.st_size;

	cap_buffp = mmap(0, cap_len, PROT_READ, MAP_PRIVATE, capfile_in, 0);
	(void) close(capfile_in);
	if ((int)cap_buffp == -1)
		pr_err("couldn't mmap %s: %m", name);

	/* Check if new snoop capture file format */

	cap_new = bcmp(cap_buffp, snoop_id, snoop_idlen) == 0;

	/*
	 * If new file - check version and
	 * set buffer pointer to point at first packet
	 */
	if (cap_new) {
		cap_vers = ntohl(*(int *)(cap_buffp + snoop_idlen));
		cap_buffp += snoop_idlen + sizeof (int);
		cap_len   -= snoop_idlen + sizeof (int);

		switch (cap_vers) {
		case 1:
			device_mac_type = DL_ETHER;
			break;

		case 2:
			device_mac_type = ntohl(*((int *)cap_buffp));
			cap_buffp += sizeof (int);
			cap_len   -= sizeof (int);
			break;

		default:
			pr_err("capture file: %s: Version %d unrecognized\n",
			    name, cap_vers);
		}

		for (interface = &INTERFACES[0]; interface->mac_type != -1;
		    interface++)
			if (interface->mac_type == device_mac_type)
				break;

		if (interface->mac_type == -1)
			pr_err("Mac Type = %x is not supported\n",
			    device_mac_type);
	} else {
		/* Use heuristic to check if it's an old-style file */

		device_mac_type = DL_ETHER;
		word = (int *)cap_buffp;

		if (!((word[0] < 1600 && word[1] < 1600) &&
		    (word[0] < word[1]) &&
		    (word[2] > 610000000 && word[2] < 770000000)))
			pr_err("not a capture file: %s", name);

		/* Change protection so's we can fix the headers */

		if (mprotect(cap_buffp, cap_len, PROT_READ | PROT_WRITE) < 0)
			pr_err("mprotect: %s: %m", name);
	}
}

void
cap_read(int first, int last, int filter, void (*proc)(), int flags)
{
	extern int count;

	count = 0;

	scan(cap_buffp, cap_len, filter, 1, !cap_new, proc, first, last, flags);

	(void) munmap(cap_buffp, cap_len);
}

/* ARGSUSED */
void
cap_write(struct sb_hdr *hdrp, char *pktp, int num, int flags)
{
	int pktlen, mac;
	static int first = 1;
	struct sb_hdr nhdr;
	extern boolean_t qflg;

	if (hdrp == NULL)
		return;

	if (first) {
		first = 0;
		mac = htonl(interface->mac_type);
		if (nwrite(capfile_out, &mac, sizeof (int)) == -1)
			cap_write_error("mac_type");
	}

	pktlen = hdrp->sbh_totlen - sizeof (*hdrp);

	/*
	 * Convert sb_hdr to network byte order
	 */
	nhdr.sbh_origlen = htonl(hdrp->sbh_origlen);
	nhdr.sbh_msglen = htonl(hdrp->sbh_msglen);
	nhdr.sbh_totlen = htonl(hdrp->sbh_totlen);
	nhdr.sbh_drops = htonl(hdrp->sbh_drops);
	nhdr.sbh_timestamp.tv_sec = htonl(hdrp->sbh_timestamp.tv_sec);
	nhdr.sbh_timestamp.tv_usec = htonl(hdrp->sbh_timestamp.tv_usec);

	if (nwrite(capfile_out, &nhdr, sizeof (nhdr)) == -1)
		cap_write_error("packet header");

	if (nwrite(capfile_out, pktp, pktlen) == -1)
		cap_write_error("packet");

	if (! qflg)
		show_count();
}

/*
 * Convert a packet header from
 * old to new format.
 */
static void
convert_old(struct ohdr *ohdrp)
{
	struct sb_hdr nhdr;

	nhdr.sbh_origlen = ohdrp->o_len;
	nhdr.sbh_msglen  = ohdrp->o_msglen;
	nhdr.sbh_totlen  = ohdrp->o_totlen;
	nhdr.sbh_drops   = ohdrp->o_drops;
	nhdr.sbh_timestamp = ohdrp->o_time;

	*(struct sb_hdr *)ohdrp = nhdr;
}

static int
strioctl(int fd, int cmd, int timout, int len, void *dp)
{
	struct	strioctl	sioc;
	int	rc;

	sioc.ic_cmd = cmd;
	sioc.ic_timout = timout;
	sioc.ic_len = len;
	sioc.ic_dp = dp;
	rc = ioctl(fd, I_STR, &sioc);

	if (rc < 0)
		return (rc);
	else
		return (sioc.ic_len);
}
