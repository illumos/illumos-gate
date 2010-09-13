/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 *  You may not use this file except in compliance with the License.
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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Synchronous loop-back test program
 * For installation verification of synchronous lines and facilities
 */

#include <sys/types.h>
#include <ctype.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <sys/time.h>
#include <sys/file.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/stream.h>
#include <sys/stropts.h>
#include <sys/poll.h>
#include <sys/ser_sync.h>
#include <libdlpi.h>

static void Usage(void);
static void quiet_period(void);
static void first_packet();
static void many_packets();
static void printhex(char *cp, int len);

static unsigned int speed = 9600;
static int reccount = 100;
static int reclen = 100;
static char loopstr[MAX_INPUT];
static int looptype = 0;
static int loopchange = 0;
static int clockchange = 0;
static int cfd, dfd;		/* control and data descriptors */
static int data = -1;
static int verbose = 0;

static char *yesno[] = {
	"no",
	"yes",
	"silent",
	0,
};

static char *txnames[] = {
	"txc",
	"rxc",
	"baud",
	"pll",
	"sysclk",
	"-txc",
	0,
};

static char *rxnames[] = {
	"rxc",
	"txc",
	"baud",
	"pll",
	"sysclk",
	"-rxc",
	0,
};

#define	MAXPACKET	4096

int
main(int argc, char **argv)
{
	char *portname;
	char dnambuf[MAXPATHLEN], *cp;
	char device[DLPI_LINKNAME_MAX];
	struct scc_mode sm;
	struct strioctl sioc;
	uint_t ppa;
	char *devstr = "/dev/";
	int devstrlen;
	int retval;
	dlpi_handle_t dh;

	argc--;
	argv++;
	while (argc > 0 && argv[0][0] == '-')
		switch (argv[0][1]) {
		case 'c':	/* rec count */
			if (argc < 2)
				Usage();
			reccount = atoi(argv[1]);
			argc -= 2;
			argv += 2;
			break;
		case 'd':
			if (sscanf(argv[1], "%x", (uint_t *)&data) != 1)
				Usage();
			argc -= 2;
			argv += 2;
			break;
		case 'l':	/* rec length */
			if (argc < 2)
				Usage();
			reclen = atoi(argv[1]);
			argc -= 2;
			argv += 2;
			break;
		case 's':	/* line speed */
			if (argc < 2)
				Usage();
			speed = atoi(argv[1]);
			argc -= 2;
			argv += 2;
			break;
		case 't':	/* test type */
			if (argc < 2)
				Usage();
			looptype = atoi(argv[1]);
			argc -= 2;
			argv += 2;
			break;
		case 'v':
			verbose = 1;
			argc--;
			argv++;
			break;
		}
	if (argc != 1)
		Usage();
	portname = argv[0];

	devstrlen = strlen(devstr);
	if (strncmp(devstr, portname, devstrlen) != 0) {
		if (snprintf(dnambuf, sizeof (dnambuf), "%s%s", devstr,
		    portname) >= sizeof (dnambuf)) {
			(void) fprintf(stderr,
			    "syncloop: invalid device name (too long) %s\n",
			    portname);
			exit(1);
		}
	}

	dfd = open(dnambuf, O_RDWR);
	if (dfd < 0) {
		(void) fprintf(stderr, "syncloop: cannot open %s\n", dnambuf);
		perror(dnambuf);
		exit(1);
	}

	cp = portname;
	while (*cp)			/* find the end of the name */
		cp++;
	cp--;
	if (!isdigit(*cp)) {
		(void) fprintf(stderr,
		    "syncloop: %s missing minor device number\n", portname);
		exit(1);
	}

	if (strlen(portname) >= DLPI_LINKNAME_MAX) {
		(void) fprintf(stderr,
		    "syncloop: invalid device name (too long) %s\n",
		    portname);
		exit(1);
	}

	if ((retval = dlpi_open(portname, &dh, DLPI_SERIAL)) != DLPI_SUCCESS) {
		(void) fprintf(stderr, "syncloop: dlpi_open %s: %s\n", portname,
		    dlpi_strerror(retval));
		exit(1);
	}

	(void) dlpi_parselink(portname, device, &ppa);

	if (reclen < 0 || reclen > MAXPACKET) {
		(void) printf("invalid packet length: %d\n", reclen);
		exit(1);
	}
	(void) printf("[ Data device: %s | Control device: %s, ppa=%u ]\n",
		dnambuf, device, ppa);

	cfd = dlpi_fd(dh);

	sioc.ic_cmd = S_IOCGETMODE;
	sioc.ic_timout = -1;
	sioc.ic_len = sizeof (struct scc_mode);
	sioc.ic_dp = (char *)&sm;
	if (ioctl(cfd, I_STR, &sioc) < 0) {
		perror("S_IOCGETMODE");
		(void) fprintf(stderr, "syncloop: can't get sync mode info "
		    "for %s\n", portname);
		exit(1);
	}
	while (looptype < 1 || looptype > 4) {
		(void) printf("Enter test type:\n");
		(void) printf("1: Internal Test\n");
		(void) printf(
"            (internal data loop, internal clocking)\n");
		(void) printf("2: Test using loopback plugs\n");
		(void) printf(
"            (external data loop, internal clocking)\n");
		(void) printf("3: Test using local or remote modem loopback\n");
		(void) printf(
"            (external data loop, external clocking)\n");
		(void) printf("4: Other, previously set, special mode\n");
		(void) printf("> "); (void) fflush(stdout);
		(void) fgets(loopstr, sizeof (loopstr), stdin);
		(void) sscanf(loopstr, "%d", &looptype);
	}
	switch (looptype) {
	case 1:
		if ((sm.sm_txclock != TXC_IS_BAUD) ||
		    (sm.sm_rxclock != RXC_IS_BAUD))
			clockchange++;
		sm.sm_txclock = TXC_IS_BAUD;
		sm.sm_rxclock = RXC_IS_BAUD;
		if ((sm.sm_config & CONN_LPBK) == 0)
			loopchange++;
		sm.sm_config |= CONN_LPBK;
		break;
	case 2:
		if ((sm.sm_txclock != TXC_IS_BAUD) ||
		    (sm.sm_rxclock != RXC_IS_RXC))
			clockchange++;
		sm.sm_txclock = TXC_IS_BAUD;
		sm.sm_rxclock = RXC_IS_RXC;
		if ((sm.sm_config & CONN_LPBK) != 0)
			loopchange++;
		sm.sm_config &= ~CONN_LPBK;
		break;
	case 3:
		if ((sm.sm_txclock != TXC_IS_TXC) ||
		    (sm.sm_rxclock != RXC_IS_RXC))
			clockchange++;
		sm.sm_txclock = TXC_IS_TXC;
		sm.sm_rxclock = RXC_IS_RXC;
		if ((sm.sm_config & CONN_LPBK) != 0)
			loopchange++;
		sm.sm_config &= ~CONN_LPBK;
		break;
	case 4:
		goto no_params;
	}

	sm.sm_baudrate = speed;

	sioc.ic_cmd = S_IOCSETMODE;
	sioc.ic_timout = -1;
	sioc.ic_len = sizeof (struct scc_mode);
	sioc.ic_dp = (char *)&sm;
	if (ioctl(cfd, I_STR, &sioc) < 0) {
		perror("S_IOCSETMODE");
		(void) fprintf(stderr,
		    "syncloop: can't set sync mode info for %s\n", portname);
		exit(1);
	}

no_params:
	/* report state */
	sioc.ic_cmd = S_IOCGETMODE;
	sioc.ic_timout = -1;
	sioc.ic_len = sizeof (struct scc_mode);
	sioc.ic_dp = (char *)&sm;
	if (ioctl(cfd, I_STR, &sioc) < 0) {
		perror("S_IOCGETMODE");
		(void) fprintf(stderr, "syncloop: can't get sync mode info "
			"for %s\n", portname);
		exit(1);
	}
	(void) printf("speed=%d, loopback=%s, nrzi=%s, txc=%s, rxc=%s\n",
		sm.sm_baudrate,
		yesno[((int)(sm.sm_config & CONN_LPBK) > 0)],
		yesno[((int)(sm.sm_config & CONN_NRZI) > 0)],
		txnames[sm.sm_txclock],
		rxnames[sm.sm_rxclock]);

	quiet_period();
	first_packet();
	many_packets();
	return (0);
}

static void
Usage()
{
	(void) printf("Usage: syncloop [ options ] portname\n");
	(void) printf("Options: -c packet_count\n");
	(void) printf("         -l packet_length\n");
	(void) printf("         -s line_speed\n");
	(void) printf("         -t test_type\n");
	(void) printf("         -d hex_data_byte\n");
	exit(1);
}

static int zero_time = 0;
static int short_time = 1000;
static int long_time = 4000;
static char bigbuf[4096];
static char packet[MAXPACKET];
static struct pollfd pfd;

static void
quiet_period()
{
	(void) printf("[ checking for quiet line ]\n");
	pfd.fd = dfd;
	pfd.events = POLLIN;
	pfd.revents = 0;
	while (poll(&pfd, 1, short_time) == 1) {
		(void) read(dfd, bigbuf, sizeof (bigbuf));
	}
	if (poll(&pfd, 1, long_time) == 1) {
		(void) printf("packet received but none sent!\n");
		(void) printf("quiesce other end before starting syncloop\n");
		exit(1);
	}
}

static void
first_packet()
{
	int i, len;
	int pollret;
	struct strioctl sioc;
	struct sl_stats start_stats, end_stats;

	for (i = 0; i < reclen; i++)
		packet[i] = (data == -1) ? rand() : data;
	(void) printf("[ Trying first packet ]\n");
	sioc.ic_cmd = S_IOCGETSTATS;
	sioc.ic_timout = -1;
	sioc.ic_len = sizeof (struct sl_stats);
	sioc.ic_dp = (char *)&start_stats;
	if (ioctl(cfd, I_STR, &sioc) < 0) {
		perror("S_IOCGETSTATS");
		exit(1);
	}

	for (i = 0; i < 5; i++) {
		if (write(dfd, packet, reclen) != reclen) {
			(void) fprintf(stderr,
				"packet write failed, errno %d\n",
				errno);
			exit(1);
		}
		pfd.fd = dfd;
		pfd.events = POLLIN;
		pollret = poll(&pfd, 1, long_time);
		if (pollret < 0) perror("poll");
		if (pollret == 0)
			(void) printf("poll: nothing to read.\n");
		if (pollret == 1) {
			len = read(dfd, bigbuf, reclen);
			if (len == reclen && memcmp(packet, bigbuf, len) == 0)
				return;	/* success */
			else {
				(void) printf("len %d should be %d\n",
					len, reclen);
				if (verbose) {
					(void) printf("           ");
					printhex(bigbuf, len);
					(void) printf("\nshould be ");
					printhex(packet, reclen);
					(void) printf("\n");
				}
			}
		}
	}
	(void) printf("Loopback has TOTALLY FAILED - ");
	(void) printf("no packets returned after 5 attempts\n");
	sioc.ic_cmd = S_IOCGETSTATS;
	sioc.ic_timout = -1;
	sioc.ic_len = sizeof (struct sl_stats);
	sioc.ic_dp = (char *)&end_stats;
	if (ioctl(cfd, I_STR, &sioc) < 0) {
		perror("S_IOCGETSTATS");
		exit(1);
	}
	if (start_stats.opack == end_stats.opack)
		(void) printf(
			"No packets transmitted - no transmit clock present\n");
	exit(1);
}

static void
many_packets()
{
	struct strioctl sioc;
	struct sl_stats start_stats, end_stats;
	struct timeval start_time, end_time;
	int baddata = 0;
	float secs, speed;
	int i, len;
	int incount = 0;
	long prev_sec = -1;
	int pollret;

	(void) printf("[ Trying many packets ]\n");
	sioc.ic_cmd = S_IOCGETSTATS;
	sioc.ic_timout = -1;
	sioc.ic_len = sizeof (struct sl_stats);
	sioc.ic_dp = (char *)&start_stats;
	if (ioctl(cfd, I_STR, &sioc) < 0) {
		perror("S_IOCGETSTATS");
		exit(1);
	}
	(void) gettimeofday(&start_time, 0);
	end_time = start_time;

	i = 0;
	while (i < reccount) {
		if (end_time.tv_sec != prev_sec) {
			prev_sec = end_time.tv_sec;
			(void) printf("\r %d ", incount);
			(void) fflush(stdout);
		}
		pfd.fd = dfd;
		pfd.events = POLLIN;
		while (pollret = poll(&pfd, 1, zero_time)) {
			if (pollret < 0)
				perror("poll");
			else {
				(void) lseek(dfd, (long)0, 0);
				len = read(dfd, bigbuf, reclen);
				if (len != reclen ||
				    memcmp(packet, bigbuf, len) != 0) {
					(void) printf("len %d should be %d\n",
						len, reclen);
					if (verbose) {
						(void) printf("           ");
						printhex(bigbuf, len);
						(void) printf("\nshould be ");
						printhex(packet, reclen);
						(void) printf("\n");
					}
					baddata++;
				}
				incount++;
				(void) gettimeofday(&end_time, 0);
			}
		}
		pfd.fd = dfd;
		pfd.events = POLLIN|POLLOUT;
		pollret = poll(&pfd, 1, long_time);
		if (pollret < 0)
			perror("poll");
		if (pollret == 0)
			(void) printf("poll: nothing to read or write.\n");
		if (pollret == 1) {
			if (pfd.revents & POLLOUT) {
				(void) write(dfd, packet, reclen);
				i++;
			} else if (!(pfd.revents & POLLIN)) {
				(void) printf("OUTPUT HAS LOCKED UP!!!\n");
				break;
			}
		}
	}
	pfd.fd = dfd;
	pfd.events = POLLIN;
	while ((incount < reccount) && (poll(&pfd, 1, long_time) == 1)) {
		if (end_time.tv_sec != prev_sec) {
			prev_sec = end_time.tv_sec;
			(void) printf("\r %d ", incount);
			(void) fflush(stdout);
		}
		len = read(dfd, bigbuf, reclen);
		if (len != reclen || memcmp(packet, bigbuf, len) != 0) {
			(void) printf("len %d should be %d\n", len, reclen);
			if (verbose) {
				(void) printf("           ");
				printhex(bigbuf, len);
				(void) printf("\nshould be ");
				printhex(packet, reclen);
				(void) printf("\n");
			}
			baddata++;
		}
		incount++;
		(void) gettimeofday(&end_time, 0);
	}
	(void) printf("\r %d \n", incount);
	if (baddata)
		(void) printf("%d packets with wrong data received!\n",
			baddata);
	sioc.ic_cmd = S_IOCGETSTATS;
	sioc.ic_timout = -1;
	sioc.ic_len = sizeof (struct sl_stats);
	sioc.ic_dp = (char *)&end_stats;
	if (ioctl(cfd, I_STR, &sioc) < 0) {
		perror("S_IOCGETSTATS");
		exit(1);
	}
	end_stats.ipack -= start_stats.ipack;
	end_stats.opack -= start_stats.opack;
	end_stats.abort -= start_stats.abort;
	end_stats.crc -= start_stats.crc;
	end_stats.overrun -= start_stats.overrun;
	end_stats.underrun -= start_stats.underrun;
	end_stats.ierror -= start_stats.ierror;
	end_stats.oerror -= start_stats.oerror;
	if (reccount > end_stats.opack)
		(void) printf("%d packets lost in outbound queueing\n",
			reccount - end_stats.opack);
	if (incount < end_stats.ipack && incount < reccount)
		(void) printf("%d packets lost in inbound queueing\n",
			end_stats.ipack - incount);
	(void) printf("%d packets sent, %d received\n", reccount, incount);
	(void) printf("CRC errors    Aborts   Overruns  Underruns         ");
	(void) printf("   In <-Drops-> Out\n%9d  %9d  %9d  %9d  %12d  %12d\n",
		end_stats.crc, end_stats.abort,
		end_stats.overrun, end_stats.underrun,
		end_stats.ierror, end_stats.oerror);
	secs = (float)(end_time.tv_usec - start_time.tv_usec) / 1000000.0;
	secs += (float)(end_time.tv_sec - start_time.tv_sec);
	if (secs) {
		speed = 8 * incount * (4 + reclen) / secs;
		(void) printf("estimated line speed = %d bps\n", (int)speed);
	}
}

static void
printhex(char *cp, int len)
{
	char c, *hex = "0123456789ABCDEF";
	int i;

	for (i = 0; i < len; i++) {
		c = *cp++;
		(void) putchar(hex[(c >> 4) & 0xF]);
		(void) putchar(hex[c & 0xF]);
	}
}
