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
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved	*/


/*
 * sar generates a report either from an input data file or by invoking sadc to
 * read system activity counters at the specified intervals.
 *
 * usage:  sar [-ubdycwaqvmpgrkA] [-o file] t [n]
 *	   sar [-ubdycwaqvmpgrkA][-s hh:mm][-e hh:mm][-i ss][-f file]
 */

#include <sys/param.h>
#include <sys/stat.h>
#include <sys/sysinfo.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/wait.h>

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "sa.h"

#define	PGTOBLK(x)	((x) * (pagesize >> 9))
#define	BLKTOPG(x)	((x) / (pagesize >> 9))
#define	BLKS(x)		((x) >> 9)

static void	prpass(int);
static void	prtopt(void);
static void	prtavg(void);
static void	prttim(void);
static void	prtmachid(void);
static void	prthdg(void);
static void	tsttab(void);
static void	update_counters(void);
static void	usage(void);
static void	fail(int, char *, ...);
static void	safe_zalloc(void **, int, int);
static int	safe_read(int, void *, size_t);
static void	safe_write(int, void *, size_t);
static int	safe_strtoi(char const *, char *);
static void	ulong_delta(uint64_t *, uint64_t *, uint64_t *, uint64_t *,
	int, int);
static float	denom(float);
static float	freq(float, float);

static struct sa64	nx, ox, ax, dx;
static iodevinfo_t	*nxio, *oxio, *axio, *dxio;
static struct tm	*curt, args, arge;

static int	sflg, eflg, iflg, oflg, fflg;
static int	realtime, passno = 0, do_disk;
static int	t = 0, n = 0, lines = 0;
static int	hz;
static int	niodevs;
static int	tabflg;
static char	options[30], fopt[30];
static float	tdiff, sec_diff, totsec_diff = 0.0, percent;
static float	start_time, end_time, isec;
static int	fin, fout;
static pid_t	childid;
static int	pipedes[2];
static char	arg1[10], arg2[10];
static int	pagesize;

/*
 * To avoid overflow in the kmem allocation data, declare a copy of the
 * main kmeminfo_t type with larger data types. Use this for storing
 * the data held to display average values
 */
static struct kmeminfo_l
{
	u_longlong_t	km_mem[KMEM_NCLASS];
	u_longlong_t	km_alloc[KMEM_NCLASS];
	u_longlong_t	km_fail[KMEM_NCLASS];
} kmi;

int
main(int argc, char **argv)
{
	char    flnm[PATH_MAX], ofile[PATH_MAX];
	char	ccc;
	time_t	temp;
	int	i, jj = 0;

	pagesize = sysconf(_SC_PAGESIZE);

	/*
	 * Process options with arguments and pack options
	 * without arguments.
	 */
	while ((i = getopt(argc, argv, "ubdycwaqvmpgrkAo:s:e:i:f:")) != EOF)
		switch (ccc = (char)i) {
		case 'o':
			oflg++;
			if (strlcpy(ofile, optarg, sizeof (ofile)) >=
			    sizeof (ofile)) {
				fail(2, "-o filename is too long: %s", optarg);
			}
			break;
		case 's':
			if (sscanf(optarg, "%d:%d:%d",
			    &args.tm_hour, &args.tm_min, &args.tm_sec) < 1)
				fail(0, "-%c %s -- illegal option argument",
				    ccc, optarg);
			else {
				sflg++;
				start_time = args.tm_hour*3600.0 +
				    args.tm_min*60.0 +
				    args.tm_sec;
			}
			break;
		case 'e':
			if (sscanf(optarg, "%d:%d:%d",
			    &arge.tm_hour, &arge.tm_min, &arge.tm_sec) < 1)
				fail(0, "-%c %s -- illegal option argument",
				    ccc, optarg);
			else {
				eflg++;
				end_time = arge.tm_hour*3600.0 +
				    arge.tm_min*60.0 +
				    arge.tm_sec;
			}
			break;
		case 'i':
			if (sscanf(optarg, "%f", &isec) < 1)
				fail(0, "-%c %s -- illegal option argument",
				    ccc, optarg);
			else {
				if (isec > 0.0)
					iflg++;
			}
			break;
		case 'f':
			fflg++;
			if (strlcpy(flnm, optarg, sizeof (flnm)) >=
			    sizeof (ofile)) {
				fail(2, "-f filename is too long: %s", optarg);
			}
			break;
		case '?':
			usage();
			exit(1);
			break;
		default:

			/*
			 * Check for repeated options. To make sure
			 * that options[30] does not overflow.
			 */
			if (strchr(options, ccc) == NULL)
				(void) strncat(options, &ccc, 1);
			break;
		}

	/*
	 * Are starting and ending times consistent?
	 */
	if ((sflg) && (eflg) && (end_time <= start_time))
		fail(0, "ending time <= starting time");

	/*
	 * Determine if t and n arguments are given, and whether to run in real
	 * time or from a file.
	 */
	switch (argc - optind) {
	case 0:		/*   Get input data from file   */
		if (fflg == 0) {
			temp = time(NULL);
			curt = localtime(&temp);
			(void) snprintf(flnm, PATH_MAX, "/var/adm/sa/sa%.2d",
			    curt->tm_mday);
		}
		if ((fin = open(flnm, 0)) == -1)
			fail(1, "can't open %s", flnm);
		break;
	case 1:		/*   Real time data; one cycle   */
		realtime++;
		t = safe_strtoi(argv[optind], "invalid sampling interval");
		n = 2;
		break;
	case 2:		/*   Real time data; specified cycles   */
	default:
		realtime++;
		t = safe_strtoi(argv[optind], "invalid sampling interval");
		n = 1 + safe_strtoi(argv[optind+1], "invalid sample count");
		break;
	}

	/*
	 * "u" is the default option, which displays CPU utilization.
	 */
	if (strlen(options) == 0)
		(void) strcpy(options, "u");

	/*
	 * "A" means all data options.
	 */
	if (strchr(options, 'A') != NULL)
		(void) strcpy(options, "udqbwcayvmpgrk");

	if (realtime) {
		/*
		 * Get input data from sadc via pipe.
		 */
		if (t <= 0)
			fail(0, "sampling interval t <= 0 sec");
		if (n < 2)
			fail(0, "number of sample intervals n <= 0");
		(void) sprintf(arg1, "%d", t);
		(void) sprintf(arg2, "%d", n);
		if (pipe(pipedes) == -1)
			fail(1, "pipe failed");
		if ((childid = fork()) == 0) {
			/*
			 * Child:  shift pipedes[write] to stdout,
			 * and close the pipe entries.
			 */
			(void) dup2(pipedes[1], 1);
			if (pipedes[0] != 1)
				(void) close(pipedes[0]);
			if (pipedes[1] != 1)
				(void) close(pipedes[1]);

			if (execlp("/usr/lib/sa/sadc",
			    "/usr/lib/sa/sadc", arg1, arg2, 0) == -1)
				fail(1, "exec of /usr/lib/sa/sadc failed");
		} else if (childid == -1) {
			fail(1, "Could not fork to exec sadc");
		}
		/*
		 * Parent:  close unused output.
		 */
		fin = pipedes[0];
		(void) close(pipedes[1]);
	}

	if (oflg) {
		if (strcmp(ofile, flnm) == 0)
			fail(0, "output file name same as input file name");
		fout = creat(ofile, 00644);
	}

	hz = sysconf(_SC_CLK_TCK);

	nxio = oxio = dxio = axio = NULL;

	if (realtime) {
		/*
		 * Make single pass, processing all options.
		 */
		(void) strcpy(fopt, options);
		passno++;
		prpass(realtime);
		(void) kill(childid, SIGINT);
		(void) wait(NULL);
	} else {
		/*
		 * Make multiple passes, one for each option.
		 */
		while (strlen(strncpy(fopt, &options[jj++], 1))) {
			if (lseek(fin, 0, SEEK_SET) == (off_t)-1)
				fail(0, "lseek failed");
			passno++;
			prpass(realtime);
		}
	}

	return (0);
}

/*
 * Convert array of 32-bit uints to 64-bit uints
 */
static void
convert_32to64(uint64_t *dst, uint_t *src, int size)
{
	for (; size > 0; size--)
		*dst++ = (uint64_t)(*src++);
}

/*
 * Convert array of 64-bit uints to 32-bit uints
 */
static void
convert_64to32(uint_t *dst, uint64_t *src, int size)
{
	for (; size > 0; size--)
		*dst++ = (uint32_t)(*src++);
}

/*
 * Read records from input, classify, and decide on printing.
 */
static void
prpass(int input_pipe)
{
	size_t size;
	int i, j, state_change, recno = 0;
	kid_t kid;
	float trec, tnext = 0;
	ulong_t old_niodevs = 0, prev_niodevs = 0;
	iodevinfo_t *aio, *dio, *oio;
	struct stat in_stat;
	struct sa tx;
	uint64_t ts, te; /* time interval start and end */

	do_disk = (strchr(fopt, 'd') != NULL);
	if (!input_pipe && fstat(fin, &in_stat) == -1)
		fail(1, "unable to stat data file");

	if (sflg)
		tnext = start_time;

	while (safe_read(fin, &tx, sizeof (struct sa))) {
		/*
		 * First, we convert 32-bit tx to 64-bit nx structure
		 * which is used later. Conversion could be done
		 * after initial operations, right before calculations,
		 * but it would introduce additional juggling with vars.
		 * Thus, we convert all data now, and don't care about
		 * tx any further.
		 */
		nx.valid = tx.valid;
		nx.ts = tx.ts;
		convert_32to64((uint64_t *)&nx.csi, (uint_t *)&tx.csi,
		    sizeof (tx.csi) / sizeof (uint_t));
		convert_32to64((uint64_t *)&nx.cvmi, (uint_t *)&tx.cvmi,
		    sizeof (tx.cvmi) / sizeof (uint_t));
		convert_32to64((uint64_t *)&nx.si, (uint_t *)&tx.si,
		    sizeof (tx.si) / sizeof (uint_t));
		(void) memcpy(&nx.vmi, &tx.vmi,
		    sizeof (tx) - (((char *)&tx.vmi) - ((char *)&tx)));
		/*
		 * sadc is the only utility used to generate sar data
		 * and it uses the valid field as follows:
		 * 0 - dummy record
		 * 1 - data record
		 * We can use this fact to improve sar's ability to detect
		 * bad data, since any value apart from 0 or 1 can be
		 * interpreted as invalid data.
		 */
		if (nx.valid != 0 && nx.valid != 1)
			fail(2, "data file not in sar format");
		state_change = 0;
		niodevs = nx.niodevs;
		/*
		 * niodevs has the value of current number of devices
		 * from nx structure.
		 *
		 * The following 'if' condition is to decide whether memory
		 * has to be allocated or not if already allocated memory is
		 * bigger or smaller than memory needed to store the current
		 * niodevs details in memory.
		 *
		 * when first while loop starts, pre_niodevs has 0 and then
		 * always get initialized to the current number of devices
		 * from nx.niodevs if it is different from previously read
		 * niodevs.
		 *
		 * if the current niodevs has the same value of previously
		 * allocated memory i.e, for prev_niodevs, it skips the
		 * following  'if' loop or otherwise it allocates memory for
		 * current devises (niodevs) and stores that value in
		 * prev_niodevs for next time when loop continues to read
		 * from the file.
		 */
		if (niodevs != prev_niodevs) {
			off_t curr_pos;
			/*
			 * The required buffer size must fit in a size_t.
			 */
			if (SIZE_MAX / sizeof (iodevinfo_t) < niodevs)
				fail(2, "insufficient address space to hold "
				    "%lu device records", niodevs);
			size = niodevs * sizeof (iodevinfo_t);
			prev_niodevs = niodevs;
			/*
			 * The data file must exceed this size to be valid.
			 */
			if (!input_pipe) {
				if ((curr_pos = lseek(fin, 0, SEEK_CUR)) ==
				    (off_t)-1)
					fail(1, "lseek failed");
				if (in_stat.st_size < curr_pos ||
				    size > in_stat.st_size - curr_pos)
					fail(2, "data file corrupt; "
					    "specified size exceeds actual");
			}

			safe_zalloc((void **)&nxio, size, 1);
		}
		if (niodevs != old_niodevs)
			state_change = 1;
		for (i = 0; i < niodevs; i++) {
			if (safe_read(fin, &nxio[i], sizeof (iodevinfo_t)) == 0)
				fail(1, "premature end-of-file seen");
			if (i < old_niodevs &&
			    nxio[i].ks.ks_kid != oxio[i].ks.ks_kid)
				state_change = 1;
		}
		curt = localtime(&nx.ts);
		trec = curt->tm_hour * 3600.0 +
		    curt->tm_min * 60.0 +
		    curt->tm_sec;
		if ((recno == 0) && (trec < start_time))
			continue;
		if ((eflg) && (trec > end_time))
			break;
		if ((oflg) && (passno == 1)) {
			/*
			 * The calculated values are stroed in nx strcuture.
			 * Convert 64-bit nx to 32-bit tx structure.
			 */
			tx.valid = nx.valid;
			tx.ts = nx.ts;
			convert_64to32((uint_t *)&tx.csi, (uint64_t *)&nx.csi,
			    sizeof (nx.csi) / sizeof (uint64_t));
			convert_64to32((uint_t *)&tx.cvmi, (uint64_t *)&nx.cvmi,
			    sizeof (nx.cvmi) / sizeof (uint64_t));
			convert_64to32((uint_t *)&tx.si, (uint64_t *)&nx.si,
			    sizeof (nx.si) / sizeof (uint64_t));
			(void) memcpy(&tx.vmi, &nx.vmi,
			    sizeof (nx) - (((char *)&nx.vmi) - ((char *)&nx)));
			if (tx.valid != 0 && tx.valid != 1)
				fail(2, "data file not in sar format");

			safe_write(fout, &tx, sizeof (struct sa));
			for (i = 0; i < niodevs; i++)
				safe_write(fout, &nxio[i],
				    sizeof (iodevinfo_t));
		}

		if (recno == 0) {
			if (passno == 1)
				prtmachid();

			prthdg();
			recno = 1;
			if ((iflg) && (tnext == 0))
				tnext = trec;
		}

		if (nx.valid == 0) {
			/*
			 * This dummy record signifies system restart
			 * New initial values of counters follow in next
			 * record.
			 */
			if (!realtime) {
				prttim();
				(void) printf("\tunix restarts\n");
				recno = 1;
				continue;
			}
		}
		if ((iflg) && (trec < tnext))
			continue;

		if (state_change) {
			/*
			 * Either the number of devices or the ordering of
			 * the kstats has changed.  We need to re-organise
			 * the layout of our avg/delta arrays so that we
			 * can cope with this in update_counters().
			 */
			size = niodevs * sizeof (iodevinfo_t);
			safe_zalloc((void *)&aio, size, 0);
			safe_zalloc((void *)&dio, size, 0);
			safe_zalloc((void *)&oio, size, 0);

			/*
			 * Loop through all the newly read iodev's, locate
			 * the corresponding entry in the old arrays and
			 * copy the entries into the same bucket of the
			 * new arrays.
			 */
			for (i = 0; i < niodevs; i++) {
				kid = nxio[i].ks.ks_kid;
				for (j = 0; j < old_niodevs; j++) {
					if (oxio[j].ks.ks_kid == kid) {
						oio[i] = oxio[j];
						aio[i] = axio[j];
						dio[i] = dxio[j];
					}
				}
			}

			free(axio);
			free(oxio);
			free(dxio);

			axio = aio;
			oxio = oio;
			dxio = dio;

			old_niodevs = niodevs;
		}

		if (recno++ > 1) {
			ts = ox.csi.cpu[0] + ox.csi.cpu[1] +
			    ox.csi.cpu[2] + ox.csi.cpu[3];
			te = nx.csi.cpu[0] + nx.csi.cpu[1] +
			    nx.csi.cpu[2] + nx.csi.cpu[3];
			tdiff = (float)(te - ts);
			sec_diff = tdiff / hz;
			percent = 100.0 / tdiff;

			/*
			 * If the CPU stat counters have rolled
			 * backward, this is our best indication that
			 * a CPU has been offlined.  We don't have
			 * enough data to compute a sensible delta, so
			 * toss out this interval, but compute the next
			 * interval's delta from these values.
			 */
			if (tdiff <= 0) {
				ox = nx;
				continue;
			}
			update_counters();
			prtopt();
			lines++;
			if (passno == 1)
				totsec_diff += sec_diff;
		}
		ox = nx;		/*  Age the data	*/
		(void) memcpy(oxio, nxio, niodevs * sizeof (iodevinfo_t));
		if (isec > 0)
			while (tnext <= trec)
				tnext += isec;
	}
	/*
	 * After this place, all functions are using niodevs to access the
	 * memory for device details. Here, old_niodevs has the correct value
	 * of memory allocated for storing device information. Since niodevs
	 * doesn't have correct value, sometimes, it was corrupting memory.
	 */
	niodevs = old_niodevs;
	if (lines > 1)
		prtavg();
	(void) memset(&ax, 0, sizeof (ax));	/* Zero out the accumulators. */
	(void) memset(&kmi, 0, sizeof (kmi));
	lines = 0;
	/*
	 * axio will not be allocated if the user specified -e or -s, and
	 * no records in the file fell inside the specified time range.
	 */
	if (axio) {
		(void) memset(axio, 0, niodevs * sizeof (iodevinfo_t));
	}
}

/*
 * Print time label routine.
 */
static void
prttim(void)
{
	curt = localtime(&nx.ts);
	(void) printf("%.2d:%.2d:%.2d", curt->tm_hour, curt->tm_min,
	    curt->tm_sec);
	tabflg = 1;
}

/*
 * Test if 8-spaces to be added routine.
 */
static void
tsttab(void)
{
	if (tabflg == 0)
		(void) printf("        ");
	else
		tabflg = 0;
}

/*
 * Print machine identification.
 */
static void
prtmachid(void)
{
	struct utsname name;

	(void) uname(&name);
	(void) printf("\n%s %s %s %s %s    %.2d/%.2d/%.4d\n",
	    name.sysname, name.nodename, name.release, name.version,
	    name.machine, curt->tm_mon + 1, curt->tm_mday,
	    curt->tm_year + 1900);
}

/*
 * Print report heading routine.
 */
static void
prthdg(void)
{
	int	jj = 0;
	char	ccc;

	(void) printf("\n");
	prttim();
	while ((ccc = fopt[jj++]) != '\0') {
		tsttab();
		switch (ccc) {
		case 'u':
			(void) printf(" %7s %7s %7s %7s\n",
			    "%usr",
			    "%sys",
			    "%wio",
			    "%idle");
			break;
		case 'b':
			(void) printf(" %7s %7s %7s %7s %7s %7s %7s %7s\n",
			    "bread/s",
			    "lread/s",
			    "%rcache",
			    "bwrit/s",
			    "lwrit/s",
			    "%wcache",
			    "pread/s",
			    "pwrit/s");
			break;
		case 'd':
			(void) printf("   %-8.8s    %7s %7s %7s %7s %7s %7s\n",
			    "device",
			    "%busy",
			    "avque",
			    "r+w/s",
			    "blks/s",
			    "avwait",
			    "avserv");
			break;
		case 'y':
			(void) printf(" %7s %7s %7s %7s %7s %7s\n",
			    "rawch/s",
			    "canch/s",
			    "outch/s",
			    "rcvin/s",
			    "xmtin/s",
			    "mdmin/s");
			break;
		case 'c':
			(void) printf(" %7s %7s %7s %7s %7s %7s %7s\n",
			    "scall/s",
			    "sread/s",
			    "swrit/s",
			    "fork/s",
			    "exec/s",
			    "rchar/s",
			    "wchar/s");
			break;
		case 'w':
			(void) printf(" %7s %7s %7s %7s %7s\n",
			    "swpin/s",
			    "bswin/s",
			    "swpot/s",
			    "bswot/s",
			    "pswch/s");
			break;
		case 'a':
			(void) printf(" %7s %7s %7s\n",
			    "iget/s",
			    "namei/s",
			    "dirbk/s");
			break;
		case 'q':
			(void) printf(" %7s %7s %7s %7s\n",
			    "runq-sz",
			    "%runocc",
			    "swpq-sz",
			    "%swpocc");
			break;
		case 'v':
			(void) printf("  %s  %s  %s   %s\n",
			    "proc-sz    ov",
			    "inod-sz    ov",
			    "file-sz    ov",
			    "lock-sz");
			break;
		case 'm':
			(void) printf(" %7s %7s\n",
			    "msg/s",
			    "sema/s");
			break;
		case 'p':
			(void) printf(" %7s %7s %7s %7s %7s %7s\n",
			    "atch/s",
			    "pgin/s",
			    "ppgin/s",
			    "pflt/s",
			    "vflt/s",
			    "slock/s");
			break;
		case 'g':
			(void) printf(" %8s %8s %8s %8s %8s\n",
			    "pgout/s",
			    "ppgout/s",
			    "pgfree/s",
			    "pgscan/s",
			    "%ufs_ipf");
			break;
		case 'r':
			(void) printf(" %7s %8s\n",
			    "freemem",
			    "freeswap");
			break;
		case 'k':
			(void) printf(" %7s %7s %5s %7s %7s %5s %11s %5s\n",
			    "sml_mem",
			    "alloc",
			    "fail",
			    "lg_mem",
			    "alloc",
			    "fail",
			    "ovsz_alloc",
			    "fail");
			break;
		}
	}
	if (jj > 2 || do_disk)
		(void) printf("\n");
}

/*
 * compute deltas and update accumulators
 */
static void
update_counters(void)
{
	int i;
	iodevinfo_t *nio, *oio, *aio, *dio;

	ulong_delta((uint64_t *)&nx.csi, (uint64_t *)&ox.csi,
	    (uint64_t *)&dx.csi, (uint64_t *)&ax.csi, 0, sizeof (ax.csi));
	ulong_delta((uint64_t *)&nx.si, (uint64_t *)&ox.si,
	    (uint64_t *)&dx.si, (uint64_t *)&ax.si, 0, sizeof (ax.si));
	ulong_delta((uint64_t *)&nx.cvmi, (uint64_t *)&ox.cvmi,
	    (uint64_t *)&dx.cvmi, (uint64_t *)&ax.cvmi, 0,
	    sizeof (ax.cvmi));

	ax.vmi.freemem += dx.vmi.freemem = nx.vmi.freemem - ox.vmi.freemem;
	ax.vmi.swap_avail += dx.vmi.swap_avail =
	    nx.vmi.swap_avail - ox.vmi.swap_avail;

	nio = nxio;
	oio = oxio;
	aio = axio;
	dio = dxio;
	for (i = 0; i < niodevs; i++) {
		aio->kios.wlastupdate += dio->kios.wlastupdate
		    = nio->kios.wlastupdate - oio->kios.wlastupdate;
		aio->kios.reads += dio->kios.reads
		    = nio->kios.reads - oio->kios.reads;
		aio->kios.writes += dio->kios.writes
		    = nio->kios.writes - oio->kios.writes;
		aio->kios.nread += dio->kios.nread
		    = nio->kios.nread - oio->kios.nread;
		aio->kios.nwritten += dio->kios.nwritten
		    = nio->kios.nwritten - oio->kios.nwritten;
		aio->kios.wlentime += dio->kios.wlentime
		    = nio->kios.wlentime - oio->kios.wlentime;
		aio->kios.rlentime += dio->kios.rlentime
		    = nio->kios.rlentime - oio->kios.rlentime;
		aio->kios.wtime += dio->kios.wtime
		    = nio->kios.wtime - oio->kios.wtime;
		aio->kios.rtime += dio->kios.rtime
		    = nio->kios.rtime - oio->kios.rtime;
		aio->ks.ks_snaptime += dio->ks.ks_snaptime
		    = nio->ks.ks_snaptime - oio->ks.ks_snaptime;
		nio++;
		oio++;
		aio++;
		dio++;
	}
}

static void
prt_u_opt(struct sa64 *xx)
{
	(void) printf(" %7.0f %7.0f %7.0f %7.0f\n",
	    (float)xx->csi.cpu[1] * percent,
	    (float)xx->csi.cpu[2] * percent,
	    (float)xx->csi.cpu[3] * percent,
	    (float)xx->csi.cpu[0] * percent);
}

static void
prt_b_opt(struct sa64 *xx)
{
	(void) printf(" %7.0f %7.0f %7.0f %7.0f %7.0f %7.0f %7.0f %7.0f\n",
	    (float)xx->csi.bread / sec_diff,
	    (float)xx->csi.lread / sec_diff,
	    freq((float)xx->csi.lread, (float)xx->csi.bread),
	    (float)xx->csi.bwrite / sec_diff,
	    (float)xx->csi.lwrite / sec_diff,
	    freq((float)xx->csi.lwrite, (float)xx->csi.bwrite),
	    (float)xx->csi.phread / sec_diff,
	    (float)xx->csi.phwrite / sec_diff);
}

static void
prt_d_opt(int ii, iodevinfo_t *xio)
{
	double etime, hr_etime, tps, avq, avs, pbusy;

	tsttab();

	hr_etime = (double)xio[ii].ks.ks_snaptime;
	if (hr_etime == 0.0)
		hr_etime = (double)NANOSEC;
	pbusy = (double)xio[ii].kios.rtime * 100.0 / hr_etime;
	if (pbusy > 100.0)
		pbusy = 100.0;
	etime = hr_etime / (double)NANOSEC;
	tps = (double)(xio[ii].kios.reads + xio[ii].kios.writes) / etime;
	avq = (double)xio[ii].kios.wlentime / hr_etime;
	avs = (double)xio[ii].kios.rlentime / hr_etime;

	(void) printf("   %-8.8s    ", nxio[ii].ks.ks_name);
	(void) printf("%7.0f %7.1f %7.0f %7.0f %7.1f %7.1f\n",
	    pbusy,
	    avq + avs,
	    tps,
	    BLKS(xio[ii].kios.nread + xio[ii].kios.nwritten) / etime,
	    (tps > 0 ? avq / tps * 1000.0 : 0.0),
	    (tps > 0 ? avs / tps * 1000.0 : 0.0));
}

static void
prt_y_opt(struct sa64 *xx)
{
	(void) printf(" %7.0f %7.0f %7.0f %7.0f %7.0f %7.0f\n",
	    (float)xx->csi.rawch / sec_diff,
	    (float)xx->csi.canch / sec_diff,
	    (float)xx->csi.outch / sec_diff,
	    (float)xx->csi.rcvint / sec_diff,
	    (float)xx->csi.xmtint / sec_diff,
	    (float)xx->csi.mdmint / sec_diff);
}

static void
prt_c_opt(struct sa64 *xx)
{
	(void) printf(" %7.0f %7.0f %7.0f %7.2f %7.2f %7.0f %7.0f\n",
	    (float)xx->csi.syscall / sec_diff,
	    (float)xx->csi.sysread / sec_diff,
	    (float)xx->csi.syswrite / sec_diff,
	    (float)(xx->csi.sysfork + xx->csi.sysvfork) / sec_diff,
	    (float)xx->csi.sysexec / sec_diff,
	    (float)xx->csi.readch / sec_diff,
	    (float)xx->csi.writech / sec_diff);
}

static void
prt_w_opt(struct sa64 *xx)
{
	(void) printf(" %7.2f %7.1f %7.2f %7.1f %7.0f\n",
	    (float)xx->cvmi.swapin / sec_diff,
	    (float)PGTOBLK(xx->cvmi.pgswapin) / sec_diff,
	    (float)xx->cvmi.swapout / sec_diff,
	    (float)PGTOBLK(xx->cvmi.pgswapout) / sec_diff,
	    (float)xx->csi.pswitch / sec_diff);
}

static void
prt_a_opt(struct sa64 *xx)
{
	(void) printf(" %7.0f %7.0f %7.0f\n",
	    (float)xx->csi.ufsiget / sec_diff,
	    (float)xx->csi.namei / sec_diff,
	    (float)xx->csi.ufsdirblk / sec_diff);
}

static void
prt_q_opt(struct sa64 *xx)
{
	if (xx->si.runocc == 0 || xx->si.updates == 0)
		(void) printf(" %7.1f %7.0f", 0., 0.);
	else {
		(void) printf(" %7.1f %7.0f",
		    (float)xx->si.runque / (float)xx->si.runocc,
		    (float)xx->si.runocc / (float)xx->si.updates * 100.0);
	}
	if (xx->si.swpocc == 0 || xx->si.updates == 0)
		(void) printf(" %7.1f %7.0f\n", 0., 0.);
	else {
		(void) printf(" %7.1f %7.0f\n",
		    (float)xx->si.swpque / (float)xx->si.swpocc,
		    (float)xx->si.swpocc / (float)xx->si.updates * 100.0);
	}
}

static void
prt_v_opt(struct sa64 *xx)
{
	(void) printf(" %4lu/%-4lu %4llu %4lu/%-4lu %4llu %4lu/%-4lu "
	    "%4llu %4lu/%-4lu\n",
	    nx.szproc, nx.mszproc, xx->csi.procovf,
	    nx.szinode, nx.mszinode, xx->csi.inodeovf,
	    nx.szfile, nx.mszfile, xx->csi.fileovf,
	    nx.szlckr, nx.mszlckr);
}

static void
prt_m_opt(struct sa64 *xx)
{
	(void) printf(" %7.2f %7.2f\n",
	    (float)xx->csi.msg / sec_diff,
	    (float)xx->csi.sema / sec_diff);
}

static void
prt_p_opt(struct sa64 *xx)
{
	(void) printf(" %7.2f %7.2f %7.2f %7.2f %7.2f %7.2f\n",
	    (float)xx->cvmi.pgfrec / sec_diff,
	    (float)xx->cvmi.pgin / sec_diff,
	    (float)xx->cvmi.pgpgin / sec_diff,
	    (float)(xx->cvmi.prot_fault + xx->cvmi.cow_fault) / sec_diff,
	    (float)(xx->cvmi.hat_fault + xx->cvmi.as_fault) / sec_diff,
	    (float)xx->cvmi.softlock / sec_diff);
}

static void
prt_g_opt(struct sa64 *xx)
{
	(void) printf(" %8.2f %8.2f %8.2f %8.2f %8.2f\n",
	    (float)xx->cvmi.pgout / sec_diff,
	    (float)xx->cvmi.pgpgout / sec_diff,
	    (float)xx->cvmi.dfree / sec_diff,
	    (float)xx->cvmi.scan / sec_diff,
	    (float)xx->csi.ufsipage * 100.0 /
	    denom((float)xx->csi.ufsipage +
	    (float)xx->csi.ufsinopage));
}

static void
prt_r_opt(struct sa64 *xx)
{
	/* Avoid divide by Zero - Should never happen */
	if (xx->si.updates == 0)
		(void) printf(" %7.0f %8.0f\n", 0., 0.);
	else {
		(void) printf(" %7.0f %8.0f\n",
		    (double)xx->vmi.freemem / (float)xx->si.updates,
		    (double)PGTOBLK(xx->vmi.swap_avail) /
		    (float)xx->si.updates);
	}
}

static void
prt_k_opt(struct sa64 *xx, int n)
{
	if (n != 1) {
		(void) printf(" %7.0f %7.0f %5.0f %7.0f %7.0f %5.0f %11.0f"
		    " %5.0f\n",
		    (float)kmi.km_mem[KMEM_SMALL] / n,
		    (float)kmi.km_alloc[KMEM_SMALL] / n,
		    (float)kmi.km_fail[KMEM_SMALL] / n,
		    (float)kmi.km_mem[KMEM_LARGE] / n,
		    (float)kmi.km_alloc[KMEM_LARGE] / n,
		    (float)kmi.km_fail[KMEM_LARGE] / n,
		    (float)kmi.km_alloc[KMEM_OSIZE] / n,
		    (float)kmi.km_fail[KMEM_OSIZE] / n);
	} else {
		/*
		 * If we are not reporting averages, use the read values
		 * directly.
		 */
		(void) printf(" %7.0f %7.0f %5.0f %7.0f %7.0f %5.0f %11.0f"
		    " %5.0f\n",
		    (float)xx->kmi.km_mem[KMEM_SMALL],
		    (float)xx->kmi.km_alloc[KMEM_SMALL],
		    (float)xx->kmi.km_fail[KMEM_SMALL],
		    (float)xx->kmi.km_mem[KMEM_LARGE],
		    (float)xx->kmi.km_alloc[KMEM_LARGE],
		    (float)xx->kmi.km_fail[KMEM_LARGE],
		    (float)xx->kmi.km_alloc[KMEM_OSIZE],
		    (float)xx->kmi.km_fail[KMEM_OSIZE]);
	}
}

/*
 * Print options routine.
 */
static void
prtopt(void)
{
	int	ii, jj = 0;
	char	ccc;

	prttim();

	while ((ccc = fopt[jj++]) != '\0') {
		if (ccc != 'd')
			tsttab();
		switch (ccc) {
		case 'u':
			prt_u_opt(&dx);
			break;
		case 'b':
			prt_b_opt(&dx);
			break;
		case 'd':
			for (ii = 0; ii < niodevs; ii++)
				prt_d_opt(ii, dxio);
			break;
		case 'y':
			prt_y_opt(&dx);
			break;
		case 'c':
			prt_c_opt(&dx);
			break;
		case 'w':
			prt_w_opt(&dx);
			break;
		case 'a':
			prt_a_opt(&dx);
			break;
		case 'q':
			prt_q_opt(&dx);
			break;
		case 'v':
			prt_v_opt(&dx);
			break;
		case 'm':
			prt_m_opt(&dx);
			break;
		case 'p':
			prt_p_opt(&dx);
			break;
		case 'g':
			prt_g_opt(&dx);
			break;
		case 'r':
			prt_r_opt(&dx);
			break;
		case 'k':
			prt_k_opt(&nx, 1);
			/*
			 * To avoid overflow, copy the data from the sa record
			 * into a struct kmeminfo_l which has members with
			 * larger data types.
			 */
			kmi.km_mem[KMEM_SMALL] += nx.kmi.km_mem[KMEM_SMALL];
			kmi.km_alloc[KMEM_SMALL] += nx.kmi.km_alloc[KMEM_SMALL];
			kmi.km_fail[KMEM_SMALL] += nx.kmi.km_fail[KMEM_SMALL];
			kmi.km_mem[KMEM_LARGE] += nx.kmi.km_mem[KMEM_LARGE];
			kmi.km_alloc[KMEM_LARGE] += nx.kmi.km_alloc[KMEM_LARGE];
			kmi.km_fail[KMEM_LARGE] += nx.kmi.km_fail[KMEM_LARGE];
			kmi.km_alloc[KMEM_OSIZE] += nx.kmi.km_alloc[KMEM_OSIZE];
			kmi.km_fail[KMEM_OSIZE] += nx.kmi.km_fail[KMEM_OSIZE];
			break;
		}
	}
	if (jj > 2 || do_disk)
		(void) printf("\n");
	if (realtime)
		(void) fflush(stdout);
}

/*
 * Print average routine.
 */
static void
prtavg(void)
{
	int	ii, jj = 0;
	char	ccc;

	tdiff = ax.csi.cpu[0] + ax.csi.cpu[1] + ax.csi.cpu[2] + ax.csi.cpu[3];
	if (tdiff <= 0.0)
		return;

	sec_diff = tdiff / hz;
	percent = 100.0 / tdiff;
	(void) printf("\n");

	while ((ccc = fopt[jj++]) != '\0') {
		if (ccc != 'v')
			(void) printf("Average ");
		switch (ccc) {
		case 'u':
			prt_u_opt(&ax);
			break;
		case 'b':
			prt_b_opt(&ax);
			break;
		case 'd':
			tabflg = 1;
			for (ii = 0; ii < niodevs; ii++)
				prt_d_opt(ii, axio);
			break;
		case 'y':
			prt_y_opt(&ax);
			break;
		case 'c':
			prt_c_opt(&ax);
			break;
		case 'w':
			prt_w_opt(&ax);
			break;
		case 'a':
			prt_a_opt(&ax);
			break;
		case 'q':
			prt_q_opt(&ax);
			break;
		case 'v':
			break;
		case 'm':
			prt_m_opt(&ax);
			break;
		case 'p':
			prt_p_opt(&ax);
			break;
		case 'g':
			prt_g_opt(&ax);
			break;
		case 'r':
			prt_r_opt(&ax);
			break;
		case 'k':
			prt_k_opt(&ax, lines);
			break;
		}
	}
}

static void
ulong_delta(uint64_t *new, uint64_t *old, uint64_t *delta, uint64_t *accum,
    int begin, int end)
{
	int i;
	uint64_t n, o, d;

	for (i = begin; i < end; i += sizeof (uint64_t)) {
		n = *new++;
		o = *old++;
		if (o > n) {
			d = n + 0x100000000LL - o;
		} else {
			d = n - o;
		}
		*accum++ += *delta++ = d;
	}
}

/*
 * used to prevent zero denominators
 */
static float
denom(float x)
{
	return ((x > 0.5) ? x : 1.0);
}

/*
 * a little calculation that comes up often when computing frequency
 * of one operation relative to another
 */
static float
freq(float x, float y)
{
	return ((x < 0.5) ? 100.0 : (x - y) / x * 100.0);
}

static void
usage(void)
{
	(void) fprintf(stderr,
	    "usage: sar [-ubdycwaqvmpgrkA][-o file] t [n]\n"
	    "\tsar [-ubdycwaqvmpgrkA] [-s hh:mm][-e hh:mm][-i ss][-f file]\n");
}

static void
fail(int do_perror, char *message, ...)
{
	va_list args;

	va_start(args, message);
	(void) fprintf(stderr, "sar: ");
	(void) vfprintf(stderr, message, args);
	va_end(args);
	(void) fprintf(stderr, "\n");
	switch (do_perror) {
	case 0:				/* usage message */
		usage();
		break;
	case 1:				/* perror output */
		perror("");
		break;
	case 2:				/* no further output */
		break;
	default:			/* error */
		(void) fprintf(stderr, "unsupported failure mode\n");
		break;
	}
	exit(2);
}

static int
safe_strtoi(char const *val, char *errmsg)
{
	char *end;
	long tmp;

	errno = 0;
	tmp = strtol(val, &end, 10);
	if (*end != '\0' || errno)
		fail(0, "%s %s", errmsg, val);
	return ((int)tmp);
}

static void
safe_zalloc(void **ptr, int size, int free_first)
{
	if (free_first && *ptr != NULL)
		free(*ptr);
	if ((*ptr = malloc(size)) == NULL)
		fail(1, "malloc failed");
	(void) memset(*ptr, 0, size);
}

static int
safe_read(int fd, void *buf, size_t size)
{
	size_t rsize = read(fd, buf, size);

	if (rsize == 0)
		return (0);

	if (rsize != size)
		fail(1, "read failed");

	return (1);
}

static void
safe_write(int fd, void *buf, size_t size)
{
	if (write(fd, buf, size) != size)
		fail(1, "write failed");
}
