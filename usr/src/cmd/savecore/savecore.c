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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <deflt.h>
#include <time.h>
#include <syslog.h>
#include <stropts.h>
#include <sys/mem.h>
#include <sys/statvfs.h>
#include <sys/dumphdr.h>
#include <sys/dumpadm.h>
#include <sys/compress.h>
#include <sys/sysmacros.h>

static char 	progname[9] = "savecore";
static char	*savedir;		/* savecore directory */
static char	*dumpfile;		/* source of raw crash dump */
static long	pagesize;		/* dump pagesize */
static int	dumpfd = -1;		/* dumpfile descriptor */
static dumphdr_t corehdr, dumphdr;	/* initial and terminal dumphdrs */
static offset_t	endoff;			/* offset of end-of-dump header */
static int	verbose;		/* chatty mode */
static int	disregard_valid_flag;	/* disregard valid flag */
static int	livedump;		/* dump the current running system */

static void
usage(void)
{
	(void) fprintf(stderr,
	    "usage: %s [-Lvd] [-f dumpfile] [dirname]\n", progname);
	exit(1);
}

static void
logprint(int logpri, int showmsg, int exitcode, char *message, ...)
{
	va_list args;
	char buf[1024];

	if (showmsg) {
		va_start(args, message);
		(void) vsnprintf(buf, 1024, message, args);
		(void) fprintf(stderr, "%s: %s\n", progname, buf);
		if (logpri >= 0)
			syslog(logpri, buf);
		va_end(args);
	}
	if (exitcode >= 0)
		exit(exitcode);
}

/*
 * System call / libc wrappers that exit on error.
 */
static int
Open(const char *name, int oflags, mode_t mode)
{
	int fd;

	if ((fd = open64(name, oflags, mode)) == -1)
		logprint(LOG_ERR, 1, 1, "open(\"%s\"): %s",
		    name, strerror(errno));
	return (fd);
}

static void
Pread(int fd, void *buf, size_t size, offset_t off)
{
	if (pread64(fd, buf, size, off) != size)
		logprint(LOG_ERR, 1, 1, "pread: %s", strerror(errno));
}

static void
Pwrite(int fd, void *buf, size_t size, offset_t off)
{
	if (pwrite64(fd, buf, size, off) != size)
		logprint(LOG_ERR, 1, 1, "pwrite: %s", strerror(errno));
}

static void *
Zalloc(size_t size)
{
	void *buf;

	if ((buf = calloc(size, 1)) == NULL)
		logprint(LOG_ERR, 1, 1, "calloc: %s", strerror(errno));
	return (buf);
}

static long
read_number_from_file(const char *filename, long default_value)
{
	long file_value = -1;
	FILE *fp;

	if ((fp = fopen(filename, "r")) != NULL) {
		(void) fscanf(fp, "%ld", &file_value);
		(void) fclose(fp);
	}
	return (file_value < 0 ? default_value : file_value);
}

static void
read_dumphdr(void)
{
	dumpfd = Open(dumpfile, O_RDWR | O_DSYNC, 0644);
	endoff = llseek(dumpfd, -DUMP_OFFSET, SEEK_END) & -DUMP_OFFSET;
	Pread(dumpfd, &dumphdr, sizeof (dumphdr), endoff);

	pagesize = dumphdr.dump_pagesize;

	if ((dumphdr.dump_flags & DF_VALID) == 0 && !disregard_valid_flag)
		logprint(-1, verbose, 0, "dump already processed");

	if (dumphdr.dump_magic != DUMP_MAGIC)
		logprint(-1, verbose, 0, "bad magic number %x",
		    dumphdr.dump_magic);

	if (dumphdr.dump_version != DUMP_VERSION)
		logprint(-1, verbose, 0,
		    "dump version (%d) != %s version (%d)",
		    dumphdr.dump_version, progname, DUMP_VERSION);

	if (dumphdr.dump_wordsize != DUMP_WORDSIZE)
		logprint(LOG_WARNING, 1, 0,
		    "dump is from %u-bit kernel - cannot save on %u-bit kernel",
		    dumphdr.dump_wordsize, DUMP_WORDSIZE);
	/*
	 * Read the initial header, clear the valid bits, and compare headers.
	 * The main header may have been overwritten by swapping if we're
	 * using a swap partition as the dump device, in which case we bail.
	 */
	Pread(dumpfd, &corehdr, sizeof (dumphdr_t), dumphdr.dump_start);

	corehdr.dump_flags &= ~DF_VALID;
	dumphdr.dump_flags &= ~DF_VALID;

	if (memcmp(&corehdr, &dumphdr, sizeof (dumphdr_t)) != 0) {
		/*
		 * Clear valid bit so we don't complain on every invocation.
		 */
		Pwrite(dumpfd, &dumphdr, sizeof (dumphdr), endoff);
		logprint(LOG_ERR, 1, 1, "initial dump header corrupt");
	}
}

static void
check_space(void)
{
	struct statvfs fsb;
	int64_t spacefree, dumpsize, minfree;

	if (statvfs(".", &fsb) < 0)
		logprint(LOG_ERR, 1, 1, "statvfs: %s", strerror(errno));

	dumpsize = (dumphdr.dump_data - dumphdr.dump_start) +
	    (int64_t)dumphdr.dump_npages * pagesize;
	spacefree = (int64_t)fsb.f_bavail * fsb.f_frsize;
	minfree = 1024LL * read_number_from_file("minfree", 1024);
	if (spacefree < minfree + dumpsize)
		logprint(LOG_ERR, 1, 1,
		    "not enough space in %s (%lld MB avail, %lld MB needed)",
		    savedir, spacefree >> 20, (minfree + dumpsize) >> 20);
}

static void
build_dump_map(int corefd, const pfn_t *pfn_table)
{
	long i;
	static long misses = 0;
	size_t dump_mapsize = (corehdr.dump_hashmask + 1) * sizeof (dump_map_t);
	mem_vtop_t vtop;
	dump_map_t *dmp = Zalloc(dump_mapsize);

	corehdr.dump_data = corehdr.dump_map + roundup(dump_mapsize, pagesize);

	for (i = 0; i < corehdr.dump_nvtop; i++) {
		long first = 0;
		long last = corehdr.dump_npages - 1;
		long middle;
		pfn_t pfn;
		uintptr_t h;

		Pread(dumpfd, &vtop, sizeof (mem_vtop_t),
		    dumphdr.dump_map + i * sizeof (mem_vtop_t));

		while (last >= first) {
			middle = (first + last) / 2;
			pfn = pfn_table[middle];
			if (pfn == vtop.m_pfn)
				break;
			if (pfn < vtop.m_pfn)
				first = middle + 1;
			else
				last = middle - 1;
		}
		if (pfn != vtop.m_pfn) {
			if (++misses <= 10)
				(void) fprintf(stderr,
				    "pfn %ld not found for as=%p, va=%p\n",
				    vtop.m_pfn, (void *)vtop.m_as, vtop.m_va);
			continue;
		}

		dmp[i].dm_as = vtop.m_as;
		dmp[i].dm_va = (uintptr_t)vtop.m_va;
		dmp[i].dm_data = corehdr.dump_data +
		    ((uint64_t)middle << corehdr.dump_pageshift);

		h = DUMP_HASH(&corehdr, dmp[i].dm_as, dmp[i].dm_va);
		dmp[i].dm_next = dmp[h].dm_first;
		dmp[h].dm_first = corehdr.dump_map + i * sizeof (dump_map_t);
	}

	Pwrite(corefd, dmp, dump_mapsize, corehdr.dump_map);
	free(dmp);
}

static void
build_corefile(const char *namelist, const char *corefile)
{
	char *inbuf = Zalloc(pagesize);
	char *outbuf = Zalloc(pagesize);
	size_t pfn_table_size = dumphdr.dump_npages * sizeof (pfn_t);
	size_t ksyms_size = dumphdr.dump_ksyms_size;
	size_t ksyms_csize = dumphdr.dump_ksyms_csize;
	pfn_t *pfn_table = Zalloc(pfn_table_size);
	char *ksyms_base = Zalloc(ksyms_size);
	char *ksyms_cbase = Zalloc(ksyms_csize);
	int corefd = Open(corefile, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	int namefd = Open(namelist, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	offset_t dumpoff;
	int percent_done = 0;
	pgcnt_t saved = 0;
	uint32_t csize;
	size_t dsize;

	(void) printf("Constructing namelist %s/%s\n", savedir, namelist);

	/*
	 * Read in the compressed symbol table, copy it to corefile,
	 * decompress it, and write the result to namelist.
	 */
	corehdr.dump_ksyms = pagesize;
	Pread(dumpfd, ksyms_cbase, ksyms_csize, dumphdr.dump_ksyms);
	Pwrite(corefd, ksyms_cbase, ksyms_csize, corehdr.dump_ksyms);

	if ((dsize = decompress(ksyms_cbase, ksyms_base, ksyms_csize,
	    ksyms_size)) != ksyms_size)
	    logprint(LOG_WARNING, 1, -1, "bad data in symbol table, %lu of %lu"
		" bytes saved", dsize, ksyms_size);

	Pwrite(namefd, ksyms_base, ksyms_size, 0);
	(void) close(namefd);
	free(ksyms_cbase);
	free(ksyms_base);

	(void) printf("Constructing corefile %s/%s\n", savedir, corefile);

	/*
	 * Read in and write out the pfn table.
	 */
	corehdr.dump_pfn = corehdr.dump_ksyms + roundup(ksyms_size, pagesize);
	Pread(dumpfd, pfn_table, pfn_table_size, dumphdr.dump_pfn);
	Pwrite(corefd, pfn_table, pfn_table_size, corehdr.dump_pfn);

	/*
	 * Convert the raw translation data into a hashed dump map.
	 */
	corehdr.dump_map = corehdr.dump_pfn + roundup(pfn_table_size, pagesize);
	build_dump_map(corefd, pfn_table);

	/*
	 * Decompress and save the pages.
	 */
	dumpoff = dumphdr.dump_data;
	while (saved < dumphdr.dump_npages) {
		Pread(dumpfd, &csize, sizeof (uint32_t), dumpoff);
		dumpoff += sizeof (uint32_t);
		if (csize > pagesize)
			break;
		Pread(dumpfd, inbuf, csize, dumpoff);
		dumpoff += csize;
		if (decompress(inbuf, outbuf, csize, pagesize) != pagesize)
			break;
		Pwrite(corefd, outbuf, pagesize,
		    corehdr.dump_data + saved * pagesize);
		if (++saved * 100LL / dumphdr.dump_npages > percent_done) {
			(void) printf("\r%3d%% done", ++percent_done);
			(void) fflush(stdout);
		}
	}

	(void) printf(": %ld of %ld pages saved\n", saved, dumphdr.dump_npages);

	if (saved != dumphdr.dump_npages)
		logprint(LOG_WARNING, 1, -1, "bad data after page %ld", saved);

	/*
	 * Write out the modified dump headers.
	 */
	Pwrite(corefd, &corehdr, sizeof (corehdr), 0);
	Pwrite(dumpfd, &dumphdr, sizeof (dumphdr), endoff);

	(void) close(corefd);
	(void) close(dumpfd);
}

/*
 * When the system panics, the kernel saves all undelivered messages (messages
 * that never made it out to syslogd(1M)) in the dump.  At a mimimum, the
 * panic message itself will always fall into this category.  Upon reboot,
 * the syslog startup script runs savecore -m to recover these messages.
 *
 * To do this, we read the unsent messages from the dump and send them to
 * /dev/conslog on priority band 1.  This has the effect of prepending them
 * to any already-accumulated messages in the console backlog, thus preserving
 * temporal ordering across the reboot.
 *
 * Note: since savecore -m is used *only* for this purpose, it does *not*
 * attempt to save the crash dump.  The dump will be saved later, after
 * syslogd(1M) starts, by the savecore startup script.
 */
static int
message_save(void)
{
	offset_t dumpoff = -(DUMP_OFFSET + DUMP_LOGSIZE);
	offset_t ldoff;
	log_dump_t ld;
	log_ctl_t lc;
	struct strbuf ctl, dat;
	int logfd;

	logfd = Open("/dev/conslog", O_WRONLY, 0644);
	dumpfd = Open(dumpfile, O_RDWR | O_DSYNC, 0644);
	dumpoff = llseek(dumpfd, dumpoff, SEEK_END) & -DUMP_OFFSET;

	ctl.buf = (void *)&lc;
	ctl.len = sizeof (log_ctl_t);

	dat.buf = Zalloc(DUMP_LOGSIZE);

	for (;;) {
		ldoff = dumpoff;

		Pread(dumpfd, &ld, sizeof (log_dump_t), dumpoff);
		dumpoff += sizeof (log_dump_t);
		dat.len = ld.ld_msgsize;

		if (ld.ld_magic == 0)
			break;

		if (ld.ld_magic != LOG_MAGIC)
			logprint(-1, verbose, 0, "bad magic %x", ld.ld_magic);

		if (dat.len >= DUMP_LOGSIZE)
			logprint(-1, verbose, 0, "bad size %d", ld.ld_msgsize);

		Pread(dumpfd, ctl.buf, ctl.len, dumpoff);
		dumpoff += ctl.len;

		if (ld.ld_csum != checksum32(ctl.buf, ctl.len))
			logprint(-1, verbose, 0, "bad log_ctl checksum");

		lc.flags |= SL_LOGONLY;

		Pread(dumpfd, dat.buf, dat.len, dumpoff);
		dumpoff += dat.len;

		if (ld.ld_msum != checksum32(dat.buf, dat.len))
			logprint(-1, verbose, 0, "bad message checksum");

		if (putpmsg(logfd, &ctl, &dat, 1, MSG_BAND) == -1)
			logprint(LOG_ERR, 1, 1, "putpmsg: %s", strerror(errno));

		ld.ld_magic = 0;	/* clear magic so we never save twice */
		Pwrite(dumpfd, &ld, sizeof (log_dump_t), ldoff);
	}
	return (0);
}

int
main(int argc, char *argv[])
{
	int c, bfd;
	int mflag = 0;
	long bounds;
	char namelist[30], corefile[30], boundstr[30];

	openlog(progname, LOG_ODELAY, LOG_AUTH);
	(void) defopen("/etc/dumpadm.conf");
	savedir = defread("DUMPADM_SAVDIR=");

	while ((c = getopt(argc, argv, "Lvdmf:")) != EOF) {
		switch (c) {
		case 'L':
			livedump++;
			break;
		case 'v':
			verbose++;
			break;
		case 'd':
			disregard_valid_flag++;
			break;
		case 'm':
			mflag++;
			break;
		case 'f':
			dumpfile = optarg;
			break;
		case '?':
			usage();
		}
	}

	if (dumpfile == NULL || livedump)
		dumpfd = Open("/dev/dump", O_RDONLY, 0444);

	if (dumpfile == NULL) {
		dumpfile = Zalloc(MAXPATHLEN);
		if (ioctl(dumpfd, DIOCGETDEV, dumpfile) == -1) {
			/*
			 * If this isn't an interactive session, we are running
			 * as part of the boot process.  If this is the case,
			 * don't complain about the lack of dump device.
			 */
			if (isatty(STDOUT_FILENO))
				logprint(LOG_ERR, 1, 1,
				    "no dump device configured");
			else
				return (1);
		}
	}

	if (mflag)
		return (message_save());

	if (optind == argc - 1)
		savedir = argv[optind];
	if (savedir == NULL || optind < argc - 1)
		usage();

	if (livedump && ioctl(dumpfd, DIOCDUMP, NULL) == -1)
		logprint(-1, 1, 1, "dedicated dump device required");

	(void) close(dumpfd);

	read_dumphdr();

	/*
	 * We want this message to go to the log file, but not the console.
	 * There's no good way to do that with the existing syslog facility.
	 * We could extend it to handle this, but there doesn't seem to be
	 * a general need for it, so we isolate the complexity here instead.
	 */
	if (dumphdr.dump_panicstring[0] != '\0') {
		int logfd = Open("/dev/conslog", O_WRONLY, 0644);
		log_ctl_t lc;
		struct strbuf ctl, dat;
		char msg[DUMP_PANICSIZE + 100];
		char fmt[] = "reboot after panic: %s";
		uint32_t msgid;

		STRLOG_MAKE_MSGID(fmt, msgid);

		(void) sprintf(msg, "%s: [ID %u FACILITY_AND_PRIORITY] ",
		    progname, msgid);
		(void) sprintf(msg + strlen(msg), fmt,
		    dumphdr.dump_panicstring);

		lc.pri = LOG_AUTH | LOG_ERR;
		lc.flags = SL_CONSOLE | SL_LOGONLY;
		lc.level = 0;

		ctl.buf = (void *)&lc;
		ctl.len = sizeof (log_ctl_t);

		dat.buf = (void *)msg;
		dat.len = strlen(msg) + 1;

		(void) putmsg(logfd, &ctl, &dat, 0);
		(void) close(logfd);
	}

	if (chdir(savedir) == -1)
		logprint(LOG_ERR, 1, 1, "chdir(\"%s\"): %s",
		    savedir, strerror(errno));

	if ((dumphdr.dump_flags & DF_COMPLETE) == 0)
		logprint(LOG_WARNING, 1, -1, "incomplete dump on dump device");

	(void) printf("System dump time: %s", ctime(&dumphdr.dump_crashtime));

	check_space();

	bounds = read_number_from_file("bounds", 0);

	(void) sprintf(namelist, "unix.%ld", bounds);
	(void) sprintf(corefile, "vmcore.%ld", bounds);

	syslog(LOG_ERR, "saving system crash dump in %s/*.%ld",
	    savedir, bounds);

	build_corefile(namelist, corefile);

	(void) sprintf(boundstr, "%ld\n", bounds + 1);
	bfd = Open("bounds", O_WRONLY | O_CREAT | O_TRUNC, 0644);
	Pwrite(bfd, boundstr, strlen(boundstr), 0);
	(void) close(bfd);

	return (0);
}
