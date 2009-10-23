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
#include <pthread.h>
#include <limits.h>
#include <atomic.h>
#include <sys/mem.h>
#include <sys/statvfs.h>
#include <sys/dumphdr.h>
#include <sys/dumpadm.h>
#include <sys/compress.h>
#include <sys/sysmacros.h>
#include <sys/stat.h>
#include <sys/resource.h>
#include <bzip2/bzlib.h>

/* fread/fwrite buffer size */
#define	FBUFSIZE		(1ULL << 20)

/* minimum size for output buffering */
#define	MINCOREBLKSIZE		(1ULL << 17)

/* create this file if metrics collection is enabled in the kernel */
#define	METRICSFILE "METRICS.csv"

static char 	progname[9] = "savecore";
static char	*savedir;		/* savecore directory */
static char	*dumpfile;		/* source of raw crash dump */
static long	bounds;			/* numeric suffix */
static long	pagesize;		/* dump pagesize */
static int	dumpfd = -1;		/* dumpfile descriptor */
static dumphdr_t corehdr, dumphdr;	/* initial and terminal dumphdrs */
static offset_t	endoff;			/* offset of end-of-dump header */
static int	verbose;		/* chatty mode */
static int	disregard_valid_flag;	/* disregard valid flag */
static int	livedump;		/* dump the current running system */
static int	interactive;		/* user invoked; no syslog */
static int	csave;			/* save dump compressed */
static int	filemode;		/* processing file, not dump device */
static int	percent_done;		/* progress indicator */
static hrtime_t	startts;		/* timestamp at start */
static volatile uint64_t saved;		/* count of pages written */
static volatile uint64_t zpages;	/* count of zero pages not written */
static dumpdatahdr_t datahdr;		/* compression info */
static long	coreblksize;		/* preferred write size (st_blksize) */

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
		(void) vsnprintf(buf, sizeof (buf), message, args);
		(void) fprintf(stderr, "%s: %s\n", progname, buf);
		if (!interactive && logpri >= 0)
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
Fread(void *buf, size_t size, FILE *f)
{
	if (fread(buf, size, 1, f) != 1)
		logprint(LOG_ERR, 1, 1, "fread: ferror %d feof %d",
		    ferror(f), feof(f));
}

static void
Fwrite(void *buf, size_t size, FILE *f)
{
	if (fwrite(buf, size, 1, f) != 1)
		logprint(LOG_ERR, 1, 1, "fwrite: %s", strerror(errno));
}

static void
Fseek(offset_t off, FILE *f)
{
	if (fseeko64(f, off, SEEK_SET) != 0)
		logprint(LOG_ERR, 1, 1, "fseeko64: %s", strerror(errno));
}

typedef struct stat64 Stat_t;

static void
Fstat(int fd, Stat_t *sb, const char *fname)
{
	if (fstat64(fd, sb) != 0)
		logprint(LOG_ERR, 1, 1, "fstat(\"%s\"): %s", fname,
		    strerror(errno));
}

static void
Stat(const char *fname, Stat_t *sb)
{
	if (stat64(fname, sb) != 0)
		logprint(LOG_ERR, 1, 1, "stat(\"%s\"): %s", fname,
		    strerror(errno));
}

static void
Pread(int fd, void *buf, size_t size, offset_t off)
{
	ssize_t sz = pread64(fd, buf, size, off);

	if (sz < 0)
		logprint(LOG_ERR, 1, 1,
		    "pread: %s", strerror(errno));
	else if (sz != size)
		logprint(LOG_ERR, 1, 1,
		    "pread: size %ld != %ld", sz, size);
}

static void
Pwrite(int fd, void *buf, size_t size, off64_t off)
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
	if (filemode)
		dumpfd = Open(dumpfile, O_RDONLY, 0644);
	else
		dumpfd = Open(dumpfile, O_RDWR | O_DSYNC, 0644);
	endoff = llseek(dumpfd, -DUMP_OFFSET, SEEK_END) & -DUMP_OFFSET;
	Pread(dumpfd, &dumphdr, sizeof (dumphdr), endoff);
	Pread(dumpfd, &datahdr, sizeof (datahdr), endoff + sizeof (dumphdr));

	pagesize = dumphdr.dump_pagesize;

	if (dumphdr.dump_magic != DUMP_MAGIC)
		logprint(-1, 1, 0, "bad magic number %x",
		    dumphdr.dump_magic);

	if ((dumphdr.dump_flags & DF_VALID) == 0 && !disregard_valid_flag)
		logprint(-1, verbose, 0, "dump already processed");

	if (dumphdr.dump_version != DUMP_VERSION)
		logprint(-1, verbose, 0,
		    "dump version (%d) != %s version (%d)",
		    dumphdr.dump_version, progname, DUMP_VERSION);

	if (dumphdr.dump_wordsize != DUMP_WORDSIZE)
		logprint(-1, 1, 0,
		    "dump is from %u-bit kernel - cannot save on %u-bit kernel",
		    dumphdr.dump_wordsize, DUMP_WORDSIZE);

	if (datahdr.dump_datahdr_magic == DUMP_DATAHDR_MAGIC) {
		if (datahdr.dump_datahdr_version != DUMP_DATAHDR_VERSION)
			logprint(-1, verbose, 0,
			    "dump data version (%d) != %s data version (%d)",
			    datahdr.dump_datahdr_version, progname,
			    DUMP_DATAHDR_VERSION);
	} else {
		memset(&datahdr, 0, sizeof (datahdr));
		datahdr.dump_maxcsize = pagesize;
	}

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
		if (!filemode)
			Pwrite(dumpfd, &dumphdr, sizeof (dumphdr), endoff);
		logprint(LOG_ERR, 1, 1, "initial dump header corrupt");
	}
}

static void
check_space(int csave)
{
	struct statvfs fsb;
	int64_t spacefree, dumpsize, minfree, datasize;

	if (statvfs(".", &fsb) < 0)
		logprint(LOG_ERR, 1, 1, "statvfs: %s", strerror(errno));

	dumpsize = dumphdr.dump_data - dumphdr.dump_start;
	datasize = dumphdr.dump_npages * pagesize;
	if (!csave)
		dumpsize += datasize;
	else
		dumpsize += datahdr.dump_data_csize;

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
	char *inbuf = Zalloc(FBUFSIZE);
	FILE *in = fdopen(dup(dumpfd), "rb");

	setvbuf(in, inbuf, _IOFBF, FBUFSIZE);
	Fseek(dumphdr.dump_map, in);

	corehdr.dump_data = corehdr.dump_map + roundup(dump_mapsize, pagesize);

	for (i = 0; i < corehdr.dump_nvtop; i++) {
		long first = 0;
		long last = corehdr.dump_npages - 1;
		long middle;
		pfn_t pfn;
		uintptr_t h;

		Fread(&vtop, sizeof (mem_vtop_t), in);
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
	fclose(in);
	free(inbuf);
}

/*
 * Copy whole sections of the dump device to the file.
 */
static void
Copy(offset_t dumpoff, len_t nb, offset_t *offp, int fd, char *buf,
    size_t sz)
{
	size_t nr;
	offset_t off = *offp;

	while (nb > 0) {
		nr = sz < nb ? sz : (size_t)nb;
		Pread(dumpfd, buf, nr, dumpoff);
		Pwrite(fd, buf, nr, off);
		off += nr;
		dumpoff += nr;
		nb -= nr;
	}
	*offp = off;
}

/*
 * Copy pages when the dump data header is missing.
 * This supports older kernels with latest savecore.
 */
static void
CopyPages(offset_t dumpoff, offset_t *offp, int fd, char *buf, size_t sz)
{
	uint32_t csize;
	FILE *in = fdopen(dup(dumpfd), "rb");
	FILE *out = fdopen(dup(fd), "wb");
	char *cbuf = Zalloc(pagesize);
	char *outbuf = Zalloc(FBUFSIZE);
	pgcnt_t np = dumphdr.dump_npages;

	setvbuf(out, outbuf, _IOFBF, FBUFSIZE);
	setvbuf(in, buf, _IOFBF, sz);
	Fseek(dumphdr.dump_data, in);

	Fseek(*offp, out);
	while (np > 0) {
		Fread(&csize, sizeof (uint32_t), in);
		Fwrite(&csize, sizeof (uint32_t), out);
		*offp += sizeof (uint32_t);
		if (csize > pagesize || csize == 0) {
			logprint(LOG_ERR, 1, -1,
			    "CopyPages: page %lu csize %d (0x%x) pagesize %d",
			    dumphdr.dump_npages - np, csize, csize,
			    pagesize);
			break;
		}
		Fread(cbuf, csize, in);
		Fwrite(cbuf, csize, out);
		*offp += csize;
		np--;
	}
	fclose(in);
	fclose(out);
	free(outbuf);
	free(buf);
}

/*
 * Concatenate dump contents into a new file.
 * Update corehdr with new offsets.
 */
static void
copy_crashfile(const char *corefile)
{
	int corefd = Open(corefile, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	size_t bufsz = FBUFSIZE;
	char *inbuf = Zalloc(bufsz);
	offset_t coreoff;
	size_t nb;

	logprint(LOG_ERR, verbose, -1,
	    "Copying %s to %s/%s\n", dumpfile, savedir, corefile);

	/*
	 * This dump file is still compressed
	 */
	corehdr.dump_flags |= DF_COMPRESSED | DF_VALID;

	/*
	 * Leave room for corehdr, it is updated and written last
	 */
	corehdr.dump_start = 0;
	coreoff = sizeof (corehdr);

	/*
	 * Read in the compressed symbol table, copy it to corefile.
	 */
	coreoff = roundup(coreoff, pagesize);
	corehdr.dump_ksyms = coreoff;
	Copy(dumphdr.dump_ksyms, dumphdr.dump_ksyms_csize, &coreoff, corefd,
	    inbuf, bufsz);

	/*
	 * Save the pfn table.
	 */
	coreoff = roundup(coreoff, pagesize);
	corehdr.dump_pfn = coreoff;
	Copy(dumphdr.dump_pfn, dumphdr.dump_npages * sizeof (pfn_t), &coreoff,
	    corefd, inbuf, bufsz);

	/*
	 * Save the dump map.
	 */
	coreoff = roundup(coreoff, pagesize);
	corehdr.dump_map = coreoff;
	Copy(dumphdr.dump_map, dumphdr.dump_nvtop * sizeof (mem_vtop_t),
	    &coreoff, corefd, inbuf, bufsz);

	/*
	 * Save the data pages.
	 */
	coreoff = roundup(coreoff, pagesize);
	corehdr.dump_data = coreoff;
	if (datahdr.dump_data_csize != 0)
		Copy(dumphdr.dump_data, datahdr.dump_data_csize, &coreoff,
		    corefd, inbuf, bufsz);
	else
		CopyPages(dumphdr.dump_data, &coreoff, corefd, inbuf, bufsz);

	/*
	 * Now write the modified dump header to front and end of the copy.
	 * Make it look like a valid dump device.
	 *
	 * From dumphdr.h: Two headers are written out: one at the
	 * beginning of the dump, and the other at the very end of the
	 * dump device. The terminal header is at a known location
	 * (end of device) so we can always find it.
	 *
	 * Pad with zeros to each DUMP_OFFSET boundary.
	 */
	memset(inbuf, 0, DUMP_OFFSET);

	nb = DUMP_OFFSET - (coreoff & (DUMP_OFFSET - 1));
	if (nb > 0) {
		Pwrite(corefd, inbuf, nb, coreoff);
		coreoff += nb;
	}

	Pwrite(corefd, &corehdr, sizeof (corehdr), coreoff);
	coreoff += sizeof (corehdr);

	Pwrite(corefd, &datahdr, sizeof (datahdr), coreoff);
	coreoff += sizeof (datahdr);

	nb = DUMP_OFFSET - (coreoff & (DUMP_OFFSET - 1));
	if (nb > 0) {
		Pwrite(corefd, inbuf, nb, coreoff);
	}

	free(inbuf);
	Pwrite(corefd, &corehdr, sizeof (corehdr), corehdr.dump_start);

	/*
	 * Write out the modified dump header to the dump device.
	 * The dump device has been processed, so DF_VALID is clear.
	 */
	if (!filemode)
		Pwrite(dumpfd, &dumphdr, sizeof (dumphdr), endoff);

	(void) close(corefd);
}

/*
 * compressed streams
 */
typedef struct blockhdr blockhdr_t;
typedef struct block block_t;

struct blockhdr {
	block_t *head;
	block_t *tail;
};

struct block {
	block_t *next;
	char *block;
	int size;
};

typedef enum streamstate {
	STREAMSTART,
	STREAMPAGES
} streamstate_t;

typedef struct stream {
	streamstate_t state;
	int init;
	int tag;
	int bound;
	int nout;
	char *blkbuf;
	blockhdr_t blocks;
	pgcnt_t pagenum;
	pgcnt_t curpage;
	pgcnt_t npages;
	pgcnt_t done;
	bz_stream strm;
	dumpcsize_t sc;
	dumpstreamhdr_t sh;
} stream_t;

static stream_t *streams;
static stream_t *endstreams;

const int cs = sizeof (dumpcsize_t);

typedef struct tinfo {
	pthread_t tid;
	int corefd;
} tinfo_t;

static int threads_stop;
static int threads_active;
static tinfo_t *tinfo;
static tinfo_t *endtinfo;

static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t cvfree = PTHREAD_COND_INITIALIZER;
static pthread_cond_t cvwork = PTHREAD_COND_INITIALIZER;
static pthread_cond_t cvbarrier = PTHREAD_COND_INITIALIZER;

static blockhdr_t freeblocks;

static void
enqt(blockhdr_t *h, block_t *b)
{
	b->next = NULL;
	if (h->tail == NULL)
		h->head = b;
	else
		h->tail->next = b;
	h->tail = b;
}

static block_t *
deqh(blockhdr_t *h)
{
	block_t *b = h->head;

	if (b != NULL) {
		h->head = b->next;
		if (h->head == NULL)
			h->tail = NULL;
	}
	return (b);
}

static void *runstreams(void *arg);

static void
initstreams(int corefd, int nstreams, int maxcsize)
{
	int nthreads;
	int nblocks;
	int i;
	block_t *b;
	tinfo_t *t;

	nthreads = sysconf(_SC_NPROCESSORS_ONLN);
	if (nstreams < nthreads)
		nthreads = nstreams;
	if (nthreads < 1)
		nthreads = 1;
	nblocks = nthreads * 2;

	tinfo = Zalloc(nthreads * sizeof (tinfo_t));
	endtinfo = &tinfo[nthreads];

	/* init streams */
	streams = Zalloc(nstreams * sizeof (stream_t));
	endstreams = &streams[nstreams];

	/* init stream block buffers */
	for (i = 0; i < nblocks; i++) {
		b = Zalloc(sizeof (block_t));
		b->block = Zalloc(maxcsize);
		enqt(&freeblocks, b);
	}

	/* init worker threads */
	pthread_mutex_lock(&lock);
	threads_active = 1;
	threads_stop = 0;
	for (t = tinfo; t != endtinfo; t++) {
		t->corefd = dup(corefd);
		if (t->corefd < 0) {
			nthreads = t - tinfo;
			endtinfo = t;
			break;
		}
		if (pthread_create(&t->tid, NULL, runstreams, t) != 0)
			logprint(LOG_ERR, 1, 1, "pthread_create: %s",
			    strerror(errno));
	}
	pthread_mutex_unlock(&lock);
}

static void
sbarrier()
{
	stream_t *s;

	pthread_mutex_lock(&lock);
	for (s = streams; s != endstreams; s++) {
		while (s->bound || s->blocks.head != NULL)
			pthread_cond_wait(&cvbarrier, &lock);
	}
	pthread_mutex_unlock(&lock);
}

static void
stopstreams()
{
	tinfo_t *t;

	if (threads_active) {
		sbarrier();
		pthread_mutex_lock(&lock);
		threads_stop = 1;
		pthread_cond_signal(&cvwork);
		pthread_mutex_unlock(&lock);
		for (t = tinfo; t != endtinfo; t++)
			pthread_join(t->tid, NULL);
		free(tinfo);
		tinfo = NULL;
		threads_active = 0;
	}
}

static block_t *
getfreeblock()
{
	block_t *b;

	pthread_mutex_lock(&lock);
	while ((b = deqh(&freeblocks)) == NULL)
		pthread_cond_wait(&cvfree, &lock);
	pthread_mutex_unlock(&lock);
	return (b);
}

/* data page offset from page number */
#define	BTOP(b)		((b) >> dumphdr.dump_pageshift)
#define	PTOB(p)		((p) << dumphdr.dump_pageshift)
#define	DATAOFF(p)	(corehdr.dump_data + PTOB(p))

/* check for coreblksize boundary */
static int
isblkbnd(pgcnt_t pgnum)
{
	return (P2PHASE(DATAOFF(pgnum), coreblksize) == 0);
}

static int
iszpage(char *buf)
{
	size_t sz;
	uint64_t *pl;

	pl = (uint64_t *)(buf);
	for (sz = 0; sz < pagesize; sz += sizeof (*pl))
		if (*pl++ != 0)
			return (0);
	return (1);
}

volatile uint_t *hist;

/* write pages to the core file */
static void
putpage(int corefd, char *buf, pgcnt_t pgnum, pgcnt_t np)
{
	atomic_inc_uint(&hist[np]);
	if (np > 0)
		Pwrite(corefd, buf, PTOB(np), DATAOFF(pgnum));
}

/*
 * Process one lzjb block.
 * No object (stream header or page) will be split over a block boundary.
 */
static void
lzjbblock(int corefd, stream_t *s, char *block, size_t blocksz)
{
	int rc = 0;
	int in = 0;
	int csize;
	int doflush;
	char *out;
	size_t dsize;
	dumpcsize_t sc;
	dumpstreamhdr_t sh;

	if (!s->init) {
		s->init = 1;
		if (s->blkbuf == NULL)
			s->blkbuf = Zalloc(coreblksize);
		s->state = STREAMSTART;
	}
	while (in < blocksz) {
		switch (s->state) {
		case STREAMSTART:
			memcpy(&sh, block + in, sizeof (sh));
			in += sizeof (sh);
			if (strcmp(DUMP_STREAM_MAGIC, sh.stream_magic) != 0)
				logprint(LOG_ERR, 1, 1,
				    "LZJB STREAMSTART: bad stream header");
			if (sh.stream_npages > datahdr.dump_maxrange)
				logprint(LOG_ERR, 1, 1,
				    "LZJB STREAMSTART: bad range: %d > %d",
				    sh.stream_npages, datahdr.dump_maxrange);
			s->pagenum = sh.stream_pagenum;
			s->npages = sh.stream_npages;
			s->curpage = s->pagenum;
			s->nout = 0;
			s->done = 0;
			s->state = STREAMPAGES;
			break;
		case STREAMPAGES:
			memcpy(&sc, block + in, cs);
			in += cs;
			csize = DUMP_GET_CSIZE(sc);
			if (csize > pagesize)
				logprint(LOG_ERR, 1, 1,
				    "LZJB STREAMPAGES: bad csize=%d", csize);

			out =  s->blkbuf + PTOB(s->nout);
			dsize = decompress(block + in, out, csize, pagesize);

			if (dsize != pagesize)
				logprint(LOG_ERR, 1, 1,
				    "LZJB STREAMPAGES: dsize %d != pagesize %d",
				    dsize, pagesize);

			in += csize;
			atomic_inc_64(&saved);

			doflush = 0;
			if (s->nout == 0 && iszpage(out)) {
				doflush = 1;
				atomic_inc_64(&zpages);
			} else if (++s->nout >= BTOP(coreblksize) ||
			    isblkbnd(s->curpage + s->nout)) {
				doflush = 1;
			}
			if (++s->done >= s->npages) {
				s->state = STREAMSTART;
				doflush = 1;
			}
			if (doflush) {
				putpage(corefd, s->blkbuf, s->curpage, s->nout);
				s->nout = 0;
				s->curpage = s->pagenum + s->done;
			}
			break;
		}
	}
}

/* bzlib library reports errors with this callback */
void
bz_internal_error(int errcode)
{
	logprint(LOG_ERR, 1, 1, "bz_internal_error: err %s\n",
	    BZ2_bzErrorString(errcode));
}

/*
 * Return one object in the stream.
 *
 * An object (stream header or page) will likely span an input block
 * of compression data. Return non-zero when an entire object has been
 * retrieved from the stream.
 */
static int
bz2decompress(stream_t *s, void *buf, size_t size)
{
	int rc;

	if (s->strm.avail_out == 0) {
		s->strm.next_out = buf;
		s->strm.avail_out = size;
	}
	while (s->strm.avail_in > 0) {
		rc = BZ2_bzDecompress(&s->strm);
		if (rc == BZ_STREAM_END) {
			rc = BZ2_bzDecompressReset(&s->strm);
			if (rc != BZ_OK)
				logprint(LOG_ERR, 1, 1,
				    "BZ2_bzDecompressReset: %s",
				    BZ2_bzErrorString(rc));
			continue;
		}

		if (s->strm.avail_out == 0)
			break;
	}
	return (s->strm.avail_out == 0);
}

/*
 * Process one bzip2 block.
 * The interface is documented here:
 * http://www.bzip.org/1.0.5/bzip2-manual-1.0.5.html
 */
static void
bz2block(int corefd, stream_t *s, char *block, size_t blocksz)
{
	int rc = 0;
	int doflush;
	char *out;

	if (!s->init) {
		s->init = 1;
		rc = BZ2_bzDecompressInit(&s->strm, 0, 0);
		if (rc != BZ_OK)
			logprint(LOG_ERR, 1, 1,
			    "BZ2_bzDecompressInit: %s", BZ2_bzErrorString(rc));
		if (s->blkbuf == NULL)
			s->blkbuf = Zalloc(coreblksize);
		s->strm.avail_out = 0;
		s->state = STREAMSTART;
	}
	s->strm.next_in = block;
	s->strm.avail_in = blocksz;

	while (s->strm.avail_in > 0) {
		switch (s->state) {
		case STREAMSTART:
			if (!bz2decompress(s, &s->sh, sizeof (s->sh)))
				return;
			if (strcmp(DUMP_STREAM_MAGIC, s->sh.stream_magic) != 0)
				logprint(LOG_ERR, 1, 1,
				    "BZ2 STREAMSTART: bad stream header");
			if (s->sh.stream_npages > datahdr.dump_maxrange)
				logprint(LOG_ERR, 1, 1,
				    "BZ2 STREAMSTART: bad range: %d > %d",
				    s->sh.stream_npages, datahdr.dump_maxrange);
			s->pagenum = s->sh.stream_pagenum;
			s->npages = s->sh.stream_npages;
			s->curpage = s->pagenum;
			s->nout = 0;
			s->done = 0;
			s->state = STREAMPAGES;
			break;
		case STREAMPAGES:
			out = s->blkbuf + PTOB(s->nout);
			if (!bz2decompress(s, out, pagesize))
				return;

			atomic_inc_64(&saved);

			doflush = 0;
			if (s->nout == 0 && iszpage(out)) {
				doflush = 1;
				atomic_inc_64(&zpages);
			} else if (++s->nout >= BTOP(coreblksize) ||
			    isblkbnd(s->curpage + s->nout)) {
				doflush = 1;
			}
			if (++s->done >= s->npages) {
				s->state = STREAMSTART;
				doflush = 1;
			}
			if (doflush) {
				putpage(corefd, s->blkbuf, s->curpage, s->nout);
				s->nout = 0;
				s->curpage = s->pagenum + s->done;
			}
			break;
		}
	}
}

/* report progress */
static void
report_progress()
{
	int sec, percent;

	if (!interactive)
		return;

	percent = saved * 100LL / corehdr.dump_npages;
	if (percent > percent_done) {
		sec = (gethrtime() - startts) / 1000 / 1000 / 1000;
		(void) printf("\r%2d:%02d %3d%% done", sec / 60, sec % 60,
		    percent);
		(void) fflush(stdout);
		percent_done = percent;
	}
}

/* thread body */
static void *
runstreams(void *arg)
{
	tinfo_t *t = arg;
	stream_t *s;
	block_t *b;
	int bound;

	pthread_mutex_lock(&lock);
	while (!threads_stop) {
		bound = 0;
		for (s = streams; s != endstreams; s++) {
			if (s->bound || s->blocks.head == NULL)
				continue;
			s->bound = 1;
			bound = 1;
			pthread_cond_signal(&cvwork);
			while (s->blocks.head != NULL) {
				b = deqh(&s->blocks);
				pthread_mutex_unlock(&lock);

				if (datahdr.dump_clevel < DUMP_CLEVEL_BZIP2)
					lzjbblock(t->corefd, s, b->block,
					    b->size);
				else
					bz2block(t->corefd, s, b->block,
					    b->size);

				pthread_mutex_lock(&lock);
				enqt(&freeblocks, b);
				pthread_cond_signal(&cvfree);

				report_progress();
			}
			s->bound = 0;
			pthread_cond_signal(&cvbarrier);
		}
		if (!bound && !threads_stop)
			pthread_cond_wait(&cvwork, &lock);
	}
	close(t->corefd);
	pthread_cond_signal(&cvwork);
	pthread_mutex_unlock(&lock);
	return (arg);
}

/*
 * Process compressed pages.
 *
 * The old format, now called single-threaded lzjb, is a 32-bit size
 * word followed by 'size' bytes of lzjb compression data for one
 * page. The new format extends this by storing a 12-bit "tag" in the
 * upper bits of the size word. When the size word is pagesize or
 * less, it is assumed to be one lzjb page. When the size word is
 * greater than pagesize, it is assumed to be a "stream block",
 * belonging to up to 4095 streams. In practice, the number of streams
 * is set to one less than the number of CPUs running at crash
 * time. One CPU processes the crash dump, the remaining CPUs
 * separately process groups of data pages.
 *
 * savecore creates a thread per stream, but never more threads than
 * the number of CPUs running savecore. This is because savecore can
 * be processing a crash file from a remote machine, which may have
 * more CPUs.
 *
 * When the kernel uses parallel lzjb or parallel bzip2, we expect a
 * series of 128KB blocks of compression data. In this case, each
 * block has a "tag", in the range 1-4095. Each block is handed off to
 * to the threads running "runstreams". The dump format is either lzjb
 * or bzip2, never a mixture. These threads, in turn, process the
 * compression data for groups of pages. Groups of pages are delimited
 * by a "stream header", which indicates a starting pfn and number of
 * pages. When a stream block has been read, the condition variable
 * "cvwork" is signalled, which causes one of the avaiable threads to
 * wake up and process the stream.
 *
 * In the parallel case there will be streams blocks encoding all data
 * pages. The stream of blocks is terminated by a zero size
 * word. There can be a few lzjb pages tacked on the end, depending on
 * the architecture. The sbarrier function ensures that all stream
 * blocks have been processed so that the page number for the few
 * single pages at the end can be known.
 */
static void
decompress_pages(int corefd)
{
	char *cpage = NULL;
	char *dpage = NULL;
	char *out;
	pgcnt_t curpage;
	block_t *b;
	FILE *dumpf;
	FILE *tracef = NULL;
	stream_t *s;
	size_t dsize;
	size_t insz = FBUFSIZE;
	char *inbuf = Zalloc(insz);
	uint32_t csize;
	dumpcsize_t dcsize;
	dumpstreamhdr_t sh;
	int nstreams = datahdr.dump_nstreams;
	int maxcsize = datahdr.dump_maxcsize;
	int nout, tag, doflush;

	dumpf = fdopen(dup(dumpfd), "rb");
	if (dumpf == NULL)
		logprint(LOG_ERR, 1, 1, "fdopen: %s", strerror(errno));

	setvbuf(dumpf, inbuf, _IOFBF, insz);
	Fseek(dumphdr.dump_data, dumpf);

	while (1) {

		/*
		 * The csize word delimits stream blocks.
		 * See dumphdr.h for a description.
		 */
		Fread(&dcsize, sizeof (dcsize), dumpf);

		tag = DUMP_GET_TAG(dcsize);
		csize = DUMP_GET_CSIZE(dcsize);

		if (tag != 0) {		/* a stream block */

			if (nstreams == 0)
				logprint(LOG_ERR, 1, 1,
				    "starting data header is missing");

			if (tag > nstreams)
				logprint(LOG_ERR, 1, 1,
				    "stream tag %d not in range 1..%d",
				    tag, nstreams);

			if (csize > maxcsize)
				logprint(LOG_ERR, 1, 1,
				    "block size 0x%x > max csize 0x%x",
				    csize, maxcsize);

			if (streams == NULL)
				initstreams(corefd, nstreams, maxcsize);
			s = &streams[tag - 1];
			s->tag = tag;

			b = getfreeblock();
			b->size = csize;
			Fread(b->block, csize, dumpf);

			pthread_mutex_lock(&lock);
			enqt(&s->blocks, b);
			if (!s->bound)
				pthread_cond_signal(&cvwork);
			pthread_mutex_unlock(&lock);

		} else if (csize > 0) {		/* one lzjb page */

			if (csize > pagesize)
				logprint(LOG_ERR, 1, 1,
				    "csize 0x%x > pagesize 0x%x",
				    csize, pagesize);

			if (cpage == NULL)
				cpage = Zalloc(pagesize);
			if (dpage == NULL) {
				dpage = Zalloc(coreblksize);
				nout = 0;
			}

			Fread(cpage, csize, dumpf);

			out = dpage + PTOB(nout);
			dsize = decompress(cpage, out, csize, pagesize);

			if (dsize != pagesize)
				logprint(LOG_ERR, 1, 1,
				    "dsize 0x%x != pagesize 0x%x",
				    dsize, pagesize);

			/*
			 * wait for streams to flush so that 'saved' is correct
			 */
			if (threads_active)
				sbarrier();

			doflush = 0;
			if (nout == 0)
				curpage = saved;

			atomic_inc_64(&saved);

			if (nout == 0 && iszpage(dpage)) {
				doflush = 1;
				atomic_inc_64(&zpages);
			} else if (++nout >= BTOP(coreblksize) ||
			    isblkbnd(curpage + nout) ||
			    saved >= dumphdr.dump_npages) {
				doflush = 1;
			}

			if (doflush) {
				putpage(corefd, dpage, curpage, nout);
				nout = 0;
			}

			report_progress();

			/*
			 * Non-streams lzjb does not use blocks.  Stop
			 * here if all the pages have been decompressed.
			 */
			if (saved >= dumphdr.dump_npages)
				break;

		} else {
			break;			/* end of data */
		}
	}

	stopstreams();
	if (tracef != NULL)
		fclose(tracef);
	fclose(dumpf);
	if (inbuf)
		free(inbuf);
	if (cpage)
		free(cpage);
	if (dpage)
		free(dpage);
	if (streams)
		free(streams);
}

static void
build_corefile(const char *namelist, const char *corefile)
{
	size_t pfn_table_size = dumphdr.dump_npages * sizeof (pfn_t);
	size_t ksyms_size = dumphdr.dump_ksyms_size;
	size_t ksyms_csize = dumphdr.dump_ksyms_csize;
	pfn_t *pfn_table;
	char *ksyms_base = Zalloc(ksyms_size);
	char *ksyms_cbase = Zalloc(ksyms_csize);
	size_t ksyms_dsize;
	Stat_t st;
	int corefd = Open(corefile, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	int namefd = Open(namelist, O_WRONLY | O_CREAT | O_TRUNC, 0644);

	(void) printf("Constructing namelist %s/%s\n", savedir, namelist);

	/*
	 * Determine the optimum write size for the core file
	 */
	Fstat(corefd, &st, corefile);

	if (verbose > 1)
		printf("%s: %ld block size\n", corefile, st.st_blksize);
	coreblksize = st.st_blksize;
	if (coreblksize < MINCOREBLKSIZE || !ISP2(coreblksize))
		coreblksize = MINCOREBLKSIZE;

	hist = Zalloc((sizeof (uint64_t) * BTOP(coreblksize)) + 1);

	/*
	 * This dump file is now uncompressed
	 */
	corehdr.dump_flags &= ~DF_COMPRESSED;

	/*
	 * Read in the compressed symbol table, copy it to corefile,
	 * decompress it, and write the result to namelist.
	 */
	corehdr.dump_ksyms = pagesize;
	Pread(dumpfd, ksyms_cbase, ksyms_csize, dumphdr.dump_ksyms);
	Pwrite(corefd, ksyms_cbase, ksyms_csize, corehdr.dump_ksyms);

	ksyms_dsize = decompress(ksyms_cbase, ksyms_base, ksyms_csize,
	    ksyms_size);
	if (ksyms_dsize != ksyms_size)
		logprint(LOG_WARNING, 1, -1,
		    "bad data in symbol table, %lu of %lu bytes saved",
		    ksyms_dsize, ksyms_size);

	Pwrite(namefd, ksyms_base, ksyms_size, 0);
	(void) close(namefd);
	free(ksyms_cbase);
	free(ksyms_base);

	(void) printf("Constructing corefile %s/%s\n", savedir, corefile);

	/*
	 * Read in and write out the pfn table.
	 */
	pfn_table = Zalloc(pfn_table_size);
	corehdr.dump_pfn = corehdr.dump_ksyms + roundup(ksyms_size, pagesize);
	Pread(dumpfd, pfn_table, pfn_table_size, dumphdr.dump_pfn);
	Pwrite(corefd, pfn_table, pfn_table_size, corehdr.dump_pfn);

	/*
	 * Convert the raw translation data into a hashed dump map.
	 */
	corehdr.dump_map = corehdr.dump_pfn + roundup(pfn_table_size, pagesize);
	build_dump_map(corefd, pfn_table);
	free(pfn_table);

	/*
	 * Decompress the pages
	 */
	decompress_pages(corefd);
	(void) printf(": %ld of %ld pages saved\n", (pgcnt_t)saved,
	    dumphdr.dump_npages);

	if (verbose)
		(void) printf("%ld (%ld%%) zero pages were not written\n",
		    (pgcnt_t)zpages, (pgcnt_t)zpages * 100 /
		    dumphdr.dump_npages);

	if (saved != dumphdr.dump_npages)
		logprint(LOG_WARNING, 1, -1, "bad data after page %ld", saved);

	/*
	 * Write out the modified dump headers.
	 */
	Pwrite(corefd, &corehdr, sizeof (corehdr), 0);
	if (!filemode)
		Pwrite(dumpfd, &dumphdr, sizeof (dumphdr), endoff);

	(void) close(corefd);
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
			logprint(LOG_ERR, verbose, 0, "bad magic %x",
			    ld.ld_magic);

		if (dat.len >= DUMP_LOGSIZE)
			logprint(LOG_ERR, verbose, 0, "bad size %d",
			    ld.ld_msgsize);

		Pread(dumpfd, ctl.buf, ctl.len, dumpoff);
		dumpoff += ctl.len;

		if (ld.ld_csum != checksum32(ctl.buf, ctl.len))
			logprint(LOG_ERR, verbose, 0, "bad log_ctl checksum");

		lc.flags |= SL_LOGONLY;

		Pread(dumpfd, dat.buf, dat.len, dumpoff);
		dumpoff += dat.len;

		if (ld.ld_msum != checksum32(dat.buf, dat.len))
			logprint(LOG_ERR, verbose, 0, "bad message checksum");

		if (putpmsg(logfd, &ctl, &dat, 1, MSG_BAND) == -1)
			logprint(LOG_ERR, 1, 1, "putpmsg: %s", strerror(errno));

		ld.ld_magic = 0;	/* clear magic so we never save twice */
		Pwrite(dumpfd, &ld, sizeof (log_dump_t), ldoff);
	}
	return (0);
}

static long
getbounds(const char *f)
{
	long b = -1;
	const char *p = strrchr(f, '/');

	sscanf(p ? p + 1 : f, "vmdump.%ld", &b);
	return (b);
}

int
main(int argc, char *argv[])
{
	int i, n, c, bfd;
	int mflag = 0;
	Stat_t st;
	struct rlimit rl;
	long filebounds = -1;
	char namelist[30], corefile[30], boundstr[30], metricsname[PATH_MAX];

	startts = gethrtime();

	getrlimit(RLIMIT_NOFILE, &rl);
	rl.rlim_cur = rl.rlim_max;
	setrlimit(RLIMIT_NOFILE, &rl);

	openlog(progname, LOG_ODELAY, LOG_AUTH);

	(void) defopen("/etc/dumpadm.conf");
	savedir = strdup(defread("DUMPADM_SAVDIR="));
	sprintf(metricsname, "%s/%s", savedir, METRICSFILE);

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
			filebounds = getbounds(dumpfile);
			break;
		case '?':
			usage();
		}
	}

	interactive = isatty(STDOUT_FILENO);

	if (dumpfile == NULL || livedump)
		dumpfd = Open("/dev/dump", O_RDONLY, 0444);

	if (dumpfile == NULL) {
		dumpfile = Zalloc(MAXPATHLEN);
		if (ioctl(dumpfd, DIOCGETDEV, dumpfile) == -1)
			logprint(-1, interactive, 1,
			    "no dump device configured");
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
	dumpfd = -1;

	Stat(dumpfile, &st);

	filemode = S_ISREG(st.st_mode);

	if (!filemode && defread("DUMPADM_CSAVE=off") == NULL)
		csave = 1;

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

	logprint(LOG_WARNING, 1, -1, "System dump time: %s",
	    ctime(&dumphdr.dump_crashtime));

	check_space(csave);

	if (filebounds < 0)
		bounds = read_number_from_file("bounds", 0);
	else
		bounds = filebounds;

	if (csave) {
		size_t metrics_size = datahdr.dump_metrics;

		(void) sprintf(corefile, "vmdump.%ld", bounds);

		datahdr.dump_metrics = 0;

		logprint(LOG_ERR, 1, -1,
		    "Saving compressed system crash dump in %s/%s",
		    savedir, corefile);

		copy_crashfile(corefile);

		if (metrics_size > 0) {
			int sec = (gethrtime() - startts) / 1000 / 1000 / 1000;
			FILE *mfile = fopen(metricsname, "a");
			char *metrics = Zalloc(metrics_size + 1);

			Pread(dumpfd, metrics, metrics_size, endoff +
			    sizeof (dumphdr) + sizeof (datahdr));

			if (mfile == NULL) {
				logprint(LOG_WARNING, 1, -1,
				    "Can't create %s:\n%s",
				    metricsname, metrics);
			} else {
				fprintf(mfile, "[[[[,,,");
				for (i = 0; i < argc; i++)
					fprintf(mfile, "%s ", argv[i]);
				fprintf(mfile, "\n");
				fprintf(mfile, ",,,%s %s %s %s %s\n",
				    dumphdr.dump_utsname.sysname,
				    dumphdr.dump_utsname.nodename,
				    dumphdr.dump_utsname.release,
				    dumphdr.dump_utsname.version,
				    dumphdr.dump_utsname.machine);
				fprintf(mfile, ",,,%s dump time %s\n",
				    dumphdr.dump_flags & DF_LIVE ? "Live" :
				    "Crash", ctime(&dumphdr.dump_crashtime));
				fprintf(mfile, ",,,%s/%s\n", savedir, corefile);
				fprintf(mfile, "Metrics:\n%s\n", metrics);
				fprintf(mfile, "Copy pages,%ld\n", dumphdr.
				    dump_npages);
				fprintf(mfile, "Copy time,%d\n", sec);
				fprintf(mfile, "Copy pages/sec,%ld\n",
				    dumphdr.dump_npages / sec);
				fprintf(mfile, "]]]]\n");
				fclose(mfile);
			}
			free(metrics);
		}

		logprint(LOG_ERR, 1, -1,
		    "Decompress the crash dump with "
		    "\n'savecore -vf %s/%s'",
		    savedir, corefile);

	} else {
		(void) sprintf(namelist, "unix.%ld", bounds);
		(void) sprintf(corefile, "vmcore.%ld", bounds);

		if (interactive && filebounds >= 0 && access(corefile, F_OK)
		    == 0)
			logprint(-1, 1, 1,
			    "%s already exists: remove with "
			    "'rm -f %s/{unix,vmcore}.%ld'",
			    corefile, savedir, bounds);

		logprint(LOG_ERR, 1, -1,
		    "saving system crash dump in %s/{unix,vmcore}.%ld",
		    savedir, bounds);

		build_corefile(namelist, corefile);

		if (access(metricsname, F_OK) == 0) {
			int sec = (gethrtime() - startts) / 1000 / 1000 / 1000;
			FILE *mfile = fopen(metricsname, "a");

			fprintf(mfile, "[[[[,,,");
			for (i = 0; i < argc; i++)
				fprintf(mfile, "%s ", argv[i]);
			fprintf(mfile, "\n");
			fprintf(mfile, ",,,%s/%s\n", savedir, corefile);
			fprintf(mfile, ",,,%s %s %s %s %s\n",
			    dumphdr.dump_utsname.sysname,
			    dumphdr.dump_utsname.nodename,
			    dumphdr.dump_utsname.release,
			    dumphdr.dump_utsname.version,
			    dumphdr.dump_utsname.machine);
			fprintf(mfile, "Uncompress pages,%ld\n", saved);
			fprintf(mfile, "Uncompress time,%d\n", sec);
			fprintf(mfile, "Uncompress pages/sec,%ld\n",
			    saved / sec);
			fprintf(mfile, "]]]]\n");
			fclose(mfile);
		}
	}

	if (filebounds < 0) {
		(void) sprintf(boundstr, "%ld\n", bounds + 1);
		bfd = Open("bounds", O_WRONLY | O_CREAT | O_TRUNC, 0644);
		Pwrite(bfd, boundstr, strlen(boundstr), 0);
		(void) close(bfd);
	}

	if (verbose) {
		int sec = (gethrtime() - startts) / 1000 / 1000 / 1000;

		printf("%d:%02d dump %s is done\n",
		    sec / 60, sec % 60,
		    csave ? "copy" : "decompress");
	}

	if (verbose > 1 && hist != NULL) {
		int i, nw;

		for (i = 1, nw = 0; i <= BTOP(coreblksize); ++i)
			nw += hist[i] * i;
		printf("pages count     %%\n");
		for (i = 0; i <= BTOP(coreblksize); ++i) {
			if (hist[i] == 0)
				continue;
			printf("%3d   %5u  %6.2f\n",
			    i, hist[i], 100.0 * hist[i] * i / nw);
		}
	}

	(void) close(dumpfd);
	dumpfd = -1;

	return (0);
}
