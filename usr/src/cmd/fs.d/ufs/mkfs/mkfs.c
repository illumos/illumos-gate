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
 * Copyright (c) 1988, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * University Copyright- Copyright (c) 1982, 1986, 1988
 * The Regents of the University of California
 * All Rights Reserved
 *
 * University Acknowledgment- Portions of this document are derived from
 * software developed by the University of California, Berkeley, and its
 * contributors.
 */

/*
 * The maximum supported file system size (in sectors) is the
 * number of frags that can be represented in an int32_t field
 * (INT_MAX) times the maximum number of sectors per frag.  Since
 * the maximum frag size is MAXBSIZE, the maximum number of sectors
 * per frag is MAXBSIZE/DEV_BSIZE.
 */
#define	FS_MAX	(((diskaddr_t)INT_MAX) * (MAXBSIZE/DEV_BSIZE))

/*
 * make file system for cylinder-group style file systems
 *
 * usage:
 *
 *    mkfs [-F FSType] [-V] [-G [-P]] [-M dirname] [-m] [options]
 *	[-o specific_options]  special size
 *	[nsect ntrack bsize fsize cpg	minfree	rps nbpi opt apc rotdelay
 *	  2     3      4     5     6	7	8   9	 10  11  12
 *	nrpos maxcontig mtb]
 *	13    14	15
 *
 *  where specific_options are:
 *	N - no create
 *	nsect - The number of sectors per track
 *	ntrack - The number of tracks per cylinder
 *	bsize - block size
 *	fragsize - fragment size
 *	cgsize - The number of disk cylinders per cylinder group.
 * 	free - minimum free space
 *	rps - rotational speed (rev/sec).
 *	nbpi - number of data bytes per allocated inode
 *	opt - optimization (space, time)
 *	apc - number of alternates
 *	gap - gap size
 *	nrpos - number of rotational positions
 *	maxcontig - maximum number of logical blocks that will be
 *		allocated contiguously before inserting rotational delay
 *	mtb - if "y", set up file system for eventual growth to over a
 *		a terabyte
 * -P Do not grow the file system, but print on stdout the maximal
 *    size in sectors to which the file system can be increased. The calculated
 *    size is limited by the value provided by the operand size.
 *
 * Note that -P is a project-private interface and together with -G intended
 * to be used only by the growfs script. It is therefore purposely not
 * documented in the man page.
 * The -P option is covered by PSARC case 2003/422.
 */

/*
 * The following constants set the defaults used for the number
 * of sectors/track (fs_nsect), and number of tracks/cyl (fs_ntrak).
 *
 *			NSECT		NTRAK
 *	72MB CDC	18		9
 *	30MB CDC	18		5
 *	720KB Diskette	9		2
 *
 * However the defaults will be different for disks larger than CHSLIMIT.
 */

#define	DFLNSECT	32
#define	DFLNTRAK	16

/*
 * The following default sectors and tracks values are used for
 * non-efi disks that are larger than the CHS addressing limit. The
 * existing default cpg of 16 (DESCPG) holds good for larger disks too.
 */
#define	DEF_SECTORS_EFI	128
#define	DEF_TRACKS_EFI	48

/*
 * The maximum number of cylinders in a group depends upon how much
 * information can be stored on a single cylinder. The default is to
 * use 16 cylinders per group.  This is effectively tradition - it was
 * the largest value acceptable under SunOs 4.1
 */
#define	DESCPG		16	/* desired fs_cpg */

/*
 * The following two constants set the default block and fragment sizes.
 * Both constants must be a power of 2 and meet the following constraints:
 *	MINBSIZE <= DESBLKSIZE <= MAXBSIZE
 *	DEV_BSIZE <= DESFRAGSIZE <= DESBLKSIZE
 *	DESBLKSIZE / DESFRAGSIZE <= 8
 */
#define	DESBLKSIZE	8192
#define	DESFRAGSIZE	1024

/*
 * MINFREE gives the minimum acceptable percentage of file system
 * blocks which may be free. If the freelist drops below this level
 * only the superuser may continue to allocate blocks. This may
 * be set to 0 if no reserve of free blocks is deemed necessary,
 * however throughput drops by fifty percent if the file system
 * is run at between 90% and 100% full; thus the default value of
 * fs_minfree is 10%. With 10% free space, fragmentation is not a
 * problem, so we choose to optimize for time.
 */
#define	MINFREE		10
#define	DEFAULTOPT	FS_OPTTIME

/*
 * ROTDELAY gives the minimum number of milliseconds to initiate
 * another disk transfer on the same cylinder. It is no longer used
 * and will always default to 0.
 */
#define	ROTDELAY	0

/*
 * MAXBLKPG determines the maximum number of data blocks which are
 * placed in a single cylinder group. The default is one indirect
 * block worth of data blocks.
 */
#define	MAXBLKPG(bsize)	((bsize) / sizeof (daddr32_t))

/*
 * Each file system has a number of inodes statically allocated.
 * We allocate one inode slot per NBPI bytes, expecting this
 * to be far more than we will ever need.
 */
#define	NBPI		2048	/* Number Bytes Per Inode */
#define	MTB_NBPI	(MB)	/* Number Bytes Per Inode for multi-terabyte */

/*
 * Disks are assumed to rotate at 60HZ, unless otherwise specified.
 */
#define	DEFHZ		60

/*
 * Cylinder group related limits.
 *
 * For each cylinder we keep track of the availability of blocks at different
 * rotational positions, so that we can lay out the data to be picked
 * up with minimum rotational latency.  NRPOS is the number of rotational
 * positions which we distinguish.  With NRPOS 8 the resolution of our
 * summary information is 2ms for a typical 3600 rpm drive.
 */
#define	NRPOS		8	/* number distinct rotational positions */

#ifdef DEBUG
#define	dprintf(x)	printf x
#else
#define	dprintf(x)
#endif

/*
 * For the -N option, when calculating the backup superblocks, do not print
 * them if we are not really sure. We may have to try an alternate method of
 * arriving at the superblocks. So defer printing till a handful of superblocks
 * look good.
 */
#define	tprintf(x)	if (Nflag && retry) \
				(void) strncat(tmpbuf, x, strlen(x)); \
			else \
				(void) fprintf(stderr, x);

#define	ALTSB		32	/* Location of first backup superblock */

/*
 * range_check "user_supplied" flag values.
 */
#define	RC_DEFAULT	0
#define	RC_KEYWORD	1
#define	RC_POSITIONAL	2

/*
 * ufs hole
 */
#define	UFS_HOLE	-1

#ifndef	STANDALONE
#include	<stdio.h>
#include	<sys/mnttab.h>
#endif

#include	<stdlib.h>
#include	<unistd.h>
#include	<malloc.h>
#include	<string.h>
#include	<strings.h>
#include	<ctype.h>
#include	<errno.h>
#include	<sys/param.h>
#include	<time.h>
#include	<sys/types.h>
#include	<sys/sysmacros.h>
#include	<sys/vnode.h>
#include	<sys/fs/ufs_fsdir.h>
#include	<sys/fs/ufs_inode.h>
#include	<sys/fs/ufs_fs.h>
#include	<sys/fs/ufs_log.h>
#include	<sys/mntent.h>
#include	<sys/filio.h>
#include	<limits.h>
#include	<sys/int_const.h>
#include	<signal.h>
#include	<sys/efi_partition.h>
#include	"roll_log.h"

#define	bcopy(f, t, n)    (void) memcpy(t, f, n)
#define	bzero(s, n)	(void) memset(s, 0, n)
#define	bcmp(s, d, n)	memcmp(s, d, n)

#define	index(s, r)	strchr(s, r)
#define	rindex(s, r)	strrchr(s, r)

#include	<sys/stat.h>
#include	<sys/statvfs.h>
#include	<locale.h>
#include	<fcntl.h>
#include 	<sys/isa_defs.h>	/* for ENDIAN defines */
#include	<sys/vtoc.h>

#include	<sys/dkio.h>
#include	<sys/asynch.h>

extern offset_t	llseek();
extern char	*getfullblkname();
extern long	lrand48();

extern int	optind;
extern char	*optarg;


/*
 * The size of a cylinder group is calculated by CGSIZE. The maximum size
 * is limited by the fact that cylinder groups are at most one block.
 * Its size is derived from the size of the maps maintained in the
 * cylinder group and the (struct cg) size.
 */
#define	CGSIZE(fs) \
	/* base cg		*/ (sizeof (struct cg) + \
	/* blktot size	*/ (fs)->fs_cpg * sizeof (long) + \
	/* blks size	*/ (fs)->fs_cpg * (fs)->fs_nrpos * sizeof (short) + \
	/* inode map	*/ howmany((fs)->fs_ipg, NBBY) + \
	/* block map */ howmany((fs)->fs_cpg * (fs)->fs_spc / NSPF(fs), NBBY))

/*
 * We limit the size of the inode map to be no more than a
 * third of the cylinder group space, since we must leave at
 * least an equal amount of space for the block map.
 *
 * N.B.: MAXIpG must be a multiple of INOPB(fs).
 */
#define	MAXIpG(fs)	roundup((fs)->fs_bsize * NBBY / 3, INOPB(fs))

/*
 * Same as MAXIpG, but parameterized by the block size (b) and the
 * cylinder group divisor (d), which is the reciprocal of the fraction of the
 * cylinder group overhead block that is used for the inode map.  So for
 * example, if d = 5, the macro's computation assumes that 1/5 of the
 * cylinder group overhead block can be dedicated to the inode map.
 */
#define	MAXIpG_B(b, d)	roundup((b) * NBBY / (d), (b) / sizeof (struct dinode))

#define	UMASK		0755
#define	MAXINOPB	(MAXBSIZE / sizeof (struct dinode))
#define	POWEROF2(num)	(((num) & ((num) - 1)) == 0)
#define	MB		(1024*1024)
#define	BETWEEN(x, l, h)	((x) >= (l) && (x) <= (h))

/*
 * Used to set the inode generation number. Since both inodes and dinodes
 * are dealt with, we really need a pointer to an icommon here.
 */
#define	IRANDOMIZE(icp)	(icp)->ic_gen = lrand48();

/*
 * Flags for number()
 */
#define	ALLOW_PERCENT	0x01	/* allow trailing `%' on number */
#define	ALLOW_MS1	0x02	/* allow trailing `ms', state 1 */
#define	ALLOW_MS2	0x04	/* allow trailing `ms', state 2 */
#define	ALLOW_END_ONLY	0x08	/* must be at end of number & suffixes */

#define	MAXAIO	1000	/* maximum number of outstanding I/O's we'll manage */
#define	BLOCK	1	/* block in aiowait */
#define	NOBLOCK	0	/* don't block in aiowait */

#define	RELEASE 1	/* free an aio buffer after use */
#define	SAVE	0	/* don't free the buffer */

typedef struct aio_trans {
	aio_result_t resultbuf;
	diskaddr_t bno;
	char *buffer;
	int size;
	int release;
	struct aio_trans *next;
} aio_trans;

typedef struct aio_results {
	int max;
	int outstanding;
	int maxpend;
	aio_trans *trans;
} aio_results;

int aio_inited = 0;
aio_results results;

/*
 * Allow up to MAXBUF aio requests that each have a unique buffer.
 * More aio's might be done, but not using memory through the getbuf()
 * interface.  This can be raised, but you run into the potential of
 * using more memory than is physically available on the machine,
 * and if you start swapping, you can forget about performance.
 * To prevent this, we also limit the total memory used for a given
 * type of buffer to MAXBUFMEM.
 *
 * Tests indicate a cylinder group's worth of inodes takes:
 *
 *	NBPI	Size of Inode Buffer
 *	 2k	1688k
 *	 8k	 424k
 *
 * initcg() stores all the inodes for a cylinder group in one buffer,
 * so allowing 20 buffers could take 32 MB if not limited by MAXBUFMEM.
 */
#define	MAXBUF		20
#define	MAXBUFMEM	(8 * 1024 * 1024)

/*
 * header information for buffers managed by getbuf() and freebuf()
 */
typedef struct bufhdr {
	struct bufhdr *head;
	struct bufhdr *next;
} bufhdr;

int bufhdrsize;

bufhdr inodebuf = { NULL, NULL };
bufhdr cgsumbuf = { NULL, NULL };

#define	SECTORS_PER_TERABYTE	(1LL << 31)
/*
 * The following constant specifies an upper limit for file system size
 * that is actually a lot bigger than we expect to support with UFS. (Since
 * it's specified in sectors, the file system size would be 2**44 * 512,
 * which is 2**53, which is 8192 Terabytes.)  However, it's useful
 * for checking the basic sanity of a size value that is input on the
 * command line.
 */
#define	FS_SIZE_UPPER_LIMIT	0x100000000000LL

/*
 * Forward declarations
 */
static char *getbuf(bufhdr *bufhead, int size);
static void freebuf(char *buf);
static void freetrans(aio_trans *transp);
static aio_trans *get_aiop();
static aio_trans *wait_for_write(int block);
static void initcg(int cylno);
static void fsinit();
static int makedir(struct direct *protodir, int entries);
static void iput(struct inode *ip);
static void rdfs(diskaddr_t bno, int size, char *bf);
static void wtfs(diskaddr_t bno, int size, char *bf);
static void awtfs(diskaddr_t bno, int size, char *bf, int release);
static void wtfs_breakup(diskaddr_t bno, int size, char *bf);
static int isblock(struct fs *fs, unsigned char *cp, int h);
static void clrblock(struct fs *fs, unsigned char *cp, int h);
static void setblock(struct fs *fs, unsigned char *cp, int h);
static void usage();
static void dump_fscmd(char *fsys, int fsi);
static uint64_t number(uint64_t d_value, char *param, int flags);
static int match(char *s);
static char checkopt(char *optim);
static char checkmtb(char *mtbarg);
static void range_check(long *varp, char *name, long minimum,
    long maximum, long def_val, int user_supplied);
static void range_check_64(uint64_t *varp, char *name, uint64_t minimum,
    uint64_t maximum, uint64_t def_val, int user_supplied);
static daddr32_t alloc(int size, int mode);
static diskaddr_t get_max_size(int fd);
static long get_max_track_size(int fd);
static void block_sigint(sigset_t *old_mask);
static void unblock_sigint(sigset_t *old_mask);
static void recover_from_sigint(int signum);
static int confirm_abort(void);
static int getaline(FILE *fp, char *loc, int maxlen);
static void flush_writes(void);
static long compute_maxcpg(long, long, long, long, long);
static int in_64bit_mode(void);
static int validate_size(int fd, diskaddr_t size);
static void dump_sblock(void);

/*
 * Workaround for mkfs to function properly on disks attached to XMIT 2.X
 * controller. If the address is not aligned at 8 byte boundary, mkfs on
 * disks attached to XMIT 2.X controller exhibts un-predictable behaviour.
 */
#define	XMIT_2_X_ALIGN	8
#pragma	align XMIT_2_X_ALIGN(fsun, altfsun, cgun)

union {
	struct fs fs;
	char pad[SBSIZE];
} fsun, altfsun;
#define	sblock	fsun.fs
#define	altsblock	altfsun.fs

struct	csum *fscs;

union cgun {
	struct cg cg;
	char pad[MAXBSIZE];
} cgun;

#define	acg	cgun.cg
/*
 * Size of screen in cols in which to fit output
 */
#define	WIDTH	80

struct dinode zino[MAXBSIZE / sizeof (struct dinode)];

/*
 * file descriptors used for rdfs(fsi) and wtfs(fso).
 * Initialized to an illegal file descriptor number.
 */
int	fsi = -1;
int	fso = -1;

/*
 * The BIG parameter is machine dependent.  It should be a longlong integer
 * constant that can be used by the number parser to check the validity
 * of numeric parameters.
 */

#define	BIG		0x7fffffffffffffffLL

/* Used to indicate to number() that a bogus value should cause us to exit */
#define	NO_DEFAULT	LONG_MIN

/*
 * INVALIDSBLIMIT is the number of bad backup superblocks that will be
 * tolerated before we decide to try arriving at a different set of them
 * using a different logic. This is applicable for non-EFI disks only.
 */
#define	INVALIDSBLIMIT	10

/*
 * The *_flag variables are used to indicate that the user specified
 * the values, rather than that we made them up ourselves.  We can
 * complain about the user giving us bogus values.
 */

/* semi-constants */
long	sectorsize = DEV_BSIZE;		/* bytes/sector from param.h */
long	bbsize = BBSIZE;		/* boot block size */
long	sbsize = SBSIZE;		/* superblock size */

/* parameters */
diskaddr_t	fssize_db;		/* file system size in disk blocks */
diskaddr_t	fssize_frag;		/* file system size in frags */
long	cpg;				/* cylinders/cylinder group */
int	cpg_flag = RC_DEFAULT;
long	rotdelay = -1;			/* rotational delay between blocks */
int	rotdelay_flag = RC_DEFAULT;
long	maxcontig;			/* max contiguous blocks to allocate */
int	maxcontig_flag = RC_DEFAULT;
long	nsect = DFLNSECT;		/* sectors per track */
int	nsect_flag = RC_DEFAULT;
long	ntrack = DFLNTRAK;		/* tracks per cylinder group */
int	ntrack_flag = RC_DEFAULT;
long	bsize = DESBLKSIZE;		/* filesystem block size */
int	bsize_flag = RC_DEFAULT;
long	fragsize = DESFRAGSIZE; 	/* filesystem fragment size */
int	fragsize_flag = RC_DEFAULT;
long	minfree = MINFREE; 		/* fs_minfree */
int	minfree_flag = RC_DEFAULT;
long	rps = DEFHZ;			/* revolutions/second of drive */
int	rps_flag = RC_DEFAULT;
long	nbpi = NBPI;			/* number of bytes per inode */
int	nbpi_flag = RC_DEFAULT;
long	nrpos = NRPOS;			/* number of rotational positions */
int	nrpos_flag = RC_DEFAULT;
long	apc = 0;			/* alternate sectors per cylinder */
int	apc_flag = RC_DEFAULT;
char	opt = 't';			/* optimization style, `t' or `s' */
char	mtb = 'n';			/* multi-terabyte format, 'y' or 'n' */
#define	DEFAULT_SECT_TRAK_CPG	(nsect_flag == RC_DEFAULT && \
				ntrack_flag == RC_DEFAULT && \
				cpg_flag == RC_DEFAULT)

long	debug = 0;			/* enable debugging output */

int	spc_flag = 0;			/* alternate sectors specified or */
					/* found */

/* global state */
int	Nflag;		/* do not write to disk */
int	mflag;		/* return the command line used to create this FS */
int	rflag;		/* report the superblock in an easily-parsed form */
int	Rflag;		/* dump the superblock in binary */
char	*fsys;
time_t	mkfstime;
char	*string;
int	label_type;

/*
 * logging support
 */
int	islog;			/* true if ufs logging is enabled */
int	islogok;		/* true if ufs log state is good */
int	waslog;			/* true when ufs logging disabled during grow */

/*
 * growfs defines, globals, and forward references
 */
#define	NOTENOUGHSPACE 33
int		grow;
#define	GROW_WITH_DEFAULT_TRAK	(grow && ntrack_flag == RC_DEFAULT)

static int	Pflag;		/* probe to which size the fs can be grown */
int		ismounted;
char		*directory;
diskaddr_t	grow_fssize;
long		grow_fs_size;
long		grow_fs_ncg;
diskaddr_t		grow_fs_csaddr;
long		grow_fs_cssize;
int		grow_fs_clean;
struct csum	*grow_fscs;
diskaddr_t		grow_sifrag;
int		test;
int		testforce;
diskaddr_t		testfrags;
int		inlockexit;
int		isbad;

void		lockexit(int);
void		randomgeneration(void);
void		checksummarysize(void);
int		checksblock(struct fs, int);
void		growinit(char *);
void		checkdev(char *, char  *);
void		checkmount(struct mnttab *, char *);
struct dinode	*gdinode(ino_t);
int		csfraginrange(daddr32_t);
struct csfrag	*findcsfrag(daddr32_t, struct csfrag **);
void		checkindirect(ino_t, daddr32_t *, daddr32_t, int);
void		addcsfrag(ino_t, daddr32_t, struct csfrag **);
void		delcsfrag(daddr32_t, struct csfrag **);
void		checkdirect(ino_t, daddr32_t *, daddr32_t *, int);
void		findcsfragino(void);
void		fixindirect(daddr32_t, int);
void		fixdirect(caddr_t, daddr32_t, daddr32_t *, int);
void		fixcsfragino(void);
void		extendsummaryinfo(void);
int		notenoughspace(void);
void		unalloccsfragino(void);
void		unalloccsfragfree(void);
void		findcsfragfree(void);
void		copycsfragino(void);
void		rdcg(long);
void		wtcg(void);
void		flcg(void);
void		allocfrags(long, daddr32_t *, long *);
void		alloccsfragino(void);
void		alloccsfragfree(void);
void		freefrags(daddr32_t, long, long);
int		findfreerange(long *, long *);
void		resetallocinfo(void);
void		extendcg(long);
void		ulockfs(void);
void		wlockfs(void);
void		clockfs(void);
void		wtsb(void);
static int64_t	checkfragallocated(daddr32_t);
static struct csum 	*read_summaryinfo(struct fs *);
static diskaddr_t 	probe_summaryinfo();

int
main(int argc, char *argv[])
{
	long i, mincpc, mincpg, ibpcl;
	long cylno, rpos, blk, j, warn = 0;
	long mincpgcnt, maxcpg;
	uint64_t used, bpcg, inospercg;
	long mapcramped, inodecramped;
	long postblsize, rotblsize, totalsbsize;
	FILE *mnttab;
	struct mnttab mntp;
	char *special;
	struct statvfs64 fs;
	struct dk_geom dkg;
	struct dk_minfo dkminfo;
	char pbuf[sizeof (uint64_t) * 3 + 1];
	char *tmpbuf;
	int width, plen;
	uint64_t num;
	int c, saverr;
	diskaddr_t max_fssize;
	long tmpmaxcontig = -1;
	struct sigaction sigact;
	uint64_t nbytes64;
	int remaining_cg;
	int do_dot = 0;
	int use_efi_dflts = 0, retry = 0, isremovable = 0, ishotpluggable = 0;
	int invalid_sb_cnt, ret, skip_this_sb, cg_too_small;
	int geom_nsect, geom_ntrack, geom_cpg;

	(void) setlocale(LC_ALL, "");

#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN "SYS_TEST"
#endif
	(void) textdomain(TEXT_DOMAIN);

	while ((c = getopt(argc, argv, "F:bmo:VPGM:T:t:")) != EOF) {
		switch (c) {

		case 'F':
			string = optarg;
			if (strcmp(string, "ufs") != 0)
				usage();
			break;

		case 'm':	/* return command line used to create this FS */
			mflag++;
			break;

		case 'o':
			/*
			 * ufs specific options.
			 */
			string = optarg;
			while (*string != '\0') {
				if (match("nsect=")) {
					nsect = number(DFLNSECT, "nsect", 0);
					nsect_flag = RC_KEYWORD;
				} else if (match("ntrack=")) {
					ntrack = number(DFLNTRAK, "ntrack", 0);
					ntrack_flag = RC_KEYWORD;
				} else if (match("bsize=")) {
					bsize = number(DESBLKSIZE, "bsize", 0);
					bsize_flag = RC_KEYWORD;
				} else if (match("fragsize=")) {
					fragsize = number(DESFRAGSIZE,
					    "fragsize", 0);
					fragsize_flag = RC_KEYWORD;
				} else if (match("cgsize=")) {
					cpg = number(DESCPG, "cgsize", 0);
					cpg_flag = RC_KEYWORD;
				} else if (match("free=")) {
					minfree = number(MINFREE, "free",
					    ALLOW_PERCENT);
					minfree_flag = RC_KEYWORD;
				} else if (match("maxcontig=")) {
					tmpmaxcontig =
					    number(-1, "maxcontig", 0);
					maxcontig_flag = RC_KEYWORD;
				} else if (match("nrpos=")) {
					nrpos = number(NRPOS, "nrpos", 0);
					nrpos_flag = RC_KEYWORD;
				} else if (match("rps=")) {
					rps = number(DEFHZ, "rps", 0);
					rps_flag = RC_KEYWORD;
				} else if (match("nbpi=")) {
					nbpi = number(NBPI, "nbpi", 0);
					nbpi_flag = RC_KEYWORD;
				} else if (match("opt=")) {
					opt = checkopt(string);
				} else if (match("mtb=")) {
					mtb = checkmtb(string);
				} else if (match("apc=")) {
					apc = number(0, "apc", 0);
					apc_flag = RC_KEYWORD;
				} else if (match("gap=")) {
					(void) number(0, "gap", ALLOW_MS1);
					rotdelay = ROTDELAY;
					rotdelay_flag = RC_DEFAULT;
				} else if (match("debug=")) {
					debug = number(0, "debug", 0);
				} else if (match("N")) {
					Nflag++;
				} else if (match("calcsb")) {
					rflag++;
					Nflag++;
				} else if (match("calcbinsb")) {
					rflag++;
					Rflag++;
					Nflag++;
				} else if (*string == '\0') {
					break;
				} else {
					(void) fprintf(stderr, gettext(
					    "illegal option: %s\n"), string);
					usage();
				}

				if (*string == ',') string++;
				if (*string == ' ') string++;
			}
			break;

		case 'V':
			{
				char	*opt_text;
				int	opt_count;

				(void) fprintf(stdout, gettext("mkfs -F ufs "));
				for (opt_count = 1; opt_count < argc;
				    opt_count++) {
					opt_text = argv[opt_count];
					if (opt_text)
						(void) fprintf(stdout, " %s ",
						    opt_text);
				}
				(void) fprintf(stdout, "\n");
			}
			break;

		case 'b':	/* do nothing for this */
			break;

		case 'M':	/* grow the mounted file system */
			directory = optarg;

			/* FALLTHROUGH */
		case 'G':	/* grow the file system */
			grow = 1;
			break;
		case 'P':	/* probe the file system growing size 	*/
			Pflag = 1;
			grow = 1; /* probe mode implies fs growing	*/
			break;
		case 'T':	/* For testing */
			testforce = 1;

			/* FALLTHROUGH */
		case 't':
			test = 1;
			string = optarg;
			testfrags = number(NO_DEFAULT, "testfrags", 0);
			break;

		case '?':
			usage();
			break;
		}
	}
#ifdef MKFS_DEBUG
	/*
	 * Turning on MKFS_DEBUG causes mkfs to produce a filesystem
	 * that can be reproduced by setting the time to 0 and seeding
	 * the random number generator to a constant.
	 */
	mkfstime = 0;	/* reproducible results */
#else
	(void) time(&mkfstime);
#endif

	if (optind >= (argc - 1)) {
		if (optind > (argc - 1)) {
			(void) fprintf(stderr,
			    gettext("special not specified\n"));
			usage();
		} else if (mflag == 0) {
			(void) fprintf(stderr,
			    gettext("size not specified\n"));
			usage();
		}
	}
	argc -= optind;
	argv = &argv[optind];

	fsys = argv[0];
	fsi = open64(fsys, O_RDONLY);
	if (fsi < 0) {
		(void) fprintf(stderr, gettext("%s: cannot open\n"), fsys);
		lockexit(32);
	}

	if (mflag) {
		dump_fscmd(fsys, fsi);
		lockexit(0);
	}

	/*
	 * The task of setting all of the configuration parameters for a
	 * UFS file system is basically a matter of solving n equations
	 * in m variables.  Typically, m is greater than n, so there is
	 * usually more than one valid solution.  Since this is usually
	 * an under-constrained problem, it's not always obvious what the
	 * "best" configuration is.
	 *
	 * In general, the approach is to
	 * 1. Determine the values for the file system parameters
	 *    that are externally contrained and therefore not adjustable
	 *    by mkfs (such as the device's size and maxtransfer size).
	 * 2. Acquire the user's requested setting for all configuration
	 *    values that can be set on the command line.
	 * 3. Determine the final value of all configuration values, by
	 *    the following approach:
	 *	- set the file system block size (fs_bsize).  Although
	 *	  this could be regarded as an adjustable parameter, in
	 *	  fact, it's pretty much a constant.  At this time, it's
	 *	  generally set to 8k (with older hardware, it can
	 *	  sometimes make sense to set it to 4k, but those
	 *	  situations are pretty rare now).
	 *	- re-adjust the maximum file system size based on the
	 *	  value of the file system block size.  Since the
	 *	  frag size can't be any larger than a file system
	 *	  block, and the number of frags in the file system
	 *	  has to fit into 31 bits, the file system block size
	 *	  affects the maximum file system size.
	 *	- now that the real maximum file system is known, set the
	 *	  actual size of the file system to be created to
	 *	  MIN(requested size, maximum file system size).
	 *	- now validate, and if necessary, adjust the following
	 *	  values:
	 *		rotdelay
	 *		nsect
	 *		maxcontig
	 *		apc
	 *		frag_size
	 *		rps
	 *		minfree
	 *		nrpos
	 *		nrack
	 *		nbpi
	 *	- calculate maxcpg (the maximum value of the cylinders-per-
	 *	  cylinder-group configuration parameters).  There are two
	 *	  algorithms for calculating maxcpg:  an old one, which is
	 *	  used for file systems of less than 1 terabyte, and a
	 *	  new one, implemented in the function compute_maxcpg(),
	 *	  which is used for file systems of greater than 1 TB.
	 *	  The difference between them is that compute_maxcpg()
	 *	  really tries to maximize the cpg value.  The old
	 *	  algorithm fails to take advantage of smaller frags and
	 *	  lower inode density when determining the maximum cpg,
	 *	  and thus comes up with much lower numbers in some
	 *	  configurations.  At some point, we might use the
	 *	  new algorithm for determining maxcpg for all file
	 *	  systems, but at this time, the changes implemented for
	 *	  multi-terabyte UFS are NOT being automatically applied
	 *	  to UFS file systems of less than a terabyte (in the
	 *	  interest of not changing existing UFS policy too much
	 *	  until the ramifications of the changes are well-understood
	 *	  and have been evaluated for their effects on performance.)
	 *	- check the current values of the configuration parameters
	 *	  against the various constraints imposed by UFS.  These
	 *	  include:
	 *		* There must be at least one inode in each
	 *		  cylinder group.
	 *		* The cylinder group overhead block, which
	 *		  contains the inode and frag bigmaps, must fit
	 *		  within one file system block.
	 *		* The space required for inode maps should
	 *		  occupy no more than a third of the cylinder
	 *		  group overhead block.
	 *		* The rotational position tables have to fit
	 *		  within the available space in the super block.
	 *	  Adjust the configuration values that can be adjusted
	 *	  so that these constraints are satisfied.  The
	 *	  configuration values that are adjustable are:
	 *		* frag size
	 *		* cylinders per group
	 *		* inode density (can be increased)
	 *		* number of rotational positions (the rotational
	 *		  position tables are eliminated altogether if
	 *		  there isn't enough room for them.)
	 * 4. Set the values for all the dependent configuration
	 *    values (those that aren't settable on the command
	 *    line and which are completely dependent on the
	 *    adjustable parameters).  This include cpc (cycles
	 *    per cylinder, spc (sectors-per-cylinder), and many others.
	 */

	/*
	 * Figure out the partition size and initialize the label_type.
	 */
	max_fssize = get_max_size(fsi);

	/*
	 * Get and check positional arguments, if any.
	 */
	switch (argc - 1) {
	default:
		usage();
		/*NOTREACHED*/
	case 15:
		mtb = checkmtb(argv[15]);
		/* FALLTHROUGH */
	case 14:
		string = argv[14];
		tmpmaxcontig = number(-1, "maxcontig", 0);
		maxcontig_flag = RC_POSITIONAL;
		/* FALLTHROUGH */
	case 13:
		string = argv[13];
		nrpos = number(NRPOS, "nrpos", 0);
		nrpos_flag = RC_POSITIONAL;
		/* FALLTHROUGH */
	case 12:
		string = argv[12];
		rotdelay = ROTDELAY;
		rotdelay_flag = RC_DEFAULT;
		/* FALLTHROUGH */
	case 11:
		string = argv[11];
		apc = number(0, "apc", 0);
		apc_flag = RC_POSITIONAL;
		/* FALLTHROUGH */
	case 10:
		opt = checkopt(argv[10]);
		/* FALLTHROUGH */
	case 9:
		string = argv[9];
		nbpi = number(NBPI, "nbpi", 0);
		nbpi_flag = RC_POSITIONAL;
		/* FALLTHROUGH */
	case 8:
		string = argv[8];
		rps = number(DEFHZ, "rps", 0);
		rps_flag = RC_POSITIONAL;
		/* FALLTHROUGH */
	case 7:
		string = argv[7];
		minfree = number(MINFREE, "free", ALLOW_PERCENT);
		minfree_flag = RC_POSITIONAL;
		/* FALLTHROUGH */
	case 6:
		string = argv[6];
		cpg = number(DESCPG, "cgsize", 0);
		cpg_flag = RC_POSITIONAL;
		/* FALLTHROUGH */
	case 5:
		string = argv[5];
		fragsize = number(DESFRAGSIZE, "fragsize", 0);
		fragsize_flag = RC_POSITIONAL;
		/* FALLTHROUGH */
	case 4:
		string = argv[4];
		bsize = number(DESBLKSIZE, "bsize", 0);
		bsize_flag = RC_POSITIONAL;
		/* FALLTHROUGH */
	case 3:
		string = argv[3];
		ntrack = number(DFLNTRAK, "ntrack", 0);
		ntrack_flag = RC_POSITIONAL;
		/* FALLTHROUGH */
	case 2:
		string = argv[2];
		nsect = number(DFLNSECT, "nsect", 0);
		nsect_flag = RC_POSITIONAL;
		/* FALLTHROUGH */
	case 1:
		string = argv[1];
		fssize_db = number(max_fssize, "size", 0);
	}

	/*
	 * Initialize the parameters in the same way as newfs so that
	 * newfs and mkfs would result in the same file system layout
	 * for EFI labelled disks. Do this only in the absence of user
	 * specified values for these parameters.
	 */
	if (label_type == LABEL_TYPE_EFI) {
		if (apc_flag == RC_DEFAULT) apc = 0;
		if (nrpos_flag == RC_DEFAULT) nrpos = 1;
		if (ntrack_flag == RC_DEFAULT) ntrack = DEF_TRACKS_EFI;
		if (rps_flag == RC_DEFAULT) rps = DEFHZ;
		if (nsect_flag == RC_DEFAULT) nsect = DEF_SECTORS_EFI;
	}

	if ((maxcontig_flag == RC_DEFAULT) || (tmpmaxcontig == -1) ||
	    (maxcontig == -1)) {
		long maxtrax = get_max_track_size(fsi);
		maxcontig = maxtrax / bsize;

	} else {
		maxcontig = tmpmaxcontig;
	}
	dprintf(("DeBuG maxcontig : %ld\n", maxcontig));

	if (rotdelay == -1) {	/* default by newfs and mkfs */
		rotdelay = ROTDELAY;
	}

	if (cpg_flag == RC_DEFAULT) { /* If not explicity set, use default */
		cpg = DESCPG;
	}
	dprintf(("DeBuG cpg : %ld\n", cpg));

	/*
	 * Now that we have the semi-sane args, either positional, via -o,
	 * or by defaulting, handle inter-dependencies and range checks.
	 */

	/*
	 * Settle the file system block size first, since it's a fixed
	 * parameter once set and so many other parameters, including
	 * max_fssize, depend on it.
	 */
	range_check(&bsize, "bsize", MINBSIZE, MAXBSIZE, DESBLKSIZE,
	    bsize_flag);

	if (!POWEROF2(bsize)) {
		(void) fprintf(stderr,
		    gettext("block size must be a power of 2, not %ld\n"),
		    bsize);
		bsize = DESBLKSIZE;
		(void) fprintf(stderr,
		    gettext("mkfs: bsize reset to default %ld\n"),
		    bsize);
	}

	if (fssize_db > max_fssize && validate_size(fsi, fssize_db)) {
		(void) fprintf(stderr, gettext(
		    "Warning: the requested size of this file system\n"
		    "(%lld sectors) is greater than the size of the\n"
		    "device reported by the driver (%lld sectors).\n"
		    "However, a read of the device at the requested size\n"
		    "does succeed, so the requested size will be used.\n"),
		    fssize_db, max_fssize);
		max_fssize = fssize_db;
	}
	/*
	 * Since the maximum allocatable unit (the frag) must be less than
	 * or equal to bsize, and the number of frags must be less than or
	 * equal to INT_MAX, the total size of the file system (in
	 * bytes) must be less than or equal to bsize * INT_MAX.
	 */

	if (max_fssize > ((diskaddr_t)bsize/DEV_BSIZE) * INT_MAX)
		max_fssize = ((diskaddr_t)bsize/DEV_BSIZE) * INT_MAX;

	range_check_64(&fssize_db, "size", 1024LL, max_fssize, max_fssize, 1);

	if (fssize_db >= SECTORS_PER_TERABYTE) {
		mtb = 'y';
		if (!in_64bit_mode()) {
			(void) fprintf(stderr, gettext(
"mkfs:  Warning: Creating a file system greater than 1 terabyte on a\n"
"       system running a 32-bit kernel.  This file system will not be\n"
"       accessible until the system is rebooted with a 64-bit kernel.\n"));
		}
	}
	dprintf(("DeBuG mtb : %c\n", mtb));

	/*
	 * With newer and much larger disks, the newfs(1M) and mkfs_ufs(1M)
	 * commands had problems in correctly handling the "native" geometries
	 * for various storage devices.
	 *
	 * To handle the new age disks, mkfs_ufs(1M) will use the EFI style
	 * for non-EFI disks that are larger than the CHS addressing limit
	 * ( > 8GB approx ) and ignore the disk geometry information for
	 * these drives. This is what is currently done for multi-terrabyte
	 * filesystems on EFI disks.
	 *
	 * However if the user asked for a specific layout by supplying values
	 * for even one of the three parameters (nsect, ntrack, cpg), honour
	 * the user supplied parameters.
	 *
	 * Choosing EFI style or native geometry style can make a lot of
	 * difference, because the size of a cylinder group is dependent on
	 * this choice. This in turn means that the position of alternate
	 * superblocks varies depending on the style chosen. It is not
	 * necessary that all disks of size > CHSLIMIT have EFI style layout.
	 * There can be disks which are > CHSLIMIT size, but have native
	 * geometry style layout, thereby warranting the need for alternate
	 * logic in superblock detection.
	 */
	if (mtb != 'y' && (ntrack == -1 || GROW_WITH_DEFAULT_TRAK ||
	    DEFAULT_SECT_TRAK_CPG)) {
		/*
		 * "-1" indicates that we were called from newfs and ntracks
		 * was not specified in newfs command line. Calculate nsect
		 * and ntrack in the same manner as newfs.
		 *
		 * This is required because, the defaults for nsect and ntrack
		 * is hardcoded in mkfs, whereas to generate the alternate
		 * superblock locations for the -N option, there is a need for
		 * the geometry based values that newfs would have arrived at.
		 * Newfs would have arrived at these values as below.
		 */
		if (label_type == LABEL_TYPE_EFI ||
		    label_type == LABEL_TYPE_OTHER) {
			use_efi_dflts = 1;
			retry = 1;
		} else if (ioctl(fsi, DKIOCGGEOM, &dkg)) {
			dprintf(("%s: Unable to read Disk geometry", fsys));
			perror(gettext("Unable to read Disk geometry"));
			lockexit(32);
		} else {
			nsect = dkg.dkg_nsect;
			ntrack = dkg.dkg_nhead;
#ifdef i386	/* Bug 1170182 */
			if (ntrack > 32 && (ntrack % 16) != 0) {
				ntrack -= (ntrack % 16);
			}
#endif
			if (ioctl(fsi, DKIOCREMOVABLE, &isremovable)) {
				dprintf(("DeBuG Unable to determine if %s is"
				    " Removable Media. Proceeding with system"
				    " determined parameters.\n", fsys));
				isremovable = 0;
			}
			if (ioctl(fsi, DKIOCHOTPLUGGABLE, &ishotpluggable)) {
				dprintf(("DeBuG Unable to determine if %s is"
				    " Hotpluggable Media. Proceeding with "
				    "system determined parameters.\n", fsys));
				ishotpluggable = 0;
			}
			if ((((diskaddr_t)dkg.dkg_ncyl * dkg.dkg_nhead *
			    dkg.dkg_nsect) > CHSLIMIT) || isremovable ||
			    ishotpluggable) {
				use_efi_dflts = 1;
				retry = 1;
			}
		}
	}
	dprintf(("DeBuG CHSLIMIT = %d geom = %llu\n", CHSLIMIT,
	    (diskaddr_t)dkg.dkg_ncyl * dkg.dkg_nhead * dkg.dkg_nsect));
	dprintf(("DeBuG label_type = %d isremovable = %d ishotpluggable = %d "
	    "use_efi_dflts = %d\n", label_type, isremovable, ishotpluggable,
	    use_efi_dflts));

	/*
	 * For the newfs -N case, even if the disksize is > CHSLIMIT, do not
	 * blindly follow EFI style. If the fs_version indicates a geometry
	 * based layout, try that one first. If it fails we can always try the
	 * other logic.
	 *
	 * If we were called from growfs, we will have a problem if we mix
	 * and match the filesystem creation and growth styles. For example,
	 * if we create using EFI style, we have to also grow using EFI
	 * style. So follow the style indicated by the fs_version.
	 *
	 * Read and verify the primary superblock. If it looks sane, use the
	 * fs_version from the superblock. If the primary superblock does
	 * not look good, read and verify the first alternate superblock at
	 * ALTSB. Use the fs_version to decide whether to use the
	 * EFI style logic or the old geometry based logic to calculate
	 * the alternate superblock locations.
	 */
	if ((Nflag && use_efi_dflts) || (grow)) {
		if (grow && ntrack_flag != RC_DEFAULT)
			goto start_fs_creation;
		rdfs((diskaddr_t)(SBOFF / sectorsize), (int)sbsize,
		    (char *)&altsblock);
		ret = checksblock(altsblock, 1);

		if (!ret) {
			if (altsblock.fs_magic == MTB_UFS_MAGIC) {
				mtb = 'y';
				goto start_fs_creation;
			}
			use_efi_dflts = (altsblock.fs_version ==
			    UFS_EFISTYLE4NONEFI_VERSION_2) ? 1 : 0;
		} else {
			/*
			 * The primary superblock didn't help in determining
			 * the fs_version. Try the first alternate superblock.
			 */
			dprintf(("DeBuG checksblock() failed - error : %d"
			    " for sb : %d\n", ret, SBOFF/sectorsize));
			rdfs((diskaddr_t)ALTSB, (int)sbsize,
			    (char *)&altsblock);
			ret = checksblock(altsblock, 1);

			if (!ret) {
				if (altsblock.fs_magic == MTB_UFS_MAGIC) {
					mtb = 'y';
					goto start_fs_creation;
				}
				use_efi_dflts = (altsblock.fs_version ==
				    UFS_EFISTYLE4NONEFI_VERSION_2) ? 1 : 0;
			}
			dprintf(("DeBuG checksblock() returned : %d"
			    " for sb : %d\n", ret, ALTSB));
		}
	}

	geom_nsect = nsect;
	geom_ntrack = ntrack;
	geom_cpg = cpg;
	dprintf(("DeBuG geom_nsect=%d, geom_ntrack=%d, geom_cpg=%d\n",
	    geom_nsect, geom_ntrack, geom_cpg));

start_fs_creation:
retry_alternate_logic:
	invalid_sb_cnt = 0;
	cg_too_small = 0;
	if (use_efi_dflts) {
		nsect = DEF_SECTORS_EFI;
		ntrack = DEF_TRACKS_EFI;
		cpg = DESCPG;
		dprintf(("\nDeBuG Using EFI defaults\n"));
	} else {
		nsect = geom_nsect;
		ntrack = geom_ntrack;
		cpg = geom_cpg;
		dprintf(("\nDeBuG Using Geometry\n"));
		/*
		 * 32K based on max block size of 64K, and rotational layout
		 * test of nsect <= (256 * sectors/block).  Current block size
		 * limit is not 64K, but it's growing soon.
		 */
		range_check(&nsect, "nsect", 1, 32768, DFLNSECT, nsect_flag);
		/*
		 * ntrack is the number of tracks per cylinder.
		 * The ntrack value must be between 1 and the total number of
		 * sectors in the file system.
		 */
		range_check(&ntrack, "ntrack", 1,
		    fssize_db > INT_MAX ? INT_MAX : (uint32_t)fssize_db,
		    DFLNTRAK, ntrack_flag);
	}

	range_check(&apc, "apc", 0, nsect - 1, 0, apc_flag);

	if (mtb == 'y')
		fragsize = bsize;

	range_check(&fragsize, "fragsize", sectorsize, bsize,
	    MAX(bsize / MAXFRAG, MIN(DESFRAGSIZE, bsize)), fragsize_flag);

	if ((bsize / MAXFRAG) > fragsize) {
		(void) fprintf(stderr, gettext(
"fragment size %ld is too small, minimum with block size %ld is %ld\n"),
		    fragsize, bsize, bsize / MAXFRAG);
		(void) fprintf(stderr,
		    gettext("mkfs: fragsize reset to minimum %ld\n"),
		    bsize / MAXFRAG);
		fragsize = bsize / MAXFRAG;
	}

	if (!POWEROF2(fragsize)) {
		(void) fprintf(stderr,
		    gettext("fragment size must be a power of 2, not %ld\n"),
		    fragsize);
		fragsize = MAX(bsize / MAXFRAG, MIN(DESFRAGSIZE, bsize));
		(void) fprintf(stderr,
		    gettext("mkfs: fragsize reset to %ld\n"),
		    fragsize);
	}

	/* At this point, bsize must be >= fragsize, so no need to check it */

	if (bsize < PAGESIZE) {
		(void) fprintf(stderr, gettext(
		    "WARNING: filesystem block size (%ld) is smaller than "
		    "memory page size (%ld).\nResulting filesystem can not be "
		    "mounted on this system.\n\n"),
		    bsize, (long)PAGESIZE);
	}

	range_check(&rps, "rps", 1, 1000, DEFHZ, rps_flag);
	range_check(&minfree, "free", 0, 99, MINFREE, minfree_flag);
	range_check(&nrpos, "nrpos", 1, nsect, MIN(nsect, NRPOS), nrpos_flag);

	/*
	 * nbpi is variable, but 2MB seems a reasonable upper limit,
	 * as 4MB tends to cause problems (using otherwise-default
	 * parameters).  The true limit is where we end up with one
	 * inode per cylinder group.  If this file system is being
	 * configured for multi-terabyte access, nbpi must be at least 1MB.
	 */
	if (mtb == 'y' && nbpi < MTB_NBPI) {
		if (nbpi_flag != RC_DEFAULT)
			(void) fprintf(stderr, gettext("mkfs: bad value for "
			    "nbpi: must be at least 1048576 for multi-terabyte,"
			    " nbpi reset to default 1048576\n"));
		nbpi = MTB_NBPI;
	}

	if (mtb == 'y')
		range_check(&nbpi, "nbpi", MTB_NBPI, 2 * MB, MTB_NBPI,
		    nbpi_flag);
	else
		range_check(&nbpi, "nbpi", DEV_BSIZE, 2 * MB, NBPI, nbpi_flag);

	/*
	 * maxcpg is another variably-limited parameter.  Calculate
	 * the limit based on what we've got for its dependent
	 * variables.  Effectively, it's how much space is left in the
	 * superblock after all the other bits are accounted for.  We
	 * only fill in sblock fields so we can use MAXIpG.
	 *
	 * If the calculation of maxcpg below (for the mtb == 'n'
	 * case) is changed, update newfs as well.
	 *
	 * For old-style, non-MTB format file systems, use the old
	 * algorithm for calculating the maximum cylinder group size,
	 * even though it limits the cylinder group more than necessary.
	 * Since layout can affect performance, we don't want to change
	 * the default layout for non-MTB file systems at this time.
	 * However, for MTB file systems, use the new maxcpg calculation,
	 * which really maxes out the cylinder group size.
	 */

	sblock.fs_bsize = bsize;
	sblock.fs_inopb = sblock.fs_bsize / sizeof (struct dinode);

	if (mtb == 'n') {
		maxcpg = (bsize - sizeof (struct cg) -
		    howmany(MAXIpG(&sblock), NBBY)) /
		    (sizeof (long) + nrpos * sizeof (short) +
		    nsect / (MAXFRAG * NBBY));
	} else {
		maxcpg = compute_maxcpg(bsize, fragsize, nbpi, nrpos,
		    nsect * ntrack);
	}

	dprintf(("DeBuG cpg : %ld\n", cpg));
	/*
	 * Increase the cpg to maxcpg if either newfs was invoked
	 * with -T option or if mkfs wants to create a mtb file system
	 * and if the user has not specified the cpg.
	 */
	if (cpg == -1 || (mtb == 'y' && cpg_flag == RC_DEFAULT))
		cpg = maxcpg;
	dprintf(("DeBuG cpg : %ld\n", cpg));

	/*
	 * mincpg is variable in complex ways, so we really can't
	 * do a sane lower-end limit check at this point.
	 */
	range_check(&cpg, "cgsize", 1, maxcpg, MIN(maxcpg, DESCPG), cpg_flag);

	/*
	 * get the controller info
	 */
	islog = 0;
	islogok = 0;
	waslog = 0;

	/*
	 * Do not grow the file system, but print on stdout the maximum
	 * size in sectors to which the file system can be increased.
	 * The calculated size is limited by fssize_db.
	 * Note that we don't lock the filesystem and therefore under rare
	 * conditions (the filesystem is mounted, the free block count is
	 * almost zero, and the superuser is still changing it) the calculated
	 * size can be imprecise.
	 */
	if (Pflag) {
		(void) printf("%llu\n", probe_summaryinfo());
		exit(0);
	}

	/*
	 * If we're growing an existing filesystem, then we're about
	 * to start doing things that can require recovery efforts if
	 * we get interrupted, so make sure we get a chance to do so.
	 */
	if (grow) {
		sigact.sa_handler = recover_from_sigint;
		sigemptyset(&sigact.sa_mask);
		sigact.sa_flags = SA_RESTART;

		if (sigaction(SIGINT, &sigact, (struct sigaction *)NULL) < 0) {
			perror(gettext("Could not register SIGINT handler"));
			lockexit(3);
		}
	}

	if (!Nflag) {
		/*
		 * Check if MNTTAB is trustable
		 */
		if (statvfs64(MNTTAB, &fs) < 0) {
			(void) fprintf(stderr, gettext("can't statvfs %s\n"),
			    MNTTAB);
			exit(32);
		}

		if (strcmp(MNTTYPE_MNTFS, fs.f_basetype) != 0) {
			(void) fprintf(stderr, gettext(
			    "%s file system type is not %s, can't mkfs\n"),
			    MNTTAB, MNTTYPE_MNTFS);
			exit(32);
		}

		special = getfullblkname(fsys);
		checkdev(fsys, special);

		/*
		 * If we found the block device name,
		 * then check the mount table.
		 * if mounted, and growing write lock the file system
		 *
		 */
		if ((special != NULL) && (*special != '\0')) {
			if ((mnttab = fopen(MNTTAB, "r")) == NULL) {
				(void) fprintf(stderr, gettext(
				    "can't open %s\n"), MNTTAB);
				exit(32);
			}
			while ((getmntent(mnttab, &mntp)) == NULL) {
				if (grow) {
					checkmount(&mntp, special);
					continue;
				}
				if (strcmp(special, mntp.mnt_special) == 0) {
					(void) fprintf(stderr, gettext(
					    "%s is mounted, can't mkfs\n"),
					    special);
					exit(32);
				}
			}
			(void) fclose(mnttab);
		}

		if (directory && (ismounted == 0)) {
			(void) fprintf(stderr, gettext("%s is not mounted\n"),
			    special);
			lockexit(32);
		}

		fso = (grow) ? open64(fsys, O_WRONLY) : creat64(fsys, 0666);
		if (fso < 0) {
			saverr = errno;
			(void) fprintf(stderr,
			    gettext("%s: cannot create: %s\n"),
			    fsys, strerror(saverr));
			lockexit(32);
		}

	} else {

		/*
		 * For the -N case, a file descriptor is needed for the llseek()
		 * in wtfs(). See the comment in wtfs() for more information.
		 *
		 * Get a file descriptor that's read-only so that this code
		 * doesn't accidentally write to the file.
		 */
		fso = open64(fsys, O_RDONLY);
		if (fso < 0) {
			saverr = errno;
			(void) fprintf(stderr, gettext("%s: cannot open: %s\n"),
			    fsys, strerror(saverr));
			lockexit(32);
		}
	}

	/*
	 * Check the media sector size
	 */
	if (ioctl(fso, DKIOCGMEDIAINFO, &dkminfo) != -1) {
		if (dkminfo.dki_lbsize != 0 &&
		    POWEROF2(dkminfo.dki_lbsize / DEV_BSIZE) &&
		    dkminfo.dki_lbsize != DEV_BSIZE) {
			fprintf(stderr,
			    gettext("The device sector size %u is not "
			    "supported by ufs!\n"), dkminfo.dki_lbsize);
			(void) close(fso);
			exit(1);
		}
	}

	/*
	 * seed random # generator (for ic_generation)
	 */
#ifdef MKFS_DEBUG
	srand48(12962);	/* reproducible results */
#else
	srand48((long)(time((time_t *)NULL) + getpid()));
#endif

	if (grow) {
		growinit(fsys);
		goto grow00;
	}

	/*
	 * Validate the given file system size.
	 * Verify that its last block can actually be accessed.
	 *
	 * Note: it's ok to use sblock as a buffer because it is immediately
	 * overwritten by the rdfs() of the superblock in the next line.
	 *
	 * ToDo: Because the size checking is done in rdfs()/wtfs(), the
	 * error message for specifying an illegal size is very unfriendly.
	 * In the future, one could replace the rdfs()/wtfs() calls
	 * below with in-line calls to read() or write(). This allows better
	 * error messages to be put in place.
	 */
	rdfs(fssize_db - 1, (int)sectorsize, (char *)&sblock);

	/*
	 * make the fs unmountable
	 */
	rdfs((diskaddr_t)(SBOFF / sectorsize), (int)sbsize, (char *)&sblock);
	sblock.fs_magic = -1;
	sblock.fs_clean = FSBAD;
	sblock.fs_state = FSOKAY - sblock.fs_time;
	wtfs((diskaddr_t)(SBOFF / sectorsize), (int)sbsize, (char *)&sblock);
	bzero(&sblock, (size_t)sbsize);

	sblock.fs_nsect = nsect;
	sblock.fs_ntrak = ntrack;

	/*
	 * Validate specified/determined spc
	 * and calculate minimum cylinders per group.
	 */

	/*
	 * sectors/cyl = tracks/cyl * sectors/track
	 */
	sblock.fs_spc = sblock.fs_ntrak * sblock.fs_nsect;

grow00:
	if (apc_flag) {
		sblock.fs_spc -= apc;
	}
	/*
	 * Have to test for this separately from apc_flag, due to
	 * the growfs case....
	 */
	if (sblock.fs_spc != sblock.fs_ntrak * sblock.fs_nsect) {
		spc_flag = 1;
	}
	if (grow)
		goto grow10;

	sblock.fs_nrpos = nrpos;
	sblock.fs_bsize = bsize;
	sblock.fs_fsize = fragsize;
	sblock.fs_minfree = minfree;

grow10:
	if (nbpi < sblock.fs_fsize) {
		(void) fprintf(stderr, gettext(
		"warning: wasteful data byte allocation / inode (nbpi):\n"));
		(void) fprintf(stderr, gettext(
		    "%ld smaller than allocatable fragment size of %d\n"),
		    nbpi, sblock.fs_fsize);
	}
	if (grow)
		goto grow20;

	if (opt == 's')
		sblock.fs_optim = FS_OPTSPACE;
	else
		sblock.fs_optim = FS_OPTTIME;

	sblock.fs_bmask = ~(sblock.fs_bsize - 1);
	sblock.fs_fmask = ~(sblock.fs_fsize - 1);
	/*
	 * Planning now for future expansion.
	 */
#if defined(_BIG_ENDIAN)
		sblock.fs_qbmask.val[0] = 0;
		sblock.fs_qbmask.val[1] = ~sblock.fs_bmask;
		sblock.fs_qfmask.val[0] = 0;
		sblock.fs_qfmask.val[1] = ~sblock.fs_fmask;
#endif
#if defined(_LITTLE_ENDIAN)
		sblock.fs_qbmask.val[0] = ~sblock.fs_bmask;
		sblock.fs_qbmask.val[1] = 0;
		sblock.fs_qfmask.val[0] = ~sblock.fs_fmask;
		sblock.fs_qfmask.val[1] = 0;
#endif
	for (sblock.fs_bshift = 0, i = sblock.fs_bsize; i > 1; i >>= 1)
		sblock.fs_bshift++;
	for (sblock.fs_fshift = 0, i = sblock.fs_fsize; i > 1; i >>= 1)
		sblock.fs_fshift++;
	sblock.fs_frag = numfrags(&sblock, sblock.fs_bsize);
	for (sblock.fs_fragshift = 0, i = sblock.fs_frag; i > 1; i >>= 1)
		sblock.fs_fragshift++;
	if (sblock.fs_frag > MAXFRAG) {
		(void) fprintf(stderr, gettext(
	"fragment size %d is too small, minimum with block size %d is %d\n"),
		    sblock.fs_fsize, sblock.fs_bsize,
		    sblock.fs_bsize / MAXFRAG);
		lockexit(32);
	}
	sblock.fs_nindir = sblock.fs_bsize / sizeof (daddr32_t);
	sblock.fs_inopb = sblock.fs_bsize / sizeof (struct dinode);
	sblock.fs_nspf = sblock.fs_fsize / sectorsize;
	for (sblock.fs_fsbtodb = 0, i = NSPF(&sblock); i > 1; i >>= 1)
		sblock.fs_fsbtodb++;

	/*
	 * Compute the super-block, cylinder group, and inode blocks.
	 * Note that these "blkno" are really fragment addresses.
	 * For example, on an 8K/1K (block/fragment) system, fs_sblkno is 16,
	 * fs_cblkno is 24, and fs_iblkno is 32. This is why CGSIZE is so
	 * important: only 1 FS block is allocated for the cg struct (fragment
	 * numbers 24 through 31).
	 */
	sblock.fs_sblkno =
	    roundup(howmany(bbsize + sbsize, sblock.fs_fsize), sblock.fs_frag);
	sblock.fs_cblkno = (daddr32_t)(sblock.fs_sblkno +
	    roundup(howmany(sbsize, sblock.fs_fsize), sblock.fs_frag));
	sblock.fs_iblkno = sblock.fs_cblkno + sblock.fs_frag;

	sblock.fs_cgoffset = roundup(
	    howmany(sblock.fs_nsect, NSPF(&sblock)), sblock.fs_frag);
	for (sblock.fs_cgmask = -1, i = sblock.fs_ntrak; i > 1; i >>= 1)
		sblock.fs_cgmask <<= 1;
	if (!POWEROF2(sblock.fs_ntrak))
		sblock.fs_cgmask <<= 1;
	/*
	 * Validate specified/determined spc
	 * and calculate minimum cylinders per group.
	 */

	for (sblock.fs_cpc = NSPB(&sblock), i = sblock.fs_spc;
	    sblock.fs_cpc > 1 && (i & 1) == 0;
	    sblock.fs_cpc >>= 1, i >>= 1)
		/* void */;
	mincpc = sblock.fs_cpc;

	/* if these calculations are changed, check dump_fscmd also */
	bpcg = (uint64_t)sblock.fs_spc * sectorsize;
	inospercg = (uint64_t)roundup(bpcg / sizeof (struct dinode),
	    INOPB(&sblock));
	if (inospercg > MAXIpG(&sblock))
		inospercg = MAXIpG(&sblock);
	used = (uint64_t)(sblock.fs_iblkno + inospercg /
	    INOPF(&sblock)) * NSPF(&sblock);
	mincpgcnt = (long)howmany((uint64_t)sblock.fs_cgoffset *
	    (~sblock.fs_cgmask) + used, sblock.fs_spc);
	mincpg = roundup(mincpgcnt, mincpc);
	/*
	 * Insure that cylinder group with mincpg has enough space
	 * for block maps
	 */
	sblock.fs_cpg = mincpg;
	sblock.fs_ipg = (int32_t)inospercg;
	mapcramped = 0;

	/*
	 * Make sure the cg struct fits within the file system block.
	 * Use larger block sizes until it fits
	 */
	while (CGSIZE(&sblock) > sblock.fs_bsize) {
		mapcramped = 1;
		if (sblock.fs_bsize < MAXBSIZE) {
			sblock.fs_bsize <<= 1;
			if ((i & 1) == 0) {
				i >>= 1;
			} else {
				sblock.fs_cpc <<= 1;
				mincpc <<= 1;
				mincpg = roundup(mincpgcnt, mincpc);
				sblock.fs_cpg = mincpg;
			}
			sblock.fs_frag <<= 1;
			sblock.fs_fragshift += 1;
			if (sblock.fs_frag <= MAXFRAG)
				continue;
		}

		/*
		 * Looped far enough. The fragment is now as large as the
		 * filesystem block!
		 */
		if (sblock.fs_fsize == sblock.fs_bsize) {
			(void) fprintf(stderr, gettext(
		    "There is no block size that can support this disk\n"));
			lockexit(32);
		}

		/*
		 * Try a larger fragment. Double the fragment size.
		 */
		sblock.fs_frag >>= 1;
		sblock.fs_fragshift -= 1;
		sblock.fs_fsize <<= 1;
		sblock.fs_nspf <<= 1;
	}
	/*
	 * Insure that cylinder group with mincpg has enough space for inodes
	 */
	inodecramped = 0;
	used *= sectorsize;
	nbytes64 = (uint64_t)mincpg * bpcg - used;
	inospercg = (uint64_t)roundup((nbytes64 / nbpi), INOPB(&sblock));
	sblock.fs_ipg = (int32_t)inospercg;
	while (inospercg > MAXIpG(&sblock)) {
		inodecramped = 1;
		if (mincpc == 1 || sblock.fs_frag == 1 ||
		    sblock.fs_bsize == MINBSIZE)
			break;
		nbytes64 = (uint64_t)mincpg * bpcg - used;
		(void) fprintf(stderr,
		    gettext("With a block size of %d %s %lu\n"),
		    sblock.fs_bsize, gettext("minimum bytes per inode is"),
		    (uint32_t)(nbytes64 / MAXIpG(&sblock) + 1));
		sblock.fs_bsize >>= 1;
		sblock.fs_frag >>= 1;
		sblock.fs_fragshift -= 1;
		mincpc >>= 1;
		sblock.fs_cpg = roundup(mincpgcnt, mincpc);
		if (CGSIZE(&sblock) > sblock.fs_bsize) {
			sblock.fs_bsize <<= 1;
			break;
		}
		mincpg = sblock.fs_cpg;
		nbytes64 = (uint64_t)mincpg * bpcg - used;
		inospercg = (uint64_t)roundup((nbytes64 / nbpi),
		    INOPB(&sblock));
		sblock.fs_ipg = (int32_t)inospercg;
	}
	if (inodecramped) {
		if (inospercg > MAXIpG(&sblock)) {
			nbytes64 = (uint64_t)mincpg * bpcg - used;
			(void) fprintf(stderr, gettext(
			    "Minimum bytes per inode is %d\n"),
			    (uint32_t)(nbytes64 / MAXIpG(&sblock) + 1));
		} else if (!mapcramped) {
			(void) fprintf(stderr, gettext(
	    "With %ld bytes per inode, minimum cylinders per group is %ld\n"),
			    nbpi, mincpg);
		}
	}
	if (mapcramped) {
		(void) fprintf(stderr, gettext(
		    "With %d sectors per cylinder, minimum cylinders "
		    "per group is %ld\n"),
		    sblock.fs_spc, mincpg);
	}
	if (inodecramped || mapcramped) {
		/*
		 * To make this at least somewhat comprehensible in
		 * the world of i18n, figure out what we're going to
		 * say and then say it all at one time.  The days of
		 * needing to scrimp on string space are behind us....
		 */
		if ((sblock.fs_bsize != bsize) &&
		    (sblock.fs_fsize != fragsize)) {
			(void) fprintf(stderr, gettext(
	    "This requires the block size to be changed from %ld to %d\n"
	    "and the fragment size to be changed from %ld to %d\n"),
			    bsize, sblock.fs_bsize,
			    fragsize, sblock.fs_fsize);
		} else if (sblock.fs_bsize != bsize) {
			(void) fprintf(stderr, gettext(
	    "This requires the block size to be changed from %ld to %d\n"),
			    bsize, sblock.fs_bsize);
		} else if (sblock.fs_fsize != fragsize) {
			(void) fprintf(stderr, gettext(
	    "This requires the fragment size to be changed from %ld to %d\n"),
			    fragsize, sblock.fs_fsize);
		} else {
			(void) fprintf(stderr, gettext(
	    "Unable to make filesystem fit with the given constraints\n"));
		}
		(void) fprintf(stderr, gettext(
		    "Please re-run mkfs with corrected parameters\n"));
		lockexit(32);
	}
	/*
	 * Calculate the number of cylinders per group
	 */
	sblock.fs_cpg = cpg;
	if (sblock.fs_cpg % mincpc != 0) {
		(void) fprintf(stderr, gettext(
		    "Warning: cylinder groups must have a multiple "
		    "of %ld cylinders with the given\n         parameters\n"),
		    mincpc);
		sblock.fs_cpg = roundup(sblock.fs_cpg, mincpc);
		(void) fprintf(stderr, gettext("Rounded cgsize up to %d\n"),
		    sblock.fs_cpg);
	}
	/*
	 * Must insure there is enough space for inodes
	 */
	/* if these calculations are changed, check dump_fscmd also */
	nbytes64 = (uint64_t)sblock.fs_cpg * bpcg - used;
	sblock.fs_ipg = roundup((uint32_t)(nbytes64 / nbpi), INOPB(&sblock));

	/*
	 * Slim down cylinders per group, until the inodes can fit.
	 */
	while (sblock.fs_ipg > MAXIpG(&sblock)) {
		inodecramped = 1;
		sblock.fs_cpg -= mincpc;
		nbytes64 = (uint64_t)sblock.fs_cpg * bpcg - used;
		sblock.fs_ipg = roundup((uint32_t)(nbytes64 / nbpi),
		    INOPB(&sblock));
	}
	/*
	 * Must insure there is enough space to hold block map.
	 * Cut down on cylinders per group, until the cg struct fits in a
	 * filesystem block.
	 */
	while (CGSIZE(&sblock) > sblock.fs_bsize) {
		mapcramped = 1;
		sblock.fs_cpg -= mincpc;
		nbytes64 = (uint64_t)sblock.fs_cpg * bpcg - used;
		sblock.fs_ipg = roundup((uint32_t)(nbytes64 / nbpi),
		    INOPB(&sblock));
	}
	sblock.fs_fpg = (sblock.fs_cpg * sblock.fs_spc) / NSPF(&sblock);
	if ((sblock.fs_cpg * sblock.fs_spc) % NSPB(&sblock) != 0) {
		(void) fprintf(stderr,
		gettext("newfs: panic (fs_cpg * fs_spc) %% NSPF != 0\n"));
		lockexit(32);
	}
	if (sblock.fs_cpg < mincpg) {
		(void) fprintf(stderr, gettext(
"With the given parameters, cgsize must be at least %ld; please re-run mkfs\n"),
		    mincpg);
		lockexit(32);
	}
	sblock.fs_cgsize = fragroundup(&sblock, CGSIZE(&sblock));
grow20:
	/*
	 * Now have size for file system and nsect and ntrak.
	 * Determine number of cylinders and blocks in the file system.
	 */
	fssize_frag = (int64_t)dbtofsb(&sblock, fssize_db);
	if (fssize_frag > INT_MAX) {
		(void) fprintf(stderr, gettext(
"There are too many fragments in the system, increase fragment size\n"),
		    mincpg);
		lockexit(32);
	}
	sblock.fs_size = (int32_t)fssize_frag;
	sblock.fs_ncyl = (int32_t)(fssize_frag * NSPF(&sblock) / sblock.fs_spc);
	if (fssize_frag * NSPF(&sblock) >
	    (uint64_t)sblock.fs_ncyl * sblock.fs_spc) {
		sblock.fs_ncyl++;
		warn = 1;
	}
	if (sblock.fs_ncyl < 1) {
		(void) fprintf(stderr, gettext(
		    "file systems must have at least one cylinder\n"));
		lockexit(32);
	}
	if (grow)
		goto grow30;
	/*
	 * Determine feasability/values of rotational layout tables.
	 *
	 * The size of the rotational layout tables is limited by the size
	 * of the file system block, fs_bsize.  The amount of space
	 * available for tables is calculated as (fs_bsize - sizeof (struct
	 * fs)).  The size of these tables is inversely proportional to the
	 * block size of the file system. The size increases if sectors per
	 * track are not powers of two, because more cylinders must be
	 * described by the tables before the rotational pattern repeats
	 * (fs_cpc).
	 */
	sblock.fs_postblformat = FS_DYNAMICPOSTBLFMT;
	sblock.fs_sbsize = fragroundup(&sblock, sizeof (struct fs));
	sblock.fs_npsect = sblock.fs_nsect;
	if (sblock.fs_ntrak == 1) {
		sblock.fs_cpc = 0;
		goto next;
	}
	postblsize = sblock.fs_nrpos * sblock.fs_cpc * sizeof (short);
	rotblsize = sblock.fs_cpc * sblock.fs_spc / NSPB(&sblock);
	totalsbsize = sizeof (struct fs) + rotblsize;

	/* do static allocation if nrpos == 8 and fs_cpc == 16  */
	if (sblock.fs_nrpos == 8 && sblock.fs_cpc <= 16) {
		/* use old static table space */
		sblock.fs_postbloff = (char *)(&sblock.fs_opostbl[0][0]) -
		    (char *)(&sblock.fs_link);
		sblock.fs_rotbloff = &sblock.fs_space[0] -
		    (uchar_t *)(&sblock.fs_link);
	} else {
		/* use 4.3 dynamic table space */
		sblock.fs_postbloff = &sblock.fs_space[0] -
		    (uchar_t *)(&sblock.fs_link);
		sblock.fs_rotbloff = sblock.fs_postbloff + postblsize;
		totalsbsize += postblsize;
	}
	if (totalsbsize > sblock.fs_bsize ||
	    sblock.fs_nsect > (1 << NBBY) * NSPB(&sblock)) {
		(void) fprintf(stderr, gettext(
		    "Warning: insufficient space in super block for\n"
		    "rotational layout tables with nsect %d, ntrack %d, "
		    "and nrpos %d.\nOmitting tables - file system "
		    "performance may be impaired.\n"),
		    sblock.fs_nsect, sblock.fs_ntrak, sblock.fs_nrpos);

		/*
		 * Setting fs_cpc to 0 tells alloccgblk() in ufs_alloc.c to
		 * ignore the positional layout table and rotational
		 * position table.
		 */
		sblock.fs_cpc = 0;
		goto next;
	}
	sblock.fs_sbsize = fragroundup(&sblock, totalsbsize);


	/*
	 * calculate the available blocks for each rotational position
	 */
	for (cylno = 0; cylno < sblock.fs_cpc; cylno++)
		for (rpos = 0; rpos < sblock.fs_nrpos; rpos++)
			fs_postbl(&sblock, cylno)[rpos] = -1;
	for (i = (rotblsize - 1) * sblock.fs_frag;
	    i >= 0; i -= sblock.fs_frag) {
		cylno = cbtocylno(&sblock, i);
		rpos = cbtorpos(&sblock, i);
		blk = fragstoblks(&sblock, i);
		if (fs_postbl(&sblock, cylno)[rpos] == -1)
			fs_rotbl(&sblock)[blk] = 0;
		else
			fs_rotbl(&sblock)[blk] =
			    fs_postbl(&sblock, cylno)[rpos] - blk;
		fs_postbl(&sblock, cylno)[rpos] = blk;
	}
next:
grow30:
	/*
	 * Compute/validate number of cylinder groups.
	 * Note that if an excessively large filesystem is specified
	 * (e.g., more than 16384 cylinders for an 8K filesystem block), it
	 * does not get detected until checksummarysize()
	 */
	sblock.fs_ncg = sblock.fs_ncyl / sblock.fs_cpg;
	if (sblock.fs_ncyl % sblock.fs_cpg)
		sblock.fs_ncg++;
	sblock.fs_dblkno = sblock.fs_iblkno + sblock.fs_ipg / INOPF(&sblock);
	i = MIN(~sblock.fs_cgmask, sblock.fs_ncg - 1);
	ibpcl = cgdmin(&sblock, i) - cgbase(&sblock, i);
	if (ibpcl >= sblock.fs_fpg) {
		(void) fprintf(stderr, gettext(
		    "inode blocks/cyl group (%d) >= data blocks (%d)\n"),
		    cgdmin(&sblock, i) - cgbase(&sblock, i) / sblock.fs_frag,
		    sblock.fs_fpg / sblock.fs_frag);
		if ((ibpcl < 0) || (sblock.fs_fpg < 0)) {
			(void) fprintf(stderr, gettext(
	    "number of cylinders per cylinder group (%d) must be decreased.\n"),
			    sblock.fs_cpg);
		} else {
			(void) fprintf(stderr, gettext(
	    "number of cylinders per cylinder group (%d) must be increased.\n"),
			    sblock.fs_cpg);
		}
		(void) fprintf(stderr, gettext(
"Note that cgsize may have been adjusted to allow struct cg to fit.\n"));
		lockexit(32);
	}
	j = sblock.fs_ncg - 1;
	if ((i = fssize_frag - j * sblock.fs_fpg) < sblock.fs_fpg &&
	    cgdmin(&sblock, j) - cgbase(&sblock, j) > i) {
		(void) fprintf(stderr, gettext(
		    "Warning: inode blocks/cyl group (%d) >= data "
		    "blocks (%ld) in last\n    cylinder group. This "
		    "implies %ld sector(s) cannot be allocated.\n"),
		    (cgdmin(&sblock, j) - cgbase(&sblock, j)) / sblock.fs_frag,
		    i / sblock.fs_frag, i * NSPF(&sblock));
		/*
		 * If there is only one cylinder group and that is not even
		 * big enough to hold the inodes, exit.
		 */
		if (sblock.fs_ncg == 1)
			cg_too_small = 1;
		sblock.fs_ncg--;
		sblock.fs_ncyl = sblock.fs_ncg * sblock.fs_cpg;
		sblock.fs_size = fssize_frag =
		    (int64_t)sblock.fs_ncyl * (int64_t)sblock.fs_spc /
		    (int64_t)NSPF(&sblock);
		warn = 0;
	}
	if (warn && !spc_flag) {
		(void) fprintf(stderr, gettext(
		    "Warning: %d sector(s) in last cylinder unallocated\n"),
		    sblock.fs_spc - (uint32_t)(fssize_frag * NSPF(&sblock) -
		    (uint64_t)(sblock.fs_ncyl - 1) * sblock.fs_spc));
	}
	/*
	 * fill in remaining fields of the super block
	 */

	/*
	 * The csum records are stored in cylinder group 0, starting at
	 * cgdmin, the first data block.
	 */
	sblock.fs_csaddr = cgdmin(&sblock, 0);
	sblock.fs_cssize =
	    fragroundup(&sblock, sblock.fs_ncg * sizeof (struct csum));
	i = sblock.fs_bsize / sizeof (struct csum);
	sblock.fs_csmask = ~(i - 1);
	for (sblock.fs_csshift = 0; i > 1; i >>= 1)
		sblock.fs_csshift++;
	fscs = (struct csum *)calloc(1, sblock.fs_cssize);

	checksummarysize();
	if (mtb == 'y') {
		sblock.fs_magic = MTB_UFS_MAGIC;
		sblock.fs_version = MTB_UFS_VERSION_1;
	} else {
		sblock.fs_magic = FS_MAGIC;
		if (use_efi_dflts)
			sblock.fs_version = UFS_EFISTYLE4NONEFI_VERSION_2;
		else
			sblock.fs_version = UFS_VERSION_MIN;
	}

	if (grow) {
		bcopy((caddr_t)grow_fscs, (caddr_t)fscs, (int)grow_fs_cssize);
		extendsummaryinfo();
		goto grow40;
	}
	sblock.fs_rotdelay = rotdelay;
	sblock.fs_maxcontig = maxcontig;
	sblock.fs_maxbpg = MAXBLKPG(sblock.fs_bsize);

	sblock.fs_rps = rps;
	sblock.fs_cgrotor = 0;
	sblock.fs_cstotal.cs_ndir = 0;
	sblock.fs_cstotal.cs_nbfree = 0;
	sblock.fs_cstotal.cs_nifree = 0;
	sblock.fs_cstotal.cs_nffree = 0;
	sblock.fs_fmod = 0;
	sblock.fs_ronly = 0;
	sblock.fs_time = mkfstime;
	sblock.fs_state = FSOKAY - sblock.fs_time;
	sblock.fs_clean = FSCLEAN;
grow40:

	/*
	 * If all that's needed is a dump of the superblock we
	 * would use by default, we've got it now.  So, splat it
	 * out and leave.
	 */
	if (rflag) {
		dump_sblock();
		lockexit(0);
	}
	/*
	 * Dump out summary information about file system.
	 */
	(void) fprintf(stderr, gettext(
	    "%s:\t%lld sectors in %d cylinders of %d tracks, %d sectors\n"),
	    fsys, (uint64_t)sblock.fs_size * NSPF(&sblock), sblock.fs_ncyl,
	    sblock.fs_ntrak, sblock.fs_nsect);
	(void) fprintf(stderr, gettext(
	    "\t%.1fMB in %d cyl groups (%d c/g, %.2fMB/g, %d i/g)\n"),
	    (float)sblock.fs_size * sblock.fs_fsize / MB, sblock.fs_ncg,
	    sblock.fs_cpg, (float)sblock.fs_fpg * sblock.fs_fsize / MB,
	    sblock.fs_ipg);

	tmpbuf = calloc(sblock.fs_ncg / 50 + 500, 1);
	if (tmpbuf == NULL) {
		perror("calloc");
		lockexit(32);
	}
	if (cg_too_small) {
		(void) fprintf(stderr, gettext("File system creation failed. "
		    "There is only one cylinder group and\nthat is "
		    "not even big enough to hold the inodes.\n"));
		lockexit(32);
	}
	/*
	 * Now build the cylinders group blocks and
	 * then print out indices of cylinder groups.
	 */
	tprintf(gettext(
	    "super-block backups (for fsck -F ufs -o b=#) at:\n"));
	for (width = cylno = 0; cylno < sblock.fs_ncg && cylno < 10; cylno++) {
		if ((grow == 0) || (cylno >= grow_fs_ncg))
			initcg(cylno);
		num = fsbtodb(&sblock, (uint64_t)cgsblock(&sblock, cylno));
		/*
		 * If Nflag and if the disk is larger than the CHSLIMIT,
		 * then sanity test the superblocks before reporting. If there
		 * are too many superblocks which look insane, we have
		 * to retry with alternate logic. If both methods have
		 * failed, then our efforts to arrive at alternate
		 * superblocks failed, so complain and exit.
		 */
		if (Nflag && retry) {
			skip_this_sb = 0;
			rdfs((diskaddr_t)num, sbsize, (char *)&altsblock);
			ret = checksblock(altsblock, 1);
			if (ret) {
				skip_this_sb = 1;
				invalid_sb_cnt++;
				dprintf(("DeBuG checksblock() failed - error :"
				    " %d for sb : %llu invalid_sb_cnt : %d\n",
				    ret, num, invalid_sb_cnt));
			} else {
				/*
				 * Though the superblock looks sane, verify if
				 * the fs_version in the superblock and the
				 * logic that we are using to arrive at the
				 * superblocks match.
				 */
				if (use_efi_dflts && altsblock.fs_version
				    != UFS_EFISTYLE4NONEFI_VERSION_2) {
					skip_this_sb = 1;
					invalid_sb_cnt++;
				}
			}
			if (invalid_sb_cnt >= INVALIDSBLIMIT) {
				if (retry > 1) {
					(void) fprintf(stderr, gettext(
					    "Error determining alternate "
					    "superblock locations\n"));
					free(tmpbuf);
					lockexit(32);
				}
				retry++;
				use_efi_dflts = !use_efi_dflts;
				free(tmpbuf);
				goto retry_alternate_logic;
			}
			if (skip_this_sb)
				continue;
		}
		(void) sprintf(pbuf, " %llu,", num);
		plen = strlen(pbuf);
		if ((width + plen) > (WIDTH - 1)) {
			width = plen;
			tprintf("\n");
		} else {
			width += plen;
		}
		if (Nflag && retry)
			(void) strncat(tmpbuf, pbuf, strlen(pbuf));
		else
			(void) fprintf(stderr, "%s", pbuf);
	}
	tprintf("\n");

	remaining_cg = sblock.fs_ncg - cylno;

	/*
	 * If there are more than 300 cylinder groups still to be
	 * initialized, print a "." for every 50 cylinder groups.
	 */
	if (remaining_cg > 300) {
		tprintf(gettext("Initializing cylinder groups:\n"));
		do_dot = 1;
	}

	/*
	 * Now initialize all cylinder groups between the first ten
	 * and the last ten.
	 *
	 * If the number of cylinder groups was less than 10, all of the
	 * cylinder group offsets would have printed in the last loop
	 * and cylno will already be equal to sblock.fs_ncg and so this
	 * loop will not be entered.  If there are less than 20 cylinder
	 * groups, cylno is already less than fs_ncg - 10, so this loop
	 * won't be entered in that case either.
	 */

	i = 0;
	for (; cylno < sblock.fs_ncg - 10; cylno++) {
		if ((grow == 0) || (cylno >= grow_fs_ncg))
			initcg(cylno);
		if (do_dot && cylno % 50 == 0) {
			tprintf(".");
			i++;
			if (i == WIDTH - 1) {
				tprintf("\n");
				i = 0;
			}
		}
	}

	/*
	 * Now print the cylinder group offsets for the last 10
	 * cylinder groups, if any are left.
	 */

	if (do_dot) {
		tprintf(gettext(
	    "\nsuper-block backups for last 10 cylinder groups at:\n"));
	}
	for (width = 0; cylno < sblock.fs_ncg; cylno++) {
		if ((grow == 0) || (cylno >= grow_fs_ncg))
			initcg(cylno);
		num = fsbtodb(&sblock, (uint64_t)cgsblock(&sblock, cylno));
		if (Nflag && retry) {
			skip_this_sb = 0;
			rdfs((diskaddr_t)num, sbsize, (char *)&altsblock);
			ret = checksblock(altsblock, 1);
			if (ret) {
				skip_this_sb = 1;
				invalid_sb_cnt++;
				dprintf(("DeBuG checksblock() failed - error :"
				    " %d for sb : %llu invalid_sb_cnt : %d\n",
				    ret, num, invalid_sb_cnt));
			} else {
				/*
				 * Though the superblock looks sane, verify if
				 * the fs_version in the superblock and the
				 * logic that we are using to arrive at the
				 * superblocks match.
				 */
				if (use_efi_dflts && altsblock.fs_version
				    != UFS_EFISTYLE4NONEFI_VERSION_2) {
					skip_this_sb = 1;
					invalid_sb_cnt++;
				}
			}
			if (invalid_sb_cnt >= INVALIDSBLIMIT) {
				if (retry > 1) {
					(void) fprintf(stderr, gettext(
					    "Error determining alternate "
					    "superblock locations\n"));
					free(tmpbuf);
					lockexit(32);
				}
				retry++;
				use_efi_dflts = !use_efi_dflts;
				free(tmpbuf);
				goto retry_alternate_logic;
			}
			if (skip_this_sb)
				continue;
		}
		/* Don't print ',' for the last superblock */
		if (cylno == sblock.fs_ncg-1)
			(void) sprintf(pbuf, " %llu", num);
		else
			(void) sprintf(pbuf, " %llu,", num);
		plen = strlen(pbuf);
		if ((width + plen) > (WIDTH - 1)) {
			width = plen;
			tprintf("\n");
		} else {
			width += plen;
		}
		if (Nflag && retry)
			(void) strncat(tmpbuf, pbuf, strlen(pbuf));
		else
			(void) fprintf(stderr, "%s", pbuf);
	}
	tprintf("\n");
	if (Nflag) {
		if (retry)
			(void) fprintf(stderr, "%s", tmpbuf);
		free(tmpbuf);
		lockexit(0);
	}

	free(tmpbuf);
	if (grow)
		goto grow50;

	/*
	 * Now construct the initial file system,
	 * then write out the super-block.
	 */
	fsinit();
grow50:
	/*
	 * write the superblock and csum information
	 */
	wtsb();

	/*
	 * extend the last cylinder group in the original file system
	 */
	if (grow) {
		extendcg(grow_fs_ncg-1);
		wtsb();
	}

	/*
	 * Write out the duplicate super blocks to the first 10
	 * cylinder groups (or fewer, if there are fewer than 10
	 * cylinder groups).
	 */
	for (cylno = 0; cylno < sblock.fs_ncg && cylno < 10; cylno++)
		awtfs(fsbtodb(&sblock, (uint64_t)cgsblock(&sblock, cylno)),
		    (int)sbsize, (char *)&sblock, SAVE);

	/*
	 * Now write out duplicate super blocks to the remaining
	 * cylinder groups.  In the case of multi-terabyte file
	 * systems, just write out the super block to the last ten
	 * cylinder groups (or however many are left).
	 */
	if (mtb == 'y') {
		if (sblock.fs_ncg <= 10)
			cylno = sblock.fs_ncg;
		else if (sblock.fs_ncg <= 20)
			cylno = 10;
		else
			cylno = sblock.fs_ncg - 10;
	}

	for (; cylno < sblock.fs_ncg; cylno++)
		awtfs(fsbtodb(&sblock, (uint64_t)cgsblock(&sblock, cylno)),
		    (int)sbsize, (char *)&sblock, SAVE);

	/*
	 * Flush out all the AIO writes we've done.  It's not
	 * necessary to do this explicitly, but it's the only
	 * way to report any errors from those writes.
	 */
	flush_writes();

	/*
	 * set clean flag
	 */
	if (grow)
		sblock.fs_clean = grow_fs_clean;
	else
		sblock.fs_clean = FSCLEAN;
	sblock.fs_time = mkfstime;
	sblock.fs_state = FSOKAY - sblock.fs_time;
	wtfs((diskaddr_t)(SBOFF / sectorsize), sbsize, (char *)&sblock);
	isbad = 0;

	if (fsync(fso) == -1) {
		saverr = errno;
		(void) fprintf(stderr,
		    gettext("mkfs: fsync failed on write disk: %s\n"),
		    strerror(saverr));
		/* we're just cleaning up, so keep going */
	}
	if (close(fsi) == -1) {
		saverr = errno;
		(void) fprintf(stderr,
		    gettext("mkfs: close failed on read disk: %s\n"),
		    strerror(saverr));
		/* we're just cleaning up, so keep going */
	}
	if (close(fso) == -1) {
		saverr = errno;
		(void) fprintf(stderr,
		    gettext("mkfs: close failed on write disk: %s\n"),
		    strerror(saverr));
		/* we're just cleaning up, so keep going */
	}
	fsi = fso = -1;

#ifndef STANDALONE
	lockexit(0);
#endif

	return (0);
}

/*
 * Figure out how big the partition we're dealing with is.
 * The value returned is in disk blocks (sectors);
 */
static diskaddr_t
get_max_size(int fd)
{
	struct extvtoc vtoc;
	dk_gpt_t *efi_vtoc;
	diskaddr_t	slicesize;

	int index = read_extvtoc(fd, &vtoc);

	if (index >= 0) {
		label_type = LABEL_TYPE_VTOC;
	} else {
		if (index == VT_ENOTSUP || index == VT_ERROR) {
			/* it might be an EFI label */
			index = efi_alloc_and_read(fd, &efi_vtoc);
			label_type = LABEL_TYPE_EFI;
		}
	}

	if (index < 0) {
		switch (index) {
		case VT_ERROR:
			break;
		case VT_EIO:
			errno = EIO;
			break;
		case VT_EINVAL:
			errno = EINVAL;
		}
		perror(gettext("Can not determine partition size"));
		lockexit(32);
	}

	if (label_type == LABEL_TYPE_EFI) {
		slicesize = efi_vtoc->efi_parts[index].p_size;
		efi_free(efi_vtoc);
	} else {
		/*
		 * In the vtoc struct, p_size is a 32-bit signed quantity.
		 * In the dk_gpt struct (efi's version of the vtoc), p_size
		 * is an unsigned 64-bit quantity.  By casting the vtoc's
		 * psize to an unsigned 32-bit quantity, it will be copied
		 * to 'slicesize' (an unsigned 64-bit diskaddr_t) without
		 * sign extension.
		 */

		slicesize = (uint32_t)vtoc.v_part[index].p_size;
	}

	dprintf(("DeBuG get_max_size index = %d, p_size = %lld, dolimit = %d\n",
	    index, slicesize, (slicesize > FS_MAX)));

	/*
	 * The next line limits a UFS file system to the maximum
	 * supported size.
	 */

	if (slicesize > FS_MAX)
		return (FS_MAX);
	return (slicesize);
}

static long
get_max_track_size(int fd)
{
	struct dk_cinfo ci;
	long track_size = -1;

	if (ioctl(fd, DKIOCINFO, &ci) == 0) {
		track_size = ci.dki_maxtransfer * DEV_BSIZE;
	}

	if ((track_size < 0)) {
		int	error = 0;
		int	maxphys;
		int	gotit = 0;

		gotit = fsgetmaxphys(&maxphys, &error);
		if (gotit) {
			track_size = MIN(MB, maxphys);
		} else {
			(void) fprintf(stderr, gettext(
"Warning: Could not get system value for maxphys. The value for\n"
"maxcontig will default to 1MB.\n"));
			track_size = MB;
		}
	}
	return (track_size);
}

/*
 * Initialize a cylinder group.
 */
static void
initcg(int cylno)
{
	diskaddr_t cbase, d;
	diskaddr_t dlower;	/* last data block before cg metadata */
	diskaddr_t dupper;	/* first data block after cg metadata */
	diskaddr_t dmax;
	int64_t i;
	struct csum *cs;
	struct dinode *inode_buffer;
	int size;

	/*
	 * Variables used to store intermediate results as a part of
	 * the internal implementation of the cbtocylno() macros.
	 */
	diskaddr_t bno;		/* UFS block number (not sector number) */
	int	cbcylno;	/* current cylinder number */
	int	cbcylno_sect;	/* sector offset within cylinder */
	int	cbsect_incr;	/* amount to increment sector offset */

	/*
	 * Variables used to store intermediate results as a part of
	 * the internal implementation of the cbtorpos() macros.
	 */
	short	*cgblks;	/* pointer to array of free blocks in cg */
	int	trackrpos;	/* tmp variable for rotation position */
	int	trackoff;	/* offset within a track */
	int	trackoff_incr;	/* amount to increment trackoff */
	int	rpos;		/* rotation position of current block */
	int	rpos_incr;	/* amount to increment rpos per block */

	union cgun *icgun;	/* local pointer to a cg summary block */
#define	icg	(icgun->cg)

	icgun = (union cgun *)getbuf(&cgsumbuf, sizeof (union cgun));

	/*
	 * Determine block bounds for cylinder group.
	 * Allow space for super block summary information in first
	 * cylinder group.
	 */
	cbase = cgbase(&sblock, cylno);
	dmax = cbase + sblock.fs_fpg;
	if (dmax > sblock.fs_size)	/* last cg may be smaller than normal */
		dmax = sblock.fs_size;
	dlower = cgsblock(&sblock, cylno) - cbase;
	dupper = cgdmin(&sblock, cylno) - cbase;
	if (cylno == 0)
		dupper += howmany(sblock.fs_cssize, sblock.fs_fsize);
	cs = fscs + cylno;
	icg.cg_time = mkfstime;
	icg.cg_magic = CG_MAGIC;
	icg.cg_cgx = cylno;
	/* last one gets whatever's left */
	if (cylno == sblock.fs_ncg - 1)
		icg.cg_ncyl = sblock.fs_ncyl - (sblock.fs_cpg * cylno);
	else
		icg.cg_ncyl = sblock.fs_cpg;
	icg.cg_niblk = sblock.fs_ipg;
	icg.cg_ndblk = dmax - cbase;
	icg.cg_cs.cs_ndir = 0;
	icg.cg_cs.cs_nffree = 0;
	icg.cg_cs.cs_nbfree = 0;
	icg.cg_cs.cs_nifree = 0;
	icg.cg_rotor = 0;
	icg.cg_frotor = 0;
	icg.cg_irotor = 0;
	icg.cg_btotoff = &icg.cg_space[0] - (uchar_t *)(&icg.cg_link);
	icg.cg_boff = icg.cg_btotoff + sblock.fs_cpg * sizeof (long);
	icg.cg_iusedoff = icg.cg_boff +
	    sblock.fs_cpg * sblock.fs_nrpos * sizeof (short);
	icg.cg_freeoff = icg.cg_iusedoff + howmany(sblock.fs_ipg, NBBY);
	icg.cg_nextfreeoff = icg.cg_freeoff +
	    howmany(sblock.fs_cpg * sblock.fs_spc / NSPF(&sblock), NBBY);
	for (i = 0; i < sblock.fs_frag; i++) {
		icg.cg_frsum[i] = 0;
	}
	bzero((caddr_t)cg_inosused(&icg), icg.cg_freeoff - icg.cg_iusedoff);
	icg.cg_cs.cs_nifree += sblock.fs_ipg;
	if (cylno == 0)
		for (i = 0; i < UFSROOTINO; i++) {
			setbit(cg_inosused(&icg), i);
			icg.cg_cs.cs_nifree--;
		}

	/*
	 * Initialize all the inodes in the cylinder group using
	 * random numbers.
	 */
	size = sblock.fs_ipg * sizeof (struct dinode);
	inode_buffer = (struct dinode *)getbuf(&inodebuf, size);

	for (i = 0; i < sblock.fs_ipg; i++) {
		IRANDOMIZE(&(inode_buffer[i].di_ic));
	}

	/*
	 * Write all inodes in a single write for performance.
	 */
	awtfs(fsbtodb(&sblock, (uint64_t)cgimin(&sblock, cylno)), (int)size,
	    (char *)inode_buffer, RELEASE);

	bzero((caddr_t)cg_blktot(&icg), icg.cg_boff - icg.cg_btotoff);
	bzero((caddr_t)cg_blks(&sblock, &icg, 0),
	    icg.cg_iusedoff - icg.cg_boff);
	bzero((caddr_t)cg_blksfree(&icg), icg.cg_nextfreeoff - icg.cg_freeoff);

	if (cylno > 0) {
		for (d = 0; d < dlower; d += sblock.fs_frag) {
			setblock(&sblock, cg_blksfree(&icg), d/sblock.fs_frag);
			icg.cg_cs.cs_nbfree++;
			cg_blktot(&icg)[cbtocylno(&sblock, d)]++;
			cg_blks(&sblock, &icg, cbtocylno(&sblock, d))
			    [cbtorpos(&sblock, d)]++;
		}
		sblock.fs_dsize += dlower;
	}
	sblock.fs_dsize += icg.cg_ndblk - dupper;
	if ((i = dupper % sblock.fs_frag) != 0) {
		icg.cg_frsum[sblock.fs_frag - i]++;
		for (d = dupper + sblock.fs_frag - i; dupper < d; dupper++) {
			setbit(cg_blksfree(&icg), dupper);
			icg.cg_cs.cs_nffree++;
		}
	}

	/*
	 * WARNING: The following code is somewhat confusing, but
	 * results in a substantial performance improvement in mkfs.
	 *
	 * Instead of using cbtocylno() and cbtorpos() macros, we
	 * keep track of all the intermediate state of those macros
	 * in some variables.  This allows simple addition to be
	 * done to calculate the results as we step through the
	 * blocks in an orderly fashion instead of the slower
	 * multiplication and division the macros are forced to
	 * used so they can support random input.  (Multiplication,
	 * division, and remainder operations typically take about
	 * 10x as many processor cycles as other operations.)
	 *
	 * The basic idea is to take code:
	 *
	 *	for (x = starting_x; x < max; x++)
	 *		y = (x * c) / z
	 *
	 * and rewrite it to take advantage of the fact that
	 * the variable x is incrementing in an orderly way:
	 *
	 *	intermediate = starting_x * c
	 *	yval = intermediate / z
	 *	for (x = starting_x; x < max; x++) {
	 *		y = yval;
	 *		intermediate += c
	 *		if (intermediate > z) {
	 *			yval++;
	 *			intermediate -= z
	 *		}
	 *	}
	 *
	 * Performance has improved as much as 4X using this code.
	 */

	/*
	 * Initialize the starting points for all the cbtocylno()
	 * macro variables and figure out the increments needed each
	 * time through the loop.
	 */
	cbcylno_sect = dupper * NSPF(&sblock);
	cbsect_incr = sblock.fs_frag * NSPF(&sblock);
	cbcylno = cbcylno_sect / sblock.fs_spc;
	cbcylno_sect %= sblock.fs_spc;
	cgblks = cg_blks(&sblock, &icg, cbcylno);
	bno = dupper / sblock.fs_frag;

	/*
	 * Initialize the starting points for all the cbtorpos()
	 * macro variables and figure out the increments needed each
	 * time through the loop.
	 *
	 * It's harder to simplify the cbtorpos() macro if there were
	 * alternate sectors specified (or if they previously existed
	 * in the growfs case).  Since this is rare, we just revert to
	 * using the macros in this case and skip the variable setup.
	 */
	if (!spc_flag) {
		trackrpos = (cbcylno_sect % sblock.fs_nsect) * sblock.fs_nrpos;
		rpos = trackrpos / sblock.fs_nsect;
		trackoff = trackrpos % sblock.fs_nsect;
		trackoff_incr = cbsect_incr * sblock.fs_nrpos;
		rpos_incr = (trackoff_incr / sblock.fs_nsect) % sblock.fs_nrpos;
		trackoff_incr = trackoff_incr % sblock.fs_nsect;
	}

	/*
	 * Loop through all the blocks, marking them free and
	 * updating totals kept in the superblock and cg summary.
	 */
	for (d = dupper; d + sblock.fs_frag <= dmax - cbase; ) {
		setblock(&sblock, cg_blksfree(&icg),  bno);
		icg.cg_cs.cs_nbfree++;

		cg_blktot(&icg)[cbcylno]++;

		if (!spc_flag)
			cgblks[rpos]++;
		else
			cg_blks(&sblock, &icg, cbtocylno(&sblock, d))
			    [cbtorpos(&sblock, d)]++;

		d += sblock.fs_frag;
		bno++;

		/*
		 * Increment the sector offset within the cylinder
		 * for the cbtocylno() macro reimplementation.  If
		 * we're beyond the end of the cylinder, update the
		 * cylinder number, calculate the offset in the
		 * new cylinder, and update the cgblks pointer
		 * to the next rotational position.
		 */
		cbcylno_sect += cbsect_incr;
		if (cbcylno_sect >= sblock.fs_spc) {
			cbcylno++;
			cbcylno_sect -= sblock.fs_spc;
			cgblks += sblock.fs_nrpos;
		}

		/*
		 * If there aren't alternate sectors, increment the
		 * rotational position variables for the cbtorpos()
		 * reimplementation.  Note that we potentially
		 * increment rpos twice.  Once by rpos_incr, and one
		 * more time when we wrap to a new track because
		 * trackoff >= fs_nsect.
		 */
		if (!spc_flag) {
			trackoff += trackoff_incr;
			rpos += rpos_incr;
			if (trackoff >= sblock.fs_nsect) {
				trackoff -= sblock.fs_nsect;
				rpos++;
			}
			if (rpos >= sblock.fs_nrpos)
				rpos -= sblock.fs_nrpos;
		}
	}

	if (d < dmax - cbase) {
		icg.cg_frsum[dmax - cbase - d]++;
		for (; d < dmax - cbase; d++) {
			setbit(cg_blksfree(&icg), d);
			icg.cg_cs.cs_nffree++;
		}
	}
	sblock.fs_cstotal.cs_ndir += icg.cg_cs.cs_ndir;
	sblock.fs_cstotal.cs_nffree += icg.cg_cs.cs_nffree;
	sblock.fs_cstotal.cs_nbfree += icg.cg_cs.cs_nbfree;
	sblock.fs_cstotal.cs_nifree += icg.cg_cs.cs_nifree;
	*cs = icg.cg_cs;
	awtfs(fsbtodb(&sblock, (uint64_t)cgtod(&sblock, cylno)),
	    sblock.fs_bsize, (char *)&icg, RELEASE);
}

/*
 * initialize the file system
 */
struct inode node;

#define	LOSTDIR
#ifdef LOSTDIR
#define	PREDEFDIR 3
#else
#define	PREDEFDIR 2
#endif

struct direct root_dir[] = {
	{ UFSROOTINO, sizeof (struct direct), 1, "." },
	{ UFSROOTINO, sizeof (struct direct), 2, ".." },
#ifdef LOSTDIR
	{ LOSTFOUNDINO, sizeof (struct direct), 10, "lost+found" },
#endif
};
#ifdef LOSTDIR
struct direct lost_found_dir[] = {
	{ LOSTFOUNDINO, sizeof (struct direct), 1, "." },
	{ UFSROOTINO, sizeof (struct direct), 2, ".." },
	{ 0, DIRBLKSIZ, 0, 0 },
};
#endif
char buf[MAXBSIZE];

static void
fsinit()
{
	int i;


	/*
	 * initialize the node
	 */
	node.i_atime = mkfstime;
	node.i_mtime = mkfstime;
	node.i_ctime = mkfstime;
#ifdef LOSTDIR
	/*
	 * create the lost+found directory
	 */
	(void) makedir(lost_found_dir, 2);
	for (i = DIRBLKSIZ; i < sblock.fs_bsize; i += DIRBLKSIZ) {
		bcopy(&lost_found_dir[2], &buf[i], DIRSIZ(&lost_found_dir[2]));
	}
	node.i_number = LOSTFOUNDINO;
	node.i_smode = IFDIR | 0700;
	node.i_nlink = 2;
	node.i_size = sblock.fs_bsize;
	node.i_db[0] = alloc((int)node.i_size, node.i_mode);
	node.i_blocks = btodb(fragroundup(&sblock, (int)node.i_size));
	IRANDOMIZE(&node.i_ic);
	wtfs(fsbtodb(&sblock, (uint64_t)node.i_db[0]), (int)node.i_size, buf);
	iput(&node);
#endif
	/*
	 * create the root directory
	 */
	node.i_number = UFSROOTINO;
	node.i_mode = IFDIR | UMASK;
	node.i_nlink = PREDEFDIR;
	node.i_size = makedir(root_dir, PREDEFDIR);
	node.i_db[0] = alloc(sblock.fs_fsize, node.i_mode);
	/* i_size < 2GB because we are initializing the file system */
	node.i_blocks = btodb(fragroundup(&sblock, (int)node.i_size));
	IRANDOMIZE(&node.i_ic);
	wtfs(fsbtodb(&sblock, (uint64_t)node.i_db[0]), sblock.fs_fsize, buf);
	iput(&node);
}

/*
 * construct a set of directory entries in "buf".
 * return size of directory.
 */
static int
makedir(struct direct *protodir, int entries)
{
	char *cp;
	int i;
	ushort_t spcleft;

	spcleft = DIRBLKSIZ;
	for (cp = buf, i = 0; i < entries - 1; i++) {
		protodir[i].d_reclen = DIRSIZ(&protodir[i]);
		bcopy(&protodir[i], cp, protodir[i].d_reclen);
		cp += protodir[i].d_reclen;
		spcleft -= protodir[i].d_reclen;
	}
	protodir[i].d_reclen = spcleft;
	bcopy(&protodir[i], cp, DIRSIZ(&protodir[i]));
	return (DIRBLKSIZ);
}

/*
 * allocate a block or frag
 */
static daddr32_t
alloc(int size, int mode)
{
	int i, frag;
	daddr32_t d;

	rdfs(fsbtodb(&sblock, (uint64_t)cgtod(&sblock, 0)), sblock.fs_cgsize,
	    (char *)&acg);
	if (acg.cg_magic != CG_MAGIC) {
		(void) fprintf(stderr, gettext("cg 0: bad magic number\n"));
		lockexit(32);
	}
	if (acg.cg_cs.cs_nbfree == 0) {
		(void) fprintf(stderr,
		    gettext("first cylinder group ran out of space\n"));
		lockexit(32);
	}
	for (d = 0; d < acg.cg_ndblk; d += sblock.fs_frag)
		if (isblock(&sblock, cg_blksfree(&acg), d / sblock.fs_frag))
			goto goth;
	(void) fprintf(stderr,
	    gettext("internal error: can't find block in cyl 0\n"));
	lockexit(32);
goth:
	clrblock(&sblock, cg_blksfree(&acg), d / sblock.fs_frag);
	acg.cg_cs.cs_nbfree--;
	sblock.fs_cstotal.cs_nbfree--;
	fscs[0].cs_nbfree--;
	if (mode & IFDIR) {
		acg.cg_cs.cs_ndir++;
		sblock.fs_cstotal.cs_ndir++;
		fscs[0].cs_ndir++;
	}
	cg_blktot(&acg)[cbtocylno(&sblock, d)]--;
	cg_blks(&sblock, &acg, cbtocylno(&sblock, d))[cbtorpos(&sblock, d)]--;
	if (size != sblock.fs_bsize) {
		frag = howmany(size, sblock.fs_fsize);
		fscs[0].cs_nffree += sblock.fs_frag - frag;
		sblock.fs_cstotal.cs_nffree += sblock.fs_frag - frag;
		acg.cg_cs.cs_nffree += sblock.fs_frag - frag;
		acg.cg_frsum[sblock.fs_frag - frag]++;
		for (i = frag; i < sblock.fs_frag; i++)
			setbit(cg_blksfree(&acg), d + i);
	}
	wtfs(fsbtodb(&sblock, (uint64_t)cgtod(&sblock, 0)), sblock.fs_cgsize,
	    (char *)&acg);
	return (d);
}

/*
 * Allocate an inode on the disk
 */
static void
iput(struct inode *ip)
{
	struct dinode buf[MAXINOPB];
	diskaddr_t d;

	rdfs(fsbtodb(&sblock, (uint64_t)cgtod(&sblock, 0)), sblock.fs_cgsize,
	    (char *)&acg);
	if (acg.cg_magic != CG_MAGIC) {
		(void) fprintf(stderr, gettext("cg 0: bad magic number\n"));
		lockexit(32);
	}
	acg.cg_cs.cs_nifree--;
	setbit(cg_inosused(&acg), ip->i_number);
	wtfs(fsbtodb(&sblock, (uint64_t)cgtod(&sblock, 0)), sblock.fs_cgsize,
	    (char *)&acg);
	sblock.fs_cstotal.cs_nifree--;
	fscs[0].cs_nifree--;
	if ((int)ip->i_number >= sblock.fs_ipg * sblock.fs_ncg) {
		(void) fprintf(stderr,
		    gettext("fsinit: inode value out of range (%d).\n"),
		    ip->i_number);
		lockexit(32);
	}
	d = fsbtodb(&sblock, (uint64_t)itod(&sblock, (int)ip->i_number));
	rdfs(d, sblock.fs_bsize, (char *)buf);
	buf[itoo(&sblock, (int)ip->i_number)].di_ic = ip->i_ic;
	wtfs(d, sblock.fs_bsize, (char *)buf);
}

/*
 * getbuf()	-- Get a buffer for use in an AIO operation.  Buffer
 *		is zero'd the first time returned, left with whatever
 *		was in memory after that.  This function actually gets
 *		enough memory the first time it's called to support
 *		MAXBUF buffers like a slab allocator.  When all the
 *		buffers are in use, it waits for an aio to complete
 *		and make a buffer available.
 *
 *		Never returns an error.  Either succeeds or exits.
 */
static char *
getbuf(bufhdr *bufhead, int size)
{
	bufhdr *pbuf;
	bufhdr *prev;
	int i;
	int buf_size, max_bufs;

	/*
	 * Initialize all the buffers
	 */
	if (bufhead->head == NULL) {
		/*
		 * round up the size of our buffer header to a
		 * 16 byte boundary so the address we return to
		 * the caller is "suitably aligned".
		 */
		bufhdrsize = (sizeof (bufhdr) + 15) & ~15;

		/*
		 * Add in our header to the buffer and round it all up to
		 * a 16 byte boundry so each member of the slab is aligned.
		 */
		buf_size = (size + bufhdrsize + 15) & ~15;

		/*
		 * Limit number of buffers to lesser of MAXBUFMEM's worth
		 * or MAXBUF, whichever is less.
		 */
		max_bufs = MAXBUFMEM / buf_size;
		if (max_bufs > MAXBUF)
			max_bufs = MAXBUF;

		pbuf = (bufhdr *)calloc(max_bufs, buf_size);
		if (pbuf == NULL) {
			perror("calloc");
			lockexit(32);
		}

		bufhead->head = bufhead;
		prev = bufhead;
		for (i = 0; i < max_bufs; i++) {
			pbuf->head = bufhead;
			prev->next = pbuf;
			prev = pbuf;
			pbuf = (bufhdr *)((char *)pbuf + buf_size);
		}
	}

	/*
	 * Get an available buffer, waiting for I/O if necessary
	 */
	wait_for_write(NOBLOCK);
	while (bufhead->next == NULL)
		wait_for_write(BLOCK);

	/*
	 * Take the buffer off the list
	 */
	pbuf = bufhead->next;
	bufhead->next = pbuf->next;
	pbuf->next = NULL;

	/*
	 * return the empty buffer space just past the header
	 */
	return ((char *)pbuf + bufhdrsize);
}

/*
 * freebuf()	-- Free a buffer gotten previously through getbuf.
 *		Puts the buffer back on the appropriate list for
 *		later use.  Never calls free().
 *
 * Assumes that SIGINT is blocked.
 */
static void
freebuf(char *buf)
{
	bufhdr *pbuf;
	bufhdr *bufhead;

	/*
	 * get the header for this buffer
	 */
	pbuf = (bufhdr *)(buf - bufhdrsize);

	/*
	 * Put it back on the list of available buffers
	 */
	bufhead = pbuf->head;
	pbuf->next = bufhead->next;
	bufhead->next = pbuf;
}

/*
 * freetrans()	-- Free a transaction gotten previously through getaiop.
 *		Puts the transaction struct back on the appropriate list for
 *		later use.  Never calls free().
 *
 * Assumes that SIGINT is blocked.
 */
static void
freetrans(aio_trans *transp)
{
	/*
	 * free the buffer associated with this AIO if needed
	 */
	if (transp->release == RELEASE)
		freebuf(transp->buffer);

	/*
	 * Put transaction on the free list
	 */
	transp->next = results.trans;
	results.trans = transp;
}

/*
 * wait_for_write()	-- Wait for an aio write to complete.  Return
 *			the transaction structure for that write.
 *
 * Blocks SIGINT if necessary.
 */
aio_trans *
wait_for_write(int block)
{
	aio_trans	*transp;
	aio_result_t	*resultp;
	static struct timeval  zero_wait = { 0, 0 };
	sigset_t	old_mask;

	/*
	 * If we know there aren't any outstanding transactions, just return
	 */
	if (results.outstanding == 0)
		return ((aio_trans *) 0);

	block_sigint(&old_mask);

	resultp = aiowait(block ? NULL : &zero_wait);
	if (resultp == NULL ||
	    (resultp == (aio_result_t *)-1 && errno == EINVAL)) {
		unblock_sigint(&old_mask);
		return ((aio_trans *) 0);
	}

	results.outstanding--;
	transp = (aio_trans *)resultp;

	if (resultp->aio_return != transp->size) {
		if (resultp->aio_return == -1) {
			/*
			 * The aiowrite() may have failed because the
			 * kernel didn't have enough memory to do the job.
			 * Flush all pending writes and try a normal
			 * write().  wtfs_breakup() will call exit if it
			 * fails, so we don't worry about errors here.
			 */
			flush_writes();
			wtfs_breakup(transp->bno, transp->size, transp->buffer);
		} else {
			(void) fprintf(stderr, gettext(
			    "short write (%d of %d bytes) on sector %lld\n"),
			    resultp->aio_return, transp->size,
			    transp->bno);
			/*
			 * Don't unblock SIGINT, to avoid potential
			 * looping due to queued interrupts and
			 * error handling.
			 */
			lockexit(32);
		}
	}

	resultp->aio_return = 0;
	freetrans(transp);
	unblock_sigint(&old_mask);
	return (transp);
}

/*
 * flush_writes()	-- flush all the outstanding aio writes.
 */
static void
flush_writes(void)
{
	while (wait_for_write(BLOCK))
		;
}

/*
 * get_aiop()	-- find and return an aio_trans structure on which a new
 *		aio can be done.  Blocks on aiowait() if needed.  Reaps
 *		all outstanding completed aio's.
 *
 * Assumes that SIGINT is blocked.
 */
aio_trans *
get_aiop()
{
	int i;
	aio_trans *transp;
	aio_trans *prev;

	/*
	 * initialize aio stuff
	 */
	if (!aio_inited) {
		aio_inited = 1;

		results.maxpend = 0;
		results.outstanding = 0;
		results.max = MAXAIO;

		results.trans = (aio_trans *)calloc(results.max,
		    sizeof (aio_trans));
		if (results.trans == NULL) {
			perror("calloc");
			lockexit(32);
		}

		/*
		 * Initialize the linked list of aio transaction
		 * structures.  Note that the final "next" pointer
		 * will be NULL since we got the buffer from calloc().
		 */
		prev = results.trans;
		for (i = 1; i < results.max; i++) {
			prev->next = &(results.trans[i]);
			prev = prev->next;
		}
	}

	wait_for_write(NOBLOCK);
	while (results.trans == NULL)
		wait_for_write(BLOCK);
	transp = results.trans;
	results.trans = results.trans->next;

	transp->next = 0;
	transp->resultbuf.aio_return = AIO_INPROGRESS;
	return (transp);
}

/*
 * read a block from the file system
 */
static void
rdfs(diskaddr_t bno, int size, char *bf)
{
	int n, saverr;

	/*
	 * In case we need any data that's pending in an aiowrite(),
	 * we wait for them all to complete before doing a read.
	 */
	flush_writes();

	/*
	 * Note: the llseek() can succeed, even if the offset is out of range.
	 * It's not until the file i/o operation (the read()) that one knows
	 * for sure if the raw device can handle the offset.
	 */
	if (llseek(fsi, (offset_t)bno * sectorsize, 0) < 0) {
		saverr = errno;
		(void) fprintf(stderr,
		    gettext("seek error on sector %lld: %s\n"),
		    bno, strerror(saverr));
		lockexit(32);
	}
	n = read(fsi, bf, size);
	if (n != size) {
		saverr = errno;
		if (n == -1)
			(void) fprintf(stderr,
			    gettext("read error on sector %lld: %s\n"),
			    bno, strerror(saverr));
		else
			(void) fprintf(stderr, gettext(
			    "short read (%d of %d bytes) on sector %lld\n"),
			    n, size, bno);
		lockexit(32);
	}
}

/*
 * write a block to the file system
 */
static void
wtfs(diskaddr_t bno, int size, char *bf)
{
	int n, saverr;

	if (fso == -1)
		return;

	/*
	 * Note: the llseek() can succeed, even if the offset is out of range.
	 * It's not until the file i/o operation (the write()) that one knows
	 * for sure if the raw device can handle the offset.
	 */
	if (llseek(fso, (offset_t)bno * sectorsize, 0) < 0) {
		saverr = errno;
		(void) fprintf(stderr,
		    gettext("seek error on sector %lld: %s\n"),
		    bno, strerror(saverr));
		lockexit(32);
	}
	if (Nflag)
		return;
	n = write(fso, bf, size);
	if (n != size) {
		saverr = errno;
		if (n == -1)
			(void) fprintf(stderr,
			    gettext("write error on sector %lld: %s\n"),
			    bno, strerror(saverr));
		else
			(void) fprintf(stderr, gettext(
			    "short write (%d of %d bytes) on sector %lld\n"),
			    n, size, bno);
		lockexit(32);
	}
}

/*
 * write a block to the file system -- buffered with aio
 */
static void
awtfs(diskaddr_t bno, int size, char *bf, int release)
{
	int n;
	aio_trans 	*transp;
	sigset_t 	old_mask;

	if (fso == -1)
		return;

	/*
	 * We need to keep things consistent if we get interrupted,
	 * so defer any expected interrupts for the time being.
	 */
	block_sigint(&old_mask);

	if (Nflag) {
		if (release == RELEASE)
			freebuf(bf);
	} else {
		transp = get_aiop();
		transp->bno = bno;
		transp->buffer = bf;
		transp->size = size;
		transp->release = release;

		n = aiowrite(fso, bf, size, (off_t)bno * sectorsize,
		    SEEK_SET, &transp->resultbuf);

		if (n < 0) {
			/*
			 * The aiowrite() may have failed because the
			 * kernel didn't have enough memory to do the job.
			 * Flush all pending writes and try a normal
			 * write().  wtfs_breakup() will call exit if it
			 * fails, so we don't worry about errors here.
			 */
			flush_writes();
			wtfs_breakup(transp->bno, transp->size, transp->buffer);
			freetrans(transp);
		} else {
			/*
			 * Keep track of our pending writes.
			 */
			results.outstanding++;
			if (results.outstanding > results.maxpend)
				results.maxpend = results.outstanding;
		}
	}

	unblock_sigint(&old_mask);
}


/*
 * write a block to the file system, but break it up into sbsize
 * chunks to avoid forcing a large amount of memory to be locked down.
 * Only used as a fallback when an aio write has failed.
 */
static void
wtfs_breakup(diskaddr_t bno, int size, char *bf)
{
	int n, saverr;
	int wsize;
	int block_incr = sbsize / sectorsize;

	if (size < sbsize)
		wsize = size;
	else
		wsize = sbsize;

	n = 0;
	while (size) {
		/*
		 * Note: the llseek() can succeed, even if the offset is
		 * out of range.  It's not until the file i/o operation
		 * (the write()) that one knows for sure if the raw device
		 * can handle the offset.
		 */
		if (llseek(fso, (offset_t)bno * sectorsize, 0) < 0) {
			saverr = errno;
			(void) fprintf(stderr,
			    gettext("seek error on sector %lld: %s\n"),
			    bno, strerror(saverr));
			lockexit(32);
		}

		n = write(fso, bf, wsize);
		if (n == -1) {
			saverr = errno;
			(void) fprintf(stderr,
			    gettext("write error on sector %lld: %s\n"),
			    bno, strerror(saverr));
			lockexit(32);
		}
		if (n != wsize) {
			saverr = errno;
			(void) fprintf(stderr, gettext(
			    "short write (%d of %d bytes) on sector %lld\n"),
			    n, size, bno);
			lockexit(32);
		}

		bno += block_incr;
		bf += wsize;
		size -= wsize;
		if (size < wsize)
			wsize = size;
	}
}


/*
 * check if a block is available
 */
static int
isblock(struct fs *fs, unsigned char *cp, int h)
{
	unsigned char mask;

	switch (fs->fs_frag) {
	case 8:
		return (cp[h] == 0xff);
	case 4:
		mask = 0x0f << ((h & 0x1) << 2);
		return ((cp[h >> 1] & mask) == mask);
	case 2:
		mask = 0x03 << ((h & 0x3) << 1);
		return ((cp[h >> 2] & mask) == mask);
	case 1:
		mask = 0x01 << (h & 0x7);
		return ((cp[h >> 3] & mask) == mask);
	default:
		(void) fprintf(stderr, "isblock bad fs_frag %d\n", fs->fs_frag);
		return (0);
	}
}

/*
 * take a block out of the map
 */
static void
clrblock(struct fs *fs, unsigned char *cp, int h)
{
	switch ((fs)->fs_frag) {
	case 8:
		cp[h] = 0;
		return;
	case 4:
		cp[h >> 1] &= ~(0x0f << ((h & 0x1) << 2));
		return;
	case 2:
		cp[h >> 2] &= ~(0x03 << ((h & 0x3) << 1));
		return;
	case 1:
		cp[h >> 3] &= ~(0x01 << (h & 0x7));
		return;
	default:
		(void) fprintf(stderr,
		    gettext("clrblock: bad fs_frag value %d\n"), fs->fs_frag);
		return;
	}
}

/*
 * put a block into the map
 */
static void
setblock(struct fs *fs, unsigned char *cp, int h)
{
	switch (fs->fs_frag) {
	case 8:
		cp[h] = 0xff;
		return;
	case 4:
		cp[h >> 1] |= (0x0f << ((h & 0x1) << 2));
		return;
	case 2:
		cp[h >> 2] |= (0x03 << ((h & 0x3) << 1));
		return;
	case 1:
		cp[h >> 3] |= (0x01 << (h & 0x7));
		return;
	default:
		(void) fprintf(stderr,
		    gettext("setblock: bad fs_frag value %d\n"), fs->fs_frag);
		return;
	}
}

static void
usage()
{
	(void) fprintf(stderr,
	    gettext("ufs usage: mkfs [-F FSType] [-V] [-m] [-o options] "
	    "special "				/* param 0 */
	    "size(sectors) \\ \n"));		/* param 1 */
	(void) fprintf(stderr,
	    "[nsect "				/* param 2 */
	    "ntrack "				/* param 3 */
	    "bsize "				/* param 4 */
	    "fragsize "				/* param 5 */
	    "cpg "				/* param 6 */
	    "free "				/* param 7 */
	    "rps "				/* param 8 */
	    "nbpi "				/* param 9 */
	    "opt "				/* param 10 */
	    "apc "				/* param 11 */
	    "gap "				/* param 12 */
	    "nrpos "				/* param 13 */
	    "maxcontig "			/* param 14 */
	    "mtb]\n");				/* param 15 */
	(void) fprintf(stderr,
	    gettext(" -m : dump fs cmd line used to make this partition\n"
	    " -V :print this command line and return\n"
	    " -o :ufs options: :nsect=%d,ntrack=%d,bsize=%d,fragsize=%d\n"
	    " -o :ufs options: :cgsize=%d,free=%d,rps=%d,nbpi=%d,opt=%c\n"
	    " -o :ufs options: :apc=%d,gap=%d,nrpos=%d,maxcontig=%d\n"
	    " -o :ufs options: :mtb=%c,calcsb,calcbinsb\n"
"NOTE that all -o suboptions: must be separated only by commas so as to\n"
"be parsed as a single argument\n"),
	    nsect, ntrack, bsize, fragsize, cpg, sblock.fs_minfree, rps,
	    nbpi, opt, apc, (rotdelay == -1) ? 0 : rotdelay,
	    sblock.fs_nrpos, maxcontig, mtb);
	lockexit(32);
}

/*ARGSUSED*/
static void
dump_fscmd(char *fsys, int fsi)
{
	int64_t used, bpcg, inospercg;
	int64_t nbpi;
	uint64_t nbytes64;

	bzero((char *)&sblock, sizeof (sblock));
	rdfs((diskaddr_t)SBLOCK, SBSIZE, (char *)&sblock);

	/*
	 * ensure a valid file system and if not, exit with error or else
	 * we will end up computing block numbers etc and dividing by zero
	 * which will cause floating point errors in this routine.
	 */

	if ((sblock.fs_magic != FS_MAGIC) &&
	    (sblock.fs_magic != MTB_UFS_MAGIC)) {
		(void) fprintf(stderr, gettext(
		    "[not currently a valid file system - bad superblock]\n"));
		lockexit(32);
	}

	if (sblock.fs_magic == FS_MAGIC &&
	    (sblock.fs_version != UFS_EFISTYLE4NONEFI_VERSION_2 &&
	    sblock.fs_version != UFS_VERSION_MIN)) {
		(void) fprintf(stderr, gettext(
		    "Unknown version of UFS format: %d\n"), sblock.fs_version);
		lockexit(32);
	}

	if (sblock.fs_magic == MTB_UFS_MAGIC &&
	    (sblock.fs_version > MTB_UFS_VERSION_1 ||
	    sblock.fs_version < MTB_UFS_VERSION_MIN)) {
		(void) fprintf(stderr, gettext(
		    "Unknown version of UFS format: %d\n"), sblock.fs_version);
		lockexit(32);
	}

	/*
	 * Compute a reasonable nbpi value.
	 * The algorithm for "used" is copied from code
	 * in main() verbatim.
	 * The nbpi equation is taken from main where the
	 * fs_ipg value is set for the last time.  The INOPB(...) - 1
	 * is used to account for the roundup.
	 * The problem is that a range of nbpi values map to
	 * the same file system layout.  So it is not possible
	 * to calculate the exact value specified when the file
	 * system was created.  So instead we determine the top
	 * end of the range of values.
	 */
	bpcg = sblock.fs_spc * sectorsize;
	inospercg = (int64_t)roundup(bpcg / sizeof (struct dinode),
	    INOPB(&sblock));
	if (inospercg > MAXIpG(&sblock))
		inospercg = MAXIpG(&sblock);
	used = (int64_t)
	    (sblock.fs_iblkno + inospercg / INOPF(&sblock)) * NSPF(&sblock);
	used *= sectorsize;
	nbytes64 = (uint64_t)sblock.fs_cpg * bpcg - used;

	/*
	 * The top end of the range of values for nbpi may not be
	 * a valid command line value for mkfs. Report the bottom
	 * end instead.
	 */
	nbpi = (int64_t)(nbytes64 / (sblock.fs_ipg));

	(void) fprintf(stdout, gettext("mkfs -F ufs -o "), fsys);
	(void) fprintf(stdout, "nsect=%d,ntrack=%d,",
	    sblock.fs_nsect, sblock.fs_ntrak);
	(void) fprintf(stdout, "bsize=%d,fragsize=%d,cgsize=%d,free=%d,",
	    sblock.fs_bsize, sblock.fs_fsize, sblock.fs_cpg, sblock.fs_minfree);
	(void) fprintf(stdout, "rps=%d,nbpi=%lld,opt=%c,apc=%d,gap=%d,",
	    sblock.fs_rps, nbpi, (sblock.fs_optim == FS_OPTSPACE) ? 's' : 't',
	    (sblock.fs_ntrak * sblock.fs_nsect) - sblock.fs_spc,
	    sblock.fs_rotdelay);
	(void) fprintf(stdout, "nrpos=%d,maxcontig=%d,mtb=%c ",
	    sblock.fs_nrpos, sblock.fs_maxcontig,
	    ((sblock.fs_magic == MTB_UFS_MAGIC) ? 'y' : 'n'));
	(void) fprintf(stdout, "%s %lld\n", fsys,
	    fsbtodb(&sblock, sblock.fs_size));

	bzero((char *)&sblock, sizeof (sblock));
}

/* number ************************************************************* */
/*									*/
/* Convert a numeric string arg to binary				*/
/*									*/
/* Args:	d_value - default value, if have parse error		*/
/*		param - the name of the argument, for error messages	*/
/*		flags - parser state and what's allowed in the arg	*/
/* Global arg:  string - pointer to command arg				*/
/*									*/
/* Valid forms: 123 | 123k | 123*123 | 123x123				*/
/*									*/
/* Return:	converted number					*/
/*									*/
/* ******************************************************************** */

static uint64_t
number(uint64_t d_value, char *param, int flags)
{
	char *cs;
	uint64_t n, t;
	uint64_t cut = BIG / 10;    /* limit to avoid overflow */
	int minus = 0;

	cs = string;
	if (*cs == '-') {
		minus = 1;
		cs += 1;
	}
	if ((*cs < '0') || (*cs > '9')) {
		goto bail_out;
	}
	n = 0;
	while ((*cs >= '0') && (*cs <= '9') && (n <= cut)) {
		n = n*10 + *cs++ - '0';
	}
	if (minus)
		n = -n;
	for (;;) {
		switch (*cs++) {
		case 'k':
			if (flags & ALLOW_END_ONLY)
				goto bail_out;
			if (n > (BIG / 1024))
				goto overflow;
			n *= 1024;
			continue;

		case '*':
		case 'x':
			if (flags & ALLOW_END_ONLY)
				goto bail_out;
			string = cs;
			t = number(d_value, param, flags);
			if (n > (BIG / t))
				goto overflow;
			n *= t;
			cs = string + 1; /* adjust for -- below */

			/* recursion has read rest of expression */
			/* FALLTHROUGH */

		case ',':
		case '\0':
			cs--;
			string = cs;
			return (n);

		case '%':
			if (flags & ALLOW_END_ONLY)
				goto bail_out;
			if (flags & ALLOW_PERCENT) {
				flags &= ~ALLOW_PERCENT;
				flags |= ALLOW_END_ONLY;
				continue;
			}
			goto bail_out;

		case 'm':
			if (flags & ALLOW_END_ONLY)
				goto bail_out;
			if (flags & ALLOW_MS1) {
				flags &= ~ALLOW_MS1;
				flags |= ALLOW_MS2;
				continue;
			}
			goto bail_out;

		case 's':
			if (flags & ALLOW_END_ONLY)
				goto bail_out;
			if (flags & ALLOW_MS2) {
				flags &= ~ALLOW_MS2;
				flags |= ALLOW_END_ONLY;
				continue;
			}
			goto bail_out;

		case '0': case '1': case '2': case '3': case '4':
		case '5': case '6': case '7': case '8': case '9':
overflow:
			(void) fprintf(stderr,
			    gettext("mkfs: value for %s overflowed\n"),
			    param);
			while ((*cs != '\0') && (*cs != ','))
				cs++;
			string = cs;
			return (BIG);

		default:
bail_out:
			(void) fprintf(stderr, gettext(
			    "mkfs: bad numeric arg for %s: \"%s\"\n"),
			    param, string);
			while ((*cs != '\0') && (*cs != ','))
				cs++;
			string = cs;
			if (d_value != NO_DEFAULT) {
				(void) fprintf(stderr,
				    gettext("mkfs: %s reset to default %lld\n"),
				    param, d_value);
				return (d_value);
			}
			lockexit(2);

		}
	} /* never gets here */
}

/* match ************************************************************** */
/*									*/
/* Compare two text strings for equality				*/
/*									*/
/* Arg:	 s - pointer to string to match with a command arg		*/
/* Global arg:  string - pointer to command arg				*/
/*									*/
/* Return:	1 if match, 0 if no match				*/
/*		If match, also reset `string' to point to the text	*/
/*		that follows the matching text.				*/
/*									*/
/* ******************************************************************** */

static int
match(char *s)
{
	char *cs;

	cs = string;
	while (*cs++ == *s) {
		if (*s++ == '\0') {
			goto true;
		}
	}
	if (*s != '\0') {
		return (0);
	}

true:
	cs--;
	string = cs;
	return (1);
}

/*
 * GROWFS ROUTINES
 */

/* ARGSUSED */
void
lockexit(int exitstatus)
{
	if (Pflag) {
		/* the probe mode neither changes nor locks the filesystem */
		exit(exitstatus);
	}

	/*
	 * flush the dirty cylinder group
	 */
	if (inlockexit == 0) {
		inlockexit = 1;
		flcg();
	}

	if (aio_inited) {
		flush_writes();
	}

	/*
	 * make sure the file system is unlocked before exiting
	 */
	if ((inlockexit == 1) && (!isbad)) {
		inlockexit = 2;
		ulockfs();
		/*
		 * if logging was enabled, then re-enable it
		 */
		if (waslog) {
			if (rl_log_control(fsys, _FIOLOGENABLE) != RL_SUCCESS) {
				(void) fprintf(stderr, gettext(
				    "failed to re-enable logging\n"));
			}
		}
	} else if (grow) {
		if (isbad) {
			(void) fprintf(stderr, gettext(
			    "Filesystem is currently inconsistent.  It "
			    "must be repaired with fsck(1M)\nbefore being "
			    "used.  Use the following command to "
			    "do this:\n\n\tfsck %s\n\n"), fsys);

			if (ismounted) {
				(void) fprintf(stderr, gettext(
				    "You will be told that the filesystem "
				    "is already mounted, and asked if you\n"
				    "wish to continue.  Answer `yes' to "
				    "this question.\n\n"));
			}

			(void) fprintf(stderr, gettext(
			    "One problem should be reported, that the summary "
			    "information is bad.\nYou will then be asked if it "
			    "should be salvaged.  Answer `yes' to\nthis "
			    "question.\n\n"));
		}

		if (ismounted) {
			/*
			 * In theory, there's no way to get here without
			 * isbad also being set, but be robust in the
			 * face of future code changes.
			 */
			(void) fprintf(stderr, gettext(
			    "The filesystem is currently mounted "
			    "read-only and write-locked.  "));
			if (isbad) {
				(void) fprintf(stderr, gettext(
				    "After\nrunning fsck, unlock the "
				    "filesystem and "));
			} else {
				(void) fprintf(stderr, gettext(
				    "Unlock the filesystem\nand "));
			}

			(void) fprintf(stderr, gettext(
			    "re-enable writing with\nthe following "
			    "command:\n\n\tlockfs -u %s\n\n"), directory);
		}
	}

	exit(exitstatus);
}

void
randomgeneration()
{
	int		 i;
	struct dinode	*dp;

	/*
	 * always perform fsirand(1) function... newfs will notice that
	 * the inodes have been randomized and will not call fsirand itself
	 */
	for (i = 0, dp = zino; i < sblock.fs_inopb; ++i, ++dp)
		IRANDOMIZE(&dp->di_ic);
}

/*
 * Check the size of the summary information.
 * Fields in sblock are not changed in this function.
 *
 * For an 8K filesystem block, the maximum number of cylinder groups is 16384.
 *     MAXCSBUFS {32}  *   8K  {FS block size}
 *                         divided by (sizeof csum) {16}
 *
 * Note that MAXCSBUFS is not used in the kernel; as of Solaris 2.6 build 32,
 * this is the only place where it's referenced.
 */
void
checksummarysize()
{
	diskaddr_t	dmax;
	diskaddr_t	dmin;
	int64_t	cg0frags;
	int64_t	cg0blocks;
	int64_t	maxncg;
	int64_t	maxfrags;
	uint64_t	fs_size;
	uint64_t maxfs_blocks; /* filesystem blocks for max filesystem size */

	/*
	 * compute the maximum summary info size
	 */
	dmin = cgdmin(&sblock, 0);
	dmax = cgbase(&sblock, 0) + sblock.fs_fpg;
	fs_size = (grow) ? grow_fs_size : sblock.fs_size;
	if (dmax > fs_size)
		dmax = fs_size;
	cg0frags  = dmax - dmin;
	cg0blocks = cg0frags / sblock.fs_frag;
	cg0frags = cg0blocks * sblock.fs_frag;
	maxncg   = (longlong_t)cg0blocks *
	    (longlong_t)(sblock.fs_bsize / sizeof (struct csum));

	maxfs_blocks = FS_MAX;

	if (maxncg > ((longlong_t)maxfs_blocks / (longlong_t)sblock.fs_fpg) + 1)
		maxncg = ((longlong_t)maxfs_blocks /
		    (longlong_t)sblock.fs_fpg) + 1;

	maxfrags = maxncg * (longlong_t)sblock.fs_fpg;

	if (maxfrags > maxfs_blocks)
		maxfrags = maxfs_blocks;


	/*
	 * remember for later processing in extendsummaryinfo()
	 */
	if (test)
		grow_sifrag = dmin + (cg0blocks * sblock.fs_frag);
	if (testfrags == 0)
		testfrags = cg0frags;
	if (testforce)
		if (testfrags > cg0frags) {
			(void) fprintf(stderr,
			    gettext("Too many test frags (%lld); "
			    "try %lld\n"), testfrags, cg0frags);
			lockexit(32);
		}

	/*
	 * if summary info is too large (too many cg's) tell the user and exit
	 */
	if ((longlong_t)sblock.fs_size > maxfrags) {
		(void) fprintf(stderr, gettext(
		    "Too many cylinder groups with %llu sectors;\n    try "
		    "increasing cgsize, or decreasing fssize to %llu\n"),
		    fsbtodb(&sblock, (uint64_t)sblock.fs_size),
		    fsbtodb(&sblock, (uint64_t)maxfrags));
		lockexit(32);
	}
}

/*
 * checksblock() has two uses:
 *	- One is to sanity test the superblock and is used when newfs(1M)
 *	  is invoked with the "-N" option. If any discrepancy was found,
 *	  just return whatever error was found and do not exit.
 *	- the other use of it is in places where you expect the superblock
 *	  to be sane, and if it isn't, then we exit.
 * Which of the above two actions to take is indicated with the second argument.
 */

int
checksblock(struct fs sb, int proceed)
{
	int err = 0;
	char *errmsg;

	if ((sb.fs_magic != FS_MAGIC) && (sb.fs_magic != MTB_UFS_MAGIC)) {
		err = 1;
		errmsg = gettext("Bad superblock; magic number wrong\n");
	} else if ((sb.fs_magic == FS_MAGIC &&
	    (sb.fs_version != UFS_EFISTYLE4NONEFI_VERSION_2 &&
	    sb.fs_version != UFS_VERSION_MIN)) ||
	    (sb.fs_magic == MTB_UFS_MAGIC &&
	    (sb.fs_version > MTB_UFS_VERSION_1 ||
	    sb.fs_version < MTB_UFS_VERSION_MIN))) {
		err = 2;
		errmsg = gettext("Unrecognized version of UFS\n");
	} else if (sb.fs_ncg < 1) {
		err = 3;
		errmsg = gettext("Bad superblock; ncg out of range\n");
	} else if (sb.fs_cpg < 1) {
		err = 4;
		errmsg = gettext("Bad superblock; cpg out of range\n");
	} else if (sb.fs_ncg * sb.fs_cpg < sb.fs_ncyl ||
	    (sb.fs_ncg - 1) * sb.fs_cpg >= sb.fs_ncyl) {
		err = 5;
		errmsg = gettext("Bad superblock; ncyl out of range\n");
	} else if (sb.fs_sbsize <= 0 || sb.fs_sbsize > sb.fs_bsize) {
		err = 6;
		errmsg = gettext("Bad superblock; superblock size out of "
		    "range\n");
	}

	if (proceed) {
		if (err) dprintf(("%s", errmsg));
		return (err);
	}

	if (err) {
		fprintf(stderr, "%s", errmsg);
		lockexit(32);
	}
	return (32);
}

/*
 * Roll the embedded log, if any, and set up the global variables
 * islog and islogok.
 */
static void
logsetup(char *devstr)
{
	void		*buf, *ud_buf;
	extent_block_t	*ebp;
	ml_unit_t	*ul;
	ml_odunit_t	*ud;

	/*
	 * Does the superblock indicate that we are supposed to have a log ?
	 */
	if (sblock.fs_logbno == 0) {
		/*
		 * No log present, nothing to do.
		 */
		islog = 0;
		islogok = 0;
		return;
	} else {
		/*
		 * There's a log in a yet unknown state, attempt to roll it.
		 */
		islogok = 0;

		/*
		 * We failed to roll the log, bail out.
		 */
		if (rl_roll_log(devstr) != RL_SUCCESS)
			return;

		islog = 1;

		/* log is not okay; check the fs */
		if ((FSOKAY != (sblock.fs_state + sblock.fs_time)) ||
		    (sblock.fs_clean != FSLOG))
			return;

		/* get the log allocation block */
		buf = (void *)malloc(DEV_BSIZE);
		if (buf == (void *) NULL)
			return;

		ud_buf = (void *)malloc(DEV_BSIZE);
		if (ud_buf == (void *) NULL) {
			free(buf);
			return;
		}

		rdfs((diskaddr_t)logbtodb(&sblock, sblock.fs_logbno),
		    DEV_BSIZE, buf);
		ebp = (extent_block_t *)buf;

		/* log allocation block is not okay; check the fs */
		if (ebp->type != LUFS_EXTENTS) {
			free(buf);
			free(ud_buf);
			return;
		}

		/* get the log state block(s) */
		rdfs((diskaddr_t)logbtodb(&sblock, ebp->extents[0].pbno),
		    DEV_BSIZE, ud_buf);
		ud = (ml_odunit_t *)ud_buf;
		ul = (ml_unit_t *)malloc(sizeof (*ul));
		ul->un_ondisk = *ud;

		/* log state is okay */
		if ((ul->un_chksum == ul->un_head_ident + ul->un_tail_ident) &&
		    (ul->un_version == LUFS_VERSION_LATEST) &&
		    (ul->un_badlog == 0))
			islogok = 1;
		free(ud_buf);
		free(buf);
		free(ul);
	}
}

void
growinit(char *devstr)
{
	int	i;
	char	buf[DEV_BSIZE];

	/*
	 * Read and verify the superblock
	 */
	rdfs((diskaddr_t)(SBOFF / sectorsize), (int)sbsize, (char *)&sblock);
	(void) checksblock(sblock, 0);
	if (sblock.fs_postblformat != FS_DYNAMICPOSTBLFMT) {
		(void) fprintf(stderr,
		    gettext("old file system format; can't growfs\n"));
		lockexit(32);
	}

	/*
	 * can't shrink a file system
	 */
	grow_fssize = fsbtodb(&sblock, (uint64_t)sblock.fs_size);
	if (fssize_db < grow_fssize) {
		(void) fprintf(stderr,
		    gettext("%lld sectors < current size of %lld sectors\n"),
		    fssize_db, grow_fssize);
		lockexit(32);
	}

	/*
	 * can't grow a system to over a terabyte unless it was set up
	 * as an MTB UFS file system.
	 */
	if (mtb == 'y' && sblock.fs_magic != MTB_UFS_MAGIC) {
		if (fssize_db >= SECTORS_PER_TERABYTE) {
			(void) fprintf(stderr, gettext(
"File system was not set up with the multi-terabyte format.\n"));
			(void) fprintf(stderr, gettext(
"Its size cannot be increased to a terabyte or more.\n"));
		} else {
			(void) fprintf(stderr, gettext(
"Cannot convert file system to multi-terabyte format.\n"));
		}
		lockexit(32);
	}

	logsetup(devstr);

	/*
	 * can't growfs when logging device has errors
	 */
	if ((islog && !islogok) ||
	    ((FSOKAY == (sblock.fs_state + sblock.fs_time)) &&
	    (sblock.fs_clean == FSLOG && !islog))) {
		(void) fprintf(stderr,
		    gettext("logging device has errors; can't growfs\n"));
		lockexit(32);
	}

	/*
	 * disable ufs logging for growing
	 */
	if (islog) {
		if (rl_log_control(devstr, _FIOLOGDISABLE) != RL_SUCCESS) {
			(void) fprintf(stderr, gettext(
			    "failed to disable logging\n"));
			lockexit(32);
		}
		islog = 0;
		waslog = 1;
	}

	/*
	 * if mounted write lock the file system to be grown
	 */
	if (ismounted)
		wlockfs();

	/*
	 * refresh dynamic superblock state - disabling logging will have
	 * changed the amount of free space available in the file system
	 */
	rdfs((diskaddr_t)(SBOFF / sectorsize), sbsize, (char *)&sblock);

	/*
	 * make sure device is big enough
	 */
	rdfs((diskaddr_t)fssize_db - 1, DEV_BSIZE, buf);
	wtfs((diskaddr_t)fssize_db - 1, DEV_BSIZE, buf);

	/*
	 * read current summary information
	 */
	grow_fscs = read_summaryinfo(&sblock);

	/*
	 * save some current size related fields from the superblock
	 * These are used in extendsummaryinfo()
	 */
	grow_fs_size	= sblock.fs_size;
	grow_fs_ncg	= sblock.fs_ncg;
	grow_fs_csaddr	= (diskaddr_t)sblock.fs_csaddr;
	grow_fs_cssize	= sblock.fs_cssize;

	/*
	 * save and reset the clean flag
	 */
	if (FSOKAY == (sblock.fs_state + sblock.fs_time))
		grow_fs_clean = sblock.fs_clean;
	else
		grow_fs_clean = FSBAD;
	sblock.fs_clean = FSBAD;
	sblock.fs_state = FSOKAY - sblock.fs_time;
	isbad = 1;
	wtfs((diskaddr_t)(SBOFF / sectorsize), sbsize, (char *)&sblock);
}

void
checkdev(char *rdev, char *bdev)
{
	struct stat64	statarea;

	if (stat64(bdev, &statarea) < 0) {
		(void) fprintf(stderr, gettext("can't check mount point; "));
		(void) fprintf(stderr, gettext("can't stat %s\n"), bdev);
		lockexit(32);
	}
	if ((statarea.st_mode & S_IFMT) != S_IFBLK) {
		(void) fprintf(stderr, gettext(
		    "can't check mount point; %s is not a block device\n"),
		    bdev);
		lockexit(32);
	}
	if (stat64(rdev, &statarea) < 0) {
		(void) fprintf(stderr, gettext("can't stat %s\n"), rdev);
		lockexit(32);
	}
	if ((statarea.st_mode & S_IFMT) != S_IFCHR) {
		(void) fprintf(stderr,
		    gettext("%s is not a character device\n"), rdev);
		lockexit(32);
	}
}

void
checkmount(struct mnttab *mntp, char *bdevname)
{
	struct stat64	statdir;
	struct stat64	statdev;

	if (strcmp(bdevname, mntp->mnt_special) == 0) {
		if (stat64(mntp->mnt_mountp, &statdir) == -1) {
			(void) fprintf(stderr, gettext("can't stat %s\n"),
			    mntp->mnt_mountp);
			lockexit(32);
		}
		if (stat64(mntp->mnt_special, &statdev) == -1) {
			(void) fprintf(stderr, gettext("can't stat %s\n"),
			    mntp->mnt_special);
			lockexit(32);
		}
		if (statdir.st_dev != statdev.st_rdev) {
			(void) fprintf(stderr, gettext(
			    "%s is not mounted on %s; mnttab(4) wrong\n"),
			    mntp->mnt_special, mntp->mnt_mountp);
			lockexit(32);
		}
		ismounted = 1;
		if (directory) {
			if (strcmp(mntp->mnt_mountp, directory) != 0) {
				(void) fprintf(stderr,
				    gettext("%s is mounted on %s, not %s\n"),
				    bdevname, mntp->mnt_mountp, directory);
				lockexit(32);
			}
		} else {
			if (grow)
				(void) fprintf(stderr, gettext(
				    "%s is mounted on %s; can't growfs\n"),
				    bdevname, mntp->mnt_mountp);
			else
				(void) fprintf(stderr,
				    gettext("%s is mounted, can't mkfs\n"),
				    bdevname);
			lockexit(32);
		}
	}
}

struct dinode	*dibuf	= 0;
diskaddr_t	difrag	= 0;

struct dinode *
gdinode(ino_t ino)
{
	/*
	 * read the block of inodes containing inode number ino
	 */
	if (dibuf == 0)
		dibuf = (struct dinode *)malloc((unsigned)sblock.fs_bsize);
	if (itod(&sblock, ino) != difrag) {
		difrag = itod(&sblock, ino);
		rdfs(fsbtodb(&sblock, (uint64_t)difrag), (int)sblock.fs_bsize,
		    (char *)dibuf);
	}
	return (dibuf + (ino % INOPB(&sblock)));
}

/*
 * structure that manages the frags we need for extended summary info
 *	These frags can be:
 *		free
 *		data  block
 *		alloc block
 */
struct csfrag {
	struct csfrag	*next;		/* next entry */
	daddr32_t	 ofrag;		/* old frag */
	daddr32_t	 nfrag;		/* new frag */
	long		 cylno;		/* cylno of nfrag */
	long		 frags;		/* number of frags */
	long		 size;		/* size in bytes */
	ino_t		 ino;		/* inode number */
	long		 fixed;		/* Boolean - Already fixed? */
};
struct csfrag	*csfrag;		/* state unknown */
struct csfrag	*csfragino;		/* frags belonging to an inode */
struct csfrag	*csfragfree;		/* frags that are free */

daddr32_t maxcsfrag	= 0;		/* maximum in range */
daddr32_t mincsfrag	= 0x7fffffff;	/* minimum in range */

int
csfraginrange(daddr32_t frag)
{
	return ((frag >= mincsfrag) && (frag <= maxcsfrag));
}

struct csfrag *
findcsfrag(daddr32_t frag, struct csfrag **cfap)
{
	struct csfrag	*cfp;

	if (!csfraginrange(frag))
		return (NULL);

	for (cfp = *cfap; cfp; cfp = cfp->next)
		if (cfp->ofrag == frag)
			return (cfp);
	return (NULL);
}

void
checkindirect(ino_t ino, daddr32_t *fragsp, daddr32_t frag, int level)
{
	int			i;
	int			ne	= sblock.fs_bsize / sizeof (daddr32_t);
	daddr32_t			fsb[MAXBSIZE / sizeof (daddr32_t)];

	if (frag == 0)
		return;

	rdfs(fsbtodb(&sblock, frag), (int)sblock.fs_bsize,
	    (char *)fsb);

	checkdirect(ino, fragsp, fsb, sblock.fs_bsize / sizeof (daddr32_t));

	if (level)
		for (i = 0; i < ne && *fragsp; ++i)
			checkindirect(ino, fragsp, fsb[i], level-1);
}

void
addcsfrag(ino_t ino, daddr32_t frag, struct csfrag **cfap)
{
	struct csfrag	*cfp, *curr, *prev;

	/*
	 * establish a range for faster checking in csfraginrange()
	 */
	if (frag > maxcsfrag)
		maxcsfrag = frag;
	if (frag < mincsfrag)
		mincsfrag = frag;

	/*
	 * if this frag belongs to an inode and is not the start of a block
	 *	then see if it is part of a frag range for this inode
	 */
	if (ino && (frag % sblock.fs_frag))
		for (cfp = *cfap; cfp; cfp = cfp->next) {
			if (ino != cfp->ino)
				continue;
			if (frag != cfp->ofrag + cfp->frags)
				continue;
			cfp->frags++;
			cfp->size += sblock.fs_fsize;
			return;
		}
	/*
	 * allocate a csfrag entry and insert it in an increasing order into the
	 * specified list
	 */
	cfp = (struct csfrag *)calloc(1, sizeof (struct csfrag));
	cfp->ino	= ino;
	cfp->ofrag	= frag;
	cfp->frags	= 1;
	cfp->size	= sblock.fs_fsize;
	for (prev = NULL, curr = *cfap; curr != NULL;
	    prev = curr, curr = curr->next) {
		if (frag < curr->ofrag) {
			cfp->next = curr;
			if (prev)
				prev->next = cfp;	/* middle element */
			else
				*cfap = cfp;		/* first element */
			break;
		}
		if (curr->next == NULL) {
			curr->next = cfp;		/* last element	*/
			break;
		}
	}
	if (*cfap == NULL)	/* will happen only once */
		*cfap = cfp;
}

void
delcsfrag(daddr32_t frag, struct csfrag **cfap)
{
	struct csfrag	*cfp;
	struct csfrag	**cfpp;

	/*
	 * free up entry whose beginning frag matches
	 */
	for (cfpp = cfap; *cfpp; cfpp = &(*cfpp)->next) {
		if (frag == (*cfpp)->ofrag) {
			cfp = *cfpp;
			*cfpp = (*cfpp)->next;
			free((char *)cfp);
			return;
		}
	}
}

/*
 * See whether any of the direct blocks in the array pointed by "db" and of
 * length "ne" are within the range of frags needed to extend the cylinder
 * summary. If so, remove those frags from the "as-yet-unclassified" list
 * (csfrag) and add them to the "owned-by-inode" list (csfragino).
 * For each such frag found, decrement the frag count pointed to by fragsp.
 * "ino" is the inode that contains (either directly or indirectly) the frags
 * being checked.
 */
void
checkdirect(ino_t ino, daddr32_t *fragsp, daddr32_t *db, int ne)
{
	int	 i;
	int	 j;
	int	 found;
	diskaddr_t	 frag;

	/*
	 * scan for allocation within the new summary info range
	 */
	for (i = 0; i < ne && *fragsp; ++i) {
		if ((frag = *db++) != 0) {
			found = 0;
			for (j = 0; j < sblock.fs_frag && *fragsp; ++j) {
				if (found || (found = csfraginrange(frag))) {
					addcsfrag(ino, frag, &csfragino);
					delcsfrag(frag, &csfrag);
				}
				++frag;
				--(*fragsp);
			}
		}
	}
}

void
findcsfragino()
{
	int		 i;
	int		 j;
	daddr32_t		 frags;
	struct dinode	*dp;

	/*
	 * scan all old inodes looking for allocations in the new
	 * summary info range.  Move the affected frag from the
	 * generic csfrag list onto the `owned-by-inode' list csfragino.
	 */
	for (i = UFSROOTINO; i < grow_fs_ncg*sblock.fs_ipg && csfrag; ++i) {
		dp = gdinode((ino_t)i);
		switch (dp->di_mode & IFMT) {
			case IFSHAD	:
			case IFLNK 	:
			case IFDIR 	:
			case IFREG 	: break;
			default		: continue;
		}

		frags   = dbtofsb(&sblock, dp->di_blocks);

		checkdirect((ino_t)i, &frags, &dp->di_db[0], NDADDR+NIADDR);
		for (j = 0; j < NIADDR && frags; ++j) {
			/* Negate the block if its an fallocate'd block */
			if (dp->di_ib[j] < 0 && dp->di_ib[j] != UFS_HOLE)
				checkindirect((ino_t)i, &frags,
				    -(dp->di_ib[j]), j);
			else
				checkindirect((ino_t)i, &frags,
				    dp->di_ib[j], j);
		}
	}
}

void
fixindirect(daddr32_t frag, int level)
{
	int			 i;
	int			 ne	= sblock.fs_bsize / sizeof (daddr32_t);
	daddr32_t			fsb[MAXBSIZE / sizeof (daddr32_t)];

	if (frag == 0)
		return;

	rdfs(fsbtodb(&sblock, (uint64_t)frag), (int)sblock.fs_bsize,
	    (char *)fsb);

	fixdirect((caddr_t)fsb, frag, fsb, ne);

	if (level)
		for (i = 0; i < ne; ++i)
			fixindirect(fsb[i], level-1);
}

void
fixdirect(caddr_t bp, daddr32_t frag, daddr32_t *db, int ne)
{
	int	 i;
	struct csfrag	*cfp;

	for (i = 0; i < ne; ++i, ++db) {
		if (*db == 0)
			continue;
		if ((cfp = findcsfrag(*db, &csfragino)) == NULL)
			continue;
		*db = cfp->nfrag;
		cfp->fixed = 1;
		wtfs(fsbtodb(&sblock, (uint64_t)frag), (int)sblock.fs_bsize,
		    bp);
	}
}

void
fixcsfragino()
{
	int		 i;
	struct dinode	*dp;
	struct csfrag	*cfp;

	for (cfp = csfragino; cfp; cfp = cfp->next) {
		if (cfp->fixed)
			continue;
		dp = gdinode((ino_t)cfp->ino);
		fixdirect((caddr_t)dibuf, difrag, dp->di_db, NDADDR+NIADDR);
		for (i = 0; i < NIADDR; ++i)
			fixindirect(dp->di_ib[i], i);
	}
}

/*
 * Read the cylinders summary information specified by settings in the
 * passed 'fs' structure into a new allocated array of csum structures.
 * The caller is responsible for freeing the returned array.
 * Return a pointer to an array of csum structures.
 */
static struct csum *
read_summaryinfo(struct	fs *fsp)
{
	struct csum 	*csp;
	int		i;

	if ((csp = malloc((size_t)fsp->fs_cssize)) == NULL) {
		(void) fprintf(stderr, gettext("cannot create csum list,"
		    " not enough memory\n"));
		exit(32);
	}

	for (i = 0; i < fsp->fs_cssize; i += fsp->fs_bsize) {
		rdfs(fsbtodb(fsp,
		    (uint64_t)(fsp->fs_csaddr + numfrags(fsp, i))),
		    (int)(fsp->fs_cssize - i < fsp->fs_bsize ?
		    fsp->fs_cssize - i : fsp->fs_bsize), ((caddr_t)csp) + i);
	}

	return (csp);
}

/*
 * Check the allocation of fragments that are to be made part of a csum block.
 * A fragment is allocated if it is either in the csfragfree list or, it is
 * in the csfragino list and has new frags associated with it.
 * Return the number of allocated fragments.
 */
int64_t
checkfragallocated(daddr32_t frag)
{
	struct 	csfrag	*cfp;
	/*
	 * Since the lists are sorted we can break the search if the asked
	 * frag is smaller then the one in the list.
	 */
	for (cfp = csfragfree; cfp != NULL && frag >= cfp->ofrag;
	    cfp = cfp->next) {
		if (frag == cfp->ofrag)
			return (1);
	}
	for (cfp = csfragino; cfp != NULL && frag >= cfp->ofrag;
	    cfp = cfp->next) {
		if (frag == cfp->ofrag && cfp->nfrag != 0)
			return (cfp->frags);
	}

	return (0);
}

/*
 * Figure out how much the filesystem can be grown. The limiting factor is
 * the available free space needed to extend the cg summary info block.
 * The free space is determined in three steps:
 * - Try to extend the cg summary block to the required size.
 * - Find free blocks in last cg.
 * - Find free space in the last already allocated fragment of the summary info
 *   block, and use it for additional csum structures.
 * Return the maximum size of the new filesystem or 0 if it can't be grown.
 * Please note that this function leaves the global list pointers csfrag,
 * csfragfree, and csfragino initialized, and the caller is responsible for
 * freeing the lists.
 */
diskaddr_t
probe_summaryinfo()
{
	/* fragments by which the csum block can be extended. */
	int64_t 	growth_csum_frags = 0;
	/* fragments by which the filesystem can be extended. */
	int64_t		growth_fs_frags = 0;
	int64_t		new_fs_cssize;	/* size of csum blk in the new FS */
	int64_t		new_fs_ncg;	/* number of cg in the new FS */
	int64_t 	spare_csum;
	daddr32_t	oldfrag_daddr;
	daddr32_t	newfrag_daddr;
	daddr32_t	daddr;
	int		i;

	/*
	 * read and verify the superblock
	 */
	rdfs((diskaddr_t)(SBOFF / sectorsize), (int)sbsize, (char *)&sblock);
	(void) checksblock(sblock, 0);

	/*
	 * check how much we can extend the cg summary info block
	 */

	/*
	 * read current summary information
	 */
	fscs = read_summaryinfo(&sblock);

	/*
	 * build list of frags needed for cg summary info block extension
	 */
	oldfrag_daddr = howmany(sblock.fs_cssize, sblock.fs_fsize) +
	    sblock.fs_csaddr;
	new_fs_ncg = howmany(dbtofsb(&sblock, fssize_db), sblock.fs_fpg);
	new_fs_cssize = fragroundup(&sblock, new_fs_ncg * sizeof (struct csum));
	newfrag_daddr = howmany(new_fs_cssize, sblock.fs_fsize) +
	    sblock.fs_csaddr;
	/*
	 * add all of the frags that are required to grow the cyl summary to the
	 * csfrag list, which is the generic/unknown list, since at this point
	 * we don't yet know the state of those frags.
	 */
	for (daddr = oldfrag_daddr; daddr < newfrag_daddr; daddr++)
		addcsfrag((ino_t)0, daddr, &csfrag);

	/*
	 * filter free fragments and allocate them. Note that the free frags
	 * must be allocated first otherwise they could be grabbed by
	 * alloccsfragino() for data frags.
	 */
	findcsfragfree();
	alloccsfragfree();

	/*
	 * filter fragments owned by inodes and allocate them
	 */
	grow_fs_ncg = sblock.fs_ncg; /* findcsfragino() needs this glob. var. */
	findcsfragino();
	alloccsfragino();

	if (notenoughspace()) {
		/*
		 * check how many consecutive fragments could be allocated
		 * in both lists.
		 */
		int64_t tmp_frags;
		for (daddr = oldfrag_daddr; daddr < newfrag_daddr;
		    daddr += tmp_frags) {
			if ((tmp_frags = checkfragallocated(daddr)) > 0)
				growth_csum_frags += tmp_frags;
			else
				break;
		}
	} else {
		/*
		 * We have all we need for the new desired size,
		 * so clean up and report back.
		 */
		return (fssize_db);
	}

	/*
	 * given the number of fragments by which the csum block can be grown
	 * compute by how many new fragments the FS can be increased.
	 * It is the number of csum instances per fragment multiplied by
	 * `growth_csum_frags' and the number of fragments per cylinder group.
	 */
	growth_fs_frags = howmany(sblock.fs_fsize, sizeof (struct csum)) *
	    growth_csum_frags * sblock.fs_fpg;

	/*
	 * compute free fragments in the last cylinder group
	 */
	rdcg(sblock.fs_ncg - 1);
	growth_fs_frags += sblock.fs_fpg - acg.cg_ndblk;

	/*
	 * compute how many csum instances are unused in the old csum block.
	 * For each unused csum instance the FS can be grown by one cylinder
	 * group without extending the csum block.
	 */
	spare_csum = howmany(sblock.fs_cssize, sizeof (struct csum)) -
	    sblock.fs_ncg;
	if (spare_csum > 0)
		growth_fs_frags += spare_csum * sblock.fs_fpg;

	/*
	 * recalculate the new filesystem size in sectors, shorten it by
	 * the requested size `fssize_db' if necessary.
	 */
	if (growth_fs_frags > 0) {
		diskaddr_t sect;
		sect = (sblock.fs_size + growth_fs_frags) * sblock.fs_nspf;
		return ((sect > fssize_db) ? fssize_db : sect);
	}

	return (0);
}

void
extendsummaryinfo()
{
	int64_t		i;
	int		localtest	= test;
	int64_t		frags;
	daddr32_t		oldfrag;
	daddr32_t		newfrag;

	/*
	 * if no-write (-N), don't bother
	 */
	if (Nflag)
		return;

again:
	flcg();
	/*
	 * summary info did not change size -- do nothing unless in test mode
	 */
	if (grow_fs_cssize == sblock.fs_cssize)
		if (!localtest)
			return;

	/*
	 * build list of frags needed for additional summary information
	 */
	oldfrag = howmany(grow_fs_cssize, sblock.fs_fsize) + grow_fs_csaddr;
	newfrag = howmany(sblock.fs_cssize, sblock.fs_fsize) + grow_fs_csaddr;
	/*
	 * add all of the frags that are required to grow the cyl summary to the
	 * csfrag list, which is the generic/unknown list, since at this point
	 * we don't yet know the state of those frags.
	 */
	for (i = oldfrag, frags = 0; i < newfrag; ++i, ++frags)
		addcsfrag((ino_t)0, (diskaddr_t)i, &csfrag);
	/*
	 * reduce the number of data blocks in the file system (fs_dsize) by
	 * the number of frags that need to be added to the cyl summary
	 */
	sblock.fs_dsize -= (newfrag - oldfrag);

	/*
	 * In test mode, we move more data than necessary from
	 * cylinder group 0.  The lookup/allocate/move code can be
	 * better stressed without having to create HUGE file systems.
	 */
	if (localtest)
		for (i = newfrag; i < grow_sifrag; ++i) {
			if (frags >= testfrags)
				break;
			frags++;
			addcsfrag((ino_t)0, (diskaddr_t)i, &csfrag);
		}

	/*
	 * move frags to free or inode lists, depending on owner
	 */
	findcsfragfree();
	findcsfragino();

	/*
	 * if not all frags can be located, file system must be inconsistent
	 */
	if (csfrag) {
		isbad = 1;	/* should already be set, but make sure */
		lockexit(32);
	}

	/*
	 * allocate the free frags. Note that the free frags must be allocated
	 * first otherwise they could be grabbed by alloccsfragino() for data
	 * frags.
	 */
	alloccsfragfree();
	/*
	 * allocate extra space for inode frags
	 */
	alloccsfragino();

	/*
	 * not enough space
	 */
	if (notenoughspace()) {
		unalloccsfragfree();
		unalloccsfragino();
		if (localtest && !testforce) {
			localtest = 0;
			goto again;
		}
		(void) fprintf(stderr, gettext("Not enough free space\n"));
		lockexit(NOTENOUGHSPACE);
	}

	/*
	 * copy the data from old frags to new frags
	 */
	copycsfragino();

	/*
	 * fix the inodes to point to the new frags
	 */
	fixcsfragino();

	/*
	 * We may have moved more frags than we needed.  Free them.
	 */
	rdcg((long)0);
	for (i = newfrag; i <= maxcsfrag; ++i)
		setbit(cg_blksfree(&acg), i-cgbase(&sblock, 0));
	wtcg();

	flcg();
}

/*
 * Check if all fragments in the `csfragino' list were reallocated.
 */
int
notenoughspace()
{
	struct csfrag	*cfp;

	/*
	 * If any element in the csfragino array has a "new frag location"
	 * of 0, the allocfrags() function was unsuccessful in allocating
	 * space for moving the frag represented by this array element.
	 */
	for (cfp = csfragino; cfp; cfp = cfp->next)
		if (cfp->nfrag == 0)
			return (1);
	return (0);
}

void
unalloccsfragino()
{
	struct csfrag	*cfp;

	while ((cfp = csfragino) != NULL) {
		if (cfp->nfrag)
			freefrags(cfp->nfrag, cfp->frags, cfp->cylno);
		delcsfrag(cfp->ofrag, &csfragino);
	}
}

void
unalloccsfragfree()
{
	struct csfrag	*cfp;

	while ((cfp = csfragfree) != NULL) {
		freefrags(cfp->ofrag, cfp->frags, cfp->cylno);
		delcsfrag(cfp->ofrag, &csfragfree);
	}
}

/*
 * For each frag in the "as-yet-unclassified" list (csfrag), see if
 * it's free (i.e., its bit is set in the free frag bit map).  If so,
 * move it from the "as-yet-unclassified" list to the csfragfree list.
 */
void
findcsfragfree()
{
	struct csfrag	*cfp;
	struct csfrag	*cfpnext;

	/*
	 * move free frags onto the free-frag list
	 */
	rdcg((long)0);
	for (cfp = csfrag; cfp; cfp = cfpnext) {
		cfpnext = cfp->next;
		if (isset(cg_blksfree(&acg), cfp->ofrag - cgbase(&sblock, 0))) {
			addcsfrag(cfp->ino, cfp->ofrag, &csfragfree);
			delcsfrag(cfp->ofrag, &csfrag);
		}
	}
}

void
copycsfragino()
{
	struct csfrag	*cfp;
	char		buf[MAXBSIZE];

	/*
	 * copy data from old frags to newly allocated frags
	 */
	for (cfp = csfragino; cfp; cfp = cfp->next) {
		rdfs(fsbtodb(&sblock, (uint64_t)cfp->ofrag), (int)cfp->size,
		    buf);
		wtfs(fsbtodb(&sblock, (uint64_t)cfp->nfrag), (int)cfp->size,
		    buf);
	}
}

long	curcylno	= -1;
int	cylnodirty	= 0;

void
rdcg(long cylno)
{
	if (cylno != curcylno) {
		flcg();
		curcylno = cylno;
		rdfs(fsbtodb(&sblock, (uint64_t)cgtod(&sblock, curcylno)),
		    (int)sblock.fs_cgsize, (char *)&acg);
	}
}

void
flcg()
{
	if (cylnodirty) {
		if (debug && Pflag) {
			(void) fprintf(stderr,
			    "Assert: cylnodirty set in probe mode\n");
			return;
		}
		resetallocinfo();
		wtfs(fsbtodb(&sblock, (uint64_t)cgtod(&sblock, curcylno)),
		    (int)sblock.fs_cgsize, (char *)&acg);
		cylnodirty = 0;
	}
	curcylno = -1;
}

void
wtcg()
{
	if (!Pflag) {
		/* probe mode should never write to disk */
		cylnodirty = 1;
	}
}

void
allocfrags(long frags, daddr32_t *fragp, long *cylnop)
{
	int	 i;
	int	 j;
	long	 bits;
	long	 bit;

	/*
	 * Allocate a free-frag range in an old cylinder group
	 */
	for (i = 0, *fragp = 0; i < grow_fs_ncg; ++i) {
		if (((fscs+i)->cs_nffree < frags) && ((fscs+i)->cs_nbfree == 0))
			continue;
		rdcg((long)i);
		bit = bits = 0;
		while (findfreerange(&bit, &bits)) {
			if (frags <= bits)  {
				for (j = 0; j < frags; ++j)
					clrbit(cg_blksfree(&acg), bit+j);
				wtcg();
				*cylnop = i;
				*fragp  = bit + cgbase(&sblock, i);
				return;
			}
			bit += bits;
		}
	}
}

/*
 * Allocate space for frags that need to be moved in order to free up space for
 * expanding the cylinder summary info.
 * For each frag that needs to be moved (each frag or range of frags in
 * the csfragino list), allocate a new location and store the frag number
 * of that new location in the nfrag field of the csfrag struct.
 * If a new frag can't be allocated for any element in the csfragino list,
 * set the new frag number for that element to 0 and return immediately.
 * The notenoughspace() function will detect this condition.
 */
void
alloccsfragino()
{
	struct csfrag	*cfp;

	/*
	 * allocate space for inode frag ranges
	 */
	for (cfp = csfragino; cfp; cfp = cfp->next) {
		allocfrags(cfp->frags, &cfp->nfrag, &cfp->cylno);
		if (cfp->nfrag == 0)
			break;
	}
}

void
alloccsfragfree()
{
	struct csfrag	*cfp;

	/*
	 * allocate the free frags needed for extended summary info
	 */
	rdcg((long)0);

	for (cfp = csfragfree; cfp; cfp = cfp->next)
		clrbit(cg_blksfree(&acg), cfp->ofrag - cgbase(&sblock, 0));

	wtcg();
}

void
freefrags(daddr32_t frag, long frags, long cylno)
{
	int	i;

	/*
	 * free frags
	 */
	rdcg(cylno);
	for (i = 0; i < frags; ++i) {
		setbit(cg_blksfree(&acg), (frag+i) - cgbase(&sblock, cylno));
	}
	wtcg();
}

int
findfreerange(long *bitp, long *bitsp)
{
	long	 bit;

	/*
	 * find a range of free bits in a cylinder group bit map
	 */
	for (bit = *bitp, *bitsp = 0; bit < acg.cg_ndblk; ++bit)
		if (isset(cg_blksfree(&acg), bit))
			break;

	if (bit >= acg.cg_ndblk)
		return (0);

	*bitp  = bit;
	*bitsp = 1;
	for (++bit; bit < acg.cg_ndblk; ++bit, ++(*bitsp)) {
		if ((bit % sblock.fs_frag) == 0)
			break;
		if (isclr(cg_blksfree(&acg), bit))
			break;
	}
	return (1);
}

void
resetallocinfo()
{
	long	cno;
	long	bit;
	long	bits;

	/*
	 * Compute the free blocks/frags info and update the appropriate
	 * inmemory superblock, summary info, and cylinder group fields
	 */
	sblock.fs_cstotal.cs_nffree -= acg.cg_cs.cs_nffree;
	sblock.fs_cstotal.cs_nbfree -= acg.cg_cs.cs_nbfree;

	acg.cg_cs.cs_nffree = 0;
	acg.cg_cs.cs_nbfree = 0;

	bzero((caddr_t)acg.cg_frsum, sizeof (acg.cg_frsum));
	bzero((caddr_t)cg_blktot(&acg), (int)(acg.cg_iusedoff-acg.cg_btotoff));

	bit = bits = 0;
	while (findfreerange(&bit, &bits)) {
		if (bits == sblock.fs_frag) {
			acg.cg_cs.cs_nbfree++;
			cno = cbtocylno(&sblock, bit);
			cg_blktot(&acg)[cno]++;
			cg_blks(&sblock, &acg, cno)[cbtorpos(&sblock, bit)]++;
		} else {
			acg.cg_cs.cs_nffree += bits;
			acg.cg_frsum[bits]++;
		}
		bit += bits;
	}

	*(fscs + acg.cg_cgx) = acg.cg_cs;

	sblock.fs_cstotal.cs_nffree += acg.cg_cs.cs_nffree;
	sblock.fs_cstotal.cs_nbfree += acg.cg_cs.cs_nbfree;
}

void
extendcg(long cylno)
{
	int	i;
	diskaddr_t	dupper;
	diskaddr_t	cbase;
	diskaddr_t	dmax;

	/*
	 * extend the cylinder group at the end of the old file system
	 * if it was partially allocated becase of lack of space
	 */
	flcg();
	rdcg(cylno);

	dupper = acg.cg_ndblk;
	if (cylno == sblock.fs_ncg - 1)
		acg.cg_ncyl = sblock.fs_ncyl - (sblock.fs_cpg * cylno);
	else
		acg.cg_ncyl = sblock.fs_cpg;
	cbase = cgbase(&sblock, cylno);
	dmax = cbase + sblock.fs_fpg;
	if (dmax > sblock.fs_size)
		dmax = sblock.fs_size;
	acg.cg_ndblk = dmax - cbase;

	for (i = dupper; i < acg.cg_ndblk; ++i)
		setbit(cg_blksfree(&acg), i);

	sblock.fs_dsize += (acg.cg_ndblk - dupper);

	wtcg();
	flcg();
}

struct lockfs	lockfs;
int		lockfd;
int		islocked;
int		lockfskey;
char		lockfscomment[128];

void
ulockfs()
{
	/*
	 * if the file system was locked, unlock it before exiting
	 */
	if (islocked == 0)
		return;

	/*
	 * first, check if the lock held
	 */
	lockfs.lf_flags = LOCKFS_MOD;
	if (ioctl(lockfd, _FIOLFSS, &lockfs) == -1) {
		perror(directory);
		lockexit(32);
	}

	if (LOCKFS_IS_MOD(&lockfs)) {
		(void) fprintf(stderr,
		    gettext("FILE SYSTEM CHANGED DURING GROWFS!\n"));
		(void) fprintf(stderr,
		    gettext("   See lockfs(1), umount(1), and fsck(1)\n"));
		lockexit(32);
	}
	/*
	 * unlock the file system
	 */
	lockfs.lf_lock  = LOCKFS_ULOCK;
	lockfs.lf_flags = 0;
	lockfs.lf_key   = lockfskey;
	clockfs();
	if (ioctl(lockfd, _FIOLFS, &lockfs) == -1) {
		perror(directory);
		lockexit(32);
	}
}

void
wlockfs()
{

	/*
	 * if no-write (-N), don't bother
	 */
	if (Nflag)
		return;
	/*
	 * open the mountpoint, and write lock the file system
	 */
	if ((lockfd = open64(directory, O_RDONLY)) == -1) {
		perror(directory);
		lockexit(32);
	}

	/*
	 * check if it is already locked
	 */
	if (ioctl(lockfd, _FIOLFSS, &lockfs) == -1) {
		perror(directory);
		lockexit(32);
	}

	if (lockfs.lf_lock != LOCKFS_WLOCK) {
		lockfs.lf_lock  = LOCKFS_WLOCK;
		lockfs.lf_flags = 0;
		lockfs.lf_key   = 0;
		clockfs();
		if (ioctl(lockfd, _FIOLFS, &lockfs) == -1) {
			perror(directory);
			lockexit(32);
		}
	}
	islocked = 1;
	lockfskey = lockfs.lf_key;
}

void
clockfs()
{
	time_t	t;
	char	*ct;

	(void) time(&t);
	ct = ctime(&t);
	ct[strlen(ct)-1] = '\0';

	(void) sprintf(lockfscomment, "%s -- mkfs pid %d", ct, getpid());
	lockfs.lf_comlen  = strlen(lockfscomment)+1;
	lockfs.lf_comment = lockfscomment;
}

/*
 * Write the csum records and the superblock
 */
void
wtsb()
{
	long	i;

	/*
	 * write summary information
	 */
	for (i = 0; i < sblock.fs_cssize; i += sblock.fs_bsize)
		wtfs(fsbtodb(&sblock, (uint64_t)(sblock.fs_csaddr +
		    numfrags(&sblock, i))),
		    (int)(sblock.fs_cssize - i < sblock.fs_bsize ?
		    sblock.fs_cssize - i : sblock.fs_bsize),
		    ((char *)fscs) + i);

	/*
	 * write superblock
	 */
	sblock.fs_time = mkfstime;
	wtfs((diskaddr_t)(SBOFF / sectorsize), sbsize, (char *)&sblock);
}

/*
 * Verify that the optimization selection is reasonable, and advance
 * the global "string" appropriately.
 */
static char
checkopt(char *optim)
{
	char	opt;
	int	limit = strcspn(optim, ",");

	switch (limit) {
	case 0:	/* missing indicator (have comma or nul) */
		(void) fprintf(stderr, gettext(
		    "mkfs: missing optimization flag reset to `t' (time)\n"));
		opt = 't';
		break;

	case 1: /* single-character indicator */
		opt = *optim;
		if ((opt != 's') && (opt != 't')) {
			(void) fprintf(stderr, gettext(
		    "mkfs: bad optimization value `%c' reset to `t' (time)\n"),
			    opt);
			opt = 't';
		}
		break;

	default: /* multi-character indicator */
		(void) fprintf(stderr, gettext(
	    "mkfs: bad optimization value `%*.*s' reset to `t' (time)\n"),
		    limit, limit, optim);
		opt = 't';
		break;
	}

	string += limit;

	return (opt);
}

/*
 * Verify that the mtb selection is reasonable, and advance
 * the global "string" appropriately.
 */
static char
checkmtb(char *mtbarg)
{
	char	mtbc;
	int	limit = strcspn(mtbarg, ",");

	switch (limit) {
	case 0:	/* missing indicator (have comma or nul) */
		(void) fprintf(stderr, gettext(
		    "mkfs: missing mtb flag reset to `n' (no mtb support)\n"));
		mtbc = 'n';
		break;

	case 1: /* single-character indicator */
		mtbc = tolower(*mtbarg);
		if ((mtbc != 'y') && (mtbc != 'n')) {
			(void) fprintf(stderr, gettext(
		    "mkfs: bad mtb value `%c' reset to `n' (no mtb support)\n"),
			    mtbc);
			mtbc = 'n';
		}
		break;

	default: /* multi-character indicator */
		(void) fprintf(stderr, gettext(
	    "mkfs: bad mtb value `%*.*s' reset to `n' (no mtb support)\n"),
		    limit, limit, mtbarg);
		opt = 'n';
		break;
	}

	string += limit;

	return (mtbc);
}

/*
 * Verify that a value is in a range.  If it is not, resets it to
 * its default value if one is supplied, exits otherwise.
 *
 * When testing, can compare user_supplied to RC_KEYWORD or RC_POSITIONAL.
 */
static void
range_check(long *varp, char *name, long minimum, long maximum,
    long def_val, int user_supplied)
{
	dprintf(("DeBuG %s : %ld (%ld %ld %ld)\n",
	    name, *varp, minimum, maximum, def_val));

	if ((*varp < minimum) || (*varp > maximum)) {
		if (user_supplied != RC_DEFAULT) {
			(void) fprintf(stderr, gettext(
	    "mkfs: bad value for %s: %ld must be between %ld and %ld\n"),
			    name, *varp, minimum, maximum);
		}
		if (def_val != NO_DEFAULT) {
			if (user_supplied) {
				(void) fprintf(stderr,
				    gettext("mkfs: %s reset to default %ld\n"),
				    name, def_val);
			}
			*varp = def_val;
			dprintf(("DeBuG %s : %ld\n", name, *varp));
			return;
		}
		lockexit(2);
		/*NOTREACHED*/
	}
}

/*
 * Verify that a value is in a range.  If it is not, resets it to
 * its default value if one is supplied, exits otherwise.
 *
 * When testing, can compare user_supplied to RC_KEYWORD or RC_POSITIONAL.
 */
static void
range_check_64(uint64_t *varp, char *name, uint64_t minimum, uint64_t maximum,
    uint64_t def_val, int user_supplied)
{
	if ((*varp < minimum) || (*varp > maximum)) {
		if (user_supplied != RC_DEFAULT) {
			(void) fprintf(stderr, gettext(
	    "mkfs: bad value for %s: %lld must be between %lld and %lld\n"),
			    name, *varp, minimum, maximum);
		}
		if (def_val != NO_DEFAULT) {
			if (user_supplied) {
				(void) fprintf(stderr,
				    gettext("mkfs: %s reset to default %lld\n"),
				    name, def_val);
			}
			*varp = def_val;
			return;
		}
		lockexit(2);
		/*NOTREACHED*/
	}
}

/*
 * Blocks SIGINT from delivery.  Returns the previous mask in the
 * buffer provided, so that mask may be later restored.
 */
static void
block_sigint(sigset_t *old_mask)
{
	sigset_t block_mask;

	if (sigemptyset(&block_mask) < 0) {
		fprintf(stderr, gettext("Could not clear signal mask\n"));
		lockexit(3);
	}
	if (sigaddset(&block_mask, SIGINT) < 0) {
		fprintf(stderr, gettext("Could not set signal mask\n"));
		lockexit(3);
	}
	if (sigprocmask(SIG_BLOCK, &block_mask, old_mask) < 0) {
		fprintf(stderr, gettext("Could not block SIGINT\n"));
		lockexit(3);
	}
}

/*
 * Restores the signal mask that was in force before a call
 * to block_sigint().  This may actually still have SIGINT blocked,
 * if we've been recursively invoked.
 */
static void
unblock_sigint(sigset_t *old_mask)
{
	if (sigprocmask(SIG_UNBLOCK, old_mask, (sigset_t *)NULL) < 0) {
		fprintf(stderr, gettext("Could not restore signal mask\n"));
		lockexit(3);
	}
}

/*
 * Attempt to be somewhat graceful about being interrupted, rather than
 * just silently leaving the filesystem in an unusable state.
 *
 * The kernel has blocked SIGINT upon entry, so we don't have to worry
 * about recursion if the user starts pounding on the keyboard.
 */
static void
recover_from_sigint(int signum)
{
	if (fso > -1) {
		if ((Nflag != 0) || confirm_abort()) {
			lockexit(4);
		}
	}
}

static int
confirm_abort(void)
{
	char line[80];

	printf(gettext("\n\nAborting at this point will leave the filesystem "
	    "in an inconsistent\nstate.  If you do choose to stop, "
	    "you will be given instructions on how to\nrecover "
	    "the filesystem.  Do you wish to cancel the filesystem "
	    "grow\noperation (y/n)?"));
	if (getaline(stdin, line, sizeof (line)) == EOF)
		line[0] = 'y';

	printf("\n");
	if (line[0] == 'y' || line[0] == 'Y')
		return (1);
	else {
		return (0);
	}
}

static int
getaline(FILE *fp, char *loc, int maxlen)
{
	int n;
	char *p, *lastloc;

	p = loc;
	lastloc = &p[maxlen-1];
	while ((n = getc(fp)) != '\n') {
		if (n == EOF)
			return (EOF);
		if (!isspace(n) && p < lastloc)
			*p++ = n;
	}
	*p = 0;
	return (p - loc);
}

/*
 * Calculate the maximum value of cylinders-per-group for a file
 * system with the characteristics:
 *
 *	bsize - file system block size
 *	fragsize - frag size
 *	nbpi - number of bytes of disk space per inode
 *	nrpos - number of rotational positions
 *	spc - sectors per cylinder
 *
 * These five characteristic are not adjustable (by this function).
 * The only attribute of the file system which IS adjusted by this
 * function in order to maximize cylinders-per-group is the proportion
 * of the cylinder group overhead block used for the inode map.  The
 * inode map cannot occupy more than one-third of the cylinder group
 * overhead block, but it's OK for it to occupy less than one-third
 * of the overhead block.
 *
 * The setting of nbpi determines one possible value for the maximum
 * size of a cylinder group.  It does so because it determines the total
 * number of inodes in the file system (file system size is fixed, and
 * nbpi is fixed, so the total number of inodes is fixed too).  The
 * cylinder group has to be small enough so that the number of inodes
 * in the cylinder group is less than or equal to the number of bits
 * in one-third (or whatever proportion is assumed) of a file system
 * block.  The details of the calculation are:
 *
 *     The macro MAXIpG_B(bsize, inode_divisor) determines the maximum
 *     number of inodes that can be in a cylinder group, given the
 *     proportion of the cylinder group overhead block used for the
 *     inode bitmaps (an inode_divisor of 3 means that 1/3 of the
 *     block is used for inode bitmaps; an inode_divisor of 12 means
 *     that 1/12 of the block is used for inode bitmaps.)
 *
 *     Once the number of inodes per cylinder group is known, the
 *     maximum value of cylinders-per-group (determined by nbpi)
 *     is calculated by the formula
 *
 *     maxcpg_given_nbpi = (size of a cylinder group)/(size of a cylinder)
 *
 *			 = (inodes-per-cg * nbpi)/(spc * DEV_BSIZE)
 *
 *     (Interestingly, the size of the file system never enters
 *     into this calculation.)
 *
 * Another possible value for the maximum cylinder group size is determined
 * by frag_size and nrpos.  The frags in the cylinder group must be
 * representable in the frag bitmaps in the cylinder overhead block and the
 * rotational positions for each cylinder must be represented in the
 * rotational position tables.  The calculation of the maximum cpg
 * value, given the frag and nrpos vales, is:
 *
 *     maxcpg_given_fragsize =
 *	  (available space in the overhead block) / (size of per-cylinder data)
 *
 *     The available space in the overhead block =
 *	  bsize - sizeof (struct cg) - space_used_for_inode_bitmaps
 *
 *     The size of the per-cylinder data is:
 *	    sizeof(long)            # for the "blocks avail per cylinder" field
 *	    + nrpos * sizeof(short)   # for the rotational position table entry
 *	    + frags-per-cylinder/NBBY # number of bytes to represent this
 *				      # cylinder in the frag bitmap
 *
 * The two calculated maximum values of cylinder-per-group will typically
 * turn out to be different, since they are derived from two different
 * constraints.  Usually, maxcpg_given_nbpi is much bigger than
 * maxcpg_given_fragsize.  But they can be brought together by
 * adjusting the proportion of the overhead block dedicated to
 * the inode bitmaps.  Decreasing the proportion of the cylinder
 * group overhead block used for inode maps will decrease
 * maxcpg_given_nbpi and increase maxcpg_given_fragsize.
 *
 * This function calculates the initial values of maxcpg_given_nbpi
 * and maxcpg_given_fragsize assuming that 1/3 of the cg overhead
 * block is used for inode bitmaps.  Then it decreases the proportion
 * of the cg overhead block used for inode bitmaps (by increasing
 * the value of inode_divisor) until maxcpg_given_nbpi and
 * maxcpg_given_fragsize are the same, or stop changing, or
 * maxcpg_given_nbpi is less than maxcpg_given_fragsize.
 *
 * The loop terminates when any of the following occur:
 *	* maxcpg_given_fragsize is greater than or equal to
 *	  maxcpg_given_nbpi
 *	* neither maxcpg_given_fragsize nor maxcpg_given_nbpi
 *	  change in the expected direction
 *
 * The loop is guaranteed to terminate because it only continues
 * while maxcpg_given_fragsize and maxcpg_given_nbpi are approaching
 * each other.  As soon they cross each other, or neither one changes
 * in the direction of the other, or one of them moves in the wrong
 * direction, the loop completes.
 */

static long
compute_maxcpg(long bsize, long fragsize, long nbpi, long nrpos, long spc)
{
	int	maxcpg_given_nbpi;	/* in cylinders */
	int	maxcpg_given_fragsize;	/* in cylinders */
	int	spf;			/* sectors per frag */
	int	inode_divisor;
	int	old_max_given_frag = 0;
	int	old_max_given_nbpi = INT_MAX;

	spf = fragsize / DEV_BSIZE;
	inode_divisor = 3;

	while (1) {
		maxcpg_given_nbpi =
		    (((int64_t)(MAXIpG_B(bsize, inode_divisor))) * nbpi) /
		    (DEV_BSIZE * ((int64_t)spc));
		maxcpg_given_fragsize =
		    (bsize - (sizeof (struct cg)) - (bsize / inode_divisor)) /
		    (sizeof (long) + nrpos * sizeof (short) +
		    (spc / spf) / NBBY);

		if (maxcpg_given_fragsize >= maxcpg_given_nbpi)
			return (maxcpg_given_nbpi);

		/*
		 * If neither value moves toward the other, return the
		 * least of the old values (we use the old instead of the
		 * new because: if the old is the same as the new, it
		 * doesn't matter which ones we use.  If one of the
		 * values changed, but in the wrong direction, the
		 * new values are suspect.  Better use the old.  This
		 * shouldn't happen, but it's best to check.
		 */

		if (!(maxcpg_given_nbpi < old_max_given_nbpi) &&
		    !(maxcpg_given_fragsize > old_max_given_frag))
			return (MIN(old_max_given_nbpi, old_max_given_frag));

		/*
		 * This is probably impossible, but if one of the maxcpg
		 * values moved in the "right" direction and one moved
		 * in the "wrong" direction (that is, the two values moved
		 * in the same direction), the previous conditional won't
		 * recognize that the values aren't converging (since at
		 * least one value moved in the "right" direction, the
		 * last conditional says "keep going").
		 *
		 * Just to make absolutely certain that the loop terminates,
		 * check for one of the values moving in the "wrong" direction
		 * and terminate the loop if it happens.
		 */

		if (maxcpg_given_nbpi > old_max_given_nbpi ||
		    maxcpg_given_fragsize < old_max_given_frag)
			return (MIN(old_max_given_nbpi, old_max_given_frag));

		old_max_given_nbpi = maxcpg_given_nbpi;
		old_max_given_frag = maxcpg_given_fragsize;

		inode_divisor++;
	}
}

static int
in_64bit_mode(void)
{
	/*  cmd must be an absolute path, for security */
	char *cmd = "/usr/bin/isainfo -b";
	char buf[BUFSIZ];
	FILE *ptr;
	int retval = 0;

	putenv("IFS= \t");
	if ((ptr = popen(cmd, "r")) != NULL) {
		if (fgets(buf, BUFSIZ, ptr) != NULL &&
		    strncmp(buf, "64", 2) == 0)
			retval = 1;
		(void) pclose(ptr);
	}
	return (retval);
}

/*
 * validate_size
 *
 * Return 1 if the device appears to be at least "size" sectors long.
 * Return 0 if it's shorter or we can't read it.
 */

static int
validate_size(int fd, diskaddr_t size)
{
	char 		buf[DEV_BSIZE];
	int rc;

	if ((llseek(fd, (offset_t)((size - 1) * DEV_BSIZE), SEEK_SET) == -1) ||
	    (read(fd, buf, DEV_BSIZE)) != DEV_BSIZE)
		rc = 0;
	else
		rc = 1;
	return (rc);
}

/*
 * Print every field of the calculated superblock, along with
 * its value.  To make parsing easier on the caller, the value
 * is printed first, then the name.  Additionally, there's only
 * one name/value pair per line.  All values are reported in
 * hexadecimal (with the traditional 0x prefix), as that's slightly
 * easier for humans to read.  Not that they're expected to, but
 * debugging happens.
 */
static void
dump_sblock(void)
{
	int row, column, pending, written;
	caddr_t source;

	if (Rflag) {
		pending = sizeof (sblock);
		source = (caddr_t)&sblock;
		do {
			written = write(fileno(stdout), source, pending);
			pending -= written;
			source += written;
		} while ((pending > 0) && (written > 0));

		if (written < 0) {
			perror(gettext("Binary dump of superblock failed"));
			lockexit(1);
		}
		return;
	} else {
		printf("0x%x sblock.fs_link\n", sblock.fs_link);
		printf("0x%x sblock.fs_rolled\n", sblock.fs_rolled);
		printf("0x%x sblock.fs_sblkno\n", sblock.fs_sblkno);
		printf("0x%x sblock.fs_cblkno\n", sblock.fs_cblkno);
		printf("0x%x sblock.fs_iblkno\n", sblock.fs_iblkno);
		printf("0x%x sblock.fs_dblkno\n", sblock.fs_dblkno);
		printf("0x%x sblock.fs_cgoffset\n", sblock.fs_cgoffset);
		printf("0x%x sblock.fs_cgmask\n", sblock.fs_cgmask);
		printf("0x%x sblock.fs_time\n", sblock.fs_time);
		printf("0x%x sblock.fs_size\n", sblock.fs_size);
		printf("0x%x sblock.fs_dsize\n", sblock.fs_dsize);
		printf("0x%x sblock.fs_ncg\n", sblock.fs_ncg);
		printf("0x%x sblock.fs_bsize\n", sblock.fs_bsize);
		printf("0x%x sblock.fs_fsize\n", sblock.fs_fsize);
		printf("0x%x sblock.fs_frag\n", sblock.fs_frag);
		printf("0x%x sblock.fs_minfree\n", sblock.fs_minfree);
		printf("0x%x sblock.fs_rotdelay\n", sblock.fs_rotdelay);
		printf("0x%x sblock.fs_rps\n", sblock.fs_rps);
		printf("0x%x sblock.fs_bmask\n", sblock.fs_bmask);
		printf("0x%x sblock.fs_fmask\n", sblock.fs_fmask);
		printf("0x%x sblock.fs_bshift\n", sblock.fs_bshift);
		printf("0x%x sblock.fs_fshift\n", sblock.fs_fshift);
		printf("0x%x sblock.fs_maxcontig\n", sblock.fs_maxcontig);
		printf("0x%x sblock.fs_maxbpg\n", sblock.fs_maxbpg);
		printf("0x%x sblock.fs_fragshift\n", sblock.fs_fragshift);
		printf("0x%x sblock.fs_fsbtodb\n", sblock.fs_fsbtodb);
		printf("0x%x sblock.fs_sbsize\n", sblock.fs_sbsize);
		printf("0x%x sblock.fs_csmask\n", sblock.fs_csmask);
		printf("0x%x sblock.fs_csshift\n", sblock.fs_csshift);
		printf("0x%x sblock.fs_nindir\n", sblock.fs_nindir);
		printf("0x%x sblock.fs_inopb\n", sblock.fs_inopb);
		printf("0x%x sblock.fs_nspf\n", sblock.fs_nspf);
		printf("0x%x sblock.fs_optim\n", sblock.fs_optim);
#ifdef _LITTLE_ENDIAN
		printf("0x%x sblock.fs_state\n", sblock.fs_state);
#else
		printf("0x%x sblock.fs_npsect\n", sblock.fs_npsect);
#endif
		printf("0x%x sblock.fs_si\n", sblock.fs_si);
		printf("0x%x sblock.fs_trackskew\n", sblock.fs_trackskew);
		printf("0x%x sblock.fs_id[0]\n", sblock.fs_id[0]);
		printf("0x%x sblock.fs_id[1]\n", sblock.fs_id[1]);
		printf("0x%x sblock.fs_csaddr\n", sblock.fs_csaddr);
		printf("0x%x sblock.fs_cssize\n", sblock.fs_cssize);
		printf("0x%x sblock.fs_cgsize\n", sblock.fs_cgsize);
		printf("0x%x sblock.fs_ntrak\n", sblock.fs_ntrak);
		printf("0x%x sblock.fs_nsect\n", sblock.fs_nsect);
		printf("0x%x sblock.fs_spc\n", sblock.fs_spc);
		printf("0x%x sblock.fs_ncyl\n", sblock.fs_ncyl);
		printf("0x%x sblock.fs_cpg\n", sblock.fs_cpg);
		printf("0x%x sblock.fs_ipg\n", sblock.fs_ipg);
		printf("0x%x sblock.fs_fpg\n", sblock.fs_fpg);
		printf("0x%x sblock.fs_cstotal\n", sblock.fs_cstotal);
		printf("0x%x sblock.fs_fmod\n", sblock.fs_fmod);
		printf("0x%x sblock.fs_clean\n", sblock.fs_clean);
		printf("0x%x sblock.fs_ronly\n", sblock.fs_ronly);
		printf("0x%x sblock.fs_flags\n", sblock.fs_flags);
		printf("0x%x sblock.fs_fsmnt\n", sblock.fs_fsmnt);
		printf("0x%x sblock.fs_cgrotor\n", sblock.fs_cgrotor);
		printf("0x%x sblock.fs_u.fs_csp\n", sblock.fs_u.fs_csp);
		printf("0x%x sblock.fs_cpc\n", sblock.fs_cpc);

		/*
		 * No macros are defined for the dimensions of the
		 * opostbl array.
		 */
		for (row = 0; row < 16; row++) {
			for (column = 0; column < 8; column++) {
				printf("0x%x sblock.fs_opostbl[%d][%d]\n",
				    sblock.fs_opostbl[row][column],
				    row, column);
			}
		}

		/*
		 * Ditto the size of sparecon.
		 */
		for (row = 0; row < 51; row++) {
			printf("0x%x sblock.fs_sparecon[%d]\n",
			    sblock.fs_sparecon[row], row);
		}

		printf("0x%x sblock.fs_version\n", sblock.fs_version);
		printf("0x%x sblock.fs_logbno\n", sblock.fs_logbno);
		printf("0x%x sblock.fs_reclaim\n", sblock.fs_reclaim);
		printf("0x%x sblock.fs_sparecon2\n", sblock.fs_sparecon2);
#ifdef _LITTLE_ENDIAN
		printf("0x%x sblock.fs_npsect\n", sblock.fs_npsect);
#else
		printf("0x%x sblock.fs_state\n", sblock.fs_state);
#endif
		printf("0x%llx sblock.fs_qbmask\n", sblock.fs_qbmask);
		printf("0x%llx sblock.fs_qfmask\n", sblock.fs_qfmask);
		printf("0x%x sblock.fs_postblformat\n", sblock.fs_postblformat);
		printf("0x%x sblock.fs_nrpos\n", sblock.fs_nrpos);
		printf("0x%x sblock.fs_postbloff\n", sblock.fs_postbloff);
		printf("0x%x sblock.fs_rotbloff\n", sblock.fs_rotbloff);
		printf("0x%x sblock.fs_magic\n", sblock.fs_magic);

		/*
		 * fs_space isn't of much use in this context, so we'll
		 * just ignore it for now.
		 */
	}
}
