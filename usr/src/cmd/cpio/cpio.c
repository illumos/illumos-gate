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
 * Copyright 2012 Milan Jurik. All rights reserved.
 * Copyright (c) 2012 Gary Mills
 */

/*	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
/*	All Rights Reserved					*/

/*
 * Portions of this source code were derived from Berkeley 4.3 BSD
 * under license from the Regents of the University of California.
 */

#include <stdio.h>
#include <sys/types.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <memory.h>
#include <string.h>
#include <stdarg.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/mkdev.h>
#include <sys/param.h>
#include <utime.h>
#include <pwd.h>
#include <grp.h>
#include <signal.h>
#include <ctype.h>
#include <locale.h>
#include <sys/ioctl.h>
#include <sys/mtio.h>
#include <sys/fdio.h>
#include "cpio.h"
#include <sys/acl.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <fnmatch.h>
#include <libgen.h>
#include <libintl.h>
#include <dirent.h>
#include <limits.h>
#include <aclutils.h>
#if defined(_PC_SATTR_ENABLED)
#include <libnvpair.h>
#include <attr.h>
#include <libcmdutils.h>
#endif	/* _PC_SATTR_ENABLED */
#ifdef SOLARIS_PRIVS
#include <priv.h>
#endif	/* SOLARIS_PRIVS */

/*
 * Special kludge for off_t being a signed quantity.
 */
#if _FILE_OFFSET_BITS == 64
typedef	u_longlong_t	u_off_t;
#else
typedef	ulong_t		u_off_t;
#endif

#define	SECMODE	0xe080

#define	DEVNULL		"/dev/null"
#define	XATTRHDR	".hdr"

#define	NAMELEN		32
#define	TYPELEN 	16
#define	PERMLEN		4

#define	FILE_COPIED	1
#define	FILE_LINKED	2
#define	FILE_PASS_ERR	-1

#define	ARCHIVE_NORMAL	0
#define	ARCHIVE_ACL	1
#define	ARCHIVE_XATTR	2
#define	ARCHIVE_SPARSE	3

#ifndef	VIEW_READONLY
#define	VIEW_READONLY	"SUNWattr_ro"
#endif

#ifndef	VIEW_READWRITE
#define	VIEW_READWRITE	"SUNWattr_rw"
#endif


#define	LSTAT(dir, path, statbuf) fstatat(dir, \
    get_component((Gen.g_attrnam_p == NULL) ? \
    path : Gen.g_attrnam_p), statbuf, AT_SYMLINK_NOFOLLOW)
#define	STAT(dir, path, statbuf) fstatat(dir, \
    get_component((Gen.g_attrnam_p == NULL) ? \
    path : Gen.g_attrnam_p), statbuf, 0)

/*
 *	These limits reflect the maximum size regular file that
 *	can be archived, depending on the archive type. For archives
 *	with character-format headers (odc, tar, ustar) we use
 *	CHAR_OFFSET_MAX.  For archives with SVR4 ASCII headers (-c, -H crc)
 *	we store filesize in an 8-char hexadecimal string and use
 *	ASC_OFFSET_MAX.  Otherwise, we are limited to the size that will
 *	fit in a signed long value.
 */
#define	CHAR_OFFSET_MAX	077777777777ULL	/* 11 octal digits */
#define	ASC_OFFSET_MAX	0XFFFFFFFF	/* 8 hexadecimal digits */
#define	BIN_OFFSET_MAX	LONG_MAX	/* signed long max value */

#define	POSIXMODES	07777

static char	aclchar = ' ';

static struct Lnk *add_lnk(struct Lnk **);
static int bfill(void);
static void bflush(void);
static int chgreel(int dir);
static int ckname(int);
static void ckopts(long mask);
static long cksum(char hdr, int byt_cnt, int *err);
static int creat_hdr(void);
static int creat_lnk(int dirfd, char *name1_p, char *name2_p);
static int creat_spec(int dirfd);
static int creat_tmp(char *nam_p);
static void data_in(int proc_mode);
static void data_out(void);
static void data_pass(void);
static void file_in(void);
static int file_out(void);
static int file_pass(void);
static void flush_lnks(void);
static int gethdr(void);
static int getname(void);
static void getpats(int largc, char **largv);
static void ioerror(int dir);
static int matched(void);
static int missdir(char *nam_p);
static long mklong(short v[]);
static void mkshort(short sval[], long v);
static int openout(int dirfd);
static int read_hdr(int hdr);
static void reclaim(struct Lnk *l_p);
static void rstbuf(void);
static void setpasswd(char *nam);
static void rstfiles(int over, int dirfd);
static void scan4trail(void);
static void setup(int largc, char **largv);
static void set_tym(int dirfd, char *nam_p, time_t atime, time_t mtime);
static void sigint(int sig);
static void swap(char *buf_p, int cnt);
static void usage(void);
static void verbose(char *nam_p);
static void write_hdr(int arcflag, off_t len);
static void write_trail(void);
static int ustar_dir(void);
static int ustar_spec(void);
static struct stat *convert_to_old_stat(struct stat *, char *, char *);
static void read_bar_vol_hdr(void);
static void read_bar_file_hdr(void);
static void setup_uncompress(FILE **);
static void skip_bar_volhdr(void);
static void bar_file_in(void);
static int g_init(int *devtype, int *fdes);
static int g_read(int, int, char *, unsigned);
static int g_write(int, int, char *, unsigned);
static int is_floppy(int);
static int is_tape(int);
static void write_ancillary(char *buf, size_t len, boolean_t padding);
static int remove_dir(char *);
static int save_cwd(void);
static void rest_cwd(int cwd);

static void xattrs_out(int (*func)());
static void get_parent(char *path, char *dir);
static void prepare_xattr_hdr(char **attrbuf, char *filename,
    char *attrname, char typeflag, struct Lnk *linkinfo, int *rlen);
static char tartype(int type);
static int openfile(int omode);
static mode_t attrmode(char type);
static char *get_component(char *path);
static int open_dir(char *name);
static int open_dirfd();
static void close_dirfd();
static void write_xattr_hdr();
static char *skipslashes(char *string, char *start);
static int read_xattr_hdr();
static void chop_endslashes(char *path);


/* helpful types */

static
struct passwd	*Curpw_p,	/* Current password entry for -t option */
		*Rpw_p,		/* Password entry for -R option */
		*dpasswd;

static
struct group	*Curgr_p,	/* Current group entry for -t option */
		*dgroup;

/* Data structure for buffered I/O. */

static
struct buf_info {
	char	*b_base_p,	/* Pointer to base of buffer */
		*b_out_p,	/* Position to take bytes from buffer at */
		*b_in_p,	/* Position to put bytes into buffer at */
		*b_end_p;	/* Pointer to end of buffer */
	long	b_cnt,		/* Count of unprocessed bytes */
		b_size;		/* Size of buffer in bytes */
} Buffr;

/* Generic header format */

static
struct gen_hdr {
	ulong_t	g_magic,	/* Magic number field */
		g_ino,		/* Inode number of file */
		g_mode,		/* Mode of file */
		g_uid,		/* Uid of file */
		g_gid,		/* Gid of file */
		g_nlink,	/* Number of links */
		g_mtime;	/* Modification time */
	off_t	g_filesz;	/* Length of file */
	ulong_t	g_dev,		/* File system of file */
		g_rdev,		/* Major/minor numbers of special files */
		g_namesz,	/* Length of filename */
		g_cksum;	/* Checksum of file */
	char	g_gname[32],
		g_uname[32],
		g_version[2],
		g_tmagic[6],
		g_typeflag;
	char	*g_tname,
		*g_prefix,
		*g_nam_p,	/* Filename */
		*g_attrparent_p, /* attribute parent */
		*g_attrpath_p, /* attribute path */
		*g_attrnam_p,	/* attribute */
		*g_attrfnam_p,  /* Real file name attr belongs to */
		*g_linktoattrfnam_p, /* file linked attribute belongs to */
		*g_linktoattrnam_p,  /* attribute g_attrnam_p is linked to */
		*g_dirpath;	/* dirname currently opened */
	int	g_dirfd;	/* directory file descriptor */
	int	g_passdirfd;	/* directory fd to pass to */
	int	g_rw_sysattr;	/* read-write system attribute */
	int	g_baseparent_fd;	/* base file's parent fd */
	holes_info_t *g_holes;	/* sparse file information */

} Gen, *G_p;

/* Data structure for handling multiply-linked files */
static
char	prebuf[PRESIZ+1],
	nambuf[NAMSIZ+1],
	fullnam[MAXNAM+1];


static
struct Lnk {
	short	L_cnt,		/* Number of links encountered */
		L_data;		/* Data has been encountered if 1 */
	struct gen_hdr	L_gen;	/* gen_hdr information for this file */
	struct Lnk	*L_nxt_p,	/* Next file in list */
			*L_bck_p,	/* Previous file in list */
			*L_lnk_p;	/* Next link for this file */
} Lnk_hd;

static
struct hdr_cpio	Hdr;

/*
 * -------------------------------------------------------------------------
 *		   Stuff needed to pre-view the name stream
 *
 * issymlink is used to remember that the current file is a symlink between
 * getname() and file_pass(); the former trashes this information immediately
 * when -L is specified.
 */

static
int	issymlink = 0;

static
FILE	*In_p = stdin;		/* Where the input comes from */

typedef struct sl_info
{
	struct sl_info *llink;	/* Left subtree ptr (tree depth in *sl_head) */
	struct sl_info *rlink;	/* Right subtree ptr */
	int bal;		/* Subtree balance factor */
	ulong_t	sl_count;	/* Number of symlinks */
	int	sl_ftype;	/* file type of inode */
	ino_t	sl_ino;		/* Inode of file */
	ino_t	sl_ino2;	/* alternate inode for -Hodc */
} sl_info_t;

typedef struct data_in
{
	int		data_in_errno;
	char		data_in_swapfile;
	char		data_in_proc_mode;
	char		data_in_rd_eof;
	char		data_in_wr_part;
	char		data_in_compress_flag;
	long		data_in_cksumval;
	FILE		*data_in_pipef;
} data_in_t;

/*
 * The following structure maintains a hash entry for the
 * balancing trees which are allocated for each device nodes.
 */
typedef struct sl_info_link
{
	dev_t		dev;
	sl_info_t	*head;
	struct sl_info_link *next;
} sl_info_link_t;

#define	SL_INFO_ALLOC_CHUNK	1024
#define	NDEVHENTRY		0x40
#define	DEV_HASHKEY(x)		((x) & (NDEVHENTRY -1))

/*
 * For remapping dev,inode for -Hodc archives.
 */

typedef struct sl_remap
{
	dev_t			dev;		/* device */
	int			inode_count;	/* # inodes seen on dev */
	struct sl_remap 	*next;		/* next in the chain */
} sl_remap_t;

/* forward declarations */

static sl_info_t 	*sl_info_alloc(void);
static sl_info_t 	*sl_insert(dev_t, ino_t, int);
static ulong_t		sl_numlinks(dev_t, ino_t, int);
static void		sl_preview_synonyms(void);
static void		sl_remember_tgt(const struct stat *, int, int);
static sl_info_t 	*sl_search(dev_t, ino_t, int);
static sl_info_t	*sl_devhash_lookup(dev_t);
static void		sl_devhash_insert(dev_t, sl_info_t *);

extern int		sl_compare(ino_t, int, ino_t, int);
#define	sl_compare(lino, lftype, rino, rftype)	(lino < rino ? -1 : \
	    (lino > rino ? 1 : (lftype < rftype ? -1 : \
	    (lftype > rftype ? 1 : 0))))

/* global storage */

static sl_remap_t  *sl_remap_head = NULL; /* head of the inode-remap list */
static sl_info_link_t	*sl_devhash[NDEVHENTRY]; /* hash table */

/*
 * -------------------------------------------------------------------------
 */

static
struct stat	ArchSt,	/* stat(2) information of the archive */
		SrcSt,	/* stat(2) information of source file */
		DesSt,	/* stat(2) of destination file */
		*OldSt = NULL;	/* stat info converted to svr32 format */

/*
 * bin_mag: Used to validate a binary magic number,
 * by combining to bytes into an unsigned short.
 */

static
union bin_mag {
	unsigned char b_byte[2];
	ushort_t b_half;
} Binmag;

static
union tblock *Thdr_p;	/* TAR header pointer */

static union b_block *bar_Vhdr;
static struct gen_hdr Gen_bar_vol;

/*
 * swpbuf: Used in swap() to swap bytes within a halfword,
 * halfwords within a word, or to reverse the order of the
 * bytes within a word.  Also used in mklong() and mkshort().
 */

static
union swpbuf {
	unsigned char	s_byte[4];
	ushort_t	s_half[2];
	ulong_t	s_word;
} *Swp_p;

static
char	*myname,		/* program name */
	Adir,			/* Flags object as a directory */
	Hiddendir,		/* Processing hidden attribute directory */
	Aspec,			/* Flags object as a special file */
	Do_rename,		/* Indicates rename() is to be used */
	Time[50],		/* Array to hold date and time */
	Ttyname[] = "/dev/tty",	/* Controlling console */
	T_lname[MAXPATHLEN],	/* Array to hold links name for tar */
	*Buf_p,			/* Buffer for file system I/O */
	*Full_p,		/* Pointer to full pathname */
	*Efil_p,		/* -E pattern file string */
	*Eom_p = "Change to part %d and press RETURN key. [q] ",
	*Fullnam_p,		/* Full pathname */
	*Attrfile_p,		/* attribute file */
	*Hdr_p,			/* -H header type string */
	*IOfil_p,		/* -I/-O input/output archive string */
	*Lnkend_p,		/* Pointer to end of Lnknam_p */
	*Lnknam_p,		/* Buffer for linking files with -p option */
	*Nam_p,			/* Array to hold filename */
	*Savenam_p,		/* copy of filename xattr belongs to */
	*Own_p,			/* New owner login id string */
	*Renam_p,		/* Buffer for renaming files */
	*Renam_attr_p,		/* Buffer for renaming attr with sys attrs */
	*Renametmp_p,		/* Tmp Buffer for renaming files */
	*Symlnk_p,		/* Buffer for holding symbolic link name */
	*Over_p,		/* Holds temporary filename when overwriting */
	**Pat_pp = 0,		/* Pattern strings */
	bar_linkflag,		/* flag to indicate if the file is a link */
	bar_linkname[MAXPATHLEN]; /* store the name of the link */

static
int	Append = 0,	/* Flag set while searching to end of archive */
	Archive,	/* File descriptor of the archive */
	Buf_error = 0,	/* I/O error occurred during buffer fill */
	Compress_sparse = 0,	/* Compress sparse files */
	Def_mode = 0777,	/* Default file/directory protection modes */
	Device,		/* Device type being accessed (used with libgenIO) */
	Error_cnt = 0,	/* Cumulative count of I/O errors */
	Finished = 1,	/* Indicates that a file transfer has completed */
	Hdrsz = ASCSZ,	/* Fixed length portion of the header */
	Hdr_type,		/* Flag to indicate type of header selected */
	Ifile,		/* File des. of file being archived */
	Ofile,		/* File des. of file being extracted from archive */
	Use_old_stat = 0,    /* Create an old style -Hodc hdr (small dev's) */
	Onecopy = 0,	/* Flags old vs. new link handling */
	Pad_val = 0,	/* Indicates the number of bytes to pad (if any) */
	PageSize = 0,	/* The native page size, used for figuring block size */
	Volcnt = 1,	/* Number of archive volumes processed */
	Verbcnt = 0,	/* Count of number of dots '.' output */
	Eomflag = 0,
	Dflag = 0,
	Atflag = 0,	/* Archive/restore extended attributes */
	SysAtflag = 0,	/* Archive/restore extended system attributes */
	Compressed,	/* Flag to indicate if the bar archive is compressed */
	Bar_vol_num = 0, /* Volume number count for bar archive */
	privileged = 0,	/* Flag set if running with higher privileges */
	attr_baseparent_fd = -1;	/* attribute's base file descriptor */


static
gid_t	Lastgid = (gid_t)-1;	/* Used with -t & -v to record current gid */

static
uid_t	Lastuid = (uid_t)-1;	/* Used with -t & -v to record current uid */

static
long	Args,		/* Mask of selected options */
	Max_namesz = CPATH;	/* Maximum size of pathnames/filenames */

static
int	Bufsize = BUFSZ;	/* Default block size */


static u_longlong_t    Blocks;	/* full blocks transferred */
static u_longlong_t    SBlocks;	/* cumulative char count from short reads */


static off_t	Max_offset = BIN_OFFSET_MAX;	/* largest file size */
static off_t	Max_filesz;			/* from getrlimit */

static ulong_t	Savedev;

static
FILE	*Ef_p,			/* File pointer of pattern input file */
	*Err_p = stderr,	/* File pointer for error reporting */
	*Out_p = stdout,	/* File pointer for non-archive output */
	*Rtty_p,		/* Input file pointer for interactive rename */
	*Wtty_p;		/* Output file ptr for interactive rename */

static
ushort_t	Ftype = S_IFMT;	/* File type mask */

/* ACL support */
static struct sec_attr {
	char	attr_type;
	char	attr_len[7];
	char	attr_info[1];
} *attr;

static int	Pflag = 0;	/* flag indicates that acl is preserved */
static int	acl_is_set = 0; /* True if an acl was set on the file */

acl_t *aclp;

#if defined(O_XATTR)
typedef enum {
	ATTR_OK,
	ATTR_SKIP,
	ATTR_CHDIR_ERR,
	ATTR_OPEN_ERR,
	ATTR_XATTR_ERR,
	ATTR_SATTR_ERR
} attr_status_t;
#endif

#if defined(O_XATTR)
typedef enum {
	ARC_CREATE,
	ARC_RESTORE
} arc_action_t;
#endif


/*
 *
 * cpio has been changed to support extended attributes.
 *
 * As part of this change cpio has been changed to use the new *at() syscalls
 * such as openat, fchownat(), unlinkat()...
 *
 * This was done so that attributes can be handled with as few code changes
 * as possible.
 *
 * What this means is that cpio now opens the directory that a file or directory
 * resides in and then performs *at() functions to manipulate the entry.
 *
 * For example a new file is now created like this:
 *
 * dfd = open(<some dir path>)
 * fd = openat(dfd, <name>,....);
 *
 * or in the case of an extended attribute
 *
 * dfd = attropen(<pathname>, ".", ....)
 *
 * Once we have a directory file descriptor all of the *at() functions can
 * be applied to it.
 *
 * unlinkat(dfd, <component name>,...)
 * fchownat(dfd, <component name>,..)
 *
 * This works for both normal namespace files and extended attribute file
 *
 */

/*
 * Extended attribute layout
 *
 * Extended attributes are stored in two pieces.
 * 1. An attribute header which has information about
 *    what file the attribute is for and what the attribute
 *    is named.
 * 2. The attribute record itself.  Stored as a normal file type
 *    of entry.
 * Both the header and attribute record have special modes/typeflags
 * associated with them.
 *
 * The names of the header in the archive look like:
 * /dev/null/attr.hdr
 *
 * The name of the attribute looks like:
 * /dev/null/attr.
 *
 * This is done so that an archiver that doesn't understand these formats
 * can just dispose of the attribute records unless the user chooses to
 * rename them via cpio -r or pax -i
 *
 * The format is composed of a fixed size header followed
 * by a variable sized xattr_buf. If the attribute is a hard link
 * to another attribute, then another xattr_buf section is included
 * for the link.
 *
 * The xattr_buf is used to define the necessary "pathing" steps
 * to get to the extended attribute.  This is necessary to support
 * a fully recursive attribute model where an attribute may itself
 * have an attribute.
 *
 * The basic layout looks like this.
 *
 *     --------------------------------
 *     |                              |
 *     |         xattr_hdr            |
 *     |                              |
 *     --------------------------------
 *     --------------------------------
 *     |                              |
 *     |        xattr_buf             |
 *     |                              |
 *     --------------------------------
 *     --------------------------------
 *     |                              |
 *     |      (optional link info)    |
 *     |                              |
 *     --------------------------------
 *     --------------------------------
 *     |                              |
 *     |      attribute itself        |
 *     |      stored as normal tar    |
 *     |      or cpio data with       |
 *     |      special mode or         |
 *     |      typeflag                |
 *     |                              |
 *     --------------------------------
 *
 */

/*
 * Extended attributes structures
 *
 * xattrhead is the complete extended attribute header, as read of off
 * disk/tape. It includes the variable xattr_buf portion.
 *
 * xattrp is basically an offset into xattrhead that points to the
 * "pathing" section which defines how to get to the attribute.
 *
 * xattr_linkp is identical to xattrp except that it is used for linked
 * attributes.  It provides the pathing steps to get to the linked
 * attribute.
 *
 * These structures are updated when an extended attribute header is read off
 * of disk/tape.
 */
static struct xattr_hdr	*xattrhead;
static struct xattr_buf	*xattrp;
static struct xattr_buf	*xattr_linkp;
static int 		xattrbadhead;	/* is extended attribute header bad? */

static int	append_secattr(char **, int *, acl_t *);

/*
 * Note regarding cpio and changes to ensure cpio doesn't try to second
 * guess whether it runs with sufficient privileges or not:
 *
 * cpio has been changed so that it doesn't carry a second implementation of
 * the kernel's policy with respect to privileges.  Instead of attempting
 * to restore uid and gid from an archive only if cpio is run as uid 0,
 * cpio now *always* tries to restore the uid and gid from the archive
 * except when the -R option is specified.  When the -R is specified,
 * the uid and gid of the restored file will be changed to those of the
 * login id specified.  In addition, chown(), set_tym(), and chmod() should
 * only be executed once during archive extraction, and to ensure
 * setuid/setgid bits are restored properly, chown() should always be
 * executed before chmod().
 *
 * Note regarding debugging mechanism for cpio:
 *
 * The following mechanism is provided to allow us to debug cpio in complicated
 * situations, like when it is part of a pipe.  The idea is that you compile
 * with -DWAITAROUND defined, and then add the "-z" command line option to the
 * target cpio invocation.  If stderr is available, it will tell you to which
 * pid to attach the debugger; otherwise, use ps to find it.  Attach to the
 * process from the debugger, and, *PRESTO*, you are there!
 *
 * Simply assign "waitaround = 0" once you attach to the process, and then
 * proceed from there as usual.
 */

#ifdef WAITAROUND
int waitaround = 0;		/* wait for rendezvous with the debugger */
#endif

#define	EXIT_CODE	(Error_cnt > 255 ? 255 : Error_cnt)

/*
 * main: Call setup() to process options and perform initializations,
 * and then select either copy in (-i), copy out (-o), or pass (-p) action.
 */

int
main(int argc, char **argv)
{
	int i;
	int passret;

	(void) setlocale(LC_ALL, "");
#if !defined(TEXT_DOMAIN)	/* Should be defined by cc -D */
#define	TEXT_DOMAIN "SYS_TEST"	/* Use this only if it weren't */
#endif
	(void) textdomain(TEXT_DOMAIN);

	(void) memset(&Gen, 0, sizeof (Gen));
	myname = e_strdup(E_EXIT, basename(argv[0]));
	setup(argc, argv);

	if (signal(SIGINT, sigint) == SIG_IGN)
		(void) signal(SIGINT, SIG_IGN);
	switch (Args & (OCi | OCo | OCp)) {
	case OCi: /* COPY IN */
		Hdr_type = NONE;
		if (Atflag || SysAtflag) {
			/*
			 * Save the current working directory, so
			 * we can change back here after cd'ing into
			 * the attribute directory when processing
			 * attributes.
			 */
			if ((attr_baseparent_fd = save_cwd()) < 0) {
				msg(EXT, "Unable to open current directory.");
			}
		}
		while ((i = gethdr()) != 0) {
			Gen.g_dirfd = -1;
			if (i == 1) {
				file_in();
				/*
				 * Any ACL info for this file would or should
				 * have been used after file_in(); clear out
				 * aclp so it is is not erroneously used on
				 * the next file.
				 */
				if (aclp != NULL) {
					acl_free(aclp);
					aclp = NULL;
				}
				acl_is_set = 0;
			}
			(void) memset(&Gen, 0, sizeof (Gen));
		}
		/* Do not count "extra" "read-ahead" buffered data */
		if (Buffr.b_cnt > Bufsize)
			Blocks -=  (u_longlong_t)(Buffr.b_cnt / Bufsize);
		break;
	case OCo: /* COPY OUT */
		if (Args & OCA) {
			scan4trail();
		}

		Gen.g_dirfd = -1;
		Gen.g_dirpath = NULL;
		sl_preview_synonyms();

		while ((i = getname()) != 0) {
			if (i == 1) {
				(void) file_out();
				if (Atflag || SysAtflag) {
					if (Gen.g_dirfd != -1) {
						(void) close(Gen.g_dirfd);
					}
					Gen.g_dirfd = -1;
					xattrs_out(file_out);
				}
			}
			if (aclp != NULL) {
				acl_free(aclp);
				aclp = NULL;
				acl_is_set = 0;
			}
		}
		write_trail();
		break;
	case OCp: /* PASS */
		sl_preview_synonyms();

		Gen.g_dirfd = -1;
		Gen.g_passdirfd = -1;
		Gen.g_dirpath = NULL;
		Compress_sparse = 1;
		while (getname()) {
			/*
			 * If file is a fully qualified path then
			 * file_pass will strip off the leading '/'
			 * and we need to save off the unstripped
			 * name for attribute traversal.
			 */
			if (Atflag || SysAtflag) {
				(void) strcpy(Savenam_p, Gen.g_nam_p);
			}
			passret = file_pass();
			if (aclp != NULL) {
				acl_free(aclp);
				aclp = NULL;
				acl_is_set = 0;
			}
			if (Gen.g_passdirfd != -1)
				(void) close(Gen.g_passdirfd);
			Gen.g_passdirfd = -1;
			if (Atflag || SysAtflag) {
				if (Gen.g_dirfd != -1) {
					(void) close(Gen.g_dirfd);
				}
				Gen.g_dirfd = -1;
				if (passret != FILE_LINKED) {
					Gen.g_nam_p = Savenam_p;
					xattrs_out(file_pass);
				}
			}
		}
		break;
	default:
		msg(EXT, "Impossible action.");
	}
	if (Ofile > 0) {
		if (close(Ofile) != 0)
			msg(EXTN, "close error");
	}
	if (Archive > 0) {
		if (close(Archive) != 0)
			msg(EXTN, "close error");
	}
	if ((Args & OCq) == 0) {
		Blocks = (u_longlong_t)(Blocks * Bufsize + SBlocks +
		    0x1FF) >> 9;
		msg(EPOST, "%lld blocks", Blocks);
	}
	if (Error_cnt)
		msg(EPOST, "%d error(s)", Error_cnt);
	return (EXIT_CODE);
}

/*
 * add_lnk: Add a linked file's header to the linked file data structure, by
 * either adding it to the end of an existing sub-list or starting
 * a new sub-list.  Each sub-list saves the links to a given file.
 *
 * Directly returns a pointer to the new entry; returns a pointer to the head
 * of the sub-list in which that entry is located through the argument.
 */

static struct Lnk *
add_lnk(struct Lnk **sublist_return)
{
	struct Lnk *new_entry, *sublist;

	for (sublist = Lnk_hd.L_nxt_p;
	    sublist != &Lnk_hd;
	    sublist = sublist->L_nxt_p) {
		if (sublist->L_gen.g_ino == G_p->g_ino &&
		    sublist->L_gen.g_dev == G_p->g_dev) {
			/* found */
			break;
		}
	}

	new_entry = e_zalloc(E_EXIT, sizeof (struct Lnk));

	new_entry->L_lnk_p = NULL;
	new_entry->L_gen = *G_p; /* structure copy */

	new_entry->L_gen.g_nam_p = e_zalloc(E_EXIT, (size_t)G_p->g_namesz);

	(void) strcpy(new_entry->L_gen.g_nam_p, G_p->g_nam_p);

	if (sublist == &Lnk_hd) {
		/* start new sub-list */
		new_entry->L_nxt_p = &Lnk_hd;
		new_entry->L_bck_p = Lnk_hd.L_bck_p;
		Lnk_hd.L_bck_p = new_entry->L_bck_p->L_nxt_p = new_entry;
		new_entry->L_lnk_p = NULL;
		new_entry->L_cnt = 1;
		new_entry->L_data = Onecopy ? 0 : 1;
		sublist = new_entry;
	} else {
		/* add to existing sub-list */
		struct Lnk *ptr;

		sublist->L_cnt++;

		for (ptr = sublist;
		    ptr->L_lnk_p != NULL;
		    ptr = ptr->L_lnk_p) {
			ptr->L_gen.g_filesz = G_p->g_filesz;
		}

		ptr->L_gen.g_filesz = G_p->g_filesz;
		ptr->L_lnk_p = new_entry;
	}

	*sublist_return = sublist;
	return (new_entry);
}

/*
 * bfill: Read req_cnt bytes (out of filelen bytes) from the I/O buffer,
 * moving them to rd_buf_p.  When there are no bytes left in the I/O buffer,
 * Fillbuf is set and the I/O buffer is filled.  The variable dist is the
 * distance to lseek if an I/O error is encountered with the -k option set
 * (converted to a multiple of Bufsize).
 */

static int
bfill(void)
{
	int i = 0, rv;
	static int eof = 0;

	if (!Dflag) {
	while ((Buffr.b_end_p - Buffr.b_in_p) >= Bufsize) {
		errno = 0;
		if ((rv = g_read(Device, Archive, Buffr.b_in_p, Bufsize)) < 0) {
			if (((Buffr.b_end_p - Buffr.b_in_p) >= Bufsize) &&
			    (Eomflag == 0)) {
				Eomflag = 1;
				return (1);
			}
			if (errno == ENOSPC) {
				(void) chgreel(INPUT);
				if (Hdr_type == BAR) {
					skip_bar_volhdr();
				}
				continue;
			} else if (Args & OCk) {
				if (i++ > MX_SEEKS)
					msg(EXT, "Cannot recover.");
				if (lseek(Archive, Bufsize, SEEK_REL) < 0)
					msg(EXTN, "Cannot lseek()");
				Error_cnt++;
				Buf_error++;
				rv = 0;
				continue;
			} else
				ioerror(INPUT);
		} /* (rv = g_read(Device, Archive ... */
		if (Hdr_type != BAR || rv == Bufsize) {
			Buffr.b_in_p += rv;
			Buffr.b_cnt += (long)rv;
		}
		if (rv == Bufsize) {
			eof = 0;
			Blocks++;
		} else if (rv == 0) {
			if (!eof) {
				eof = 1;
				break;
			}
			(void) chgreel(INPUT);
			eof = 0;	/* reset the eof after chgreel	*/

			/*
			 * if spans multiple volume, skip the volume header of
			 * the next volume so that the file currently being
			 * extracted can continue to be extracted.
			 */
			if (Hdr_type == BAR) {
				skip_bar_volhdr();
			}

			continue;
		} else {
			eof = 0;
			SBlocks += (u_longlong_t)rv;
		}
	} /* (Buffr.b_end_p - Buffr.b_in_p) <= Bufsize */

	} else {			/* Dflag */
		errno = 0;
		if ((rv = g_read(Device, Archive, Buffr.b_in_p, Bufsize)) < 0) {
			return (-1);
		} /* (rv = g_read(Device, Archive ... */
		Buffr.b_in_p += rv;
		Buffr.b_cnt += (long)rv;
		if (rv == Bufsize) {
			eof = 0;
			Blocks++;
		} else if (!rv) {
			if (!eof) {
				eof = 1;
				return (rv);
			}
			return (-1);
		} else {
			eof = 0;
			SBlocks += (u_longlong_t)rv;
		}
	}
	return (rv);
}

/*
 * bflush: Move wr_cnt bytes from data_p into the I/O buffer.  When the
 * I/O buffer is full, Flushbuf is set and the buffer is written out.
 */

static void
bflush(void)
{
	int rv;

	while (Buffr.b_cnt >= Bufsize) {
		errno = 0;
		if ((rv = g_write(Device, Archive, Buffr.b_out_p,
		    Bufsize)) < 0) {
			if (errno == ENOSPC && !Dflag)
				rv = chgreel(OUTPUT);
			else
				ioerror(OUTPUT);
		}
		Buffr.b_out_p += rv;
		Buffr.b_cnt -= (long)rv;
		if (rv == Bufsize)
			Blocks++;
		else if (rv > 0)
			SBlocks += (u_longlong_t)rv;
	}
	rstbuf();
}

/*
 * chgreel: Determine if end-of-medium has been reached.  If it has,
 * close the current medium and prompt the user for the next medium.
 */

static int
chgreel(int dir)
{
	int lastchar, tryagain, askagain, rv;
	int tmpdev;
	char str[APATH];
	struct stat statb;

	rv = 0;
	if (fstat(Archive, &statb) < 0)
		msg(EXTN, "Error during stat() of archive");
	if ((statb.st_mode & S_IFMT) != S_IFCHR) {
		if (dir == INPUT) {
			msg(EXT, "%s%s\n",
			    "Can't read input:  end of file encountered ",
			    "prior to expected end of archive.");
		}
	}
	msg(EPOST, "\007End of medium on \"%s\".", dir ? "output" : "input");
	if (is_floppy(Archive))
		(void) ioctl(Archive, FDEJECT, NULL);
	if ((close(Archive) != 0) && (dir == OUTPUT))
		msg(EXTN, "close error");
	Archive = 0;
	Volcnt++;
	for (;;) {
		if (Rtty_p == NULL)
			Rtty_p = fopen(Ttyname, "r");
		do { /* tryagain */
			if (IOfil_p) {
				do {
					msg(EPOST, Eom_p, Volcnt);
					if (!Rtty_p || fgets(str, sizeof (str),
					    Rtty_p) == NULL)
						msg(EXT, "Cannot read tty.");
					askagain = 0;
					switch (*str) {
					case '\n':
						(void) strcpy(str, IOfil_p);
						break;
					case 'q':
						exit(EXIT_CODE);
					default:
						askagain = 1;
					}
				} while (askagain);
			} else {

				if (Hdr_type == BAR)
					Bar_vol_num++;

				msg(EPOST,
				    "To continue, type device/file name when "
				    "ready.");
				if (!Rtty_p || fgets(str, sizeof (str),
				    Rtty_p) == NULL)
					msg(EXT, "Cannot read tty.");
				lastchar = strlen(str) - 1;
				if (*(str + lastchar) == '\n') /* remove '\n' */
					*(str + lastchar) = '\0';
				if (!*str)
					exit(EXIT_CODE);
			}
			tryagain = 0;
			if ((Archive = open(str, dir)) < 0) {
				msg(ERRN, "Cannot open \"%s\"", str);
				tryagain = 1;
			}
		} while (tryagain);
		(void) g_init(&tmpdev, &Archive);
		if (tmpdev != Device)
			msg(EXT, "Cannot change media types in mid-stream.");
		if (dir == INPUT)
			break;
		else { /* dir == OUTPUT */
			errno = 0;
			if ((rv = g_write(Device, Archive, Buffr.b_out_p,
			    Bufsize)) == Bufsize)
				break;
			else
				msg(ERR,
				    "Unable to write this medium, try "
				    "another.");
		}
	} /* ;; */
	Eomflag = 0;
	return (rv);
}

/*
 * ckname: Check filenames against user specified patterns,
 * and/or ask the user for new name when -r is used.
 */

static int
ckname(int flag)
{
	int	lastchar;
	size_t	rename_bufsz = Max_namesz + 1;

	if (Hdr_type != TAR && Hdr_type != USTAR && Hdr_type != BAR) {
		/* Re-visit tar size issues later */
		if (G_p->g_namesz - 1 > Max_namesz) {
			msg(ERR, "Name exceeds maximum length - skipped.");
			return (F_SKIP);
		}
	}

	if (Pat_pp && !matched())
		return (F_SKIP);

	/* rename interactively */
	if ((Args & OCr) && !Adir && !G_p->g_rw_sysattr) {
		(void) fprintf(Wtty_p, gettext("Rename \"%s%s%s\"? "),
		    (G_p->g_attrnam_p == NULL) ? G_p->g_nam_p : Renam_p,
		    (G_p->g_attrnam_p == NULL) ? "" : gettext(" Attribute "),
		    (G_p->g_attrnam_p == NULL) ? "" : G_p->g_attrnam_p);
		(void) fflush(Wtty_p);
		if (fgets(Renametmp_p, rename_bufsz, Rtty_p) == NULL)
			msg(EXT, "Cannot read tty.");
		if (feof(Rtty_p))
			exit(EXIT_CODE);
		lastchar = strlen(Renametmp_p) - 1;

		/* remove trailing '\n' */
		if (*(Renametmp_p + lastchar) == '\n')
			*(Renametmp_p + lastchar) = '\0';
		if (*Renametmp_p == '\0') {
			msg(POST, "%s%s%s Skipped.",
			    (G_p->g_attrnam_p == NULL) ? G_p->g_nam_p :
			    G_p->g_attrfnam_p,
			    (G_p->g_attrnam_p == NULL) ? "" :
			    gettext(" Attribute "),
			    (G_p->g_attrnam_p == NULL) ? "" : G_p->g_attrnam_p);
			if (G_p->g_attrparent_p == NULL) {
				*G_p->g_nam_p = '\0';
			}
			if (Renam_attr_p) {
				*Renam_attr_p = '\0';
			}
			return (F_SKIP);
		} else if (strcmp(Renametmp_p, ".") != 0) {
			if (G_p->g_attrnam_p == NULL) {
				if (strlen(Renametmp_p) > strlen(
				    G_p->g_nam_p)) {
					if ((G_p->g_nam_p != &nambuf[0]) &&
					    (G_p->g_nam_p != &fullnam[0])) {
						free(G_p->g_nam_p);
						G_p->g_nam_p = e_zalloc(E_EXIT,
						    rename_bufsz);
					}
				}
				if (Renam_attr_p) {
					*Renam_attr_p = '\0';
				}
				if ((strlcpy(Renam_p, Renametmp_p,
				    rename_bufsz) > rename_bufsz) ||
				    (strlcpy(G_p->g_nam_p, Renametmp_p,
				    rename_bufsz) > rename_bufsz)) {
					msg(EXTN, "buffer overflow");
				}
			} else {
				if (G_p->g_attrnam_p != NULL) {
					free(G_p->g_attrnam_p);
					G_p->g_attrnam_p = e_strdup(E_EXIT,
					    Renametmp_p);
					(void) strcpy(G_p->g_nam_p, Renam_p);
					if (Renam_attr_p) {
						if (strlcpy(Renam_attr_p,
						    Renametmp_p, rename_bufsz) >
						    rename_bufsz) {
							msg(EXTN,
							    "buffer overflow");
						}
					}
				}
			}
		} else {
			if (G_p->g_attrnam_p == NULL) {
				*Renam_p = '\0';
			}
			if (Renam_attr_p) {
				*Renam_attr_p = '\0';
			}
		}
	}
	if (flag != 0 || Onecopy == 0) {
		VERBOSE((Args & OCt), G_p->g_nam_p);
	}
	if (Args & OCt)
		return (F_SKIP);
	return (F_EXTR);
}

/*
 * ckopts: Check the validity of all command line options.
 */

static void
ckopts(long mask)
{
	int oflag;
	char *t_p;
	long errmsk;
	uid_t	Euid = geteuid();	/* Effective uid of invoker */
#ifdef SOLARIS_PRIVS
	priv_set_t *privset;
	priv_set_t *zones_privset;
#endif	/* SOLARIS_PRIVS */

	if (mask & OCi) {
		errmsk = mask & INV_MSK4i;
	} else if (mask & OCo) {
		errmsk = mask & INV_MSK4o;
	} else if (mask & OCp) {
		errmsk = mask & INV_MSK4p;
	} else {
		msg(ERR, "One of -i, -o or -p must be specified.");
		errmsk = 0;
	}

	if (errmsk) {
		/* if non-zero, invalid options were specified */
		Error_cnt++;
	}

	if ((mask & OCa) && (mask & OCm) && ((mask & OCi) ||
	    (mask & OCo))) {
		msg(ERR, "-a and -m are mutually exclusive.");
	}

	if ((mask & OCc) && (mask & OCH) &&
	    (strcmp("odc", Hdr_p) != 0 && strcmp("odc_sparse", Hdr_p) != 0)) {
		msg(ERR, "-c and -H are mutually exclusive.");
	}

	if ((mask & OCv) && (mask & OCV)) {
		msg(ERR, "-v and -V are mutually exclusive.");
	}

	if ((mask & OCt) && (mask & OCV)) {
		msg(ERR, "-t and -V are mutually exclusive.");
	}

	if ((mask & OCB) && (mask & OCC)) {
		msg(ERR, "-B and -C are mutually exclusive.");
	}

	if ((mask & OCH) && (mask & OC6)) {
		msg(ERR, "-H and -6 are mutually exclusive.");
	}

	if ((mask & OCM) && !((mask & OCI) || (mask & OCO))) {
		msg(ERR, "-M not meaningful without -O or -I.");
	}

	if ((mask & OCA) && !(mask & OCO)) {
		msg(ERR, "-A requires the -O option.");
	}

	if (Bufsize <= 0) {
		msg(ERR, "Illegal size given for -C option.");
	}

	if (mask & OCH) {
		t_p = Hdr_p;

		while (*t_p != NULL) {
			if (isupper(*t_p)) {
				*t_p = 'a' + (*t_p - 'A');
			}

			t_p++;
		}

		if (!(strcmp("odc", Hdr_p))) {
			Hdr_type = CHR;
			Max_namesz = CPATH;
			Onecopy = 0;
			Use_old_stat = 1;
		} else if (!(strcmp("odc_sparse", Hdr_p))) {
			Hdr_type = CHR;
			Max_namesz = CPATH;
			Onecopy = 0;
			Use_old_stat = 1;
			Compress_sparse = 1;
		} else if (!(strcmp("ascii_sparse", Hdr_p))) {
			Hdr_type = ASC;
			Max_namesz = APATH;
			Onecopy = 1;
			Compress_sparse = 1;
		} else if (!(strcmp("crc", Hdr_p))) {
			Hdr_type = CRC;
			Max_namesz = APATH;
			Onecopy = 1;
		} else if (!(strcmp("tar", Hdr_p))) {
			if (Args & OCo) {
				Hdr_type = USTAR;
				Max_namesz = HNAMLEN - 1;
			} else {
				Hdr_type = TAR;
				Max_namesz = TNAMLEN - 1;
			}
			Onecopy = 0;
		} else if (!(strcmp("ustar", Hdr_p))) {
			Hdr_type = USTAR;
			Max_namesz = HNAMLEN - 1;
			Onecopy = 0;
		} else if (!(strcmp("bar", Hdr_p))) {
			if ((Args & OCo) || (Args & OCp)) {
				msg(ERR,
				    "Header type bar can only be used with -i");
			}

			if (Args & OCP) {
				msg(ERR,
				    "Can't preserve using bar header");
			}

			Hdr_type = BAR;
			Max_namesz = TNAMLEN - 1;
			Onecopy = 0;
		} else {
			msg(ERR, "Invalid header \"%s\" specified", Hdr_p);
		}
	}

	if (mask & OCr) {
		Rtty_p = fopen(Ttyname, "r");
		Wtty_p = fopen(Ttyname, "w");

		if (Rtty_p == NULL || Wtty_p == NULL) {
			msg(ERR, "Cannot rename, \"%s\" missing", Ttyname);
		}
	}

	if ((mask & OCE) && (Ef_p = fopen(Efil_p, "r")) == NULL) {
		msg(ERR, "Cannot open \"%s\" to read patterns", Efil_p);
	}

	if ((mask & OCI) && (Archive = open(IOfil_p, O_RDONLY)) < 0) {
		msg(ERR, "Cannot open \"%s\" for input", IOfil_p);
	}

	if (mask & OCO) {
		if (mask & OCA) {
			if ((Archive = open(IOfil_p, O_RDWR)) < 0) {
				msg(ERR,
				    "Cannot open \"%s\" for append",
				    IOfil_p);
			}
		} else {
			oflag = (O_WRONLY | O_CREAT | O_TRUNC);

			if ((Archive = open(IOfil_p, oflag, 0777)) < 0) {
				msg(ERR,
				    "Cannot open \"%s\" for output",
				    IOfil_p);
			}
		}
	}

#ifdef SOLARIS_PRIVS
	if ((privset = priv_allocset()) == NULL) {
		msg(ERR, "Unable to allocate privilege set");
	} else if (getppriv(PRIV_EFFECTIVE, privset) != 0) {
		msg(ERR, "Unable to obtain privilege set");
	} else {
		zones_privset = priv_str_to_set("zone", "", NULL);
		if (zones_privset != NULL) {
			privileged = (priv_issubset(zones_privset,
			    privset) == B_TRUE);
			priv_freeset(zones_privset);
		} else {
			msg(ERR, "Unable to map privilege to privilege set");
		}
	}
	if (privset != NULL) {
		priv_freeset(privset);
	}
#else
	privileged = (Euid == 0);
#endif	/* SOLARIS_PRIVS */

	if (mask & OCR) {
		if ((Rpw_p = getpwnam(Own_p)) == NULL) {
			msg(ERR, "\"%s\" is not a valid user id", Own_p);
		} else if ((Euid != Rpw_p->pw_uid) && !privileged) {
			msg(ERR, "R option only valid for super-user or "
			    "id matches login id of user executing cpio");
		}
	}

	if ((mask & OCo) && !(mask & OCO)) {
		Out_p = stderr;
	}

	if ((mask & OCp) && ((mask & (OCB|OCC)) == 0)) {
		/*
		 * We are in pass mode with no block size specified.  Use the
		 * larger of the native page size and 8192.
		 */

		Bufsize = (PageSize > 8192) ? PageSize : 8192;
	}
}

/*
 * cksum: Calculate the simple checksum of a file (CRC) or header
 * (TARTYP (TAR and USTAR)).  For -o and the CRC header, the file is opened and
 * the checksum is calculated.  For -i and the CRC header, the checksum
 * is calculated as each block is transferred from the archive I/O buffer
 * to the file system I/O buffer.  The TARTYP (TAR and USTAR) headers calculate
 * the simple checksum of the header (with the checksum field of the
 * header initialized to all spaces (\040).
 */

static long
cksum(char hdr, int byt_cnt, int *err)
{
	char *crc_p, *end_p;
	int cnt;
	long checksum = 0L, have;
	off_t lcnt;

	if (err != NULL)
		*err = 0;
	switch (hdr) {
	case CRC:
		if (Args & OCi) { /* do running checksum */
			end_p = Buffr.b_out_p + byt_cnt;
			for (crc_p = Buffr.b_out_p; crc_p < end_p; crc_p++)
				checksum += (long)*crc_p;
			break;
		}
		/* OCo - do checksum of file */
		lcnt = G_p->g_filesz;

		while (lcnt > 0) {
			have = (lcnt < Bufsize) ? lcnt : Bufsize;
			errno = 0;
			if (read(Ifile, Buf_p, have) != have) {
				msg(ERR, "Error computing checksum.");
				if (err != NULL)
					*err = 1;
				break;
			}
			end_p = Buf_p + have;
			for (crc_p = Buf_p; crc_p < end_p; crc_p++)
				checksum += (long)*crc_p;
			lcnt -= have;
		}
		if (lseek(Ifile, (off_t)0, SEEK_ABS) < 0)
			msg(ERRN, "Cannot reset file after checksum");
		break;
	case TARTYP: /* TAR and USTAR */
		crc_p = Thdr_p->tbuf.t_cksum;
		for (cnt = 0; cnt < TCRCLEN; cnt++) {
			*crc_p = '\040';
			crc_p++;
		}
		crc_p = (char *)Thdr_p;
		for (cnt = 0; cnt < TARSZ; cnt++) {
			/*
			 * tar uses unsigned checksum, so we must use unsigned
			 * here in order to be able to read tar archives.
			 */
			checksum += (long)((unsigned char)(*crc_p));
			crc_p++;
		}
		break;
	default:
		msg(EXT, "Impossible header type.");
	} /* hdr */
	return (checksum);
}

/*
 * creat_hdr: Fill in the generic header structure with the specific
 *            header information based on the value of Hdr_type.
 *
 *            return (1) if this process was successful, and (0) otherwise.
 */

static int
creat_hdr(void)
{
	ushort_t ftype;
	int fullnamesize;
	dev_t dev;
	ino_t ino;

	ftype = SrcSt.st_mode & Ftype;
	Adir = (ftype == S_IFDIR);
	Aspec = (ftype == S_IFBLK || ftype == S_IFCHR || ftype == S_IFIFO ||
	    ftype == S_IFSOCK);
	switch (Hdr_type) {
		case BIN:
			Gen.g_magic = CMN_BIN;
			break;
		case CHR:
			Gen.g_magic = CMN_BIN;
			break;
		case ASC:
			Gen.g_magic = CMN_ASC;
			break;
		case CRC:
			Gen.g_magic = CMN_CRC;
			break;
		case USTAR:
			/*
			 * If the length of the full name is greater than 256,
			 * print out a message and return.
			 */
			if ((fullnamesize = strlen(Gen.g_nam_p)) > MAXNAM) {
				msg(ERR,
				    "%s: file name too long", Gen.g_nam_p);
				return (0);
			} else if (fullnamesize > NAMSIZ) {
				/*
				 * The length of the full name is greater than
				 * 100, so we must split the filename from the
				 * path
				 */
				char namebuff[NAMSIZ+1];
				char prebuff[PRESIZ+1];
				char *lastslash;
				int presize, namesize;

				(void) memset(namebuff, '\0',
				    sizeof (namebuff));
				(void) memset(prebuff, '\0', sizeof (prebuff));

				lastslash = strrchr(Gen.g_nam_p, '/');

				if (lastslash != NULL) {
					namesize = strlen(++lastslash);
					presize = fullnamesize - namesize - 1;
				} else {
					namesize = fullnamesize;
					lastslash = Gen.g_nam_p;
					presize = 0;
				}

				/*
				 * If the filename is greater than 100 we can't
				 * archive the file
				 */
				if (namesize > NAMSIZ) {
					msg(ERR,
					    "%s: filename is greater than %d",
					    lastslash, NAMSIZ);
					return (0);
				}
				(void) strncpy(&namebuff[0], lastslash,
				    namesize);
				/*
				 * If the prefix is greater than 155 we can't
				 * archive the file.
				 */
				if (presize > PRESIZ) {
					msg(ERR,
					    "%s: prefix is greater than %d",
					    Gen.g_nam_p, PRESIZ);
					return (0);
				}
				(void) strncpy(&prebuff[0], Gen.g_nam_p,
				    presize);

				Gen.g_tname = e_zalloc(E_EXIT, namesize + 1);
				(void) strcpy(Gen.g_tname, namebuff);

				Gen.g_prefix = e_zalloc(E_EXIT, presize + 1);
				(void) strcpy(Gen.g_prefix, prebuff);
			} else {
				Gen.g_tname = Gen.g_nam_p;
			}
			(void) strcpy(Gen.g_tmagic, "ustar");
			(void) strcpy(Gen.g_version, "00");

			dpasswd = getpwuid(SrcSt.st_uid);
			if (dpasswd == NULL) {
				msg(EPOST,
				    "cpio: could not get passwd information "
				    "for %s%s%s",
				    (Gen.g_attrnam_p == NULL) ?
				    Gen.g_nam_p : Gen.g_attrfnam_p,
				    (Gen.g_attrnam_p == NULL) ?
				    "" : Gen.g_rw_sysattr ?
				    gettext(" System Attribute ") :
				    gettext(" Attribute "),
				    (Gen.g_attrnam_p == NULL) ?
				    "" : Gen.g_attrnam_p);
				/* make name null string */
				Gen.g_uname[0] = '\0';
			} else {
				(void) strncpy(&Gen.g_uname[0],
				    dpasswd->pw_name, 32);
			}
			dgroup = getgrgid(SrcSt.st_gid);
			if (dgroup == NULL) {
				msg(EPOST,
				    "cpio: could not get group information "
				    "for %s%s%s",
				    (Gen.g_attrnam_p == NULL) ?
				    Gen.g_nam_p : Gen.g_attrfnam_p,
				    (Gen.g_attrnam_p == NULL) ?
				    "" : Gen.g_rw_sysattr ?
				    gettext(" System Attribute ") :
				    gettext(" Attribute "),
				    (Gen.g_attrnam_p == NULL) ?
				    "" : Gen.g_attrnam_p);
				/* make name null string */
				Gen.g_gname[0] = '\0';
			} else {
				(void) strncpy(&Gen.g_gname[0],
				    dgroup->gr_name, 32);
			}
			Gen.g_typeflag = tartype(ftype);
			/* FALLTHROUGH */
		case TAR:
			(void) memset(T_lname, '\0', sizeof (T_lname));
			break;
		default:
			msg(EXT, "Impossible header type.");
	}

	if (Use_old_stat && (Gen.g_attrnam_p != NULL)) {
		/*
		 * When processing extended attributes, creat_hdr()
		 * can get called multiple times which means that
		 * SrcSt.st.st_dev would have gotten converted to
		 * -Hodc format.  We should always use the original
		 * device here as we need to be able to match on
		 * the original device id from the file that was
		 * previewed in sl_preview_synonyms().
		 */
		dev = Savedev;
	} else {
		dev = SrcSt.st_dev;
	}
	ino = SrcSt.st_ino;

	if (Use_old_stat) {
		SrcSt = *OldSt;
	}

	Gen.g_namesz = strlen(Gen.g_nam_p) + 1;
	Gen.g_uid = SrcSt.st_uid;
	Gen.g_gid = SrcSt.st_gid;
	Gen.g_dev = SrcSt.st_dev;

	if (Use_old_stat) {
		/* -Hodc */

		sl_info_t *p = sl_search(dev, ino, ftype);
		Gen.g_ino = p ? p->sl_ino2 : -1;

		if (Gen.g_ino == (ulong_t)-1) {
			msg(ERR, "%s%s%s: cannot be archived - inode too big "
			    "for -Hodc format",
			    (Gen.g_attrnam_p == NULL) ?
			    Gen.g_nam_p : Gen.g_attrfnam_p,
			    (Gen.g_attrnam_p == NULL) ? "" : Gen.g_rw_sysattr ?
			    gettext(" System Attribute ") :
			    gettext(" Attribute "),
			    (Gen.g_attrnam_p == NULL) ? "" : Gen.g_attrnam_p);
			return (0);
		}
	} else {
		Gen.g_ino = SrcSt.st_ino;
	}

	Gen.g_mode = SrcSt.st_mode;
	Gen.g_mtime = SrcSt.st_mtime;
	Gen.g_nlink = Adir ? SrcSt.st_nlink : sl_numlinks(dev, ino, ftype);

	if (ftype == S_IFREG || ftype == S_IFLNK)
		Gen.g_filesz = (off_t)SrcSt.st_size;
	else
		Gen.g_filesz = (off_t)0;
	Gen.g_rdev = SrcSt.st_rdev;
	return (1);
}

/*
 * creat_lnk: Create a link from the existing name1_p to name2_p.
 */

static
int
creat_lnk(int dirfd, char *name1_p, char *name2_p)
{
	int cnt = 0;

	do {
		errno = 0;
		if (!link(name1_p, name2_p)) {
			if (aclp != NULL) {
				acl_free(aclp);
				aclp = NULL;
				acl_is_set = 0;
			}
			cnt = 0;
			break;
		} else if ((errno == EEXIST) && (cnt == 0)) {
			struct stat lsb1;
			struct stat lsb2;

			/*
			 * Check to see if we are trying to link this
			 * file to itself.  If so, count the effort as
			 * successful.  If the two files are different,
			 * or if either lstat is unsuccessful, proceed
			 * as we would have otherwise; the appropriate
			 * error will be reported subsequently.
			 */

			if (lstat(name1_p, &lsb1) != 0) {
				msg(ERR, "Cannot lstat source file %s",
				    name1_p);
			} else {
				if (lstat(name2_p, &lsb2) != 0) {
					msg(ERR, "Cannot lstat "
					    "destination file %s", name2_p);
				} else {
					if (lsb1.st_dev == lsb2.st_dev &&
					    lsb1.st_ino == lsb2.st_ino) {
						VERBOSE((Args & (OCv | OCV)),
						    name2_p);
						return (0);
					}
				}
			}

			if (!(Args & OCu) && G_p->g_mtime <= DesSt.st_mtime)
				msg(ERR, "Existing \"%s\" same age or newer",
				    name2_p);
			else if (unlinkat(dirfd, get_component(name2_p), 0) < 0)
				msg(ERRN, "Error cannot unlink \"%s\"",
				    name2_p);
		}
		cnt++;
	} while ((cnt < 2) && missdir(name2_p) == 0);
	if (!cnt) {
		char *newname;
		char *fromname;
		char *attrname;

		newname = name2_p;
		fromname = name1_p;
		attrname = Gen.g_attrnam_p;
		if (attrname) {
			if (Args & OCp) {
				newname = fromname = Fullnam_p;
			} else {
				newname = Gen.g_attrfnam_p;
			}
		}
		if (Args & OCv) {
			(void) fprintf(Err_p,
			    gettext("%s%s%s linked to %s%s%s\n"), newname,
			    (attrname == NULL) ? "" : gettext(" attribute "),
			    (attrname == NULL) ? "" : attrname,
			    (attrname == NULL) ? fromname : newname,
			    (attrname == NULL) ? "" : gettext(" attribute "),
			    (attrname == NULL) ? "" : name1_p);
		} else {
			VERBOSE((Args & (OCv | OCV)), newname);
		}
	} else if (cnt == 1)
		msg(ERRN,
		    "Unable to create directory for \"%s\"", name2_p);
	else if (cnt == 2)
		msg(ERRN,
		    "Cannot link \"%s\" and \"%s\"", name1_p, name2_p);
	return (cnt);
}

/*
 * creat_spec:
 *   Create one of the following:
 *       directory
 *       character special file
 *       block special file
 *       fifo
 *	 socket
 */

static int
creat_spec(int dirfd)
{
	char *nam_p;
	int cnt, result, rv = 0;
	char *curdir;
	char *lastslash;

	Do_rename = 0;	/* creat_tmp() may reset this */

	if (Args & OCp) {
		nam_p = Fullnam_p;
	} else {
		nam_p = G_p->g_nam_p;
	}

	/*
	 * Is this the extraction of the hidden attribute directory?
	 * If we are processing the hidden attribute directory of an
	 * attribute, then just return as modes and times cannot be set.
	 * Otherwise, if we are processing a hidden attribute, just set
	 * the mode/times correctly and return.
	 */

	if (Hiddendir) {
		if (G_p->g_attrparent_p == NULL) {
			if (Args & OCR) {
				if (fchownat(dirfd, ".", Rpw_p->pw_uid,
				    Rpw_p->pw_gid, 0) != 0) {
					msg(ERRN,
					    "Cannot chown() \"attribute "
					    "directory of file %s\"",
					    G_p->g_attrfnam_p);
				}
			} else if ((fchownat(dirfd, ".", G_p->g_uid,
			    G_p->g_gid, 0) != 0) && privileged) {
				msg(ERRN,
				    "Cannot chown() \"attribute directory of "
				    "file %s\"", G_p->g_attrfnam_p);
			}

			if (fchmod(dirfd, G_p->g_mode) != 0) {
				msg(ERRN,
				    "Cannot chmod() \"attribute directory of "
				    "file %s\"", G_p->g_attrfnam_p);
			}

			acl_is_set = 0;
			if (Pflag && aclp != NULL) {
				if (facl_set(dirfd, aclp) < 0) {
					msg(ERRN,
					    "failed to set acl on attribute"
					    " directory of %s ",
					    G_p->g_attrfnam_p);
				} else {
					acl_is_set = 1;
				}
				acl_free(aclp);
				aclp = NULL;
			}
		}

		return (1);
	}

	result = stat(nam_p, &DesSt);

	if (ustar_dir() || Adir) {
		/*
		 *  The archive file is a directory.
		 *  Skip "." and ".."
		 */

		curdir = strrchr(nam_p, '.');

		if (curdir != NULL && curdir[1] == NULL) {
			lastslash = strrchr(nam_p, '/');

			if (lastslash != NULL) {
				lastslash++;
			} else {
				lastslash = nam_p;
			}

			if (!(strcmp(lastslash, ".")) ||
			    !(strcmp(lastslash, ".."))) {
				return (1);
			}
		}

		if (result == 0) {
			/* A file by the same name exists. */

			/* Take care of ACLs */
			acl_is_set = 0;

			if (Pflag && aclp != NULL) {
				if (acl_set(nam_p, aclp) < 0) {
					msg(ERRN,
					    "\"%s\": failed to set acl",
					    nam_p);
				} else {
					acl_is_set = 1;
				}

				acl_free(aclp);
				aclp = NULL;
			}
			if (Args & OCd) {
				/*
				 * We are creating directories.  Keep the
				 * existing file.
				 */

				rstfiles(U_KEEP, dirfd);
			}

			/* Report success. */

			return (1);
		}
	} else {
		/* The archive file is not a directory. */

		if (result == 0) {
			/*
			 * A file by the same name exists.  Move it to a
			 * temporary file.
			 */

			if (creat_tmp(nam_p) < 0) {
				/*
				 * We weren't able to create the temp file.
				 * Report failure.
				 */

				return (0);
			}
		}
	}

	/*
	 * This pile tries to create the file directly, and, if there is a
	 * problem, creates missing directories, and then tries to create the
	 * file again.  Two strikes and you're out.
	 */

	cnt = 0;

	do {
		if (ustar_dir() || Adir) {
			/* The archive file is a directory. */

			result = mkdir(nam_p, G_p->g_mode);
		} else if (ustar_spec() || Aspec) {
			/*
			 * The archive file is block special,
			 * char special, socket, or a fifo.
			 * Note that, for a socket, the third
			 * parameter to mknod() is ignored.
			 */

			result = mknod(nam_p, (int)G_p->g_mode,
			    (int)G_p->g_rdev);
		}

		if (result >= 0) {
			/*
			 * The file creation succeeded.  Take care of the ACLs.
			 */

			acl_is_set = 0;

			if (Pflag && aclp != NULL) {
				if (acl_set(nam_p, aclp) < 0) {
					msg(ERRN,
					    "\"%s\": failed to set acl", nam_p);
				} else {
					acl_is_set = 1;
				}

				acl_free(aclp);
				aclp = NULL;
			}

			cnt = 0;
			break;
		}

		cnt++;
	} while (cnt < 2 && missdir(nam_p) == 0);

	switch (cnt) {
	case 0:
		rv = 1;
		rstfiles(U_OVER, dirfd);
		break;

	case 1:
		msg(ERRN,
		    "Cannot create directory for \"%s\"", nam_p);

		if (*Over_p == '\0') {
			rstfiles(U_KEEP, dirfd);
		}

		break;

	case 2:
		if (ustar_dir() || Adir) {
			msg(ERRN, "Cannot create directory \"%s\"", nam_p);
		} else if (ustar_spec() || Aspec) {
			msg(ERRN, "Cannot mknod() \"%s\"", nam_p);
		}

		if (*Over_p == '\0') {
			rstfiles(U_KEEP, dirfd);
		}

		break;

	default:
		msg(EXT, "Impossible case.");
	}

	return (rv);
}

/*
 * creat_tmp:
 */

static int
creat_tmp(char *nam_p)
{
	char *t_p;
	int	cwd;

	if ((Args & OCp) && G_p->g_ino == DesSt.st_ino &&
	    G_p->g_dev == DesSt.st_dev) {
		msg(ERR, "Attempt to pass a file to itself.");
		return (-1);
	}

	if (G_p->g_mtime <= DesSt.st_mtime && !(Args & OCu)) {
		msg(ERR, "Existing \"%s\" same age or newer", nam_p);
		return (-1);
	}

	/* Make the temporary file name. */

	(void) strcpy(Over_p, nam_p);
	t_p = Over_p + strlen(Over_p);

	while (t_p != Over_p) {
		if (*(t_p - 1) == '/')
			break;
		t_p--;
	}

	(void) strcpy(t_p, "XXXXXX");

	if (G_p->g_attrnam_p != NULL) {
		/*
		 * Save our current directory, so we can go into
		 * the attribute directory to make the temp file
		 * and then return.
		 */

		cwd = save_cwd();
		(void) fchdir(G_p->g_dirfd);
	}

	(void) mktemp(Over_p);

	if (G_p->g_attrnam_p != NULL) {
		/* Return to the current directory. */

		rest_cwd(cwd);
	}

	if (*Over_p == '\0') {
		/* mktemp reports a failure. */

		msg(ERR, "Cannot get temporary file name.");
		return (-1);
	}

	/*
	 * If it's a regular file, write to the temporary file, and then rename
	 * in order to accommodate potential executables.
	 *
	 * Note: g_typeflag is only defined (set) for USTAR archive types.  It
	 * defaults to 0 in the cpio-format-regular file case, so this test
	 * succeeds.
	 */

	if (G_p->g_typeflag == 0 &&
	    (DesSt.st_mode & (ulong_t)Ftype) == S_IFREG &&
	    (G_p->g_mode & (ulong_t)Ftype) == S_IFREG) {
		/*
		 * The archive file and the filesystem file are both regular
		 * files.  We write to the temporary file in this case.
		 */

		if (Args & OCp) {
			if (G_p->g_attrnam_p == NULL) {
				Fullnam_p = Over_p;
			} else {
				Attrfile_p = Over_p;
			}
		} else {
			G_p->g_nam_p = Over_p;
			if (G_p->g_attrnam_p != NULL) {
				Attrfile_p = Over_p;
			}
		}

		if (G_p->g_attrnam_p == NULL) {
			Over_p = nam_p;
		} else {
			Over_p = G_p->g_attrnam_p;
		}

		Do_rename = 1;
	} else {
		/*
		 * Either the archive file or the filesystem file is not a
		 * regular file.
		 */

		Do_rename = 0;

		if (S_ISDIR(DesSt.st_mode)) {
			/*
			 * The filesystem file is a directory.
			 *
			 * Save the current working directory because we will
			 * want to restore it back just in case remove_dir()
			 * fails or get confused about where we should be.
			 */

			*Over_p = '\0';
			cwd = save_cwd();

			if (remove_dir(nam_p) < 0) {
				msg(ERRN,
				    "Cannot remove the directory \"%s\"",
				    nam_p);
				/*
				 * Restore working directory back to the one
				 * saved earlier.
				 */

				rest_cwd(cwd);
				return (-1);
			}

			/*
			 * Restore working directory back to the one
			 * saved earlier
			 */

			rest_cwd(cwd);
		} else {
			/*
			 * The file is not a directory. Will use the original
			 * link/unlink construct, however, if the file is
			 * namefs, link would fail with EXDEV. Therefore, we
			 * use rename() first to back up the file.
			 */
			if (rename(nam_p, Over_p) < 0) {
				/*
				 * If rename failed, try old construction
				 * method.
				 */
				if (link(nam_p, Over_p) < 0) {
					msg(ERRN,
					    "Cannot rename temporary file "
					    "\"%s\" to \"%s\"", Over_p, nam_p);
					*Over_p = '\0';
					return (-1);
				}

				if (unlink(nam_p) < 0) {
					msg(ERRN,
					    "Cannot unlink() current \"%s\"",
					    nam_p);
					(void) unlink(Over_p);
					*Over_p = '\0';
					return (-1);
				}
			}
		}
	}

	return (1);
}

/*
 * Copy the datasize amount of data from the input file to buffer.
 *
 * ifd		- Input file descriptor.
 * buffer	- Buffer (allocated by caller) to copy data to.
 * datasize	- The amount of data to read from the input file
 *		and copy to the buffer.
 * error	- When reading from an Archive file, indicates unreadable
 *		data was encountered, otherwise indicates errno.
 * data_in_info	- Information needed when called from data_in().
 */
static ssize_t
read_chunk(int ifd, char *buffer, size_t datasize, data_in_t *data_in_info)
{
	if (Args & OCp) {
		return (read(ifd, buffer, datasize));
	} else {
		FILL(datasize);
		if (data_in_info->data_in_proc_mode != P_SKIP) {
			if (Hdr_type == CRC)
				data_in_info->data_in_cksumval += cksum(CRC,
				    datasize, NULL);
			if (data_in_info->data_in_swapfile)
				swap(Buffr.b_out_p, datasize);


			/*
			 * if the bar archive is compressed, set up a pipe and
			 * do the de-compression while reading in the file
			 */
			if (Hdr_type == BAR) {
				if (data_in_info->data_in_compress_flag == 0 &&
				    Compressed) {
					setup_uncompress(
					    &(data_in_info->data_in_pipef));
					data_in_info->data_in_compress_flag++;
				}
			}
		}
		(void) memcpy(buffer, Buffr.b_out_p, datasize);
		Buffr.b_out_p += datasize;
		Buffr.b_cnt -= datasize;
		return (datasize);
	}
}

/*
 * Read as much data as we can.
 *
 * ifd		- input file descriptor.
 * buf		- Buffer (allocated by caller) to copy data to.
 * bytes	- The amount of data to read from the input file
 *		and copy to the buffer.
 * rdblocksz	- The size of the chunk of data to read.
 *
 * Return number of bytes failed to read.
 * Return -1 when buffer is empty and read failed.
 */
static int
read_bytes(int ifd, char *buf, size_t bytes, size_t rdblocksz,
    data_in_t *data_in_info)
{
	size_t	bytesread;
	ssize_t	got;

	for (bytesread = 0; bytesread < bytes; bytesread += got) {
		/*
		 * Read the data from either the input file descriptor
		 * or the archive file.  read_chunk() will only return
		 * <= 0 if data_copy() was called from data_pass().
		 */
		if ((got = read_chunk(ifd, buf + bytesread,
		    min(bytes - bytesread, rdblocksz),
		    data_in_info)) <= 0) {
			/*
			 * We come here only in the pass mode.
			 * If data couldn't be read from the input file
			 * descriptor, return number of bytes in the buf.
			 * If buffer is empty, return -1.
			 */
			if (bytesread == 0) {
				if (got == 0) /* EOF */
					data_in_info->data_in_rd_eof = 1;
				return (-1);
			}
			return (bytes - bytesread);
		}
	}
	return (0);
}

/*
 * Write as much data as we can.
 *
 * ofd		- output file descriptor.
 * buf		- Source buffer to output data from.
 * maxwrite	- The amount of data to write to the output.
 *
 * return 0 upon success.
 */
static int
write_bytes(int ofd, char *buf, size_t maxwrite, data_in_t *data_in_info)
{
	ssize_t	cnt;

	errno = 0;
	if ((cnt = write(ofd, buf, maxwrite)) < (ssize_t)maxwrite) {
		data_in_info->data_in_errno = errno;
		/*
		 * data_in() needs to know if it was an actual write(2)
		 * failure, or if we just couldn't write all of the data
		 * requested so that we know that the rest of the file's
		 * data can be read but not written.
		 */
		if (cnt != -1)
			data_in_info->data_in_wr_part = 1;
		return (1);
	} else if (Args & OCp) {
		Blocks += (u_longlong_t)((cnt + (Bufsize - 1)) / Bufsize);
	}
	return (0);
}

/*
 * Perform I/O for given byte size with using limited i/o block size
 * and supplied buffer.
 *
 * ifd/ofd	- i/o file descriptor
 * buf		- buffer to be used for i/o
 * bytes	- Amount to read/write
 * wrblocksz	- Output block size.
 * rdblocksz	- Read block size.
 *
 * Return 0 upon success. Return negative if read failed.
 * Return positive non-zero if write failed.
 */
static int
rdwr_bytes(int ifd, int ofd, char *buf, off_t bytes,
    size_t wrblocksz, size_t rdblocksz, data_in_t *data_in_info)
{
	int rv, sz;
	int error = 0;
	int write_it = (data_in_info->data_in_proc_mode != P_SKIP);

	while (bytes > 0) {
		/*
		 * If the number of bytes left to write is smaller than
		 * the preferred I/O size, then we're about to do our final
		 * write to the file, so just set wrblocksz to the number of
		 * bytes left to write.
		 */
		if (bytes < wrblocksz)
			wrblocksz = bytes;

		/* Read input till satisfy output block size */
		sz = read_bytes(ifd, buf, wrblocksz, rdblocksz, data_in_info);
		if (sz < 0)
			return (sz);

		if (write_it) {
			rv = write_bytes(ofd, buf,
			    wrblocksz - sz, data_in_info);
			if (rv != 0) {
				/*
				 * If we wrote partial, we return and quits.
				 * Otherwise, read through the rest of input
				 * to go to the next file.
				 */
				if ((Args & OCp) ||
				    data_in_info->data_in_wr_part) {
					return (rv);
				} else {
					write_it = 0;
				}
				error = 1;
			}
		}
		bytes -= (wrblocksz - sz);
	}
	return (error);
}

/*
 * Write zeros for give size.
 *
 * ofd		- output file descriptor
 * buf		- buffer to fill with zeros
 * bytes	- Amount to write
 * wrblocksz	- Write block size
 *
 * return 0 upon success.
 */
static int
write_zeros(int ofd, char *buf, off_t bytes, size_t wrblocksz,
    data_in_t *data_in_info)
{
	int	rv;

	(void) memset(buf, 0, min(bytes, wrblocksz));
	while (bytes > 0) {
		if (bytes < wrblocksz)
			wrblocksz = bytes;
		rv = write_bytes(ofd, buf, wrblocksz, data_in_info);
		if (rv != 0)
			return (rv);
		bytes -= wrblocksz;
	}
	return (0);
}

/*
 * To figure out the size of the buffer used to accumulate data from
 * readtape() and to write to the file, we need to determine the largest
 * chunk of data to be written to the file at one time. This is determined
 * based on the following three things:
 *	1) The size of the archived file.
 *	2) The preferred I/O size of the file.
 *	3) If the file is a read-write system attribute file.
 * If the size of the file is less than the preferred I/O size or it's a
 * read-write system attribute file, which must be written in one operation,
 * then set the maximum write size to the size of the archived file.
 * Otherwise, the maximum write size is preferred I/O size.
 */
static int
calc_maxwrite(int ofd, int rw_sysattr, off_t bytes, size_t blocksize)
{
	struct stat tsbuf;
	size_t maxwrite;
	size_t piosize;		/* preferred I/O size */

	if (rw_sysattr || bytes < blocksize) {
		maxwrite = bytes;
	} else {
		if (fstat(ofd, &tsbuf) == 0) {
			piosize = tsbuf.st_blksize;
		} else {
			piosize = blocksize;
		}
		maxwrite = min(bytes, piosize);
	}
	return (maxwrite);
}
/*
 * data_copy() and data_copy_with_holes() copy data from the input
 * file to output file descriptor. If ifd is -1, then the input file is
 * the archive file.
 *
 * Parameters
 *	ifd		- Input file descriptor to read from.
 *	ofd		- Output file descriptor of extracted file.
 *	rw_sysattr	- Flag indicating if a file is an extended
 *			system attribute file.
 *	bytes		- Amount of data (file size) of copy/write.
 *	blocksize	- Amount of data to read at a time from either
 *			the input file descriptor or from the archive.
 *	data_in_info	- information needed while reading data when
 *			called by data_in().
 *	holes		- Information of holes in the input file.
 *
 * Return code
 *	0		Success
 *	< 0		An error occurred during the read of the input
 *			file
 *	> 0		An error occurred during the write of the output
 *			file descriptor.
 */
static int
data_copy(int ifd, int ofd, int rw_sysattr, off_t bytes,
    size_t blocksize, data_in_t *data_in_info)
{
	char *buf;
	size_t maxwrite;
	int rv;

	/* No data to copy. */
	if (bytes == 0)
		return (0);

	maxwrite = calc_maxwrite(ofd, rw_sysattr, bytes, blocksize);
	buf = e_zalloc(E_EXIT, maxwrite);

	rv = rdwr_bytes(ifd, ofd, buf, bytes, maxwrite,
	    blocksize, data_in_info);

	free(buf);
	return (rv);
}

static int
data_copy_with_holes(int ifd, int ofd, int rw_sysattr, off_t bytes,
    size_t blocksize, data_in_t *data_in_info, holes_info_t *holes)
{
	holes_list_t	*hl;
	off_t		curpos, noff, datasize;
	char		*buf;
	size_t		maxwrite;
	int		rv, error;

	if (bytes == 0)
		return (0);

	maxwrite = calc_maxwrite(ofd, rw_sysattr, bytes, blocksize);
	buf = e_zalloc(E_EXIT, maxwrite);

	error = 0;
	curpos = 0;
	for (hl = holes->holes_list; hl != NULL; hl = hl->hl_next) {
		if (curpos != hl->hl_data) {
			/* adjust output position */
			noff = lseek(ofd, hl->hl_data, SEEK_SET);
			if (noff != hl->hl_data) {
				/*
				 * Can't seek to the target, try to adjust
				 * position by filling with zeros.
				 */
				datasize = hl->hl_data - curpos;
				rv = write_zeros(ofd, buf, datasize,
				    maxwrite, data_in_info);
				if (rv != 0)
					goto errout;
			}
			/*
			 * Data is contiguous in the archive, but fragmented
			 * in the regular file, so we also adjust the input
			 * file position in pass mode.
			 */
			if (Args & OCp) {
				/* adjust input position */
				(void) lseek(ifd, hl->hl_data, SEEK_SET);
			}
			curpos = hl->hl_data;
		}
		datasize = hl->hl_hole - hl->hl_data;
		if (datasize == 0) {
			/*
			 * There is a hole at the end of file. To create
			 * such hole, we append one byte, and truncate the
			 * last block. This is necessary because ftruncate(2)
			 * alone allocates one block on the end of file.
			 */
			rv = write_zeros(ofd, buf, 1, maxwrite, data_in_info);
			if (rv != 0)
				goto errout;
			(void) ftruncate(ofd, hl->hl_data);
			break;
		}
		rv = rdwr_bytes(ifd, ofd, buf, datasize, maxwrite,
		    blocksize, data_in_info);
		if (rv != 0) {
errout:
			/*
			 * Return if we got a read error or in pass mode,
			 * or failed with partial write. Otherwise, we'll
			 * read through the input stream till next file.
			 */
			if (rv < 0 || (Args & OCp) ||
			    data_in_info->data_in_wr_part) {
				free(buf);
				return (rv);
			}
			error = 1;
			hl = hl->hl_next;
			break;
		}
		curpos += datasize;
	}

	/*
	 * We should read through the input data to go to the next
	 * header when non-fatal error occured.
	 */
	if (error && !(Args & OCp)) {
		data_in_info->data_in_proc_mode = P_SKIP;
		while (hl != NULL) {
			datasize = hl->hl_hole - hl->hl_data;
			rv = rdwr_bytes(ifd, ofd, buf, datasize, maxwrite,
			    blocksize, data_in_info);
			if (rv != 0)
				break;
			hl = hl->hl_next;
		}
	}

	free(buf);
	return (error);
}

/*
 * Strip off the sparse file information that is prepended to
 * the compressed sparse file. The information is in the following
 * format:
 * 	<prepended info size><SP><orig file size><SP><holes info>
 * where prepended info size is long right justified in 10 bytes.
 * Holesdata consists of the series of offset pairs:
 * 	<data offset><SP><hole offset><SP><data offset><SP><hole offset>...
 * prepended info size and original file size have been read in gethdr().
 * We read the rest of holes information here in this function.
 */
static int
read_holesdata(holes_info_t *holes, off_t *fileszp,
    char *nam_p, data_in_t *data_in_info)
{
	char		*holesdata;
	size_t		holesdata_sz;

	/* We've already read the header. */
	holesdata_sz = holes->holesdata_sz - MIN_HOLES_HDRSIZE;

	if ((holesdata = e_zalloc(E_NORMAL, holesdata_sz)) == NULL) {
		msg(ERRN, "Could not allocate memory for "
		    "sparse file information", nam_p);
		return (1);
	}
	/*
	 * This function is called only in OCi mode. Therefore,
	 * read_bytes() won't fail, and won't return if error occurs in
	 * input stream. See rstbuf().
	 */
	(void) read_bytes(-1, holesdata, holesdata_sz, CPIOBSZ, data_in_info);
	*fileszp -= holesdata_sz;

	/* The string should be terminated. */
	if (holesdata[holesdata_sz - 1] != '\0') {
invalid:
		free(holesdata);
		msg(ERR, "invalid sparse file information", nam_p);
		return (1);
	}
	if (parse_holesdata(holes, holesdata) != 0)
		goto invalid;

	/* sanity check */
	if (*fileszp != holes->data_size)
		goto invalid;

	free(holesdata);
	return (0);
}

/*
 * data_in:  If proc_mode == P_PROC, bread() the file's data from the archive
 * and write(2) it to the open fdes gotten from openout().  If proc_mode ==
 * P_SKIP, or becomes P_SKIP (due to errors etc), bread(2) the file's data
 * and ignore it.  If the user specified any of the "swap" options (b, s or S),
 * and the length of the file is not appropriate for that action, do not
 * perform the "swap", otherwise perform the action on a buffer by buffer basis.
 * If the CRC header was selected, calculate a running checksum as each buffer
 * is processed.
 */
static void
data_in(int proc_mode)
{
	char *nam_p;
	int pad, rv;
	int error = 0;
	int swapfile = 0;
	int cstatus = 0;
	off_t	filesz;
	data_in_t *data_in_info;

	if (G_p->g_attrnam_p != NULL) {
		nam_p = G_p->g_attrnam_p;
	} else {
		nam_p = G_p->g_nam_p;
	}

	if (((G_p->g_mode & Ftype) == S_IFLNK && proc_mode != P_SKIP) ||
	    (Hdr_type == BAR && bar_linkflag == '2' && proc_mode != P_SKIP)) {
		proc_mode = P_SKIP;
		VERBOSE((Args & (OCv | OCV)), nam_p);
	}
	if (Args & (OCb | OCs | OCS)) { /* verfify that swapping is possible */
		swapfile = 1;
		if (Args & (OCs | OCb) && G_p->g_filesz % 2) {
			msg(ERR,
			    "Cannot swap bytes of \"%s\", odd number of bytes",
			    nam_p);
			swapfile = 0;
		}
		if (Args & (OCS | OCb) && G_p->g_filesz % 4) {
			msg(ERR,
			    "Cannot swap halfwords of \"%s\", odd number "
			    "of halfwords", nam_p);
			swapfile = 0;
		}
	}

	data_in_info = e_zalloc(E_EXIT, sizeof (data_in_t));
	data_in_info->data_in_swapfile = swapfile;
	data_in_info->data_in_proc_mode = proc_mode;

	filesz = G_p->g_filesz;

	if (S_ISSPARSE(G_p->g_mode) && G_p->g_holes != NULL) {
		/* We've already read the header in gethdr() */
		filesz -= MIN_HOLES_HDRSIZE;

		/*
		 * Strip rest of the sparse file information. This includes
		 * the data/hole offset pairs which will be used to restore
		 * the holes in the file.
		 */
		if (proc_mode == P_SKIP) {
			/* holes info isn't necessary to skip file */
			free_holes_info(G_p->g_holes);
			G_p->g_holes = NULL;
		} else {
			rv = read_holesdata(G_p->g_holes, &filesz,
			    nam_p, data_in_info);
			if (rv != 0) {
				/*
				 * We got an error. Skip this file. holes info
				 * is no longer necessary.
				 */
				free_holes_info(G_p->g_holes);
				G_p->g_holes = NULL;

				data_in_info->data_in_proc_mode = P_SKIP;
				error = 1;
			}
		}
	}

	if (G_p->g_holes != NULL) {
		rv = data_copy_with_holes(-1, Ofile,
		    (G_p->g_attrnam_p == NULL) ? 0 : G_p->g_rw_sysattr,
		    G_p->g_holes->orig_size,
		    CPIOBSZ, data_in_info, G_p->g_holes);

		free_holes_info(G_p->g_holes);
		G_p->g_holes = NULL;
	} else {
		rv = data_copy(-1, Ofile,
		    (G_p->g_attrnam_p == NULL) ? 0 : G_p->g_rw_sysattr,
		    filesz, CPIOBSZ, data_in_info);
	}

	/* This writes out the file from the archive */
	if (rv != 0 || error) {
		errno = data_in_info->data_in_errno;

		if (!error) {
			msg(data_in_info->data_in_wr_part ? EXTN : ERRN,
			    "Cannot write \"%s%s%s\"",
			    (G_p->g_attrnam_p == NULL) ? "" :
			    G_p->g_attrfnam_p,
			    (G_p->g_attrnam_p == NULL) ? "" :
			    G_p->g_rw_sysattr ?
			    gettext(" System Attribute ") :
			    gettext(" Attribute "), nam_p);
		}
		/*
		 * We've failed to write to the file, and input data
		 * has been skiped to the next file. We'll need to restore
		 * the original file, and skip the rest of work.
		 */
		proc_mode = P_SKIP;
		rstfiles(U_KEEP, G_p->g_dirfd);
		cstatus = close(Ofile);
		Ofile = 0;
		if (cstatus != 0) {
			msg(EXTN, "close error");
		}
	}

	/* we must use g_filesz for the amount of padding */
	pad = (Pad_val + 1 - (G_p->g_filesz & Pad_val)) & Pad_val;
	if (pad != 0) {
		FILL(pad);
		Buffr.b_out_p += pad;
		Buffr.b_cnt -= pad;
	}
	if (proc_mode != P_SKIP) {
		if (Hdr_type == CRC &&
		    Gen.g_cksum != data_in_info->data_in_cksumval) {
			msg(ERR, "\"%s\" - checksum error", nam_p);
			rstfiles(U_KEEP, G_p->g_dirfd);
		} else
			rstfiles(U_OVER, G_p->g_dirfd);
		if (Hdr_type == BAR && data_in_info->data_in_compress_flag) {
			(void) pclose(data_in_info->data_in_pipef);
		} else {
			cstatus = close(Ofile);
		}
		Ofile = 0;
		if (cstatus != 0) {
			msg(EXTN, "close error");
		}
	}
	(void) free(data_in_info);

	VERBOSE((proc_mode != P_SKIP && (Args & (OCv | OCV))),
	    (G_p->g_attrparent_p == NULL) ? G_p->g_nam_p : G_p->g_attrpath_p);
	Finished = 1;
}

/*
 * Read regular file. Return number of bytes which weren't read.
 * Upon return, real_filesz will be real file size of input file.
 * When read_exact is specified, read size is adjusted to the given
 * file size.
 */
static off_t
read_file(char *nam_p, off_t file_size, off_t *real_filesz,
    boolean_t read_exact)
{
	int	amount_read;
	off_t	amt_to_read;
	off_t	readsz;

	if (file_size == 0)
		return (0);

	amt_to_read = file_size;
	do {
		if (read_exact && amt_to_read < CPIOBSZ)
			readsz = amt_to_read;
		else
			readsz = CPIOBSZ;

		FLUSH(readsz);
		errno = 0;

		if ((amount_read = read(Ifile, Buffr.b_in_p, readsz)) < 0) {
			msg(EXTN, "Cannot read \"%s%s%s\"",
			    (Gen.g_attrnam_p == NULL) ?
			    nam_p : Gen.g_attrfnam_p,
			    (Gen.g_attrnam_p == NULL) ? "" : Gen.g_rw_sysattr ?
			    gettext(" System Attribute ") :
			    gettext(" Attribute "),
			    (Gen.g_attrnam_p == NULL) ? "" : nam_p);
			break;
		}

		if (amount_read == 0) {
			/* got EOF. the file has shrunk */
			*real_filesz = file_size - amt_to_read;
			break;
		} else if (amount_read > amt_to_read) {
			/* the file has grown */
			*real_filesz = file_size +
			    (amount_read - amt_to_read);
			amount_read = amt_to_read;
		} else if (amount_read == amt_to_read) {
			/* the file is the same size */
			*real_filesz = file_size;
		}

		Buffr.b_in_p += amount_read;
		Buffr.b_cnt += (long)amount_read;

		amt_to_read -= (off_t)amount_read;
		if (!read_exact &&
		    amt_to_read == 0 && amount_read == CPIOBSZ) {
			/*
			 * If the file size is multiple of CPIOBSZ, we may
			 * be able to read more from the file even though
			 * amt_to_read already gets 0.
			 */
			FLUSH(CPIOBSZ);
			amount_read = read(Ifile, Buffr.b_in_p, CPIOBSZ);
			if (amount_read != 0) {
				/* the file has grown */
				*real_filesz = file_size + amount_read;
			}
		}
	} while (amt_to_read != 0);

	return (amt_to_read);
}

/*
 * Read through the data in files skipping holes.
 */
static off_t
read_compress_holes(char *nam_p, off_t file_size, off_t *real_filesz,
    holes_info_t *holes, int *hole_changed)
{
	off_t		left;
	off_t		datasize, realsz;
	off_t		curpos, npos;
	holes_list_t	*hl = holes->holes_list;

	curpos = 0;
	for (hl = holes->holes_list; hl != NULL; hl = hl->hl_next) {
		datasize = hl->hl_hole - hl->hl_data;

		npos = lseek(Ifile, curpos, SEEK_DATA);
		if (npos == -1 && errno == ENXIO) {
			/*
			 * No more data. There are two cases.
			 * - we have a hole toward the end of file.
			 * - file has been shrunk, and we've reached EOF.
			 */
			*real_filesz = lseek(Ifile, 0, SEEK_END);
			if (hl->hl_data == file_size)
				return (0);
			/*
			 * File has been shrunk. Check the amount of data
			 * left.
			 */
			left = 0;
			while (hl != NULL) {
				left += (hl->hl_hole - hl->hl_data);
				hl = hl->hl_next;
			}
			return (left);
		}

		/* found data */
		curpos = npos;
		if (curpos != hl->hl_data) {
			/*
			 * File has been changed. We shouldn't read data
			 * from different offset since we've already put
			 * the holes data.
			 */
			*hole_changed = 1;
			(void) lseek(Ifile, hl->hl_data, SEEK_SET);
			curpos = hl->hl_data;
		}
		left = read_file(nam_p, datasize, &realsz, B_TRUE);
		if (left != 0) {
			/* file has been shrunk */
			*real_filesz = curpos + datasize - left;
			left = file_size - *real_filesz;
			return (left);
		}
		curpos += datasize;
	}
	/*
	 * We've read exact size of holes. We need to make sure
	 * that file hasn't grown by reading from the EOF.
	 */
	realsz = 0;
	(void) read_file(nam_p, CPIOBSZ, &realsz, B_FALSE);

	*real_filesz = curpos + realsz;
	return (0);
}

/*
 * data_out:  open(2) the file to be archived, compute the checksum
 * of it's data if the CRC header was specified and write the header.
 * read(2) each block of data and bwrite() it to the archive.  For TARTYP (TAR
 * and USTAR) archives, pad the data with NULLs to the next 512 byte boundary.
 */
static void
data_out(void)
{
	char		*nam_p;
	int		cnt, pad;
	off_t		amt_to_read;
	off_t		real_filesz;
	int		errret = 0;
	int		hole_changed = 0;
	off_t		orig_filesz;
	holes_info_t	*holes = NULL;

	nam_p = G_p->g_nam_p;
	if (Aspec) {
		if (Pflag && aclp != NULL) {
			char    *secinfo = NULL;
			int	len = 0;

			/* append security attributes */
			if (append_secattr(&secinfo, &len, aclp) == -1) {
				msg(ERR,
				    "can create security information");
			}
			/* call append_secattr() if more than one */

			if (len > 0) {
			/* write ancillary only if there is sec info */
				write_hdr(ARCHIVE_ACL, (off_t)len);
				write_ancillary(secinfo, len, B_TRUE);
			}
		}
		write_hdr(ARCHIVE_NORMAL, (off_t)0);
		rstfiles(U_KEEP, G_p->g_dirfd);
		VERBOSE((Args & (OCv | OCV)), nam_p);
		return;
	}
	if ((G_p->g_mode & Ftype) == S_IFLNK && (Hdr_type !=
	    USTAR && Hdr_type != TAR)) { /* symbolic link */
		int size;
		write_hdr(ARCHIVE_NORMAL, (off_t)0);

		FLUSH(G_p->g_filesz);
		errno = 0;

		/* Note that "size" and G_p->g_filesz are the same number */

		if ((size = readlink(nam_p, Buffr.b_in_p, G_p->g_filesz)) <
		    0) {
			msg(ERRN, "Cannot read symbolic link \"%s\"", nam_p);
			return;
		}

		/*
		 * Note that it is OK not to add the NUL after the name read by
		 * readlink, because it is not being used subsequently.
		 */

		Buffr.b_in_p += size;
		Buffr.b_cnt += size;
		pad = (Pad_val + 1 - (size & Pad_val)) & Pad_val;
		if (pad != 0) {
			FLUSH(pad);
			(void) memset(Buffr.b_in_p, 0, pad);
			Buffr.b_in_p += pad;
			Buffr.b_cnt += pad;
		}
		VERBOSE((Args & (OCv | OCV)), nam_p);
		return;
	} else if ((G_p->g_mode & Ftype) == S_IFLNK &&
	    (Hdr_type == USTAR || Hdr_type == TAR)) {
		int size;

		/*
		 * G_p->g_filesz is the length of the right-hand side of
		 * the symlink "x -> y".
		 * The tar link field is only NAMSIZ long.
		 */

		if (G_p->g_filesz > NAMSIZ) {
			msg(ERRN,
			    "Symbolic link too long \"%s\"", nam_p);
			return;
		}
		if ((size = readlink(nam_p, T_lname, G_p->g_filesz)) < 0) {
			msg(ERRN,
			    "Cannot read symbolic link \"%s\"", nam_p);
			return;
		}
		T_lname[size] = '\0';
		G_p->g_filesz = (off_t)0;
		write_hdr(ARCHIVE_NORMAL, (off_t)0);
		VERBOSE((Args & (OCv | OCV)), nam_p);
		return;
	}
	if ((Ifile = openfile(O_RDONLY)) < 0) {
		msg(ERR, "\"%s%s%s\" ?",
		    (Gen.g_attrnam_p == NULL) ? nam_p : Gen.g_attrfnam_p,
		    (Gen.g_attrnam_p == NULL) ? "" : Gen.g_rw_sysattr ?
		    gettext(" System Attribute ") : gettext(" Attribute "),
		    (Gen.g_attrnam_p == NULL) ? "" :
		    (Gen.g_attrparent_p == NULL) ? Gen.g_attrnam_p :
		    Gen.g_attrparent_p);
		return;
	}

	/* save original file size */
	orig_filesz = G_p->g_filesz;

	/*
	 * Calculate the new compressed file size of a sparse file
	 * before any of the header information is written
	 * to the archive.
	 */
	if (Compress_sparse && S_ISREG(G_p->g_mode)) {
		/*
		 * If the file being processed is a sparse file, gather the
		 * hole information and the compressed file size.
		 * G_p->g_filesz will need to be changed to be the size of
		 * the compressed sparse file plus the the size of the hole
		 * information that will be prepended to the compressed file
		 * in the archive.
		 */
		holes = get_holes_info(Ifile, G_p->g_filesz, B_FALSE);
		if (holes != NULL)
			G_p->g_filesz = holes->holesdata_sz + holes->data_size;

		if (G_p->g_filesz > Max_offset) {
			msg(ERR, "%s%s%s: too large to archive "
			    "in current mode",
			    G_p->g_nam_p,
			    (G_p->g_attrnam_p == NULL) ? "" :
			    G_p->g_rw_sysattr ?
			    gettext(" System Attribute ") :
			    gettext(" Attribute "),
			    (G_p->g_attrnam_p == NULL) ? "" :
			    ((G_p->g_attrparent_p == NULL) ?
			    G_p->g_attrnam_p:
			    G_p->g_attrpath_p));

			(void) close(Ifile);
			if (holes != NULL)
				free_holes_info(holes);
			return; /* do not archive if it's too big */
		}
	}

	/*
	 * Dump extended attribute header.
	 */

	if (Gen.g_attrnam_p != NULL) {
		write_xattr_hdr();
	}

	if (Hdr_type == CRC) {
		long csum = cksum(CRC, 0, &errret);
		if (errret != 0) {
			G_p->g_cksum = (ulong_t)-1;
			msg(POST, "\"%s%s%s\" skipped",
			    (Gen.g_attrnam_p == NULL) ?
			    nam_p : Gen.g_attrfnam_p,
			    (Gen.g_attrnam_p == NULL) ? "" : Gen.g_rw_sysattr ?
			    gettext(" System Attribute ") :
			    gettext(" Attribute "),
			    (Gen.g_attrnam_p == NULL) ? "" : nam_p);
			if (holes != NULL)
				free_holes_info(holes);
			(void) close(Ifile);
			return;
		}
		G_p->g_cksum = csum;
	} else {
		G_p->g_cksum = 0;
	}

	/*
	 * ACL has been retrieved in getname().
	 */
	if (Pflag) {
		char    *secinfo = NULL;
		int	len = 0;

		/* append security attributes */
		if ((append_secattr(&secinfo, &len, aclp)) == -1)
			msg(ERR, "can create security information");

		/* call append_secattr() if more than one */

		if (len > 0) {
		/* write ancillary only if there is sec info */
			write_hdr(ARCHIVE_ACL, (off_t)len);
			write_ancillary(secinfo, len, B_TRUE);
		}
	}

	if (holes != NULL) {
		/*
		 * Write the header info with a modified c_mode field to
		 * indicate a compressed sparse file is being archived,
		 * as well as the new file size, including the size of the
		 * compressed file as well as all the prepended data.
		 */
		write_hdr(ARCHIVE_SPARSE, (off_t)0);
		/* Prepend sparse file info */
		write_ancillary(holes->holesdata,
		    holes->holesdata_sz, B_FALSE);
	} else {
		write_hdr(ARCHIVE_NORMAL, (off_t)0);
	}

	real_filesz = 0;

	if (holes != NULL) {
		amt_to_read = read_compress_holes(nam_p, G_p->g_filesz,
		    &real_filesz, holes, &hole_changed);
	} else {
		amt_to_read = read_file(nam_p, G_p->g_filesz,
		    &real_filesz, B_FALSE);
	}

	while (amt_to_read > 0) {
		cnt = (amt_to_read > CPIOBSZ) ? CPIOBSZ : (int)amt_to_read;
		FLUSH(cnt);
		(void) memset(Buffr.b_in_p, 0, cnt);
		Buffr.b_in_p += cnt;
		Buffr.b_cnt += cnt;
		amt_to_read -= cnt;
	}

	pad = (Pad_val + 1 - (G_p->g_filesz & Pad_val)) & Pad_val;
	if (pad != 0) {
		FLUSH(pad);
		(void) memset(Buffr.b_in_p, 0, pad);
		Buffr.b_in_p += pad;
		Buffr.b_cnt += pad;
	}

	if (hole_changed == 1) {
		msg(ERR,
		    "File data and hole offsets of \"%s%s%s\" have changed",
		    (Gen.g_attrnam_p == NULL) ?
		    G_p->g_nam_p : Gen.g_attrfnam_p,
		    (Gen.g_attrnam_p == NULL) ? "" : Gen.g_rw_sysattr ?
		    gettext(" System Attribute ") : gettext(" Attribute "),
		    (Gen.g_attrnam_p == NULL) ? "" : G_p->g_nam_p);
	}
	if (real_filesz > orig_filesz) {
		msg(ERR, "File size of \"%s%s%s\" has increased by %lld",
		    (Gen.g_attrnam_p == NULL) ?
		    G_p->g_nam_p : Gen.g_attrfnam_p,
		    (Gen.g_attrnam_p == NULL) ? "" : Gen.g_rw_sysattr ?
		    gettext(" System Attribute ") : gettext(" Attribute "),
		    (Gen.g_attrnam_p == NULL) ? "" : G_p->g_nam_p,
		    (real_filesz - orig_filesz));
	}
	if (real_filesz < orig_filesz) {
		msg(ERR, "File size of \"%s%s%s\" has decreased by %lld",
		    (Gen.g_attrnam_p == NULL) ?
		    G_p->g_nam_p : Gen.g_attrfnam_p,
		    (Gen.g_attrnam_p == NULL) ? "" : Gen.g_rw_sysattr ?
		    gettext(" System Attribute ") : gettext(" Attribute "),
		    (Gen.g_attrnam_p == NULL) ? "" : G_p->g_nam_p,
		    (orig_filesz - real_filesz));
	}

	if (holes != NULL)
		free_holes_info(holes);

	(void) close(Ifile);
	rstfiles(U_KEEP, G_p->g_dirfd);
	VERBOSE((Args & (OCv | OCV)), G_p->g_nam_p);
}

/*
 * data_pass:  If not a special file (Aspec), open(2) the file to be
 * transferred, read(2) each block of data and write(2) it to the output file
 * Ofile, which was opened in file_pass().
 */
static void
data_pass(void)
{
	int rv;
	int cstatus;
	char *namep = Nam_p;
	holes_info_t *holes = NULL;
	data_in_t *data_in_info;

	if (G_p->g_attrnam_p != NULL) {
		namep = G_p->g_attrnam_p;
	}
	if (Aspec) {
		rstfiles(U_KEEP, G_p->g_passdirfd);
		cstatus = close(Ofile);
		Ofile = 0;
		VERBOSE((Args & (OCv | OCV)), Nam_p);
		if (cstatus != 0) {
			msg(EXTN, "close error");
		}
		return;
	}
	if ((Ifile = openat(G_p->g_dirfd, get_component(namep), 0)) < 0) {
		msg(ERRN, "Cannot open \"%s%s%s\", skipped",
		    (G_p->g_attrnam_p == NULL) ? Nam_p : G_p->g_attrfnam_p,
		    (G_p->g_attrnam_p == NULL) ? "" : G_p->g_rw_sysattr ?
		    gettext(" System Attribute ") : gettext(" Attribute "),
		    (G_p->g_attrnam_p == NULL) ? "" : G_p->g_attrnam_p);
		rstfiles(U_KEEP, G_p->g_passdirfd);
		cstatus = close(Ofile);
		Ofile = 0;
		if (cstatus != 0) {
			msg(EXTN, "close error");
		}
		return;
	}

	data_in_info = e_zalloc(E_EXIT, sizeof (data_in_t));
	data_in_info->data_in_proc_mode = P_PROC;

	if (S_ISREG(G_p->g_mode))
		holes = get_holes_info(Ifile, G_p->g_filesz, B_TRUE);

	if (holes != NULL) {
		rv = data_copy_with_holes(Ifile, Ofile,
		    (G_p->g_attrnam_p == NULL) ? 0 : G_p->g_rw_sysattr,
		    G_p->g_filesz, Bufsize, data_in_info, holes);

		free_holes_info(holes);
	} else {
		rv = data_copy(Ifile, Ofile,
		    (G_p->g_attrnam_p == NULL) ? 0 : G_p->g_rw_sysattr,
		    G_p->g_filesz, Bufsize, data_in_info);
	}

	if (rv < 0) {
		/* read error or unexpected EOF */
		if (data_in_info->data_in_rd_eof) {
			/*
			 * read has reached EOF unexpectedly, but this isn't
			 * an error since it's the latest shape of the file.
			 */
			msg(EPOST, "File size of \"%s%s%s\" has decreased",
			    (G_p->g_attrnam_p == NULL) ?
			    Nam_p : G_p->g_attrfnam_p,
			    (G_p->g_attrnam_p == NULL) ? "" :
			    G_p->g_rw_sysattr ? gettext(" System Attribute ") :
			    gettext(" Attribute "),
			    (G_p->g_attrnam_p == NULL) ? "" : G_p->g_attrnam_p);

			/* It's not error. We'll use the new file */
			rv = 0;
		} else {
			/* read error */
			msg(ERRN, "Cannot read \"%s%s%s\"",
			    (G_p->g_attrnam_p == NULL) ?
			    Nam_p : G_p->g_attrfnam_p,
			    (G_p->g_attrnam_p == NULL) ? "" :
			    G_p->g_rw_sysattr ? gettext(" System Attribute ") :
			    gettext(" Attribute "),
			    (G_p->g_attrnam_p == NULL) ? "" : G_p->g_attrnam_p);
		}
	} else if (rv > 0) {
		/* write error */
		if (Do_rename) {
			msg(ERRN, "Cannot write \"%s%s%s\"", Over_p,
			    (G_p->g_attrnam_p == NULL) ? "" :
			    G_p->g_rw_sysattr ? gettext(" System Attribute ") :
			    gettext(" Attribute "),
			    (G_p->g_attrnam_p == NULL) ? "" : Over_p);
		} else {
			msg(ERRN, "Cannot write \"%s%s%s\"",
			    Fullnam_p,
			    (G_p->g_attrnam_p == NULL) ? "" :
			    G_p->g_rw_sysattr ? gettext(" System Attribute ") :
			    gettext(" Attribute "),
			    (G_p->g_attrnam_p == NULL) ? "" : G_p->g_attrnam_p);
		}
	}

	free(data_in_info);

	if (rv == 0) {
		rstfiles(U_OVER, G_p->g_passdirfd);
	} else {
		rstfiles(U_KEEP, G_p->g_passdirfd);
	}

	(void) close(Ifile);
	cstatus = close(Ofile);
	Ofile = 0;
	if (cstatus != 0) {
		msg(EXTN, "close error");
	}
	VERBOSE((Args & (OCv | OCV)), Fullnam_p);
	Finished = 1;
}

/*
 * file_in:  Process an object from the archive.  If a TARTYP (TAR or USTAR)
 * archive and g_nlink == 1, link this file to the file name in t_linkname
 * and return.  Handle linked files in one of two ways.  If Onecopy == 0, this
 * is an old style (binary or -c) archive, create and extract the data for the
 * first link found, link all subsequent links to this file and skip their data.
 * If Oncecopy == 1, save links until all have been processed, and then
 * process the links first to last checking their names against the patterns
 * and/or asking the user to rename them.  The first link that is accepted
 * for xtraction is created and the data is read from the archive.
 * All subsequent links that are accepted are linked to this file.
 */
static void
file_in(void)
{
	struct Lnk *l_p, *tl_p;
	int lnkem = 0, cleanup = 0;
	int proc_file;
	struct Lnk *ttl_p;
	int typeflag;
	char savacl;
	int cwd;

	G_p = &Gen;

	/*
	 * Now that we've read the extended header,
	 * determine if we should restore attributes.
	 * Don't restore the attribute if we are extracting
	 * a file from an archive (as opposed to doing a table of
	 * contents) and any of the following are true:
	 * 1. neither -@ or -/ was specified.
	 * 2. -@ was specified, -/ wasn't specified, and we're
	 * processing a hidden attribute directory of an attribute
	 * or we're processing a read-write system attribute file.
	 * 3.  -@ wasn't specified, -/ was specified, and the file
	 * we're processing it not a read-write system attribute file,
	 * or we're processing the hidden attribute directory of an
	 * attribute.
	 *
	 * We always process the attributes if we're just generating
	 * generating a table of contents, or if both -@ and -/ were
	 * specified.
	 */
	if (G_p->g_attrnam_p != NULL) {
		if (((Args & OCt) == 0) &&
		    ((!Atflag && !SysAtflag) ||
		    (Atflag && !SysAtflag && ((G_p->g_attrparent_p != NULL) ||
		    G_p->g_rw_sysattr)) ||
		    (!Atflag && SysAtflag && ((G_p->g_attrparent_p != NULL) ||
		    !G_p->g_rw_sysattr)))) {
			proc_file = F_SKIP;
			data_in(P_SKIP);
			return;
		}
	}

	/*
	 * Open target directory if this isn't a skipped file
	 * and g_nlink == 1
	 *
	 * Links are handled further down in this function.
	 */

	proc_file = ckname(0);

	if (proc_file == F_SKIP && G_p->g_nlink == 1) {
		/*
		 * Normally ckname() prints out the file as a side
		 * effect except for table of contents listing
		 * when its parameter is zero and Onecopy isn't
		 * Zero.  Due to this we need to force the name
		 * to be printed here.
		 */
		if (Onecopy == 1) {
			VERBOSE((Args & OCt), G_p->g_nam_p);
		}
		data_in(P_SKIP);
		return;
	}

	if (proc_file != F_SKIP && open_dirfd() != 0) {
		data_in(P_SKIP);
		return;
	}

	if (Hdr_type == BAR) {
		bar_file_in();
		close_dirfd();
		return;
	}

	/*
	 * For archives in USTAR format, the files are extracted according
	 * to the typeflag.
	 */
	if (Hdr_type == USTAR || Hdr_type == TAR) {
		typeflag = Thdr_p->tbuf.t_typeflag;
		if (G_p->g_nlink == 1) {		/* hard link */
			if (proc_file != F_SKIP) {
				int i;
				char lname[NAMSIZ+1];
				(void) memset(lname, '\0', sizeof (lname));

				(void) strncpy(lname, Thdr_p->tbuf.t_linkname,
				    NAMSIZ);
				for (i = 0; i <= NAMSIZ && lname[i] != 0; i++)
					;

				lname[i] = 0;
				(void) creat_lnk(G_p->g_dirfd,
				    &lname[0], G_p->g_nam_p);
			}
			close_dirfd();
			return;
		}
		if (typeflag == '3' || typeflag == '4' || typeflag == '5' ||
		    typeflag == '6') {
			if (proc_file != F_SKIP &&
			    creat_spec(G_p->g_dirfd) > 0) {
				VERBOSE((Args & (OCv | OCV)),
				    (G_p->g_attrparent_p == NULL) ?
				    G_p->g_nam_p : G_p->g_attrpath_p);
			}
			close_dirfd();
			return;
		} else if (Adir || Aspec) {
			if ((proc_file == F_SKIP) ||
			    (Ofile = openout(G_p->g_dirfd)) < 0) {
				data_in(P_SKIP);
			} else {
				data_in(P_PROC);
			}
			close_dirfd();
			return;
		}
	}

	if (Adir) {
		if (proc_file != F_SKIP && creat_spec(G_p->g_dirfd) > 0) {
			VERBOSE((Args & (OCv | OCV)), G_p->g_nam_p);
		}
		close_dirfd();
		if (Onecopy == 1) {
			VERBOSE((Args & OCt), G_p->g_nam_p);
		}
		return;
	}
	if (G_p->g_nlink == 1 || (Hdr_type == TAR ||
	    Hdr_type == USTAR)) {
		if (Aspec) {
			if (proc_file != F_SKIP && creat_spec(G_p->g_dirfd) > 0)
				VERBOSE((Args & (OCv | OCV)), G_p->g_nam_p);
		} else {
			if ((proc_file == F_SKIP) ||
			    (Ofile = openout(G_p->g_dirfd)) < 0) {
				data_in(P_SKIP);
			} else {
				data_in(P_PROC);
			}
		}
		close_dirfd();
		return;
	}
	close_dirfd();

	tl_p = add_lnk(&ttl_p);
	l_p = ttl_p;
	if (l_p->L_cnt == l_p->L_gen.g_nlink)
		cleanup = 1;
	if (!Onecopy || G_p->g_attrnam_p != NULL) {
		lnkem = (tl_p != l_p) ? 1 : 0;
		G_p = &tl_p->L_gen;
		if (proc_file == F_SKIP) {
			data_in(P_SKIP);
		} else {
			if (open_dirfd() != 0)
				return;
			if (!lnkem) {
				if (Aspec) {
					if (creat_spec(G_p->g_dirfd) > 0)
						VERBOSE((Args & (OCv | OCV)),
						    G_p->g_nam_p);
				} else if ((Ofile =
				    openout(G_p->g_dirfd)) < 0) {
					data_in(P_SKIP);
					close_dirfd();
					reclaim(l_p);
				} else {
					data_in(P_PROC);
					close_dirfd();
				}
			} else {
				/*
				 * Are we linking an attribute?
				 */
				cwd = -1;
				if (l_p->L_gen.g_attrnam_p != NULL) {
					(void) strcpy(Lnkend_p,
					    l_p->L_gen.g_attrnam_p);
					(void) strcpy(Full_p,
					    tl_p->L_gen.g_attrnam_p);
					cwd = save_cwd();
					(void) fchdir(G_p->g_dirfd);
				} else {
					(void) strcpy(Lnkend_p,
					    l_p->L_gen.g_nam_p);
					(void) strcpy(Full_p,
					    tl_p->L_gen.g_nam_p);
				}
				(void) creat_lnk(G_p->g_dirfd,
				    Lnkend_p, Full_p);
				data_in(P_SKIP);
				close_dirfd();
				l_p->L_lnk_p = NULL;
				free(tl_p->L_gen.g_nam_p);
				free(tl_p);
				if (cwd != -1)
					rest_cwd(cwd);
			}
		}
	} else { /* Onecopy */
		if (tl_p->L_gen.g_filesz)
			cleanup = 1;
		if (!cleanup) {
			close_dirfd();
			return; /* don't do anything yet */
		}
		tl_p = l_p;
		/*
		 * ckname will clear aclchar. We need to keep aclchar for
		 * all links.
		 */
		savacl = aclchar;
		while (tl_p != NULL) {
			G_p = &tl_p->L_gen;
			aclchar = savacl;
			if ((proc_file = ckname(1)) != F_SKIP) {
				if (open_dirfd() != 0) {
					return;
				}
				if (l_p->L_data) {
					(void) creat_lnk(G_p->g_dirfd,
					    l_p->L_gen.g_nam_p,
					    G_p->g_nam_p);
				} else if (Aspec) {
					(void) creat_spec(G_p->g_dirfd);
					l_p->L_data = 1;
					VERBOSE((Args & (OCv | OCV)),
					    G_p->g_nam_p);
				} else if ((Ofile =
				    openout(G_p->g_dirfd)) < 0) {
					proc_file = F_SKIP;
				} else {
					data_in(P_PROC);
					l_p->L_data = 1;
				}
			} /* (proc_file = ckname(1)) != F_SKIP */

			tl_p = tl_p->L_lnk_p;

			close_dirfd();

			if (proc_file == F_SKIP && !cleanup) {
				tl_p->L_nxt_p = l_p->L_nxt_p;
				tl_p->L_bck_p = l_p->L_bck_p;
				l_p->L_bck_p->L_nxt_p = tl_p;
				l_p->L_nxt_p->L_bck_p = tl_p;
				free(l_p->L_gen.g_nam_p);
				free(l_p);
			}
		} /* tl_p->L_lnk_p != NULL */
		if (l_p->L_data == 0) {
			data_in(P_SKIP);
		}
	}
	if (cleanup) {
		reclaim(l_p);
	}
}

/*
 * file_out:  If the current file is not a special file (!Aspec) and it
 * is identical to the archive, skip it (do not archive the archive if it
 * is a regular file).  If creating a TARTYP (TAR or USTAR) archive, the first
 * time a link to a file is encountered, write the header and file out normally.
 * Subsequent links to this file put this file name in their t_linkname field.
 * Otherwise, links are handled in one of two ways, for the old headers
 * (i.e. binary and -c), linked files are written out as they are encountered.
 * For the new headers (ASC and CRC), links are saved up until all the links
 * to each file are found.  For a file with n links, write n - 1 headers with
 * g_filesz set to 0, write the final (nth) header with the correct g_filesz
 * value and write the data for the file to the archive.
 */
static
int
file_out(void)
{
	struct Lnk *l_p, *tl_p;
	int cleanup = 0;
	struct Lnk *ttl_p;

	G_p = &Gen;
	if (!Aspec && IDENT(SrcSt, ArchSt))
		return (1); /* do not archive the archive if it's a reg file */
	/*
	 * If compressing sparse files, wait until the compressed file size
	 * is known to check if file size is too big.
	 */
	if (Compress_sparse == 0 && G_p->g_filesz > Max_offset) {
		msg(ERR, "%s%s%s: too large to archive in current mode",
		    G_p->g_nam_p,
		    (G_p->g_attrnam_p == NULL) ? "" : G_p->g_rw_sysattr ?
		    gettext(" System Attribute ") : gettext(" Attribute "),
		    (G_p->g_attrnam_p == NULL) ? "" :
		    ((G_p->g_attrparent_p == NULL) ? G_p->g_attrnam_p:
		    G_p->g_attrpath_p));
		return (1); /* do not archive if it's too big */
	}
	if (Hdr_type == TAR || Hdr_type == USTAR) { /* TAR and USTAR */
		if (Adir) {
			if (Gen.g_attrnam_p != NULL) {
				write_xattr_hdr();
			}
			write_hdr(ARCHIVE_NORMAL, 0);
			return (0);
		}
		if (G_p->g_nlink == 1) {
			data_out();
			return (0);
		}
		tl_p = add_lnk(&ttl_p);
		l_p = ttl_p;
		if (tl_p == l_p) { /* first link to this file encountered */
			data_out();
			return (0);
		}
		(void) strncpy(T_lname, l_p->L_gen.g_nam_p,
		    l_p->L_gen.g_namesz);

		/*
		 * check if linkname is greater than 100 characters
		 */
		if (strlen(T_lname) > NAMSIZ) {
			msg(EPOST, "cpio: %s: linkname %s is greater than %d",
			    G_p->g_nam_p, T_lname, NAMSIZ);
			return (1);
		}

		write_hdr(ARCHIVE_NORMAL, (off_t)0);
		VERBOSE((Args & (OCv | OCV)), tl_p->L_gen.g_nam_p);

		/* find the lnk entry in sublist, unlink it, and free it */
		for (; ttl_p->L_lnk_p != NULL;
		    ttl_p = ttl_p->L_lnk_p) {
			if (ttl_p->L_lnk_p == tl_p) {
				ttl_p->L_lnk_p = tl_p->L_lnk_p;
				free(tl_p->L_gen.g_nam_p);
				free(tl_p);
				break;
			}
		}

		return (0);
	}
	if (Adir) {
		/*
		 * ACL has been retrieved in getname().
		 */
		if (Pflag) {
			char    *secinfo = NULL;
			int	len = 0;

			/* append security attributes */
			if ((append_secattr(&secinfo, &len, aclp)) == -1)
				msg(ERR, "can create security information");

			/* call append_secattr() if more than one */

			if (len > 0) {
			/* write ancillary */
				write_hdr(ARCHIVE_ACL, (off_t)len);
				write_ancillary(secinfo, len, B_TRUE);
			}
		}

		if (Gen.g_attrnam_p != NULL) {
			write_xattr_hdr();
		}
		write_hdr(ARCHIVE_NORMAL, (off_t)0);
		VERBOSE((Args & (OCv | OCV)), G_p->g_nam_p);
		return (0);
	}
	if (G_p->g_nlink == 1) {
		data_out();
		return (0);
	} else {
		tl_p = add_lnk(&ttl_p);
		l_p = ttl_p;

		if (l_p->L_cnt == l_p->L_gen.g_nlink)
			cleanup = 1;
		else if (Onecopy && G_p->g_attrnam_p == NULL) {
			return (0); /* don't process data yet */
		}
	}
	if (Onecopy && G_p->g_attrnam_p == NULL) {
		tl_p = l_p;
		while (tl_p->L_lnk_p != NULL) {
			G_p = &tl_p->L_gen;
			G_p->g_filesz = (off_t)0;
			/* one link with the acl is sufficient */
			write_hdr(ARCHIVE_NORMAL, (off_t)0);
			VERBOSE((Args & (OCv | OCV)), G_p->g_nam_p);
			tl_p = tl_p->L_lnk_p;
		}
		G_p = &tl_p->L_gen;
		if (open_dirfd() != 0)
			return (1);
	}
	/* old style: has acl and data for every link */
	data_out();
	if (cleanup)
		reclaim(l_p);
	return (0);
}

/*
 * Verify the underlying file system supports the attribute type.
 * Only archive extended attribute files when '-@' was specified.
 * Only archive system extended attribute files if '-/' was specified.
 */
#if defined(O_XATTR)
static attr_status_t
verify_attr_support(char *filename, int attrflg, arc_action_t actflag,
    int *ext_attrflg)
{
	/*
	 * Verify extended attributes are supported/exist.  We only
	 * need to check if we are processing a base file, not an
	 * extended attribute.
	 */
	if (attrflg) {
		*ext_attrflg = (pathconf(filename, (actflag == ARC_CREATE) ?
		    _PC_XATTR_EXISTS : _PC_XATTR_ENABLED) == 1);
	}
	if (Atflag) {
#if defined(_PC_SATTR_ENABLED)
		if (!*ext_attrflg) {
			if (SysAtflag) {
				/* Verify system attributes are supported */
				if (sysattr_support(filename,
				    (actflag == ARC_CREATE) ?_PC_SATTR_EXISTS :
				    _PC_SATTR_ENABLED) != 1) {
					return (ATTR_SATTR_ERR);
				}
			} else
				return (ATTR_XATTR_ERR);
#else
				return (ATTR_XATTR_ERR);
#endif  /* _PC_SATTR_ENABLED */
		}

#if defined(_PC_SATTR_ENABLED)
	} else if (SysAtflag) {
		/* Verify system attributes are supported */
		if (sysattr_support(filename, (actflag == ARC_CREATE) ?
		    _PC_SATTR_EXISTS : _PC_SATTR_ENABLED) != 1) {
			return (ATTR_SATTR_ERR);
	}
#endif  /* _PC_SATTR_ENABLED */
	} else {
		return (ATTR_SKIP);
	}

return (ATTR_OK);
}
#endif

#if defined(O_XATTR)
/*
 * Verify the attribute, attrname, is an attribute we want to restore.
 * Never restore read-only system attribute files.  Only restore read-write
 * system attributes files when -/ was specified, and only traverse into
 * the 2nd level attribute directory containing only system attributes if
 * -@ was specified.  This keeps us from archiving
 *	<attribute name>/<read-write system attribute file>
 * when -/ was specified without -@.
 *
 * attrname		- attribute file name
 * attrparent		- attribute's parent name within the base file's
 *			attribute digrectory hierarchy
 * arc_rwsysattr	- flag that indicates that read-write system attribute
 *			file should be archived as it contains other than
 *			the default system attributes.
 * rw_sysattr		- on return, flag will indicate if attrname is a
 *			read-write system attribute file.
 */
static attr_status_t
verify_attr(char *attrname, char *attrparent, int arc_rwsysattr,
    int *rw_sysattr)
{
#if defined(_PC_SATTR_ENABLED)
	int	attr_supported;

	/* Never restore read-only system attribute files */
	if ((attr_supported = sysattr_type(attrname)) == _RO_SATTR) {
		*rw_sysattr = 0;
		return (ATTR_SKIP);
	} else {
		*rw_sysattr = (attr_supported == _RW_SATTR);
	}

	/*
	 * Don't archive a read-write system attribute file if
	 * it contains only the default system attributes.
	 */
	if (*rw_sysattr && !arc_rwsysattr) {
		return (ATTR_SKIP);
	}

#else
	/* Never restore read-only system attribute files */
	if ((*rw_sysattr = is_sysattr(attrname)) == 1) {
		return (ATTR_SKIP);
	}
#endif	/* _PC_SATTR_ENABLED */

	/*
	 * Only restore read-write system attribute files
	 * when -/ was specified.  Only restore extended
	 * attributes when -@ was specified.
	 */
	if (Atflag) {
		if (!SysAtflag) {
			/*
			 * Only archive/restore the hidden directory "." if
			 * we're processing the top level hidden attribute
			 * directory.  We don't want to process the
			 * hidden attribute directory of the attribute
			 * directory that contains only extended system
			 * attributes.
			 */
			if (*rw_sysattr || (Hiddendir &&
			    (attrparent != NULL))) {
				return (ATTR_SKIP);
			}
		}
	} else if (SysAtflag) {
		/*
		 * Only archive/restore read-write extended system attribute
		 * files of the base file.
		 */
		if (!*rw_sysattr || (attrparent != NULL)) {
			return (ATTR_SKIP);
		}
	} else {
		return (ATTR_SKIP);
	}

	return (ATTR_OK);
}
#endif

#if defined(O_XATTR)
static int
retry_open_attr(int pdirfd, int cwd, char *fullname, char *pattr, char *name,
    int oflag, mode_t mode)
{
	int dirfd;
	int ofilefd = -1;
	struct timeval times[2];
	mode_t newmode;
	struct stat parentstat;
	acl_t *aclp = NULL;
	int error;

	/*
	 * We couldn't get to attrdir. See if its
	 * just a mode problem on the parent file.
	 * for example: a mode such as r-xr--r--
	 * on a ufs file system without extended
	 * system attribute support won't let us
	 * create an attribute dir if it doesn't
	 * already exist, and on a ufs file system
	 * with extended system attribute support
	 * won't let us open the attribute for
	 * write.
	 *
	 * If file has a non-trivial ACL, then save it
	 * off so that we can place it back on after doing
	 * chmod's.
	 */
	if ((dirfd = openat(cwd, (pattr == NULL) ? fullname : pattr,
	    O_RDONLY)) == -1) {
		return (-1);
	}
	if (fstat(dirfd, &parentstat) == -1) {
		msg(ERRN, "Cannot stat %sfile %s",
		    (pdirfd == -1) ? "" : gettext("parent of "),
		    (pdirfd == -1) ? fullname : name);
		(void) close(dirfd);
		return (-1);
	}
	if ((error = facl_get(dirfd, ACL_NO_TRIVIAL, &aclp)) != 0) {
		msg(ERRN, "Failed to retrieve ACL on %sfile %s",
		    (pdirfd == -1) ? "" : gettext("parent of "),
		    (pdirfd == -1) ? fullname : name);
		(void) close(dirfd);
		return (-1);
	}

	newmode = S_IWUSR | parentstat.st_mode;
	if (fchmod(dirfd, newmode) == -1) {
		msg(ERRN, "Cannot change mode of %sfile %s to %o",
		    (pdirfd == -1) ? "" : gettext("parent of "),
		    (pdirfd == -1) ? fullname : name, newmode);
		if (aclp)
			acl_free(aclp);
		(void) close(dirfd);
		return (-1);
	}


	if (pdirfd == -1) {
		/*
		 * We weren't able to create the attribute directory before.
		 * Now try again.
		 */
		ofilefd = attropen(fullname, ".", oflag);
	} else {
		/*
		 * We weren't able to create open the attribute before.
		 * Now try again.
		 */
		ofilefd = openat(pdirfd, name, oflag, mode);
	}

	/*
	 * Put mode back to original
	 */
	if (fchmod(dirfd, parentstat.st_mode) == -1) {
		msg(ERRN, "Cannot restore permissions of %sfile %s to %o",
		    (pdirfd == -1) ? "" : gettext("parent of "),
		    (pdirfd == -1) ? fullname : name, newmode);
	}

	if (aclp) {
		error = facl_set(dirfd, aclp);
		if (error) {
			msg(ERRN, "failed to set acl entries on %sfile %s\n",
			    (pdirfd == -1) ? "" : gettext("parent of "),
			    (pdirfd == -1) ? fullname : name);
		}
		acl_free(aclp);
	}

	/*
	 * Put back time stamps
	 */

	times[0].tv_sec = parentstat.st_atime;
	times[0].tv_usec = 0;
	times[1].tv_sec = parentstat.st_mtime;
	times[1].tv_usec = 0;

	(void) futimesat(cwd, (pattr == NULL) ? fullname : pattr, times);

	(void) close(dirfd);

	return (ofilefd);
}
#endif

#if defined(O_XATTR)
/*
 * Recursively open attribute directories until the attribute directory
 * containing the specified attribute, attrname, is opened.
 *
 * Currently, only 2 directory levels of attributes are supported, (i.e.,
 * extended system attributes on extended attributes).  The following are
 * the possible input combinations:
 *	1.  Open the attribute directory of the base file (don't change
 *	    into it).
 *		attr_parent = NULL
 *		attrname = '.'
 *	2.  Open the attribute directory of the base file and change into it.
 *		attr_parent = NULL
 *		attrname = <attr> | <sys_attr>
 *	3.  Open the attribute directory of the base file, change into it,
 *	    then recursively call open_attr_dir() to open the attribute's
 *	    parent directory (don't change into it).
 *		attr_parent = <attr>
 *		attrname = '.'
 *	4.  Open the attribute directory of the base file, change into it,
 *	    then recursively call open_attr_dir() to open the attribute's
 *	    parent directory and change into it.
 *		attr_parent = <attr>
 *		attrname = <attr> | <sys_attr>
 *
 * An attribute directory will be opened only if the underlying file system
 * supports the attribute type, and if the command line specifications
 * (f_extended_attr and f_sys_attr) enable the processing of the attribute
 * type.
 *
 * On succesful return, attr_parentfd will be the file descriptor of the
 * opened attribute directory.  In addition, if the attribute is a read-write
 * extended system attribute, rw_sysattr will be set to 1, otherwise
 * it will be set to 0.
 *
 * Possible return values:
 * 	ATTR_OK		Successfully opened and, if needed, changed into the
 *			attribute directory containing attrname.
 *	ATTR_SKIP	The command line specifications don't enable the
 *			processing of the attribute type.
 * 	ATTR_CHDIR_ERR	An error occurred while trying to change into an
 *			attribute directory.
 * 	ATTR_OPEN_ERR	An error occurred while trying to open an
 *			attribute directory.
 *	ATTR_XATTR_ERR	The underlying file system doesn't support extended
 *			attributes.
 *	ATTR_SATTR_ERR	The underlying file system doesn't support extended
 *			system attributes.
 */
static int
open_attr_dir(char *attrname, char *dirp, int cwd, char *attr_parent,
    int *attr_parentfd, int *rw_sysattr)
{
	attr_status_t	rc;
	int		firsttime = (*attr_parentfd == -1);
	int		saveerrno;
	int		ext_attr;

	/*
	 * open_attr_dir() was recursively called (input combination number 4),
	 * close the previously opened file descriptor as we've already changed
	 * into it.
	 */
	if (!firsttime) {
		(void) close(*attr_parentfd);
		*attr_parentfd = -1;
	}

	/*
	 * Verify that the underlying file system supports the restoration
	 * of the attribute.
	 */
	if ((rc = verify_attr_support(dirp, firsttime, ARC_RESTORE,
	    &ext_attr)) != ATTR_OK) {
		return (rc);
	}

	/* Open the base file's attribute directory */
	if ((*attr_parentfd = attropen(dirp, ".", O_RDONLY)) == -1) {
		/*
		 * Save the errno from the attropen so it can be reported
		 * if the retry of the attropen fails.
		 */
		saveerrno = errno;
		if ((*attr_parentfd = retry_open_attr(-1, cwd, dirp,
		    NULL, ".", O_RDONLY, 0)) == -1) {
			(void) close(*attr_parentfd);
			*attr_parentfd = -1;
			errno = saveerrno;
			return (ATTR_OPEN_ERR);
		}
	}

	/*
	 * Change into the parent attribute's directory unless we are
	 * processing the hidden attribute directory of the base file itself.
	 */
	if ((Hiddendir == 0) || (firsttime && (attr_parent != NULL))) {
		if (fchdir(*attr_parentfd) != 0) {
			saveerrno = errno;
			(void) close(*attr_parentfd);
			*attr_parentfd = -1;
			errno = saveerrno;
			return (ATTR_CHDIR_ERR);
		}
	}

	/* Determine if the attribute should be processed */
	if ((rc = verify_attr(attrname, attr_parent, 1,
	    rw_sysattr)) != ATTR_OK) {
		saveerrno = errno;
		(void) close(*attr_parentfd);
		*attr_parentfd = -1;
		errno = saveerrno;
		return (rc);
	}

	/*
	 * If the attribute is an extended system attribute of an attribute
	 * (i.e., <attr>/<sys_attr>), then recursively call open_attr_dir() to
	 * open the attribute directory of the parent attribute.
	 */
	if (firsttime && (attr_parent != NULL)) {
		return (open_attr_dir(attrname, attr_parent, *attr_parentfd,
		    attr_parent, attr_parentfd, rw_sysattr));
	}

	return (ATTR_OK);
}
#endif

/*
 * file_pass:  If the -l option is set (link files when possible), and the
 * source and destination file systems are the same, link the source file
 * (G_p->g_nam_p) to the destination file (Fullnam) and return.  If not a
 * linked file, transfer the data.  Otherwise, the first link to a file
 * encountered is transferred normally and subsequent links are linked to it.
 */

static int
file_pass(void)
{
	struct Lnk *l_p, *tl_p;
	struct Lnk *ttl_p;
	char *save_name;
	int size;
	int cwd;
	char *lfrom, *lto;

	G_p = &Gen;

	if (Adir && !(Args & OCd)) {
		msg(ERR, "Use -d option to copy \"%s\"", G_p->g_nam_p);
		return (FILE_PASS_ERR);
	}

	save_name = G_p->g_nam_p;

	while (*(G_p->g_nam_p) == '/') {
		G_p->g_nam_p++;
	}

	(void) strcpy(Full_p, (G_p->g_attrfnam_p == NULL) ?
	    G_p->g_nam_p : G_p->g_attrfnam_p);

	if (G_p->g_attrnam_p == NULL) {
		G_p->g_passdirfd = open_dir(Fullnam_p);

		if (G_p->g_passdirfd == -1) {
			msg(ERRN,
			    "Cannot open/create \"%s\"", Fullnam_p);
			return (FILE_PASS_ERR);
		}
	} else {
		int	rw_sysattr;

		/*
		 * Open the file's attribute directory.
		 * Change into the base file's starting directory then call
		 * open_attr_dir() to open the attribute directory of either
		 * the base file (if G_p->g_attrparent_p is NULL) or the
		 * attribute (if G_p->g_attrparent_p is set) of the base file.
		 */

		G_p->g_passdirfd = -1;
		(void) fchdir(G_p->g_baseparent_fd);
		(void) open_attr_dir(G_p->g_attrnam_p, Fullnam_p,
		    G_p->g_baseparent_fd, (G_p->g_attrparent_p == NULL) ? NULL :
		    G_p->g_attrparent_p, &G_p->g_passdirfd, &rw_sysattr);
		if (G_p->g_passdirfd == -1) {
			msg(ERRN,
			    "Cannot open attribute directory of "
			    "%s%s%sfile \"%s\"",
			    (G_p->g_attrparent_p == NULL) ? "" :
			    gettext("attribute \""),
			    (G_p->g_attrparent_p == NULL) ? "" :
			    G_p->g_attrparent_p,
			    (G_p->g_attrparent_p == NULL) ? "" :
			    gettext("\" of "), Fullnam_p);
			return (FILE_PASS_ERR);
		}
	}

	if (Args & OCl) {
		/* We are linking back to the source directory. */

		if (!Adir) {
			char *existingfile = save_name;

			if ((Args & OCL) && issymlink) {
				/* We are chasing symlinks. */

				if ((size = readlink(save_name, Symlnk_p,
				    MAXPATHLEN)) < 0) {
					msg(ERRN,
					    "Cannot read symbolic link \"%s\"",
					    save_name);
					return (FILE_PASS_ERR);
				}

				Symlnk_p[size] = '\0';
				existingfile = Symlnk_p;
			}

			if (G_p->g_attrnam_p == NULL) {
				if (creat_lnk(G_p->g_passdirfd,
				    existingfile, Fullnam_p) == 0) {
					return (FILE_LINKED);
				}
			}
		}
	}

	if ((G_p->g_mode & Ftype) == S_IFLNK && !(Args & OCL)) {
		/* The archive file is a symlink. */

		errno = 0;

		if ((size = readlink(save_name, Symlnk_p, MAXPATHLEN)) < 0) {
			msg(ERRN,
			    "Cannot read symbolic link \"%s\"", save_name);
			return (FILE_PASS_ERR);
		}

		errno = 0;
		(void) missdir(Fullnam_p);
		*(Symlnk_p + size) = '\0';

		if (symlink(Symlnk_p, Fullnam_p) < 0) {
			if (errno == EEXIST) {
				if (openout(G_p->g_passdirfd) < 0) {
					if (errno != EEXIST) {
						msg(ERRN,
						    "Cannot create \"%s\"",
						    Fullnam_p);
					}
					return (FILE_PASS_ERR);
				}
			} else {
				msg(ERRN, "Cannot create \"%s\"", Fullnam_p);
				return (FILE_PASS_ERR);
			}
		} else {
			if (Args & OCR) {
				if (lchown(Fullnam_p, (int)Rpw_p->pw_uid,
				    (int)Rpw_p->pw_gid) < 0) {
					msg(ERRN,
					    "Error during chown() of \"%s\"",
					    Fullnam_p);
				}
			} else if ((lchown(Fullnam_p, (int)G_p->g_uid,
			    (int)G_p->g_gid) < 0) && privileged) {
				msg(ERRN,
				    "Error during chown() of \"%s\"",
				    Fullnam_p);
			}
		}

		VERBOSE((Args & (OCv | OCV)), Fullnam_p);
		return (FILE_PASS_ERR);
	}

	if (!Adir && G_p->g_nlink > 1) {
		/* The archive file has hard links. */

		tl_p = add_lnk(&ttl_p);
		l_p = ttl_p;

		if (tl_p == l_p) {
			/* The archive file was not found. */

			G_p = &tl_p->L_gen;
		} else {
			/* The archive file was found. */

			cwd = -1;

			if (l_p->L_gen.g_attrnam_p != NULL) {
				/* We are linking an attribute */

				(void) strcpy(Lnkend_p, l_p->L_gen.g_attrnam_p);
				cwd = save_cwd();
				(void) fchdir(G_p->g_passdirfd);
				lfrom = get_component(Lnknam_p);
				lto = tl_p->L_gen.g_attrnam_p;
			} else {
				/* We are not linking an attribute */

				(void) strcpy(Lnkend_p, l_p->L_gen.g_nam_p);
				(void) strcpy(Full_p, tl_p->L_gen.g_nam_p);
				lfrom = Lnknam_p;
				lto = Fullnam_p;
			}

			(void) creat_lnk(G_p->g_passdirfd, lfrom, lto);

			if (cwd) {
				rest_cwd(cwd);
			}

			l_p->L_lnk_p = NULL;
			free(tl_p->L_gen.g_nam_p);
			free(tl_p);

			if (l_p->L_cnt == G_p->g_nlink) {
				reclaim(l_p);
			}

			return (FILE_LINKED);
		}
	}

	if (Adir || Aspec) {
		/*
		 * The archive file is a directory,  block special, char
		 * special or a fifo.
		 */

		if (creat_spec(G_p->g_passdirfd) > 0) {
			VERBOSE((Args & (OCv | OCV)), Fullnam_p);
		}
	} else if ((Ofile = openout(G_p->g_passdirfd)) > 0) {
		data_pass();
	}

	return (FILE_COPIED);
}

/*
 * flush_lnks: With new linked file handling, linked files are not archived
 * until all links have been collected.  When the end of the list of filenames
 * to archive has been reached, all files that did not encounter all their links
 * are written out with actual (encountered) link counts.  A file with n links
 * (that are archived) will be represented by n headers (one for each link (the
 * first n - 1 have g_filesz set to 0)) followed by the data for the file.
 */

static void
flush_lnks(void)
{
	struct Lnk *l_p, *tl_p;
	off_t tfsize;

	l_p = Lnk_hd.L_nxt_p;
	while (l_p != &Lnk_hd) {
		(void) strcpy(Gen.g_nam_p, l_p->L_gen.g_nam_p);
		if (stat(Gen.g_nam_p, &SrcSt) == 0) { /* check if file exists */
			tl_p = l_p;
			(void) creat_hdr();
			Gen.g_nlink = l_p->L_cnt; /* "actual" link count */
			tfsize = Gen.g_filesz;
			Gen.g_filesz = (off_t)0;
			G_p = &Gen;
			while (tl_p != NULL) {
				Gen.g_nam_p = tl_p->L_gen.g_nam_p;
				Gen.g_namesz = tl_p->L_gen.g_namesz;
				if (tl_p->L_lnk_p == NULL) {
					Gen.g_filesz = tfsize;
					if (open_dirfd() != 0) {
						break;
					}
					data_out();
					break;
				}
				write_hdr(ARCHIVE_NORMAL,
				    (off_t)0); /* header only */
				VERBOSE((Args & (OCv | OCV)), Gen.g_nam_p);
				tl_p = tl_p->L_lnk_p;
			}
			Gen.g_nam_p = Nam_p;
		} else /* stat(Gen.g_nam_p, &SrcSt) == 0 */
			msg(ERR, "\"%s%s%s\" has disappeared",
			    (Gen.g_attrnam_p == NULL) ?
			    Gen.g_nam_p : Gen.g_attrfnam_p,
			    (Gen.g_attrnam_p == NULL) ?
			    "" : Gen.g_rw_sysattr ?
			    gettext(" System Attribute ") :
			    gettext(" Attribute "),
			    (Gen.g_attrnam_p == NULL) ?
			    "" : Gen.g_attrnam_p);
		tl_p = l_p;
		l_p = l_p->L_nxt_p;
		reclaim(tl_p);
	} /* l_p != &Lnk_hd */
}

#if defined(O_XATTR)
static int
is_sysattr(char *name)
{
	return ((strcmp(name, VIEW_READONLY) == 0) ||
	    (strcmp(name, VIEW_READWRITE) == 0));
}
#endif

/*
 * gethdr: Get a header from the archive, validate it and check for the trailer.
 * Any user specified Hdr_type is ignored (set to NONE in main).  Hdr_type is
 * set appropriately after a valid header is found.  Unless the -k option is
 * set a corrupted header causes an exit with an error.  I/O errors during
 * examination of any part of the header cause gethdr to throw away any current
 * data and start over.  Other errors during examination of any part of the
 * header cause gethdr to advance one byte and continue the examination.
 */

static int
gethdr(void)
{
	ushort_t ftype;
	int hit = NONE, cnt = 0;
	int goodhdr, hsize, offset;
	int bswap = 0;
	char *preptr;
	int k = 0;
	int j;
	int error;
	int aclcnt;

	Gen.g_nam_p = Nam_p;
	do { /* hit == NONE && (Args & OCk) && Buffr.b_cnt > 0 */
		FILL(Hdrsz);
		switch (Hdr_type) {
		case NONE:
		case BIN:
			Binmag.b_byte[0] = Buffr.b_out_p[0];
			Binmag.b_byte[1] = Buffr.b_out_p[1];
			if ((Binmag.b_half == CMN_BIN) ||
			    (Binmag.b_half == CMN_BBS)) {
				hit = read_hdr(BIN);
				if (Hdr_type == NONE)
					bswap = 1;
				hsize = HDRSZ + Gen.g_namesz;
				break;
			}
			if (Hdr_type != NONE)
				break;
			/*FALLTHROUGH*/
		case CHR:
			if (!(strncmp(Buffr.b_out_p, CMS_CHR, CMS_LEN))) {
				hit = read_hdr(CHR);
				hsize = CHRSZ + Gen.g_namesz;
				break;
			}
			if (Hdr_type != NONE)
				break;
			/*FALLTHROUGH*/
		case ASC:
			if (!(strncmp(Buffr.b_out_p, CMS_ASC, CMS_LEN))) {
				hit = read_hdr(ASC);
				hsize = ASCSZ + Gen.g_namesz;
				Max_namesz = APATH;
				break;
			}
			if (Hdr_type != NONE)
				break;
			/*FALLTHROUGH*/
		case CRC:
			if (!(strncmp(Buffr.b_out_p, CMS_CRC, CMS_LEN))) {
				hit = read_hdr(CRC);
				hsize = ASCSZ + Gen.g_namesz;
				Max_namesz = APATH;
				break;
			}
			if (Hdr_type != NONE)
				break;
			/*FALLTHROUGH*/

		case BAR:
			if (Hdr_p != NULL && strcmp(Hdr_p, "bar") == 0) {
				Hdrsz = BARSZ;
				FILL(Hdrsz);
				if ((hit = read_hdr(BAR)) == NONE) {
					Hdrsz = ASCSZ;
					break;
				}
				hit = BAR;
				hsize = BARSZ;
				break;
			}
			/*FALLTHROUGH*/

		case USTAR:
			if (Hdr_p != NULL && strcmp(Hdr_p, "ustar") == 0) {
				Hdrsz = TARSZ;
				FILL(Hdrsz);
				if ((hit = read_hdr(USTAR)) == NONE) {
					Hdrsz = ASCSZ;
					break;
				}
				hit = USTAR;
				hsize = TARSZ;
				break;
			}
			/*FALLTHROUGH*/
		case TAR:
			if (Hdr_p != NULL && strcmp(Hdr_p, "tar") == 0) {
				Hdrsz = TARSZ;
				FILL(Hdrsz);
				if ((hit = read_hdr(TAR)) == NONE) {
					Hdrsz = ASCSZ;
					break;
				}
				hit = TAR;
				hsize = TARSZ;
				break;
			}
			/*FALLTHROUGH*/
		default:
			msg(EXT, "Impossible header type.");
		} /* Hdr_type */

		if (hit == TAR || hit == USTAR) {
			Gen.g_nam_p = &nambuf[0];
		}

		if (hit != NONE) {
			FILL(hsize);
			goodhdr = 1;
			if (Gen.g_filesz < (off_t)0 || Gen.g_namesz < 1)
				goodhdr = 0;
			if ((hit != USTAR) && (hit != TAR))
				if (Gen.g_namesz - 1 > Max_namesz)
					goodhdr = 0;
			/* TAR and USTAR */
			if ((hit == USTAR) || (hit == TAR)) {
				if (*Gen.g_nam_p == '\0') { /* tar trailer */
					goodhdr = 1;
				} else {

					G_p = &Gen;
					if (G_p->g_cksum !=
					    cksum(TARTYP, 0, NULL)) {
						goodhdr = 0;
						msg(ERR,
						    "Bad header - checksum "
						    "error.");
					}
				}
			} else if (hit != BAR) { /* binary, -c, ASC and CRC */
				if (Gen.g_nlink <= (ulong_t)0)
					goodhdr = 0;
				if (*(Buffr.b_out_p + hsize - 1) != '\0')
					goodhdr = 0;
			}
			if (!goodhdr) {
				hit = NONE;
				if (!(Args & OCk))
					break;
				msg(ERR,
				    "Corrupt header, file(s) may be lost.");
			} else {
				FILL(hsize);
			}
		} /* hit != NONE */
		if (hit == NONE) {
			Buffr.b_out_p++;
			Buffr.b_cnt--;
			if (!(Args & OCk))
				break;
			if (!cnt++)
				msg(ERR, "Searching for magic number/header.");
		}
	} while (hit == NONE);
	if (hit == NONE) {
		if (Hdr_type == NONE)
			msg(EXT, "Not a cpio file, bad header.");
		else
			msg(EXT, "Bad magic number/header.");
	} else if (cnt > 0) {
		msg(EPOST, "Re-synchronized on magic number/header.");
	}
	if (Hdr_type == NONE) {
		Hdr_type = hit;
		switch (Hdr_type) {
		case BIN:
			if (bswap)
				Args |= BSM;
			Hdrsz = HDRSZ;
			Max_namesz = CPATH;
			Pad_val = HALFWD;
			Onecopy = 0;
			break;
		case CHR:
			Hdrsz = CHRSZ;
			Max_namesz = CPATH;
			Pad_val = 0;
			Onecopy = 0;
			break;
		case ASC:
		case CRC:
			Hdrsz = ASCSZ;
			Max_namesz = APATH;
			Pad_val = FULLWD;
			Onecopy = 1;
			break;
		case USTAR:
			Hdrsz = TARSZ;
			Max_namesz = HNAMLEN - 1;
			Pad_val = FULLBK;
			Onecopy = 0;
			break;
		case BAR:
		case TAR:
			Hdrsz = TARSZ;
			Max_namesz = TNAMLEN - 1;
			Pad_val = FULLBK;
			Onecopy = 0;
			break;
		default:
			msg(EXT, "Impossible header type.");
		} /* Hdr_type */
	} /* Hdr_type == NONE */
	if ((Hdr_type == USTAR) || (Hdr_type == TAR) ||
	    (Hdr_type == BAR)) {			/* TAR, USTAR, BAR */
		Gen.g_namesz = 0;
		if (Gen.g_nam_p[0] == '\0')
			return (0);
		else {
			preptr = &prebuf[0];
			if (*preptr != NULL) {
				k = strlen(&prebuf[0]);
				if (k < PRESIZ) {
					(void) strcpy(&fullnam[0], &prebuf[0]);
					j = 0;
					fullnam[k++] = '/';
					while ((j < NAMSIZ) && (nambuf[j] !=
					    '\0')) {
						fullnam[k] = nambuf[j];
						k++; j++;
					}
					fullnam[k] = '\0';
				} else if (k >= PRESIZ) {
					k = 0;
					while ((k < PRESIZ) && (prebuf[k] !=
					    '\0')) {
						fullnam[k] = prebuf[k];
						k++;
					}
					fullnam[k++] = '/';
					j = 0;
					while ((j < NAMSIZ) && (nambuf[j] !=
					    '\0')) {
						fullnam[k] = nambuf[j];
						k++; j++;
					}
					fullnam[k] = '\0';
				}
				Gen.g_nam_p = &fullnam[0];
			} else
				Gen.g_nam_p = &nambuf[0];

			/*
			 * initialize the buffer so that the prefix will not
			 * applied to the next entry in the archive
			 */
			(void) memset(prebuf, 0, sizeof (prebuf));
		}
	} else if (Hdr_type != BAR) {
		(void) memcpy(Gen.g_nam_p, Buffr.b_out_p + Hdrsz, Gen.g_namesz);
		if (!(strcmp(Gen.g_nam_p, "TRAILER!!!")))
			return (0);
	}
	offset = ((hsize + Pad_val) & ~Pad_val);
	FILL(offset + Hdrsz);
	Thdr_p = (union tblock *)Buffr.b_out_p;
	Buffr.b_out_p += offset;
	Buffr.b_cnt -= (off_t)offset;
	ftype = Gen.g_mode & Ftype;

#if defined(O_XATTR)
	/* extended attribute support */
	if (((Gen.g_mode & S_IFMT) == _XATTR_CPIO_MODE) ||
	    ((Hdr_type == USTAR || Hdr_type == TAR) &&
	    Thdr_p->tbuf.t_typeflag == _XATTR_HDRTYPE)) {
		char	*aname;
		char	*attrparent = NULL;
		char	*attrpath = NULL;
		char	*tapath;
		char	*taname;

		if (xattrp != NULL) {
			if (xattrbadhead) {
				free(xattrhead);
				xattrp = NULL;
				xattr_linkp = NULL;
				xattrhead = NULL;
				return (1);
			}

			/*
			 * At this point, the attribute path contains
			 * the path to the attribute rooted at the hidden
			 * attribute directory of the base file.  This can
			 * be a simple attribute or extended attribute name,
			 * or it can be something like <attr>/<sys attr> if
			 * we are processing a system attribute of an attribute.
			 * Determine the attribute name and attribute parent
			 * (if there is one).  When we are processing a simple
			 * attribute or extended attribute name, the attribute
			 * parent will be set to NULL.  When we are processing
			 * something like <attr>/<sys attr>, the attribute
			 * parent will be contain <attr>, and the attribute
			 * name will contain <sys attr>.
			 */
			tapath = xattrp->h_names +
			    strlen(xattrp->h_names) + 1;
			attrpath = e_strdup(E_EXIT, tapath);
			if ((taname = strpbrk(tapath, "/")) != NULL) {
				aname = taname + 1;
				*taname = '\0';
				attrparent = tapath;
			} else {
				aname = tapath;
			}

			Gen.g_rw_sysattr = is_sysattr(aname);
			Gen.g_baseparent_fd = attr_baseparent_fd;

			if (Gen.g_attrfnam_p != NULL) {
				free(Gen.g_attrfnam_p);
				Gen.g_attrfnam_p = NULL;
			}
			if (Gen.g_attrnam_p != NULL) {
				free(Gen.g_attrnam_p);
				Gen.g_attrnam_p = NULL;
			}
			if (Gen.g_attrparent_p != NULL) {
				free(Gen.g_attrparent_p);
				Gen.g_attrparent_p = NULL;
			}
			if (Gen.g_attrpath_p != NULL) {
				free(Gen.g_attrpath_p);
				Gen.g_attrpath_p = NULL;
			}
			if (Renam_p && Renam_p[0] != '\0') {
				Gen.g_attrfnam_p = e_strdup(E_EXIT, Renam_p);
			} else {
				Gen.g_attrfnam_p = e_strdup(E_EXIT,
				    xattrp->h_names);
			}
			Gen.g_attrnam_p = e_strdup(E_EXIT, aname);

			if (attrparent != NULL) {
				if (Renam_attr_p && Renam_attr_p[0] != '\0') {
					size_t	apathlen = strlen(attrparent) +
					    strlen(aname) + 2;
					Gen.g_attrparent_p = e_strdup(E_EXIT,
					    Renam_attr_p);
					Gen.g_attrpath_p = e_zalloc(E_EXIT,
					    apathlen);
					(void) snprintf(Gen.g_attrpath_p,
					    apathlen, "%s/%s", Renam_attr_p,
					    aname);
					(void) free(attrparent);
					(void) free(attrpath);
				} else {
					Gen.g_attrparent_p = attrparent;
					Gen.g_attrpath_p = attrpath;
				}
			} else {
				Gen.g_attrpath_p = attrpath;
			}

			if (xattr_linkp != NULL) {
				if (Gen.g_linktoattrfnam_p != NULL) {
					free(Gen.g_linktoattrfnam_p);
					Gen.g_linktoattrfnam_p = NULL;
				}
				if (Gen.g_linktoattrnam_p != NULL) {
					free(Gen.g_linktoattrnam_p);
					Gen.g_linktoattrnam_p = NULL;
				}
				if (Renam_attr_p && Renam_attr_p[0] != '\0') {
					Gen.g_linktoattrfnam_p = e_strdup(
					    E_EXIT, Renam_attr_p);
				} else {
					Gen.g_linktoattrfnam_p = e_strdup(
					    E_EXIT, xattr_linkp->h_names);
				}
				Gen.g_linktoattrnam_p = e_strdup(E_EXIT,
				    aname);
				xattr_linkp = NULL;
			}
			if (Hdr_type != USTAR && Hdr_type != TAR) {
				Gen.g_mode = Gen.g_mode & (~_XATTR_CPIO_MODE);
				Gen.g_mode |= attrmode(xattrp->h_typeflag);
			} else if (Hdr_type == USTAR || Hdr_type == TAR) {
				Thdr_p->tbuf.t_typeflag = xattrp->h_typeflag;
			}

			ftype = Gen.g_mode & Ftype;
			Adir = ftype == S_IFDIR;
			Aspec = (ftype == S_IFBLK || ftype == S_IFCHR ||
			    ftype == S_IFIFO || ftype == S_IFSOCK);

			if (Gen.g_attrnam_p[0] == '.' &&
			    Gen.g_attrnam_p[1] == '\0' &&
			    xattrp->h_typeflag == DIRTYPE) {
				Hiddendir = 1;
			} else {
				Hiddendir = 0;
			}

			free(xattrhead);
			xattrhead = NULL;
			xattrp = NULL;
		} else {
			if (xattrbadhead == 0) {
				(void) read_xattr_hdr();
				return (2);
			}
		}
	} else {
		Hiddendir = 0;
	}
#endif /* O_XATTR */

	/* acl support: grab acl info */
	if ((Gen.g_mode == SECMODE) || ((Hdr_type == USTAR ||
	    Hdr_type == TAR) && Thdr_p->tbuf.t_typeflag == 'A')) {
		/* this is an ancillary file */
		off_t	bytes;
		char	*secp;
		int	pad;
		int	cnt;
		char	*tp;
		int	attrsize;

		if (Pflag) {
			bytes = Gen.g_filesz;
			secp = e_zalloc(E_EXIT, (uint_t)bytes);
			tp = secp;

			while (bytes > 0) {
				cnt = (int)(bytes > CPIOBSZ) ? CPIOBSZ : bytes;
				FILL(cnt);
				(void) memcpy(tp, Buffr.b_out_p, cnt);
				tp += cnt;
				Buffr.b_out_p += cnt;
				Buffr.b_cnt -= (off_t)cnt;
				bytes -= (off_t)cnt;
			}

			pad = (Pad_val + 1 - (Gen.g_filesz & Pad_val)) &
			    Pad_val;
			if (pad != 0) {
				FILL(pad);
				Buffr.b_out_p += pad;
				Buffr.b_cnt -= (off_t)pad;
			}

			/* got all attributes in secp */
			tp = secp;
			do {
				attr = (struct sec_attr *)tp;
				switch (attr->attr_type) {
				case UFSD_ACL:
				case ACE_ACL:
					(void) sscanf(attr->attr_len, "%7lo",
					    (ulong_t *)&aclcnt);
					/* header is 8 */
					attrsize = 8 +
					    strlen(&attr->attr_info[0])
					    + 1;

					error =
					    acl_fromtext(&attr->attr_info[0],
					    &aclp);

					if (error != 0) {
						msg(ERR,
						    "aclfromtext failed: %s",
						    acl_strerror(error));
						bytes -= attrsize;
						break;
					}

					if (aclcnt != acl_cnt(aclp)) {
						msg(ERR, "acl count error");
						bytes -= attrsize;
						break;
					}
					bytes -= attrsize;
					break;

				/* SunFed case goes here */

				default:
					msg(EXT, "unrecognized attr type");
					break;
			}
			/* next attributes */
			tp += attrsize;
			} while (bytes > 0);
			free(secp);
		} else {
			/* skip security info */
			G_p = &Gen;
			data_in(P_SKIP);
		}
		/*
		 * We already got the file content, dont call file_in()
		 * when return. The new return code(2) is used to
		 *  indicate that.
		 */
		VERBOSE((Args & OCt), Gen.g_nam_p);
		return (2);
	} /* acl */

	/*
	 * Sparse file support
	 * Read header of holesdata to get original file size.
	 * This is necessary because ckname() or file_in() shows file size
	 * with OCt before data_in() extracts the holesdata. data_in()
	 * actually doesn't extract the holesdata since proc_mode will be
	 * P_SKIP in the OCt mode.
	 */
	if ((Hdr_type == CHR || Hdr_type == ASC) &&
	    S_ISSPARSE(Gen.g_mode) && Gen.g_filesz > MIN_HOLES_HDRSIZE) {
		char	holesdata[MIN_HOLES_HDRSIZE + 1];

		FILL(MIN_HOLES_HDRSIZE);
		(void) memcpy(holesdata, Buffr.b_out_p, MIN_HOLES_HDRSIZE);
		holesdata[MIN_HOLES_HDRSIZE] = '\0';

		Gen.g_holes = read_holes_header(holesdata, Gen.g_filesz);
		if (Gen.g_holes == NULL) {
			msg(EXT, "invalid sparse file information");
		} else {
			Buffr.b_out_p += MIN_HOLES_HDRSIZE;
			Buffr.b_cnt -= MIN_HOLES_HDRSIZE;
		}
	}

	Adir = (ftype == S_IFDIR);
	Aspec = (ftype == S_IFBLK || ftype == S_IFCHR || ftype == S_IFIFO ||
	    ftype == S_IFSOCK);

	/*
	 * Skip any trailing slashes
	 */
	chop_endslashes(Gen.g_nam_p);
	return (1);
}

/*
 * getname: Get file names for inclusion in the archive.  When end of file
 * on the input stream of file names is reached, flush the link buffer out.
 * For each filename, remove leading "./"s and multiple "/"s, and remove
 * any trailing newline "\n".  Finally, verify the existence of the file,
 * and call creat_hdr() to fill in the gen_hdr structure.
 */

static int
getname(void)
{
	int goodfile = 0, lastchar, err;
	char *s;
	char *dir;

	Gen.g_nam_p = Nam_p;
	Hiddendir = 0;

	while (!goodfile) {
		err = 0;

		while ((s = fgets(Gen.g_nam_p, APATH+1, In_p)) != NULL) {
			lastchar = strlen(s) - 1;
			issymlink = 0;

			if (s[lastchar] != '\n') {
				if (lastchar == APATH - 1) {
					if (!err) {
						msg(ERR,
						    "%s name too long.",
						    Nam_p);
					}
					goodfile = 0;
					err = 1;
				} else {
					break;
				}
			} else {
				s[lastchar] = '\0';
				break;
			}
		}

		if (s == NULL) {
			if (Gen.g_dirfd != -1) {
				(void) close(Gen.g_dirfd);
				Gen.g_dirfd = -1;
			}
			if (Onecopy && (Args & OCo)) {
				flush_lnks();
			}
			return (0);
		}

		while (*Gen.g_nam_p == '.' && Gen.g_nam_p[1] == '/') {
			Gen.g_nam_p += 2;
			while (*Gen.g_nam_p == '/')
				Gen.g_nam_p++;
		}

		/*
		 * Skip any trailing slashes
		 */
		chop_endslashes(Gen.g_nam_p);

		/*
		 * Figure out parent directory
		 */

		if (Gen.g_attrnam_p != NULL) {
			if (Gen.g_dirfd != -1) {
				(void) close(Gen.g_dirfd);
			}
			Gen.g_dirfd = attropen(Gen.g_attrfnam_p, ".", O_RDONLY);
			if (Gen.g_dirfd == -1) {
				msg(ERRN,
				    "Cannot open attribute directory"
				    " of file %s", Gen.g_attrfnam_p);
				continue;
			}
		} else {
#ifdef O_XATTR
			char dirpath[PATH_MAX];

			get_parent(Gen.g_nam_p, dirpath);
			if (Atflag || SysAtflag) {
				dir = dirpath;
				if (Gen.g_dirfd != -1) {
					(void) close(Gen.g_dirfd);
				}
				Gen.g_dirfd = open(dir, O_RDONLY);
				if (Gen.g_dirfd == -1) {
					msg(ERRN,
					    "Cannot open directory %s", dir);
					continue;
				}
			} else {
				/*
				 * g_dirpath is the pathname cache maintaining
				 * the dirname which is currently opened.
				 * We first check the g_dirpath to see if the
				 * given dirname matches. If so, we don't need
				 * to open the dir, but we can use the g_dirfd
				 * as is if it is still available.
				 */
				dir = NULL;
				if (Gen.g_dirpath == NULL ||
				    Gen.g_dirfd == -1) {
					/*
					 * It's the first time or it has
					 * all gone.
					 */
					dir = e_strdup(E_EXIT, dirpath);
				} else {
					if (strcmp(Gen.g_dirpath,
					    dirpath) != 0) {
						/* different directory */
						dir = e_strdup(E_EXIT, dirpath);
					}
				}
				if (dir != NULL) {
					/*
					 * We need to open the new directory.
					 * discard the pathname and dirfd
					 * for the previous directory.
					 */
					if (Gen.g_dirpath != NULL) {
						free(Gen.g_dirpath);
						Gen.g_dirpath = NULL;
					}
					if (Gen.g_dirfd != -1) {
						(void) close(Gen.g_dirfd);
					}
					/* open the new dir */
					Gen.g_dirfd = open(dir, O_RDONLY);
					if (Gen.g_dirfd == -1) {
						msg(ERRN, "Cannot open "
						    "directory %s", dir);
						continue;
					}
					Gen.g_dirpath = dir;
				}
			}
#else
			Gen.g_dirfd = -1;
#endif
		}

		/* creat_hdr checks for USTAR filename length */

		if (Hdr_type != USTAR && strlen(Gen.g_nam_p) >
		    Max_namesz) {
			if (!err) {
				msg(ERR, "%s%s%s name too long.",
				    (Gen.g_attrnam_p == NULL) ?
				    Nam_p : Gen.g_attrfnam_p,
				    (Gen.g_attrnam_p == NULL) ?
				    "" : Gen.g_rw_sysattr ?
				    gettext(" System Attribute ") :
				    gettext(" Attribute "),
				    (Gen.g_attrnam_p == NULL) ?
				    "" : Gen.g_attrnam_p);
			}
			goodfile = 0;
			err = 1;
		}

		if (err) {
			continue;
		} else {
			G_p = &Gen;
			if (!LSTAT(Gen.g_dirfd, Gen.g_nam_p, &SrcSt)) {
				goodfile = 1;

				if ((SrcSt.st_mode & Ftype) == S_IFLNK) {
					issymlink = 1;

					if ((Args & OCL)) {
						errno = 0;
						if (STAT(Gen.g_dirfd,
						    G_p->g_nam_p,
						    &SrcSt) < 0) {
							msg(ERRN,
							    "Cannot follow"
							    " \"%s%s%s\"",
							    (Gen.g_attrnam_p ==
							    NULL) ?
							    Gen.g_nam_p :
							    Gen.g_attrfnam_p,
							    (Gen.g_attrnam_p ==
							    NULL) ? "" :
							    Gen.g_rw_sysattr ?
							    gettext(
							    " System "
							    "Attribute ") :
							    gettext(
							    " Attribute "),
							    (Gen.g_attrnam_p ==
							    NULL) ? "" :
							    Gen.g_attrnam_p);
							goodfile = 0;
						}
					}
				}

				if (Use_old_stat) {
					OldSt = convert_to_old_stat(&SrcSt,
					    Gen.g_nam_p, Gen.g_attrnam_p);

					if (OldSt == NULL) {
						goodfile = 0;
					}
				}
			} else {
				msg(ERRN,
				    "Error with fstatat() of \"%s%s%s\"",
				    (Gen.g_attrnam_p == NULL) ?
				    Gen.g_nam_p : Gen.g_attrfnam_p,
				    (Gen.g_attrnam_p == NULL) ? "" :
				    Gen.g_rw_sysattr ?
				    gettext(" System Attribute ") :
				    gettext(" Attribute "),
				    (Gen.g_attrnam_p == NULL) ?
				    "" : Gen.g_attrnam_p);
			}
		}
	}

	/*
	 * Get ACL info: dont bother allocating space if there are only
	 * standard permissions, i.e. ACL count < 4
	 */
	if ((SrcSt.st_mode & Ftype) != S_IFLNK && Pflag) {
		if (acl_get(Gen.g_nam_p, ACL_NO_TRIVIAL, &aclp) != 0)
			msg(ERRN, "Error with acl() of \"%s\"", Gen.g_nam_p);
	}
	/* else: only traditional permissions, so proceed as usual */
	if (creat_hdr())
		return (1);
	else return (2);
}

/*
 * getpats: Save any filenames/patterns specified as arguments.
 * Read additional filenames/patterns from the file specified by the
 * user.  The filenames/patterns must occur one per line.
 */

static void
getpats(int largc, char **largv)
{
	char **t_pp;
	size_t len;
	unsigned numpat = largc, maxpat = largc + 2;

	Pat_pp = e_zalloc(E_EXIT, maxpat * sizeof (char *));
	t_pp = Pat_pp;
	while (*largv) {
		*t_pp = e_zalloc(E_EXIT, strlen(*largv) + 1);
		(void) strcpy(*t_pp, *largv);
		t_pp++;
		largv++;
	}
	while (fgets(Nam_p, Max_namesz + 1, Ef_p) != NULL) {
		if (numpat == maxpat - 1) {
			maxpat += 10;
			Pat_pp = e_realloc(E_EXIT, Pat_pp,
			    maxpat * sizeof (char *));
			t_pp = Pat_pp + numpat;
		}
		len = strlen(Nam_p); /* includes the \n */
		*(Nam_p + len - 1) = '\0'; /* remove the \n */
		*t_pp = e_zalloc(E_EXIT, len);
		(void) strcpy(*t_pp, Nam_p);
		t_pp++;
		numpat++;
	}
	*t_pp = NULL;
}

static void
ioerror(int dir)
{
	int t_errno;

	t_errno = errno;
	errno = 0;
	if (fstat(Archive, &ArchSt) < 0)
		msg(EXTN, "Error during stat() of archive");
	errno = t_errno;
	if ((ArchSt.st_mode & Ftype) != S_IFCHR) {
		if (dir) {
			if (errno == EFBIG)
				msg(EXT, "ulimit reached for output file.");
			else if (errno == ENOSPC)
				msg(EXT, "No space left for output file.");
			else
				msg(EXTN, "I/O error - cannot continue");
		} else
			msg(EXT, "Unexpected end-of-file encountered.");
	} else
		msg(EXTN, "\007I/O error on \"%s\"", dir ? "output" : "input");
}

/*
 * matched: Determine if a filename matches the specified pattern(s).  If the
 * pattern is matched (the second return), return 0 if -f was specified, else
 * return != 0.  If the pattern is not matched (the first and third
 * returns), return 0 if -f was not specified, else return != 0.
 */

static int
matched(void)
{
	char *str_p = G_p->g_nam_p;
	char **pat_pp = Pat_pp;
	int negatep, result;

	/*
	 * Check for attribute
	 */
	if (G_p->g_attrfnam_p != NULL)
		str_p = G_p->g_attrfnam_p;

	for (pat_pp = Pat_pp; *pat_pp; pat_pp++) {
		negatep = (**pat_pp == '!');

		result = fnmatch(negatep ? (*pat_pp+1) : *pat_pp, str_p, 0);

		if (result != 0 && result != FNM_NOMATCH) {
			msg(POST, "error matching file %s with pattern"
			    " %s\n", str_p, *pat_pp);
			return (Args & OCf);
		}

		if ((result == 0 && ! negatep) ||
		    (result == FNM_NOMATCH && negatep)) {
			/* match occurred */
			return (!(Args & OCf));
		}
	}
	return (Args & OCf); /* not matched */
}

/*
 * missdir: Create missing directories for files.
 * (Possible future performance enhancement, if missdir is called, we know
 * that at least the very last directory of the path does not exist, therefore,
 * scan the path from the end
 */

static int
missdir(char *nam_p)
{
	char *c_p;
	int cnt = 2;
	char *lastp;

	if (*(c_p = nam_p) == '/') /* skip over 'root slash' */
		c_p++;

	lastp = c_p + strlen(nam_p) - 1;
	if (*lastp == '/')
		*lastp = '\0';

	for (; *c_p; ++c_p) {
		if (*c_p == '/') {
			*c_p = '\0';
			if (stat(nam_p, &DesSt) < 0) {
				if (Args & OCd) {
					cnt = mkdir(nam_p, Def_mode);
					if (cnt != 0) {
						*c_p = '/';
						return (cnt);
					}
				} else {
					msg(ERR, "Missing -d option.");
					*c_p = '/';
					return (-1);
				}
			}
			*c_p = '/';
		}
	}
	if (cnt == 2) /* the file already exists */
		cnt = 0;
	return (cnt);
}

/*
 * mklong: Convert two shorts into one long.  For VAX, Interdata ...
 */

static long
mklong(short v[])
{

	union swpbuf swp_b;

	swp_b.s_word = 1;
	if (swp_b.s_byte[0]) {
		swp_b.s_half[0] = v[1];
		swp_b.s_half[1] = v[0];
	} else {
		swp_b.s_half[0] = v[0];
		swp_b.s_half[1] = v[1];
	}
	return (swp_b.s_word);
}

/*
 * mkshort: Convert a long into 2 shorts, for VAX, Interdata ...
 */

static void
mkshort(short sval[], long v)
{
	union swpbuf *swp_p, swp_b;

	/* LINTED alignment */
	swp_p = (union swpbuf *)sval;
	swp_b.s_word = 1;
	if (swp_b.s_byte[0]) {
		swp_b.s_word = v;
		swp_p->s_half[0] = swp_b.s_half[1];
		swp_p->s_half[1] = swp_b.s_half[0];
	} else {
		swp_b.s_word = v;
		swp_p->s_half[0] = swp_b.s_half[0];
		swp_p->s_half[1] = swp_b.s_half[1];
	}
}

/*
 * msg: Print either a message (no error) (POST), an error message with or
 * without the errno (ERRN or ERR), or print an error message with or without
 * the errno and exit (EXTN or EXT).
 */
void
msg(int severity, const char *fmt, ...)
{
	FILE *file_p;
	va_list ap;

	if ((Args & OCV) && Verbcnt) { /* clear current line of dots */
		(void) fputc('\n', Out_p);
		Verbcnt = 0;
	}
	va_start(ap, fmt);
	if (severity == POST)
		file_p = Out_p;
	else
		if (severity == EPOST)
			file_p = Err_p;
		else {
			file_p = Err_p;
			Error_cnt++;
		}
	(void) fflush(Out_p);
	(void) fflush(Err_p);
	if ((severity != POST) && (severity != EPOST))
		(void) fprintf(file_p, "cpio: ");

	/* gettext replaces version of string */

	(void) vfprintf(file_p, gettext(fmt), ap);
	if (severity == ERRN || severity == EXTN) {
		if (G_p && (G_p->g_attrnam_p != NULL) && G_p->g_rw_sysattr) {
			if (errno == EPERM) {
				(void) fprintf(file_p, ", errno %d, %s", errno,
				    gettext("insufficient privileges\n"));
			} else if (errno == EINVAL) {
				(void) fprintf(file_p, ", errno %d, %s",
				    errno, gettext(
				    "unsupported on underlying file system\n"));
			} else {
				(void) fprintf(file_p, ", errno %d, ", errno);
				perror("");
			}
		} else {
			(void) fprintf(file_p, ", errno %d, ", errno);
			perror("");
		}
	} else
		(void) fprintf(file_p, "\n");
	(void) fflush(file_p);
	va_end(ap);
	if (severity == EXT || severity == EXTN) {
		(void) fprintf(file_p, gettext("%d errors\n"), Error_cnt);
		exit(EXIT_CODE);
	}
}

/*
 * openout: Open files for output and set all necessary information.
 * If the u option is set (unconditionally overwrite existing files),
 * and the current file exists, get a temporary file name from mktemp(3C),
 * link the temporary file to the existing file, and remove the existing file.
 * Finally either creat(2), mkdir(2) or mknod(2) as appropriate.
 *
 */

static int
openout(int dirfd)
{
	char *nam_p;
	int cnt, result;

	Do_rename = 0;	/* creat_tmp() may reset this */

	if (G_p->g_attrnam_p != NULL) {
		nam_p = G_p->g_attrnam_p;
	} else {
		if (Args & OCp) {
			nam_p = Fullnam_p;
		} else {
			nam_p = G_p->g_nam_p;
		}
	}


	if ((Max_filesz != RLIM_INFINITY) &&
	    (Max_filesz < (G_p->g_filesz >> 9))) {
		/* ... divided by 512 ... */
		msg(ERR, "Skipping \"%s%s%s\": exceeds ulimit by %lld bytes",
		    (G_p->g_attrnam_p == NULL) ? nam_p : G_p->g_attrfnam_p,
		    (G_p->g_attrnam_p == NULL) ? "" : G_p->g_rw_sysattr ?
		    gettext(" System Attribute ") : gettext(" Attribute "),
		    (G_p->g_attrnam_p == NULL) ? "" : nam_p,
		    (off_t)(G_p->g_filesz - (Max_filesz << 9)));
		return (-1);
	}

	if (LSTAT(dirfd, nam_p, &DesSt) == 0) {
		/*
		 * A file by the same name exists.  Move it to a temporary
		 * file unless it's a system attribute file.  If we are
		 * restoring a system attribute file on a file system that
		 * supports system attributes, then the system attribute file
		 * will already exist (a default system attribute file will
		 * get created when the file it is associated with is created).
		 * If we create a temporary system attribute file, we can't
		 * overwrite the existing system attribute file using
		 * renameat().  In addition, only system attributes can exist
		 * for an attribute of a file, therefore, a temporary file
		 * cannot be created for a system attribute of an attribute.
		 * Thus, when restoring a system attribute, we won't move it
		 * to a temporary file, but will attempt to process it as if
		 * it didn't already exist.
		 */

#if defined(_PC_SATTR_ENABLED)
		if (G_p->g_rw_sysattr == 0)
#endif	/* _PC_SATTR_ENABLED */
			if (creat_tmp(nam_p) < 0) {
				/*
				 * We weren't able to create the temp file.
				 * Report failure.
				 */

				return (-1);
			}
	}

	if (Do_rename) {
		/* nam_p was changed by creat_tmp() above. */

		if (Args & OCp) {
			if (G_p->g_attrnam_p != NULL) {
				nam_p = Attrfile_p;
			} else {
				nam_p = Fullnam_p;
			}
		} else {
			nam_p = G_p->g_nam_p;
		}
	}

	/*
	 * This pile tries to create the file directly, and, if there is a
	 * problem, creates missing directories, and then tries to create the
	 * file again.  Two strikes and you're out.
	 *
	 * On XATTR system, the directory has already been created by
	 * open_dirfd(), so error shouldn't happen in the loop. However,
	 * on non-XATTR system, symlink/open may fail with ENOENT. In such
	 * case, we go to create missing directories.
	 */

	cnt = 0;

	do {
		errno = 0;

		if (Hdr_type == TAR && Thdr_p->tbuf.t_typeflag == SYMTYPE) {
			/* The archive file is a TAR symlink. */
			if ((result =
			    symlink(Thdr_p->tbuf.t_linkname, nam_p)) >= 0) {
				cnt = 0;
				if (Over_p != NULL) {
					(void) unlinkat(dirfd,
					    get_component(Over_p), 0);
					*Over_p = '\0';
				}
				break;
			} else if (errno != ENOENT) {
				/* The attempt to symlink failed. */
				msg(ERRN,
				    "Cannot create symbolic link \"%s\" -> "
				    "\"%s\"",
				    Thdr_p->tbuf.t_linkname, nam_p);

				if (*Over_p != '\0') {
					rstfiles(U_KEEP, dirfd);
				}
				return (-1);
			}
		} else if (Hdr_type == BAR && bar_linkflag == SYMTYPE) {
			if ((result = symlink(bar_linkname, nam_p)) >= 0) {
				cnt = 0;
				if (Over_p != NULL) {
					(void) unlinkat(dirfd,
					    get_component(Over_p), 0);
					*Over_p = '\0';
				}
				break;
			} else if (errno != ENOENT) {
				/* The attempt to symlink failed. */
				msg(ERRN,
				    "Cannot create symbolic link \"%s\" -> "
				    "\"%s\"",
				    bar_linkname, nam_p);
				if (*Over_p != '\0') {
					rstfiles(U_KEEP, dirfd);
				}
				return (-1);
			}
		} else if ((G_p->g_mode & Ftype) == S_IFLNK) {
			if ((!(Args & OCp)) && !(Hdr_type == USTAR)) {
				FILL(G_p->g_filesz);
				(void) strncpy(Symlnk_p,
				    Buffr.b_out_p, G_p->g_filesz);
				*(Symlnk_p + G_p->g_filesz) = '\0';
			} else if ((!(Args & OCp)) && (Hdr_type == USTAR)) {
				Symlnk_p[NAMSIZ] = '\0';
				(void) strncpy(Symlnk_p,
				    &Thdr_p->tbuf.t_linkname[0], NAMSIZ);
			}
			if ((result = symlink(Symlnk_p, nam_p)) >= 0) {
				cnt = 0;
				if (Over_p != NULL) {
					(void) unlinkat(dirfd,
					    get_component(Over_p), 0);
					*Over_p = '\0';
				}
				break;
			} else if (errno != ENOENT) {
				/* The attempt to symlink failed. */
				msg(ERRN,
				    "Cannot create symbolic link \"%s\" -> "
				    "\"%s\"",
				    Symlnk_p, nam_p);

				if (*Over_p != '\0') {
					rstfiles(U_KEEP, dirfd);
				}
				return (-1);
			}
		} else {
			int	saveerrno;

			if ((result = openat(dirfd, get_component(nam_p),
			    O_CREAT|O_RDWR|O_TRUNC, (int)G_p->g_mode)) < 0) {
				saveerrno = errno;
				if (G_p->g_attrnam_p != NULL)  {
					result = retry_open_attr(dirfd,
					    Gen.g_baseparent_fd, Fullnam_p,
					    (G_p->g_attrparent_p == NULL) ?
					    NULL : G_p->g_attrparent_p, nam_p,
					    O_CREAT|O_RDWR|O_TRUNC,
					    (int)G_p->g_mode);
				}
			}
			if (result < 0) {
				errno = saveerrno;
				if (errno != ENOENT) {
					/* The attempt to open failed. */
					msg(ERRN, "Cannot open file \"%s\"",
					    nam_p);
					if (*Over_p != '\0') {
						rstfiles(U_KEEP, dirfd);
					}
					return (-1);
				}
			} else {
				/* acl support */
				acl_is_set = 0;
				if (Pflag && aclp != NULL) {
					if (facl_set(result, aclp) < 0) {
						msg(ERRN,
						    "\"%s\": failed to set acl",
						    nam_p);
					} else {
						acl_is_set = 1;
					}
					acl_free(aclp);
					aclp = NULL;
				}
				cnt = 0;
				break;
			}
		}
		cnt++;
	} while (cnt < 2 && missdir(nam_p) == 0);

	switch (cnt) {
	case 0:
		if ((Args & OCi) && (Hdr_type == USTAR)) {
			setpasswd(nam_p);
		}
		if ((G_p->g_mode & Ftype) == S_IFLNK ||
		    (Hdr_type == BAR && bar_linkflag == SYMTYPE)) {
			if (Args & OCR) {
				if (fchownat(dirfd,
				    get_component(nam_p),
				    (int)Rpw_p->pw_uid,
				    (int)Rpw_p->pw_gid,
				    AT_SYMLINK_NOFOLLOW) < 0) {
					msg(ERRN,
					    "Error during chown() of "
					    "\"%s%s%s\"",
					    (G_p->g_attrnam_p == NULL) ?
					    nam_p : G_p->g_attrfnam_p,
					    (G_p->g_attrnam_p == NULL) ?
					    "" : G_p->g_rw_sysattr ?
					    gettext(" System Attribute ") :
					    gettext(" Attribute "),
					    (G_p->g_attrnam_p == NULL) ?
					    "" : nam_p);
				}
			} else if ((fchownat(dirfd, get_component(nam_p),
			    (int)G_p->g_uid, (int)G_p->g_gid,
			    AT_SYMLINK_NOFOLLOW) < 0) && privileged) {
				msg(ERRN,
				    "Error during chown() of \"%s%s%s\"",
				    (G_p->g_attrnam_p == NULL) ?
				    nam_p : G_p->g_attrfnam_p,
				    (G_p->g_attrnam_p == NULL) ? "" :
				    G_p->g_rw_sysattr ?
				    gettext(" System Attribute ") :
				    gettext(" Attribute "),
				    (G_p->g_attrnam_p == NULL) ? "" : nam_p);
			}
		}
		break;

	case 1:
		if (Do_rename) {
			msg(ERRN, "Cannot create directory for \"%s%s%s\"",
			    (G_p->g_attrnam_p == NULL) ? Over_p :
			    G_p->g_attrfnam_p,
			    (G_p->g_attrnam_p == NULL) ? "" :
			    G_p->g_rw_sysattr ?
			    gettext(" System Attribute ") :
			    gettext(" Attribute "),
			    (G_p->g_attrnam_p == NULL) ? "" : Over_p);
		} else {
			msg(ERRN, "Cannot create directory for \"%s%s%s\"",
			    (G_p->g_attrnam_p == NULL) ? nam_p :
			    G_p->g_attrfnam_p,
			    (G_p->g_attrnam_p == NULL) ? "" :
			    G_p->g_rw_sysattr ?
			    gettext(" System Attribute ") :
			    gettext(" Attribute "),
			    (G_p->g_attrnam_p == NULL) ? "" : nam_p);
		}
		break;

	case 2:
		if (Do_rename) {
			msg(ERRN, "Cannot create \"%s%s%s\"",
			    (G_p->g_attrnam_p == NULL) ? Over_p :
			    G_p->g_attrfnam_p,
			    (G_p->g_attrnam_p == NULL) ? "" :
			    G_p->g_rw_sysattr ?
			    gettext(" System Attribute ") :
			    gettext(" Attribute "),
			    (G_p->g_attrnam_p == NULL) ? "" :
			    Over_p);
		} else {
			msg(ERRN, "Cannot create \"%s%s%s\"",
			    (G_p->g_attrnam_p == NULL) ? nam_p :
			    G_p->g_attrfnam_p,
			    (G_p->g_attrnam_p == NULL) ? "" :
			    G_p->g_rw_sysattr ?
			    gettext(" System Attribute ") :
			    gettext(" Attribute "),
			    (G_p->g_attrnam_p == NULL) ? "" : nam_p);
		}
		break;

	default:
		msg(EXT, "Impossible case.");
	}

	Finished = 0;
	return (result);
}

/*
 * read_hdr: Transfer headers from the selected format
 * in the archive I/O buffer to the generic structure.
 */

static
int
read_hdr(int hdr)
{
	int rv = NONE;
	major_t maj, rmaj;
	minor_t min, rmin;
	char tmpnull;
	static int bar_read_cnt = 0;

	if (hdr != BAR) {
		if (Buffr.b_end_p != (Buffr.b_out_p + Hdrsz)) {
			tmpnull = *(Buffr.b_out_p + Hdrsz);
			*(Buffr.b_out_p + Hdrsz) = '\0';
		}
	}

	switch (hdr) {
	case BIN:
		(void) memcpy(&Hdr, Buffr.b_out_p, HDRSZ);
		if (Hdr.h_magic == (short)CMN_BBS) {
			swap((char *)&Hdr, HDRSZ);
		}
		Gen.g_magic = Hdr.h_magic;
		Gen.g_mode = Hdr.h_mode;
		Gen.g_uid = Hdr.h_uid;
		Gen.g_gid = Hdr.h_gid;
		Gen.g_nlink = Hdr.h_nlink;
		Gen.g_mtime = mklong(Hdr.h_mtime);
		Gen.g_ino = Hdr.h_ino;
		Gen.g_dev = Hdr.h_dev;
		Gen.g_rdev = Hdr.h_rdev;
		Gen.g_cksum = 0L;
		Gen.g_filesz = (off_t)mklong(Hdr.h_filesize);
		Gen.g_namesz = Hdr.h_namesize;
		rv = BIN;
		break;
	case CHR:
		if (sscanf(Buffr.b_out_p,
		    "%6lo%6lo%6lo%6lo%6lo%6lo%6lo%6lo%11lo%6o%11llo",
		    &Gen.g_magic, &Gen.g_dev, &Gen.g_ino, &Gen.g_mode,
		    &Gen.g_uid, &Gen.g_gid, &Gen.g_nlink, &Gen.g_rdev,
		    (ulong_t *)&Gen.g_mtime, (uint_t *)&Gen.g_namesz,
		    (u_off_t *)&Gen.g_filesz) == CHR_CNT) {
			rv = CHR;
#define	cpioMAJOR(x)	(int)(((unsigned)x >> 8) & 0x7F)
#define	cpioMINOR(x)	(int)(x & 0xFF)
			maj = cpioMAJOR(Gen.g_dev);
			rmaj = cpioMAJOR(Gen.g_rdev);
			min = cpioMINOR(Gen.g_dev);
			rmin = cpioMINOR(Gen.g_rdev);
			if (Use_old_stat) {
				/* needs error checking */
				Gen.g_dev = (maj << 8) | min;
				Gen.g_rdev = (rmaj << 8) | rmin;
			} else {
				Gen.g_dev = makedev(maj, min);
				Gen.g_rdev = makedev(rmaj, rmin);
			}
		}
		break;
	case ASC:
	case CRC:
		if (sscanf(Buffr.b_out_p,
		    "%6lx%8lx%8lx%8lx%8lx%8lx%8lx%8llx%8x%8x%8x%8x%8x%8lx",
		    &Gen.g_magic, &Gen.g_ino, &Gen.g_mode, &Gen.g_uid,
		    &Gen.g_gid, &Gen.g_nlink, &Gen.g_mtime,
		    (u_off_t *)&Gen.g_filesz, (uint_t *)&maj, (uint_t *)&min,
		    (uint_t *)&rmaj, (uint_t *)&rmin, (uint_t *)&Gen.g_namesz,
		    &Gen.g_cksum) == ASC_CNT) {
			Gen.g_dev = makedev(maj, min);
			Gen.g_rdev = makedev(rmaj, rmin);
			rv = hdr;
		}
		break;
	case USTAR: /* TAR and USTAR */
		if (*Buffr.b_out_p == '\0') {
			*Gen.g_nam_p = '\0';
			nambuf[0] = '\0';
		} else {
			Thdr_p = (union tblock *)Buffr.b_out_p;
			Gen.g_nam_p[0] = '\0';
			(void) strncpy((char *)&nambuf,
			    Thdr_p->tbuf.t_name, NAMSIZ);
			(void) sscanf(Thdr_p->tbuf.t_mode, "%8lo",
			    &Gen.g_mode);
			(void) sscanf(Thdr_p->tbuf.t_uid, "%8lo", &Gen.g_uid);
			(void) sscanf(Thdr_p->tbuf.t_gid, "%8lo", &Gen.g_gid);
			(void) sscanf(Thdr_p->tbuf.t_size, "%11llo",
			    (u_off_t *)&Gen.g_filesz);
			(void) sscanf(Thdr_p->tbuf.t_mtime, "%12lo",
			    (ulong_t *)&Gen.g_mtime);
			(void) sscanf(Thdr_p->tbuf.t_cksum, "%8lo",
			    (ulong_t *)&Gen.g_cksum);
			if (Thdr_p->tbuf.t_linkname[0] != '\0')
				Gen.g_nlink = 1;
			else
				Gen.g_nlink = 0;

			switch (Thdr_p->tbuf.t_typeflag) {
			case SYMTYPE:
				/* Symbolic Link */
				Gen.g_nlink = 2;
				break;
			case CHRTYPE:
				Gen.g_mode |= (S_IFMT & S_IFCHR);
				break;
			case BLKTYPE:
				Gen.g_mode |= (S_IFMT & S_IFBLK);
				break;
			case DIRTYPE:
				Gen.g_mode |= (S_IFMT & S_IFDIR);
				break;
			case FIFOTYPE:
				Gen.g_mode |= (S_IFMT & S_IFIFO);
				break;
			}

			(void) sscanf(Thdr_p->tbuf.t_magic, "%8lo",
			    /* LINTED alignment */
			    (ulong_t *)&Gen.g_tmagic);
			(void) sscanf(Thdr_p->tbuf.t_version, "%8lo",
			    /* LINTED alignment */
			    (ulong_t *)&Gen.g_version);
			(void) sscanf(Thdr_p->tbuf.t_uname, "%32s",
			    (char *)&Gen.g_uname);
			(void) sscanf(Thdr_p->tbuf.t_gname, "%32s",
			    (char *)&Gen.g_gname);
			(void) sscanf(Thdr_p->tbuf.t_devmajor, "%8lo",
			    &Gen.g_dev);
			(void) sscanf(Thdr_p->tbuf.t_devminor, "%8lo",
			    &Gen.g_rdev);
			(void) strncpy((char *)&prebuf,
			    Thdr_p->tbuf.t_prefix, PRESIZ);
			Gen.g_namesz = strlen(Gen.g_nam_p) + 1;
			Gen.g_dev = makedev(maj, min);
		}
		rv = USTAR;
		break;
	case TAR:
		if (*Buffr.b_out_p == '\0') {
			*Gen.g_nam_p = '\0';
			nambuf[0] = '\0';
		} else {
			Thdr_p = (union tblock *)Buffr.b_out_p;
			Gen.g_nam_p[0] = '\0';
			(void) sscanf(Thdr_p->tbuf.t_mode, "%lo", &Gen.g_mode);
			(void) sscanf(Thdr_p->tbuf.t_uid, "%lo", &Gen.g_uid);
			(void) sscanf(Thdr_p->tbuf.t_gid, "%lo", &Gen.g_gid);
			(void) sscanf(Thdr_p->tbuf.t_size, "%llo",
			    (u_off_t *)&Gen.g_filesz);
			(void) sscanf(Thdr_p->tbuf.t_mtime, "%lo",
			    &Gen.g_mtime);
			(void) sscanf(Thdr_p->tbuf.t_cksum, "%lo",
			    &Gen.g_cksum);
			if (Thdr_p->tbuf.t_typeflag == '1')	/* hardlink */
				Gen.g_nlink = 1;
			else
				Gen.g_nlink = 0;
			(void) strncpy(Gen.g_nam_p,
			    Thdr_p->tbuf.t_name, NAMSIZ);
			Gen.g_namesz = strlen(Gen.g_nam_p) + 1;
			(void) strcpy(nambuf, Gen.g_nam_p);
		}
		rv = TAR;
		break;
	case BAR:
		if (Bar_vol_num == 0 && bar_read_cnt == 0) {
			read_bar_vol_hdr();
			bar_read_cnt++;
		}
		else
			read_bar_file_hdr();
		rv = BAR;
		break;
	default:
		msg(EXT, "Impossible header type.");
	}

	if (hdr != BAR) {
		if (Buffr.b_end_p != (Buffr.b_out_p + Hdrsz))
			*(Buffr.b_out_p + Hdrsz) = tmpnull;
	}

	return (rv);
}

/*
 * reclaim: Reclaim linked file structure storage.
 */

static void
reclaim(struct Lnk *p)
{
	p->L_bck_p->L_nxt_p = p->L_nxt_p;
	p->L_nxt_p->L_bck_p = p->L_bck_p;

	while (p != NULL) {
		struct Lnk *new_p = p->L_lnk_p;

		free(p->L_gen.g_nam_p);
		free(p);
		p = new_p;
	}
}

/*
 * rstbuf: Reset the I/O buffer, move incomplete potential headers to
 * the front of the buffer and force bread() to refill the buffer.  The
 * return value from bread() is returned (to identify I/O errors).  On the
 * 3B2, reads must begin on a word boundary, therefore, with the -i option,
 * any remaining bytes in the buffer must be moved to the base of the buffer
 * in such a way that the destination locations of subsequent reads are
 * word aligned.
 */

static void
rstbuf(void)
{
	int pad;

	if ((Args & OCi) || Append) {
		if (Buffr.b_out_p != Buffr.b_base_p) {
			pad = ((Buffr.b_cnt + FULLWD) & ~FULLWD);
			Buffr.b_in_p = Buffr.b_base_p + pad;
			pad -= Buffr.b_cnt;
			(void) memcpy(Buffr.b_base_p + pad, Buffr.b_out_p,
			    (int)Buffr.b_cnt);
			Buffr.b_out_p = Buffr.b_base_p + pad;
		}
		if (bfill() < 0)
			msg(EXT, "Unexpected end-of-archive encountered.");
	} else { /* OCo */
		(void) memcpy(Buffr.b_base_p, Buffr.b_out_p, (int)Buffr.b_cnt);
		Buffr.b_out_p = Buffr.b_base_p;
		Buffr.b_in_p = Buffr.b_base_p + Buffr.b_cnt;
	}
}

static void
setpasswd(char *nam)
{
	if ((dpasswd = getpwnam(&Gen.g_uname[0])) == NULL) {
		msg(EPOST, "cpio: problem reading passwd entry");
		msg(EPOST, "cpio: %s: owner not changed", nam);
		if (Gen.g_uid == UID_NOBODY && S_ISREG(Gen.g_mode))
			Gen.g_mode &= ~S_ISUID;
	} else
		Gen.g_uid = dpasswd->pw_uid;

	if ((dgroup = getgrnam(&Gen.g_gname[0])) == NULL) {
		msg(EPOST, "cpio: problem reading group entry");
		msg(EPOST, "cpio: %s: group not changed", nam);
		if (Gen.g_gid == GID_NOBODY && S_ISREG(Gen.g_mode))
			Gen.g_mode &= ~S_ISGID;
	} else
		Gen.g_gid = dgroup->gr_gid;
	G_p = &Gen;
}

/*
 * rstfiles:  Perform final changes to the file.  If the -u option is set,
 * and overwrite == U_OVER, remove the temporary file, else if overwrite
 * == U_KEEP, unlink the current file, and restore the existing version
 * of the file.  In addition, where appropriate, set the access or modification
 * times, change the owner and change the modes of the file.
 *
 * Note that if Do_rename is set, then the roles of original and temporary
 * file are reversed. If all went well, we will rename() the temporary file
 * over the original in order to accommodate potentially executing files.
 */
static void
rstfiles(int over, int dirfd)
{
	char *inam_p, *onam_p, *nam_p;
	int error;

#if defined(_PC_SATTR_ENABLED)
	/* Time or permissions cannot be set on system attribute files */
	if ((Gen.g_attrnam_p != NULL) && (Gen.g_rw_sysattr == 1)) {
		return;
	}
#endif	/* _PC_SATTR_ENABLED */

	if (Args & OCp) {
		if (G_p->g_attrnam_p == NULL) {
			nam_p = Fullnam_p;
		} else {
			nam_p = G_p->g_attrnam_p;
		}
	} else {
		if (Gen.g_nlink > (ulong_t)0) {
			nam_p = G_p->g_nam_p;
		} else {
			nam_p = Gen.g_nam_p;
		}
	}
	if (Gen.g_attrnam_p != NULL) {
		nam_p = Gen.g_attrnam_p;
	}

	if ((Args & OCi) && (Hdr_type == USTAR)) {
		setpasswd(nam_p);
	}
	if (over == U_KEEP && *Over_p != '\0') {
		if (Do_rename) {
			msg(POST, "Restoring existing \"%s%s%s\"",
			    (G_p->g_attrnam_p == NULL) ? Over_p : Fullnam_p,
			    (G_p->g_attrnam_p == NULL) ? "" :
			    G_p->g_rw_sysattr ? gettext(" System Attribute ") :
			    gettext(" Attribute "),
			    (G_p->g_attrnam_p == NULL) ? "" : Over_p);
		} else {
			msg(POST, "Restoring existing \"%s%s%s\"",
			    (G_p->g_attrnam_p == NULL) ? nam_p : Fullnam_p,
			    (G_p->g_attrnam_p == NULL) ? "" :
			    G_p->g_rw_sysattr ? gettext(" System Attribute ") :
			    gettext(" Attribute "),
			    (G_p->g_attrnam_p == NULL) ? "" : nam_p);
		}

		/* delete what we just built */
		(void) unlinkat(dirfd, get_component(nam_p), 0);

		/* If the old file needs restoring, do the necessary links */
		if (Do_rename) {
			char *tmp_ptr;

			if (Args & OCp) {
				tmp_ptr = Fullnam_p;
				Fullnam_p = Over_p;
			} else {
				tmp_ptr = G_p->g_nam_p;
				G_p->g_nam_p = Over_p;
			}
			Over_p = tmp_ptr;

			Do_rename = 0;	/* names now have original values */
		} else {
			if (rename(Over_p, nam_p) < 0) {
				if (link(Over_p, nam_p) < 0) {
					msg(EXTN,
					    "Cannot recover original version"
					    " of \"%s%s%s\"",
					    (G_p->g_attrnam_p == NULL) ?
					    nam_p : Fullnam_p,
					    (G_p->g_attrnam_p == NULL) ? "" :
					    G_p->g_rw_sysattr ?
					    gettext(" System Attribute ") :
					    gettext(" Attribute "),
					    (G_p->g_attrnam_p == NULL) ?
					    "" : nam_p);
				}
				if (unlinkat(dirfd, get_component(Over_p), 0)) {
					msg(ERRN,
					    "Cannot remove temp file "
					    "\"%s%s%s\"",
					    (G_p->g_attrnam_p == NULL) ?
					    Over_p : Fullnam_p,
					    (G_p->g_attrnam_p == NULL) ? "" :
					    G_p->g_rw_sysattr ?
					    gettext(" System Attribute ") :
					    gettext(" Attribute "),
					    (G_p->g_attrnam_p == NULL) ?
					    "" : Over_p);
				}
			}
		}
		*Over_p = '\0';
		return;
	} else if (over == U_OVER && *Over_p != '\0') {
		if (Do_rename) {
			char *tmp_ptr;

			(void) renameat(dirfd, get_component(nam_p),
			    dirfd, get_component(Over_p));
			if (Args & OCp) {
				if (G_p->g_attrnam_p == NULL) {
					tmp_ptr = Fullnam_p;
					Fullnam_p = Over_p;
					Over_p = tmp_ptr;
				} else {
					/*
					 * Over_p is pointing at g_attrnam_p
					 * which must be preserved.
					 *
					 * We don't want the tmp_ptr and so
					 * on to throw away our only copy of
					 * the name.
					 */
					Over_p = Attrfile_p;
				}
			} else {
				tmp_ptr = G_p->g_nam_p;
				G_p->g_nam_p = Over_p;
				Over_p = tmp_ptr;
			}
			Do_rename = 0;	/* names now have original values */
		} else {
			if (unlinkat(dirfd, get_component(Over_p), 0) < 0) {
				msg(ERRN,
				    "Cannot unlink() temp file \"%s%s%s\"",
				    (G_p->g_attrnam_p == NULL) ?
				    Over_p : Fullnam_p,
				    (G_p->g_attrnam_p == NULL) ? "" :
				    G_p->g_rw_sysattr ?
				    gettext(" System Attribute ") :
				    gettext(" Attribute "),
				    (G_p->g_attrnam_p == NULL) ? "" : Over_p);
			}
		}
		*Over_p = '\0';
	}
	if (Args & OCp) {
		if (G_p->g_attrnam_p != NULL) {
			inam_p = G_p->g_attrfnam_p;
			onam_p = G_p->g_attrnam_p;
		} else {
			inam_p = Nam_p;
			onam_p = Fullnam_p;
		}
	} else /* OCi only uses onam_p, OCo only uses inam_p */
		if (G_p->g_attrnam_p != NULL) {
			inam_p = onam_p = G_p->g_attrnam_p;
		} else {
			inam_p = onam_p = G_p->g_nam_p;
		}

	/*
	 * Change the owner, time, and mode to those of the file
	 * originally created in the archive.  Note: time and
	 * mode do not need to be restored for a symbolic link
	 * since rstfiles() is not called when the archived file
	 * is a symlink.
	 */
	if (!(Args & OCo)) {
		if (Args & OCR) {
			if (fchownat(dirfd, get_component(onam_p),
			    Rpw_p->pw_uid, Rpw_p->pw_gid,
			    AT_SYMLINK_NOFOLLOW) < 0) {
				msg(ERRN, "Cannot chown() \"%s%s%s\"",
				    onam_p,
				    (G_p->g_attrnam_p == NULL) ? "" :
				    G_p->g_rw_sysattr ?
				    gettext(" System Attribute ") :
				    gettext(" Attribute "),
				    (G_p->g_attrnam_p == NULL) ? "" : onam_p);
			}
		} else {
			if ((fchownat(dirfd, get_component(onam_p),
			    G_p->g_uid, G_p->g_gid,
			    AT_SYMLINK_NOFOLLOW) < 0) && privileged) {
				msg(ERRN, "Cannot chown() \"%s%s%s\"",
				    onam_p,
				    (G_p->g_attrnam_p == NULL) ? "" :
				    G_p->g_rw_sysattr ?
				    gettext(" System Attribute ") :
				    gettext(" Attribute "),
				    (G_p->g_attrnam_p == NULL) ? "" : onam_p);
			}
		}

		if (Args & OCm) {
			set_tym(dirfd, get_component(onam_p),
			    G_p->g_mtime, G_p->g_mtime);
		}

		/* Acl was not set, so we must chmod */
		if (!acl_is_set) {
			mode_t orig_mask, new_mask;

			/*
			 * use fchmod for attributes, since
			 * we known they are always regular
			 * files, whereas when it isn't an
			 * attribute it could be for a fifo
			 * or something other that we don't
			 * open and don't have a valid Ofile
			 * for.
			 */
			if (privileged) {
				new_mask = G_p->g_mode;
			} else {
				orig_mask = umask(0);
				new_mask = G_p->g_mode & ~orig_mask;
			}

			if (G_p->g_attrnam_p != NULL) {
				error = fchmod(Ofile, new_mask);
			} else {
				error = chmod(onam_p, new_mask);
			}
			if (error < 0) {
				msg(ERRN,
				    "Cannot chmod() \"%s%s%s\"",
				    (G_p->g_attrnam_p == NULL) ?
				    onam_p : G_p->g_attrfnam_p,
				    (G_p->g_attrnam_p == NULL) ? "" :
				    G_p->g_rw_sysattr ?
				    gettext(" System Attribute ") :
				    gettext(" Attribute "),
				    (G_p->g_attrnam_p == NULL) ? "" : onam_p);
			}
			if (!privileged) {
				(void) umask(orig_mask);
			}
		}
	}

	if (!(Args & OCi) && (Args & OCa)) {
		/*
		 * Use dirfd since we are updating original file
		 * and not just created file
		 */
		set_tym(G_p->g_dirfd, get_component(inam_p),
		    (ulong_t)SrcSt.st_atime, (ulong_t)SrcSt.st_mtime);
	}
}

/*
 * scan4trail: Scan the archive looking for the trailer.
 * When found, back the archive up over the trailer and overwrite
 * the trailer with the files to be added to the archive.
 */

static void
scan4trail(void)
{
	int rv;
	off_t off1, off2;

	Append = 1;
	Hdr_type = NONE;
	G_p = NULL;
	while (gethdr()) {
		G_p = &Gen;
		data_in(P_SKIP);
	}
	off1 = Buffr.b_cnt;
	off2 = Bufsize - (Buffr.b_cnt % Bufsize);
	Buffr.b_out_p = Buffr.b_in_p = Buffr.b_base_p;
	Buffr.b_cnt = (off_t)0;
	if (lseek(Archive, -(off1 + off2), SEEK_REL) < 0)
		msg(EXTN, "Unable to append to this archive");
	if ((rv = g_read(Device, Archive, Buffr.b_in_p, Bufsize)) < 0)
		msg(EXTN, "Cannot append to this archive");
	if (lseek(Archive, (off_t)-rv, SEEK_REL) < 0)
		msg(EXTN, "Unable to append to this archive");
	Buffr.b_cnt = off2;
	Buffr.b_in_p = Buffr.b_base_p + Buffr.b_cnt;
	Append = 0;
}

/*
 * setup:  Perform setup and initialization functions.  Parse the options
 * using getopt(3C), call ckopts to check the options and initialize various
 * structures and pointers.  Specifically, for the -i option, save any
 * patterns, for the -o option, check (via stat(2)) the archive, and for
 * the -p option, validate the destination directory.
 */

static void
setup(int largc, char **largv)
{
	extern int optind;
	extern char *optarg;

#if defined(O_XATTR)
#if defined(_PC_SATTR_ENABLED)
#ifdef WAITAROUND
	char	*opts_p = "zabcdfiklmopqrstuvABC:DE:H:I:LM:O:PR:SV6@/";
#else
	char	*opts_p = "abcdfiklmopqrstuvABC:DE:H:I:LM:O:PR:SV6@/";
#endif	/* WAITAROUND */

#else	/* _PC_SATTR_ENABLED */
#ifdef WAITAROUND
	char	*opts_p = "zabcdfiklmopqrstuvABC:DE:H:I:LM:O:PR:SV6@";
#else
	char	*opts_p = "abcdfiklmopqrstuvABC:DE:H:I:LM:O:PR:SV6@";
#endif	/* WAITAROUND */
#endif	/* _PC_SATTR_ENABLED */

#else	/* O_XATTR */
#ifdef WAITAROUND
	char	*opts_p = "zabcdfiklmopqrstuvABC:DE:H:I:LM:O:PR:SV6";
#else
	char	*opts_p = "abcdfiklmopqrstuvABC:DE:H:I:LM:O:PR:SV6";
#endif	/* WAITAROUND */
#endif	/* O_XATTR */

	char   *dupl_p = "Only one occurrence of -%c allowed";
	int option;
	int blk_cnt, blk_cnt_max;
	struct rlimit rlim;

	/* Remember the native page size. */

	PageSize = sysconf(_SC_PAGESIZE);

	if (PageSize == -1) {
		/*
		 * This sysconf call will almost certainly never fail.  The
		 * symbol PAGESIZE itself resolves to the above sysconf call,
		 * so we should go ahead and define our own constant.
		 */
		PageSize = 8192;
	}

	Hdr_type = BIN;
	Max_offset = (off_t)(BIN_OFFSET_MAX);
	Efil_p = Hdr_p = Own_p = IOfil_p = NULL;
	while ((option = getopt(largc, largv, opts_p)) != EOF) {
		switch (option) {
#ifdef WAITAROUND
		case 'z':
			/* rendezvous with the debugger */
			waitaround = 1;
			break;
#endif
		case 'a':	/* reset access time */
			Args |= OCa;
			break;
		case 'b':	/* swap bytes and halfwords */
			Args |= OCb;
			break;
		case 'c':	/* select character header */
			Args |= OCc;
			Hdr_type = ASC;
			Max_namesz = APATH;
			Onecopy = 1;
			break;
		case 'd':	/* create directories as needed */
			Args |= OCd;
			break;
		case 'f':	/* select files not in patterns */
			Args |= OCf;
			break;
		case 'i':	/* "copy in" */
			Args |= OCi;
			Archive = 0;
			break;
		case 'k':	/* retry after I/O errors */
			Args |= OCk;
			break;
		case 'l':	/* link files when possible */
			Args |= OCl;
			break;
		case 'm':	/* retain modification time */
			Args |= OCm;
			break;
		case 'o':	/* "copy out" */
			Args |= OCo;
			Archive = 1;
			break;
		case 'p':	/* "pass" */
			Max_namesz = APATH;
			Args |= OCp;
			break;
		case 'q':	/* "quiet" */
			Args |= OCq;
			break;
		case 'r':	/* rename files interactively */
			Args |= OCr;
			break;
		case 's':	/* swap bytes */
			Args |= OCs;
			break;
		case 't':	/* table of contents */
			Args |= OCt;
			break;
		case 'u':	/* copy unconditionally */
			Args |= OCu;
			break;
		case 'v':	/* verbose - print file names */
			Args |= OCv;
			break;
		case 'A':	/* append to existing archive */
			Args |= OCA;
			break;
		case 'B':	/* set block size to 5120 bytes */
			Args |= OCB;
			Bufsize = 5120;
			break;
		case 'C':	/* set arbitrary block size */
			if (Args & OCC)
				msg(ERR, dupl_p, 'C');
			else {
				Args |= OCC;
				Bufsize = atoi(optarg);
			}
			break;
		case 'D':
			Dflag = 1;
			break;
		case 'E':	/* alternate file for pattern input */
			if (Args & OCE)
				msg(ERR, dupl_p, 'E');
			else {
				Args |= OCE;
				Efil_p = optarg;
			}
			break;
		case 'H':	/* select header type */
			if (Args & OCH)
				msg(ERR, dupl_p, 'H');
			else {
				Args |= OCH;
				Hdr_p = optarg;
			}
			break;
		case 'I':	/* alternate file for archive input */
			if (Args & OCI)
				msg(ERR, dupl_p, 'I');
			else {
				Args |= OCI;
				IOfil_p = optarg;
			}
			break;
		case 'L':	/* follow symbolic links */
			Args |= OCL;
			break;
		case 'M':	/* specify new end-of-media message */
			if (Args & OCM)
				msg(ERR, dupl_p, 'M');
			else {
				Args |= OCM;
				Eom_p = optarg;
			}
			break;
		case 'O':	/* alternate file for archive output */
			if (Args & OCO)
				msg(ERR, dupl_p, 'O');
			else {
				Args |= OCO;
				IOfil_p = optarg;
			}
			break;
		case 'P':	/* preserve acls */
			Args |= OCP;
			Pflag++;
			break;
		case 'R':	/* change owner/group of files */
			if (Args & OCR)
				msg(ERR, dupl_p, 'R');
			else {
				Args |= OCR;
				Own_p = optarg;
			}
			break;
		case 'S':	/* swap halfwords */
			Args |= OCS;
			break;
		case 'V':	/* print a dot '.' for each file */
			Args |= OCV;
			break;
		case '6':	/* for old, sixth-edition files */
			Args |= OC6;
			Ftype = SIXTH;
			break;
#if defined(O_XATTR)
		case '@':
			Atflag++;
			break;
#if defined(_PC_SATTR_ENABLED)
		case '/':
			SysAtflag++;
			break;
#endif	/* _PC_SATTR_ENABLED */
#endif	/* O_XATTR */
		default:
			Error_cnt++;
		} /* option */
	} /* (option = getopt(largc, largv, opts_p)) != EOF */

#ifdef WAITAROUND
	if (waitaround) {
		(void) fprintf(stderr, gettext("Rendezvous with cpio on pid"
		    " %d\n"), getpid());

		while (waitaround) {
			(void) sleep(10);
		}
	}
#endif

	largc -= optind;
	largv += optind;
	ckopts(Args);
	if (!Error_cnt) {
		if (Args & OCr) {
			Renam_p = e_zalloc(E_EXIT, APATH + 1);
			Renametmp_p = e_zalloc(E_EXIT, APATH + 1);
#if defined(_PC_SATTR_ENABLED)
			Renam_attr_p = e_zalloc(E_EXIT, APATH + 1);
#endif
		}
		Symlnk_p = e_zalloc(E_EXIT, APATH);
		Over_p = e_zalloc(E_EXIT, APATH);
		Nam_p = e_zalloc(E_EXIT, APATH + 1);
		if (Args & OCp) {
			Savenam_p = e_zalloc(E_EXIT, APATH + 1);
		}
		Fullnam_p = e_zalloc(E_EXIT, APATH);
		Lnknam_p = e_zalloc(E_EXIT, APATH);
		Gen.g_nam_p = Nam_p;
		if ((Fullnam_p = getcwd(NULL, APATH)) == NULL)
			msg(EXT, "Unable to determine current directory.");
		if (Args & OCi) {
			if (largc > 0) /* save patterns for -i option, if any */
				Pat_pp = largv;
			if (Args & OCE)
				getpats(largc, largv);
		} else if (Args & OCo) {
			if (largc != 0) /* error if arguments left with -o */
				Error_cnt++;
			else if (fstat(Archive, &ArchSt) < 0)
				msg(ERRN, "Error during stat() of archive");
			switch (Hdr_type) {
			case BIN:
				Hdrsz = HDRSZ;
				Pad_val = HALFWD;
				break;
			case CHR:
				Hdrsz = CHRSZ;
				Pad_val = 0;
				Max_offset = (off_t)(CHAR_OFFSET_MAX);
				break;
			case ASC:
			case CRC:
				Hdrsz = ASCSZ;
				Pad_val = FULLWD;
				Max_offset = (off_t)(ASC_OFFSET_MAX);
				break;
			case TAR:
			/* FALLTHROUGH */
			case USTAR: /* TAR and USTAR */
				Hdrsz = TARSZ;
				Pad_val = FULLBK;
				Max_offset = (off_t)(CHAR_OFFSET_MAX);
				break;
			default:
				msg(EXT, "Impossible header type.");
			}
		} else { /* directory must be specified */
			if (largc != 1)
				Error_cnt++;
			else if (access(*largv, 2) < 0 && (errno != EACCES))
				/*
				 * EACCES is ignored here as it may occur
				 * when any directory component of the path
				 * does not have write permission, even though
				 * the destination subdirectory has write
				 * access. Writing to a read only directory
				 * is handled later, as in "copy in" mode.
				 */
				msg(ERRN,
				    "Error during access() of \"%s\"", *largv);
		}
	}
	if (Error_cnt)
		usage(); /* exits! */
	if (Args & (OCi | OCo)) {
		if (!Dflag) {
			if (Args & (OCB | OCC)) {
				if (g_init(&Device, &Archive) < 0)
					msg(EXTN,
					    "Error during initialization");
			} else {
				if ((Bufsize = g_init(&Device, &Archive)) < 0)
					msg(EXTN,
					    "Error during initialization");
			}
		}

		blk_cnt_max = _20K / Bufsize;
		if (blk_cnt_max < MX_BUFS) {
			blk_cnt_max = MX_BUFS;
		}

		Buffr.b_base_p = NULL;

		for (blk_cnt = blk_cnt_max; blk_cnt > 1; blk_cnt--) {
			Buffr.b_size = (size_t)(Bufsize * blk_cnt);
			Buffr.b_base_p = e_valloc(E_NORMAL, Buffr.b_size);
			if (Buffr.b_base_p != NULL) {
				break;
			}
		}
		if (Buffr.b_base_p == NULL || Buffr.b_size < (2 * CPIOBSZ)) {
			msg(EXT, "Out of memory");
		}

		Buffr.b_out_p = Buffr.b_in_p = Buffr.b_base_p;
		Buffr.b_cnt = 0L;
		Buffr.b_end_p = Buffr.b_base_p + Buffr.b_size;
	}

	/*
	 * Now that Bufsize has stabilized, we can allocate our i/o buffer
	 */
	Buf_p = e_valloc(E_EXIT, Bufsize);

	if (Args & OCp) { /* get destination directory */
		(void) strcpy(Fullnam_p, *largv);
		if (stat(Fullnam_p, &DesSt) < 0)
			msg(EXTN, "Error during stat() of \"%s\"", Fullnam_p);
		if ((DesSt.st_mode & Ftype) != S_IFDIR)
			msg(EXT, "\"%s\" is not a directory", Fullnam_p);
	}
	Full_p = Fullnam_p + strlen(Fullnam_p) - 1;
	if (*Full_p != '/') {
		Full_p++;
		*Full_p = '/';
	}
	Full_p++;
	*Full_p = '\0';
	(void) strcpy(Lnknam_p, Fullnam_p);
	Lnkend_p = Lnknam_p + strlen(Lnknam_p);
	(void) getrlimit(RLIMIT_FSIZE, &rlim);
	Max_filesz = (off_t)rlim.rlim_cur;
	Lnk_hd.L_nxt_p = Lnk_hd.L_bck_p = &Lnk_hd;
	Lnk_hd.L_lnk_p = NULL;
}

/*
 * set_tym: Set the access and/or modification times for a file.
 */

static void
set_tym(int dirfd, char *nam_p, time_t atime, time_t mtime)
{
	struct timeval times[2];

	times[0].tv_sec = atime;
	times[0].tv_usec = 0;
	times[1].tv_sec = mtime;
	times[1].tv_usec = 0;

	if (futimesat(dirfd, nam_p, times) < 0) {
		if (Args & OCa) {
			msg(ERRN,
			    "Unable to reset access time for \"%s%s%s\"",
			    (G_p->g_attrnam_p == NULL) ? nam_p : Fullnam_p,
			    (G_p->g_attrnam_p == NULL) ? "" :
			    G_p->g_rw_sysattr ? gettext(" System Attribute ") :
			    gettext(" Attribute "),
			    (G_p->g_attrnam_p == NULL) ? "" : nam_p);
		} else {
			msg(ERRN,
			    "Unable to reset modification time for \"%s%s%s\"",
			    (G_p->g_attrnam_p == NULL) ? nam_p : Fullnam_p,
			    (G_p->g_attrnam_p == NULL) ? "" :
			    G_p->g_rw_sysattr ? gettext(" System Attribute ") :
			    gettext(" Attribute "),
			    (G_p->g_attrnam_p == NULL) ? "" : nam_p);
		}
	}
}

/*
 * sigint:  Catch interrupts.  If an interrupt occurs during the extraction
 * of a file from the archive with the -u option set, and the filename did
 * exist, remove the current file and restore the original file.  Then exit.
 */

/*ARGSUSED*/
static void
sigint(int sig)
{
	char *nam_p;

	(void) signal(SIGINT, SIG_IGN); /* block further signals */
	if (!Finished) {
		if (Args & OCi)
			nam_p = G_p->g_nam_p;
		else /* OCp */
			nam_p = Fullnam_p;
		if (*Over_p != '\0') { /* There is a temp file */
			if (unlink(nam_p) < 0) {
				msg(ERRN,
				    "Cannot remove incomplete \"%s\"", nam_p);
			}
			if (rename(Over_p, nam_p) < 0) {
				if (link(Over_p, nam_p) < 0) {
					msg(ERRN,
					    "Cannot recover original \"%s\"",
					    nam_p);
				}
				if (unlink(Over_p)) {
					msg(ERRN,
					    "Cannot remove temp file \"%s\"",
					    Over_p);
				}
			}
		} else if (unlink(nam_p))
			msg(ERRN, "Cannot remove incomplete \"%s\"", nam_p);
		*Over_p = '\0';
	}
	exit(EXIT_CODE);
}

/*
 * swap: Swap bytes (-s), halfwords (-S) or or both halfwords and bytes (-b).
 */

static void
swap(char *buf_p, int cnt)
{
	unsigned char tbyte;
	int tcnt;
	int rcnt;
	ushort_t thalf;

	rcnt = cnt % 4;
	cnt /= 4;
	if (Args & (OCb | OCs | BSM)) {
		tcnt = cnt;
		/* LINTED alignment */
		Swp_p = (union swpbuf *)buf_p;
		while (tcnt-- > 0) {
			tbyte = Swp_p->s_byte[0];
			Swp_p->s_byte[0] = Swp_p->s_byte[1];
			Swp_p->s_byte[1] = tbyte;
			tbyte = Swp_p->s_byte[2];
			Swp_p->s_byte[2] = Swp_p->s_byte[3];
			Swp_p->s_byte[3] = tbyte;
			Swp_p++;
		}
		if (rcnt >= 2) {
		tbyte = Swp_p->s_byte[0];
		Swp_p->s_byte[0] = Swp_p->s_byte[1];
		Swp_p->s_byte[1] = tbyte;
		tbyte = Swp_p->s_byte[2];
		}
	}
	if (Args & (OCb | OCS)) {
		tcnt = cnt;
		/* LINTED alignment */
		Swp_p = (union swpbuf *)buf_p;
		while (tcnt-- > 0) {
			thalf = Swp_p->s_half[0];
			Swp_p->s_half[0] = Swp_p->s_half[1];
			Swp_p->s_half[1] = thalf;
			Swp_p++;
		}
	}
}

/*
 * usage: Print the usage message on stderr and exit.
 */

static void
usage(void)
{

	(void) fflush(stdout);
#if defined(O_XATTR)
	(void) fprintf(stderr, gettext("USAGE:\n"
	    "\tcpio -i[bcdfkmqrstuv@BSV6] [-C size] "
	    "[-E file] [-H hdr] [-I file [-M msg]] "
	    "[-R id] [patterns]\n"
	    "\tcpio -o[acv@ABLV] [-C size] "
	    "[-H hdr] [-O file [-M msg]]\n"
	    "\tcpio -p[adlmuv@LV] [-R id] directory\n"));
#else
	(void) fprintf(stderr, gettext("USAGE:\n"
	    "\tcpio -i[bcdfkmqrstuvBSV6] [-C size] "
	    "[-E file] [-H hdr] [-I file [-M msg]] "
	    "[-R id] [patterns]\n"
	    "\tcpio -o[acvABLV] [-C size] "
	    "[-H hdr] [-O file [-M msg]]\n"
	    "\tcpio -p[adlmuvLV] [-R id] directory\n"));
#endif
	(void) fflush(stderr);
	exit(EXIT_CODE);
}

/*
 * verbose: For each file, print either the filename (-v) or a dot (-V).
 * If the -t option (table of contents) is set, print either the filename,
 * or if the -v option is also set, print an "ls -l"-like listing.
 */

static void
verbose(char *nam_p)
{
	int i, j, temp;
	mode_t mode;
	char modestr[12];
	time_t	ttime;

	/*
	 * The printf format and associated arguments to print the current
	 * filename.  Normally, just nam_p.  If we're processing an extended
	 * attribute, these are overridden.
	 */
	char *name_fmt = "%s";
	const char *name = nam_p;
	const char *attribute = NULL;

	if (Gen.g_attrnam_p != NULL) {
		/*
		 * Translation note:
		 * 'attribute' is a noun.
		 */

		if (Gen.g_rw_sysattr) {
			name_fmt = gettext("%s system attribute %s");
		} else if ((Args & OCt) &&
		    (is_sysattr(basename(Gen.g_attrnam_p)))) {
			name_fmt = gettext("%s system attribute %s");
		} else {
			name_fmt = gettext("%s attribute %s");
		}

		name = (Args & OCp) ? nam_p : Gen.g_attrfnam_p;
		if (Gen.g_attrparent_p == NULL) {
			attribute = Gen.g_attrnam_p;
		} else {
			attribute = Gen.g_attrpath_p;
		}
	}

	if ((Gen.g_mode == SECMODE) || ((Hdr_type == USTAR ||
	    Hdr_type == TAR) && Thdr_p->tbuf.t_typeflag == 'A')) {
		/* dont print ancillary file */
		aclchar = '+';
		return;
	}
	for (i = 0; i < 11; i++)
		modestr[i] = '-';
	modestr[i] = '\0';
	modestr[i-1] = aclchar;
	aclchar = ' ';

	if ((Args & OCt) && (Args & OCv)) {
		mode = Gen.g_mode;
		for (i = 0; i < 3; i++) {
			temp = (mode >> (6 - (i * 3)));
			j = (i * 3) + 1;
			if (S_IROTH & temp)
				modestr[j] = 'r';
			if (S_IWOTH & temp)
				modestr[j + 1] = 'w';
			if (S_IXOTH & temp)
				modestr[j + 2] = 'x';
		}

		if (Hdr_type != BAR) {
			temp = Gen.g_mode & Ftype;
			switch (temp) {
			case (S_IFIFO):
				modestr[0] = 'p';
				break;
			case (S_IFSOCK):
				modestr[0] = 's';
				break;
			case (S_IFCHR):
				modestr[0] = 'c';
				break;
			case (S_IFDIR):
				modestr[0] = 'd';
				break;
			case (S_IFBLK):
				modestr[0] = 'b';
				break;
			case (S_IFREG): /* was initialized to '-' */
				break;
			case (S_IFLNK):
				modestr[0] = 'l';
				break;
			default:
				msg(ERR, "Impossible file type");
			}
		} else {		/* bar */
			temp = Gen.g_mode & Ftype;
			switch (temp) {
			case (S_IFIFO):
				modestr[0] = 'p';
				break;
			case (S_IFSOCK):
				modestr[0] = 's';
				break;
			case (S_IFCHR):
				modestr[0] = 'c';
				break;
			case (S_IFDIR):
				modestr[0] = 'd';
				break;
			case (S_IFBLK):
				modestr[0] = 'b';
				break;
			}
			if (bar_linkflag == SYMTYPE)
				modestr[0] = 'l';
		}
		if ((S_ISUID & Gen.g_mode) == S_ISUID)
			modestr[3] = 's';
		if ((S_ISVTX & Gen.g_mode) == S_ISVTX)
			modestr[9] = 't';
		if ((S_ISGID & G_p->g_mode) == S_ISGID && modestr[6] == 'x')
			modestr[6] = 's';
		else if ((S_ENFMT & Gen.g_mode) == S_ENFMT && modestr[6] != 'x')
			modestr[6] = 'l';
		if ((Hdr_type == TAR || Hdr_type == USTAR) && Gen.g_nlink == 0)
			(void) printf("%s%4d ", modestr, (int)Gen.g_nlink+1);
		else
			(void) printf("%s%4d ", modestr, (int)Gen.g_nlink);
		if (Lastuid == (uid_t)Gen.g_uid) {
			if (Lastuid == (uid_t)-1)
				(void) printf("-1       ");
			else
				(void) printf("%-9s", Curpw_p->pw_name);
		} else {
			if (Curpw_p = getpwuid((int)Gen.g_uid)) {
				(void) printf("%-9s", Curpw_p->pw_name);
				Lastuid = (uid_t)Gen.g_uid;
			} else {
				(void) printf("%-9d", (int)Gen.g_uid);
				Lastuid = (uid_t)-1;
			}
		}
		if (Lastgid == (gid_t)Gen.g_gid) {
			if (Lastgid == (gid_t)-1)
				(void) printf("-1       ");
			else
				(void) printf("%-9s", Curgr_p->gr_name);
		} else {
			if (Curgr_p = getgrgid((int)Gen.g_gid)) {
				(void) printf("%-9s", Curgr_p->gr_name);
				Lastgid = (gid_t)Gen.g_gid;
			} else {
				(void) printf("%-9d", (int)Gen.g_gid);
				Lastgid = (gid_t)-1;
			}
		}

		/* print file size */
		if (!Aspec || ((Gen.g_mode & Ftype) == S_IFIFO) ||
		    ((Gen.g_mode & Ftype) == S_IFSOCK) ||
		    (Hdr_type == BAR && bar_linkflag == SYMTYPE)) {
			off_t filesz = Gen.g_filesz;

			if (S_ISSPARSE(Gen.g_mode) && Gen.g_holes != NULL)
				filesz = Gen.g_holes->orig_size;

			if (filesz < (1LL << 31))
				(void) printf("%7lld ", (offset_t)filesz);
			else
				(void) printf("%11lld ", (offset_t)filesz);
		} else
			(void) printf("%3d,%3d ", (int)major(Gen.g_rdev),
			    (int)minor(Gen.g_rdev));
		ttime = Gen.g_mtime;
		(void) strftime(Time, sizeof (Time),
		    dcgettext(NULL, FORMAT, LC_TIME), localtime(&ttime));
		(void) printf("%s, ", Time);
		str_fprintf(stdout, name_fmt, name, attribute);
		if ((Gen.g_mode & Ftype) == S_IFLNK) {
			if (Hdr_type == USTAR || Hdr_type == TAR)
				(void) strcpy(Symlnk_p,
				    Thdr_p->tbuf.t_linkname);
			else {
				FILL(Gen.g_filesz);
				(void) strncpy(Symlnk_p, Buffr.b_out_p,
				    Gen.g_filesz);
				*(Symlnk_p + Gen.g_filesz) = '\0';
			}
			(void) printf(" -> %s", Symlnk_p);
		}
		if (Hdr_type == BAR) {
			if (bar_linkflag == SYMTYPE)
				(void) printf(gettext(" symbolic link to %s"),
				    bar_linkname);
			else if (bar_linkflag == '1')
				(void) printf(gettext(" linked to %s"),
				    bar_linkname);
		}
		if ((Hdr_type == USTAR || Hdr_type == TAR) &&
		    Thdr_p->tbuf.t_typeflag == '1') {
			(void) printf(gettext(" linked to %s%s%s"),
			    (Gen.g_attrnam_p == NULL) ?
			    Thdr_p->tbuf.t_linkname : Gen.g_attrfnam_p,
			    (Gen.g_attrnam_p == NULL) ? "" :
			    gettext(" attribute "),
			    (Gen.g_attrnam_p == NULL) ?
			    "" : Gen.g_linktoattrnam_p);
		}
		(void) printf("\n");
	} else if ((Args & OCt) || (Args & OCv)) {
		str_fprintf(Out_p, name_fmt, name, attribute);
		(void) fputc('\n', Out_p);
	} else { /* OCV */
		(void) fputc('.', Out_p);
		if (Verbcnt++ >= 49) { /* start a new line of dots */
			Verbcnt = 0;
			(void) fputc('\n', Out_p);
		}
	}
	(void) fflush(Out_p);
}

#define	MK_USHORT(a)	(a & 00000177777)

/*
 * write_hdr: Transfer header information for the generic structure
 * into the format for the selected header and bwrite() the header.
 */

static void
write_hdr(int arcflag, off_t len)
{
	int cnt, pad;
	mode_t mode;
	uid_t uid;
	gid_t gid;
	const char warnfmt[] = "%s%s%s : %s";

	switch (arcflag) {
	case ARCHIVE_ACL:
		mode = SECMODE;
		break;

	case ARCHIVE_XATTR:
	case ARCHIVE_NORMAL:
		/*
		 * If attribute is being archived in cpio format then
		 * zap off the file type bits since those are truly a
		 * mask and reset them with _XATTR_CPIO_MODE
		 */
		/*
		 * len is the value of g_filesz for normal files
		 * and the length of the special header buffer in
		 * the case of acl and xattr headers.
		 */
		if (G_p->g_attrnam_p != NULL && Hdr_type != USTAR &&
		    Hdr_type != TAR) {
			mode = (G_p->g_mode & POSIXMODES) | _XATTR_CPIO_MODE;
		} else {
			mode = G_p->g_mode;
		}
		if (arcflag != ARCHIVE_XATTR) {
			len = G_p->g_filesz;
		}
		break;

	case ARCHIVE_SPARSE:
		mode = G_p->g_mode | C_ISSPARSE;
		len = G_p->g_filesz;
		break;
	}

	uid = G_p->g_uid;
	gid = G_p->g_gid;
	/*
	 * Handle EFT uids and gids.  If they get too big
	 * to be represented in a particular format, force 'em to 'nobody'.
	 */
	switch (Hdr_type) {
	case BIN:			/* 16-bits of u_short */
		if ((ulong_t)uid > (ulong_t)USHRT_MAX)
			uid = UID_NOBODY;
		if ((ulong_t)gid > (ulong_t)USHRT_MAX)
			gid = GID_NOBODY;
		break;
	case CHR:			/* %.6lo => 262143 base 10 */
		if ((ulong_t)uid > (ulong_t)0777777)
			uid = UID_NOBODY;
		if ((ulong_t)gid > (ulong_t)0777777)
			gid = GID_NOBODY;
		break;
	case ASC:			/* %.8lx => full 32 bits */
	case CRC:
		break;
	case USTAR:
	case TAR:			/* %.7lo => 2097151 base 10 */
		if ((ulong_t)uid > (ulong_t)07777777)
			uid = UID_NOBODY;
		if ((ulong_t)gid > (ulong_t)07777777)
			gid = GID_NOBODY;
		break;
	default:
		msg(EXT, "Impossible header type.");
	}

	/*
	 * Since cpio formats -don't- encode the symbolic names, print
	 * a warning message when we map the uid or gid this way.
	 * Also, if the ownership just changed, clear set[ug]id bits
	 *
	 * (Except for USTAR format of course, where we have a string
	 * representation of the username embedded in the header)
	 */
	if (uid != G_p->g_uid && Hdr_type != USTAR) {
		msg(ERR, warnfmt,
		    (G_p->g_attrnam_p == NULL) ?
		    G_p->g_nam_p : G_p->g_attrfnam_p,
		    (G_p->g_attrnam_p == NULL) ? "" : G_p->g_rw_sysattr ?
		    gettext(" System Attribute ") : gettext(" Attribute "),
		    (G_p->g_attrnam_p == NULL) ? "" : G_p->g_attrnam_p,
		    gettext("uid too large for archive format"));
		if (S_ISREG(mode))
			mode &= ~S_ISUID;
	}
	if (gid != G_p->g_gid && Hdr_type != USTAR) {
		msg(ERR, warnfmt,
		    (G_p->g_attrnam_p == NULL) ?
		    G_p->g_nam_p : G_p->g_attrfnam_p,
		    (G_p->g_attrnam_p == NULL) ? "" : G_p->g_rw_sysattr ?
		    gettext(" System Attribute ") : gettext(" Attribute "),
		    (G_p->g_attrnam_p == NULL) ? "" : G_p->g_attrnam_p,
		    gettext("gid too large for archive format"));
		if (S_ISREG(mode))
			mode &= ~S_ISGID;
	}

	switch (Hdr_type) {
	case BIN:
	case CHR:
	case ASC:
	case CRC:
		cnt = Hdrsz + G_p->g_namesz;
		break;
	case TAR:
		/*FALLTHROUGH*/
	case USTAR: /* TAR and USTAR */
		cnt = TARSZ;
		break;
	default:
		msg(EXT, "Impossible header type.");
	}
	FLUSH(cnt);

	switch (Hdr_type) {
	case BIN:
		Hdr.h_magic = (short)G_p->g_magic;
		Hdr.h_dev = G_p->g_dev;
		Hdr.h_ino = G_p->g_ino;
		Hdr.h_uid = uid;
		Hdr.h_gid = gid;
		Hdr.h_mode = mode;
		Hdr.h_nlink = G_p->g_nlink;
		Hdr.h_rdev = G_p->g_rdev;
		mkshort(Hdr.h_mtime, (long)G_p->g_mtime);
		Hdr.h_namesize = (short)G_p->g_namesz;
		mkshort(Hdr.h_filesize, (long)len);
		(void) strcpy(Hdr.h_name, G_p->g_nam_p);
		(void) memcpy(Buffr.b_in_p, &Hdr, cnt);
		break;
	case CHR:
		/*LINTED*/
		(void) sprintf(Buffr.b_in_p,
		    "%.6lo%.6lo%.6lo%.6lo%.6lo%.6lo%.6lo%.6lo%.11lo%.6lo%."
		    "11llo%s", G_p->g_magic, G_p->g_dev, G_p->g_ino, mode,
		    (long)uid, (long)gid, G_p->g_nlink, MK_USHORT(G_p->g_rdev),
		    G_p->g_mtime, (long)G_p->g_namesz, (offset_t)len,
		    G_p->g_nam_p);
		break;
	case ASC:
	case CRC:
		/*LINTED*/
		(void) sprintf(Buffr.b_in_p,
		    "%.6lx%.8lx%.8lx%.8lx%.8lx%.8lx%.8lx%.8lx%.8lx%.8lx%."
		    "8lx%.8lx%.8lx%.8lx%s",
		    G_p->g_magic, G_p->g_ino, mode, G_p->g_uid,
		    G_p->g_gid, G_p->g_nlink, G_p->g_mtime, (ulong_t)len,
		    major(G_p->g_dev), minor(G_p->g_dev),
		    major(G_p->g_rdev), minor(G_p->g_rdev),
		    G_p->g_namesz, G_p->g_cksum, G_p->g_nam_p);
		break;
	case USTAR:
		Thdr_p = (union tblock *)Buffr.b_in_p;
		(void) memset(Thdr_p, 0, TARSZ);
		(void) strncpy(Thdr_p->tbuf.t_name, G_p->g_tname,
		    (int)strlen(G_p->g_tname));
		(void) sprintf(Thdr_p->tbuf.t_mode, "%07o", (int)mode);
		(void) sprintf(Thdr_p->tbuf.t_uid, "%07o", (int)uid);
		(void) sprintf(Thdr_p->tbuf.t_gid, "%07o", (int)gid);
		(void) sprintf(Thdr_p->tbuf.t_size, "%011llo",
		    (offset_t)len);
		(void) sprintf(Thdr_p->tbuf.t_mtime, "%011lo", G_p->g_mtime);
		if (arcflag == ARCHIVE_ACL) {
			Thdr_p->tbuf.t_typeflag = 'A';	/* ACL file type */
		} else if (arcflag == ARCHIVE_XATTR ||
		    (G_p->g_attrnam_p != NULL)) {
			Thdr_p->tbuf.t_typeflag = _XATTR_HDRTYPE;
		} else {
			Thdr_p->tbuf.t_typeflag = G_p->g_typeflag;
		}
		if (T_lname[0] != '\0') {
			/*
			 * if not a symbolic link
			 */
			if (((G_p->g_mode & Ftype) != S_IFLNK) &&
			    (G_p->g_attrnam_p == NULL)) {
				Thdr_p->tbuf.t_typeflag = LNKTYPE;
				(void) sprintf(Thdr_p->tbuf.t_size,
				    "%011lo", 0L);
			}
			(void) strncpy(Thdr_p->tbuf.t_linkname, T_lname,
			    strlen(T_lname));
		}
		(void) strcpy(Thdr_p->tbuf.t_magic, TMAGIC);
		(void) strcpy(Thdr_p->tbuf.t_version, TVERSION);
		(void) strcpy(Thdr_p->tbuf.t_uname, G_p->g_uname);
		(void) strcpy(Thdr_p->tbuf.t_gname, G_p->g_gname);
		(void) sprintf(Thdr_p->tbuf.t_devmajor, "%07o",
		    (int)major(G_p->g_rdev));
		(void) sprintf(Thdr_p->tbuf.t_devminor, "%07o",
		    (int)minor(G_p->g_rdev));
		if (Gen.g_prefix) {
			(void) strcpy(Thdr_p->tbuf.t_prefix, Gen.g_prefix);
			free(Gen.g_prefix);
			Gen.g_prefix = NULL;
		} else {
			Thdr_p->tbuf.t_prefix[0] = '\0';
		}
		(void) sprintf(Thdr_p->tbuf.t_cksum, "%07o",
		    (int)cksum(TARTYP, 0, NULL));
		break;
	case TAR:
		Thdr_p = (union tblock *)Buffr.b_in_p;
		(void) memset(Thdr_p, 0, TARSZ);
		(void) strncpy(Thdr_p->tbuf.t_name, G_p->g_nam_p,
		    G_p->g_namesz);
		(void) sprintf(Thdr_p->tbuf.t_mode, "%07o ", (int)mode);
		(void) sprintf(Thdr_p->tbuf.t_uid, "%07o ", (int)uid);
		(void) sprintf(Thdr_p->tbuf.t_gid, "%07o ", (int)gid);
		(void) sprintf(Thdr_p->tbuf.t_size, "%011llo ",
		    (offset_t)len);
		(void) sprintf(Thdr_p->tbuf.t_mtime, "%011o ",
		    (int)G_p->g_mtime);
		if (T_lname[0] != '\0') {
			Thdr_p->tbuf.t_typeflag = '1';
		} else {
			Thdr_p->tbuf.t_typeflag = '\0';
		}
		(void) strncpy(Thdr_p->tbuf.t_linkname, T_lname,
		    strlen(T_lname));
		break;
	default:
		msg(EXT, "Impossible header type.");
	} /* Hdr_type */

	Buffr.b_in_p += cnt;
	Buffr.b_cnt += cnt;
	pad = ((cnt + Pad_val) & ~Pad_val) - cnt;
	if (pad != 0) {
		FLUSH(pad);
		(void) memset(Buffr.b_in_p, 0, pad);
		Buffr.b_in_p += pad;
		Buffr.b_cnt += pad;
	}
}

/*
 * write_trail: Create the appropriate trailer for the selected header type
 * and bwrite the trailer.  Pad the buffer with nulls out to the next Bufsize
 * boundary, and force a write.  If the write completes, or if the trailer is
 * completely written (but not all of the padding nulls (as can happen on end
 * of medium)) return.  Otherwise, the trailer was not completely written out,
 * so re-pad the buffer with nulls and try again.
 */

static void
write_trail(void)
{
	int cnt, need;

	switch (Hdr_type) {
	case BIN:
		Gen.g_magic = CMN_BIN;
		break;
	case CHR:
		Gen.g_magic = CMN_BIN;
		break;
	case ASC:
		Gen.g_magic = CMN_ASC;
		break;
	case CRC:
		Gen.g_magic = CMN_CRC;
		break;
	}

	switch (Hdr_type) {
	case BIN:
	case CHR:
	case ASC:
	case CRC:
		Gen.g_mode = Gen.g_uid = Gen.g_gid = 0;
		Gen.g_nlink = 1;
		Gen.g_mtime = Gen.g_ino = Gen.g_dev = 0;
		Gen.g_rdev = Gen.g_cksum = 0;
		Gen.g_filesz = (off_t)0;
		Gen.g_namesz = strlen("TRAILER!!!") + 1;
		(void) strcpy(Gen.g_nam_p, "TRAILER!!!");
		G_p = &Gen;
		write_hdr(ARCHIVE_NORMAL, (off_t)0);
		break;
	case TAR:
	/*FALLTHROUGH*/
	case USTAR: /* TAR and USTAR */
		for (cnt = 0; cnt < 3; cnt++) {
			FLUSH(TARSZ);
			(void) memset(Buffr.b_in_p, 0, TARSZ);
			Buffr.b_in_p += TARSZ;
			Buffr.b_cnt += TARSZ;
		}
		break;
	default:
		msg(EXT, "Impossible header type.");
	}
	need = Bufsize - (Buffr.b_cnt % Bufsize);
	if (need == Bufsize)
		need = 0;

	while (Buffr.b_cnt > 0) {
		while (need > 0) {
			cnt = (need < TARSZ) ? need : TARSZ;
			need -= cnt;
			FLUSH(cnt);
			(void) memset(Buffr.b_in_p, 0, cnt);
			Buffr.b_in_p += cnt;
			Buffr.b_cnt += cnt;
		}
		bflush();
	}
}

/*
 * if archives in USTAR format, check if typeflag == '5' for directories
 */
static int
ustar_dir(void)
{
	if (Hdr_type == USTAR || Hdr_type == TAR) {
		if (Thdr_p->tbuf.t_typeflag == '5')
			return (1);
	}
	return (0);
}

/*
 * if archives in USTAR format, check if typeflag == '3' || '4' || '6'
 * for character, block, fifo special files
 */
static int
ustar_spec(void)
{
	int typeflag;

	if (Hdr_type == USTAR || Hdr_type == TAR) {
		typeflag = Thdr_p->tbuf.t_typeflag;
		if (typeflag == '3' || typeflag == '4' || typeflag == '6')
			return (1);
	}
	return (0);
}

/*
 * The return value is a pointer to a converted copy of the information in
 * FromStat if the file is representable in -Hodc format, and NULL otherwise.
 */

static struct stat *
convert_to_old_stat(struct stat *FromStat, char *namep, char *attrp)
{
	static struct stat ToSt;
	cpioinfo_t TmpSt;

	(void) memset(&TmpSt, 0, sizeof (cpioinfo_t));
	stat_to_svr32_stat(&TmpSt, FromStat);
	(void) memset(&ToSt, 0, sizeof (ToSt));

	if (TmpSt.st_rdev == (o_dev_t)NODEV &&
	    (((TmpSt.st_mode & Ftype) == S_IFCHR) ||
	    ((TmpSt.st_mode & Ftype) == S_IFBLK))) {
		/*
		 * Encountered a problem representing the rdev information.
		 * Don't archive it.
		 */

		msg(ERR, "Error -Hodc format can't support expanded"
		    "types on %s%s%s",
		    namep,
		    (attrp == NULL) ? "" : gettext(" Attribute"),
		    (attrp == NULL) ? "" : attrp);
		return (NULL);
	}

	if (TmpSt.st_dev == (o_dev_t)NODEV) {
		/*
		 * Having trouble representing the device/inode pair.  We can't
		 * track links in this case; break them all into separate
		 * files.
		 */

		TmpSt.st_ino = 0;

		if (((TmpSt.st_mode & Ftype) != S_IFDIR) &&
		    TmpSt.st_nlink > 1)
			msg(POST,
			    "Warning: file %s%s%s has large "
			    "device number - linked "
			    "files will be restored as "
			    "separate files",
			    namep,
			    (attrp == NULL) ? "" : gettext(" Attribute"),
			    (attrp == NULL) ? "" : attrp);

		/* ensure no links */

		TmpSt.st_nlink = 1;
	}

	/* Start converting values */

	if (TmpSt.st_dev < 0) {
		ToSt.st_dev = 0;
	} else {
		ToSt.st_dev = (dev_t)TmpSt.st_dev;
	}

	/* -actual- not truncated uid */

	ToSt.st_uid = TmpSt.st_uid;

	/* -actual- not truncated gid */

	ToSt.st_gid = TmpSt.st_gid;
	ToSt.st_ino = (ino_t)TmpSt.st_ino;
	ToSt.st_mode = (mode_t)TmpSt.st_mode;
	ToSt.st_mtime = (ulong_t)TmpSt.st_modtime;
	ToSt.st_nlink = (nlink_t)TmpSt.st_nlink;
	ToSt.st_size = (off_t)TmpSt.st_size;
	ToSt.st_rdev = (dev_t)TmpSt.st_rdev;

	return (&ToSt);
}

/*
 * In the beginning of each bar archive, there is a header which describes the
 * current volume being created, followed by a header which describes the
 * current file being created, followed by the file itself.  If there is
 * more than one file to be created, a separate header will be created for
 * each additional file.  This structure may be repeated if the bar archive
 * contains multiple volumes.  If a file spans across volumes, its header
 * will not be repeated in the next volume.
 *               +------------------+
 *               |    vol header    |
 *               |------------------|
 *               |   file header i  |     i = 0
 *               |------------------|
 *               |     <file i>     |
 *               |------------------|
 *               |  file header i+1 |
 *               |------------------|
 *               |    <file i+1>    |
 *               |------------------|
 *               |        .         |
 *               |        .         |
 *               |        .         |
 *               +------------------+
 */

/*
 * read in the header that describes the current volume of the bar archive
 * to be extracted.
 */
static void
read_bar_vol_hdr(void)
{
	union b_block *tmp_hdr;

	tmp_hdr = (union b_block *)Buffr.b_out_p;
	if (tmp_hdr->dbuf.bar_magic[0] == BAR_VOLUME_MAGIC) {

		if (bar_Vhdr == NULL) {
			bar_Vhdr = e_zalloc(E_EXIT, TBLOCK);
		}
		(void) memcpy(&(bar_Vhdr->dbuf), &(tmp_hdr->dbuf), TBLOCK);
	} else {
		(void) fprintf(stderr, gettext(
		    "bar error: cannot read volume header\n"));
		exit(1);
	}

	(void) sscanf(bar_Vhdr->dbuf.mode, "%8lo", &Gen_bar_vol.g_mode);
	(void) sscanf(bar_Vhdr->dbuf.uid, "%8d", (int *)&Gen_bar_vol.g_uid);
	(void) sscanf(bar_Vhdr->dbuf.gid, "%8d", (int *)&Gen_bar_vol.g_gid);
	(void) sscanf(bar_Vhdr->dbuf.size, "%12llo",
	    (u_off_t *)&Gen_bar_vol.g_filesz);
	(void) sscanf(bar_Vhdr->dbuf.mtime, "%12lo", &Gen_bar_vol.g_mtime);
	(void) sscanf(bar_Vhdr->dbuf.chksum, "%8lo", &Gen_bar_vol.g_cksum);

	/* set the compress flag */
	if (bar_Vhdr->dbuf.compressed == '1')
		Compressed = 1;
	else
		Compressed = 0;

	Buffr.b_out_p += 512;
	Buffr.b_cnt -= 512;

	/*
	 * not the first volume; exit
	 */
	if (strcmp(bar_Vhdr->dbuf.volume_num, "1") != 0) {
		(void) fprintf(stderr,
		    gettext("error: This is not volume 1.  "));
		(void) fprintf(stderr, gettext("This is volume %s.  "),
		    bar_Vhdr->dbuf.volume_num);
		(void) fprintf(stderr, gettext("Please insert volume 1.\n"));
		exit(1);
	}

	read_bar_file_hdr();
}

/*
 * read in the header that describes the current file to be extracted
 */
static void
read_bar_file_hdr(void)
{
	union b_block *tmp_hdr;
	char *start_of_name, *name_p;
	char *tmp;

	if (*Buffr.b_out_p == '\0') {
		*Gen.g_nam_p = '\0';
		exit(0);
	}

	tmp_hdr = (union b_block *)Buffr.b_out_p;

	tmp = &tmp_hdr->dbuf.mode[1];
	(void) sscanf(tmp, "%8lo", &Gen.g_mode);
	(void) sscanf(tmp_hdr->dbuf.uid, "%8lo", &Gen.g_uid);
	(void) sscanf(tmp_hdr->dbuf.gid, "%8lo", &Gen.g_gid);
	(void) sscanf(tmp_hdr->dbuf.size, "%12llo",
	    (u_off_t *)&Gen.g_filesz);
	(void) sscanf(tmp_hdr->dbuf.mtime, "%12lo", &Gen.g_mtime);
	(void) sscanf(tmp_hdr->dbuf.chksum, "%8lo", &Gen.g_cksum);
	(void) sscanf(tmp_hdr->dbuf.rdev, "%8lo", &Gen.g_rdev);

#define	to_new_major(x)	(int)((unsigned)((x) & OMAXMAJ) << NBITSMINOR)
#define	to_new_minor(x)	(int)((x) & OMAXMIN)
	Gen.g_rdev = to_new_major(Gen.g_rdev) | to_new_minor(Gen.g_rdev);
	bar_linkflag = tmp_hdr->dbuf.linkflag;
	start_of_name = &tmp_hdr->dbuf.start_of_name;


	name_p = Gen.g_nam_p;
	while (*name_p++ = *start_of_name++)
		;
	*name_p = '\0';
	if (bar_linkflag == LNKTYPE || bar_linkflag == SYMTYPE)
		(void) strcpy(bar_linkname, start_of_name);

	Gen.g_namesz = strlen(Gen.g_nam_p) + 1;
	(void) strcpy(nambuf, Gen.g_nam_p);
}

/*
 * if the bar archive is compressed, set up a pipe and do the de-compression
 * as the compressed file is read in.
 */
static void
setup_uncompress(FILE **pipef)
{
	char *cmd_buf;
	size_t cmdlen;

	cmd_buf = e_zalloc(E_EXIT, MAXPATHLEN * 2);

	if (access(Gen.g_nam_p, W_OK) != 0) {
		cmdlen = snprintf(cmd_buf, MAXPATHLEN * 2,
		    "chmod +w '%s'; uncompress -c > '%s'; "
		    "chmod 0%o '%s'",
		    Gen.g_nam_p, Gen.g_nam_p, (int)G_p->g_mode, Gen.g_nam_p);
	} else {
		cmdlen = snprintf(cmd_buf, MAXPATHLEN * 2,
		    "uncompress -c > '%s'", Gen.g_nam_p);
	}

	if (cmdlen >= MAXPATHLEN * 2 ||
	    (*pipef = popen(cmd_buf, "w")) == NULL) {
		(void) fprintf(stderr, gettext("error\n"));
		exit(1);
	}

	if (close(Ofile) != 0)
		msg(EXTN, "close error");
	Ofile = fileno(*pipef);

	free(cmd_buf);
}

/*
 * if the bar archive spans multiple volumes, read in the header that
 * describes the next volume.
 */
static void
skip_bar_volhdr(void)
{
	char *buff;
	union b_block *tmp_hdr;

	buff = e_zalloc(E_EXIT, (uint_t)Bufsize);

	if (g_read(Device, Archive, buff, Bufsize) < 0) {
		(void) fprintf(stderr, gettext(
		    "error in skip_bar_volhdr\n"));
	} else {

		tmp_hdr = (union b_block *)buff;
		if (tmp_hdr->dbuf.bar_magic[0] == BAR_VOLUME_MAGIC) {

			if (bar_Vhdr == NULL) {
				bar_Vhdr = e_zalloc(E_EXIT, TBLOCK);
			}
			(void) memcpy(&(bar_Vhdr->dbuf),
			    &(tmp_hdr->dbuf), TBLOCK);
		} else {
			(void) fprintf(stderr,
			    gettext("cpio error: cannot read bar volume "
			    "header\n"));
			exit(1);
		}

		(void) sscanf(bar_Vhdr->dbuf.mode, "%8lo",
		    &Gen_bar_vol.g_mode);
		(void) sscanf(bar_Vhdr->dbuf.uid, "%8lo",
		    &Gen_bar_vol.g_uid);
		(void) sscanf(bar_Vhdr->dbuf.gid, "%8lo",
		    &Gen_bar_vol.g_gid);
		(void) sscanf(bar_Vhdr->dbuf.size, "%12llo",
		    (u_off_t *)&Gen_bar_vol.g_filesz);
		(void) sscanf(bar_Vhdr->dbuf.mtime, "%12lo",
		    &Gen_bar_vol.g_mtime);
		(void) sscanf(bar_Vhdr->dbuf.chksum, "%8lo",
		    &Gen_bar_vol.g_cksum);
		if (bar_Vhdr->dbuf.compressed == '1')
			Compressed = 1;
		else
			Compressed = 0;
	}

	/*
	 * Now put the rest of the bytes read in into the data buffer.
	 */
	(void) memcpy(Buffr.b_in_p, &buff[512], (Bufsize - 512));
	Buffr.b_in_p += (Bufsize - 512);
	Buffr.b_cnt += (long)(Bufsize - 512);

	free(buff);
}

/*
 * check the linkflag which indicates the type of the file to be extracted,
 * invoke the corresponding routine to extract the file.
 */
static void
bar_file_in(void)
{
	/*
	 * the file is a directory
	 */
	if (Adir) {
		if (ckname(1) != F_SKIP && creat_spec(G_p->g_dirfd) > 0) {
			VERBOSE((Args & (OCv | OCV)), G_p->g_nam_p);
		}
		return;
	}

	switch (bar_linkflag) {
	case REGTYPE:
		/* regular file */
		if ((ckname(1) == F_SKIP) ||
		    (Ofile = openout(G_p->g_dirfd)) < 0) {
			data_in(P_SKIP);
		} else {
			data_in(P_PROC);
		}
		break;
	case LNKTYPE:
		/* hard link */
		if (ckname(1) == F_SKIP) {
			break;
		}
		(void) creat_lnk(G_p->g_dirfd, bar_linkname, G_p->g_nam_p);
		break;
	case SYMTYPE:
		/* symbolic link */
		if ((ckname(1) == F_SKIP) ||
		    (Ofile = openout(G_p->g_dirfd)) < 0) {
			data_in(P_SKIP);
		} else {
			data_in(P_PROC);
		}
		break;
	case CHRTYPE:
		/* character device or FIFO */
		if (ckname(1) != F_SKIP && creat_spec(G_p->g_dirfd) > 0) {
			VERBOSE((Args & (OCv | OCV)), G_p->g_nam_p);
		}
		break;
	default:
		(void) fprintf(stderr, gettext("error: unknown file type\n"));
		break;
	}
}


/*
 * This originally came from libgenIO/g_init.c
 * XXX	And it is very broken.
 */

/* #include <sys/statvfs.h> */
#include <ftw.h>
/* #include <libgenIO.h> */
#define	G_TM_TAPE	1	/* Tapemaster controller    */
#define	G_XY_DISK	3	/* xy disks		*/
#define	G_SD_DISK	7	/* scsi sd disk		*/
#define	G_XT_TAPE	8	/* xt tapes		*/
#define	G_SF_FLOPPY	9	/* sf floppy		*/
#define	G_XD_DISK	10	/* xd disks		*/
#define	G_ST_TAPE	11	/* scsi tape		*/
#define	G_NS		12	/* noswap pseudo-dev	*/
#define	G_RAM		13	/* ram pseudo-dev	*/
#define	G_FT		14	/* tftp			*/
#define	G_HD		15	/* 386 network disk	*/
#define	G_FD		16	/* 386 AT disk		*/
#define	G_FILE		28	/* file, not a device	*/
#define	G_NO_DEV	29	/* device does not require special treatment */
#define	G_DEV_MAX	30	/* last valid device type */

/*
 * g_init: Determine the device being accessed, set the buffer size,
 * and perform any device specific initialization. Since at this point
 * Sun has no system call to read the configuration, the major numbers
 * are assumed to be static and types are figured out as such. However,
 * as a rough estimate, the buffer size for all types is set to 512
 * as a default.
 */

static int
g_init(int *devtype, int *fdes)
{
	int bufsize;
	struct stat st_buf;
	struct statvfs stfs_buf;

	*devtype = G_NO_DEV;
	bufsize = -1;
	if (fstat(*fdes, &st_buf) == -1)
		return (-1);
	if (!S_ISCHR(st_buf.st_mode) && !S_ISBLK(st_buf.st_mode)) {
		if (S_ISFIFO(st_buf.st_mode)) {
			bufsize = 512;
		} else {
			/* find block size for this file system */
			*devtype = G_FILE;
			if (fstatvfs(*fdes, &stfs_buf) < 0) {
					bufsize = -1;
					errno = ENODEV;
			} else
				bufsize = stfs_buf.f_bsize;
		}

		return (bufsize);

	/*
	 * We'll have to add a remote attribute to stat but this
	 * should work for now.
	 */
	} else if (st_buf.st_dev & 0x8000)	/* if remote  rdev */
		return (512);

	bufsize = 512;

	if (Hdr_type == BAR) {
		if (is_tape(*fdes)) {
			bufsize = BAR_TAPE_SIZE;
			msg(EPOST, "Archiving to tape blocking factor 126");
		} else if (is_floppy(*fdes)) {
			bufsize = BAR_FLOPPY_SIZE;
			msg(EPOST, "Archiving to floppy blocking factor 18");
		}
	}

	return (bufsize);
}

/*
 * This originally came from libgenIO/g_read.c
 */

/*
 * g_read: Read nbytes of data from fdes (of type devtype) and place
 * data in location pointed to by buf.  In case of end of medium,
 * translate (where necessary) device specific EOM indications into
 * the generic EOM indication of rv = -1, errno = ENOSPC.
 */

static int
g_read(int devtype, int fdes, char *buf, unsigned nbytes)
{
	int rv;

	if (devtype < 0 || devtype >= G_DEV_MAX) {
		errno = ENODEV;
		return (-1);
	}

	rv = read(fdes, buf, nbytes);

	/* st devices return 0 when no space left */
	if ((rv == 0 && errno == 0 && Hdr_type != BAR) ||
	    (rv == -1 && errno == EIO)) {
		errno = 0;
		rv = 0;
	}

	return (rv);
}

/*
 * This originally came from libgenIO/g_write.c
 */

/*
 * g_write: Write nbytes of data to fdes (of type devtype) from
 * the location pointed to by buf.  In case of end of medium,
 * translate (where necessary) device specific EOM indications into
 * the generic EOM indication of rv = -1, errno = ENOSPC.
 */

static int
g_write(int devtype, int fdes, char *buf, unsigned nbytes)
{
	int rv;

	if (devtype < 0 || devtype >= G_DEV_MAX) {
		errno = ENODEV;
		return (-1);
	}

	rv = write(fdes, buf, nbytes);

	/* st devices return 0 when no more space left */
	if ((rv == 0 && errno == 0) || (rv == -1 && errno == EIO)) {
		errno = ENOSPC;
		rv = -1;
	}

	return (rv);
}

/*
 * Test for tape
 */

static int
is_tape(int fd)
{
	struct mtget stuff;

	/*
	 * try to do a generic tape ioctl, just to see if
	 * the thing is in fact a tape drive(er).
	 */
	if (ioctl(fd, MTIOCGET, &stuff) != -1) {
		/* the ioctl succeeded, must have been a tape */
		return (1);
	}
	return (0);
}

/*
 * Test for floppy
 */

static int
is_floppy(int fd)
{
	struct fd_char stuff;

	/*
	 * try to get the floppy drive characteristics, just to see if
	 * the thing is in fact a floppy drive(er).
	 */
	if (ioctl(fd, FDIOGCHAR, &stuff) != -1) {
		/* the ioctl succeeded, must have been a floppy */
		return (1);
	}

	return (0);
}

/*
 * New functions for ACLs and other security attributes
 */

/*
 * The function appends the new security attribute info to the end of
 * existing secinfo.
 */
static int
append_secattr(
	char		**secinfo,	/* existing security info */
	int		*secinfo_len,	/* length of existing security info */
	acl_t		*aclp) 	/* new attribute data pointer */
{
	char	*new_secinfo;
	char	*attrtext;
	size_t	newattrsize;
	int	oldsize;

	/* no need to add */
	if (aclp == NULL) {
		return (0);
	}

	switch (acl_type(aclp)) {
	case ACLENT_T:
	case ACE_T:
		attrtext = acl_totext(aclp, ACL_APPEND_ID | ACL_COMPACT_FMT |
		    ACL_SID_FMT);
		if (attrtext == NULL) {
			msg(EPOST, "acltotext failed");
			return (-1);
		}
		/* header: type + size = 8 */
		newattrsize = 8 + strlen(attrtext) + 1;
		attr = e_zalloc(E_NORMAL, newattrsize);
		if (attr == NULL) {
			msg(EPOST, "can't allocate memory");
			return (-1);
		}
		attr->attr_type = (acl_type(aclp) == ACLENT_T) ?
		    UFSD_ACL : ACE_ACL;
		/* acl entry count */
		(void) sprintf(attr->attr_len, "%06o", acl_cnt(aclp));
		(void) strcpy((char *)&attr->attr_info[0], attrtext);
		free(attrtext);
		break;

		/* SunFed's case goes here */

	default:
		msg(EPOST, "unrecognized attribute type");
		return (-1);
	}

	/* old security info + new attr header(8) + new attr */
	oldsize = *secinfo_len;
	*secinfo_len += newattrsize;
	new_secinfo = e_zalloc(E_NORMAL, (uint_t)*secinfo_len);
	if (new_secinfo == NULL) {
		msg(EPOST, "can't allocate memory");
		*secinfo_len -= newattrsize;
		return (-1);
	}

	(void) memcpy(new_secinfo, *secinfo, oldsize);
	(void) memcpy(new_secinfo + oldsize, attr, newattrsize);

	free(*secinfo);
	*secinfo = new_secinfo;
	return (0);
}

/*
 * Append size amount of data from buf to the archive.
 */
static void
write_ancillary(char *buf, size_t len, boolean_t padding)
{
	int	pad, cnt;

	if (len == 0)
		return;

	while (len > 0) {
		cnt = (unsigned)(len > CPIOBSZ) ? CPIOBSZ : len;
		FLUSH(cnt);
		errno = 0;
		(void) memcpy(Buffr.b_in_p, buf, (unsigned)cnt);
		Buffr.b_in_p += cnt;
		Buffr.b_cnt += cnt;
		len -= cnt;
		buf += cnt;
	}
	if (padding) {
		pad = (Pad_val + 1 - (cnt & Pad_val)) & Pad_val;
		if (pad != 0) {
			FLUSH(pad);
			(void) memset(Buffr.b_in_p, 0, pad);
			Buffr.b_in_p += pad;
			Buffr.b_cnt += pad;
		}
	}
}

static int
remove_dir(char *path)
{
	DIR		*name;
	struct dirent	*direct;
	struct stat	sbuf;
	char		*path_copy;

#define	MSG1	"remove_dir() failed to stat(\"%s\") "
#define	MSG2	"remove_dir() failed to remove_dir(\"%s\") "
#define	MSG3	"remove_dir() failed to unlink(\"%s\") "

	/*
	 * Open the directory for reading.
	 */
	if ((name = opendir(path)) == NULL) {
		msg(ERRN, "remove_dir() failed to opendir(\"%s\") ", path);
		return (-1);
	}

	if (chdir(path) == -1) {
		msg(ERRN, "remove_dir() failed to chdir(\"%s\") ", path);
		return (-1);
	}

	/*
	 * Read every directory entry.
	 */
	while ((direct = readdir(name)) != NULL) {
		/*
		 * Ignore "." and ".." entries.
		 */
		if (strcmp(direct->d_name, ".") == 0 ||
		    strcmp(direct->d_name, "..") == 0)
			continue;

		if (lstat(direct->d_name, &sbuf) == -1) {
			msg(ERRN, MSG1, direct->d_name);
			(void) closedir(name);
			return (-1);
		}

		if (S_ISDIR(sbuf.st_mode)) {
			if (remove_dir(direct->d_name) == -1) {
				msg(ERRN, MSG2, direct->d_name);
				(void) closedir(name);
				return (-1);
			}
		} else {
			if (unlink(direct->d_name) == -1) {
				msg(ERRN, MSG3, direct->d_name);
				(void) closedir(name);
				return (-1);
			}
		}

	}

	/*
	 * Close the directory we just finished reading.
	 */
	(void) closedir(name);

	/*
	 * Change directory to the parent directory...
	 */
	if (chdir("..") == -1) {
		msg(ERRN, "remove_dir() failed to chdir(\"..\") ");
		return (-1);
	}

	/*
	 * ...and finally remove the directory; note we have to
	 * make a copy since basename is free to modify its input.
	 */
	path_copy = e_strdup(E_NORMAL, path);
	if (path_copy == NULL) {
		msg(ERRN, "cannot strdup() the directory pathname ");
		return (-1);
	}

	if (rmdir(basename(path_copy)) == -1) {
		free(path_copy);
		msg(ERRN, "remove_dir() failed to rmdir(\"%s\") ", path);
		return (-1);
	}

	free(path_copy);
	return (0);

}

static int
save_cwd(void)
{
	return (open(".", O_RDONLY));
}

static void
rest_cwd(int cwd)
{
	(void) fchdir(cwd);
	(void) close(cwd);
}

#if defined(O_XATTR)
static void
xattrs_out(int (*func)())
{
	int dirpfd;
	int filefd;
	int arc_rwsysattr = 0;
	int rw_sysattr = 0;
	int ext_attr = 0;
	DIR *dirp;
	struct dirent *dp;
	int slen;
	int plen;
	char *namep, *savenamep;
	char *apathp;
	char *attrparent = Gen.g_attrparent_p;
	char *filename;

	if (attrparent == NULL) {
		filename = Gen.g_nam_p;
	} else {
		filename = Gen.g_attrnam_p;
	}

	/*
	 * If the underlying file system supports it, then
	 * archive the extended attributes if -@ was specified,
	 * and the extended system attributes if -/ was
	 * specified.
	 */
	if (verify_attr_support(filename, (attrparent == NULL), ARC_CREATE,
	    &ext_attr) != ATTR_OK) {
		return;
	}

#if defined(_PC_SATTR_ENABLED)
	if (SysAtflag) {
		int		filefd;
		nvlist_t 	*slist = NULL;

		/*
		 * Determine if there are non-transient system
		 * attributes.
		 */
		errno = 0;
		if ((filefd = open(filename, O_RDONLY)) == -1) {
			if (attrparent == NULL) {
				msg(EXTN,
				    "unable to open %s%s%sfile %s",
				    (attrparent == NULL) ? "" :
				    gettext("attribute "),
				    (attrparent == NULL) ? "" : attrparent,
				    (attrparent == NULL) ? "" : gettext(" of "),
				    (attrparent == NULL) ? G_p->g_nam_p :
				    G_p->g_attrfnam_p);
			}
		}
		if (((slist = sysattr_list(myname, filefd,
		    filename)) != NULL) || (errno != 0)) {
			arc_rwsysattr = 1;
		}
		if (slist != NULL) {
			(void) nvlist_free(slist);
			slist = NULL;
		}
		(void) close(filefd);
	}

	/*
	 * If we aren't archiving extended system attributes, and we are
	 * processing an attribute, or if we are archiving extended system
	 * attributes, and there are are no extended attributes, then there's
	 * no need to open up the attribute directory of the file unless the
	 * extended system attributes are not transient (i.e, the system
	 * attributes are not the default values).
	 */
	if ((arc_rwsysattr == 0) && ((attrparent != NULL) ||
	    (SysAtflag && !ext_attr))) {
		return;
	}

#endif	/* _PC_SATTR_ENABLED */

	/*
	 * If aclp still exists then free it since it is was set when base
	 * file was extracted.
	 */
	if (aclp != NULL) {
		acl_free(aclp);
		aclp = NULL;
		acl_is_set = 0;
	}

	Gen.g_dirfd = attropen(filename, ".", O_RDONLY);
	if (Gen.g_dirfd == -1) {
		msg(ERRN, "Cannot open attribute directory of file \"%s%s%s\"",
		    (attrparent == NULL) ? "" : gettext("attribute "),
		    (attrparent == NULL) ? "" : attrparent,
		    (attrparent == NULL) ? "" : gettext(" of "), filename);
		return;

	}

	if (attrparent == NULL) {
		savenamep = G_p->g_nam_p;
	} else {
		savenamep = G_p->g_attrfnam_p;
	}

	if ((dirpfd = dup(Gen.g_dirfd)) == -1)  {
		msg(ERRN, "Cannot dup(2) attribute directory descriptor");
		return;
	}

	if ((dirp = fdopendir(dirpfd)) == NULL) {
		msg(ERRN, "Cannot fdopendir(2) directory file descriptor");
		return;
	}

	if (attrparent == NULL) {
		Gen.g_baseparent_fd = save_cwd();
	}

	while ((dp = readdir(dirp)) != NULL) {
		if (strcmp(dp->d_name, "..") == 0) {
			continue;
		}
		if (verify_attr(dp->d_name, attrparent,
		    arc_rwsysattr, &rw_sysattr) != ATTR_OK) {
			continue;
		}

		if (strcmp(dp->d_name, ".") == 0) {
			Hiddendir = 1;
		} else {
			Hiddendir = 0;
		}

		Gen.g_rw_sysattr = rw_sysattr;
		Gen.g_attrnam_p = dp->d_name;

		if (STAT(Gen.g_dirfd, Gen.g_nam_p, &SrcSt) == -1) {
			msg(ERRN,
			    "Could not fstatat(2) attribute \"%s\" of"
			    " file \"%s\"", dp->d_name, (attrparent == NULL) ?
			    savenamep : Gen.g_attrfnam_p);
			continue;
		}

		if (Use_old_stat) {
			Savedev = SrcSt.st_dev;
			OldSt = convert_to_old_stat(&SrcSt,
			    Gen.g_nam_p, Gen.g_attrnam_p);

			if (OldSt == NULL) {
				msg(ERRN,
				    "Could not convert to old stat format");
				continue;
			}
		}

		Gen.g_attrfnam_p = savenamep;

		/*
		 * Set up dummy header name
		 *
		 * One piece is written with .hdr, which
		 * contains the actual xattr hdr or pathing information
		 * then the name is updated to drop the .hdr off
		 * and the actual file itself is archived.
		 */
		slen = strlen(Gen.g_attrnam_p) + strlen(DEVNULL) +
		    strlen(XATTRHDR) + 2;	/* add one for '/' */
		if ((namep = e_zalloc(E_NORMAL, slen)) == NULL) {
			msg(ERRN, "Could not calloc memory for attribute name");
			continue;
		}
		(void) snprintf(namep, slen, "%s/%s%s",
		    DEVNULL, Gen.g_attrnam_p, XATTRHDR);
		Gen.g_nam_p = namep;

		plen = strlen(Gen.g_attrnam_p) + 1;
		if (Gen.g_attrparent_p != NULL) {
			plen += strlen(Gen.g_attrparent_p) + 1;
		}
		if ((apathp = e_zalloc(E_NORMAL, plen)) == NULL) {
			msg(ERRN, "Could not calloc memory for attribute name");
			continue;
		}
		(void) snprintf(apathp, plen, "%s%s%s",
		    (Gen.g_attrparent_p == NULL) ? "" : Gen.g_attrparent_p,
		    (Gen.g_attrparent_p == NULL) ? "" : "/", Gen.g_attrnam_p);

		if (Gen.g_attrpath_p != NULL) {
			free(Gen.g_attrpath_p);
		}
		Gen.g_attrpath_p = apathp;

		/*
		 * Get attribute's ACL info: don't bother allocating space
		 * if there are only standard permissions, i.e. ACL count < 4
		 */
		if (Pflag) {
			filefd = openat(Gen.g_dirfd, dp->d_name, O_RDONLY);
			if (filefd == -1) {
				msg(ERRN,
				    "Could not open attribute \"%s\" of"
				    " file \"%s\"", dp->d_name, savenamep);
				free(namep);
				continue;
			}
			if (facl_get(filefd, ACL_NO_TRIVIAL, &aclp) != 0) {
				msg(ERRN,
				    "Error with acl() on %s",
				    Gen.g_nam_p);
			}
			(void) close(filefd);
		}

		(void) creat_hdr();
		(void) (*func)();

#if defined(_PC_SATTR_ENABLED)
		/*
		 * Recursively call xattrs_out() to process the attribute's
		 * hidden attribute directory and read-write system attributes.
		 */
		if (SysAtflag && !Hiddendir && !rw_sysattr) {
			int	savedirfd = Gen.g_dirfd;

			(void) fchdir(Gen.g_dirfd);
			Gen.g_attrparent_p = dp->d_name;
			xattrs_out(func);
			Gen.g_dirfd = savedirfd;
			Gen.g_attrparent_p = NULL;
		}
#endif	/* _PC_SATTR_ENABLED */

		if (Gen.g_passdirfd != -1) {
			(void) close(Gen.g_passdirfd);
			Gen.g_passdirfd = -1;
		}
		Gen.g_attrnam_p = NULL;
		Gen.g_attrfnam_p = NULL;
		Gen.g_linktoattrfnam_p = NULL;
		Gen.g_linktoattrnam_p = NULL;
		Gen.g_rw_sysattr = 0;
		if (Gen.g_attrpath_p != NULL) {
			free(Gen.g_attrpath_p);
			Gen.g_attrpath_p = NULL;
		}

		if (aclp != NULL) {
			acl_free(aclp);
			aclp = NULL;
			acl_is_set = 0;
		}
		free(namep);
	}

	(void) closedir(dirp);
	(void) close(Gen.g_dirfd);
	if (attrparent == NULL) {
		rest_cwd(Gen.g_baseparent_fd);
		Gen.g_dirfd = -1;
	}
	Hiddendir = 0;
}
#else
static void
xattrs_out(int (*func)())
{
}
#endif

/*
 * Return the parent directory of a given path.
 *
 * Examples:
 * /usr/tmp return /usr
 * /usr/tmp/file return /usr/tmp
 * /  returns .
 * /usr returns /
 * file returns .
 *
 * dir is assumed to be at least as big as path.
 */
static void
get_parent(char *path, char *dir)
{
	char *s;
	char tmpdir[PATH_MAX + 1];

	if (strlen(path) > PATH_MAX) {
		msg(EXT, "pathname is too long");
	}
	(void) strcpy(tmpdir, path);
	chop_endslashes(tmpdir);

	if ((s = strrchr(tmpdir, '/')) == NULL) {
		(void) strcpy(dir, ".");
	} else {
		s = skipslashes(s, tmpdir);
		*s = '\0';
		if (s == tmpdir)
			(void) strcpy(dir, "/");
		else
			(void) strcpy(dir, tmpdir);
	}
}

#if defined(O_XATTR)
#define	ROUNDTOTBLOCK(a)		((a + (TBLOCK -1)) & ~(TBLOCK -1))

static void
prepare_xattr_hdr(
	char		**attrbuf,
	char		*filename,
	char		*attrpath,
	char		typeflag,
	struct Lnk	*linkinfo,
	int		*rlen)
{
	char			*bufhead;	/* ptr to full buffer */
	char			*aptr;
	struct xattr_hdr 	*hptr;		/* ptr to header in bufhead */
	struct xattr_buf	*tptr;		/* ptr to pathing pieces */
	int			totalen;	/* total buffer length */
	int			len;		/* length returned to user */
	int			stringlen;	/* length of filename + attr */
						/*
						 * length of filename + attr
						 * in link section
						 */
	int			linkstringlen;
	int			complen;	/* length of pathing section */
	int			linklen;	/* length of link section */
	int			attrnames_index; /* attrnames starting index */

	/*
	 * Release previous buffer if any.
	 */

	if (*attrbuf != NULL) {
		free(*attrbuf);
		*attrbuf = NULL;
	}

	/*
	 * First add in fixed size stuff
	 */
	len = sizeof (struct xattr_hdr) + sizeof (struct xattr_buf);

	/*
	 * Add space for two nulls
	 */
	stringlen = strlen(attrpath) + strlen(filename) + 2;
	complen = stringlen + sizeof (struct xattr_buf);

	len += stringlen;

	/*
	 * Now add on space for link info if any
	 */

	if (linkinfo != NULL) {
		/*
		 * Again add space for two nulls
		 */
		linkstringlen = strlen(linkinfo->L_gen.g_attrfnam_p) +
		    strlen(linkinfo->L_gen.g_attrnam_p) + 2;
		linklen = linkstringlen + sizeof (struct xattr_buf);
		len += linklen;
	} else {
		linklen = 0;
	}

	/*
	 * Now add padding to end to fill out TBLOCK
	 *
	 * Function returns size of real data and not size + padding.
	 */

	totalen = ROUNDTOTBLOCK(len);
	bufhead = e_zalloc(E_EXIT, totalen);

	/*
	 * Now we can fill in the necessary pieces
	 */

	/*
	 * first fill in the fixed header
	 */
	hptr = (struct xattr_hdr *)bufhead;
	(void) strcpy(hptr->h_version, XATTR_ARCH_VERS);
	(void) sprintf(hptr->h_component_len, "%0*d",
	    sizeof (hptr->h_component_len) - 1, complen);
	(void) sprintf(hptr->h_link_component_len, "%0*d",
	    sizeof (hptr->h_link_component_len) - 1, linklen);
	(void) sprintf(hptr->h_size, "%0*d", sizeof (hptr->h_size) - 1, len);

	/*
	 * Now fill in the filename + attrnames section
	 * The filename and attrnames section can be composed of two or more
	 * path segments separated by a null character.  The first segment
	 * is the path to the parent file that roots the entire sequence in
	 * the normal name space. The remaining segments describes a path
	 * rooted at the hidden extended attribute directory of the leaf file of
	 * the previous segment, making it possible to name attributes on
	 * attributes.  Thus, if we are just archiving an extended attribute,
	 * the second segment will contain the attribute name.  If we are
	 * archiving a system attribute of an extended attribute, then the
	 * second segment will contain the attribute name, and a third segment
	 * will contain the system attribute name.  The attribute pathing
	 * information is obtained from 'attrpath'.
	 */

	tptr = (struct xattr_buf *)(bufhead + sizeof (struct xattr_hdr));
	(void) sprintf(tptr->h_namesz, "%0*d", sizeof (tptr->h_namesz) - 1,
	    stringlen);
	(void) strcpy(tptr->h_names, filename);
	attrnames_index = strlen(filename) + 1;
	(void) strcpy(&tptr->h_names[attrnames_index], attrpath);
	tptr->h_typeflag = typeflag;

	/*
	 * Split the attrnames section into two segments if 'attrpath'
	 * contains pathing information for a system attribute of an
	 * extended attribute.  We split them by replacing the '/' with
	 * a '\0'.
	 */
	if ((aptr = strpbrk(&tptr->h_names[attrnames_index], "/")) != NULL) {
		*aptr = '\0';
	}

	/*
	 * Now fill in the optional link section if we have one
	 */

	if (linkinfo != NULL) {
		tptr = (struct xattr_buf *)(bufhead +
		    sizeof (struct xattr_hdr) + complen);

		(void) sprintf(tptr->h_namesz, "%0*d",
		    sizeof (tptr->h_namesz) - 1, linkstringlen);
		(void) strcpy(tptr->h_names, linkinfo->L_gen.g_attrfnam_p);
		(void) strcpy(
		    &tptr->h_names[strlen(linkinfo->L_gen.g_attrfnam_p) + 1],
		    linkinfo->L_gen.g_attrnam_p);
		tptr->h_typeflag = typeflag;
	}
	*attrbuf = (char *)bufhead;
	*rlen = len;
}
#endif	/* O_XATTR */

static char
tartype(int type)
{
	switch (type) {

	case S_IFDIR:
		return (DIRTYPE);

	case S_IFLNK:
		return (SYMTYPE);

	case S_IFIFO:
		return (FIFOTYPE);

	case S_IFCHR:
		return (CHRTYPE);

	case S_IFBLK:
		return (BLKTYPE);

	case S_IFREG:
		return (REGTYPE);

	default:
		return ('\0');
	}
}

#if defined(O_XATTR)
static int
openfile(int omode)
{
	if (G_p->g_attrnam_p != NULL) {
		return (openat(G_p->g_dirfd, G_p->g_attrnam_p, omode));
	} else {
		return (openat(G_p->g_dirfd,
		    get_component(G_p->g_nam_p), omode));
	}
}
#else
static int
openfile(int omode)
{
	return (openat(G_p->g_dirfd, get_component(G_p->g_nam_p), omode));
}
#endif

#if defined(O_XATTR)
static int
read_xattr_hdr()
{
	off_t		bytes;
	int		comp_len, link_len;
	int		namelen;
	int		asz;
	int		cnt;
	char		*tp;
	char		*xattrapath;
	int		pad;
	int		parentfilelen;

	/*
	 * Include any padding in the read.  We need to be positioned
	 * at beginning of next header.
	 */

	bytes = Gen.g_filesz;

	if ((xattrhead = e_zalloc(E_NORMAL, (size_t)bytes)) == NULL) {
		(void) fprintf(stderr, gettext(
		    "Insufficient memory for extended attribute\n"));
		return (1);
	}

	tp = (char *)xattrhead;
	while (bytes > 0) {
		cnt = (int)(bytes > CPIOBSZ) ? CPIOBSZ : bytes;
		FILL(cnt);
		(void) memcpy(tp, Buffr.b_out_p, cnt);
		tp += cnt;
		Buffr.b_out_p += cnt;
		Buffr.b_cnt -= (off_t)cnt;
		bytes -= (off_t)cnt;
	}

	pad = (Pad_val + 1 - (Gen.g_filesz & Pad_val)) &
	    Pad_val;
	if (pad != 0) {
		FILL(pad);
		Buffr.b_out_p += pad;
		Buffr.b_cnt -= (off_t)pad;
	}

	/*
	 * Validate that we can handle header format
	 */

	if (strcmp(xattrhead->h_version, XATTR_ARCH_VERS) != 0) {
		(void) fprintf(stderr,
		    gettext("Unknown extended attribute format encountered\n"));
		(void) fprintf(stderr,
		    gettext("Disabling extended attribute header parsing\n"));
		xattrbadhead = 1;
		return (1);
	}
	(void) sscanf(xattrhead->h_component_len, "%10d", &comp_len);
	(void) sscanf(xattrhead->h_link_component_len, "%10d", &link_len);
	xattrp = (struct xattr_buf *)(((char *)xattrhead) +
	    sizeof (struct xattr_hdr));
	(void) sscanf(xattrp->h_namesz, "%7d", &namelen);
	if (link_len > 0) {
		xattr_linkp = (struct xattr_buf *)((int)xattrp + (int)comp_len);
	} else {
		xattr_linkp = NULL;
	}

	/*
	 * Gather the attribute path from the filename and attrnames section.
	 * The filename and attrnames section can be composed of two or more
	 * path segments separated by a null character.  The first segment
	 * is the path to the parent file that roots the entire sequence in
	 * the normal name space. The remaining segments describes a path
	 * rooted at the hidden extended attribute directory of the leaf file of
	 * the previous segment, making it possible to name attributes on
	 * attributes.
	 */
	parentfilelen = strlen(xattrp->h_names);
	xattrapath = xattrp->h_names + parentfilelen + 1;
	asz = strlen(xattrapath);
	if ((asz + parentfilelen + 2) < namelen) {
		/*
		 * The attrnames section contains a system attribute on an
		 * attribute.  Save the name of the attribute for use later,
		 * and replace the null separating the attribute name from
		 * the system attribute name with a '/' so that xattrapath can
		 * be used to display messages with the full attribute path name
		 * rooted at the hidden attribute directory of the base file
		 * in normal name space.
		 */
		xattrapath[asz] = '/';
	}

	return (0);
}
#endif

static mode_t
attrmode(char type)
{
	mode_t mode;

	switch (type) {
	case '\0':
	case REGTYPE:
	case LNKTYPE:
		mode = S_IFREG;
		break;

	case SYMTYPE:
		mode = S_IFLNK;
		break;

	case CHRTYPE:
		mode = S_IFCHR;
		break;
	case BLKTYPE:
		mode = S_IFBLK;
		break;
	case DIRTYPE:
		mode = S_IFDIR;
		break;
	case FIFOTYPE:
		mode = S_IFIFO;
		break;
	case CONTTYPE:
	default:
		mode = 0;
	}

	return (mode);
}

#if defined(O_XATTR)
static char *
get_component(char *path)
{
	char *ptr;

	ptr = strrchr(path, '/');
	if (ptr == NULL) {
		return (path);
	} else {
		/*
		 * Handle trailing slash
		 */
		if (*(ptr + 1) == '\0')
			return (ptr);
		else
			return (ptr + 1);
	}
}
#else
static char *
get_component(char *path)
{
	return (path);
}
#endif

static int
open_dir(char *name)
{
	int fd = -1;
	int cnt = 0;
	char *dir;

	dir = e_zalloc(E_EXIT, strlen(name) + 1);

	/*
	 * open directory; creating missing directories along the way.
	 */
	get_parent(name, dir);
	do {
		fd = open(dir, O_RDONLY);
		if (fd != -1) {
			free(dir);
			return (fd);
		}
		cnt++;
	} while (cnt <= 1 && missdir(name) == 0);

	free(dir);
	return (-1);
}

static int
open_dirfd()
{
#ifdef O_XATTR
	if ((Args & OCt) == 0) {
		close_dirfd();
		if (G_p->g_attrnam_p != NULL) {
			int	rw_sysattr;

			/*
			 * Open the file's attribute directory.
			 * Change into the base file's starting directory then
			 * call open_attr_dir() to open the attribute directory
			 * of either the base file (if G_p->g_attrparent_p is
			 * NULL) or the attribute (if G_p->g_attrparent_p is
			 * set) of the base file.
			 */
			(void) fchdir(G_p->g_baseparent_fd);
			(void) open_attr_dir(G_p->g_attrnam_p,
			    G_p->g_attrfnam_p, G_p->g_baseparent_fd,
			    (G_p->g_attrparent_p == NULL) ? NULL :
			    G_p->g_attrparent_p, &G_p->g_dirfd, &rw_sysattr);
			if (Args & OCi) {
				int	saveerrno = errno;

				(void) fchdir(G_p->g_baseparent_fd);
				errno = saveerrno;
			}
			if ((G_p->g_dirfd == -1) && (Args & (OCi | OCp))) {
				msg(ERRN,
				    "Cannot open attribute directory "
				    "of %s%s%sfile \"%s\"",
				    (G_p->g_attrparent_p == NULL) ? "" :
				    gettext("attribute \""),
				    (G_p->g_attrparent_p == NULL) ? "" :
				    G_p->g_attrparent_p,
				    (G_p->g_attrparent_p == NULL) ? "" :
				    gettext("\" of "),
				    G_p->g_attrfnam_p);
				return (FILE_PASS_ERR);
			}
		} else {
			G_p->g_dirfd = open_dir(G_p->g_nam_p);
			if (G_p->g_dirfd == -1) {
				msg(ERRN,
				    "Cannot open/create %s", G_p->g_nam_p);
				return (1);
			}
		}
	} else {
		G_p->g_dirfd = -1;
	}
#else
	G_p->g_dirfd = -1;
#endif
	return (0);
}

static void
close_dirfd()
{
	if (G_p->g_dirfd != -1) {
		(void) close(G_p->g_dirfd);
		G_p->g_dirfd = -1;
	}
}

static void
write_xattr_hdr()
{
	char *attrbuf = NULL;
	int  attrlen = 0;
	char *namep;
	struct Lnk *tl_p, *linkinfo;

	/*
	 * namep was allocated in xattrs_out.  It is big enough to hold
	 * either the name + .hdr on the end or just the attr name
	 */

#if defined(O_XATTR)
	namep = Gen.g_nam_p;
	(void) creat_hdr();

	if (Args & OCo) {
		linkinfo = NULL;
		tl_p = Lnk_hd.L_nxt_p;
		while (tl_p != &Lnk_hd) {
			if (tl_p->L_gen.g_ino == G_p->g_ino &&
			    tl_p->L_gen.g_dev == G_p->g_dev) {
					linkinfo = tl_p;
					break; /* found */
			}
			tl_p = tl_p->L_nxt_p;
		}
		prepare_xattr_hdr(&attrbuf, Gen.g_attrfnam_p,
		    Gen.g_attrpath_p,
		    (linkinfo == NULL) ?
		    tartype(Gen.g_mode & Ftype) : LNKTYPE,
		    linkinfo, &attrlen);
		Gen.g_filesz = attrlen;
		write_hdr(ARCHIVE_XATTR, (off_t)attrlen);
		/*LINTED*/
		(void) sprintf(namep, "%s/%s", DEVNULL, Gen.g_attrnam_p);
		write_ancillary(attrbuf, attrlen, B_TRUE);
	}

	(void) creat_hdr();
#endif
}

/*
 * skip over extra slashes in string.
 *
 * For example:
 * /usr/tmp/////
 *
 * would return pointer at
 * /usr/tmp/////
 *         ^
 */
static char *
skipslashes(char *string, char *start)
{
	while ((string > start) && *(string - 1) == '/') {
		string--;
	}

	return (string);
}

static sl_info_t *
sl_info_alloc(void)
{
	static int num_left;
	static sl_info_t *slipool;

	if (num_left > 0) {
		return (&slipool[--num_left]);
	}
	num_left = SL_INFO_ALLOC_CHUNK;
	slipool = e_zalloc(E_EXIT, sizeof (sl_info_t) * num_left);
	return (&slipool[--num_left]);
}

/*
 * If a match for the key values was found in the tree, return a pointer to it.
 * If a match was not found, insert it and return a pointer to it.  This is
 * based on Knuth's Algorithm A in Vol 3, section 6.2.3.
 */

sl_info_t *
sl_insert(dev_t device, ino_t inode, int ftype)
{
	sl_info_t *p;		/* moves down the tree */
	sl_info_t *q;		/* scratch */
	sl_info_t *r;		/* scratch */
	sl_info_t *s;		/* pt where rebalancing may be needed */
	sl_info_t *t;		/* father of s */
	sl_info_t *head;

	int a;			/* used to hold balance factors */
	int done;		/* loop control */
	int cmpflg;		/* used to hold the result of a comparison */

	/* initialize */

	head = sl_devhash_lookup(device);

	if (head == NULL) {
		head = sl_info_alloc();
		head->llink = NULL;
		head->bal = 0;

		p = head->rlink = sl_info_alloc();
		p->sl_ino = inode;
		p->sl_ftype = ftype;
		p->sl_count = 0;
		p->bal = 0;
		p->llink = NULL;
		p->rlink = NULL;
		sl_devhash_insert(device, head);
		return (p);
	}

	t = head;
	s = p = head->rlink;

	/* compare */

	for (done = 0; ! done; ) {
		switch (sl_compare(inode, ftype, p->sl_ino, p->sl_ftype)) {
			case -1:
				/* move left */

				q = p->llink;

				if (q == NULL) {
					q = sl_info_alloc();
					p->llink = q;
					done = 1;
					continue;
				}

				break;

			case 0:
				/* found it */
				return (p);

			case 1:
				/* move right */

				q = p->rlink;

				if (q == NULL) {
					q = sl_info_alloc();
					p->rlink = q;
					done = 1;
					continue;
				}

				break;
		}

		if (q->bal != 0) {
			t = p;
			s = q;
		}

		p = q;
	}

	/* insert */

	q->sl_ino = inode;
	q->sl_ftype = ftype;
	q->sl_count = 0;
	q->llink = q->rlink = NULL;
	q->bal = 0;

	/* adjust balance factors */

	if ((cmpflg = sl_compare(inode, ftype, s->sl_ino, s->sl_ftype)) < 0) {
		r = p = s->llink;
	} else {
		r = p = s->rlink;
	}

	while (p != q) {
		switch (sl_compare(inode, ftype, p->sl_ino, p->sl_ftype)) {
			case -1:
				p->bal = -1;
				p = p->llink;
				break;

			case 0:
				break;

			case 1:
				p->bal = 1;
				p = p->rlink;
				break;
		}
	}

	/* balancing act */

	if (cmpflg < 0) {
		a = -1;
	} else {
		a = 1;
	}

	if (s->bal == 0) {
		s->bal = a;
		head->llink = (sl_info_t *)((int)head->llink + 1);
		return (q);
	} else if (s->bal == -a) {
		s->bal = 0;
		return (q);
	}

	/*
	 * (s->bal == a)
	 */

	if (r->bal == a) {
		/* single rotation */

		p = r;

		if (a == -1) {
			s->llink = r->rlink;
			r->rlink = s;
		} else if (a == 1) {
			s->rlink = r->llink;
			r->llink = s;
		}

		s->bal = r->bal = 0;

	} else if (r->bal == -a) {
		/* double rotation */

		if (a == -1) {
			p = r->rlink;
			r->rlink = p->llink;
			p->llink = r;
			s->llink = p->rlink;
			p->rlink = s;
		} else if (a == 1) {
			p = r->llink;
			r->llink = p->rlink;
			p->rlink = r;
			s->rlink = p->llink;
			p->llink = s;
		}

		if (p->bal == 0) {
			s->bal = 0;
			r->bal = 0;
		} else if (p->bal == -a) {
			s->bal = 0;
			r->bal = a;
		} else if (p->bal == a) {
			s->bal = -a;
			r->bal = 0;
		}

		p->bal = 0;
	}

	/* finishing touch */

	if (s == t->rlink) {
		t->rlink = p;
	} else {
		t->llink = p;
	}

	return (q);
}

/*
 * sl_numlinks: return the number of links that we saw during our preview.
 */

static ulong_t
sl_numlinks(dev_t device, ino_t inode, int ftype)
{
	sl_info_t *p = sl_search(device, inode, ftype);

	if (p) {
		return (p->sl_count);
	} else {
		return (1);
	}
}

/*
 * Preview extended and extended system attributes.
 *
 * Return 0 if successful, otherwise return 1.
 */
#if defined(O_XATTR)
static int
preview_attrs(char *s, char *attrparent)
{
	char		*filename = (attrparent == NULL) ? s : attrparent;
	int		dirfd;
	int		tmpfd;
	int		islnk;
	int		rc = 0;
	int		arc_rwsysattr = 0;
	int		rw_sysattr = 0;
	int		ext_attr = 0;
	DIR		*dirp;
	struct dirent	*dp;
	struct stat	sb;

	/*
	 * If the underlying file system supports it, then
	 * archive the extended attributes if -@ was specified,
	 * and the extended system attributes if -/ was
	 * specified.
	 */
	if (verify_attr_support(filename, (attrparent == NULL), ARC_CREATE,
	    &ext_attr) != ATTR_OK) {
		return (1);
	}

#if defined(_PC_SATTR_ENABLED)
	if (SysAtflag) {
		int		filefd;
		nvlist_t 	*slist = NULL;

		/* Determine if there are non-transient system attributes. */
		errno = 0;
		if ((filefd = open(filename, O_RDONLY)) < 0) {
			return (1);
		}
		if (((slist = sysattr_list(myname, filefd,
		    filename)) != NULL) || (errno != 0)) {
			arc_rwsysattr = 1;
		}
		if (slist != NULL) {
			(void) nvlist_free(slist);
			slist = NULL;
		}
		(void) close(filefd);
	}

	if ((arc_rwsysattr == 0) && ((attrparent != NULL) ||
	    (SysAtflag && !ext_attr))) {
		return (1);
	}
#endif	/* _PC_SATTR_ENABLED */
	/*
	 * We need to open the attribute directory of the
	 * file, and preview all of the file's attributes as
	 * attributes of the file can be hard links to other
	 * attributes of the file.
	 */
	dirfd = attropen(filename, ".", O_RDONLY);
	if (dirfd == -1)
		return (1);

	tmpfd = dup(dirfd);
	if (tmpfd == -1) {
		(void) close(dirfd);
		return (1);
	}
	dirp = fdopendir(tmpfd);
	if (dirp == NULL) {
		(void) close(dirfd);
		(void) close(tmpfd);
		return (1);
	}

	while (dp = readdir(dirp)) {
		if (dp->d_name[0] == '.') {
			if (dp->d_name[1] == '\0') {
				Hiddendir = 1;
			} else if ((dp->d_name[1] == '.') &&
			    (dp->d_name[2] == '\0')) {
				continue;
			} else {
				Hiddendir = 0;
			}
		} else {
			Hiddendir = 0;
		}

		if (fstatat(dirfd, dp->d_name, &sb,
		    AT_SYMLINK_NOFOLLOW) < 0) {
			continue;
		}

		if (verify_attr(dp->d_name, attrparent,
		    arc_rwsysattr, &rw_sysattr) != ATTR_OK) {
			continue;
		}

		islnk = 0;
		if (S_ISLNK(sb.st_mode)) {
			islnk = 1;
			if (Args & OCL) {
				if (fstatat(dirfd, dp->d_name,
				    &sb, 0) < 0) {
					continue;
				}
			}
		}
		sl_remember_tgt(&sb, islnk, rw_sysattr);

		/*
		 * Recursively call preview_attrs() to preview extended
		 * system attributes of attributes.
		 */
		if (SysAtflag && !Hiddendir && !rw_sysattr) {
			int	my_cwd = save_cwd();

			(void) fchdir(dirfd);
			rc = preview_attrs(s, dp->d_name);
			rest_cwd(my_cwd);
		}
	}
	(void) closedir(dirp);
	(void) close(dirfd);
	return (rc);
}
#endif	/* O_XATTR */

/*
 * sl_preview_synonyms:  Read the file list from the input stream, remembering
 * each reference to each file.
 */

static void
sl_preview_synonyms(void)
{
	char buf [APATH+1];
	char *s;

	char *suffix = "/cpioXXXXXX";
	char *tmpdir = getenv("TMPDIR");
	int    tmpfd, islnk;
	FILE *tmpfile;
	char *tmpfname;

	if (tmpdir == NULL || *tmpdir == '\0' ||
	    (strlen(tmpdir) + strlen(suffix)) > APATH) {
		struct statvfs tdsb;

		tmpdir = "/var/tmp";

		/* /var/tmp is read-only in the mini-root environment */

		if (statvfs(tmpdir, &tdsb) == -1 || tdsb.f_flag & ST_RDONLY) {
			tmpdir = "/tmp";
		}
	}

	tmpfname = e_zalloc(E_EXIT, strlen(tmpdir) + strlen(suffix) + 1);

	(void) strcpy(tmpfname, tmpdir);
	(void) strcat(tmpfname, suffix);

	if ((tmpfd = mkstemp(tmpfname)) == -1) {
		msg(EXTN, "cannot open tmpfile %s%s", tmpdir, suffix);
	}

	if (unlink(tmpfname) == -1) {
		msg(EXTN, "cannot unlink tmpfile %s", tmpfname);
	}

	if ((tmpfile = fdopen(tmpfd, "w+")) == NULL) {
		msg(EXTN, "cannot fdopen tmpfile %s", tmpfname);
	}

	while ((s = fgets(buf, APATH+1, In_p)) != NULL) {
		size_t lastchar;
		struct stat sb;

		if (fputs(buf, tmpfile) == EOF) {
			msg(EXTN, "problem writing to tmpfile %s", tmpfname);
		}

		/* pre-process the name */

		lastchar = strlen(s) - 1;

		if (s[lastchar] != '\n' && lastchar == APATH - 1) {
			continue;
		} else {
			s[lastchar] = '\0';
		}

		while (s[0] == '.' && s[1] == '/') {
			s += 2;
			while (s[0] == '/') {
				s++;
			}
		}

		if (lstat(s, &sb) < 0) {
			continue;
		}
		islnk = 0;
		if (S_ISLNK(sb.st_mode)) {
			islnk = 1;
			if (Args & OCL) {
				if (stat(s, &sb) < 0) {
					continue;
				}
			}
		}
		sl_remember_tgt(&sb, islnk, 0);

#if defined(O_XATTR)
		if (Atflag || SysAtflag) {
			(void) preview_attrs(s, NULL);
		}
#endif	/* O_XATTR */
	}

	if (ferror(In_p)) {
		msg(EXTN, "error reading stdin");
	}

	if (fseek(tmpfile, 0L, SEEK_SET) == -1) {
		msg(EXTN, "cannot fseek on tmpfile %s", tmpfname);
	}

	In_p = tmpfile;
	free(tmpfname);
}

/*
 * sl_remember_tgt: Add the device/inode for lstat or stat info to the list of
 * those we've seen before.
 *
 * This tree (rooted under head) is keyed by the device/inode of the file
 * being pointed to.  A count is kept of the number of references encountered
 * so far.
 */

static void
sl_remember_tgt(const struct stat *sbp, int isSymlink, int is_sysattr)
{
	sl_info_t *p;
	dev_t device;
	ino_t inode;
	int ftype;

	device = sbp->st_dev;
	inode  = sbp->st_ino;
	ftype  = sbp->st_mode & Ftype;

	/* Determine whether we've seen this one before */

	p = sl_insert(device, inode, ftype);

	if (p->sl_count > 0) {
		/*
		 * It appears as if have seen this file before as we found a
		 * matching device, inode, and file type as a file already
		 * processed.  Since there can possibly be files with the
		 * same device, inode, and file type, but aren't hard links
		 * (e.g., read-write system attribute files will always have
		 * the same inode), we need to only attempt to add one to the
		 * link count if the file we are processing is a hard link
		 * (i.e., st_nlink > 1).
		 *
		 * Note that if we are not chasing symlinks, and this one is a
		 * symlink, it is identically the one we saw before (you cannot
		 * have hard links to symlinks); in this case, we leave the
		 * count alone, so that we don't wind up archiving a symlink to
		 * itself.
		 */

		if (((Args & OCL) || (! isSymlink)) && !is_sysattr) {
			p->sl_count++;
		}
	} else {
		/* We have not seen this file before */

		p->sl_count = 1;

		if (Use_old_stat) {
			/* -Hodc: remap inode (-1 on overflow) */

			sl_remap_t  *q;

			for (q = sl_remap_head; q && (q->dev != device);
			    q = q->next) {
				/* do nothing */
			}

			if (q == NULL) {
				q = e_zalloc(E_EXIT, sizeof (sl_remap_t));
				q->dev = device;
				p->sl_ino2 = q->inode_count = 1;

				q->next = (sl_remap_head) ?
				    sl_remap_head->next : NULL;
				sl_remap_head = q;
			} else {
				if ((size_t)q->inode_count <=
				    ((1 << (sizeof (o_ino_t) * 8)) - 1)) {
					/* fits in o_ino_t */
					p->sl_ino2 = ++(q->inode_count);
				} else {
					p->sl_ino2 = (ino_t)-1;
				}
			}
		}
	}
}

/*
 * A faster search, which does not insert the key values into the tree.
 * If the a match was found in the tree, return a pointer to it.  If it was not
 * found, return NULL.
 */

sl_info_t *
sl_search(dev_t device, ino_t inode, int ftype)
{
	sl_info_t *p;		/* moves down the tree */
	int c;			/* comparison value */
	sl_info_t *retval = NULL; /* return value */
	sl_info_t *head;

	head = sl_devhash_lookup(device);
	if (head != NULL) {
		for (p = head->rlink; p; ) {
			if ((c = sl_compare(inode, ftype, p->sl_ino,
			    p->sl_ftype)) == 0) {
				retval = p;
				break;
			} else if (c < 0) {
				p = p->llink;
			} else {
				p = p->rlink;
			}
		}
	}

	return (retval);
}

static sl_info_t *
sl_devhash_lookup(dev_t device)
{
	int key;
	sl_info_link_t *lp;
	static sl_info_link_t *devcache;

	if (devcache != NULL && devcache->dev == device) {
		return (devcache->head);
	}

	key = DEV_HASHKEY(device);
	for (lp = sl_devhash[key]; lp; lp = lp->next) {
		if (lp->dev == device) {
			devcache = lp;
			return (lp->head);
		}
	}
	return (NULL);
}

static void
sl_devhash_insert(dev_t device, sl_info_t *head)
{
	int key = DEV_HASHKEY(device);
	sl_info_link_t *lp;

	lp = e_zalloc(E_EXIT, sizeof (sl_info_link_t));
	lp->dev = device;
	lp->head = head;
	lp->next = sl_devhash[key];
	sl_devhash[key] = lp;
}

static void
chop_endslashes(char *path)
{
	char *end, *ptr;

	end = &path[strlen(path) -1];
	if (*end == '/' && end != path) {
		ptr = skipslashes(end, path);
		if (ptr != NULL && ptr != path) {
			*ptr = '\0';
		}
	}
}

#if !defined(O_XATTR)
int
openat64(int fd, char *name, int oflag, mode_t cmode)
{
	return (open64(name, oflag, cmode));
}

int
openat(int fd, char *name, int oflag, mode_t cmode)
{
	return (open(name, oflag, cmode));
}

int
fchownat(int fd, char *name, uid_t owner, gid_t group, int flag)
{
	if (flag == AT_SYMLINK_NOFOLLOW)
		return (lchown(name, owner, group));
	else
		return (chown(name, owner, group));
}

int
renameat(int fromfd, char *old, int tofd, char *new)
{
	return (rename(old, new));
}

int
futimesat(int fd, char *path, struct timeval times[2])
{
	return (utimes(path, times));
}

int
unlinkat(int dirfd, char *path, int flag)
{
	if (flag == AT_REMOVEDIR) {
		return (rmdir(path));
	} else {
		return (unlink(path));
	}
}

int
fstatat(int fd, char *path, struct stat *buf, int flag)
{
	if (flag == AT_SYMLINK_NOFOLLOW)
		return (lstat(path, buf));
	else
		return (stat(path, buf));
}

int
attropen(char *file, char *attr, int omode, mode_t cmode)
{
	errno = ENOTSUP;
	return (-1);
}
#endif
