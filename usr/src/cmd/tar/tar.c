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
 * Copyright 2015 Joyent, Inc.
 */

/*	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*	Copyright (c) 1987, 1988 Microsoft Corporation	*/
/*	  All Rights Reserved	*/

/*
 * Portions of this source code were derived from Berkeley 4.3 BSD
 * under license from the Regents of the University of California.
 */

#include <unistd.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/mkdev.h>
#include <sys/wait.h>
#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <signal.h>
#include <ctype.h>
#include <locale.h>
#include <nl_types.h>
#include <langinfo.h>
#include <pwd.h>
#include <grp.h>
#include <fcntl.h>
#include <string.h>
#include <malloc.h>
#include <time.h>
#include <utime.h>
#include <stdlib.h>
#include <stdarg.h>
#include <widec.h>
#include <sys/mtio.h>
#include <sys/acl.h>
#include <strings.h>
#include <deflt.h>
#include <limits.h>
#include <iconv.h>
#include <assert.h>
#include <libgen.h>
#include <libintl.h>
#include <aclutils.h>
#include <libnvpair.h>
#include <archives.h>

#if defined(__SunOS_5_6) || defined(__SunOS_5_7)
extern int defcntl();
#endif
#if defined(_PC_SATTR_ENABLED)
#include <attr.h>
#include <libcmdutils.h>
#endif

/* Trusted Extensions */
#include <zone.h>
#include <tsol/label.h>
#include <sys/tsol/label_macro.h>

#include "getresponse.h"
/*
 * Source compatibility
 */

/*
 * These constants come from archives.h and sys/fcntl.h
 * and were introduced by the extended attributes project
 * in Solaris 9.
 */
#if !defined(O_XATTR)
#define	AT_SYMLINK_NOFOLLOW	0x1000
#define	AT_REMOVEDIR		0x1
#define	AT_FDCWD		0xffd19553
#define	_XATTR_HDRTYPE		'E'
static int attropen();
static int fstatat();
static int renameat();
static int unlinkat();
static int openat();
static int fchownat();
static int futimesat();
#endif

/*
 * Compiling with -D_XPG4_2 gets this but produces other problems, so
 * instead of including sys/time.h and compiling with -D_XPG4_2, I'm
 * explicitly doing the declaration here.
 */
int utimes(const char *path, const struct timeval timeval_ptr[]);

#ifndef MINSIZE
#define	MINSIZE 250
#endif
#define	DEF_FILE "/etc/default/tar"

#define	min(a, b)  ((a) < (b) ? (a) : (b))
#define	max(a, b)  ((a) > (b) ? (a) : (b))

#define	TBLOCK	512	/* tape block size--should be universal */

#ifdef	BSIZE
#define	SYS_BLOCK BSIZE	/* from sys/param.h:  secondary block size */
#else	/* BSIZE */
#define	SYS_BLOCK 512	/* default if no BSIZE in param.h */
#endif	/* BSIZE */

#define	NBLOCK	20
#define	NAMSIZ	100
#define	PRESIZ	155
#define	MAXNAM	256
#define	MODEMASK 0777777	/* file creation mode mask */
#define	POSIXMODES 07777	/* mask for POSIX mode bits */
#define	MAXEXT	9	/* reasonable max # extents for a file */
#define	EXTMIN	50	/* min blks left on floppy to split a file */

/* max value dblock.dbuf.efsize can store */
#define	TAR_EFSIZE_MAX	 0777777777

/*
 * Symbols which specify the values at which the use of the 'E' function
 * modifier is required to properly store a file.
 *
 *     TAR_OFFSET_MAX    - the largest file size we can archive
 *     OCTAL7CHAR        - the limit for ustar gid, uid, dev
 */

#ifdef XHDR_DEBUG
/* tiny values which force the creation of extended header entries */
#define	TAR_OFFSET_MAX 9
#define	OCTAL7CHAR 2
#else
/* normal values */
#define	TAR_OFFSET_MAX	077777777777ULL
#define	OCTAL7CHAR	07777777
#endif

#define	TBLOCKS(bytes)	(((bytes) + TBLOCK - 1) / TBLOCK)
#define	K(tblocks)	((tblocks+1)/2)	/* tblocks to Kbytes for printing */

#define	MAXLEV	(PATH_MAX / 2)
#define	LEV0	1
#define	SYMLINK_LEV0	0

#define	TRUE	1
#define	FALSE	0

#define	XATTR_FILE	1
#define	NORMAL_FILE	0

#define	PUT_AS_LINK	1
#define	PUT_NOTAS_LINK	0

#ifndef VIEW_READONLY
#define	VIEW_READONLY	"SUNWattr_ro"
#endif

#ifndef VIEW_READWRITE
#define	VIEW_READWRITE	"SUNWattr_rw"
#endif

#if _FILE_OFFSET_BITS == 64
#define	FMT_off_t "lld"
#define	FMT_off_t_o "llo"
#define	FMT_blkcnt_t "lld"
#else
#define	FMT_off_t "ld"
#define	FMT_off_t_o "lo"
#define	FMT_blkcnt_t "ld"
#endif

/* ACL support */

static
struct	sec_attr {
	char	attr_type;
	char	attr_len[7];
	char	attr_info[1];
} *attr;

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

typedef struct attr_data {
	char	*attr_parent;
	char	*attr_path;
	int	attr_parentfd;
	int	attr_rw_sysattr;
} attr_data_t;

/*
 *
 * Tar has been changed to support extended attributes.
 *
 * As part of this change tar now uses the new *at() syscalls
 * such as openat, fchownat(), unlinkat()...
 *
 * This was done so that attributes can be handled with as few code changes
 * as possible.
 *
 * What this means is that tar now opens the directory that a file or directory
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
 *
 * Extended attribute Format
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
 * /dev/null/attr
 *
 * This is done so that an archiver that doesn't understand these formats
 * can just dispose of the attribute records.
 *
 * The format is composed of a fixed size header followed
 * by a variable sized xattr_buf. If the attribute is a hard link
 * to another attribute then another xattr_buf section is included
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
 * xattrhead is a pointer to the xattr_hdr
 *
 * xattrp is a pointer to the xattr_buf structure
 * which contains the "pathing" steps to get to attributes
 *
 * xattr_linkp is a pointer to another xattr_buf structure that is
 * only used when an attribute is actually linked to another attribute
 *
 */

static struct xattr_hdr *xattrhead;
static struct xattr_buf *xattrp;
static struct xattr_buf *xattr_linkp;	/* pointer to link info, if any */
static char *xattrapath;		/* attribute name */
static char *xattr_linkaname;		/* attribute attribute is linked to */
static char Hiddendir;			/* are we processing hidden xattr dir */
static char xattrbadhead;

/* Was statically allocated tbuf[NBLOCK] */
static
union hblock {
	char dummy[TBLOCK];
	struct header {
		char name[NAMSIZ];	/* If non-null prefix, path is	*/
					/* <prefix>/<name>;  otherwise	*/
					/* <name>			*/
		char mode[8];
		char uid[8];
		char gid[8];
		char size[12];		/* size of this extent if file split */
		char mtime[12];
		char chksum[8];
		char typeflag;
		char linkname[NAMSIZ];
		char magic[6];
		char version[2];
		char uname[32];
		char gname[32];
		char devmajor[8];
		char devminor[8];
		char prefix[PRESIZ];	/* Together with "name", the path of */
					/* the file:  <prefix>/<name>	*/
		char extno;		/* extent #, null if not split */
		char extotal;		/* total extents */
		char efsize[10];	/* size of entire file */
	} dbuf;
} dblock, *tbuf, xhdr_buf;

static
struct xtar_hdr {
	uid_t		x_uid,		/* Uid of file */
			x_gid;		/* Gid of file */
	major_t		x_devmajor;	/* Device major node */
	minor_t		x_devminor;	/* Device minor node */
	off_t		x_filesz;	/* Length of file */
	char		*x_uname,	/* Pointer to name of user */
			*x_gname,	/* Pointer to gid of user */
			*x_linkpath,	/* Path for a hard/symbolic link */
			*x_path;	/* Path of file */
	timestruc_t	x_mtime;	/* Seconds and nanoseconds */
} Xtarhdr;

static
struct gen_hdr {
	ulong_t		g_mode;		/* Mode of file */
	uid_t		g_uid,		/* Uid of file */
			g_gid;		/* Gid of file */
	off_t		g_filesz;	/* Length of file */
	time_t		g_mtime;	/* Modification time */
	uint_t		g_cksum;	/* Checksum of file */
	ulong_t		g_devmajor,	/* File system of file */
			g_devminor;	/* Major/minor of special files */
} Gen;

static
struct linkbuf {
	ino_t	inum;
	dev_t	devnum;
	int	count;
	char	pathname[MAXNAM+1];	/* added 1 for last NULL */
	char 	attrname[MAXNAM+1];
	struct	linkbuf *nextp;
} *ihead;

/* see comments before build_table() */
#define	TABLE_SIZE 512
typedef struct	file_list	{
	char	*name;			/* Name of file to {in,ex}clude */
	struct	file_list	*next;	/* Linked list */
} file_list_t;
static	file_list_t	*exclude_tbl[TABLE_SIZE],
			*include_tbl[TABLE_SIZE];

static int	append_secattr(char **, int *, int, char *, char);
static void	write_ancillary(union hblock *, char *, int, char);

static void add_file_to_table(file_list_t *table[], char *str);
static void assert_string(char *s, char *msg);
static int istape(int fd, int type);
static void backtape(void);
static void build_table(file_list_t *table[], char *file);
static int check_prefix(char **namep, char **dirp, char **compp);
static void closevol(void);
static void copy(void *dst, void *src);
static int convtoreg(off_t);
static void delete_target(int fd, char *comp, char *namep);
static void doDirTimes(char *name, timestruc_t modTime);
static void done(int n);
static void dorep(char *argv[]);
static void dotable(char *argv[]);
static void doxtract(char *argv[]);
static int tar_chdir(const char *path);
static int is_directory(char *name);
static int has_dot_dot(char *name);
static int is_absolute(char *name);
static char *make_relative_name(char *name, char **stripped_prefix);
static void fatal(char *format, ...);
static void vperror(int exit_status, char *fmt, ...);
static void flushtape(void);
static void getdir(void);
static void *getmem(size_t);
static void longt(struct stat *st, char aclchar);
static void load_info_from_xtarhdr(u_longlong_t flag, struct xtar_hdr *xhdrp);
static int makeDir(char *name);
static void mterr(char *operation, int i, int exitcode);
static void newvol(void);
static void passtape(void);
static void putempty(blkcnt_t n);
static int putfile(char *longname, char *shortname, char *parent,
    attr_data_t *attrinfo, int filetype, int lev, int symlink_lev);
static void readtape(char *buffer);
static void seekdisk(blkcnt_t blocks);
static void setPathTimes(int dirfd, char *path, timestruc_t modTime);
static void setbytes_to_skip(struct stat *st, int err);
static void splitfile(char *longname, int ifd, char *name,
	char *prefix, int filetype);
static void tomodes(struct stat *sp);
static void usage(void);
static int xblocks(int issysattr, off_t bytes, int ofile);
static int xsfile(int issysattr, int ofd);
static void resugname(int dirfd, char *name, int symflag);
static int bcheck(char *bstr);
static int checkdir(char *name);
static int checksum(union hblock *dblockp);
#ifdef	EUC
static int checksum_signed(union hblock *dblockp);
#endif	/* EUC */
static int checkupdate(char *arg);
static int checkw(char c, char *name);
static int cmp(char *b, char *s, int n);
static int defset(char *arch);
static boolean_t endtape(void);
static int is_in_table(file_list_t *table[], char *str);
static int notsame(void);
static int is_prefix(char *s1, char *s2);
static int response(void);
static int build_dblock(const char *, const char *, const char,
	const int filetype, const struct stat *, const dev_t, const char *);
static unsigned int hash(char *str);

static blkcnt_t kcheck(char *kstr);
static off_t bsrch(char *s, int n, off_t l, off_t h);
static void onintr(int sig);
static void onquit(int sig);
static void onhup(int sig);
static uid_t getuidbyname(char *);
static gid_t getgidbyname(char *);
static char *getname(gid_t);
static char *getgroup(gid_t);
static int checkf(char *name, int mode, int howmuch);
static int writetbuf(char *buffer, int n);
static int wantit(char *argv[], char **namep, char **dirp, char **comp,
    attr_data_t **attrinfo);
static void append_ext_attr(char *shortname, char **secinfo, int *len);
static int get_xdata(void);
static void gen_num(const char *keyword, const u_longlong_t number);
static void gen_date(const char *keyword, const timestruc_t time_value);
static void gen_string(const char *keyword, const char *value);
static void get_xtime(char *value, timestruc_t *xtime);
static int chk_path_build(char *name, char *longname, char *linkname,
    char *prefix, char type, int filetype);
static int gen_utf8_names(const char *filename);
static int utf8_local(char *option, char **Xhdr_ptrptr, char *target,
    const char *src, int max_val);
static int local_utf8(char **Xhdr_ptrptr, char *target, const char *src,
    iconv_t iconv_cd, int xhdrflg, int max_val);
static int c_utf8(char *target, const char *source);
static int getstat(int dirfd, char *longname, char *shortname,
    char *attrparent);
static void xattrs_put(char *, char *, char *, char *);
static void prepare_xattr(char **, char	*, char	*,
    char, struct linkbuf *, int *);
static int put_link(char *name, char *longname, char *component,
    char *longattrname, char *prefix, int filetype, char typeflag);
static int put_extra_attributes(char *longname, char *shortname,
    char *longattrname, char *prefix, int filetype, char typeflag);
static int put_xattr_hdr(char *longname, char *shortname, char *longattrname,
    char *prefix, int typeflag, int filetype, struct linkbuf *lp);
static int read_xattr_hdr(attr_data_t **attrinfo);

/* Trusted Extensions */
#define	AUTO_ZONE	"/zone"

static void extract_attr(char **file_ptr, struct sec_attr *);
static int check_ext_attr(char *filename);
static void rebuild_comp_path(char *str, char **namep);
static int rebuild_lk_comp_path(char *str, char **namep);

static void get_parent(char *path, char *dir);
static char *get_component(char *path);
static int retry_open_attr(int pdirfd, int cwd, char *dirp, char *pattr,
    char *name, int oflag, mode_t mode);
static char *skipslashes(char *string, char *start);
static void chop_endslashes(char *path);
static pid_t compress_file(void);
static void compress_back(void);
static void decompress_file(void);
static pid_t uncompress_file(void);
static void *compress_malloc(size_t);
static void check_compression(void);
static char *bz_suffix(void);
static char *gz_suffix(void);
static char *xz_suffix(void);
static char *add_suffix();
static void wait_pid(pid_t);
static void verify_compress_opt(const char *t);
static void detect_compress(void);
static void dlog(const char *, ...);
static boolean_t should_enable_debug(void);

static	struct stat stbuf;

static	char	*myname;
static	char	*xtract_chdir = NULL;
static	int	checkflag = 0;
static	int	Xflag, Fflag, iflag, hflag, Bflag, Iflag;
static	int	rflag, xflag, vflag, tflag, mt, cflag, mflag, pflag;
static	int	uflag;
static	int	errflag;
static	int	oflag;
static	int	bflag, Aflag;
static 	int	Pflag;			/* POSIX conformant archive */
static	int	Eflag;			/* Allow files greater than 8GB */
static	int	atflag;			/* traverse extended attributes */
static	int	saflag;			/* traverse extended sys attributes */
static	int	Dflag;			/* Data change flag */
static	int	jflag;			/* flag to use 'bzip2' */
static	int	zflag;			/* flag to use 'gzip' */
static	int	Zflag;			/* flag to use 'compress' */
static	int	Jflag;			/* flag to use 'xz' */
static	int	aflag;			/* flag to use autocompression */

/* Trusted Extensions */
static	int	Tflag;			/* Trusted Extensions attr flags */
static	int	dir_flag;		/* for attribute extract */
static	int	mld_flag;		/* for attribute extract */
static	char	*orig_namep;		/* original namep - unadorned */
static	int	rpath_flag;		/* MLD real path is rebuilt */
static	char	real_path[MAXPATHLEN];	/* MLD real path */
static	int	lk_rpath_flag;		/* linked to real path is rebuilt */
static	char	lk_real_path[MAXPATHLEN]; /* linked real path */
static	bslabel_t	bs_label;	/* for attribute extract */
static	bslabel_t	admin_low;
static	bslabel_t	admin_high;
static	int	ignored_aprivs = 0;
static	int	ignored_fprivs = 0;
static	int	ignored_fattrs = 0;

static	int	term, chksum, wflag,
		first = TRUE, defaults_used = FALSE, linkerrok;
static	blkcnt_t	recno;
static	int	freemem = 1;
static	int	nblock = NBLOCK;
static	int	Errflg = 0;
static	int	exitflag = 0;

static	dev_t	mt_dev;		/* device containing output file */
static	ino_t	mt_ino;		/* inode number of output file */
static	int	mt_devtype;	/* dev type of archive, from stat structure */

static	int update = 1;		/* for `open' call */

static	off_t	low;
static	off_t	high;

static	FILE	*tfile;
static	FILE	*vfile = stdout;
static	char	*tmpdir;
static	char	*tmp_suffix = "/tarXXXXXX";
static	char	*tname;
static	char	archive[] = "archive0=";
static	char	*Xfile;
static	char	*usefile;
static	char	tfname[1024];

static	int	mulvol;		/* multi-volume option selected */
static	blkcnt_t	blocklim; /* number of blocks to accept per volume */
static	blkcnt_t	tapepos; /* current block number to be written */
static	int	NotTape;	/* true if tape is a disk */
static	int	dumping;	/* true if writing a tape or other archive */
static	int	extno;		/* number of extent:  starts at 1 */
static	int	extotal;	/* total extents in this file */
static	off_t	extsize;	/* size of current extent during extraction */
static	ushort_t	Oumask = 0;	/* old umask value */
static 	boolean_t is_posix;	/* true if archive is POSIX-conformant */
static	const	char	*magic_type = "ustar";
static	size_t	xrec_size = 8 * PATH_MAX;	/* extended rec initial size */
static	char	*xrec_ptr;
static	off_t	xrec_offset = 0;
static	int	Xhdrflag;
static	int	charset_type = 0;

static	u_longlong_t	xhdr_flgs;	/* Bits set determine which items */
					/*   need to be in extended header. */
static	pid_t	comp_pid = 0;

static boolean_t debug_output = B_FALSE;

#define	_X_DEVMAJOR	0x1
#define	_X_DEVMINOR	0x2
#define	_X_GID		0x4
#define	_X_GNAME	0x8
#define	_X_LINKPATH	0x10
#define	_X_PATH		0x20
#define	_X_SIZE		0x40
#define	_X_UID		0x80
#define	_X_UNAME	0x100
#define	_X_ATIME	0x200
#define	_X_CTIME	0x400
#define	_X_MTIME	0x800
#define	_X_XHDR		0x1000	/* Bit flag that determines whether 'X' */
				/* typeflag was followed by 'A' or non 'A' */
				/* typeflag. */
#define	_X_LAST		0x40000000

#define	PID_MAX_DIGITS		(10 * sizeof (pid_t) / 4)
#define	TIME_MAX_DIGITS		(10 * sizeof (time_t) / 4)
#define	LONG_MAX_DIGITS		(10 * sizeof (long) / 4)
#define	ULONGLONG_MAX_DIGITS	(10 * sizeof (u_longlong_t) / 4)
/*
 * UTF_8 encoding requires more space than the current codeset equivalent.
 * Currently a factor of 2-3 would suffice, but it is possible for a factor
 * of 6 to be needed in the future, so for saftey, we use that here.
 */
#define	UTF_8_FACTOR	6

static	u_longlong_t	xhdr_count = 0;
static char		xhdr_dirname[PRESIZ + 1];
static char		pidchars[PID_MAX_DIGITS + 1];
static char		*tchar = "";		/* null linkpath */

static	char	local_path[UTF_8_FACTOR * PATH_MAX + 1];
static	char	local_linkpath[UTF_8_FACTOR * PATH_MAX + 1];
static	char	local_gname[UTF_8_FACTOR * _POSIX_NAME_MAX + 1];
static	char	local_uname[UTF_8_FACTOR * _POSIX_NAME_MAX + 1];

/*
 * The following mechanism is provided to allow us to debug tar in complicated
 * situations, like when it is part of a pipe.  The idea is that you compile
 * with -DWAITAROUND defined, and then add the 'D' function modifier to the
 * target tar invocation, eg. "tar cDf tarfile file".  If stderr is available,
 * it will tell you to which pid to attach the debugger; otherwise, use ps to
 * find it.  Attach to the process from the debugger, and, *PRESTO*, you are
 * there!
 *
 * Simply assign "waitaround = 0" once you attach to the process, and then
 * proceed from there as usual.
 */

#ifdef WAITAROUND
int waitaround = 0;		/* wait for rendezvous with the debugger */
#endif

#define	BZIP		"/usr/bin/bzip2"
#define	GZIP		"/usr/bin/gzip"
#define	COMPRESS	"/usr/bin/compress"
#define	XZ		"/usr/bin/xz"
#define	BZCAT		"/usr/bin/bzcat"
#define	GZCAT		"/usr/bin/gzcat"
#define	ZCAT		"/usr/bin/zcat"
#define	XZCAT		"/usr/bin/xzcat"
#define	GSUF		8	/* number of valid 'gzip' sufixes */
#define	BSUF		4	/* number of valid 'bzip2' sufixes */
#define	XSUF		1	/* number of valid 'xz' suffixes */

static	char		*compress_opt; 	/* compression type */

static	char		*gsuffix[] = {".gz", "-gz", ".z", "-z", "_z", ".Z",
			".tgz", ".taz"};
static	char		*bsuffix[] = {".bz2", ".bz", ".tbz2", ".tbz"};
static	char		*xsuffix[] = {".xz"};
static	char		*suffix;


int
main(int argc, char *argv[])
{
	char		*cp;
	char		*tmpdirp;
	pid_t		thispid;

	(void) setlocale(LC_ALL, "");
#if !defined(TEXT_DOMAIN)	/* Should be defined by cc -D */
#define	TEXT_DOMAIN "SYS_TEST"	/* Use this only if it weren't */
#endif
	(void) textdomain(TEXT_DOMAIN);
	if (argc < 2)
		usage();

	debug_output = should_enable_debug();

	tfile = NULL;
	if ((myname = strdup(argv[0])) == NULL) {
		(void) fprintf(stderr, gettext(
		    "tar: cannot allocate program name\n"));
		exit(1);
	}

	if (init_yes() < 0) {
		(void) fprintf(stderr, gettext(ERR_MSG_INIT_YES),
		    strerror(errno));
		exit(2);
	}

	/*
	 *  For XPG4 compatibility, we must be able to accept the "--"
	 *  argument normally recognized by getopt; it is used to delimit
	 *  the end opt the options section, and so can only appear in
	 *  the position of the first argument.  We simply skip it.
	 */

	if (strcmp(argv[1], "--") == 0) {
		argv++;
		argc--;
		if (argc < 3)
			usage();
	}

	argv[argc] = NULL;
	argv++;

	/*
	 * Set up default values.
	 * Search the operand string looking for the first digit or an 'f'.
	 * If you find a digit, use the 'archive#' entry in DEF_FILE.
	 * If 'f' is given, bypass looking in DEF_FILE altogether.
	 * If no digit or 'f' is given, still look in DEF_FILE but use '0'.
	 */
	if ((usefile = getenv("TAPE")) == (char *)NULL) {
		for (cp = *argv; *cp; ++cp)
			if (isdigit(*cp) || *cp == 'f')
				break;
		if (*cp != 'f') {
			archive[7] = (*cp)? *cp: '0';
			if (!(defaults_used = defset(archive))) {
				usefile = NULL;
				nblock = 1;
				blocklim = 0;
				NotTape = 0;
			}
		}
	}

	for (cp = *argv++; *cp; cp++)
		switch (*cp) {
#ifdef WAITAROUND
		case 'D':
			/* rendezvous with the debugger */
			waitaround = 1;
			break;
#endif
		case 'f':
			assert_string(*argv, gettext(
			    "tar: tarfile must be specified with 'f' "
			    "function modifier\n"));
			usefile = *argv++;
			break;
		case 'F':
			Fflag++;
			break;
		case 'c':
			cflag++;
			rflag++;
			update = 1;
			break;
#if defined(O_XATTR)
		case '@':
			atflag++;
			break;
#endif	/* O_XATTR */
#if defined(_PC_SATTR_ENABLED)
		case '/':
			saflag++;
			break;
#endif	/* _PC_SATTR_ENABLED */
		case 'u':
			uflag++;	/* moved code after signals caught */
			rflag++;
			update = 2;
			break;
		case 'r':
			rflag++;
			update = 2;
			break;
		case 'v':
			vflag++;
			break;
		case 'w':
			wflag++;
			break;
		case 'x':
			xflag++;
			break;
		case 'X':
			assert_string(*argv, gettext(
			    "tar: exclude file must be specified with 'X' "
			    "function modifier\n"));
			Xflag = 1;
			Xfile = *argv++;
			build_table(exclude_tbl, Xfile);
			break;
		case 't':
			tflag++;
			break;
		case 'm':
			mflag++;
			break;
		case 'p':
			pflag++;
			break;
		case 'D':
			Dflag++;
			break;
		case '-':
			/* ignore this silently */
			break;
		case '0':	/* numeric entries used only for defaults */
		case '1':
		case '2':
		case '3':
		case '4':
		case '5':
		case '6':
		case '7':
			break;
		case 'b':
			assert_string(*argv, gettext(
			    "tar: blocking factor must be specified "
			    "with 'b' function modifier\n"));
			bflag++;
			nblock = bcheck(*argv++);
			break;
		case 'n':		/* not a magtape (instead of 'k') */
			NotTape++;	/* assume non-magtape */
			break;
		case 'l':
			linkerrok++;
			break;
		case 'e':
			errflag++;
		case 'o':
			oflag++;
			break;
		case 'h':
			hflag++;
			break;
		case 'i':
			iflag++;
			break;
		case 'B':
			Bflag++;
			break;
		case 'P':
			Pflag++;
			break;
		case 'E':
			Eflag++;
			Pflag++;	/* Only POSIX archive made */
			break;
		case 'T':
			Tflag++;	/* Handle Trusted Extensions attrs */
			pflag++;	/* also set flag for ACL */
			break;
		case 'j':		/* compession "bzip2" */
			jflag = 1;
			break;
		case 'z':		/* compression "gzip" */
			zflag = 1;
			break;
		case 'Z':		/* compression "compress" */
			Zflag = 1;
			break;
		case 'J':		/* compression "xz" */
			Jflag = 1;
			break;
		case 'a':
			aflag = 1;	/* autocompression */
			break;
		default:
			(void) fprintf(stderr, gettext(
			"tar: %c: unknown function modifier\n"), *cp);
			usage();
		}

	if (!rflag && !xflag && !tflag)
		usage();
	if ((rflag && xflag) || (xflag && tflag) || (rflag && tflag)) {
		(void) fprintf(stderr, gettext(
		"tar: specify only one of [ctxru].\n"));
		usage();
	}
	if (cflag) {
		if ((jflag + zflag + Zflag + Jflag + aflag) > 1) {
			(void) fprintf(stderr, gettext(
			    "tar: specify only one of [ajJzZ] to "
			    "create a compressed file.\n"));
			usage();
		}
	}
	/* Trusted Extensions attribute handling */
	if (Tflag && ((getzoneid() != GLOBAL_ZONEID) ||
	    !is_system_labeled())) {
		(void) fprintf(stderr, gettext(
		"tar: the 'T' option is only available with "
		    "Trusted Extensions\nand must be run from "
		    "the global zone.\n"));
		usage();
	}
	if (cflag && *argv == NULL)
		fatal(gettext("Missing filenames"));
	if (usefile == NULL)
		fatal(gettext("device argument required"));

	/* alloc a buffer of the right size */
	if ((tbuf = (union hblock *)
	    calloc(sizeof (union hblock) * nblock, sizeof (char))) ==
	    (union hblock *)NULL) {
		(void) fprintf(stderr, gettext(
		"tar: cannot allocate physio buffer\n"));
		exit(1);
	}

	if ((xrec_ptr = malloc(xrec_size)) == NULL) {
		(void) fprintf(stderr, gettext(
		    "tar: cannot allocate extended header buffer\n"));
		exit(1);
	}

#ifdef WAITAROUND
	if (waitaround) {
		(void) fprintf(stderr, gettext("Rendezvous with tar on pid"
		    " %d\n"), getpid());

		while (waitaround) {
			(void) sleep(10);
		}
	}
#endif

	thispid = getpid();
	(void) sprintf(pidchars, "%ld", thispid);
	thispid = strlen(pidchars);

	if ((tmpdirp = getenv("TMPDIR")) == (char *)NULL)
		(void) strcpy(xhdr_dirname, "/tmp");
	else {
		/*
		 * Make sure that dir is no longer than what can
		 * fit in the prefix part of the header.
		 */
		if (strlen(tmpdirp) > (size_t)(PRESIZ - thispid - 12)) {
			(void) strcpy(xhdr_dirname, "/tmp");
			if ((vflag > 0) && (Eflag > 0))
				(void) fprintf(stderr, gettext(
				    "Ignoring TMPDIR\n"));
		} else
			(void) strcpy(xhdr_dirname, tmpdirp);
	}
	(void) strcat(xhdr_dirname, "/PaxHeaders.");
	(void) strcat(xhdr_dirname, pidchars);

	if (rflag) {
		if (cflag && usefile != NULL)  {
			/* Set the compression type */
			if (aflag)
				detect_compress();

			if (jflag) {
				compress_opt = compress_malloc(strlen(BZIP)
				    + 1);
				(void) strcpy(compress_opt, BZIP);
			} else if (zflag) {
				compress_opt = compress_malloc(strlen(GZIP)
				    + 1);
				(void) strcpy(compress_opt, GZIP);
			} else if (Zflag) {
				compress_opt =
				    compress_malloc(strlen(COMPRESS) + 1);
				(void) strcpy(compress_opt, COMPRESS);
			} else if (Jflag) {
				compress_opt = compress_malloc(strlen(XZ) + 1);
				(void) strcpy(compress_opt, XZ);
			}
		} else {
			/*
			 * Decompress if the file is compressed for
			 * an update or replace.
			 */
			if (strcmp(usefile, "-") != 0) {
				check_compression();
				if (compress_opt != NULL) {
					decompress_file();
				}
			}
		}

		if (cflag && tfile != NULL)
			usage();
		if (signal(SIGINT, SIG_IGN) != SIG_IGN)
			(void) signal(SIGINT, onintr);
		if (signal(SIGHUP, SIG_IGN) != SIG_IGN)
			(void) signal(SIGHUP, onhup);
		if (signal(SIGQUIT, SIG_IGN) != SIG_IGN)
			(void) signal(SIGQUIT, onquit);
		if (uflag) {
			int tnum;
			struct stat sbuf;

			tmpdir = getenv("TMPDIR");
			/*
			 * If the name is invalid or this isn't a directory,
			 * or the directory is not writable, then reset to
			 * a default temporary directory.
			 */
			if (tmpdir == NULL || *tmpdir == '\0' ||
			    (strlen(tmpdir) + strlen(tmp_suffix)) > PATH_MAX) {
				tmpdir = "/tmp";
			} else if (stat(tmpdir, &sbuf) < 0 ||
			    (sbuf.st_mode & S_IFMT) != S_IFDIR ||
			    (sbuf.st_mode & S_IWRITE) == 0) {
				tmpdir = "/tmp";
			}

			if ((tname = calloc(1, strlen(tmpdir) +
			    strlen(tmp_suffix) + 1)) == NULL) {
				vperror(1, gettext("tar: out of memory, "
				    "cannot create temporary file\n"));
			}
			(void) strcpy(tname, tmpdir);
			(void) strcat(tname, tmp_suffix);

			if ((tnum = mkstemp(tname)) == -1)
				vperror(1, "%s", tname);
			if ((tfile = fdopen(tnum, "w")) == NULL)
				vperror(1, "%s", tname);
		}
		if (strcmp(usefile, "-") == 0) {
			if (cflag == 0)
				fatal(gettext(
				"can only create standard output archives."));
			vfile = stderr;
			mt = dup(1);
			++bflag;
		} else {
			if (cflag)
				mt = open(usefile,
				    O_RDWR|O_CREAT|O_TRUNC, 0666);
			else
				mt = open(usefile, O_RDWR);

			if (mt < 0) {
				if (cflag == 0 || (mt =  creat(usefile, 0666))
				    < 0)
				vperror(1, "%s", usefile);
			}
		}
		/* Get inode and device number of output file */
		(void) fstat(mt, &stbuf);
		mt_ino = stbuf.st_ino;
		mt_dev = stbuf.st_dev;
		mt_devtype = stbuf.st_mode & S_IFMT;
		NotTape = !istape(mt, mt_devtype);

		if (rflag && !cflag && (mt_devtype == S_IFIFO))
			fatal(gettext("cannot append to pipe or FIFO."));

		if (Aflag && vflag)
			(void) printf(
			gettext("Suppressing absolute pathnames\n"));
		if (cflag && compress_opt != NULL)
			comp_pid = compress_file();
		dorep(argv);
		if (rflag && !cflag && (compress_opt != NULL))
			compress_back();
	} else if (xflag || tflag) {
		/*
		 * for each argument, check to see if there is a "-I file" pair.
		 * if so, move the 3rd argument into "-I"'s place, build_table()
		 * using "file"'s name and increment argc one (the second
		 * increment appears in the for loop) which removes the two
		 * args "-I" and "file" from the argument vector.
		 */
		for (argc = 0; argv[argc]; argc++) {
			if (strcmp(argv[argc], "-I") == 0) {
				if (!argv[argc+1]) {
					(void) fprintf(stderr, gettext(
					"tar: missing argument for -I flag\n"));
					done(2);
				} else {
					Iflag = 1;
					argv[argc] = argv[argc+2];
					build_table(include_tbl, argv[++argc]);
				}
			} else if (strcmp(argv[argc], "-C") == 0) {
				if (!argv[argc+1]) {
					(void) fprintf(stderr, gettext("tar: "
					    "missing argument for -C flag\n"));
					done(2);
				} else if (xtract_chdir != NULL) {
					(void) fprintf(stderr, gettext("tar: "
					    "extract should have only one -C "
					    "flag\n"));
					done(2);
				} else {
					argv[argc] = argv[argc+2];
					xtract_chdir = argv[++argc];
				}
			}
		}
		if (strcmp(usefile, "-") == 0) {
			mt = dup(0);
			++bflag;
			/* try to recover from short reads when reading stdin */
			++Bflag;
		} else if ((mt = open(usefile, 0)) < 0)
			vperror(1, "%s", usefile);

		/* Decompress if the file is compressed */

		if (strcmp(usefile, "-") != 0) {
			check_compression();
			if (compress_opt != NULL)
				comp_pid = uncompress_file();
		}
		if (xflag) {
			if (xtract_chdir != NULL) {
				if (tar_chdir(xtract_chdir) < 0) {
					vperror(1, gettext("can't change "
					    "directories to %s"), xtract_chdir);
				}
			}
			if (Aflag && vflag)
				(void) printf(gettext(
				    "Suppressing absolute pathnames.\n"));

			doxtract(argv);
		} else if (tflag)
			dotable(argv);
	}
	else
		usage();

	done(Errflg);

	/* Not reached:  keep compiler quiet */
	return (1);
}

static boolean_t
should_enable_debug(void)
{
	const char *val;
	const char *truth[] = {
		"true",
		"1",
		"yes",
		"y",
		"please",
		NULL
	};
	unsigned int i;

	if ((val = getenv("DEBUG_TAR")) == NULL) {
		return (B_FALSE);
	}

	for (i = 0; truth[i] != NULL; i++) {
		if (strcmp(val, truth[i]) == 0) {
			return (B_TRUE);
		}
	}

	return (B_FALSE);
}

/*PRINTFLIKE1*/
static void
dlog(const char *format, ...)
{
	va_list ap;

	if (!debug_output) {
		return;
	}

	va_start(ap, format);
	(void) fprintf(stderr, "tar: DEBUG: ");
	(void) vfprintf(stderr, format, ap);
	va_end(ap);
}

static void
usage(void)
{
	(void) fprintf(stderr, gettext(
#if defined(O_XATTR)
#if defined(_PC_SATTR_ENABLED)
	    "Usage: tar {c|r|t|u|x}[BDeEFhilmnopPTvw@/[0-7]][bf][X...] "
#else
	    "Usage: tar {c|r|t|u|x}[BDeEFhilmnopPTvw@[0-7]][bf][X...] "
#endif	/* _PC_SATTR_ENABLED */
#else
	    "Usage: tar {c|r|t|u|x}[BDeEFhilmnopPTvw[0-7]][bf][X...] "
#endif	/* O_XATTR */
	    "[j|J|z|Z] "
	    "[blocksize] [tarfile] [size] [exclude-file...] "
	    "{file | -I include-file | -C directory file}...\n"));
	done(1);
}

/*
 * dorep - do "replacements"
 *
 *	Dorep is responsible for creating ('c'),  appending ('r')
 *	and updating ('u');
 */

static void
dorep(char *argv[])
{
	char *cp, *cp2, *p;
	char wdir[PATH_MAX+2], tempdir[PATH_MAX+2], *parent;
	char file[PATH_MAX*2], origdir[PATH_MAX+1];
	FILE *fp = (FILE *)NULL;
	int archtype;
	int ret;


	if (!cflag) {
		xhdr_flgs = 0;
		getdir();			/* read header for next file */
		if (Xhdrflag > 0) {
			if (!Eflag)
				fatal(gettext("Archive contains extended"
				    " header.  -E flag required.\n"));
			ret = get_xdata();	/* Get extended header items */
						/*   and regular header */
		} else {
			if (Eflag)
				fatal(gettext("Archive contains no extended"
				    " header.  -E flag not allowed.\n"));
		}
		while (!endtape()) {		/* changed from a do while */
			setbytes_to_skip(&stbuf, ret);
			passtape();		/* skip the file data */
			if (term)
				done(Errflg);	/* received signal to stop */
			xhdr_flgs = 0;
			getdir();
			if (Xhdrflag > 0)
				ret = get_xdata();
		}
		if (ret == 0) {
			if ((dblock.dbuf.typeflag != 'A') &&
			    (xhdr_flgs != 0)) {
				load_info_from_xtarhdr(xhdr_flgs,
				    &Xtarhdr);
				xhdr_flgs |= _X_XHDR;
			}
		}
		backtape();			/* was called by endtape */
		if (tfile != NULL) {
			/*
			 * Buffer size is calculated to be the size of the
			 * tmpdir string, plus 6 times the size of the tname
			 * string, plus a value that is known to be greater
			 * than the command pipeline string.
			 */
			int buflen = strlen(tmpdir) + (6 * strlen(tname)) + 100;
			char *buf;

			if ((buf = (char *)calloc(1, buflen)) == NULL) {
				vperror(1, gettext("tar: out of memory, "
				    "cannot create sort command file\n"));
			}

			(void) snprintf(buf, buflen, "env 'TMPDIR=%s' "
			    "sort +0 -1 +1nr %s -o %s; awk '$1 "
			    "!= prev {print; prev=$1}' %s >%sX;mv %sX %s",
			    tmpdir, tname, tname, tname, tname, tname, tname);
			(void) fflush(tfile);
			(void) system(buf);
			free(buf);
			(void) freopen(tname, "r", tfile);
			(void) fstat(fileno(tfile), &stbuf);
			high = stbuf.st_size;
		}
	}

	dumping = 1;
	if (mulvol) {	/* SP-1 */
		if (nblock && (blocklim%nblock) != 0)
			fatal(gettext(
			"Volume size not a multiple of block size."));
		blocklim -= 2;			/* for trailer records */
		if (vflag)
			(void) fprintf(vfile, gettext("Volume ends at %"
			    FMT_blkcnt_t "K, blocking factor = %dK\n"),
			    K((blocklim - 1)), K(nblock));
	}

	/*
	 * Save the original directory before it gets
	 * changed.
	 */
	if (getcwd(origdir, (PATH_MAX+1)) == NULL) {
		vperror(0, gettext("A parent directory cannot be read"));
		exit(1);
	}

	(void) strcpy(wdir, origdir);

	while ((*argv || fp) && !term) {
		if (fp || (strcmp(*argv, "-I") == 0)) {
			if (fp == NULL) {
				if (*++argv == NULL)
					fatal(gettext(
					    "missing file name for -I flag."));
				else if ((fp = fopen(*argv++, "r")) == NULL)
					vperror(0, "%s", argv[-1]);
				continue;
			} else if ((fgets(file, PATH_MAX-1, fp)) == NULL) {
				(void) fclose(fp);
				fp = NULL;
				continue;
			} else {
				cp = cp2 = file;
				if ((p = strchr(cp2, '\n')))
					*p = 0;
			}
		} else if ((strcmp(*argv, "-C") == 0) && argv[1]) {
			if (tar_chdir(*++argv) < 0)
				vperror(0, gettext(
				    "can't change directories to %s"), *argv);
			else
				(void) getcwd(wdir, (sizeof (wdir)));
			argv++;
			continue;
		} else
			cp = cp2 = strcpy(file, *argv++);

		/*
		 * point cp2 to the last '/' in file, but not
		 * to a trailing '/'
		 */
		for (; *cp; cp++) {
			if (*cp == '/') {
				while (*(cp+1) == '/') {
					++cp;
				}
				if (*(cp+1) != '\0') {
					/* not trailing slash */
					cp2 = cp;
				}
			}
		}
		if (cp2 != file) {
			*cp2 = '\0';
			if (tar_chdir(file) < 0) {
				vperror(0, gettext(
				    "can't change directories to %s"), file);
				continue;
			}
			*cp2 = '/';
			cp2++;
		}

		parent = getcwd(tempdir, (sizeof (tempdir)));

		archtype = putfile(file, cp2, parent, NULL, NORMAL_FILE,
		    LEV0, SYMLINK_LEV0);

#if defined(O_XATTR)
		if (!exitflag) {
			if ((atflag || saflag) &&
			    (archtype == PUT_NOTAS_LINK)) {
				xattrs_put(file, cp2, parent, NULL);
			}
		}
#endif

		if (tar_chdir(origdir) < 0)
			vperror(0, gettext("cannot change back?: %s"), origdir);

		if (exitflag) {
			/*
			 * If e function modifier has been specified
			 * write the files (that are listed before the
			 * file causing the error) to tape.  exitflag is
			 * used because only some of the error conditions
			 * in putfile() recognize the e function modifier.
			 */
			break;
		}
	}

	putempty((blkcnt_t)2);
	flushtape();
	closevol();	/* SP-1 */
	if (linkerrok == 1)
		for (; ihead != NULL; ihead = ihead->nextp) {
			if (ihead->count == 0)
				continue;
			(void) fprintf(stderr, gettext(
			"tar: missing links to %s\n"), ihead->pathname);
			if (errflag)
				done(1);
			else
				Errflg = 1;
		}
}


/*
 * endtape - check for tape at end
 *
 *	endtape checks the entry in dblock.dbuf to see if its the
 *	special EOT entry.  Endtape is usually called after getdir().
 *
 *	endtape used to call backtape; it no longer does, he who
 *	wants it backed up must call backtape himself
 *	RETURNS:	0 if not EOT, tape position unaffected
 *			1 if	 EOT, tape position unaffected
 */

static boolean_t
endtape(void)
{
	if (dblock.dbuf.name[0] != '\0') {
		/*
		 * The name field is populated.
		 */
		return (B_FALSE);
	}

	if (is_posix && dblock.dbuf.prefix[0] != '\0') {
		/*
		 * This is a ustar/POSIX archive, and although the name
		 * field is empty the prefix field is not.
		 */
		return (B_FALSE);
	}

	dlog("endtape(): found null header; EOT\n");
	return (B_TRUE);
}

/*
 *	getdir - get directory entry from tar tape
 *
 *	getdir reads the next tarblock off the tape and cracks
 *	it as a directory. The checksum must match properly.
 *
 *	If tfile is non-null getdir writes the file name and mod date
 *	to tfile.
 */

static void
getdir(void)
{
	struct stat *sp;
#ifdef EUC
	static int warn_chksum_sign = 0;
#endif /* EUC */

top:
	readtape((char *)&dblock);
	if (dblock.dbuf.name[0] == '\0')
		return;
	sp = &stbuf;
	(void) sscanf(dblock.dbuf.mode, "%8lo", &Gen.g_mode);
	(void) sscanf(dblock.dbuf.uid, "%8lo", (ulong_t *)&Gen.g_uid);
	(void) sscanf(dblock.dbuf.gid, "%8lo", (ulong_t *)&Gen.g_gid);
	(void) sscanf(dblock.dbuf.size, "%12" FMT_off_t_o, &Gen.g_filesz);
	(void) sscanf(dblock.dbuf.mtime, "%12lo", (ulong_t *)&Gen.g_mtime);
	(void) sscanf(dblock.dbuf.chksum, "%8o", &Gen.g_cksum);
	(void) sscanf(dblock.dbuf.devmajor, "%8lo", &Gen.g_devmajor);
	(void) sscanf(dblock.dbuf.devminor, "%8lo", &Gen.g_devminor);

	is_posix = (strcmp(dblock.dbuf.magic, magic_type) == 0);

	sp->st_mode = Gen.g_mode;
	if (is_posix && (sp->st_mode & S_IFMT) == 0) {
		switch (dblock.dbuf.typeflag) {
		case '0':
		case 0:
		case _XATTR_HDRTYPE:
			sp->st_mode |= S_IFREG;
			break;
		case '1':	/* hard link */
			break;
		case '2':
			sp->st_mode |= S_IFLNK;
			break;
		case '3':
			sp->st_mode |= S_IFCHR;
			break;
		case '4':
			sp->st_mode |= S_IFBLK;
			break;
		case '5':
			sp->st_mode |= S_IFDIR;
			break;
		case '6':
			sp->st_mode |= S_IFIFO;
			break;
		default:
			if (convtoreg(Gen.g_filesz))
				sp->st_mode |= S_IFREG;
			break;
		}
	}

	if ((dblock.dbuf.typeflag == 'X') || (dblock.dbuf.typeflag == 'L')) {
		Xhdrflag = 1;	/* Currently processing extended header */
	} else {
		Xhdrflag = 0;
	}

	sp->st_uid = Gen.g_uid;
	sp->st_gid = Gen.g_gid;
	sp->st_size = Gen.g_filesz;
	sp->st_mtime = Gen.g_mtime;
	chksum = Gen.g_cksum;

	if (dblock.dbuf.extno != '\0') {	/* split file? */
		extno = dblock.dbuf.extno;
		extsize = Gen.g_filesz;
		extotal = dblock.dbuf.extotal;
	} else {
		extno = 0;	/* tell others file not split */
		extsize = 0;
		extotal = 0;
	}

#ifdef	EUC
	if (chksum != checksum(&dblock)) {
		if (chksum != checksum_signed(&dblock)) {
			(void) fprintf(stderr, gettext(
			    "tar: directory checksum error\n"));
			if (iflag) {
				Errflg = 2;
				goto top;
			}
			done(2);
		} else {
			if (! warn_chksum_sign) {
				warn_chksum_sign = 1;
				(void) fprintf(stderr, gettext(
			"tar: warning: tar file made with signed checksum\n"));
			}
		}
	}
#else
	if (chksum != checksum(&dblock)) {
		(void) fprintf(stderr, gettext(
		"tar: directory checksum error\n"));
		if (iflag) {
			Errflg = 2;
			goto top;
		}
		done(2);
	}
#endif	/* EUC */
	if (tfile != NULL && Xhdrflag == 0) {
		/*
		 * If an extended header is present, then time is available
		 * in nanoseconds in the extended header data, so set it.
		 * Otherwise, give an invalid value so that checkupdate will
		 * not test beyond seconds.
		 */
		if ((xhdr_flgs & _X_MTIME))
			sp->st_mtim.tv_nsec = Xtarhdr.x_mtime.tv_nsec;
		else
			sp->st_mtim.tv_nsec = -1;

		if (xhdr_flgs & _X_PATH)
			(void) fprintf(tfile, "%s %10ld.%9.9ld\n",
			    Xtarhdr.x_path, sp->st_mtim.tv_sec,
			    sp->st_mtim.tv_nsec);
		else
			(void) fprintf(tfile, "%.*s %10ld.%9.9ld\n",
			    NAMSIZ, dblock.dbuf.name, sp->st_mtim.tv_sec,
			    sp->st_mtim.tv_nsec);
	}

#if defined(O_XATTR)
	Hiddendir = 0;
	if (xattrp && dblock.dbuf.typeflag == _XATTR_HDRTYPE) {
		if (xattrbadhead) {
			free(xattrhead);
			xattrp = NULL;
			xattr_linkp = NULL;
			xattrhead = NULL;
		} else {
			char	*aname = basename(xattrapath);
			size_t	xindex  = aname - xattrapath;

			if (xattrapath[xindex] == '.' &&
			    xattrapath[xindex + 1] == '\0' &&
			    xattrp->h_typeflag == '5') {
				Hiddendir = 1;
				sp->st_mode =
				    (S_IFDIR | (sp->st_mode & POSIXMODES));
			}
			dblock.dbuf.typeflag = xattrp->h_typeflag;
		}
	}
#endif
}


/*
 *	passtape - skip over a file on the tape
 *
 *	passtape skips over the next data file on the tape.
 *	The tape directory entry must be in dblock.dbuf. This
 *	routine just eats the number of blocks computed from the
 *	directory size entry; the tape must be (logically) positioned
 *	right after the directory info.
 */

static void
passtape(void)
{
	blkcnt_t blocks;
	char buf[TBLOCK];

	/*
	 * Print some debugging information about the directory entry
	 * we are skipping over:
	 */
	dlog("passtape: typeflag \"%c\"\n", dblock.dbuf.typeflag);
	if (dblock.dbuf.name[0] != '\0') {
		dlog("passtape: name \"%s\"\n", dblock.dbuf.name);
	}
	if (is_posix && dblock.dbuf.prefix[0] != '\0') {
		dlog("passtape: prefix \"%s\"\n", dblock.dbuf.prefix);
	}

	/*
	 * Types link(1), sym-link(2), char special(3), blk special(4),
	 *  directory(5), and FIFO(6) do not have data blocks associated
	 *  with them so just skip reading the data block.
	 */
	if (dblock.dbuf.typeflag == '1' || dblock.dbuf.typeflag == '2' ||
	    dblock.dbuf.typeflag == '3' || dblock.dbuf.typeflag == '4' ||
	    dblock.dbuf.typeflag == '5' || dblock.dbuf.typeflag == '6')
		return;
	blocks = TBLOCKS(stbuf.st_size);

	dlog("passtape: block count %" FMT_blkcnt_t "\n", blocks);

	/* if operating on disk, seek instead of reading */
	if (NotTape)
		seekdisk(blocks);
	else
		while (blocks-- > 0)
			readtape(buf);
}

#if defined(O_XATTR)
static int
is_sysattr(char *name)
{
	return ((strcmp(name, VIEW_READONLY) == 0) ||
	    (strcmp(name, VIEW_READWRITE) == 0));
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
 * attrname	- attribute file name
 * attrparent	- attribute's parent name within the base file's attribute
 *		directory hierarchy
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
#else
	/*
	 * Only need to check if this attribute is an extended system
	 * attribute.
	 */
	if (*rw_sysattr = is_sysattr(attrname)) {
		return (ATTR_SKIP);
	} else {
		return (ATTR_OK);
	}
#endif	/* _PC_SATTR_ENABLED */

	/*
	 * If the extended system attribute file is specified with the
	 * arc_rwsysattr flag, as being transient (default extended
	 * attributes), then don't archive it.
	 */
	if (*rw_sysattr && !arc_rwsysattr) {
		return (ATTR_SKIP);
	}

	/*
	 * Only restore read-write system attribute files
	 * when -/ was specified.  Only restore extended
	 * attributes when -@ was specified.
	 */
	if (atflag) {
		if (!saflag) {
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
	} else if (saflag) {
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

static void
free_children(file_list_t *children)
{
	file_list_t	*child = children;
	file_list_t	*cptr;

	while (child != NULL) {
		cptr = child->next;
		if (child->name != NULL) {
			free(child->name);
		}
		child = cptr;
	}
}

static int
putfile(char *longname, char *shortname, char *parent, attr_data_t *attrinfo,
    int filetype, int lev, int symlink_lev)
{
	int infile = -1;	/* deliberately invalid */
	blkcnt_t blocks;
	char buf[PATH_MAX + 2];	/* Add trailing slash and null */
	char *bigbuf;
	int	maxread;
	int	hint;		/* amount to write to get "in sync" */
	char filetmp[PATH_MAX + 1];
	char *cp;
	char *name;
	char *attrparent = NULL;
	char *longattrname = NULL;
	file_list_t	*child = NULL;
	file_list_t	*child_end = NULL;
	file_list_t	*cptr;
	struct dirent *dp;
	DIR *dirp;
	int i;
	int split;
	int dirfd = -1;
	int rc = PUT_NOTAS_LINK;
	int archtype = 0;
	int rw_sysattr = 0;
	char newparent[PATH_MAX + MAXNAMLEN + 1];
	char *prefix = "";
	char *tmpbuf;
	char goodbuf[PRESIZ + 2];
	char junkbuf[MAXNAM+1];
	char *lastslash;
	int j;
	struct stat sbuf;
	int readlink_max;

	(void) memset(goodbuf, '\0', sizeof (goodbuf));
	(void) memset(junkbuf, '\0', sizeof (junkbuf));

	xhdr_flgs = 0;

	if (filetype == XATTR_FILE) {
		attrparent = attrinfo->attr_parent;
		longattrname = attrinfo->attr_path;
		dirfd = attrinfo->attr_parentfd;
		rw_sysattr = attrinfo->attr_rw_sysattr;
	} else {
		dirfd = open(".", O_RDONLY);
	}

	if (dirfd == -1) {
		(void) fprintf(stderr, gettext(
		    "tar: unable to open%sdirectory %s%s%s%s\n"),
		    (filetype == XATTR_FILE) ? gettext(" attribute ") : " ",
		    (attrparent == NULL) ? "" : gettext("of attribute "),
		    (attrparent == NULL) ? "" : attrparent,
		    (attrparent == NULL) ? "" : gettext(" of "),
		    (filetype == XATTR_FILE) ? longname : parent);
		goto out;
	}

	if (lev > MAXLEV) {
		(void) fprintf(stderr,
		    gettext("tar: directory nesting too deep, %s not dumped\n"),
		    longname);
		goto out;
	}

	if (getstat(dirfd, longname, shortname, attrparent))
		goto out;

	if (hflag) {
		/*
		 * Catch nesting where a file is a symlink to its directory.
		 */
		j = fstatat(dirfd, shortname, &sbuf, AT_SYMLINK_NOFOLLOW);
		if (S_ISLNK(sbuf.st_mode)) {
			if (symlink_lev++ >= MAXSYMLINKS) {
				(void) fprintf(stderr, gettext(
				    "tar: %s: Number of symbolic links "
				    "encountered during path name traversal "
				    "exceeds MAXSYMLINKS\n"), longname);
				Errflg = 1;
				goto out;
			}
		}
	}

	/*
	 * Check if the input file is the same as the tar file we
	 * are creating
	 */
	if ((mt_ino == stbuf.st_ino) && (mt_dev == stbuf.st_dev)) {
		(void) fprintf(stderr, gettext(
		    "tar: %s%s%s%s%s same as archive file\n"),
		    rw_sysattr ? gettext("system ") : "",
		    (longattrname == NULL) ? "" : gettext("attribute "),
		    (longattrname == NULL) ? "" : longattrname,
		    (longattrname == NULL) ? "" : gettext(" of "),
		    longname);
		Errflg = 1;
		goto out;
	}
	/*
	 * Check size limit - we can't archive files that
	 * exceed TAR_OFFSET_MAX bytes because of header
	 * limitations. Exclude file types that set
	 * st_size to zero below because they take no
	 * archive space to represent contents.
	 */
	if ((stbuf.st_size > (off_t)TAR_OFFSET_MAX) &&
	    !S_ISDIR(stbuf.st_mode) &&
	    !S_ISCHR(stbuf.st_mode) &&
	    !S_ISBLK(stbuf.st_mode) &&
	    (Eflag == 0)) {
		(void) fprintf(stderr, gettext(
		    "tar: %s%s%s%s%s too large to archive.  "
		    "Use E function modifier.\n"),
		    rw_sysattr ? gettext("system ") : "",
		    (longattrname == NULL) ? "" : gettext("attribute "),
		    (longattrname == NULL) ? "" : longattrname,
		    (longattrname == NULL) ? "" : gettext(" of "),
		    longname);
		if (errflag)
			exitflag = 1;
		Errflg = 1;
		goto out;
	}

	if (tfile != NULL && checkupdate(longname) == 0) {
		goto out;
	}
	if (checkw('r', longname) == 0) {
		goto out;
	}

	if (Fflag &&
	    checkf(longname, (stbuf.st_mode & S_IFMT) == S_IFDIR, Fflag) == 0)
		goto out;

	if (Xflag) {
		if (is_in_table(exclude_tbl, longname)) {
			if (vflag) {
				(void) fprintf(vfile, gettext(
				    "a %s excluded\n"), longname);
			}
			goto out;
		}
	}

	/*
	 * If the length of the fullname is greater than MAXNAM,
	 * print out a message and return (unless extended headers are used,
	 * in which case fullname is limited to PATH_MAX).
	 */

	if ((((split = (int)strlen(longname)) > MAXNAM) && (Eflag == 0)) ||
	    (split > PATH_MAX)) {
		(void) fprintf(stderr, gettext(
		    "tar: %s: file name too long\n"), longname);
		if (errflag)
			exitflag = 1;
		Errflg = 1;
		goto out;
	}

	/*
	 * We split the fullname into prefix and name components if any one
	 * of three conditions holds:
	 *	-- the length of the fullname exceeds NAMSIZ,
	 *	-- the length of the fullname equals NAMSIZ, and the shortname
	 *	   is less than NAMSIZ, (splitting in this case preserves
	 *	   compatibility with 5.6 and 5.5.1 tar), or
	 * 	-- the length of the fullname equals NAMSIZ, the file is a
	 *	   directory and we are not in POSIX-conformant mode (where
	 *	   trailing slashes are removed from directories).
	 */
	if ((split > NAMSIZ) ||
	    (split == NAMSIZ && strlen(shortname) < NAMSIZ) ||
	    (split == NAMSIZ && S_ISDIR(stbuf.st_mode) && !Pflag)) {
		/*
		 * Since path is limited to PRESIZ characters, look for the
		 * last slash within PRESIZ + 1 characters only.
		 */
		(void) strncpy(&goodbuf[0], longname, min(split, PRESIZ + 1));
		tmpbuf = goodbuf;
		lastslash = strrchr(tmpbuf, '/');
		if (lastslash == NULL) {
			i = split;		/* Length of name */
			j = 0;			/* Length of prefix */
			goodbuf[0] = '\0';
		} else {
			*lastslash = '\0';	/* Terminate the prefix */
			j = strlen(tmpbuf);
			i = split - j - 1;
		}
		/*
		 * If the filename is greater than NAMSIZ we can't
		 * archive the file unless we are using extended headers.
		 */
		if ((i > NAMSIZ) || (i == NAMSIZ && S_ISDIR(stbuf.st_mode) &&
		    !Pflag)) {
			/* Determine which (filename or path) is too long. */
			lastslash = strrchr(longname, '/');
			if (lastslash != NULL)
				i = strlen(lastslash + 1);
			if (Eflag > 0) {
				xhdr_flgs |= _X_PATH;
				Xtarhdr.x_path = longname;
				if (i <= NAMSIZ)
					(void) strcpy(junkbuf, lastslash + 1);
				else
					(void) sprintf(junkbuf, "%llu",
					    xhdr_count + 1);
				if (split - i - 1 > PRESIZ)
					(void) strcpy(goodbuf, xhdr_dirname);
			} else {
				if ((i > NAMSIZ) || (i == NAMSIZ &&
				    S_ISDIR(stbuf.st_mode) && !Pflag))
					(void) fprintf(stderr, gettext(
					    "tar: %s: filename is greater than "
					    "%d\n"), lastslash == NULL ?
					    longname : lastslash + 1, NAMSIZ);
				else
					(void) fprintf(stderr, gettext(
					    "tar: %s: prefix is greater than %d"
					    "\n"), longname, PRESIZ);
				if (errflag)
					exitflag = 1;
				Errflg = 1;
				goto out;
			}
		} else
			(void) strncpy(&junkbuf[0], longname + j + 1,
			    strlen(longname + j + 1));
		name = junkbuf;
		prefix = goodbuf;
	} else {
		name = longname;
	}
	if (Aflag) {
		if ((prefix != NULL) && (*prefix != '\0'))
			while (*prefix == '/')
				++prefix;
		else
			while (*name == '/')
				++name;
	}

	switch (stbuf.st_mode & S_IFMT) {
	case S_IFDIR:
		stbuf.st_size = (off_t)0;
		blocks = TBLOCKS(stbuf.st_size);

		if (filetype != XATTR_FILE && Hiddendir == 0) {
			i = 0;
			cp = buf;
			while ((*cp++ = longname[i++]))
				;
			*--cp = '/';
			*++cp = 0;
		}
		if (!oflag) {
			tomodes(&stbuf);
			if (build_dblock(name, tchar, '5', filetype,
			    &stbuf, stbuf.st_dev, prefix) != 0) {
				goto out;
			}
			if (!Pflag) {
				/*
				 * Old archives require a slash at the end
				 * of a directory name.
				 *
				 * XXX
				 * If directory name is too long, will
				 * slash overfill field?
				 */
				if (strlen(name) > (unsigned)NAMSIZ-1) {
					(void) fprintf(stderr, gettext(
					    "tar: %s: filename is greater "
					    "than %d\n"), name, NAMSIZ);
					if (errflag)
						exitflag = 1;
					Errflg = 1;
					goto out;
				} else {
					if (strlen(name) == (NAMSIZ - 1)) {
						(void) memcpy(dblock.dbuf.name,
						    name, NAMSIZ);
						dblock.dbuf.name[NAMSIZ-1]
						    = '/';
					} else
						(void) sprintf(dblock.dbuf.name,
						    "%s/", name);

					/*
					 * need to recalculate checksum
					 * because the name changed.
					 */
					(void) sprintf(dblock.dbuf.chksum,
					    "%07o", checksum(&dblock));
				}
			}

			if (put_extra_attributes(longname, shortname,
			    longattrname, prefix, filetype, '5') != 0)
				goto out;

#if defined(O_XATTR)
			/*
			 * Reset header typeflag when archiving directory, since
			 * build_dblock changed it on us.
			 */
			if (filetype == XATTR_FILE) {
				dblock.dbuf.typeflag = _XATTR_HDRTYPE;
			} else {
				dblock.dbuf.typeflag = '5';
			}
#else
			dblock.dbuf.typeflag = '5';
#endif

			(void) sprintf(dblock.dbuf.chksum, "%07o",
			    checksum(&dblock));

			(void) writetbuf((char *)&dblock, 1);
		}
		if (vflag) {
			if (NotTape) {
				dlog("seek = %" FMT_blkcnt_t "K\n", K(tapepos));
			}
			if (filetype == XATTR_FILE && Hiddendir) {
				(void) fprintf(vfile,
				    gettext("a %s attribute %s "),
				    longname, longattrname);

			} else {
				(void) fprintf(vfile, "a %s/ ", longname);
			}
			if (NotTape) {
				(void) fprintf(vfile, "%" FMT_blkcnt_t "K\n",
				    K(blocks));
			} else {
				(void) fprintf(vfile, gettext("%" FMT_blkcnt_t
				    " tape blocks\n"), blocks);
			}
		}

		/*
		 * If hidden dir then break now since xattrs_put() will do
		 * the iterating of the directory.
		 *
		 * At the moment, there can only be system attributes on
		 * attributes.  There can be no attributes on attributes or
		 * directories within the attributes hidden directory hierarchy.
		 */
		if (filetype == XATTR_FILE)
			break;

		if (*shortname != '/')
			(void) sprintf(newparent, "%s/%s", parent, shortname);
		else
			(void) sprintf(newparent, "%s", shortname);

		if (tar_chdir(shortname) < 0) {
			vperror(0, "%s", newparent);
			goto out;
		}

		if ((dirp = opendir(".")) == NULL) {
			vperror(0, gettext(
			    "can't open directory %s"), longname);
			if (tar_chdir(parent) < 0)
				vperror(0, gettext("cannot change back?: %s"),
				    parent);
			goto out;
		}

		/*
		 * Create a list of files (children) in this directory to avoid
		 * having to perform telldir()/seekdir().
		 */
		while ((dp = readdir(dirp)) != NULL && !term) {
			if ((strcmp(".", dp->d_name) == 0) ||
			    (strcmp("..", dp->d_name) == 0))
				continue;
			if (((cptr = (file_list_t *)calloc(sizeof (char),
			    sizeof (file_list_t))) == NULL) ||
			    ((cptr->name = strdup(dp->d_name)) == NULL)) {
				vperror(1, gettext(
				    "Insufficient memory for directory "
				    "list entry %s/%s\n"),
				    newparent, dp->d_name);
			}

			/* Add the file to the list */
			if (child == NULL) {
				child = cptr;
			} else {
				child_end->next = cptr;
			}
			child_end = cptr;
		}
		(void) closedir(dirp);

		/*
		 * Archive each of the files in the current directory.
		 * If a file is a directory, putfile() is called
		 * recursively to archive the file hierarchy of the
		 * directory before archiving the next file in the
		 * current directory.
		 */
		while ((child != NULL) && !term) {
			(void) strcpy(cp, child->name);
			archtype = putfile(buf, cp, newparent, NULL,
			    NORMAL_FILE, lev + 1, symlink_lev);

			if (!exitflag) {
				if ((atflag || saflag) &&
				    (archtype == PUT_NOTAS_LINK)) {
					xattrs_put(buf, cp, newparent, NULL);
				}
			}
			if (exitflag)
				break;

			/* Free each child as we are done processing it. */
			cptr = child;
			child = child->next;
			free(cptr->name);
			free(cptr);
		}
		if ((child != NULL) && !term) {
			free_children(child);
		}

		if (tar_chdir(parent) < 0) {
			vperror(0, gettext("cannot change back?: %s"), parent);
		}

		break;

	case S_IFLNK:
		readlink_max = NAMSIZ;
		if (stbuf.st_size > NAMSIZ) {
			if (Eflag > 0) {
				xhdr_flgs |= _X_LINKPATH;
				readlink_max = PATH_MAX;
			} else {
				(void) fprintf(stderr, gettext(
				    "tar: %s: symbolic link too long\n"),
				    longname);
				if (errflag)
					exitflag = 1;
				Errflg = 1;
				goto out;
			}
		}
		/*
		 * Sym-links need header size of zero since you
		 * don't store any data for this type.
		 */
		stbuf.st_size = (off_t)0;
		tomodes(&stbuf);
		i = readlink(shortname, filetmp, readlink_max);
		if (i < 0) {
			vperror(0, gettext(
			    "can't read symbolic link %s"), longname);
			goto out;
		} else {
			filetmp[i] = 0;
		}
		if (vflag)
			(void) fprintf(vfile, gettext(
			    "a %s symbolic link to %s\n"),
			    longname, filetmp);
		if (xhdr_flgs & _X_LINKPATH) {
			Xtarhdr.x_linkpath = filetmp;
			if (build_dblock(name, tchar, '2', filetype, &stbuf,
			    stbuf.st_dev, prefix) != 0)
				goto out;
		} else
			if (build_dblock(name, filetmp, '2', filetype, &stbuf,
			    stbuf.st_dev, prefix) != 0)
				goto out;
		(void) writetbuf((char *)&dblock, 1);
		/*
		 * No acls for symlinks: mode is always 777
		 * dont call write ancillary
		 */
		rc = PUT_AS_LINK;
		break;
	case S_IFREG:
		if ((infile = openat(dirfd, shortname, 0)) < 0) {
			vperror(0, gettext("unable to open %s%s%s%s"), longname,
			    rw_sysattr ? gettext(" system") : "",
			    (filetype == XATTR_FILE) ?
			    gettext(" attribute ") : "",
			    (filetype == XATTR_FILE) ? (longattrname == NULL) ?
			    shortname : longattrname : "");
			goto out;
		}

		blocks = TBLOCKS(stbuf.st_size);

		if (put_link(name, longname, shortname, longattrname,
		    prefix, filetype, '1') == 0) {
			(void) close(infile);
			rc = PUT_AS_LINK;
			goto out;
		}

		tomodes(&stbuf);

		/* correctly handle end of volume */
		while (mulvol && tapepos + blocks + 1 > blocklim) {
			/* split if floppy has some room and file is large */
			if (((blocklim - tapepos) >= EXTMIN) &&
			    ((blocks + 1) >= blocklim/10)) {
				splitfile(longname, infile,
				    name, prefix, filetype);
				(void) close(dirfd);
				(void) close(infile);
				goto out;
			}
			newvol();	/* not worth it--just get new volume */
		}
		dlog("putfile: %s wants %" FMT_blkcnt_t " blocks\n", longname,
		    blocks);
		if (build_dblock(name, tchar, '0', filetype,
		    &stbuf, stbuf.st_dev, prefix) != 0) {
			goto out;
		}
		if (vflag) {
			if (NotTape) {
				dlog("seek = %" FMT_blkcnt_t "K\n", K(tapepos));
			}
			(void) fprintf(vfile, "a %s%s%s%s ", longname,
			    rw_sysattr ? gettext(" system") : "",
			    (filetype == XATTR_FILE) ? gettext(
			    " attribute ") : "",
			    (filetype == XATTR_FILE) ?
			    longattrname : "");
			if (NotTape)
				(void) fprintf(vfile, "%" FMT_blkcnt_t "K\n",
				    K(blocks));
			else
				(void) fprintf(vfile,
				    gettext("%" FMT_blkcnt_t " tape blocks\n"),
				    blocks);
		}

		if (put_extra_attributes(longname, shortname, longattrname,
		    prefix, filetype, '0') != 0)
			goto out;

		/*
		 * No need to reset typeflag for extended attribute here, since
		 * put_extra_attributes already set it and we haven't called
		 * build_dblock().
		 */
		(void) sprintf(dblock.dbuf.chksum, "%07o", checksum(&dblock));
		hint = writetbuf((char *)&dblock, 1);
		maxread = max(min(stbuf.st_blksize, stbuf.st_size),
		    (nblock * TBLOCK));
		if ((bigbuf = calloc((unsigned)maxread, sizeof (char))) == 0) {
			maxread = TBLOCK;
			bigbuf = buf;
		}

		while (((i = (int)
		    read(infile, bigbuf, min((hint*TBLOCK), maxread))) > 0) &&
		    blocks) {
			blkcnt_t nblks;

			nblks = ((i-1)/TBLOCK)+1;
			if (nblks > blocks)
				nblks = blocks;
			hint = writetbuf(bigbuf, nblks);
			blocks -= nblks;
		}
		(void) close(infile);
		if (bigbuf != buf)
			free(bigbuf);
		if (i < 0)
			vperror(0, gettext("Read error on %s"), longname);
		else if (blocks != 0 || i != 0) {
			(void) fprintf(stderr, gettext(
			"tar: %s: file changed size\n"), longname);
			if (errflag) {
				exitflag = 1;
				Errflg = 1;
			} else if (!Dflag) {
				Errflg = 1;
			}
		}
		putempty(blocks);
		break;
	case S_IFIFO:
		blocks = TBLOCKS(stbuf.st_size);
		stbuf.st_size = (off_t)0;

		if (put_link(name, longname, shortname, longattrname,
		    prefix, filetype, '6') == 0) {
			rc = PUT_AS_LINK;
			goto out;
		}
		tomodes(&stbuf);

		while (mulvol && tapepos + blocks + 1 > blocklim) {
			if (((blocklim - tapepos) >= EXTMIN) &&
			    ((blocks + 1) >= blocklim/10)) {
				splitfile(longname, infile, name,
				    prefix, filetype);
				(void) close(dirfd);
				(void) close(infile);
				goto out;
			}
			newvol();
		}
		dlog("putfile: %s wants %" FMT_blkcnt_t " blocks\n", longname,
		    blocks);
		if (vflag) {
			if (NotTape) {
				dlog("seek = %" FMT_blkcnt_t "K\n", K(tapepos));

				(void) fprintf(vfile, gettext("a %s %"
				    FMT_blkcnt_t "K\n "), longname, K(blocks));
			} else {
				(void) fprintf(vfile, gettext(
				    "a %s %" FMT_blkcnt_t " tape blocks\n"),
				    longname, blocks);
			}
		}
		if (build_dblock(name, tchar, '6', filetype,
		    &stbuf, stbuf.st_dev, prefix) != 0)
			goto out;

		if (put_extra_attributes(longname, shortname, longattrname,
		    prefix, filetype, '6') != 0)
			goto out;

		(void) sprintf(dblock.dbuf.chksum, "%07o", checksum(&dblock));
		dblock.dbuf.typeflag = '6';

		(void) writetbuf((char *)&dblock, 1);
		break;
	case S_IFCHR:
		stbuf.st_size = (off_t)0;
		blocks = TBLOCKS(stbuf.st_size);
		if (put_link(name, longname, shortname, longattrname,
		    prefix, filetype, '3') == 0) {
			rc = PUT_AS_LINK;
			goto out;
		}
		tomodes(&stbuf);

		while (mulvol && tapepos + blocks + 1 > blocklim) {
			if (((blocklim - tapepos) >= EXTMIN) &&
			    ((blocks + 1) >= blocklim/10)) {
				splitfile(longname, infile, name,
				    prefix, filetype);
				(void) close(dirfd);
				goto out;
			}
			newvol();
		}
		dlog("putfile: %s wants %" FMT_blkcnt_t " blocks\n", longname,
		    blocks);
		if (vflag) {
			if (NotTape) {
				dlog("seek = %" FMT_blkcnt_t "K\t", K(tapepos));

				(void) fprintf(vfile, gettext("a %s %"
				    FMT_blkcnt_t "K\n"), longname, K(blocks));
			} else {
				(void) fprintf(vfile, gettext("a %s %"
				    FMT_blkcnt_t " tape blocks\n"), longname,
				    blocks);
			}
		}
		if (build_dblock(name, tchar, '3',
		    filetype, &stbuf, stbuf.st_rdev, prefix) != 0)
			goto out;

		if (put_extra_attributes(longname, shortname, longattrname,
		    prefix, filetype, '3') != 0)
			goto out;

		(void) sprintf(dblock.dbuf.chksum, "%07o", checksum(&dblock));
		dblock.dbuf.typeflag = '3';

		(void) writetbuf((char *)&dblock, 1);
		break;
	case S_IFBLK:
		stbuf.st_size = (off_t)0;
		blocks = TBLOCKS(stbuf.st_size);
		if (put_link(name, longname, shortname, longattrname,
		    prefix, filetype, '4') == 0) {
			rc = PUT_AS_LINK;
			goto out;
		}
		tomodes(&stbuf);

		while (mulvol && tapepos + blocks + 1 > blocklim) {
			if (((blocklim - tapepos) >= EXTMIN) &&
			    ((blocks + 1) >= blocklim/10)) {
				splitfile(longname, infile,
				    name, prefix, filetype);
				(void) close(dirfd);
				goto out;
			}
			newvol();
		}
		dlog("putfile: %s wants %" FMT_blkcnt_t " blocks\n", longname,
		    blocks);
		if (vflag) {
			if (NotTape) {
				dlog("seek = %" FMT_blkcnt_t "K\n", K(tapepos));
			}

			(void) fprintf(vfile, "a %s ", longname);
			if (NotTape)
				(void) fprintf(vfile, "%" FMT_blkcnt_t "K\n",
				    K(blocks));
			else
				(void) fprintf(vfile, gettext("%"
				    FMT_blkcnt_t " tape blocks\n"), blocks);
		}
		if (build_dblock(name, tchar, '4',
		    filetype, &stbuf, stbuf.st_rdev, prefix) != 0)
			goto out;

		if (put_extra_attributes(longname, shortname, longattrname,
		    prefix, filetype, '4') != 0)
			goto out;

		(void) sprintf(dblock.dbuf.chksum, "%07o", checksum(&dblock));
		dblock.dbuf.typeflag = '4';

		(void) writetbuf((char *)&dblock, 1);
		break;
	default:
		(void) fprintf(stderr, gettext(
		    "tar: %s is not a file. Not dumped\n"), longname);
		if (errflag)
			exitflag = 1;
		Errflg = 1;
		goto out;
	}

out:
	if ((dirfd != -1) && (filetype != XATTR_FILE)) {
		(void) close(dirfd);
	}
	return (rc);
}


/*
 *	splitfile	dump a large file across volumes
 *
 *	splitfile(longname, fd);
 *		char *longname;		full name of file
 *		int ifd;		input file descriptor
 *
 *	NOTE:  only called by putfile() to dump a large file.
 */

static void
splitfile(char *longname, int ifd, char *name, char *prefix, int filetype)
{
	blkcnt_t blocks;
	off_t bytes, s;
	char buf[TBLOCK];
	int i, extents;

	blocks = TBLOCKS(stbuf.st_size);	/* blocks file needs */

	/*
	 * # extents =
	 *	size of file after using up rest of this floppy
	 *		blocks - (blocklim - tapepos) + 1	(for header)
	 *	plus roundup value before divide by blocklim-1
	 *		+ (blocklim - 1) - 1
	 *	all divided by blocklim-1 (one block for each header).
	 * this gives
	 *	(blocks - blocklim + tapepos + 1 + blocklim - 2)/(blocklim-1)
	 * which reduces to the expression used.
	 * one is added to account for this first extent.
	 *
	 * When one is dealing with extremely large archives, one may want
	 * to allow for a large number of extents.  This code should be
	 * revisited to determine if extents should be changed to something
	 * larger than an int.
	 */
	extents = (int)((blocks + tapepos - 1ULL)/(blocklim - 1ULL) + 1);

	if (extents < 2 || extents > MAXEXT) {	/* let's be reasonable */
		(void) fprintf(stderr, gettext(
		    "tar: %s needs unusual number of volumes to split\n"
		    "tar: %s not dumped\n"), longname, longname);
		return;
	}
	if (build_dblock(name, tchar, '0', filetype,
	    &stbuf, stbuf.st_dev, prefix) != 0)
		return;

	dblock.dbuf.extotal = extents;
	bytes = stbuf.st_size;

	/*
	 * The value contained in dblock.dbuf.efsize was formerly used when the
	 * v flag was specified in conjunction with the t flag. Although it is
	 * no longer used, older versions of tar will expect the former
	 * behaviour, so we must continue to write it to the archive.
	 *
	 * Since dblock.dbuf.efsize is 10 chars in size, the maximum value it
	 * can store is TAR_EFSIZE_MAX. If bytes exceeds that value, simply
	 * store 0.
	 */
	if (bytes <= TAR_EFSIZE_MAX)
		(void) sprintf(dblock.dbuf.efsize, "%9" FMT_off_t_o, bytes);
	else
		(void) sprintf(dblock.dbuf.efsize, "%9" FMT_off_t_o, (off_t)0);

	(void) fprintf(stderr, gettext(
	    "tar: large file %s needs %d extents.\n"
	    "tar: current device seek position = %" FMT_blkcnt_t "K\n"),
	    longname, extents, K(tapepos));

	s = (off_t)(blocklim - tapepos - 1) * TBLOCK;
	for (i = 1; i <= extents; i++) {
		if (i > 1) {
			newvol();
			if (i == extents)
				s = bytes;	/* last ext. gets true bytes */
			else
				s = (off_t)(blocklim - 1)*TBLOCK; /* all */
		}
		bytes -= s;
		blocks = TBLOCKS(s);

		(void) sprintf(dblock.dbuf.size, "%011" FMT_off_t_o, s);
		dblock.dbuf.extno = i;
		(void) sprintf(dblock.dbuf.chksum, "%07o", checksum(&dblock));
		(void) writetbuf((char *)&dblock, 1);

		if (vflag)
			(void) fprintf(vfile,
			    gettext("+++ a %s %" FMT_blkcnt_t
			    "K [extent #%d of %d]\n"),
			    longname, K(blocks), i, extents);
		while (blocks && read(ifd, buf, TBLOCK) > 0) {
			blocks--;
			(void) writetbuf(buf, 1);
		}
		if (blocks != 0) {
			(void) fprintf(stderr, gettext(
			    "tar: %s: file changed size\n"), longname);
			(void) fprintf(stderr, gettext(
			    "tar: aborting split file %s\n"), longname);
			(void) close(ifd);
			return;
		}
	}
	(void) close(ifd);
	if (vflag)
		(void) fprintf(vfile, gettext("a %s %" FMT_off_t "K (in %d "
		    "extents)\n"), longname, K(TBLOCKS(stbuf.st_size)),
		    extents);
}

/*
 *	convtoreg - determines whether the file should be converted to a
 *	            regular file when extracted
 *
 *	Returns 1 when file size > 0 and typeflag is not recognized
 * 	Otherwise returns 0
 */
static int
convtoreg(off_t size)
{
	if ((size > 0) && (dblock.dbuf.typeflag != '0') &&
	    (dblock.dbuf.typeflag != NULL) && (dblock.dbuf.typeflag != '1') &&
	    (dblock.dbuf.typeflag != '2') && (dblock.dbuf.typeflag != '3') &&
	    (dblock.dbuf.typeflag != '4') && (dblock.dbuf.typeflag != '5') &&
	    (dblock.dbuf.typeflag != '6') && (dblock.dbuf.typeflag != 'A') &&
	    (dblock.dbuf.typeflag != 'L') &&
	    (dblock.dbuf.typeflag != _XATTR_HDRTYPE) &&
	    (dblock.dbuf.typeflag != 'X')) {
		return (1);
	}
	return (0);
}

#if defined(O_XATTR)
static int
save_cwd(void)
{
	return (open(".", O_RDONLY));
}
#endif

#if defined(O_XATTR)
static void
rest_cwd(int *cwd)
{
	if (*cwd != -1) {
		if (fchdir(*cwd) < 0) {
			vperror(0, gettext(
			    "Cannot fchdir to attribute directory"));
			exit(1);
		}
		(void) close(*cwd);
		*cwd = -1;
	}
}
#endif

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

	if (atflag) {
		if (!*ext_attrflg) {
#if defined(_PC_SATTR_ENABLED)
			if (saflag) {
				/* Verify system attributes are supported */
				if (sysattr_support(filename,
				    (actflag == ARC_CREATE) ? _PC_SATTR_EXISTS :
				    _PC_SATTR_ENABLED) != 1) {
					return (ATTR_SATTR_ERR);
				}
			} else
				return (ATTR_XATTR_ERR);
#else
				return (ATTR_XATTR_ERR);
#endif	/* _PC_SATTR_ENABLED */
		}

#if defined(_PC_SATTR_ENABLED)
	} else if (saflag) {
		/* Verify system attributes are supported */
		if (sysattr_support(filename, (actflag == ARC_CREATE) ?
		    _PC_SATTR_EXISTS : _PC_SATTR_ENABLED) != 1) {
			return (ATTR_SATTR_ERR);
		}
#endif	/* _PC_SATTR_ENABLED */
	} else {
		return (ATTR_SKIP);
	}

	return (ATTR_OK);
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
 *		attrinfo->parent = NULL
 *		attrname = '.'
 *	2.  Open the attribute directory of the base file and change into it.
 *		attrinfo->parent = NULL
 *		attrname = <attr> | <sys_attr>
 *	3.  Open the attribute directory of the base file, change into it,
 *	    then recursively call open_attr_dir() to open the attribute's
 *	    parent directory (don't change into it).
 *		attrinfo->parent = <attr>
 *		attrname = '.'
 *	4.  Open the attribute directory of the base file, change into it,
 *	    then recursively call open_attr_dir() to open the attribute's
 *	    parent directory and change into it.
 *		attrinfo->parent = <attr>
 *		attrname = <attr> | <sys_attr>
 *
 * An attribute directory will be opened only if the underlying file system
 * supports the attribute type, and if the command line specifications (atflag
 * and saflag) enable the processing of the attribute type.
 *
 * On succesful return, attrinfo->parentfd will be the file descriptor of the
 * opened attribute directory.  In addition, if the attribute is a read-write
 * extended system attribute, attrinfo->rw_sysattr will be set to 1, otherwise
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
open_attr_dir(char *attrname, char *dirp, int cwd, attr_data_t *attrinfo)
{
	attr_status_t	rc;
	int		firsttime = (attrinfo->attr_parentfd == -1);
	int		saveerrno;
	int		ext_attr;

	/*
	 * open_attr_dir() was recursively called (input combination number 4),
	 * close the previously opened file descriptor as we've already changed
	 * into it.
	 */
	if (!firsttime) {
		(void) close(attrinfo->attr_parentfd);
		attrinfo->attr_parentfd = -1;
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
	if ((attrinfo->attr_parentfd = attropen(dirp, ".", O_RDONLY)) == -1) {
		/*
		 * Save the errno from the attropen so it can be reported
		 * if the retry of the attropen fails.
		 */
		saveerrno = errno;
		if ((attrinfo->attr_parentfd = retry_open_attr(-1, cwd, dirp,
		    NULL, ".", O_RDONLY, 0)) == -1) {
			/*
			 * Reset typeflag back to real value so passtape
			 * will skip ahead correctly.
			 */
			dblock.dbuf.typeflag = _XATTR_HDRTYPE;
			(void) close(attrinfo->attr_parentfd);
			attrinfo->attr_parentfd = -1;
			errno = saveerrno;
			return (ATTR_OPEN_ERR);
		}
	}

	/*
	 * Change into the parent attribute's directory unless we are
	 * processing the hidden attribute directory of the base file itself.
	 */
	if ((Hiddendir == 0) || (firsttime && attrinfo->attr_parent != NULL)) {
		if (fchdir(attrinfo->attr_parentfd) != 0) {
			saveerrno = errno;
			(void) close(attrinfo->attr_parentfd);
			attrinfo->attr_parentfd = -1;
			errno = saveerrno;
			return (ATTR_CHDIR_ERR);
		}
	}

	/* Determine if the attribute should be processed */
	if ((rc = verify_attr(attrname, attrinfo->attr_parent, 1,
	    &attrinfo->attr_rw_sysattr)) != ATTR_OK) {
		saveerrno = errno;
		(void) close(attrinfo->attr_parentfd);
		attrinfo->attr_parentfd = -1;
		errno = saveerrno;
		return (rc);
	}

	/*
	 * If the attribute is an extended attribute, or extended system
	 * attribute, of an attribute (i.e., <attr>/<sys_attr>), then
	 * recursively call open_attr_dir() to open the attribute directory
	 * of the parent attribute.
	 */
	if (firsttime && (attrinfo->attr_parent != NULL)) {
		return (open_attr_dir(attrname, attrinfo->attr_parent,
		    attrinfo->attr_parentfd, attrinfo));
	}

	return (ATTR_OK);
}
#endif

static void
doxtract(char *argv[])
{
	struct	stat	xtractbuf;	/* stat on file after extracting */
	blkcnt_t blocks;
	off_t bytes;
	int ofile;
	int newfile;			/* Does the file already exist  */
	int xcnt = 0;			/* count # files extracted */
	int fcnt = 0;			/* count # files in argv list */
	int dir;
	int dirfd = -1;
	int cwd = -1;
	int rw_sysattr;
	int saveerrno;
	uid_t Uid;
	char *namep, *dirp, *comp, *linkp; /* for removing absolute paths */
	char dirname[PATH_MAX+1];
	char templink[PATH_MAX+1];	/* temp link with terminating NULL */
	int once = 1;
	int error;
	int symflag;
	int want;
	attr_data_t *attrinfo = NULL;	/* attribute info */
	acl_t	*aclp = NULL;	/* acl info */
	char dot[] = ".";		/* dirp for using realpath */
	timestruc_t	time_zero;	/* used for call to doDirTimes */
	int		dircreate;
	int convflag;
	time_zero.tv_sec = 0;
	time_zero.tv_nsec = 0;

	/* reset Trusted Extensions variables */
	rpath_flag = 0;
	lk_rpath_flag = 0;
	dir_flag = 0;
	mld_flag = 0;
	bslundef(&bs_label);
	bsllow(&admin_low);
	bslhigh(&admin_high);
	orig_namep = 0;

	dumping = 0;	/* for newvol(), et al:  we are not writing */

	Uid = getuid();

	for (;;) {
		convflag = 0;
		symflag = 0;
		dir = 0;
		Hiddendir = 0;
		rw_sysattr = 0;
		ofile = -1;

		if (dirfd != -1) {
			(void) close(dirfd);
			dirfd = -1;
		}
		if (ofile != -1) {
			if (close(ofile) != 0)
				vperror(2, gettext("close error"));
		}

#if defined(O_XATTR)
		if (cwd != -1) {
			rest_cwd(&cwd);
		}
#endif

		/* namep is set by wantit to point to the full name */
		if ((want = wantit(argv, &namep, &dirp, &comp,
		    &attrinfo)) == 0) {
#if defined(O_XATTR)
			if (xattrp != NULL) {
				free(xattrhead);
				xattrp = NULL;
				xattr_linkp = NULL;
				xattrhead = NULL;
			}
#endif
			continue;
		}
		if (want == -1)
			break;

/* Trusted Extensions */
		/*
		 * During tar extract (x):
		 * If the pathname of the restored file has been
		 * reconstructed from the ancillary file,
		 * use it to process the normal file.
		 */
		if (mld_flag) {		/* Skip over .MLD. directory */
			mld_flag = 0;
			passtape();
			continue;
		}
		orig_namep = namep;	/* save original */
		if (rpath_flag) {
			namep = real_path;	/* use zone path */
			comp = real_path;	/* use zone path */
			dirp = dot;		/* work from the top */
			rpath_flag = 0;		/* reset */
		}

		if (dirfd != -1)
			(void) close(dirfd);

		(void) strcpy(&dirname[0], namep);
		dircreate = checkdir(&dirname[0]);

#if defined(O_XATTR)
		if (xattrp != NULL) {
			int	rc;

			if (((cwd = save_cwd()) == -1) ||
			    ((rc = open_attr_dir(comp, dirp, cwd,
			    attrinfo)) != ATTR_OK)) {
				if (cwd == -1) {
					vperror(0, gettext(
					    "unable to save current working "
					    "directory while processing "
					    "attribute %s of %s"),
					    dirp, attrinfo->attr_path);
				} else if (rc != ATTR_SKIP) {
					(void) fprintf(vfile,
					    gettext("tar: cannot open "
					    "%sattribute %s of file %s: %s\n"),
					    attrinfo->attr_rw_sysattr ? gettext(
					    "system ") : "",
					    comp, dirp, strerror(errno));
				}
				free(xattrhead);
				xattrp = NULL;
				xattr_linkp = NULL;
				xattrhead = NULL;

				passtape();
				continue;
			} else {
				dirfd = attrinfo->attr_parentfd;
				rw_sysattr = attrinfo->attr_rw_sysattr;
			}
		} else {
			dirfd = open(dirp, O_RDONLY);
		}
#else
		dirfd = open(dirp, O_RDONLY);
#endif
		if (dirfd == -1) {
			(void) fprintf(vfile, gettext(
			    "tar: cannot open %s: %s\n"),
			    dirp, strerror(errno));
			passtape();
			continue;
		}

		if (xhdr_flgs & _X_LINKPATH)
			(void) strcpy(templink, Xtarhdr.x_linkpath);
		else {
#if defined(O_XATTR)
			if (xattrp && dblock.dbuf.typeflag == '1') {
				(void) sprintf(templink, "%.*s", NAMSIZ,
				    xattrp->h_names);
			} else {
				(void) sprintf(templink, "%.*s", NAMSIZ,
				    dblock.dbuf.linkname);
			}
#else
			(void) sprintf(templink, "%.*s", NAMSIZ,
			    dblock.dbuf.linkname);
#endif
		}

		if (Fflag) {
			if (checkf(namep, is_directory(namep), Fflag) == 0) {
				passtape();
				continue;
			}
		}

		if (checkw('x', namep) == 0) {
			passtape();
			continue;
		}
		if (once) {
			if (strcmp(dblock.dbuf.magic, magic_type) == 0) {
				if (geteuid() == (uid_t)0) {
					checkflag = 1;
					pflag = 1;
				} else {
					/* get file creation mask */
					Oumask = umask(0);
					(void) umask(Oumask);
				}
				once = 0;
			} else {
				if (geteuid() == (uid_t)0) {
					pflag = 1;
					checkflag = 2;
				}
				if (!pflag) {
					/* get file creation mask */
					Oumask = umask(0);
					(void) umask(Oumask);
				}
				once = 0;
			}
		}

#if defined(O_XATTR)
		/*
		 * Handle extraction of hidden attr dir.
		 * Dir is automatically created, we only
		 * need to update mode and perm's.
		 */
		if ((xattrp != NULL) && Hiddendir == 1) {
			bytes = stbuf.st_size;
			blocks = TBLOCKS(bytes);
			if (vflag) {
				(void) fprintf(vfile,
				    "x %s%s%s, %" FMT_off_t " %s, ", namep,
				    gettext(" attribute "),
				    xattrapath, bytes,
				    gettext("bytes"));
				if (NotTape)
					(void) fprintf(vfile,
					    "%" FMT_blkcnt_t "K\n", K(blocks));
				else
					(void) fprintf(vfile, gettext("%"
					    FMT_blkcnt_t " tape blocks\n"),
					    blocks);
			}

			/*
			 * Set the permissions and mode of the attribute
			 * unless the attribute is a system attribute (can't
			 * successfully do this) or the hidden attribute
			 * directory (".") of an attribute (when the attribute
			 * is restored, the hidden attribute directory of an
			 * attribute is transient).  Note:  when the permissions
			 * and mode are set for the hidden attribute directory
			 * of a file on a system supporting extended system
			 * attributes, even though it returns successfully, it
			 * will not have any affect since the attribute
			 * directory is transient.
			 */
			if (attrinfo->attr_parent == NULL) {
				if (fchownat(dirfd, ".", stbuf.st_uid,
				    stbuf.st_gid, 0) != 0) {
					vperror(0, gettext(
					    "%s%s%s: failed to set ownership "
					    "of attribute directory"), namep,
					    gettext(" attribute "), xattrapath);
				}

				if (fchmod(dirfd, stbuf.st_mode) != 0) {
					vperror(0, gettext(
					    "%s%s%s: failed to set permissions "
					    "of attribute directory"), namep,
					    gettext(" attribute "), xattrapath);
				}
			}
			goto filedone;
		}
#endif

		if (dircreate && (!is_posix || dblock.dbuf.typeflag == '5')) {
			dir = 1;
			if (vflag) {
				(void) fprintf(vfile, "x %s, 0 %s, ",
				    &dirname[0], gettext("bytes"));
				if (NotTape)
					(void) fprintf(vfile, "0K\n");
				else
					(void) fprintf(vfile, gettext("%"
					    FMT_blkcnt_t " tape blocks\n"),
					    (blkcnt_t)0);
			}
			goto filedone;
		}

		if (dblock.dbuf.typeflag == '6') {	/* FIFO */
			if (rmdir(namep) < 0) {
				if (errno == ENOTDIR)
					(void) unlink(namep);
			}
			linkp = templink;
			if (*linkp !=  NULL) {
				if (Aflag && *linkp == '/')
					linkp++;
				if (link(linkp, namep) < 0) {
					(void) fprintf(stderr, gettext(
					    "tar: %s: cannot link\n"), namep);
					continue;
				}
				if (vflag)
					(void) fprintf(vfile, gettext(
					    "x %s linked to %s\n"), namep,
					    linkp);
				xcnt++;	 /* increment # files extracted */
				continue;
			}
			if (mknod(namep, (int)(Gen.g_mode|S_IFIFO),
			    (int)Gen.g_devmajor) < 0) {
				vperror(0, gettext("%s: mknod failed"), namep);
				continue;
			}
			bytes = stbuf.st_size;
			blocks = TBLOCKS(bytes);
			if (vflag) {
				(void) fprintf(vfile, "x %s, %" FMT_off_t
				    " %s, ", namep, bytes, gettext("bytes"));
				if (NotTape)
					(void) fprintf(vfile, "%" FMT_blkcnt_t
					    "K\n", K(blocks));
				else
					(void) fprintf(vfile, gettext("%"
					    FMT_blkcnt_t " tape blocks\n"),
					    blocks);
			}
			goto filedone;
		}
		if (dblock.dbuf.typeflag == '3' && !Uid) { /* CHAR SPECIAL */
			if (rmdir(namep) < 0) {
				if (errno == ENOTDIR)
					(void) unlink(namep);
			}
			linkp = templink;
			if (*linkp != NULL) {
				if (Aflag && *linkp == '/')
					linkp++;
				if (link(linkp, namep) < 0) {
					(void) fprintf(stderr, gettext(
					    "tar: %s: cannot link\n"), namep);
					continue;
				}
				if (vflag)
					(void) fprintf(vfile, gettext(
					    "x %s linked to %s\n"), namep,
					    linkp);
				xcnt++;	 /* increment # files extracted */
				continue;
			}
			if (mknod(namep, (int)(Gen.g_mode|S_IFCHR),
			    (int)makedev(Gen.g_devmajor, Gen.g_devminor)) < 0) {
				vperror(0, gettext(
				    "%s: mknod failed"), namep);
				continue;
			}
			bytes = stbuf.st_size;
			blocks = TBLOCKS(bytes);
			if (vflag) {
				(void) fprintf(vfile, "x %s, %" FMT_off_t
				    " %s, ", namep, bytes, gettext("bytes"));
				if (NotTape)
					(void) fprintf(vfile, "%" FMT_blkcnt_t
					    "K\n", K(blocks));
				else
					(void) fprintf(vfile, gettext("%"
					    FMT_blkcnt_t " tape blocks\n"),
					    blocks);
			}
			goto filedone;
		} else if (dblock.dbuf.typeflag == '3' && Uid) {
			(void) fprintf(stderr, gettext(
			    "Can't create special %s\n"), namep);
			continue;
		}

		/* BLOCK SPECIAL */

		if (dblock.dbuf.typeflag == '4' && !Uid) {
			if (rmdir(namep) < 0) {
				if (errno == ENOTDIR)
					(void) unlink(namep);
			}
			linkp = templink;
			if (*linkp != NULL) {
				if (Aflag && *linkp == '/')
					linkp++;
				if (link(linkp, namep) < 0) {
					(void) fprintf(stderr, gettext(
					    "tar: %s: cannot link\n"), namep);
					continue;
				}
				if (vflag)
					(void) fprintf(vfile, gettext(
					    "x %s linked to %s\n"), namep,
					    linkp);
				xcnt++;	 /* increment # files extracted */
				continue;
			}
			if (mknod(namep, (int)(Gen.g_mode|S_IFBLK),
			    (int)makedev(Gen.g_devmajor, Gen.g_devminor)) < 0) {
				vperror(0, gettext("%s: mknod failed"), namep);
				continue;
			}
			bytes = stbuf.st_size;
			blocks = TBLOCKS(bytes);
			if (vflag) {
				(void) fprintf(vfile, gettext("x %s, %"
				    FMT_off_t " bytes, "), namep, bytes);
				if (NotTape)
					(void) fprintf(vfile, "%" FMT_blkcnt_t
					    "K\n", K(blocks));
				else
					(void) fprintf(vfile, gettext("%"
					    FMT_blkcnt_t " tape blocks\n"),
					    blocks);
			}
			goto filedone;
		} else if (dblock.dbuf.typeflag == '4' && Uid) {
			(void) fprintf(stderr,
			    gettext("Can't create special %s\n"), namep);
			continue;
		}
		if (dblock.dbuf.typeflag == '2') {	/* symlink */
			if ((Tflag) && (lk_rpath_flag == 1))
				linkp = lk_real_path;
			else
				linkp = templink;
			if (Aflag && *linkp == '/')
				linkp++;
			if (rmdir(namep) < 0) {
				if (errno == ENOTDIR)
					(void) unlink(namep);
			}
			if (symlink(linkp, namep) < 0) {
				vperror(0, gettext("%s: symbolic link failed"),
				    namep);
				continue;
			}
			if (vflag)
				(void) fprintf(vfile, gettext(
				    "x %s symbolic link to %s\n"),
				    namep, linkp);

			symflag = AT_SYMLINK_NOFOLLOW;
			goto filedone;
		}
		if (dblock.dbuf.typeflag == '1') {
			linkp = templink;
			if (Aflag && *linkp == '/')
				linkp++;
			if (unlinkat(dirfd, comp, AT_REMOVEDIR) < 0) {
				if (errno == ENOTDIR)
					(void) unlinkat(dirfd, comp, 0);
			}
#if defined(O_XATTR)
			if (xattrp && xattr_linkp) {
				if (fchdir(dirfd) < 0) {
					vperror(0, gettext(
					    "Cannot fchdir to attribute "
					    "directory %s"),
					    (attrinfo->attr_parent == NULL) ?
					    dirp : attrinfo->attr_parent);
					exit(1);
				}

				error = link(xattr_linkaname, xattrapath);
			} else {
				error = link(linkp, namep);
			}
#else
			error = link(linkp, namep);
#endif

			if (error < 0) {
				(void) fprintf(stderr, gettext(
				    "tar: %s%s%s: cannot link\n"),
				    namep, (xattr_linkp != NULL) ?
				    gettext(" attribute ") : "",
				    (xattr_linkp != NULL) ?
				    xattrapath : "");
				continue;
			}
			if (vflag)
				(void) fprintf(vfile, gettext(
				    "x %s%s%s linked to %s%s%s\n"), namep,
				    (xattr_linkp != NULL) ?
				    gettext(" attribute ") : "",
				    (xattr_linkp != NULL) ?
				    xattr_linkaname : "",
				    linkp,
				    (xattr_linkp != NULL) ?
				    gettext(" attribute ") : "",
				    (xattr_linkp != NULL) ? xattrapath : "");
			xcnt++;		/* increment # files extracted */
#if defined(O_XATTR)
			if (xattrp != NULL) {
				free(xattrhead);
				xattrp = NULL;
				xattr_linkp = NULL;
				xattrhead = NULL;
			}
#endif
			continue;
		}

		/* REGULAR FILES */

		if (convtoreg(stbuf.st_size)) {
			convflag = 1;
			if (errflag) {
				(void) fprintf(stderr, gettext(
				    "tar: %s: typeflag '%c' not recognized\n"),
				    namep, dblock.dbuf.typeflag);
				done(1);
			} else {
				(void) fprintf(stderr, gettext(
				    "tar: %s: typeflag '%c' not recognized, "
				    "converting to regular file\n"), namep,
				    dblock.dbuf.typeflag);
				Errflg = 1;
			}
		}
		if (dblock.dbuf.typeflag == '0' ||
		    dblock.dbuf.typeflag == NULL || convflag) {
			delete_target(dirfd, comp, namep);
			linkp = templink;
			if (*linkp != NULL) {
				if (Aflag && *linkp == '/')
					linkp++;
				if (link(linkp, comp) < 0) {
					(void) fprintf(stderr, gettext(
					    "tar: %s: cannot link\n"), namep);
					continue;
				}
				if (vflag)
					(void) fprintf(vfile, gettext(
					    "x %s linked to %s\n"), comp,
					    linkp);
				xcnt++;	 /* increment # files extracted */
#if defined(O_XATTR)
				if (xattrp != NULL) {
					free(xattrhead);
					xattrp = NULL;
					xattr_linkp = NULL;
					xattrhead = NULL;
				}
#endif
				continue;
			}
		newfile = ((fstatat(dirfd, comp,
		    &xtractbuf, 0) == -1) ? TRUE : FALSE);
		ofile = openat(dirfd, comp, O_RDWR|O_CREAT|O_TRUNC,
		    stbuf.st_mode & MODEMASK);
		saveerrno = errno;

#if defined(O_XATTR)
		if (xattrp != NULL) {
			if (ofile < 0) {
				ofile = retry_open_attr(dirfd, cwd,
				    dirp, attrinfo->attr_parent, comp,
				    O_RDWR|O_CREAT|O_TRUNC,
				    stbuf.st_mode & MODEMASK);
			}
		}
#endif
		if (ofile < 0) {
			errno = saveerrno;
			(void) fprintf(stderr, gettext(
			    "tar: %s%s%s%s - cannot create\n"),
			    (xattrp == NULL) ? "" : (rw_sysattr ?
			    gettext("system attribute ") :
			    gettext("attribute ")),
			    (xattrp == NULL) ? "" : xattrapath,
			    (xattrp == NULL) ? "" : gettext(" of "),
			    (xattrp == NULL) ? comp : namep);
			if (errflag)
				done(1);
			else
				Errflg = 1;
#if defined(O_XATTR)
			if (xattrp != NULL) {
				dblock.dbuf.typeflag = _XATTR_HDRTYPE;
				free(xattrhead);
				xattrp = NULL;
				xattr_linkp = NULL;
				xattrhead = NULL;
			}
#endif
			passtape();
			continue;
		}

		if (Tflag && (check_ext_attr(namep) == 0)) {
			if (errflag)
				done(1);
			else
				Errflg = 1;
			passtape();
			continue;
		}

		if (extno != 0) {	/* file is in pieces */
			if (extotal < 1 || extotal > MAXEXT)
				(void) fprintf(stderr, gettext(
				    "tar: ignoring bad extent info for "
				    "%s%s%s%s\n"),
				    (xattrp == NULL) ? "" : (rw_sysattr ?
				    gettext("system attribute ") :
				    gettext("attribute ")),
				    (xattrp == NULL) ? "" : xattrapath,
				    (xattrp == NULL) ? "" : gettext(" of "),
				    (xattrp == NULL) ? comp : namep);
			else {
				/* extract it */
				(void) xsfile(rw_sysattr, ofile);
			}
		}
		extno = 0;	/* let everyone know file is not split */
		bytes = stbuf.st_size;
		blocks = TBLOCKS(bytes);
		if (vflag) {
			(void) fprintf(vfile,
			    "x %s%s%s, %" FMT_off_t " %s, ",
			    (xattrp == NULL) ? "" : dirp,
			    (xattrp == NULL) ? "" : (rw_sysattr ?
			    gettext(" system attribute ") :
			    gettext(" attribute ")),
			    (xattrp == NULL) ? namep : xattrapath, bytes,
			    gettext("bytes"));
			if (NotTape)
				(void) fprintf(vfile, "%" FMT_blkcnt_t "K\n",
				    K(blocks));
			else
				(void) fprintf(vfile, gettext("%"
				    FMT_blkcnt_t " tape blocks\n"), blocks);
		}

		if (xblocks(rw_sysattr, bytes, ofile) != 0) {
#if defined(O_XATTR)
			if (xattrp != NULL) {
				free(xattrhead);
				xattrp = NULL;
				xattr_linkp = NULL;
				xattrhead = NULL;
			}
#endif
			continue;
		}
filedone:
		if (mflag == 0 && !symflag) {
			if (dir)
				doDirTimes(namep, stbuf.st_mtim);

			else
#if defined(O_XATTR)
				if (xattrp != NULL) {
					/*
					 * Set the time on the attribute unless
					 * the attribute is a system attribute
					 * (can't successfully do this) or the
					 * hidden attribute directory, "." (the
					 * time on the hidden attribute
					 * directory will be updated when
					 * attributes are restored, otherwise
					 * it's transient).
					 */
					if (!rw_sysattr && (Hiddendir == 0)) {
						setPathTimes(dirfd, comp,
						    stbuf.st_mtim);
					}
				} else
					setPathTimes(dirfd, comp,
					    stbuf.st_mtim);
#else
				setPathTimes(dirfd, comp, stbuf.st_mtim);
#endif
		}

		/* moved this code from above */
		if (pflag && !symflag && Hiddendir == 0) {
			if (xattrp != NULL)
				(void) fchmod(ofile, stbuf.st_mode & MODEMASK);
			else
				(void) chmod(namep, stbuf.st_mode & MODEMASK);
		}


		/*
		 * Because ancillary file preceeds the normal file,
		 * acl info may have been retrieved (in aclp).
		 * All file types are directed here (go filedone).
		 * Always restore ACLs if there are ACLs.
		 */
		if (aclp != NULL) {
			int ret;

#if defined(O_XATTR)
			if (xattrp != NULL) {
				if (Hiddendir)
					ret = facl_set(dirfd, aclp);
				else
					ret = facl_set(ofile, aclp);
			} else {
				ret = acl_set(namep, aclp);
			}
#else
			ret = acl_set(namep, aclp);
#endif
			if (ret < 0) {
				if (pflag) {
					(void) fprintf(stderr, gettext(
					    "%s%s%s%s: failed to set acl "
					    "entries\n"), namep,
					    (xattrp == NULL) ? "" :
					    (rw_sysattr ? gettext(
					    " system attribute ") :
					    gettext(" attribute ")),
					    (xattrp == NULL) ? "" :
					    xattrapath);
				}
				/* else: silent and continue */
			}
			acl_free(aclp);
			aclp = NULL;
		}

		if (!oflag)
			/* set file ownership */
			resugname(dirfd, comp, symflag);

		if (pflag && newfile == TRUE && !dir &&
		    (dblock.dbuf.typeflag == '0' ||
		    dblock.dbuf.typeflag == NULL ||
		    convflag || dblock.dbuf.typeflag == '1')) {
			if (fstat(ofile, &xtractbuf) == -1)
				(void) fprintf(stderr, gettext(
				    "tar: cannot stat extracted file "
				    "%s%s%s%s\n"),
				    (xattrp == NULL) ? "" : (rw_sysattr ?
				    gettext("system attribute ") :
				    gettext("attribute ")),
				    (xattrp == NULL) ? "" : xattrapath,
				    (xattrp == NULL) ? "" :
				    gettext(" of "), namep);

			else if ((xtractbuf.st_mode & (MODEMASK & ~S_IFMT))
			    != (stbuf.st_mode & (MODEMASK & ~S_IFMT))) {
				(void) fprintf(stderr, gettext(
				    "tar: warning - file permissions have "
				    "changed for %s%s%s%s (are 0%o, should be "
				    "0%o)\n"),
				    (xattrp == NULL) ? "" : (rw_sysattr ?
				    gettext("system attribute ") :
				    gettext("attribute ")),
				    (xattrp == NULL) ? "" : xattrapath,
				    (xattrp == NULL) ? "" :
				    gettext(" of "), namep,
				    xtractbuf.st_mode, stbuf.st_mode);

			}
		}
#if defined(O_XATTR)
		if (xattrp != NULL) {
			free(xattrhead);
			xattrp = NULL;
			xattr_linkp = NULL;
			xattrhead = NULL;
		}
#endif

		if (ofile != -1) {
			(void) close(dirfd);
			dirfd = -1;
			if (close(ofile) != 0)
				vperror(2, gettext("close error"));
			ofile = -1;
		}
		xcnt++;			/* increment # files extracted */
		}

		/*
		 * Process ancillary file.
		 *
		 */

		if (dblock.dbuf.typeflag == 'A') {	/* acl info */
			char	buf[TBLOCK];
			char	*secp;
			char	*tp;
			int	attrsize;
			int	cnt;

			/* reset Trusted Extensions flags */
			dir_flag = 0;
			mld_flag = 0;
			lk_rpath_flag = 0;
			rpath_flag = 0;

			if (pflag) {
				bytes = stbuf.st_size;
				if ((secp = malloc((int)bytes)) == NULL) {
					(void) fprintf(stderr, gettext(
					    "Insufficient memory for acl\n"));
					passtape();
					continue;
				}
				tp = secp;
				blocks = TBLOCKS(bytes);

				/*
				 * Display a line for each ancillary file.
				 */
				if (vflag && Tflag)
					(void) fprintf(vfile, "x %s(A), %"
					    FMT_blkcnt_t " %s, %"
					    FMT_blkcnt_t " %s\n",
					    namep, bytes, gettext("bytes"),
					    blocks, gettext("tape blocks"));

				while (blocks-- > 0) {
					readtape(buf);
					if (bytes <= TBLOCK) {
						(void) memcpy(tp, buf,
						    (size_t)bytes);
						break;
					} else {
						(void) memcpy(tp, buf,
						    TBLOCK);
						tp += TBLOCK;
					}
					bytes -= TBLOCK;
				}
				bytes = stbuf.st_size;
				/* got all attributes in secp */
				tp = secp;
				do {
					attr = (struct sec_attr *)tp;
					switch (attr->attr_type) {
					case UFSD_ACL:
					case ACE_ACL:
						(void) sscanf(attr->attr_len,
						    "%7o",
						    (uint_t *)
						    &cnt);
						/* header is 8 */
						attrsize = 8 + (int)strlen(
						    &attr->attr_info[0]) + 1;
						error =
						    acl_fromtext(
						    &attr->attr_info[0], &aclp);

						if (error != 0) {
							(void) fprintf(stderr,
							    gettext(
							    "aclfromtext "
							    "failed: %s\n"),
							    acl_strerror(
							    error));
							bytes -= attrsize;
							break;
						}
						if (acl_cnt(aclp) != cnt) {
							(void) fprintf(stderr,
							    gettext(
							    "aclcnt error\n"));
							bytes -= attrsize;
							break;
						}
						bytes -= attrsize;
						break;

					/* Trusted Extensions */

					case DIR_TYPE:
					case LBL_TYPE:
					case APRIV_TYPE:
					case FPRIV_TYPE:
					case COMP_TYPE:
					case LK_COMP_TYPE:
					case ATTR_FLAG_TYPE:
						attrsize =
						    sizeof (struct sec_attr) +
						    strlen(&attr->attr_info[0]);
						bytes -= attrsize;
						if (Tflag)
							extract_attr(&namep,
							    attr);
						break;

					default:
						(void) fprintf(stderr, gettext(
						    "unrecognized attr"
						    " type\n"));
						bytes = (off_t)0;
						break;
					}

					/* next attributes */
					tp += attrsize;
				} while (bytes != 0);
				free(secp);
			} else {
				passtape();
			}
		} /* acl */

	} /* for */

	/*
	 *  Ensure that all the directories still on the directory stack
	 *  get their modification times set correctly by flushing the
	 *  stack.
	 */

	doDirTimes(NULL, time_zero);

#if defined(O_XATTR)
		if (xattrp != NULL) {
			free(xattrhead);
			xattrp = NULL;
			xattr_linkp = NULL;
			xattrhead = NULL;
		}
#endif

	/*
	 * Check if the number of files extracted is different from the
	 * number of files listed on the command line
	 */
	if (fcnt > xcnt) {
		(void) fprintf(stderr,
		    gettext("tar: %d file(s) not extracted\n"),
		    fcnt-xcnt);
		Errflg = 1;
	}
}

/*
 *	xblocks		extract file/extent from tape to output file
 *
 *	xblocks(issysattr, bytes, ofile);
 *
 *	issysattr			flag set if the files being extracted
 *					is an extended system attribute file.
 *	unsigned long long bytes	size of extent or file to be extracted
 *	ofile				output file
 *
 *	called by doxtract() and xsfile()
 */

static int
xblocks(int issysattr, off_t bytes, int ofile)
{
	char *buf;
	char tempname[NAMSIZ+1];
	size_t maxwrite;
	size_t bytesread;
	size_t piosize;		/* preferred I/O size */
	struct stat tsbuf;

	/* Don't need to do anything if this is a zero size file */
	if (bytes <= 0) {
		return (0);
	}

	/*
	 * To figure out the size of the buffer used to accumulate data
	 * from readtape() and to write to the file, we need to determine
	 * the largest chunk of data to be written to the file at one time.
	 * This is determined based on the smallest of the following two
	 * things:
	 *	1) The size of the archived file.
	 *	2) The preferred I/O size of the file.
	 */
	if (issysattr || (bytes <= TBLOCK)) {
		/*
		 * Writes to system attribute files must be
		 * performed in one operation.
		 */
		maxwrite = bytes;
	} else {
		/*
		 * fstat() the file to get the preferred I/O size.
		 * If it fails, then resort back to just writing
		 * one block at a time.
		 */
		if (fstat(ofile, &tsbuf) == 0) {
			piosize = tsbuf.st_blksize;
		} else {
			piosize = TBLOCK;
		}
		maxwrite = min(bytes, piosize);
	}

	/*
	 * The buffer used to accumulate the data for the write operation
	 * needs to be the maximum number of bytes to be written rounded up
	 * to the nearest TBLOCK since readtape reads one block at a time.
	 */
	if ((buf = malloc(TBLOCKS(maxwrite) * TBLOCK)) == NULL) {
		fatal(gettext("cannot allocate buffer"));
	}

	while (bytes > 0) {

		/*
		 * readtape() obtains one block (TBLOCK) of data at a time.
		 * Accumulate as many blocks of data in buf as we can write
		 * in one operation.
		 */
		for (bytesread = 0; bytesread < maxwrite; bytesread += TBLOCK) {
			readtape(buf + bytesread);
		}

		if (write(ofile, buf, maxwrite) < 0) {
			int saveerrno = errno;

			if (xhdr_flgs & _X_PATH)
				(void) strlcpy(tempname, Xtarhdr.x_path,
				    sizeof (tempname));
			else
				(void) sprintf(tempname, "%.*s", NAMSIZ,
				    dblock.dbuf.name);
			/*
			 * If the extended system attribute being extracted
			 * contains attributes that the user needs privileges
			 * for, then just display a warning message, skip
			 * the extraction of this file, and return.
			 */
			if ((saveerrno == EPERM) && issysattr) {
				(void) fprintf(stderr, gettext(
				    "tar: unable to extract system attribute "
				    "%s: insufficient privileges\n"), tempname);
				Errflg = 1;
				(void) free(buf);
				return (1);
			} else {
				(void) fprintf(stderr, gettext(
				    "tar: %s: HELP - extract write error\n"),
				    tempname);
				done(2);
			}
		}
		bytes -= maxwrite;

		/*
		 * If we've reached this point and there is still data
		 * to be written, maxwrite had to have been determined
		 * by the preferred I/O size.  If the number of bytes
		 * left to write is smaller than the preferred I/O size,
		 * then we're about to do our final write to the file, so
		 * just set maxwrite to the number of bytes left to write.
		 */
		if ((bytes > 0) && (bytes < maxwrite)) {
			maxwrite = bytes;
		}
	}
	free(buf);

	return (0);
}

/*
 * 	xsfile	extract split file
 *
 *	xsfile(ofd);	ofd = output file descriptor
 *
 *	file extracted and put in ofd via xblocks()
 *
 *	NOTE:  only called by doxtract() to extract one large file
 */

static	union	hblock	savedblock;	/* to ensure same file across volumes */

static int
xsfile(int issysattr, int ofd)
{
	int i, c;
	int sysattrerr = 0;
	char name[PATH_MAX+1];	/* holds name for diagnostics */
	int extents, totalext;
	off_t bytes, totalbytes;

	if (xhdr_flgs & _X_PATH)
		(void) strcpy(name, Xtarhdr.x_path);
	else
		(void) sprintf(name, "%.*s", NAMSIZ, dblock.dbuf.name);

	totalbytes = (off_t)0;		/* in case we read in half the file */
	totalext = 0;		/* these keep count */

	(void) fprintf(stderr, gettext(
	    "tar: %s split across %d volumes\n"), name, extotal);

	/* make sure we do extractions in order */
	if (extno != 1) {	/* starting in middle of file? */
		(void) printf(gettext(
		    "tar: first extent read is not #1\n"
		    "OK to read file beginning with extent #%d (%s/%s) ? "),
		    extno, yesstr, nostr);
		if (yes() == 0) {
canit:
			passtape();
			if (close(ofd) != 0)
				vperror(2, gettext("close error"));
			if (sysattrerr) {
				return (1);
			} else {
				return (0);
			}
		}
	}
	extents = extotal;
	i = extno;
	/*CONSTCOND*/
	while (1) {
		if (xhdr_flgs & _X_SIZE) {
			bytes = extsize;
		} else {
			bytes = stbuf.st_size;
		}

		if (vflag)
			(void) fprintf(vfile, "+++ x %s [%s #%d], %"
			    FMT_off_t " %s, %ldK\n",
			    name, gettext("extent"), extno,
			    bytes, gettext("bytes"),
			    (long)K(TBLOCKS(bytes)));
		if (xblocks(issysattr, bytes, ofd) != 0) {
			sysattrerr = 1;
			goto canit;
		}

		totalbytes += bytes;
		totalext++;
		if (++i > extents)
			break;

		/* get next volume and verify it's the right one */
		copy(&savedblock, &dblock);
tryagain:
		newvol();
		xhdr_flgs = 0;
		getdir();
		if (Xhdrflag > 0)
			(void) get_xdata();	/* Get x-header & regular hdr */
		if ((dblock.dbuf.typeflag != 'A') && (xhdr_flgs != 0)) {
			load_info_from_xtarhdr(xhdr_flgs, &Xtarhdr);
			xhdr_flgs |= _X_XHDR;
		}
		if (endtape()) {	/* seemingly empty volume */
			(void) fprintf(stderr, gettext(
			    "tar: first record is null\n"));
asknicely:
			(void) fprintf(stderr, gettext(
			    "tar: need volume with extent #%d of %s\n"),
			    i, name);
			goto tryagain;
		}
		if (notsame()) {
			(void) fprintf(stderr, gettext(
			    "tar: first file on that volume is not "
			    "the same file\n"));
			goto asknicely;
		}
		if (i != extno) {
			(void) fprintf(stderr, gettext(
			    "tar: extent #%d received out of order\ntar: "
			    "should be #%d\n"), extno, i);
			(void) fprintf(stderr, gettext(
			    "Ignore error, Abort this file, or "
			    "load New volume (i/a/n) ? "));
			c = response();
			if (c == 'a')
				goto canit;
			if (c != 'i')		/* default to new volume */
				goto asknicely;
			i = extno;		/* okay, start from there */
		}
	}
	if (vflag)
		(void) fprintf(vfile, gettext(
		    "x %s (in %d extents), %" FMT_off_t " bytes, %ldK\n"),
		    name, totalext, totalbytes, (long)K(TBLOCKS(totalbytes)));

	return (0);
}


/*
 *	notsame()	check if extract file extent is invalid
 *
 *	returns true if anything differs between savedblock and dblock
 *	except extno (extent number), checksum, or size (extent size).
 *	Determines if this header belongs to the same file as the one we're
 *	extracting.
 *
 *	NOTE:	though rather bulky, it is only called once per file
 *		extension, and it can withstand changes in the definition
 *		of the header structure.
 *
 *	WARNING:	this routine is local to xsfile() above
 */

static int
notsame(void)
{
	return (
	    (strncmp(savedblock.dbuf.name, dblock.dbuf.name, NAMSIZ)) ||
	    (strcmp(savedblock.dbuf.mode, dblock.dbuf.mode)) ||
	    (strcmp(savedblock.dbuf.uid, dblock.dbuf.uid)) ||
	    (strcmp(savedblock.dbuf.gid, dblock.dbuf.gid)) ||
	    (strcmp(savedblock.dbuf.mtime, dblock.dbuf.mtime)) ||
	    (savedblock.dbuf.typeflag != dblock.dbuf.typeflag) ||
	    (strncmp(savedblock.dbuf.linkname, dblock.dbuf.linkname, NAMSIZ)) ||
	    (savedblock.dbuf.extotal != dblock.dbuf.extotal) ||
	    (strcmp(savedblock.dbuf.efsize, dblock.dbuf.efsize)));
}

static void
dotable(char *argv[])
{
	int tcnt = 0;			/* count # files tabled */
	int fcnt = 0;			/* count # files in argv list */
	char *namep, *dirp, *comp;
	int want;
	char aclchar = ' ';			/* either blank or '+' */
	char templink[PATH_MAX+1];
	attr_data_t *attrinfo = NULL;

	dumping = 0;

	/* if not on magtape, maximize seek speed */
	if (NotTape && !bflag) {
#if SYS_BLOCK > TBLOCK
		nblock = SYS_BLOCK / TBLOCK;
#else
		nblock = 1;
#endif
	}

	for (;;) {

		/* namep is set by wantit to point to the full name */
		if ((want = wantit(argv, &namep, &dirp, &comp, &attrinfo)) == 0)
			continue;
		if (want == -1)
			break;
		if (dblock.dbuf.typeflag != 'A')
			++tcnt;

		if (Fflag) {
			if (checkf(namep, is_directory(namep), Fflag) == 0) {
				passtape();
				continue;
			}
		}
		/*
		 * ACL support:
		 * aclchar is introduced to indicate if there are
		 * acl entries. longt() now takes one extra argument.
		 */
		if (vflag) {
			if (dblock.dbuf.typeflag == 'A') {
				aclchar = '+';
				passtape();
				continue;
			}
			longt(&stbuf, aclchar);
			aclchar = ' ';
		}


#if defined(O_XATTR)
		if (xattrp != NULL) {
			int	issysattr;
			char	*bn = basename(attrinfo->attr_path);

			/*
			 * We could use sysattr_type() to test whether or not
			 * the attribute we are processing is really an
			 * extended system attribute, which as of this writing
			 * just does a strcmp(), however, sysattr_type() may
			 * be changed to issue a pathconf() call instead, which
			 * would require being changed into the parent attribute
			 * directory.  So instead, just do simple string
			 * comparisons to see if we are processing an extended
			 * system attribute.
			 */
			issysattr = is_sysattr(bn);

			(void) printf(gettext("%s %sattribute %s"),
			    xattrp->h_names,
			    issysattr ? gettext("system ") : "",
			    attrinfo->attr_path);
		} else {
			(void) printf("%s", namep);
		}
#else
			(void) printf("%s", namep);
#endif

		if (extno != 0) {
			if (vflag) {
				/* keep the '\n' for backwards compatibility */
				(void) fprintf(vfile, gettext(
				    "\n [extent #%d of %d]"), extno, extotal);
			} else {
				(void) fprintf(vfile, gettext(
				    " [extent #%d of %d]"), extno, extotal);
			}
		}
		if (xhdr_flgs & _X_LINKPATH) {
			(void) strcpy(templink, Xtarhdr.x_linkpath);
		} else {
#if defined(O_XATTR)
			if (xattrp != NULL) {
				(void) sprintf(templink,
				    "file %.*s", NAMSIZ, xattrp->h_names);
			} else {
				(void) sprintf(templink, "%.*s", NAMSIZ,
				    dblock.dbuf.linkname);
			}
#else
			(void) sprintf(templink, "%.*s", NAMSIZ,
			    dblock.dbuf.linkname);
#endif
			templink[NAMSIZ] = '\0';
		}
		if (dblock.dbuf.typeflag == '1') {
			/*
			 * TRANSLATION_NOTE
			 *	Subject is omitted here.
			 *	Translate this as if
			 *		<subject> linked to %s
			 */
#if defined(O_XATTR)
			if (xattrp != NULL) {
				(void) printf(
				    gettext(" linked to attribute %s"),
				    xattr_linkp->h_names +
				    strlen(xattr_linkp->h_names) + 1);
			} else {
				(void) printf(
				    gettext(" linked to %s"), templink);
			}
#else
				(void) printf(
				    gettext(" linked to %s"), templink);

#endif
		}
		if (dblock.dbuf.typeflag == '2')
			(void) printf(gettext(
			/*
			 * TRANSLATION_NOTE
			 *	Subject is omitted here.
			 *	Translate this as if
			 *		<subject> symbolic link to %s
			 */
			" symbolic link to %s"), templink);
		(void) printf("\n");
#if defined(O_XATTR)
		if (xattrp != NULL) {
			free(xattrhead);
			xattrp = NULL;
			xattrhead = NULL;
		}
#endif
		passtape();
	}
	/*
	 * Check if the number of files tabled is different from the
	 * number of files listed on the command line
	 */
	if (fcnt > tcnt) {
		(void) fprintf(stderr, gettext(
		    "tar: %d file(s) not found\n"), fcnt-tcnt);
		Errflg = 1;
	}
}

static void
putempty(blkcnt_t n)
{
	char buf[TBLOCK];
	char *cp;

	for (cp = buf; cp < &buf[TBLOCK]; )
		*cp++ = '\0';
	while (n-- > 0)
		(void) writetbuf(buf, 1);
}

static	ushort_t	Ftype = S_IFMT;

static	void
verbose(struct stat *st, char aclchar)
{
	int i, j, temp;
	mode_t mode;
	char modestr[12];

	for (i = 0; i < 11; i++)
		modestr[i] = '-';
	modestr[i] = '\0';

	/* a '+' sign is printed if there is ACL */
	modestr[i-1] = aclchar;

	mode = st->st_mode;
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
	temp = st->st_mode & Ftype;
	switch (temp) {
	case (S_IFIFO):
		modestr[0] = 'p';
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
		/* This field may be zero in old archives. */
		if (is_posix && dblock.dbuf.typeflag != '1') {
			/*
			 * For POSIX compliant archives, the mode field
			 * consists of 12 bits, ie:  the file type bits
			 * are not stored in dblock.dbuf.mode.
			 * For files other than hard links, getdir() sets
			 * the file type bits in the st_mode field of the
			 * stat structure based upon dblock.dbuf.typeflag.
			 */
			(void) fprintf(stderr, gettext(
			    "tar: impossible file type"));
		}
	}

	if ((S_ISUID & Gen.g_mode) == S_ISUID)
		modestr[3] = 's';
	if ((S_ISVTX & Gen.g_mode) == S_ISVTX)
		modestr[9] = 't';
	if ((S_ISGID & Gen.g_mode) == S_ISGID && modestr[6] == 'x')
		modestr[6] = 's';
	else if ((S_ENFMT & Gen.g_mode) == S_ENFMT && modestr[6] != 'x')
		modestr[6] = 'l';
	(void) fprintf(vfile, "%s", modestr);
}

static void
longt(struct stat *st, char aclchar)
{
	char fileDate[30];
	struct tm *tm;

	verbose(st, aclchar);
	(void) fprintf(vfile, "%3ld/%-3ld", st->st_uid, st->st_gid);

	if (dblock.dbuf.typeflag == '2') {
		if (xhdr_flgs & _X_LINKPATH)
			st->st_size = (off_t)strlen(Xtarhdr.x_linkpath);
		else
			st->st_size = (off_t)(memchr(dblock.dbuf.linkname,
			    '\0', NAMSIZ) ?
			    (strlen(dblock.dbuf.linkname)) : (NAMSIZ));
	}
	(void) fprintf(vfile, " %6" FMT_off_t, st->st_size);

	tm = localtime(&(st->st_mtime));
	(void) strftime(fileDate, sizeof (fileDate),
	    dcgettext((const char *)0, "%b %e %R %Y", LC_TIME), tm);
	(void) fprintf(vfile, " %s ", fileDate);
}


/*
 *  checkdir - Attempt to ensure that the path represented in name
 *             exists, and return 1 if this is true and name itself is a
 *             directory.
 *             Return 0 if this path cannot be created or if name is not
 *             a directory.
 */

static int
checkdir(char *name)
{
	char lastChar;		   /* the last character in name */
	char *cp;		   /* scratch pointer into name */
	char *firstSlash = NULL;   /* first slash in name */
	char *lastSlash = NULL;	   /* last slash in name */
	int  nameLen;		   /* length of name */
	int  trailingSlash;	   /* true if name ends in slash */
	int  leadingSlash;	   /* true if name begins with slash */
	int  markedDir;		   /* true if name denotes a directory */
	int  success;		   /* status of makeDir call */


	/*
	 *  Scan through the name, and locate first and last slashes.
	 */

	for (cp = name; *cp; cp++) {
		if (*cp == '/') {
			if (! firstSlash) {
				firstSlash = cp;
			}
			lastSlash = cp;
		}
	}

	/*
	 *  Determine what you can from the proceeds of the scan.
	 */

	lastChar	= *(cp - 1);
	nameLen		= (int)(cp - name);
	trailingSlash	= (lastChar == '/');
	leadingSlash	= (*name == '/');
	markedDir	= (dblock.dbuf.typeflag == '5' || trailingSlash);

	if (! lastSlash && ! markedDir) {
		/*
		 *  The named file does not have any subdrectory
		 *  structure; just bail out.
		 */

		return (0);
	}

	/*
	 *  Make sure that name doesn`t end with slash for the loop.
	 *  This ensures that the makeDir attempt after the loop is
	 *  meaningful.
	 */

	if (trailingSlash) {
		name[nameLen-1] = '\0';
	}

	/*
	 *  Make the path one component at a time.
	 */

	for (cp = strchr(leadingSlash ? name+1 : name, '/');
	    cp;
	    cp = strchr(cp+1, '/')) {
		*cp = '\0';
		success = makeDir(name);
		*cp = '/';

		if (!success) {
			name[nameLen-1] = lastChar;
			return (0);
		}
	}

	/*
	 *  This makes the last component of the name, if it is a
	 *  directory.
	 */

	if (markedDir) {
		if (! makeDir(name)) {
			name[nameLen-1] = lastChar;
			return (0);
		}
	}

	name[nameLen-1] = (lastChar == '/') ? '\0' : lastChar;
	return (markedDir);
}

/*
 * resugname - Restore the user name and group name.  Search the NIS
 *             before using the uid and gid.
 *             (It is presumed that an archive entry cannot be
 *	       simultaneously a symlink and some other type.)
 */

static void
resugname(int dirfd, 	/* dir fd file resides in */
	char *name,	/* name of the file to be modified */
	int symflag)	/* true if file is a symbolic link */
{
	uid_t duid;
	gid_t dgid;
	struct stat *sp = &stbuf;
	char	*u_g_name;

	if (checkflag == 1) { /* Extended tar format and euid == 0 */

		/*
		 * Try and extract the intended uid and gid from the name
		 * service before believing the uid and gid in the header.
		 *
		 * In the case where we archived a setuid or setgid file
		 * owned by someone with a large uid, then it will
		 * have made it into the archive with a uid of nobody.  If
		 * the corresponding username doesn't appear to exist, then we
		 * want to make sure it *doesn't* end up as setuid nobody!
		 *
		 * Our caller will print an error message about the fact
		 * that the restore didn't work out quite right ..
		 */
		if (xhdr_flgs & _X_UNAME)
			u_g_name = Xtarhdr.x_uname;
		else
			u_g_name = dblock.dbuf.uname;
		if ((duid = getuidbyname(u_g_name)) == -1) {
			if (S_ISREG(sp->st_mode) && sp->st_uid == UID_NOBODY &&
			    (sp->st_mode & S_ISUID) == S_ISUID)
				(void) chmod(name,
				    MODEMASK & sp->st_mode & ~S_ISUID);
			duid = sp->st_uid;
		}

		/* (Ditto for gids) */

		if (xhdr_flgs & _X_GNAME)
			u_g_name = Xtarhdr.x_gname;
		else
			u_g_name = dblock.dbuf.gname;
		if ((dgid = getgidbyname(u_g_name)) == -1) {
			if (S_ISREG(sp->st_mode) && sp->st_gid == GID_NOBODY &&
			    (sp->st_mode & S_ISGID) == S_ISGID)
				(void) chmod(name,
				    MODEMASK & sp->st_mode & ~S_ISGID);
			dgid = sp->st_gid;
		}
	} else if (checkflag == 2) { /* tar format and euid == 0 */
		duid = sp->st_uid;
		dgid = sp->st_gid;
	}
	if ((checkflag == 1) || (checkflag == 2))
		(void) fchownat(dirfd, name, duid, dgid, symflag);
}

/*ARGSUSED*/
static void
onintr(int sig)
{
	(void) signal(SIGINT, SIG_IGN);
	term++;
}

/*ARGSUSED*/
static void
onquit(int sig)
{
	(void) signal(SIGQUIT, SIG_IGN);
	term++;
}

/*ARGSUSED*/
static void
onhup(int sig)
{
	(void) signal(SIGHUP, SIG_IGN);
	term++;
}

static void
tomodes(struct stat *sp)
{
	uid_t uid;
	gid_t gid;

	bzero(dblock.dummy, TBLOCK);

	/*
	 * If the uid or gid is too large, we can't put it into
	 * the archive.  We could fail to put anything in the
	 * archive at all .. but most of the time the name service
	 * will save the day when we do a lookup at restore time.
	 *
	 * Instead we choose a "safe" uid and gid, and fix up whether
	 * or not the setuid and setgid bits are left set to extraction
	 * time.
	 */
	if (Eflag) {
		if ((ulong_t)(uid = sp->st_uid) > (ulong_t)OCTAL7CHAR) {
			xhdr_flgs |= _X_UID;
			Xtarhdr.x_uid = uid;
		}
		if ((ulong_t)(gid = sp->st_gid) > (ulong_t)OCTAL7CHAR) {
			xhdr_flgs |= _X_GID;
			Xtarhdr.x_gid = gid;
		}
		if (sp->st_size > TAR_OFFSET_MAX) {
			xhdr_flgs |= _X_SIZE;
			Xtarhdr.x_filesz = sp->st_size;
			(void) sprintf(dblock.dbuf.size, "%011" FMT_off_t_o,
			    (off_t)0);
		} else
			(void) sprintf(dblock.dbuf.size, "%011" FMT_off_t_o,
			    sp->st_size);
	} else {
		(void) sprintf(dblock.dbuf.size, "%011" FMT_off_t_o,
		    sp->st_size);
	}
	if ((ulong_t)(uid = sp->st_uid) > (ulong_t)OCTAL7CHAR)
		uid = UID_NOBODY;
	if ((ulong_t)(gid = sp->st_gid) > (ulong_t)OCTAL7CHAR)
		gid = GID_NOBODY;
	(void) sprintf(dblock.dbuf.gid, "%07lo", gid);
	(void) sprintf(dblock.dbuf.uid, "%07lo", uid);
	(void) sprintf(dblock.dbuf.mode, "%07lo", sp->st_mode & POSIXMODES);
	(void) sprintf(dblock.dbuf.mtime, "%011lo", sp->st_mtime);
}

static	int
#ifdef	EUC
/*
 * Warning:  the result of this function depends whether 'char' is a
 * signed or unsigned data type.  This a source of potential
 * non-portability among heterogeneous systems.  It is retained here
 * for backward compatibility.
 */
checksum_signed(union hblock *dblockp)
#else
checksum(union hblock *dblockp)
#endif	/* EUC */
{
	int i;
	char *cp;

	for (cp = dblockp->dbuf.chksum;
	    cp < &dblockp->dbuf.chksum[sizeof (dblockp->dbuf.chksum)]; cp++)
		*cp = ' ';
	i = 0;
	for (cp = dblockp->dummy; cp < &(dblockp->dummy[TBLOCK]); cp++)
		i += *cp;
	return (i);
}

#ifdef	EUC
/*
 * Generate unsigned checksum, regardless of what C compiler is
 * used.  Survives in the face of arbitrary 8-bit clean filenames,
 * e.g., internationalized filenames.
 */
static int
checksum(union hblock *dblockp)
{
	unsigned i;
	unsigned char *cp;

	for (cp = (unsigned char *) dblockp->dbuf.chksum;
	    cp < (unsigned char *)
	    &(dblockp->dbuf.chksum[sizeof (dblockp->dbuf.chksum)]); cp++)
		*cp = ' ';
	i = 0;
	for (cp = (unsigned char *) dblockp->dummy;
	    cp < (unsigned char *) &(dblockp->dummy[TBLOCK]); cp++)
		i += *cp;

	return (i);
}
#endif	/* EUC */

/*
 * If the w flag is set, output the action to be taken and the name of the
 * file.  Perform the action if the user response is affirmative.
 */

static int
checkw(char c, char *name)
{
	if (wflag) {
		(void) fprintf(vfile, "%c ", c);
		if (vflag)
			longt(&stbuf, ' ');	/* do we have acl info here */
		(void) fprintf(vfile, "%s: ", name);
		if (yes() == 1) {
			return (1);
		}
		return (0);
	}
	return (1);
}

/*
 * When the F flag is set, exclude RCS and SCCS directories (and any files
 * or directories under them).  If F is set twice, also exclude .o files,
 * and files names errs, core, and a.out.
 *
 * Return 0 if file should be excluded, 1 otherwise.
 */

static int
checkf(char *longname, int is_dir, int howmuch)
{
	static char fullname[PATH_MAX + 1];
	char *dir, *name;

#if defined(O_XATTR)
	/*
	 * If there is an xattr_buf structure associated with this file,
	 * always return 1.
	 */
	if (xattrp) {
		return (1);
	}
#endif

	/*
	 * First check to see if the base name is an RCS or SCCS directory.
	 */
	if (strlcpy(fullname, longname, sizeof (fullname)) >= sizeof (fullname))
		return (1);

	name = basename(fullname);
	if (is_dir) {
		if ((strcmp(name, "SCCS") == 0) || (strcmp(name, "RCS") == 0))
			return (0);
	}

	/*
	 * If two -F command line options were given then exclude .o files,
	 * and files named errs, core, and a.out.
	 */
	if (howmuch > 1 && !is_dir) {
		size_t l = strlen(name);

		if (l >= 3 && name[l - 2] == '.' && name[l - 1] == 'o')
			return (0);
		if (strcmp(name, "core") == 0 || strcmp(name, "errs") == 0 ||
		    strcmp(name, "a.out") == 0)
			return (0);
	}

	/*
	 * At this point, check to see if this file has a parent directory
	 * named RCS or SCCS.  If so, then this file should be excluded too.
	 * The strcpy() operation is done again, because basename(3C) may
	 * modify the path string passed to it.
	 */
	if (strlcpy(fullname, longname, sizeof (fullname)) >= sizeof (fullname))
		return (1);

	dir = dirname(fullname);
	while (strcmp(dir, ".") != 0) {
		name = basename(dir);
		if ((strcmp(name, "SCCS") == 0) || (strcmp(name, "RCS") == 0))
			return (0);
		dir = dirname(dir);
	}

	return (1);
}

static int
response(void)
{
	int c;

	c = getchar();
	if (c != '\n')
		while (getchar() != '\n')
			;
	else c = 'n';
	return ((c >= 'A' && c <= 'Z') ? c + ('a'-'A') : c);
}

/* Has file been modified since being put into archive? If so, return > 0. */

static off_t	lookup(char *);

static int
checkupdate(char *arg)
{
	char name[PATH_MAX+1];
	time_t	mtime;
	long nsecs;
	off_t seekp;

	rewind(tfile);
	if ((seekp = lookup(arg)) < 0)
		return (1);
	(void) fseek(tfile, seekp, 0);
	(void) fscanf(tfile, "%s %ld.%ld", name, &mtime, &nsecs);

	/*
	 * Unless nanoseconds were stored in the file, only use seconds for
	 * comparison of time.  Nanoseconds are stored when -E is specified.
	 */
	if (Eflag == 0)
		return (stbuf.st_mtime > mtime);

	if ((stbuf.st_mtime < mtime) ||
	    ((stbuf.st_mtime == mtime) && (stbuf.st_mtim.tv_nsec <= nsecs)))
		return (0);
	return (1);
}


/*
 *	newvol	get new floppy (or tape) volume
 *
 *	newvol();		resets tapepos and first to TRUE, prompts for
 *				for new volume, and waits.
 *	if dumping, end-of-file is written onto the tape.
 */

static void
newvol(void)
{
	int c;

	if (dumping) {
		dlog("newvol called with 'dumping' set\n");
		putempty((blkcnt_t)2);	/* 2 EOT marks */
		closevol();
		flushtape();
		sync();
		tapepos = 0;
	} else
		first = TRUE;
	if (close(mt) != 0)
		vperror(2, gettext("close error"));
	mt = 0;
	(void) fprintf(stderr, gettext(
	    "tar: \007please insert new volume, then press RETURN."));
	(void) fseek(stdin, (off_t)0, 2);	/* scan over read-ahead */
	while ((c = getchar()) != '\n' && ! term)
		if (c == EOF)
			done(Errflg);
	if (term)
		done(Errflg);

	errno = 0;

	if (strcmp(usefile, "-") == 0) {
		mt = dup(1);
	} else {
		mt = open(usefile, dumping ? update : 0);
	}

	if (mt < 0) {
		(void) fprintf(stderr, gettext(
		    "tar: cannot reopen %s (%s)\n"),
		    dumping ? gettext("output") : gettext("input"), usefile);

		dlog("update=%d, usefile=%s ", update, usefile);
		dlog("mt=%d, [%s]\n", mt, strerror(errno));

		done(2);
	}
}

/*
 * Write a trailer portion to close out the current output volume.
 */

static void
closevol(void)
{
	if (mulvol) {
		/*
		 * blocklim does not count the 2 EOT marks;
		 * tapepos  does count the 2 EOT marks;
		 * therefore we need the +2 below.
		 */
		putempty(blocklim + (blkcnt_t)2 - tapepos);
	}
}

static void
done(int n)
{
	/*
	 * If we were terminated in some way, and we would otherwise have
	 * exited with a value of 0, adjust to 1, so that external callers
	 * can determine this by looking at the exit status.
	 */
	if (term && n == 0)
		n = 1;

	if (tfile != NULL)
		(void) unlink(tname);
	if (compress_opt != NULL)
		(void) free(compress_opt);
	if (mt > 0) {
		if ((close(mt) != 0) || (fclose(stdout) != 0)) {
			perror(gettext("tar: close error"));
			exit(2);
		}
	}
	/*
	 * If we have a compression child, we should have a child process that
	 * we're waiting for to finish compressing or uncompressing the tar
	 * stream.
	 */
	if (comp_pid != 0)
		wait_pid(comp_pid);
	exit(n);
}

/*
 * Determine if s1 is a prefix portion of s2 (or the same as s2).
 */

static	int
is_prefix(char *s1, char *s2)
{
	while (*s1)
		if (*s1++ != *s2++)
			return (0);
	if (*s2)
		return (*s2 == '/');
	return (1);
}

/*
 * lookup and bsrch look through tfile entries to find a match for a name.
 * The name can be up to PATH_MAX bytes.  bsrch compares what it sees between
 * a pair of newline chars, so the buffer it uses must be long enough for
 * two lines:  name and modification time as well as period, newline and space.
 *
 * A kludge was added to bsrch to take care of matching on the first entry
 * in the file--there is no leading newline.  So, if we are reading from the
 * start of the file, read into byte two and set the first byte to a newline.
 * Otherwise, the first entry cannot be matched.
 *
 */

#define	N	(2 * (PATH_MAX + TIME_MAX_DIGITS + LONG_MAX_DIGITS + 3))
static	off_t
lookup(char *s)
{
	int i;
	off_t a;

	for (i = 0; s[i]; i++)
		if (s[i] == ' ')
			break;
	a = bsrch(s, i, low, high);
	return (a);
}

static off_t
bsrch(char *s, int n, off_t l, off_t h)
{
	int i, j;
	char b[N];
	off_t m, m1;


loop:
	if (l >= h)
		return ((off_t)-1);
	m = l + (h-l)/2 - N/2;
	if (m < l)
		m = l;
	(void) fseek(tfile, m, 0);
	if (m == 0) {
		(void) fread(b+1, 1, N-1, tfile);
		b[0] = '\n';
		m--;
	} else
		(void) fread(b, 1, N, tfile);
	for (i = 0; i < N; i++) {
		if (b[i] == '\n')
			break;
		m++;
	}
	if (m >= h)
		return ((off_t)-1);
	m1 = m;
	j = i;
	for (i++; i < N; i++) {
		m1++;
		if (b[i] == '\n')
			break;
	}
	i = cmp(b+j, s, n);
	if (i < 0) {
		h = m;
		goto loop;
	}
	if (i > 0) {
		l = m1;
		goto loop;
	}
	if (m < 0)
		m = 0;
	return (m);
}

static int
cmp(char *b, char *s, int n)
{
	int i;

	assert(b[0] == '\n');

	for (i = 0; i < n; i++) {
		if (b[i+1] > s[i])
			return (-1);
		if (b[i+1] < s[i])
			return (1);
	}
	return (b[i+1] == ' '? 0 : -1);
}


/*
 *	seekdisk	seek to next file on archive
 *
 *	called by passtape() only
 *
 *	WARNING: expects "nblock" to be set, that is, readtape() to have
 *		already been called.  Since passtape() is only called
 *		after a file header block has been read (why else would
 *		we skip to next file?), this is currently safe.
 *
 *	changed to guarantee SYS_BLOCK boundary
 */

static void
seekdisk(blkcnt_t blocks)
{
	off_t seekval;
#if SYS_BLOCK > TBLOCK
	/* handle non-multiple of SYS_BLOCK */
	blkcnt_t nxb;	/* # extra blocks */
#endif

	tapepos += blocks;
	dlog("seekdisk(%" FMT_blkcnt_t ") called\n", blocks);
	if (recno + blocks <= nblock) {
		recno += blocks;
		return;
	}
	if (recno > nblock)
		recno = nblock;
	seekval = (off_t)blocks - (nblock - recno);
	recno = nblock;	/* so readtape() reads next time through */
#if SYS_BLOCK > TBLOCK
	nxb = (blkcnt_t)(seekval % (off_t)(SYS_BLOCK / TBLOCK));
	dlog("xtrablks=%" FMT_blkcnt_t " seekval=%" FMT_blkcnt_t " blks\n",
	    nxb, seekval);
	if (nxb && nxb > seekval) /* don't seek--we'll read */
		goto noseek;
	seekval -=  nxb;	/* don't seek quite so far */
#endif
	if (lseek(mt, (off_t)(TBLOCK * seekval), 1) == (off_t)-1) {
		(void) fprintf(stderr, gettext(
		    "tar: device seek error\n"));
		done(3);
	}
#if SYS_BLOCK > TBLOCK
	/* read those extra blocks */
noseek:
	if (nxb) {
		dlog("reading extra blocks\n");
		if (read(mt, tbuf, TBLOCK*nblock) < 0) {
			(void) fprintf(stderr, gettext(
			    "tar: read error while skipping file\n"));
			done(8);
		}
		recno = nxb;	/* so we don't read in next readtape() */
	}
#endif
}

static void
readtape(char *buffer)
{
	int i, j;

	++tapepos;
	if (recno >= nblock || first) {
		if (first) {
			/*
			 * set the number of blocks to read initially, based on
			 * the defined defaults for the device, or on the
			 * explicit block factor given.
			 */
			if (bflag || defaults_used || NotTape)
				j = nblock;
			else
				j = NBLOCK;
		} else
			j = nblock;

		if ((i = read(mt, tbuf, TBLOCK*j)) < 0) {
			(void) fprintf(stderr, gettext(
			    "tar: tape read error\n"));
			done(3);
		/*
		 * i == 0 and !rflag means that EOF is reached and we are
		 * trying to update or replace an empty tar file, so exit
		 * with an error.
		 *
		 * If i == 0 and !first and NotTape, it means the pointer
		 * has gone past the EOF. It could happen if two processes
		 * try to update the same tar file simultaneously. So exit
		 * with an error.
		 */

		} else if (i == 0) {
			if (first && !rflag) {
				(void) fprintf(stderr, gettext(
				    "tar: blocksize = %d\n"), i);
				done(Errflg);
			} else if (!first && (!rflag || NotTape)) {
				mterr("read", 0, 2);
			}
		} else if ((!first || Bflag) && i != TBLOCK*j) {
			/*
			 * Short read - try to get the remaining bytes.
			 */

			int remaining = (TBLOCK * j) - i;
			char *b = (char *)tbuf + i;
			int r;

			do {
				if ((r = read(mt, b, remaining)) < 0) {
					(void) fprintf(stderr,
					    gettext("tar: tape read error\n"));
					done(3);
				}
				b += r;
				remaining -= r;
				i += r;
			} while (remaining > 0 && r != 0);
		}
		if (first) {
			if ((i % TBLOCK) != 0) {
				(void) fprintf(stderr, gettext(
				    "tar: tape blocksize error\n"));
				done(3);
			}
			i /= TBLOCK;
			if (vflag && i != nblock && i != 1) {
				if (!NotTape)
					(void) fprintf(stderr, gettext(
					    "tar: blocksize = %d\n"), i);
			}

			/*
			 * If we are reading a tape, then a short read is
			 * understood to signify that the amount read is
			 * the tape's actual blocking factor.  We adapt
			 * nblock accordingly.  There is no reason to do
			 * this when the device is not blocked.
			 */

			if (!NotTape)
				nblock = i;
		}
		recno = 0;
	}

	first = FALSE;
	copy(buffer, &tbuf[recno++]);
}


/*
 * replacement for writetape.
 */

static int
writetbuf(char *buffer, int n)
{
	int i;

	tapepos += n;		/* output block count */

	if (recno >= nblock) {
		i = write(mt, (char *)tbuf, TBLOCK*nblock);
		if (i != TBLOCK*nblock)
			mterr("write", i, 2);
		recno = 0;
	}

	/*
	 *  Special case:  We have an empty tape buffer, and the
	 *  users data size is >= the tape block size:  Avoid
	 *  the bcopy and dma direct to tape.  BIG WIN.  Add the
	 *  residual to the tape buffer.
	 */
	while (recno == 0 && n >= nblock) {
		i = (int)write(mt, buffer, TBLOCK*nblock);
		if (i != TBLOCK*nblock)
			mterr("write", i, 2);
		n -= nblock;
		buffer += (nblock * TBLOCK);
	}

	while (n-- > 0) {
		(void) memcpy((char *)&tbuf[recno++], buffer, TBLOCK);
		buffer += TBLOCK;
		if (recno >= nblock) {
			i = (int)write(mt, (char *)tbuf, TBLOCK*nblock);
			if (i != TBLOCK*nblock)
				mterr("write", i, 2);
			recno = 0;
		}
	}

	/* Tell the user how much to write to get in sync */
	return (nblock - recno);
}

/*
 *	backtape - reposition tape after reading soft "EOF" record
 *
 *	Backtape tries to reposition the tape back over the EOF
 *	record.  This is for the 'u' and 'r' function letters so that the
 *	tape can be extended.  This code is not well designed, but
 *	I'm confident that the only callers who care about the
 *	backspace-over-EOF feature are those involved in 'u' and 'r'.
 *
 *	The proper way to backup the tape is through the use of mtio.
 *	Earlier spins used lseek combined with reads in a confusing
 *	maneuver that only worked on 4.x, but shouldn't have, even
 *	there.  Lseeks are explicitly not supported for tape devices.
 */

static void
backtape(void)
{
	struct mtop mtcmd;
	dlog("backtape() called, recno=%" FMT_blkcnt_t " nblock=%d\n", recno,
	    nblock);
	/*
	 * Backup to the position in the archive where the record
	 * currently sitting in the tbuf buffer is situated.
	 */

	if (NotTape) {
		/*
		 * For non-tape devices, this means lseeking to the
		 * correct position.  The absolute location tapepos-recno
		 * should be the beginning of the current record.
		 */

		if (lseek(mt, (off_t)(TBLOCK*(tapepos-recno)), SEEK_SET) ==
		    (off_t)-1) {
			(void) fprintf(stderr,
			    gettext("tar: lseek to end of archive failed\n"));
			done(4);
		}
	} else {
		/*
		 * For tape devices, we backup over the most recently
		 * read record.
		 */

		mtcmd.mt_op = MTBSR;
		mtcmd.mt_count = 1;

		if (ioctl(mt, MTIOCTOP, &mtcmd) < 0) {
			(void) fprintf(stderr,
			    gettext("tar: backspace over record failed\n"));
			done(4);
		}
	}

	/*
	 * Decrement the tape and tbuf buffer indices to prepare for the
	 * coming write to overwrite the soft EOF record.
	 */

	recno--;
	tapepos--;
}


/*
 *	flushtape  write buffered block(s) onto tape
 *
 *      recno points to next free block in tbuf.  If nonzero, a write is done.
 *	Care is taken to write in multiples of SYS_BLOCK when device is
 *	non-magtape in case raw i/o is used.
 *
 *	NOTE: this is called by writetape() to do the actual writing
 */

static void
flushtape(void)
{
	dlog("flushtape() called, recno=%" FMT_blkcnt_t "\n", recno);
	if (recno > 0) {	/* anything buffered? */
		if (NotTape) {
#if SYS_BLOCK > TBLOCK
			int i;

			/*
			 * an odd-block write can only happen when
			 * we are at the end of a volume that is not a tape.
			 * Here we round recno up to an even SYS_BLOCK
			 * boundary.
			 */
			if ((i = recno % (SYS_BLOCK / TBLOCK)) != 0) {
				dlog("flushtape() %d rounding blocks\n", i);
				recno += i;	/* round up to even SYS_BLOCK */
			}
#endif
			if (recno > nblock)
				recno = nblock;
		}
		dlog("writing out %" FMT_blkcnt_t " blocks of %" FMT_blkcnt_t
		    " bytes\n", (blkcnt_t)(NotTape ? recno : nblock),
		    (blkcnt_t)(NotTape ? recno : nblock) * TBLOCK);
		if (write(mt, tbuf,
		    (size_t)(NotTape ? recno : nblock) * TBLOCK) < 0) {
			(void) fprintf(stderr, gettext(
			    "tar: tape write error\n"));
			done(2);
		}
		recno = 0;
	}
}

static void
copy(void *dst, void *src)
{
	(void) memcpy(dst, src, TBLOCK);
}

/*
 * kcheck()
 *	- checks the validity of size values for non-tape devices
 *	- if size is zero, mulvol tar is disabled and size is
 *	  assumed to be infinite.
 *	- returns volume size in TBLOCKS
 */

static blkcnt_t
kcheck(char *kstr)
{
	blkcnt_t kval;

	kval = strtoll(kstr, NULL, 0);
	if (kval == (blkcnt_t)0) {	/* no multi-volume; size is infinity. */
		mulvol = 0;	/* definitely not mulvol, but we must  */
		return (0);	/* took out setting of NotTape */
	}
	if (kval < (blkcnt_t)MINSIZE) {
		(void) fprintf(stderr, gettext(
		    "tar: sizes below %luK not supported (%" FMT_blkcnt_t
		    ").\n"), (ulong_t)MINSIZE, kval);
		(void) fprintf(stderr, gettext(
		    "bad size entry for %s in %s.\n"),
		    archive, DEF_FILE);
		done(1);
	}
	mulvol++;
	NotTape++;			/* implies non-tape */
	return (kval * 1024 / TBLOCK);	/* convert to TBLOCKS */
}


/*
 * bcheck()
 *	- checks the validity of blocking factors
 *	- returns blocking factor
 */

static int
bcheck(char *bstr)
{
	blkcnt_t bval;

	bval = strtoll(bstr, NULL, 0);
	if ((bval <= 0) || (bval > INT_MAX / TBLOCK)) {
		(void) fprintf(stderr, gettext(
		    "tar: invalid blocksize \"%s\".\n"), bstr);
		if (!bflag)
			(void) fprintf(stderr, gettext(
			    "bad blocksize entry for '%s' in %s.\n"),
			    archive, DEF_FILE);
		done(1);
	}

	return ((int)bval);
}


/*
 * defset()
 *	- reads DEF_FILE for the set of default values specified.
 *	- initializes 'usefile', 'nblock', and 'blocklim', and 'NotTape'.
 *	- 'usefile' points to static data, so will be overwritten
 *	  if this routine is called a second time.
 *	- the pattern specified by 'arch' must be followed by four
 *	  blank-separated fields (1) device (2) blocking,
 *				 (3) size(K), and (4) tape
 *	  for example: archive0=/dev/fd 1 400 n
 */

static int
defset(char *arch)
{
	char *bp;

	if (defopen(DEF_FILE) != 0)
		return (FALSE);
	if (defcntl(DC_SETFLAGS, (DC_STD & ~(DC_CASE))) == -1) {
		(void) fprintf(stderr, gettext(
		    "tar: error setting parameters for %s.\n"), DEF_FILE);
		return (FALSE);			/* & following ones too */
	}
	if ((bp = defread(arch)) == NULL) {
		(void) fprintf(stderr, gettext(
		    "tar: missing or invalid '%s' entry in %s.\n"),
		    arch, DEF_FILE);
		return (FALSE);
	}
	if ((usefile = strtok(bp, " \t")) == NULL) {
		(void) fprintf(stderr, gettext(
		    "tar: '%s' entry in %s is empty!\n"), arch, DEF_FILE);
		return (FALSE);
	}
	if ((bp = strtok(NULL, " \t")) == NULL) {
		(void) fprintf(stderr, gettext(
		    "tar: block component missing in '%s' entry in %s.\n"),
		    arch, DEF_FILE);
		return (FALSE);
	}
	nblock = bcheck(bp);
	if ((bp = strtok(NULL, " \t")) == NULL) {
		(void) fprintf(stderr, gettext(
		    "tar: size component missing in '%s' entry in %s.\n"),
		    arch, DEF_FILE);
		return (FALSE);
	}
	blocklim = kcheck(bp);
	if ((bp = strtok(NULL, " \t")) != NULL)
		NotTape = (*bp == 'n' || *bp == 'N');
	else
		NotTape = (blocklim != 0);
	(void) defopen(NULL);
	dlog("defset: archive='%s'; usefile='%s'\n", arch, usefile);
	dlog("defset: nblock='%d'; blocklim='%" FMT_blkcnt_t "'\n",
	    nblock, blocklim);
	dlog("defset: not tape = %d\n", NotTape);
	return (TRUE);
}


/*
 * Following code handles excluded and included files.
 * A hash table of file names to be {in,ex}cluded is built.
 * For excluded files, before writing or extracting a file
 * check to see if it is in the exclude_tbl.
 * For included files, the wantit() procedure will check to
 * see if the named file is in the include_tbl.
 */

static void
build_table(file_list_t *table[], char *file)
{
	FILE	*fp;
	char	buf[PATH_MAX + 1];

	if ((fp = fopen(file, "r")) == (FILE *)NULL)
		vperror(1, gettext("could not open %s"), file);
	while (fgets(buf, sizeof (buf), fp) != NULL) {
		if (buf[strlen(buf) - 1] == '\n')
			buf[strlen(buf) - 1] = '\0';
		/* Only add to table if line has something in it */
		if (strspn(buf, " \t") != strlen(buf))
			add_file_to_table(table, buf);
	}
	(void) fclose(fp);
}


/*
 * Add a file name to the the specified table, if the file name has any
 * trailing '/'s then delete them before inserting into the table
 */

static void
add_file_to_table(file_list_t *table[], char *str)
{
	char	name[PATH_MAX + 1];
	unsigned int h;
	file_list_t	*exp;

	(void) strcpy(name, str);
	while (name[strlen(name) - 1] == '/') {
		name[strlen(name) - 1] = NULL;
	}

	h = hash(name);
	if ((exp = (file_list_t *)calloc(sizeof (file_list_t),
	    sizeof (char))) == NULL) {
		(void) fprintf(stderr, gettext(
		    "tar: out of memory, exclude/include table(entry)\n"));
		exit(1);
	}

	if ((exp->name = strdup(name)) == NULL) {
		(void) fprintf(stderr, gettext(
		    "tar: out of memory, exclude/include table(file name)\n"));
		exit(1);
	}

	exp->next = table[h];
	table[h] = exp;
}


/*
 * See if a file name or any of the file's parent directories is in the
 * specified table, if the file name has any trailing '/'s then delete
 * them before searching the table
 */

static int
is_in_table(file_list_t *table[], char *str)
{
	char	name[PATH_MAX + 1];
	unsigned int	h;
	file_list_t	*exp;
	char	*ptr;

	(void) strcpy(name, str);
	while (name[strlen(name) - 1] == '/') {
		name[strlen(name) - 1] = NULL;
	}

	/*
	 * check for the file name in the passed list
	 */
	h = hash(name);
	exp = table[h];
	while (exp != NULL) {
		if (strcmp(name, exp->name) == 0) {
			return (1);
		}
		exp = exp->next;
	}

	/*
	 * check for any parent directories in the file list
	 */
	while ((ptr = strrchr(name, '/'))) {
		*ptr = NULL;
		h = hash(name);
		exp = table[h];
		while (exp != NULL) {
			if (strcmp(name, exp->name) == 0) {
				return (1);
			}
			exp = exp->next;
		}
	}

	return (0);
}


/*
 * Compute a hash from a string.
 */

static unsigned int
hash(char *str)
{
	char	*cp;
	unsigned int	h;

	h = 0;
	for (cp = str; *cp; cp++) {
		h += *cp;
	}
	return (h % TABLE_SIZE);
}

static	void *
getmem(size_t size)
{
	void *p = calloc((unsigned)size, sizeof (char));

	if (p == NULL && freemem) {
		(void) fprintf(stderr, gettext(
		    "tar: out of memory, link and directory modtime "
		    "info lost\n"));
		freemem = 0;
		if (errflag)
			done(1);
		else
			Errflg = 1;
	}
	return (p);
}

/*
 * vperror() --variable argument perror.
 * Takes 3 args: exit_status, formats, args.  If exit_status is 0, then
 * the errflag (exit on error) is checked -- if it is non-zero, tar exits
 * with the value of whatever "errno" is set to.  If exit_status is not
 * zero, then tar exits with that error status. If errflag and exit_status
 * are both zero, the routine returns to where it was called and sets Errflg
 * to errno.
 */

static void
vperror(int exit_status, char *fmt, ...)
{
	va_list	ap;

	va_start(ap, fmt);
	(void) fputs("tar: ", stderr);
	(void) vfprintf(stderr, fmt, ap);
	(void) fprintf(stderr, ": %s\n", strerror(errno));
	va_end(ap);
	if (exit_status)
		done(exit_status);
	else
		if (errflag)
			done(errno);
		else
			Errflg = errno;
}


static void
fatal(char *format, ...)
{
	va_list	ap;

	va_start(ap, format);
	(void) fprintf(stderr, "tar: ");
	(void) vfprintf(stderr, format, ap);
	(void) fprintf(stderr, "\n");
	va_end(ap);
	done(1);
}


/*
 * Check to make sure that argument is a char * ptr.
 * Actually, we just check to see that it is non-null.
 * If it is null, print out the message and call usage(), bailing out.
 */

static void
assert_string(char *s, char *msg)
{
	if (s == NULL) {
		(void) fprintf(stderr, msg);
		usage();
	}
}


static void
mterr(char *operation, int i, int exitcode)
{
	(void) fprintf(stderr, gettext(
	    "tar: %s error: "), operation);
	if (i < 0)
		perror("");
	else
		(void) fprintf(stderr, gettext("unexpected EOF\n"));
	done(exitcode);
}

static int
wantit(char *argv[], char **namep, char **dirp, char **component,
    attr_data_t **attrinfo)
{
	char **cp;
	int gotit;		/* true if we've found a match */
	int ret;

top:
	if (xhdr_flgs & _X_XHDR) {
		xhdr_flgs = 0;
	}
	getdir();
	if (Xhdrflag > 0) {
		ret = get_xdata();
		if (ret != 0) {	/* Xhdr items and regular header */
			setbytes_to_skip(&stbuf, ret);
			passtape();
			return (0);	/* Error--don't want to extract  */
		}
	}

	/*
	 * If typeflag is not 'A' and xhdr_flgs is set, then processing
	 * of ancillary file is either over or ancillary file
	 * processing is not required, load info from Xtarhdr and set
	 * _X_XHDR bit in xhdr_flgs.
	 */
	if ((dblock.dbuf.typeflag != 'A') && (xhdr_flgs != 0)) {
		load_info_from_xtarhdr(xhdr_flgs, &Xtarhdr);
		xhdr_flgs |= _X_XHDR;
	}

#if defined(O_XATTR)
	if (dblock.dbuf.typeflag == _XATTR_HDRTYPE && xattrbadhead == 0) {
		/*
		 * Always needs to read the extended header.  If atflag, saflag,
		 * or tflag isn't set, then we'll have the correct info for
		 * passtape() later.
		 */
		(void) read_xattr_hdr(attrinfo);
		goto top;
	}
	/*
	 * Now that we've read the extended header, call passtape()
	 * if we don't want to restore attributes or system attributes.
	 * Don't restore the attribute if we are extracting
	 * a file from an archive (as opposed to doing a table of
	 * contents) and any of the following are true:
	 * 1. neither -@ or -/ was specified.
	 * 2. -@ was specified, -/ wasn't specified, and we're
	 * processing a hidden attribute directory of an attribute
	 * or we're processing a read-write system attribute file.
	 * 3. -@ wasn't specified, -/ was specified, and the file
	 * we're processing is not a read-write system attribute file,
	 * or we're processing the hidden attribute directory of an
	 * attribute.
	 *
	 * We always process the attributes if we're just generating
	 * generating a table of contents, or if both -@ and -/ were
	 * specified.
	 */
	if (xattrp != NULL) {
		attr_data_t *ainfo = *attrinfo;

		if (!tflag &&
		    ((!atflag && !saflag) ||
		    (atflag && !saflag && ((ainfo->attr_parent != NULL) ||
		    ainfo->attr_rw_sysattr)) ||
		    (!atflag && saflag && ((ainfo->attr_parent != NULL) ||
		    !ainfo->attr_rw_sysattr)))) {
			passtape();
			return (0);
		}
	}
#endif

	/* sets *namep to point at the proper name */
	if (check_prefix(namep, dirp, component) != 0) {
		passtape();
		return (0);
	}

	if (endtape()) {
		if (Bflag) {
			ssize_t sz;
			size_t extra_blocks = 0;

			/*
			 * Logically at EOT - consume any extra blocks
			 * so that write to our stdin won't fail and
			 * emit an error message; otherwise something
			 * like "dd if=foo.tar | (cd bar; tar xvf -)"
			 * will produce a bogus error message from "dd".
			 */

			while ((sz = read(mt, tbuf, TBLOCK*nblock)) > 0) {
				extra_blocks += sz;
			}
			dlog("wantit(): %d bytes of extra blocks\n",
			    extra_blocks);
		}
		dlog("wantit(): at end of tape.\n");
		return (-1);
	}

	gotit = 0;

	if ((Iflag && is_in_table(include_tbl, *namep)) ||
	    (! Iflag && *argv == NULL)) {
		gotit = 1;
	} else {
		for (cp = argv; *cp; cp++) {
			if (is_prefix(*cp, *namep)) {
				gotit = 1;
				break;
			}
		}
	}

	if (! gotit) {
		passtape();
		return (0);
	}

	if (Xflag && is_in_table(exclude_tbl, *namep)) {
		if (vflag) {
			(void) fprintf(stderr, gettext("%s excluded\n"),
			    *namep);
		}
		passtape();
		return (0);
	}

	return (1);
}


static void
setbytes_to_skip(struct stat *st, int err)
{
	/*
	 * In a scenario where a typeflag 'X' was followed by
	 * a typeflag 'A' and typeflag 'O', then the number of
	 * bytes to skip should be the size of ancillary file,
	 * plus the dblock for regular file, and the size
	 * from Xtarhdr. However, if the typeflag was just 'X'
	 * followed by typeflag 'O', then the number of bytes
	 * to skip should be the size from Xtarhdr.
	 */
	if ((err != 0) && (dblock.dbuf.typeflag == 'A') &&
	    (xhdr_flgs & _X_SIZE)) {
		st->st_size += TBLOCK + Xtarhdr.x_filesz;
		xhdr_flgs |= _X_XHDR;
	} else if ((dblock.dbuf.typeflag != 'A') &&
	    (xhdr_flgs & _X_SIZE)) {
		st->st_size += Xtarhdr.x_filesz;
		xhdr_flgs |= _X_XHDR;
	}
}

static int
fill_in_attr_info(char *attr, char *longname, char *attrparent, int atparentfd,
    int rw_sysattr, attr_data_t **attrinfo)
{
	size_t	pathlen;
	char	*tpath;
	char	*tparent;

	/* parent info */
	if (attrparent != NULL) {
		if ((tparent = strdup(attrparent)) == NULL) {
			vperror(0, gettext(
			    "unable to allocate memory for attribute parent "
			    "name for %sattribute %s/%s of %s"),
			    rw_sysattr ? gettext("system ") : "",
			    attrparent, attr, longname);
			return (1);
		}
	} else {
		tparent = NULL;
	}

	/* path info */
	pathlen = strlen(attr) + 1;
	if (attrparent != NULL) {
		pathlen += strlen(attrparent) + 1;	/* add 1 for '/' */
	}
	if ((tpath = calloc(1, pathlen)) == NULL) {
		vperror(0, gettext(
		    "unable to allocate memory for full "
		    "attribute path name for %sattribute %s%s%s of %s"),
		    rw_sysattr ? gettext("system ") : "",
		    (attrparent == NULL) ? "" : attrparent,
		    (attrparent == NULL) ? "" : "/",
		    attr, longname);
		if (tparent != NULL) {
			free(tparent);
		}
		return (1);
	}
	(void) snprintf(tpath, pathlen, "%s%s%s",
	    (attrparent == NULL) ? "" : attrparent,
	    (attrparent == NULL) ? "" : "/",
	    attr);

	/* fill in the attribute info */
	if (*attrinfo == NULL) {
		if ((*attrinfo = malloc(sizeof (attr_data_t))) == NULL) {
			vperror(0, gettext(
			    "unable to allocate memory for attribute "
			    "information for %sattribute %s%s%s of %s"),
			    rw_sysattr ? gettext("system ") : "",
			    (attrparent == NULL) ? "" : attrparent,
			    (attrparent == NULL) ? "" : gettext("/"),
			    attr, longname);
			if (tparent != NULL) {
				free(tparent);
			}
			free(tpath);
			return (1);
		}
	} else {
		if ((*attrinfo)->attr_parent != NULL) {
			free((*attrinfo)->attr_parent);
		}
		if ((*attrinfo)->attr_path != NULL) {
			free((*attrinfo)->attr_path);
		}
		/*
		 * The parent file descriptor is passed in, so don't
		 * close it here as it should be closed by the function
		 * that opened it.
		 */
	}
	(*attrinfo)->attr_parent = tparent;
	(*attrinfo)->attr_path = tpath;
	(*attrinfo)->attr_rw_sysattr = rw_sysattr;
	(*attrinfo)->attr_parentfd = atparentfd;

	return (0);
}

/*
 * Test to see if name is a directory.
 *
 * Return 1 if true, 0 otherwise.
 */

static int
is_directory(char *name)
{
#if defined(O_XATTR)
	/*
	 * If there is an xattr_buf structure associated with this file,
	 * then the directory test is based on whether the name has a
	 * trailing slash.
	 */
	if (xattrp)
		return (name[strlen(name) - 1] == '/');
#endif
	if (is_posix)
		return (dblock.dbuf.typeflag == '5');
	else
		return (name[strlen(name) - 1] == '/');
}

/*
 * Version of chdir that handles directory pathnames of greater than PATH_MAX
 * length, by changing the working directory to manageable portions of the
 * complete directory pathname. If any of these attempts fail, then it exits
 * non-zero.
 *
 * If a segment (i.e. a portion of "path" between two "/"'s) of the overall
 * pathname is greater than PATH_MAX, then this still won't work, and this
 * routine will return -1 with errno set to ENAMETOOLONG.
 *
 * NOTE: this routine is semantically different to the system chdir in
 * that it is remotely possible for the currently working directory to be
 * changed to a different directory, if a chdir call fails when processing
 * one of the segments of a path that is greater than PATH_MAX. This isn't
 * a problem as this is tar's own specific version of chdir.
 */

static int
tar_chdir(const char *path) {
	const char *sep = "/";
	char *path_copy = NULL;
	char *ptr = NULL;

	/* The trivial case. */
	if (chdir(path) == 0) {
		return (0);
	}
	if (errno == ENAMETOOLONG) {
		if (path[0] == '/' && chdir(sep) != 0)
			return (-1);

		/* strtok(3C) modifies the string, so make a copy. */
		if ((path_copy = strdup(path)) == NULL) {
			return (-1);
		}

		/* chdir(2) for every path element. */
		for (ptr = strtok(path_copy, sep);
			ptr != NULL;
			ptr = strtok(NULL, sep)) {
			if (chdir(ptr) != 0) {
				free(path_copy);
				return (-1);
			}
		}
		free(path_copy);
		return (0);
	}

	/* If chdir fails for any reason except ENAMETOOLONG. */
	return (-1);
}

/*
 * Test if name has a '..' sequence in it.
 *
 * Return 1 if found, 0 otherwise.
 */

static int
has_dot_dot(char *name)
{
	char *s;
	size_t name_len = strlen(name);

	for (s = name; s < (name + name_len - 2); s++) {
		if (s[0] == '.' && s[1] == '.' && ((s[2] == '/') || !s[2]))
			return (1);

		while (! (*s == '/')) {
			if (! *s++)
				return (0);
		}
	}

	return (0);
}

/*
 * Test if name is an absolute path name.
 *
 * Return 1 if true, 0 otherwise.
 */

static int
is_absolute(char *name)
{
#if defined(O_XATTR)
	/*
	 * If this is an extended attribute (whose name will begin with
	 * "/dev/null/", always return 0 as they should be extracted with
	 * the name intact, to allow other tar archiving programs that
	 * don't understand extended attributes, to correctly throw them away.
	 */
	if (xattrp)
		return (0);
#endif

	return (name[0] == '/');
}

/*
 * Adjust the pathname to make it a relative one. Strip off any leading
 * '/' characters and if the pathname contains any '..' sequences, strip
 * upto and including the last occurance of '../' (or '..' if found at
 * the very end of the pathname).
 *
 * Return the relative pathname. stripped_prefix will also return the
 * portion of name that was stripped off and should be freed by the
 * calling routine when no longer needed.
 */

static char *
make_relative_name(char *name, char **stripped_prefix)
{
	char *s;
	size_t prefix_len = 0;
	size_t name_len = strlen(name);

	for (s = name + prefix_len; s < (name + name_len - 2); ) {
		if (s[0] == '.' && s[1] == '.' && ((s[2] == '/') || !s[2]))
			prefix_len = s + 2 - name;

		do {
			char c = *s++;

			if (c == '/')
				break;
		} while (*s);
	}

	for (s = name + prefix_len; *s == '/'; s++)
		continue;
	prefix_len = s - name;

	/* Create the portion of the name that was stripped off. */
	s = malloc(prefix_len + 1);
	memcpy(s, name, prefix_len);
	s[prefix_len] = 0;
	*stripped_prefix = s;
	s = &name[prefix_len];

	return (s);
}

/*
 *  Return through *namep a pointer to the proper fullname (i.e  "<name> |
 *  <prefix>/<name>"), as represented in the header entry dblock.dbuf.
 *
 * Returns 0 if successful, otherwise returns 1.
 */

static int
check_prefix(char **namep, char **dirp, char **compp)
{
	static char fullname[PATH_MAX + 1];
	static char dir[PATH_MAX + 1];
	static char component[PATH_MAX + 1];
	static char savename[PATH_MAX + 1];
	char *s;

	(void) memset(dir, 0, sizeof (dir));
	(void) memset(component, 0, sizeof (component));

	if (xhdr_flgs & _X_PATH) {
		(void) strcpy(fullname, Xtarhdr.x_path);
	} else {
		if (dblock.dbuf.prefix[0] != '\0')
			(void) sprintf(fullname, "%.*s/%.*s", PRESIZ,
			    dblock.dbuf.prefix, NAMSIZ, dblock.dbuf.name);
		else
			(void) sprintf(fullname, "%.*s", NAMSIZ,
			    dblock.dbuf.name);
	}

	/*
	 * If we are printing a table of contents or extracting an archive,
	 * make absolute pathnames relative and prohibit the unpacking of
	 * files contain ".." in their name (unless the user has supplied
	 * the -P option).
	 */
	if ((tflag || xflag) && !Pflag) {
		if (is_absolute(fullname) || has_dot_dot(fullname)) {
			char *stripped_prefix;

			(void) strcpy(savename, fullname);
			strcpy(fullname,
			    make_relative_name(savename, &stripped_prefix));
			(void) fprintf(stderr,
			    gettext("tar: Removing leading '%s' from '%s'\n"),
			    stripped_prefix, savename);
			free(stripped_prefix);
		}
	}

	/*
	 * Set dir and component names
	 */

	get_parent(fullname, dir);

#if defined(O_XATTR)
	if (xattrp == NULL) {
#endif
		/*
		 * Save of real name since were going to chop off the
		 * trailing slashes.
		 */
		(void) strcpy(savename, fullname);
		/*
		 * first strip of trailing slashes.
		 */
		chop_endslashes(savename);
		s = get_component(savename);
		(void) strcpy(component, s);

#if defined(O_XATTR)
	} else {
		(void) strcpy(fullname, xattrp->h_names);
		(void) strcpy(dir, fullname);
		(void) strcpy(component, basename(xattrp->h_names +
		    strlen(xattrp->h_names) + 1));
	}
#endif
	*namep = fullname;
	*dirp = dir;
	*compp = component;

	return (0);
}

/*
 * Return true if the object indicated by the file descriptor and type
 * is a tape device, false otherwise
 */

static int
istape(int fd, int type)
{
	int result = 0;

	if (S_ISCHR(type)) {
		struct mtget mtg;

		if (ioctl(fd, MTIOCGET, &mtg) != -1) {
			result = 1;
		}
	}

	return (result);
}

#include <utmpx.h>

struct utmpx utmpx;

#define	NMAX	(sizeof (utmpx.ut_name))

typedef struct cachenode {	/* this struct must be zeroed before using */
	struct cachenode *next;	/* next in hash chain */
	int val;		/* the uid or gid of this entry */
	int namehash;		/* name's hash signature */
	char name[NMAX+1];	/* the string that val maps to */
} cachenode_t;

#define	HASHSIZE	256

static cachenode_t *names[HASHSIZE];
static cachenode_t *groups[HASHSIZE];
static cachenode_t *uids[HASHSIZE];
static cachenode_t *gids[HASHSIZE];

static int
hash_byname(char *name)
{
	int i, c, h = 0;

	for (i = 0; i < NMAX; i++) {
		c = name[i];
		if (c == '\0')
			break;
		h = (h << 4) + h + c;
	}
	return (h);
}

static cachenode_t *
hash_lookup_byval(cachenode_t *table[], int val)
{
	int h = val;
	cachenode_t *c;

	for (c = table[h & (HASHSIZE - 1)]; c != NULL; c = c->next) {
		if (c->val == val)
			return (c);
	}
	return (NULL);
}

static cachenode_t *
hash_lookup_byname(cachenode_t *table[], char *name)
{
	int h = hash_byname(name);
	cachenode_t *c;

	for (c = table[h & (HASHSIZE - 1)]; c != NULL; c = c->next) {
		if (c->namehash == h && strcmp(c->name, name) == 0)
			return (c);
	}
	return (NULL);
}

static cachenode_t *
hash_insert(cachenode_t *table[], char *name, int value)
{
	cachenode_t *c;
	int signature;

	c = calloc(1, sizeof (cachenode_t));
	if (c == NULL) {
		perror("malloc");
		exit(1);
	}
	if (name != NULL) {
		(void) strncpy(c->name, name, NMAX);
		c->namehash = hash_byname(name);
	}
	c->val = value;
	if (table == uids || table == gids)
		signature = c->val;
	else
		signature = c->namehash;
	c->next = table[signature & (HASHSIZE - 1)];
	table[signature & (HASHSIZE - 1)] = c;
	return (c);
}

static char *
getname(uid_t uid)
{
	cachenode_t *c;

	if ((c = hash_lookup_byval(uids, uid)) == NULL) {
		struct passwd *pwent = getpwuid(uid);
		c = hash_insert(uids, pwent ? pwent->pw_name : NULL, uid);
	}
	return (c->name);
}

static char *
getgroup(gid_t gid)
{
	cachenode_t *c;

	if ((c = hash_lookup_byval(gids, gid)) == NULL) {
		struct group *grent = getgrgid(gid);
		c = hash_insert(gids, grent ? grent->gr_name : NULL, gid);
	}
	return (c->name);
}

static uid_t
getuidbyname(char *name)
{
	cachenode_t *c;

	if ((c = hash_lookup_byname(names, name)) == NULL) {
		struct passwd *pwent = getpwnam(name);
		c = hash_insert(names, name, pwent ? (int)pwent->pw_uid : -1);
	}
	return ((uid_t)c->val);
}

static gid_t
getgidbyname(char *group)
{
	cachenode_t *c;

	if ((c = hash_lookup_byname(groups, group)) == NULL) {
		struct group *grent = getgrnam(group);
		c = hash_insert(groups, group, grent ? (int)grent->gr_gid : -1);
	}
	return ((gid_t)c->val);
}

/*
 * Build the header.
 * Determine whether or not an extended header is also needed.  If needed,
 * create and write the extended header and its data.
 * Writing of the extended header assumes that "tomodes" has been called and
 * the relevant information has been placed in the header block.
 */

static int
build_dblock(
	const char		*name,
	const char		*linkname,
	const char		typeflag,
	const int		filetype,
	const struct stat	*sp,
	const dev_t		device,
	const char		*prefix)
{
	int nblks;
	major_t		dev;
	const char	*filename;
	const char	*lastslash;

	if (filetype == XATTR_FILE)
		dblock.dbuf.typeflag = _XATTR_HDRTYPE;
	else
		dblock.dbuf.typeflag = typeflag;
	(void) memset(dblock.dbuf.name, '\0', NAMSIZ);
	(void) memset(dblock.dbuf.linkname, '\0', NAMSIZ);
	(void) memset(dblock.dbuf.prefix, '\0', PRESIZ);

	if (xhdr_flgs & _X_PATH)
		filename = Xtarhdr.x_path;
	else
		filename = name;

	if ((dev = major(device)) > OCTAL7CHAR) {
		if (Eflag) {
			xhdr_flgs |= _X_DEVMAJOR;
			Xtarhdr.x_devmajor = dev;
		} else {
			(void) fprintf(stderr, gettext(
			    "Device major too large for %s.  Use -E flag."),
			    filename);
			if (errflag)
				done(1);
			else
				Errflg = 1;
		}
		dev = 0;
	}
	(void) sprintf(dblock.dbuf.devmajor, "%07lo", dev);
	if ((dev = minor(device)) > OCTAL7CHAR) {
		if (Eflag) {
			xhdr_flgs |= _X_DEVMINOR;
			Xtarhdr.x_devminor = dev;
		} else {
			(void) fprintf(stderr, gettext(
			    "Device minor too large for %s.  Use -E flag."),
			    filename);
			if (errflag)
				done(1);
			else
				Errflg = 1;
		}
		dev = 0;
	}
	(void) sprintf(dblock.dbuf.devminor, "%07lo", dev);

	(void) strncpy(dblock.dbuf.name, name, NAMSIZ);
	(void) strncpy(dblock.dbuf.linkname, linkname, NAMSIZ);
	(void) sprintf(dblock.dbuf.magic, "%.5s", magic_type);
	(void) sprintf(dblock.dbuf.version, "00");
	(void) sprintf(dblock.dbuf.uname, "%.31s", getname(sp->st_uid));
	(void) sprintf(dblock.dbuf.gname, "%.31s", getgroup(sp->st_gid));
	(void) strncpy(dblock.dbuf.prefix, prefix, PRESIZ);
	(void) sprintf(dblock.dbuf.chksum, "%07o", checksum(&dblock));

	if (Eflag) {
		(void) bcopy(dblock.dummy, xhdr_buf.dummy, TBLOCK);
		(void) memset(xhdr_buf.dbuf.name, '\0', NAMSIZ);
		lastslash = strrchr(name, '/');
		if (lastslash == NULL)
			lastslash = name;
		else
			lastslash++;
		(void) strcpy(xhdr_buf.dbuf.name, lastslash);
		(void) memset(xhdr_buf.dbuf.linkname, '\0', NAMSIZ);
		(void) memset(xhdr_buf.dbuf.prefix, '\0', PRESIZ);
		(void) strcpy(xhdr_buf.dbuf.prefix, xhdr_dirname);
		xhdr_count++;
		xrec_offset = 0;
		gen_date("mtime", sp->st_mtim);
		xhdr_buf.dbuf.typeflag = 'X';
		if (gen_utf8_names(filename) != 0)
			return (1);

#ifdef XHDR_DEBUG
		Xtarhdr.x_uname = dblock.dbuf.uname;
		Xtarhdr.x_gname = dblock.dbuf.gname;
		xhdr_flgs |= (_X_UNAME | _X_GNAME);
#endif
		if (xhdr_flgs) {
			if (xhdr_flgs & _X_DEVMAJOR)
				gen_num("SUN.devmajor", Xtarhdr.x_devmajor);
			if (xhdr_flgs & _X_DEVMINOR)
				gen_num("SUN.devminor", Xtarhdr.x_devminor);
			if (xhdr_flgs & _X_GID)
				gen_num("gid", Xtarhdr.x_gid);
			if (xhdr_flgs & _X_UID)
				gen_num("uid", Xtarhdr.x_uid);
			if (xhdr_flgs & _X_SIZE)
				gen_num("size", Xtarhdr.x_filesz);
			if (xhdr_flgs & _X_PATH)
				gen_string("path", Xtarhdr.x_path);
			if (xhdr_flgs & _X_LINKPATH)
				gen_string("linkpath", Xtarhdr.x_linkpath);
			if (xhdr_flgs & _X_GNAME)
				gen_string("gname", Xtarhdr.x_gname);
			if (xhdr_flgs & _X_UNAME)
				gen_string("uname", Xtarhdr.x_uname);
		}
		(void) sprintf(xhdr_buf.dbuf.size,
		    "%011" FMT_off_t_o, xrec_offset);
		(void) sprintf(xhdr_buf.dbuf.chksum, "%07o",
		    checksum(&xhdr_buf));
		(void) writetbuf((char *)&xhdr_buf, 1);
		nblks = TBLOCKS(xrec_offset);
		(void) writetbuf(xrec_ptr, nblks);
	}
	return (0);
}


/*
 *  makeDir - ensure that a directory with the pathname denoted by name
 *            exists, and return 1 on success, and 0 on failure (e.g.,
 *	      read-only file system, exists but not-a-directory).
 */

static int
makeDir(char *name)
{
	struct stat buf;

	if (access(name, 0) < 0) {  /* name doesn't exist */
		if (mkdir(name, 0777) < 0) {
			vperror(0, "%s", name);
			return (0);
		}
	} else {		   /* name exists */
		if (stat(name, &buf) < 0) {
			vperror(0, "%s", name);
			return (0);
		}

		return ((buf.st_mode & S_IFMT) == S_IFDIR);
	}

	return (1);
}


/*
 * Save this directory and its mtime on the stack, popping and setting
 * the mtimes of any stacked dirs which aren't parents of this one.
 * A null name causes the entire stack to be unwound and set.
 *
 * Since all the elements of the directory "stack" share a common
 * prefix, we can make do with one string.  We keep only the current
 * directory path, with an associated array of mtime's. A negative
 * mtime means no mtime.
 *
 * This stack algorithm is not guaranteed to work for tapes created
 * with the 'r' function letter, but the vast majority of tapes with
 * directories are not.  This avoids saving every directory record on
 * the tape and setting all the times at the end.
 *
 * (This was borrowed from the 4.1.3 source, and adapted to the 5.x
 *  environment)
 */

static void
doDirTimes(char *name, timestruc_t modTime)
{
	static char dirstack[PATH_MAX+2];
			/* Add spaces for the last slash and last NULL */
	static timestruc_t	modtimes[PATH_MAX+1]; /* hash table */
	char *p = dirstack;
	char *q = name;
	char *savp;

	if (q) {
		/*
		 * Find common prefix
		 */

		while (*p == *q && *p) {
			p++; q++;
		}
	}

	savp = p;
	while (*p) {
		/*
		 * Not a child: unwind the stack, setting the times.
		 * The order we do this doesn't matter, so we go "forward."
		 */

		if (*p == '/')
			if (modtimes[p - dirstack].tv_sec >= 0) {
				*p = '\0';	 /* zap the slash */
				setPathTimes(AT_FDCWD, dirstack,
				    modtimes[p - dirstack]);
				*p = '/';
			}
		++p;
	}

	p = savp;

	/*
	 *  Push this one on the "stack"
	 */

	if (q) {

		/*
		 * Since the name parameter points the dir pathname
		 * which is limited only to contain PATH_MAX chars
		 * at maximum, we can ignore the overflow case of p.
		 */

		while ((*p = *q++)) {	/* append the rest of the new dir */
			modtimes[p - dirstack].tv_sec = -1;
			p++;
		}

		/*
		 * If the tar file had used 'P' or 'E' function modifier,
		 * append the last slash.
		 */
		if (*(p - 1) != '/') {
			*p++ = '/';
			*p = '\0';
		}
		/* overwrite the last one */
		modtimes[p - dirstack - 1] = modTime;
	}
}


/*
 *  setPathTimes - set the modification time for given path.  Return 1 if
 *                 successful and 0 if not successful.
 */

static void
setPathTimes(int dirfd, char *path, timestruc_t modTime)

{
	struct timeval timebuf[2];

	/*
	 * futimesat takes an array of two timeval structs.
	 * The first entry contains access time.
	 * The second entry contains modification time.
	 * Unlike a timestruc_t, which uses nanoseconds, timeval uses
	 * microseconds.
	 */
	timebuf[0].tv_sec = time((time_t *)0);
	timebuf[0].tv_usec = 0;
	timebuf[1].tv_sec = modTime.tv_sec;

	/* Extended header: use microseconds */
	timebuf[1].tv_usec = (xhdr_flgs & _X_MTIME) ? modTime.tv_nsec/1000 : 0;

	if (futimesat(dirfd, path, timebuf) < 0)
		vperror(0, gettext("can't set time on %s"), path);
}


/*
 * If hflag is set then delete the symbolic link's target.
 * If !hflag then delete the target.
 */

static void
delete_target(int fd, char *comp, char *namep)
{
	struct	stat	xtractbuf;
	char buf[PATH_MAX + 1];
	int n;


	if (unlinkat(fd, comp, AT_REMOVEDIR) < 0) {
		if (errno == ENOTDIR && !hflag) {
			(void) unlinkat(fd, comp, 0);
		} else if (errno == ENOTDIR && hflag) {
			if (!lstat(namep, &xtractbuf)) {
				if ((xtractbuf.st_mode & S_IFMT) != S_IFLNK) {
					(void) unlinkat(fd, comp, 0);
				} else if ((n = readlink(namep, buf,
				    PATH_MAX)) != -1) {
					buf[n] = (char)NULL;
					(void) unlinkat(fd, buf,
					    AT_REMOVEDIR);
					if (errno == ENOTDIR)
						(void) unlinkat(fd, buf, 0);
				} else {
					(void) unlinkat(fd, comp, 0);
				}
			} else {
				(void) unlinkat(fd, comp, 0);
			}
		}
	}
}


/*
 * ACL changes:
 *	putfile():
 *		Get acl info after stat. Write out ancillary file
 *		before the normal file, i.e. directory, regular, FIFO,
 *		link, special. If acl count is less than 4, no need to
 *		create ancillary file. (i.e. standard permission is in
 *		use.
 *	doxtract():
 *		Process ancillary file. Read it in and set acl info.
 *		watch out for 'o' function modifier.
 *	't' function letter to display table
 */

/*
 * New functions for ACLs and other security attributes
 */

/*
 * The function appends the new security attribute info to the end of
 * existing secinfo.
 */
int
append_secattr(
	char	 **secinfo,	/* existing security info */
	int	 *secinfo_len,	/* length of existing security info */
	int	 size,		/* new attribute size: unit depends on type */
	char	*attrtext,	/* new attribute text */
	char	 attr_type)	/* new attribute type */
{
	char	*new_secinfo;
	int	newattrsize;
	int	oldsize;
	struct sec_attr	*attr;

	/* no need to add */
	if (attr_type != DIR_TYPE) {
		if (attrtext == NULL)
			return (0);
	}

	switch (attr_type) {
	case UFSD_ACL:
	case ACE_ACL:
		if (attrtext == NULL) {
			(void) fprintf(stderr, gettext("acltotext failed\n"));
			return (-1);
		}
		/* header: type + size = 8 */
		newattrsize = 8 + (int)strlen(attrtext) + 1;
		attr = (struct sec_attr *)malloc(newattrsize);
		if (attr == NULL) {
			(void) fprintf(stderr,
			    gettext("can't allocate memory\n"));
			return (-1);
		}
		attr->attr_type = attr_type;
		(void) sprintf(attr->attr_len,
		    "%06o", size); /* acl entry count */
		(void) strcpy((char *)&attr->attr_info[0], attrtext);
		free(attrtext);
		break;

	/* Trusted Extensions */
	case DIR_TYPE:
	case LBL_TYPE:
		newattrsize = sizeof (struct sec_attr) + strlen(attrtext);
		attr = (struct sec_attr *)malloc(newattrsize);
		if (attr == NULL) {
			(void) fprintf(stderr,
			gettext("can't allocate memory\n"));
			return (-1);
		}
		attr->attr_type = attr_type;
		(void) sprintf(attr->attr_len,
		    "%06d", size); /* len of attr data */
		(void) strcpy((char *)&attr->attr_info[0], attrtext);
		break;

	default:
		(void) fprintf(stderr,
		    gettext("unrecognized attribute type\n"));
		return (-1);
	}

	/* old security info + new attr header(8) + new attr */
	oldsize = *secinfo_len;
	*secinfo_len += newattrsize;
	new_secinfo = (char *)malloc(*secinfo_len);
	if (new_secinfo == NULL) {
		(void) fprintf(stderr, gettext("can't allocate memory\n"));
		*secinfo_len -= newattrsize;
		free(attr);
		return (-1);
	}

	(void) memcpy(new_secinfo, *secinfo, oldsize);
	(void) memcpy(new_secinfo + oldsize, attr, newattrsize);

	free(*secinfo);
	free(attr);
	*secinfo = new_secinfo;
	return (0);
}

/*
 * write_ancillary(): write out an ancillary file.
 *      The file has the same header as normal file except the type and size
 *      fields. The type is 'A' and size is the sum of all attributes
 *	in bytes.
 *	The body contains a list of attribute type, size and info. Currently,
 *	there is only ACL info.  This file is put before the normal file.
 */
void
write_ancillary(union hblock *dblockp, char *secinfo, int len, char hdrtype)
{
	long    blocks;
	int	savflag;
	int	savsize;

	/* Just tranditional permissions or no security attribute info */
	if (len == 0 || secinfo == NULL)
		return;

	/* save flag and size */
	savflag = (dblockp->dbuf).typeflag;
	(void) sscanf(dblockp->dbuf.size, "%12o", (uint_t *)&savsize);

	/* special flag for ancillary file */
	if (hdrtype == _XATTR_HDRTYPE)
		dblockp->dbuf.typeflag = _XATTR_HDRTYPE;
	else
		dblockp->dbuf.typeflag = 'A';

	/* for pre-2.5 versions of tar, need to make sure */
	/* the ACL file is readable			  */
	(void) sprintf(dblock.dbuf.mode, "%07lo",
	    (stbuf.st_mode & POSIXMODES) | 0000200);
	(void) sprintf(dblockp->dbuf.size, "%011o", len);
	(void) sprintf(dblockp->dbuf.chksum, "%07o", checksum(dblockp));

	/* write out the header */
	(void) writetbuf((char *)dblockp, 1);

	/* write out security info */
	blocks = TBLOCKS(len);
	(void) writetbuf((char *)secinfo, (int)blocks);

	/* restore mode, flag and size */
	(void) sprintf(dblock.dbuf.mode, "%07lo", stbuf.st_mode & POSIXMODES);
	dblockp->dbuf.typeflag = savflag;
	(void) sprintf(dblockp->dbuf.size, "%011o", savsize);
}

/*
 * Read the data record for extended headers and then the regular header.
 * The data are read into the buffer and then null-terminated.  Entries
 * for typeflag 'X' extended headers are of the format:
 * 	"%d %s=%s\n"
 *
 * When an extended header record is found, the extended header must
 * be processed and its values used to override the values in the
 * normal header.  The way this is done is to process the extended
 * header data record and set the data values, then call getdir
 * to process the regular header, then then to reconcile the two
 * sets of data.
 */

static int
get_xdata(void)
{
	struct keylist_pair {
		int keynum;
		char *keylist;
	}	keylist_pair[] = {	_X_DEVMAJOR, "SUN.devmajor",
					_X_DEVMINOR, "SUN.devminor",
					_X_GID, "gid",
					_X_GNAME, "gname",
					_X_LINKPATH, "linkpath",
					_X_PATH, "path",
					_X_SIZE, "size",
					_X_UID, "uid",
					_X_UNAME, "uname",
					_X_MTIME, "mtime",
					_X_LAST, "NULL" };
	char		*lineloc;
	int		length, i;
	char		*keyword, *value;
	blkcnt_t	nblocks;
	int		bufneeded;
	int		errors;

	(void) memset(&Xtarhdr, 0, sizeof (Xtarhdr));
	xhdr_count++;
	errors = 0;

	nblocks = TBLOCKS(stbuf.st_size);
	bufneeded = nblocks * TBLOCK;
	if (bufneeded >= xrec_size) {
		free(xrec_ptr);
		xrec_size = bufneeded + 1;
		if ((xrec_ptr = malloc(xrec_size)) == NULL)
			fatal(gettext("cannot allocate buffer"));
	}

	lineloc = xrec_ptr;

	while (nblocks-- > 0) {
		readtape(lineloc);
		lineloc += TBLOCK;
	}
	lineloc = xrec_ptr;
	xrec_ptr[stbuf.st_size] = '\0';
	while (lineloc < xrec_ptr + stbuf.st_size) {
		if (dblock.dbuf.typeflag == 'L') {
			length = xrec_size;
			keyword = "path";
			value = lineloc;
		} else {
			length = atoi(lineloc);
			*(lineloc + length - 1) = '\0';
			keyword = strchr(lineloc, ' ') + 1;
			value = strchr(keyword, '=') + 1;
			*(value - 1) = '\0';
		}
		i = 0;
		lineloc += length;
		while (keylist_pair[i].keynum != (int)_X_LAST) {
			if (strcmp(keyword, keylist_pair[i].keylist) == 0)
				break;
			i++;
		}
		errno = 0;
		switch (keylist_pair[i].keynum) {
		case _X_DEVMAJOR:
			Xtarhdr.x_devmajor = (major_t)strtoul(value, NULL, 0);
			if (errno) {
				(void) fprintf(stderr, gettext(
				    "tar: Extended header major value error "
				    "for file # %llu.\n"), xhdr_count);
				errors++;
			} else
				xhdr_flgs |= _X_DEVMAJOR;
			break;
		case _X_DEVMINOR:
			Xtarhdr.x_devminor = (minor_t)strtoul(value, NULL, 0);
			if (errno) {
				(void) fprintf(stderr, gettext(
				    "tar: Extended header minor value error "
				    "for file # %llu.\n"), xhdr_count);
				errors++;
			} else
				xhdr_flgs |= _X_DEVMINOR;
			break;
		case _X_GID:
			xhdr_flgs |= _X_GID;
			Xtarhdr.x_gid = strtol(value, NULL, 0);
			if ((errno) || (Xtarhdr.x_gid > UID_MAX)) {
				(void) fprintf(stderr, gettext(
				    "tar: Extended header gid value error "
				    "for file # %llu.\n"), xhdr_count);
				Xtarhdr.x_gid = GID_NOBODY;
			}
			break;
		case _X_GNAME:
			if (utf8_local("gname", &Xtarhdr.x_gname,
			    local_gname, value, _POSIX_NAME_MAX) == 0)
				xhdr_flgs |= _X_GNAME;
			break;
		case _X_LINKPATH:
			if (utf8_local("linkpath", &Xtarhdr.x_linkpath,
			    local_linkpath, value, PATH_MAX) == 0)
				xhdr_flgs |= _X_LINKPATH;
			else
				errors++;
			break;
		case _X_PATH:
			if (utf8_local("path", &Xtarhdr.x_path,
			    local_path, value, PATH_MAX) == 0)
				xhdr_flgs |= _X_PATH;
			else
				errors++;
			break;
		case _X_SIZE:
			Xtarhdr.x_filesz = strtoull(value, NULL, 0);
			if (errno) {
				(void) fprintf(stderr, gettext(
				    "tar: Extended header invalid filesize "
				    "for file # %llu.\n"), xhdr_count);
				errors++;
			} else
				xhdr_flgs |= _X_SIZE;
			break;
		case _X_UID:
			xhdr_flgs |= _X_UID;
			Xtarhdr.x_uid = strtol(value, NULL, 0);
			if ((errno) || (Xtarhdr.x_uid > UID_MAX)) {
				(void) fprintf(stderr, gettext(
				    "tar: Extended header uid value error "
				    "for file # %llu.\n"), xhdr_count);
				Xtarhdr.x_uid = UID_NOBODY;
			}
			break;
		case _X_UNAME:
			if (utf8_local("uname", &Xtarhdr.x_uname,
			    local_uname, value, _POSIX_NAME_MAX) == 0)
				xhdr_flgs |= _X_UNAME;
			break;
		case _X_MTIME:
			get_xtime(value, &(Xtarhdr.x_mtime));
			if (errno)
				(void) fprintf(stderr, gettext(
				    "tar: Extended header modification time "
				    "value error for file # %llu.\n"),
				    xhdr_count);
			else
				xhdr_flgs |= _X_MTIME;
			break;
		default:
			(void) fprintf(stderr,
			    gettext("tar:  unrecognized extended"
			    " header keyword '%s'.  Ignored.\n"), keyword);
			break;
		}
	}

	getdir();	/* get regular header */
	if (errors && errflag)
		done(1);
	else
		if (errors)
			Errflg = 1;
	return (errors);
}

/*
 * load_info_from_xtarhdr - sets Gen and stbuf variables from
 *	extended header
 *	load_info_from_xtarhdr(flag, xhdrp);
 *	u_longlong_t flag;	xhdr_flgs
 *	struct xtar_hdr *xhdrp; pointer to extended header
 *	NOTE:	called when typeflag is not 'A' and xhdr_flgs
 *		is set.
 */
static void
load_info_from_xtarhdr(u_longlong_t flag, struct xtar_hdr *xhdrp)
{
	if (flag & _X_DEVMAJOR) {
		Gen.g_devmajor = xhdrp->x_devmajor;
	}
	if (flag & _X_DEVMINOR) {
		Gen.g_devminor = xhdrp->x_devminor;
	}
	if (flag & _X_GID) {
		Gen.g_gid = xhdrp->x_gid;
		stbuf.st_gid = xhdrp->x_gid;
	}
	if (flag & _X_UID) {
		Gen.g_uid = xhdrp->x_uid;
		stbuf.st_uid  = xhdrp->x_uid;
	}
	if (flag & _X_SIZE) {
		Gen.g_filesz = xhdrp->x_filesz;
		stbuf.st_size = xhdrp->x_filesz;
	}
	if (flag & _X_MTIME) {
		Gen.g_mtime = xhdrp->x_mtime.tv_sec;
		stbuf.st_mtim.tv_sec = xhdrp->x_mtime.tv_sec;
		stbuf.st_mtim.tv_nsec = xhdrp->x_mtime.tv_nsec;
	}
}

/*
 * gen_num creates a string from a keyword and an usigned long long in the
 * format:  %d %s=%s\n
 * This is part of the extended header data record.
 */

void
gen_num(const char *keyword, const u_longlong_t number)
{
	char	save_val[ULONGLONG_MAX_DIGITS + 1];
	int	len;
	char	*curr_ptr;

	(void) sprintf(save_val, "%llu", number);
	/*
	 * len = length of entire line, including itself.  len will be
	 * two digits.  So, add the string lengths plus the length of len,
	 * plus a blank, an equal sign, and a newline.
	 */
	len = strlen(save_val) + strlen(keyword) + 5;
	if (xrec_offset + len > xrec_size) {
		if (((curr_ptr = realloc(xrec_ptr, 2 * xrec_size)) == NULL))
			fatal(gettext(
			    "cannot allocate extended header buffer"));
		xrec_ptr = curr_ptr;
		xrec_size *= 2;
	}
	(void) sprintf(&xrec_ptr[xrec_offset],
	    "%d %s=%s\n", len, keyword, save_val);
	xrec_offset += len;
}

/*
 * gen_date creates a string from a keyword and a timestruc_t in the
 * format:  %d %s=%s\n
 * This is part of the extended header data record.
 * Currently, granularity is only microseconds, so the low-order three digits
 * will be truncated.
 */

void
gen_date(const char *keyword, const timestruc_t time_value)
{
	/* Allow for <seconds>.<nanoseconds>\n */
	char	save_val[TIME_MAX_DIGITS + LONG_MAX_DIGITS + 2];
	int	len;
	char	*curr_ptr;

	(void) sprintf(save_val, "%ld", time_value.tv_sec);
	len = strlen(save_val);
	save_val[len] = '.';
	(void) sprintf(&save_val[len + 1], "%9.9ld", time_value.tv_nsec);

	/*
	 * len = length of entire line, including itself.  len will be
	 * two digits.  So, add the string lengths plus the length of len,
	 * plus a blank, an equal sign, and a newline.
	 */
	len = strlen(save_val) + strlen(keyword) + 5;
	if (xrec_offset + len > xrec_size) {
		if (((curr_ptr = realloc(xrec_ptr, 2 * xrec_size)) == NULL))
			fatal(gettext(
			    "cannot allocate extended header buffer"));
		xrec_ptr = curr_ptr;
		xrec_size *= 2;
	}
	(void) sprintf(&xrec_ptr[xrec_offset],
	    "%d %s=%s\n", len, keyword, save_val);
	xrec_offset += len;
}

/*
 * gen_string creates a string from a keyword and a char * in the
 * format:  %d %s=%s\n
 * This is part of the extended header data record.
 */

void
gen_string(const char *keyword, const char *value)
{
	int	len;
	char	*curr_ptr;

	/*
	 * len = length of entire line, including itself.  The character length
	 * of len must be 1-4 characters, because the maximum size of the path
	 * or the name is PATH_MAX, which is 1024.  So, assume 1 character
	 * for len, one for the space, one for the "=", and one for the newline.
	 * Then adjust as needed.
	 */
	/* LINTED constant expression */
	assert(PATH_MAX <= 9996);
	len = strlen(value) + strlen(keyword) + 4;
	if (len > 997)
		len += 3;
	else if (len > 98)
		len += 2;
	else if (len > 9)
		len += 1;
	if (xrec_offset + len > xrec_size) {
		if (((curr_ptr = realloc(xrec_ptr, 2 * xrec_size)) == NULL))
			fatal(gettext(
			    "cannot allocate extended header buffer"));
		xrec_ptr = curr_ptr;
		xrec_size *= 2;
	}
#ifdef XHDR_DEBUG
	if (strcmp(keyword+1, "name") != 0)
#endif
	(void) sprintf(&xrec_ptr[xrec_offset],
	    "%d %s=%s\n", len, keyword, value);
#ifdef XHDR_DEBUG
	else {
	len += 11;
	(void) sprintf(&xrec_ptr[xrec_offset],
	    "%d %s=%snametoolong\n", len, keyword, value);
	}
#endif
	xrec_offset += len;
}

/*
 * Convert time found in the extended header data to seconds and nanoseconds.
 */

void
get_xtime(char *value, timestruc_t *xtime)
{
	char nanosec[10];
	char *period;
	int i;

	(void) memset(nanosec, '0', 9);
	nanosec[9] = '\0';

	period = strchr(value, '.');
	if (period != NULL)
		period[0] = '\0';
	xtime->tv_sec = strtol(value, NULL, 10);
	if (period == NULL)
		xtime->tv_nsec = 0;
	else {
		i = strlen(period +1);
		(void) strncpy(nanosec, period + 1, min(i, 9));
		xtime->tv_nsec = strtol(nanosec, NULL, 10);
	}
}

/*
 *	Check linkpath for length.
 *	Emit an error message and return 1 if too long.
 */

int
chk_path_build(
	char	*name,
	char	*longname,
	char	*linkname,
	char	*prefix,
	char	type,
	int	filetype)
{

	if (strlen(linkname) > (size_t)NAMSIZ) {
		if (Eflag > 0) {
			xhdr_flgs |= _X_LINKPATH;
			Xtarhdr.x_linkpath = linkname;
		} else {
			(void) fprintf(stderr, gettext(
			    "tar: %s: linked to %s\n"), longname, linkname);
			(void) fprintf(stderr, gettext(
			    "tar: %s: linked name too long\n"), linkname);
			if (errflag)
				done(1);
			else
				Errflg = 1;
			return (1);
		}
	}
	if (xhdr_flgs & _X_LINKPATH)
		return (build_dblock(name, tchar, type,
		    filetype, &stbuf, stbuf.st_dev,
		    prefix));
	else
		return (build_dblock(name, linkname, type,
		    filetype, &stbuf, stbuf.st_dev, prefix));
}

/*
 * Convert from UTF-8 to local character set.
 */

static int
utf8_local(
	char		*option,
	char		**Xhdr_ptrptr,
	char		*target,
	const char	*source,
	int		max_val)
{
	static	iconv_t	iconv_cd;
	char		*nl_target;
	const	char	*iconv_src;
	char		*iconv_trg;
	size_t		inlen;
	size_t		outlen;

	if (charset_type == -1) {	/* iconv_open failed in earlier try */
		(void) fprintf(stderr, gettext(
		    "tar:  file # %llu: (%s) UTF-8 conversion failed.\n"),
		    xhdr_count, source);
		return (1);
	} else if (charset_type == 0) {	/* iconv_open has not yet been done */
		nl_target = nl_langinfo(CODESET);
		if (strlen(nl_target) == 0)	/* locale using 7-bit codeset */
			nl_target = "646";
		if (strcmp(nl_target, "646") == 0)
			charset_type = 1;
		else if (strcmp(nl_target, "UTF-8") == 0)
			charset_type = 3;
		else {
			if (strncmp(nl_target, "ISO", 3) == 0)
				nl_target += 3;
			charset_type = 2;
			errno = 0;
			if ((iconv_cd = iconv_open(nl_target, "UTF-8")) ==
			    (iconv_t)-1) {
				if (errno == EINVAL)
					(void) fprintf(stderr, gettext(
					    "tar: conversion routines not "
					    "available for current locale.  "));
				(void) fprintf(stderr, gettext(
				    "file # %llu: (%s) UTF-8 conversion"
				    " failed.\n"), xhdr_count, source);
				charset_type = -1;
				return (1);
			}
		}
	}

	/* locale using 7-bit codeset or UTF-8 locale */
	if (charset_type == 1 || charset_type == 3) {
		if (strlen(source) > max_val) {
			(void) fprintf(stderr, gettext(
			    "tar: file # %llu: Extended header %s too long.\n"),
			    xhdr_count, option);
			return (1);
		}
		if (charset_type == 3)
			(void) strcpy(target, source);
		else if (c_utf8(target, source) != 0) {
			(void) fprintf(stderr, gettext(
			    "tar:  file # %llu: (%s) UTF-8 conversion"
			    " failed.\n"), xhdr_count, source);
			return (1);
		}
		*Xhdr_ptrptr = target;
		return (0);
	}

	iconv_src = source;
	iconv_trg = target;
	inlen = strlen(source);
	outlen = max_val * UTF_8_FACTOR;
	if (iconv(iconv_cd, &iconv_src, &inlen, &iconv_trg, &outlen) ==
	    (size_t)-1) {	/* Error occurred:  didn't convert */
		(void) fprintf(stderr, gettext(
		    "tar:  file # %llu: (%s) UTF-8 conversion failed.\n"),
		    xhdr_count, source);
		/* Get remaining output; reinitialize conversion descriptor */
		iconv_src = (const char *)NULL;
		inlen = 0;
		(void) iconv(iconv_cd, &iconv_src, &inlen, &iconv_trg, &outlen);
		return (1);
	}
	/* Get remaining output; reinitialize conversion descriptor */
	iconv_src = (const char *)NULL;
	inlen = 0;
	if (iconv(iconv_cd, &iconv_src, &inlen, &iconv_trg, &outlen) ==
	    (size_t)-1) {	/* Error occurred:  didn't convert */
		(void) fprintf(stderr, gettext(
		    "tar:  file # %llu: (%s) UTF-8 conversion failed.\n"),
		    xhdr_count, source);
		return (1);
	}

	*iconv_trg = '\0';	/* Null-terminate iconv output string */
	if (strlen(target) > max_val) {
		(void) fprintf(stderr, gettext(
		    "tar: file # %llu: Extended header %s too long.\n"),
		    xhdr_count, option);
		return (1);
	}
	*Xhdr_ptrptr = target;
	return (0);
}

/*
 * Check gname, uname, path, and linkpath to see if they need to go in an
 * extended header.  If they are already slated to be in an extended header,
 * or if they are not ascii, then they need to be in the extended header.
 * Then, convert all extended names to UTF-8.
 */

int
gen_utf8_names(const char *filename)
{
	static	iconv_t	iconv_cd;
	char		*nl_target;
	char		tempbuf[MAXNAM + 1];
	int		nbytes;
	int		errors;

	if (charset_type == -1)	{	/* Previous failure to open. */
		(void) fprintf(stderr, gettext(
		    "tar: file # %llu: UTF-8 conversion failed.\n"),
		    xhdr_count);
		return (1);
	}

	if (charset_type == 0) {	/* Need to get conversion descriptor */
		nl_target = nl_langinfo(CODESET);
		if (strlen(nl_target) == 0)	/* locale using 7-bit codeset */
			nl_target = "646";
		if (strcmp(nl_target, "646") == 0)
			charset_type = 1;
		else if (strcmp(nl_target, "UTF-8") == 0)
			charset_type = 3;
		else {
			if (strncmp(nl_target, "ISO", 3) == 0)
				nl_target += 3;
			charset_type = 2;
			errno = 0;
#ifdef ICONV_DEBUG
			(void) fprintf(stderr,
			    gettext("Opening iconv_cd with target %s\n"),
			    nl_target);
#endif
			if ((iconv_cd = iconv_open("UTF-8", nl_target)) ==
			    (iconv_t)-1) {
				if (errno == EINVAL)
					(void) fprintf(stderr, gettext(
					    "tar: conversion routines not "
					    "available for current locale.  "));
				(void) fprintf(stderr, gettext(
				    "file (%s): UTF-8 conversion failed.\n"),
				    filename);
				charset_type = -1;
				return (1);
			}
		}
	}

	errors = 0;

	errors += local_utf8(&Xtarhdr.x_gname, local_gname,
	    dblock.dbuf.gname, iconv_cd, _X_GNAME, _POSIX_NAME_MAX);
	errors += local_utf8(&Xtarhdr.x_uname, local_uname,
	    dblock.dbuf.uname, iconv_cd, _X_UNAME,  _POSIX_NAME_MAX);
	if ((xhdr_flgs & _X_LINKPATH) == 0) {	/* Need null-terminated str. */
		(void) strncpy(tempbuf, dblock.dbuf.linkname, NAMSIZ);
		tempbuf[NAMSIZ] = '\0';
	}
	errors += local_utf8(&Xtarhdr.x_linkpath, local_linkpath,
	    tempbuf, iconv_cd, _X_LINKPATH, PATH_MAX);
	if ((xhdr_flgs & _X_PATH) == 0) {	/* Concatenate prefix & name */
		(void) strncpy(tempbuf, dblock.dbuf.prefix, PRESIZ);
		tempbuf[PRESIZ] = '\0';
		nbytes = strlen(tempbuf);
		if (nbytes > 0) {
			tempbuf[nbytes++] = '/';
			tempbuf[nbytes] = '\0';
		}
		(void) strncat(tempbuf + nbytes, dblock.dbuf.name,
		    (MAXNAM - nbytes));
		tempbuf[MAXNAM] = '\0';
	}
	errors += local_utf8(&Xtarhdr.x_path, local_path,
	    tempbuf, iconv_cd, _X_PATH, PATH_MAX);

	if (errors > 0)
		(void) fprintf(stderr, gettext(
		    "tar: file (%s): UTF-8 conversion failed.\n"), filename);

	if (errors && errflag)
		done(1);
	else
		if (errors)
			Errflg = 1;
	return (errors);
}

static int
local_utf8(
		char	**Xhdr_ptrptr,
		char	*target,
		const	char	*source,
		iconv_t	iconv_cd,
		int	xhdrflg,
		int	max_val)
{
	const	char	*iconv_src;
	const	char	*starting_src;
	char		*iconv_trg;
	size_t		inlen;
	size_t		outlen;
#ifdef ICONV_DEBUG
	unsigned char	c_to_hex;
#endif

	/*
	 * If the item is already slated for extended format, get the string
	 * to convert from the extended header record.  Otherwise, get it from
	 * the regular (dblock) area.
	 */
	if (xhdr_flgs & xhdrflg) {
		if (charset_type == 3) {	/* Already UTF-8, just copy */
			(void) strcpy(target, *Xhdr_ptrptr);
			*Xhdr_ptrptr = target;
			return (0);
		} else
			iconv_src = (const char *) *Xhdr_ptrptr;
	} else {
		if (charset_type == 3)		/* Already in UTF-8 format */
			return (0);		/* Don't create xhdr record */
		iconv_src = source;
	}
	starting_src = iconv_src;
	iconv_trg = target;
	if ((inlen = strlen(iconv_src)) == 0)
		return (0);

	if (charset_type == 1) {	/* locale using 7-bit codeset */
		if (c_utf8(target, starting_src) != 0) {
			(void) fprintf(stderr,
			    gettext("tar: invalid character in"
			    " UTF-8 conversion of '%s'\n"), starting_src);
			return (1);
		}
		return (0);
	}

	outlen = max_val * UTF_8_FACTOR;
	errno = 0;
	if (iconv(iconv_cd, &iconv_src, &inlen, &iconv_trg, &outlen) ==
	    (size_t)-1) {
		/* An error occurred, or not all characters were converted */
		if (errno == EILSEQ)
			(void) fprintf(stderr,
			    gettext("tar: invalid character in"
			    " UTF-8 conversion of '%s'\n"), starting_src);
		else
			(void) fprintf(stderr, gettext(
			    "tar: conversion to UTF-8 aborted for '%s'.\n"),
			    starting_src);
		/* Get remaining output; reinitialize conversion descriptor */
		iconv_src = (const char *)NULL;
		inlen = 0;
		(void) iconv(iconv_cd, &iconv_src, &inlen, &iconv_trg, &outlen);
		return (1);
	}
	/* Get remaining output; reinitialize conversion descriptor */
	iconv_src = (const char *)NULL;
	inlen = 0;
	if (iconv(iconv_cd, &iconv_src, &inlen, &iconv_trg, &outlen) ==
	    (size_t)-1) {	/* Error occurred:  didn't convert */
		if (errno == EILSEQ)
			(void) fprintf(stderr,
			    gettext("tar: invalid character in"
			    " UTF-8 conversion of '%s'\n"), starting_src);
		else
			(void) fprintf(stderr, gettext(
			    "tar: conversion to UTF-8 aborted for '%s'.\n"),
			    starting_src);
		return (1);
	}

	*iconv_trg = '\0';	/* Null-terminate iconv output string */
	if (strcmp(starting_src, target) != 0) {
		*Xhdr_ptrptr = target;
		xhdr_flgs |= xhdrflg;
#ifdef ICONV_DEBUG
		(void) fprintf(stderr, "***  inlen: %d %d; outlen: %d %d\n",
		    strlen(starting_src), inlen, max_val, outlen);
		(void) fprintf(stderr, "Input string:\n  ");
		for (inlen = 0; inlen < strlen(starting_src); inlen++) {
			c_to_hex = (unsigned char)starting_src[inlen];
			(void) fprintf(stderr, " %2.2x", c_to_hex);
			if (inlen % 20 == 19)
				(void) fprintf(stderr, "\n  ");
		}
		(void) fprintf(stderr, "\nOutput string:\n  ");
		for (inlen = 0; inlen < strlen(target); inlen++) {
			c_to_hex = (unsigned char)target[inlen];
			(void) fprintf(stderr, " %2.2x", c_to_hex);
			if (inlen % 20 == 19)
				(void) fprintf(stderr, "\n  ");
		}
		(void) fprintf(stderr, "\n");
#endif
	}

	return (0);
}

/*
 *	Function to test each byte of the source string to make sure it is
 *	in within bounds (value between 0 and 127).
 *	If valid, copy source to target.
 */

int
c_utf8(char *target, const char *source)
{
	size_t		len;
	const char	*thischar;

	len = strlen(source);
	thischar = source;
	while (len-- > 0) {
		if (!isascii((int)(*thischar++)))
			return (1);
	}

	(void) strcpy(target, source);
	return (0);
}


#if defined(O_XATTR)
#define	ROUNDTOTBLOCK(a)	((a + (TBLOCK -1)) & ~(TBLOCK -1))

static void
prepare_xattr(
	char		**attrbuf,
	char		*filename,
	char		*attrpath,
	char		typeflag,
	struct linkbuf	*linkinfo,
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
	 * Release previous buffer
	 */

	if (*attrbuf != (char *)NULL) {
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
		linkstringlen = strlen(linkinfo->pathname) +
		    strlen(linkinfo->attrname) + 2;
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

	if ((bufhead = calloc(1, totalen)) == NULL) {
		fatal(gettext("Out of memory."));
	}


	/*
	 * Now we can fill in the necessary pieces
	 */

	/*
	 * first fill in the fixed header
	 */
	hptr = (struct xattr_hdr *)bufhead;
	(void) sprintf(hptr->h_version, "%s", XATTR_ARCH_VERS);
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

	if (linkinfo != (struct linkbuf *)NULL) {
		tptr = (struct xattr_buf *)(bufhead +
		    sizeof (struct xattr_hdr) + complen);

		(void) sprintf(tptr->h_namesz, "%0*d",
		    sizeof (tptr->h_namesz) - 1, linkstringlen);
		(void) strcpy(tptr->h_names, linkinfo->pathname);
		(void) strcpy(
		    &tptr->h_names[strlen(linkinfo->pathname) + 1],
		    linkinfo->attrname);
		tptr->h_typeflag = typeflag;
	}
	*attrbuf = (char *)bufhead;
	*rlen = len;
}

#else
static void
prepare_xattr(
	char		**attrbuf,
	char		*filename,
	char		*attrname,
	char		typeflag,
	struct linkbuf	*linkinfo,
	int		*rlen)
{
	*attrbuf = NULL;
	*rlen = 0;
}
#endif

int
getstat(int dirfd, char *longname, char *shortname, char *attrparent)
{

	int i, j;
	int	printerr;
	int	slnkerr;
	struct stat symlnbuf;

	if (!hflag)
		i = fstatat(dirfd, shortname, &stbuf, AT_SYMLINK_NOFOLLOW);
	else
		i = fstatat(dirfd, shortname, &stbuf, 0);

	if (i < 0) {
		/* Initialize flag to print error mesg. */
		printerr = 1;
		/*
		 * If stat is done, then need to do lstat
		 * to determine whether it's a sym link
		 */
		if (hflag) {
			/* Save returned error */
			slnkerr = errno;

			j = fstatat(dirfd, shortname,
			    &symlnbuf, AT_SYMLINK_NOFOLLOW);
			/*
			 * Suppress error message when file is a symbolic link
			 * and function modifier 'l' is off.  Exception:  when
			 * a symlink points to a symlink points to a
			 * symlink ... and we get past MAXSYMLINKS.  That
			 * error will cause a file not to be archived, and
			 * needs to be printed.
			 */
			if ((j == 0) && (!linkerrok) && (slnkerr != ELOOP) &&
			    (S_ISLNK(symlnbuf.st_mode)))
				printerr = 0;

			/*
			 * Restore errno in case the lstat
			 * on symbolic link change
			 */
			errno = slnkerr;
		}

		if (printerr) {
			(void) fprintf(stderr, gettext(
			    "tar: %s%s%s%s: %s\n"),
			    (attrparent == NULL) ? "" : gettext("attribute "),
			    (attrparent == NULL) ? "" : attrparent,
			    (attrparent == NULL) ? "" : gettext(" of "),
			    longname, strerror(errno));
			Errflg = 1;
		}
		return (1);
	}
	return (0);
}

/*
 * Recursively archive the extended attributes and/or extended system attributes
 * of the base file, longname.  Note:  extended system attribute files will be
 * archived only if the extended system attributes are not transient (i.e. the
 * extended system attributes are other than the default values).
 *
 * If -@ was specified and the underlying file system supports it, archive the
 * extended attributes, and if there is a system attribute associated with the
 * extended attribute, then recursively call xattrs_put() to archive the
 * hidden attribute directory and the extended system attribute.  If -/ was
 * specified and the underlying file system supports it, archive the extended
 * system attributes.  Read-only extended system attributes are never archived.
 *
 * Currently, there cannot be attributes on attributes; only system
 * attributes on attributes.  In addition, there cannot be attributes on
 * system attributes.  A file and it's attribute directory hierarchy looks as
 * follows:
 *	longname ---->	.	("." is the hidden attribute directory)
 *			|
 *	     ----------------------------
 *	     |				|
 *	<sys_attr_name>		   <attr_name> ---->	.
 *							|
 *						  <sys_attr_name>
 *
 */
#if defined(O_XATTR)
static void
xattrs_put(char *longname, char *shortname, char *parent, char *attrparent)
{
	char *filename = (attrparent == NULL) ? shortname : attrparent;
	int arc_rwsysattr = 0;
	int dirfd;
	int fd = -1;
	int rw_sysattr = 0;
	int ext_attr = 0;
	int rc;
	DIR *dirp;
	struct dirent *dp;
	attr_data_t *attrinfo = NULL;

	/*
	 * If the underlying file system supports it, then archive the extended
	 * attributes if -@ was specified, and the extended system attributes
	 * if -/ was specified.
	 */
	if (verify_attr_support(filename, (attrparent == NULL), ARC_CREATE,
	    &ext_attr) != ATTR_OK) {
		return;
	}

	/*
	 * Only want to archive a read-write extended system attribute file
	 * if it contains extended system attribute settings that are not the
	 * default values.
	 */
#if defined(_PC_SATTR_ENABLED)
	if (saflag) {
		int	filefd;
		nvlist_t *slist = NULL;

		/* Determine if there are non-transient system attributes */
		errno = 0;
		if ((filefd = open(filename, O_RDONLY)) == -1) {
			if (attrparent == NULL) {
				vperror(0, gettext(
				    "unable to open file %s"), longname);
			}
			return;
		}
		if (((slist = sysattr_list(basename(myname), filefd,
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
	    (saflag && !ext_attr))) {
		return;
	}
#endif	/* _PC_SATTR_ENABLED */

	/* open the parent attribute directory */
	fd = attropen(filename, ".", O_RDONLY);
	if (fd < 0) {
		vperror(0, gettext(
		    "unable to open attribute directory for %s%s%sfile %s"),
		    (attrparent == NULL) ? "" : gettext("attribute "),
		    (attrparent == NULL) ? "" : attrparent,
		    (attrparent == NULL) ? "" : gettext(" of "),
		    longname);
		return;
	}

	/*
	 * We need to change into the parent's attribute directory to determine
	 * if each of the attributes should be archived.
	 */
	if (fchdir(fd) < 0) {
		vperror(0, gettext(
		    "cannot change to attribute directory of %s%s%sfile %s"),
		    (attrparent == NULL) ? "" : gettext("attribute "),
		    (attrparent == NULL) ? "" : attrparent,
		    (attrparent == NULL) ? "" : gettext(" of "),
		    longname);
		(void) close(fd);
		return;
	}

	if (((dirfd = dup(fd)) == -1) ||
	    ((dirp = fdopendir(dirfd)) == NULL)) {
		(void) fprintf(stderr, gettext(
		    "tar: unable to open dir pointer for %s%s%sfile %s\n"),
		    (attrparent == NULL) ? "" : gettext("attribute "),
		    (attrparent == NULL) ? "" : attrparent,
		    (attrparent == NULL) ? "" : gettext(" of "),
		    longname);
		if (fd > 0) {
			(void) close(fd);
		}
		return;
	}

	while ((dp = readdir(dirp)) != NULL) {
		if (strcmp(dp->d_name, "..") == 0) {
			continue;
		} else if (strcmp(dp->d_name, ".") == 0) {
			Hiddendir = 1;
		} else {
			Hiddendir = 0;
		}

		/* Determine if this attribute should be archived */
		if (verify_attr(dp->d_name, attrparent, arc_rwsysattr,
		    &rw_sysattr) != ATTR_OK) {
			continue;
		}

		/* gather the attribute's information to pass to putfile() */
		if ((fill_in_attr_info(dp->d_name, longname, attrparent,
		    fd, rw_sysattr, &attrinfo)) == 1) {
			continue;
		}

		/* add the attribute to the archive */
		rc = putfile(longname, dp->d_name, parent, attrinfo,
		    XATTR_FILE, LEV0, SYMLINK_LEV0);

		if (exitflag) {
			break;
		}

#if defined(_PC_SATTR_ENABLED)
		/*
		 * If both -/ and -@ were specified, then archive the
		 * attribute's extended system attributes and hidden directory
		 * by making a recursive call to xattrs_put().
		 */
		if (!rw_sysattr && saflag && atflag && (rc != PUT_AS_LINK) &&
		    (Hiddendir == 0)) {

			xattrs_put(longname, shortname, parent, dp->d_name);

			/*
			 * Change back to the parent's attribute directory
			 * to process any further attributes.
			 */
			if (fchdir(fd) < 0) {
				vperror(0, gettext(
				    "cannot change back to attribute directory "
				    "of file %s"), longname);
				break;
			}
		}
#endif	/* _PC_SATTR_ENABLED */
	}

	if (attrinfo != NULL) {
		if (attrinfo->attr_parent != NULL) {
			free(attrinfo->attr_parent);
		}
		free(attrinfo->attr_path);
		free(attrinfo);
	}
	(void) closedir(dirp);
	if (fd != -1) {
		(void) close(fd);
	}

	/* Change back to the parent directory of the base file */
	if (attrparent == NULL) {
		(void) tar_chdir(parent);
	}
	Hiddendir = 0;
}
#else
static void
xattrs_put(char *longname, char *shortname, char *parent, char *attrppath)
{
}
#endif /* O_XATTR */

static int
put_link(char *name, char *longname, char *component, char *longattrname,
    char *prefix, int filetype, char type)
{

	if (stbuf.st_nlink > 1) {
		struct linkbuf *lp;
		int found = 0;

		for (lp = ihead; lp != NULL; lp = lp->nextp)
			if (lp->inum == stbuf.st_ino &&
			    lp->devnum == stbuf.st_dev) {
				found++;
				break;
			}
		if (found) {
#if defined(O_XATTR)
			if (filetype == XATTR_FILE)
				if (put_xattr_hdr(longname, component,
				    longattrname, prefix, type, filetype, lp)) {
					goto out;
			}
#endif
			stbuf.st_size = (off_t)0;
			if (filetype != XATTR_FILE) {
				tomodes(&stbuf);
				if (chk_path_build(name, longname, lp->pathname,
				    prefix, type, filetype) > 0) {
					goto out;
				}
			}

			if (mulvol && tapepos + 1 >= blocklim)
				newvol();
			(void) writetbuf((char *)&dblock, 1);
			/*
			 * write_ancillary() is not needed here.
			 * The first link is handled in the following
			 * else statement. No need to process ACLs
			 * for other hard links since they are the
			 * same file.
			 */

			if (vflag) {
				if (NotTape)
					dlog("seek = %" FMT_blkcnt_t
					    "K\n", K(tapepos));
				if (filetype == XATTR_FILE) {
					(void) fprintf(vfile, gettext(
					    "a %s attribute %s link to "
					    "%s attribute %s\n"),
					    name, component, name,
					    lp->attrname);
				} else {
					(void) fprintf(vfile, gettext(
					    "a %s link to %s\n"),
					    longname, lp->pathname);
				}
			}
			lp->count--;
			return (0);
		} else {
			lp = (struct linkbuf *)getmem(sizeof (*lp));
			if (lp != (struct linkbuf *)NULL) {
				lp->nextp = ihead;
				ihead = lp;
				lp->inum = stbuf.st_ino;
				lp->devnum = stbuf.st_dev;
				lp->count = stbuf.st_nlink - 1;
				if (filetype == XATTR_FILE) {
					(void) strcpy(lp->pathname, longname);
					(void) strcpy(lp->attrname,
					    component);
				} else {
					(void) strcpy(lp->pathname, longname);
					(void) strcpy(lp->attrname, "");
				}
			}
		}
	}

out:
	return (1);
}

static int
put_extra_attributes(char *longname, char *shortname, char *longattrname,
    char *prefix, int filetype, char typeflag)
{
	static acl_t *aclp = NULL;
	int error;

	if (aclp != NULL) {
		acl_free(aclp);
		aclp = NULL;
	}
#if defined(O_XATTR)
	if ((atflag || saflag) && (filetype == XATTR_FILE)) {
		if (put_xattr_hdr(longname, shortname, longattrname, prefix,
		    typeflag, filetype, NULL)) {
			return (1);
		}
	}
#endif

	/* ACL support */
	if (pflag) {
		char	*secinfo = NULL;
		int	len = 0;

		/* ACL support */
		if (((stbuf.st_mode & S_IFMT) != S_IFLNK)) {
			/*
			 * Get ACL info: dont bother allocating space if
			 * there is only a trivial ACL.
			 */
			if ((error = acl_get(shortname, ACL_NO_TRIVIAL,
			    &aclp)) != 0) {
				(void) fprintf(stderr, gettext(
				    "%s: failed to retrieve acl : %s\n"),
				    longname, acl_strerror(error));
				return (1);
			}
		}

		/* append security attributes if any */
		if (aclp != NULL) {
			(void) append_secattr(&secinfo, &len, acl_cnt(aclp),
			    acl_totext(aclp, ACL_APPEND_ID | ACL_COMPACT_FMT |
			    ACL_SID_FMT), (acl_type(aclp) == ACLENT_T) ?
			    UFSD_ACL : ACE_ACL);
		}

		if (Tflag) {
			/* append Trusted Extensions extended attributes */
			append_ext_attr(shortname, &secinfo, &len);
			(void) write_ancillary(&dblock, secinfo, len, ACL_HDR);

		} else if (aclp != NULL) {
			(void) write_ancillary(&dblock, secinfo, len, ACL_HDR);
		}
	}
	return (0);
}

#if defined(O_XATTR)
static int
put_xattr_hdr(char *longname, char *shortname, char *longattrname, char *prefix,
	int typeflag, int filetype, struct linkbuf *lp)
{
	char *lname = NULL;
	char *sname = NULL;
	int  error = 0;
	static char *attrbuf = NULL;
	int attrlen;

	lname = malloc(sizeof (char) * strlen("/dev/null") + 1 +
	    strlen(shortname) + strlen(".hdr") + 1);

	if (lname == NULL) {
		fatal(gettext("Out of Memory."));
	}
	sname = malloc(sizeof (char) * strlen(shortname) +
	    strlen(".hdr") + 1);
	if (sname == NULL) {
		fatal(gettext("Out of Memory."));
	}

	(void) sprintf(sname, "%s.hdr", shortname);
	(void) sprintf(lname, "/dev/null/%s", sname);

	if (strlcpy(dblock.dbuf.name, lname, sizeof (dblock.dbuf.name)) >=
	    sizeof (dblock.dbuf.name)) {
		fatal(gettext(
		    "Buffer overflow writing extended attribute file name"));
	}

	/*
	 * dump extended attr lookup info
	 */
	prepare_xattr(&attrbuf, longname, longattrname, typeflag, lp, &attrlen);
	write_ancillary(&dblock, attrbuf, attrlen, _XATTR_HDRTYPE);

	(void) sprintf(lname, "/dev/null/%s", shortname);
	(void) strncpy(dblock.dbuf.name, sname, NAMSIZ);

	/*
	 * Set up filename for attribute
	 */

	error = build_dblock(lname, tchar, '0', filetype,
	    &stbuf, stbuf.st_dev, prefix);
	free(lname);
	free(sname);

	return (error);
}
#endif

#if defined(O_XATTR)
static int
read_xattr_hdr(attr_data_t **attrinfo)
{
	char		buf[TBLOCK];
	char		*attrparent = NULL;
	blkcnt_t	blocks;
	char		*tp;
	off_t		bytes;
	int		comp_len, link_len;
	int		namelen;
	int		attrparentlen;
	int		parentfilelen;

	if (dblock.dbuf.typeflag != _XATTR_HDRTYPE)
		return (1);

	bytes = stbuf.st_size;
	if ((xattrhead = calloc(1, (int)bytes)) == NULL) {
		(void) fprintf(stderr, gettext(
		    "Insufficient memory for extended attribute\n"));
		return (1);
	}

	tp = (char *)xattrhead;
	blocks = TBLOCKS(bytes);
	while (blocks-- > 0) {
		readtape(buf);
		if (bytes <= TBLOCK) {
			(void) memcpy(tp, buf, (size_t)bytes);
			break;
		} else {
			(void) memcpy(tp, buf, TBLOCK);
			tp += TBLOCK;
		}
		bytes -= TBLOCK;
	}

	/*
	 * Validate that we can handle header format
	 */
	if (strcmp(xattrhead->h_version, XATTR_ARCH_VERS) != 0) {
		(void) fprintf(stderr,
		    gettext("Unknown extended attribute format encountered\n"));
		(void) fprintf(stderr,
		    gettext("Disabling extended attribute parsing\n"));
		xattrbadhead = 1;
		return (0);
	}
	(void) sscanf(xattrhead->h_component_len, "%10d", &comp_len);
	(void) sscanf(xattrhead->h_link_component_len,	"%10d", &link_len);
	xattrp = (struct xattr_buf *)(((char *)xattrhead) +
	    sizeof (struct xattr_hdr));
	(void) sscanf(xattrp->h_namesz, "%7d", &namelen);
	if (link_len > 0)
		xattr_linkp = (struct xattr_buf *)
		    ((int)xattrp + (int)comp_len);
	else
		xattr_linkp = NULL;

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
	if ((strlen(xattrapath) + parentfilelen + 2) < namelen) {
		/*
		 * The attrnames section contains a system attribute on an
		 * attribute.  Save the name of the attribute for use later,
		 * and replace the null separating the attribute name from
		 * the system attribute name with a '/' so that xattrapath can
		 * be used to display messages with the full attribute path name
		 * rooted at the hidden attribute directory of the base file
		 * in normal name space.
		 */
		attrparent = strdup(xattrapath);
		attrparentlen = strlen(attrparent);
		xattrapath[attrparentlen] = '/';
	}
	if ((fill_in_attr_info((attrparent == NULL) ? xattrapath :
	    xattrapath + attrparentlen + 1, xattrapath, attrparent,
	    -1, 0, attrinfo)) == 1) {
		free(attrparent);
		return (1);
	}

	/* Gather link info */
	if (xattr_linkp) {
		xattr_linkaname = xattr_linkp->h_names +
		    strlen(xattr_linkp->h_names) + 1;
	} else {
		xattr_linkaname = NULL;
	}

	return (0);
}
#else
static int
read_xattr_hdr(attr_data_t **attrinfo)
{
	return (0);
}
#endif

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
		fatal(gettext("pathname is too long"));
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

#if defined(O_XATTR)
static int
retry_open_attr(int pdirfd, int cwd, char *dirp, char *pattr, char *name,
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
	if ((dirfd = openat(cwd, (pattr == NULL) ? dirp : pattr,
	    O_RDONLY)) == -1) {
		return (-1);
	}
	if (fstat(dirfd, &parentstat) == -1) {
		(void) fprintf(stderr, gettext(
		    "tar: cannot stat %sfile %s: %s\n"),
		    (pdirfd == -1) ? "" : gettext("parent of "),
		    (pdirfd == -1) ? dirp : name, strerror(errno));
			return (-1);
	}
	if ((error = facl_get(dirfd, ACL_NO_TRIVIAL, &aclp)) != 0) {
		(void) fprintf(stderr, gettext(
		    "tar: failed to retrieve ACL on %sfile %s: %s\n"),
		    (pdirfd == -1) ? "" : gettext("parent of "),
		    (pdirfd == -1) ? dirp : name, strerror(errno));
			return (-1);
	}

	newmode = S_IWUSR | parentstat.st_mode;
	if (fchmod(dirfd, newmode) == -1) {
		(void) fprintf(stderr,
		    gettext(
		    "tar: cannot fchmod %sfile %s to %o: %s\n"),
		    (pdirfd == -1) ? "" : gettext("parent of "),
		    (pdirfd == -1) ? dirp : name, newmode, strerror(errno));
		if (aclp)
			acl_free(aclp);
		return (-1);
	}


	if (pdirfd == -1) {
		/*
		 * We weren't able to create the attribute directory before.
		 * Now try again.
		 */
		ofilefd = attropen(dirp, ".", oflag);
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
		(void) fprintf(stderr,
		    gettext("tar: cannot chmod %sfile %s to %o: %s\n"),
		    (pdirfd == -1) ? "" : gettext("parent of "),
		    (pdirfd == -1) ? dirp : name, newmode, strerror(errno));
	}

	if (aclp) {
		error = facl_set(dirfd, aclp);
		if (error) {
			(void) fprintf(stderr,
			    gettext("tar: failed to set acl entries on "
			    "%sfile %s\n"),
			    (pdirfd == -1) ? "" : gettext("parent of "),
			    (pdirfd == -1) ? dirp : name);
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

	(void) futimesat(cwd, (pattr == NULL) ? dirp : pattr, times);

	(void) close(dirfd);

	return (ofilefd);
}
#endif

#if !defined(O_XATTR)
static int
openat64(int fd, const char *name, int oflag, mode_t cmode)
{
	return (open64(name, oflag, cmode));
}

static int
openat(int fd, const char *name, int oflag, mode_t cmode)
{
	return (open(name, oflag, cmode));
}

static int
fchownat(int fd, const char *name, uid_t owner, gid_t group, int flag)
{
	if (flag == AT_SYMLINK_NOFOLLOW)
		return (lchown(name, owner, group));
	else
		return (chown(name, owner, group));
}

static int
renameat(int fromfd, char *old, int tofd, char *new)
{
	return (rename(old, new));
}

static int
futimesat(int fd, char *path, struct timeval times[2])
{
	return (utimes(path, times));
}

static int
unlinkat(int dirfd, char *path, int flag)
{
	if (flag == AT_REMOVEDIR)
		return (rmdir(path));
	else
		return (unlink(path));
}

static int
fstatat(int fd, char *path, struct stat *buf, int flag)
{
	if (flag == AT_SYMLINK_NOFOLLOW)
		return (lstat(path, buf));
	else
		return (stat(path, buf));
}

static int
attropen(char *file, char *attr, int omode, mode_t cmode)
{
	errno = ENOTSUP;
	return (-1);
}
#endif

static void
chop_endslashes(char *path)
{
	char *end, *ptr;

	/*
	 * Chop of slashes, but not if all we have is slashes
	 * for example: ////
	 * should make no changes, otherwise it will screw up
	 * checkdir
	 */
	end = &path[strlen(path) -1];
	if (*end == '/' && end != path) {
		ptr = skipslashes(end, path);
		if (ptr != NULL && ptr != path) {
			*ptr = '\0';
		}
	}
}
/* Trusted Extensions */

/*
 * append_ext_attr():
 *
 * Append extended attributes and other information into the buffer
 * that gets written to the ancillary file.
 *
 * With option 'T', we create a tarfile which
 * has an ancillary file each corresponding archived file.
 * Each ancillary file contains 1 or more of the
 * following attributes:
 *
 *	attribute type        attribute		process procedure
 *	----------------      ----------------  --------------------------
 *   	DIR_TYPE       = 'D'   directory flag	append if a directory
 *    	LBL_TYPE       = 'L'   SL[IL] or SL	append ascii label
 *
 *
 */
static void
append_ext_attr(char *shortname, char **secinfo, int *len)
{
	bslabel_t	b_slabel;	/* binary sensitvity label */
	char		*ascii = NULL;	/* ascii label */

	/*
	 * For each attribute type, append it if it is
	 * relevant to the file type.
	 */

	/*
	 * For attribute type DIR_TYPE,
	 * append it to the following file type:
	 *
	 *	S_IFDIR: directories
	 */

	/*
	 * For attribute type LBL_TYPE,
	 * append it to the following file type:
	 *
	 *	S_IFDIR: directories (including mld, sld)
	 *	S_IFLNK: symbolic link
	 *	S_IFREG: regular file but not hard link
	 *	S_IFIFO: FIFO file but not hard link
	 *	S_IFCHR: char special file but not hard link
	 *	S_IFBLK: block special file but not hard link
	 */
	switch (stbuf.st_mode & S_IFMT) {

	case S_IFDIR:

		/*
		 * append DIR_TYPE
		 */
		(void) append_secattr(secinfo, len, 1,
		    "\0", DIR_TYPE);

		/*
		 * Get and append attribute types LBL_TYPE.
		 * For directories, LBL_TYPE contains SL.
		 */
		/* get binary sensitivity label */
		if (getlabel(shortname, &b_slabel) != 0) {
			(void) fprintf(stderr,
			    gettext("tar: can't get sensitvity label for "
			    " %s, getlabel() error: %s\n"),
			    shortname, strerror(errno));
		} else {
			/* get ascii SL */
			if (bsltos(&b_slabel, &ascii,
			    0, 0) <= 0) {
				(void) fprintf(stderr,
				    gettext("tar: can't get ascii SL for"
				    " %s\n"), shortname);
			} else {
				/* append LBL_TYPE */
				(void) append_secattr(secinfo, len,
				    strlen(ascii) + 1, ascii,
				    LBL_TYPE);

				/* free storage */
				if (ascii != NULL) {
					free(ascii);
					ascii = (char *)0;
				}
			}

		}
		break;

	case S_IFLNK:
	case S_IFREG:
	case S_IFIFO:
	case S_IFCHR:
	case S_IFBLK:

		/* get binary sensitivity label */
		if (getlabel(shortname, &b_slabel) != 0) {
			(void) fprintf(stderr,
			    gettext("tar: can't get sensitivty label for %s, "
			    "getlabel() error: %s\n"),
			    shortname, strerror(errno));
		} else {
			/* get ascii IL[SL] */
			if (bsltos(&b_slabel, &ascii, 0, 0) <= 0) {
				(void) fprintf(stderr,
				    gettext("tar: can't translate sensitivity "
				    " label for %s\n"), shortname);
			} else {
				char *cmw_label;
				size_t  cmw_length;

				cmw_length = strlen("ADMIN_LOW [] ") +
				    strlen(ascii);
				if ((cmw_label = malloc(cmw_length)) == NULL) {
					(void) fprintf(stderr, gettext(
					    "Insufficient memory for label\n"));
					exit(1);
				}
				/* append LBL_TYPE */
				(void) snprintf(cmw_label, cmw_length,
				    "ADMIN_LOW [%s]", ascii);
				(void) append_secattr(secinfo, len,
				    strlen(cmw_label) + 1, cmw_label,
				    LBL_TYPE);

				/* free storage */
				if (ascii != NULL) {
					free(cmw_label);
					free(ascii);
					ascii = (char *)0;
				}
			}
		}
		break;

	default:
		break;
	} /* end switch for LBL_TYPE */


	/* DONE !! */
	return;

} /* end of append_ext_attr */


/*
 *	Name: extract_attr()
 *
 *	Description:
 *		Process attributes from the ancillary file due to
 *		the T option.
 *
 *	Call by doxtract() as part of the switch case structure.
 *	Making this a separate routine because the nesting are too
 *	deep in doxtract, thus, leaving very little space
 *	on each line for instructions.
 *
 * With option 'T', we extract from a TS 8 or TS 2.5 ancillary file
 *
 * For option 'T', following are possible attributes in
 * a TS 8 ancillary file: (NOTE: No IL support)
 *
 *	attribute type        attribute		process procedure
 *	----------------      ----------------  -------------------------
 *    #	LBL_TYPE       = 'L'   SL               construct binary label
 *    #	APRIV_TYPE     = 'P'   allowed priv    	construct privileges
 *    #	FPRIV_TYPE     = 'p'   forced priv	construct privileges
 *    #	COMP_TYPE      = 'C'   path component	construct real path
 *    #	DIR_TYPE       = 'D'   directory flag	note it is a directory
 *    $	UFSD_ACL       = '1'   ACL data		construct ACL entries
 *	ATTR_FLAG_TYPE = 'F'   file attr flags  construct binary flags
 *	LK_COMP_TYPE   = 'K'   linked path comp construct linked real path
 *
 * note: # = attribute names common between TS 8 & TS 2.5 ancillary
 *           files.
 *       $ = ACL attribute is processed for the option 'p', it doesn't
 *           need option 'T'.
 *
 * Trusted Extensions ignores APRIV_TYPE, FPRIV_TYPE, and ATTR_FLAG_TYPE
 *
 */
static void
extract_attr(char **file_ptr, struct sec_attr *attr)
{
	int	reterr, err;
	char	*dummy_buf;	/* for attribute extract */

	dummy_buf = attr->attr_info;

	switch (attr->attr_type) {

	case DIR_TYPE:

		dir_flag++;
		break;

	case LBL_TYPE:

		/*
		 * LBL_TYPE is used to indicate SL for directory, and
		 * CMW label for other file types.
		 */

		if (!dir_flag) { /* not directory */
			/* Skip over IL portion */
			char *sl_ptr = strchr(dummy_buf, '[');

			if (sl_ptr == NULL)
				err = 0;
			else
				err = stobsl(sl_ptr, &bs_label,
				    NEW_LABEL, &reterr);
		} else { /* directory */
			err = stobsl(dummy_buf, &bs_label,
			    NEW_LABEL, &reterr);
		}
		if (err == 0) {
			(void) fprintf(stderr, gettext("tar: "
			    "can't convert %s to binary label\n"),
			    dummy_buf);
			bslundef(&bs_label);
		} else if (!blequal(&bs_label, &admin_low) &&
		    !blequal(&bs_label, &admin_high)) {
			bslabel_t *from_label;
			char *buf;
			char tempbuf[MAXPATHLEN];

			if (*orig_namep != '/') {
				/* got relative linked to path */
				(void) getcwd(tempbuf, (sizeof (tempbuf)));
				(void) strncat(tempbuf, "/", MAXPATHLEN);
			} else
				*tempbuf = '\0';

			buf = real_path;
			(void) strncat(tempbuf, orig_namep, MAXPATHLEN);
			from_label = getlabelbypath(tempbuf);
			if (from_label != NULL) {
				if (blequal(from_label, &admin_low)) {
					if ((getpathbylabel(tempbuf, buf,
					    MAXPATHLEN, &bs_label) == NULL)) {
						(void) fprintf(stderr,
						    gettext("tar: "
						"can't get zone root path for "
						"%s\n"), tempbuf);
					} else
						rpath_flag = 1;
				}
				free(from_label);
			}
		}
		break;

	case COMP_TYPE:

		rebuild_comp_path(dummy_buf, file_ptr);
		break;

	case LK_COMP_TYPE:

		if (rebuild_lk_comp_path(dummy_buf, file_ptr)
		    == 0) {
			lk_rpath_flag = 1;
		} else {
			(void) fprintf(stderr, gettext("tar: warning: link's "
			    "target pathname might be invalid.\n"));
			lk_rpath_flag = 0;
		}
		break;
	case APRIV_TYPE:
		ignored_aprivs++;
		break;
	case FPRIV_TYPE:
		ignored_fprivs++;
		break;
	case ATTR_FLAG_TYPE:
		ignored_fattrs++;
		break;

	default:

		break;
	}

	/* done */
	return;

}	/* end extract_attr */



/*
 *	Name:	rebuild_comp_path()
 *
 *	Description:
 *		Take the string of components passed down by the calling
 *		routine and parse the values and rebuild the path.
 *		This routine no longer needs to produce a new real_path
 *		string because it is produced when the 'L' LABEL_TYPE is
 *		interpreted. So the only thing done here is to distinguish
 *		between an SLD and an MLD entry. We only want one, so we
 *		ignore the MLD entry by setting the mld_flag.
 *
 *	return value:
 *		none
 */
static void
rebuild_comp_path(char *str, char **namep)
{
	char		*cp;

	while (*str != '\0') {

		switch (*str) {

		case MLD_TYPE:

			str++;
			if ((cp = strstr(str, ";;")) != NULL) {
				*cp = '\0';
				str = cp + 2;
				*cp = ';';
			}
			mld_flag = 1;
			break;

		case SLD_TYPE:

			str++;
			if ((cp = strstr(str, ";;")) != NULL) {
				*cp = '\0';
				str = cp + 2;
				*cp = ';';
			}
			mld_flag = 0;
			break;

		case PATH_TYPE:

			str++;
			if ((cp = strstr(str, ";;")) != NULL) {
				*cp = '\0';
				str = cp + 2;
				*cp = ';';
			}
			break;
		}
	}
	if (rpath_flag)
		*namep = real_path;
	return;

} /* end rebuild_comp_path() */

/*
 *	Name:	rebuild_lk_comp_path()
 *
 *	Description:
 *		Take the string of components passed down by the calling
 *		routine and parse the values and rebuild the path.
 *
 *	return value:
 *		0 = succeeded
 *		-1 = failed
 */
static int
rebuild_lk_comp_path(char *str, char **namep)
{
	char		*cp;
	int		reterr;
	bslabel_t	bslabel;
	char		*buf;
	char		pbuf[MAXPATHLEN];
	char		*ptr1, *ptr2;
	int		plen;
	int		use_pbuf;
	char		tempbuf[MAXPATHLEN];
	int		mismatch;
	bslabel_t	*from_label;
	char		zonename[ZONENAME_MAX];
	zoneid_t	zoneid;

	/* init stuff */
	use_pbuf = 0;
	mismatch = 0;

	/*
	 * For linked to pathname (LK_COMP_TYPE):
	 *  - If the linked to pathname is absolute (start with /), we
	 *    will use it as is.
	 *  - If it is a relative pathname then it is relative to 1 of 2
	 *    directories.  For a hardlink, it is relative to the current
	 *    directory.  For a symbolic link, it is relative to the
	 *    directory the symbolic link is in.  For the symbolic link
	 *    case, set a flag to indicate we need to use the prefix of
	 *    the restored file's pathname with the linked to pathname.
	 *
	 *    NOTE: At this point, we have no way to determine if we have
	 *    a hardlink or a symbolic link.  We will compare the 1st
	 *    component in the prefix portion of the restore file's
	 *    pathname to the 1st component in the attribute data
	 *    (the linked pathname).  If they are the same, we will assume
	 *    the link pathname to reconstruct is relative to the current
	 *    directory.  Otherwise, we will set a flag indicate we need
	 *    to use a prefix with the reconstructed name.  Need to compare
	 *    both the adorned and unadorned version before deciding a
	 *    mismatch.
	 */

	buf = lk_real_path;
	if (*(str + 1) != '/') { /* got relative linked to path */
		ptr1 = orig_namep;
		ptr2 = strrchr(ptr1, '/');
		plen = ptr2 - ptr1;
		if (plen > 0) {
			pbuf[0] = '\0';
			plen++;		/* include '/' */
			(void) strncpy(pbuf, ptr1, plen);
			*(pbuf + plen) = '\0';
			ptr2 = strchr(pbuf, '/');
			if (strncmp(pbuf, str + 1, ptr2 - pbuf) != 0)
				mismatch = 1;
		}

		if (mismatch == 1)
			use_pbuf = 1;
	}

	buf[0] = '\0';

	while (*str != '\0') {

		switch (*str) {

		case MLD_TYPE:

			str++;
			if ((cp = strstr(str, ";;")) != NULL) {
				*cp = '\0';

				/*
				 * Ignore attempts to backup over .MLD.
				 */
				if (strcmp(str, "../") != 0)
					(void) strncat(buf, str, MAXPATHLEN);
				str = cp + 2;
				*cp = ';';
			}
			break;

		case SLD_TYPE:

			str++;
			if ((cp = strstr(str, ";;")) != NULL) {
				*cp = '\0';

				/*
				 * Use the path name in the header if
				 * error occurs when processing the
				 * SLD type.
				 */

				if (!stobsl(str, &bslabel,
				    NO_CORRECTION, &reterr)) {
					(void) fprintf(stderr, gettext(
					    "tar: can't translate to binary"
					    "SL for SLD, stobsl() error:"
					    " %s\n"), strerror(errno));
					return (-1);
				}

				str = cp + 2;
				*cp = ';';

				if (use_pbuf == 1) {
					if (*pbuf != '/') {
						/* relative linked to path */

						(void) getcwd(tempbuf,
						    (sizeof (tempbuf)));
						(void) strncat(tempbuf, "/",
						    MAXPATHLEN);
						(void) strncat(tempbuf, pbuf,
						    MAXPATHLEN);
					}
					else
						(void) strcpy(tempbuf, pbuf);

				} else if (*buf != '/') {
					/* got relative linked to path */

					(void) getcwd(tempbuf,
					    (sizeof (tempbuf)));
					(void) strncat(tempbuf, "/",
					    MAXPATHLEN);
				} else
					*tempbuf = '\0';

				(void) strncat(tempbuf, buf, MAXPATHLEN);
				*buf = '\0';

				if (blequal(&bslabel, &admin_high)) {
					bslabel = admin_low;
				}


				/*
				 * Check for cross-zone symbolic links
				 */
				from_label = getlabelbypath(real_path);
				if (rpath_flag && (from_label != NULL) &&
				    !blequal(&bslabel, from_label)) {
					if ((zoneid =
					    getzoneidbylabel(&bslabel)) == -1) {
						(void) fprintf(stderr,
						    gettext("tar: can't get "
						    "zone ID for %s\n"),
						    tempbuf);
						return (-1);
					}
					if (zone_getattr(zoneid, ZONE_ATTR_NAME,
					    &zonename, ZONENAME_MAX) == -1) {
						/* Badly configured zone info */
						(void) fprintf(stderr,
						    gettext("tar: can't get "
						    "zonename for %s\n"),
						    tempbuf);
						return (-1);
					}
					(void) strncpy(buf, AUTO_ZONE,
					    MAXPATHLEN);
					(void) strncat(buf, "/",
					    MAXPATHLEN);
					(void) strncat(buf, zonename,
					    MAXPATHLEN);
				}
				if (from_label != NULL)
					free(from_label);
				(void) strncat(buf, tempbuf, MAXPATHLEN);
				break;
			}
			mld_flag = 0;
			break;

		case PATH_TYPE:

			str++;
			if ((cp = strstr(str, ";;")) != NULL) {
				*cp = '\0';
				(void) strncat(buf, str, MAXPATHLEN);
				str = cp + 2;
				*cp = ';';
			}
			break;

		default:

			(void) fprintf(stderr, gettext(
			    "tar: error rebuilding path %s\n"),
			    *namep);
			*buf = '\0';
			str++;
			return (-1);
		}
	}

	/*
	 * Done for LK_COMP_TYPE
	 */

	return (0);    /* component path is rebuilt successfully */

} /* end rebuild_lk_comp_path() */

/*
 *	Name: check_ext_attr()
 *
 *	Description:
 *		Check the extended attributes for a file being extracted.
 *		The attributes being checked here are CMW labels.
 *		ACLs are not set here because they are set by the
 *		pflag in doxtract().
 *
 *		If the label doesn't match, return 0
 *		else return 1
 */
static int
check_ext_attr(char *filename)
{
	bslabel_t	currentlabel;	/* label from zone */

	if (bltype(&bs_label, SUN_SL_UN)) {
		/* No label check possible */
		return (0);
	}
	if (getlabel(filename, &currentlabel) != 0) {
		(void) fprintf(stderr,
		    gettext("tar: can't get label for "
		    " %s, getlabel() error: %s\n"),
		    filename, strerror(errno));
		return (0);
	} else if ((blequal(&currentlabel, &bs_label)) == 0) {
		char	*src_label = NULL;	/* ascii label */

		/* get current src SL */
		if (bsltos(&bs_label, &src_label, 0, 0) <= 0) {
			(void) fprintf(stderr,
			    gettext("tar: can't interpret requested label for"
			    " %s\n"), filename);
		} else {
			(void) fprintf(stderr,
			    gettext("tar: can't apply label %s to %s\n"),
			    src_label, filename);
			free(src_label);
		}
		(void) fprintf(stderr,
		    gettext("tar: %s not restored\n"), filename);
		return (0);
	}
	return (1);

}	/* end check_ext_attr */

/* Compressing a tar file using compression method provided in 'opt' */

static void
compress_back()
{
	pid_t	pid;

	if (vflag) {
		(void) fprintf(vfile,
		    gettext("Compressing '%s' with '%s'...\n"),
		    usefile, compress_opt);
	}
	if ((pid = fork()) == 0) {
		verify_compress_opt(compress_opt);
		(void) execlp(compress_opt, compress_opt,
		    usefile, NULL);
	} else if (pid == -1) {
		vperror(1, "%s", gettext("Could not fork"));
	}
	wait_pid(pid);
	if (suffix == 0) {
		(void) rename(tfname, usefile);
	}
}

/* The magic numbers from /etc/magic */

#define	GZIP_MAGIC	"\037\213"
#define	BZIP_MAGIC	"BZh"
#define	COMP_MAGIC	"\037\235"
#define	XZ_MAGIC	"\375\067\172\130\132\000"

void
check_compression(void)
{
	char 	magic[16];
	FILE	*fp;

	if ((fp = fopen(usefile, "r")) != NULL) {
		(void) fread(magic, sizeof (char), 6, fp);
		(void) fclose(fp);
	}

	if (memcmp(magic, GZIP_MAGIC, 2) == 0) {
		if (xflag || tflag) {
			compress_opt = compress_malloc(strlen(GZCAT) + 1);
			(void) strcpy(compress_opt, GZCAT);
		} else if (uflag || rflag) {
			compress_opt = compress_malloc(strlen(GZIP) + 1);
			(void) strcpy(compress_opt, GZIP);
		}
	} else if (memcmp(magic, BZIP_MAGIC, 2) == 0) {
		if (xflag || tflag) {
			compress_opt = compress_malloc(strlen(BZCAT) + 1);
			(void) strcpy(compress_opt, BZCAT);
		} else if (uflag || rflag) {
			compress_opt = compress_malloc(strlen(BZIP) + 1);
			(void) strcpy(compress_opt, BZIP);
		}
	} else if (memcmp(magic, COMP_MAGIC, 2) == 0) {
		if (xflag || tflag) {
			compress_opt = compress_malloc(strlen(ZCAT) + 1);
			(void) strcpy(compress_opt, ZCAT);
		} else if (uflag || rflag) {
			compress_opt = compress_malloc(strlen(COMPRESS) + 1);
			(void) strcpy(compress_opt, COMPRESS);
		}
	} else if (memcmp(magic, XZ_MAGIC, 6) == 0) {
		if (xflag || tflag) {
			compress_opt = compress_malloc(strlen(XZCAT) + 1);
			(void) strcpy(compress_opt, XZCAT);
		} else if (uflag || rflag) {
			compress_opt = compress_malloc(strlen(XZ) + 1);
			(void) strcpy(compress_opt, XZ);
		}
	}
}

char *
add_suffix()
{
	(void) strcpy(tfname, usefile);
	if (strcmp(compress_opt, GZIP) == 0) {
		if ((suffix = gz_suffix()) == NULL) {
			strlcat(tfname, gsuffix[0], sizeof (tfname));
			return (gsuffix[0]);
		}
	} else if (strcmp(compress_opt, COMPRESS) == 0) {
		if ((suffix = gz_suffix()) == NULL) {
			strlcat(tfname, gsuffix[6], sizeof (tfname));
			return (gsuffix[6]);
		}
	} else if (strcmp(compress_opt, BZIP) == 0) {
		if ((suffix = bz_suffix()) == NULL) {
			strlcat(tfname, bsuffix[0], sizeof (tfname));
			return (bsuffix[0]);
		}
	} else if (strcmp(compress_opt, XZ) == 0) {
		if ((suffix = xz_suffix()) == NULL) {
			strlcat(tfname, xsuffix[0], sizeof (tfname));
			return (xsuffix[0]);
		}
	}
	return (NULL);
}

/* Decompressing a tar file using compression method from the file type */
void
decompress_file(void)
{
	pid_t 	pid;
	char	*added_suffix;


	added_suffix = add_suffix();
	if (added_suffix != NULL)  {
		(void) rename(usefile, tfname);
	}
	if ((pid = fork()) == 0) {
		if (vflag) {
			(void) fprintf(vfile,
			    gettext("Decompressing '%s' with "
			    "'%s'...\n"), usefile, compress_opt);
		}
		verify_compress_opt(compress_opt);
		(void) execlp(compress_opt, compress_opt, "-df",
		    tfname, NULL);
		vperror(1, gettext("Could not exec %s"), compress_opt);
	} else if (pid == -1) {
		vperror(1, gettext("Could not fork"));
	}
	wait_pid(pid);
	if (suffix != NULL) {
		/* restore the file name - original file was without suffix */
		*(usefile + strlen(usefile) - strlen(suffix)) = '\0';
	}
}

/* Set the archive for writing and then compress the archive */
pid_t
compress_file(void)
{
	int fd[2];
	pid_t pid;

	if (vflag) {
		(void) fprintf(vfile, gettext("Compressing '%s' with "
		    "'%s'...\n"), usefile, compress_opt);
	}

	if (pipe(fd) < 0) {
		vperror(1, gettext("Could not create pipe"));
	}
	if ((pid = fork()) > 0) {
		mt = fd[1];
		(void) close(fd[0]);
		return (pid);
	}
	/* child */
	(void) dup2(fd[0], STDIN_FILENO);
	(void) close(fd[1]);
	(void) dup2(mt, STDOUT_FILENO);
	verify_compress_opt(compress_opt);
	(void) execlp(compress_opt, compress_opt, NULL);
	vperror(1, gettext("Could not exec %s"), compress_opt);
	return (0);	/*NOTREACHED*/
}

pid_t
uncompress_file(void)
{
	int fd[2];
	pid_t pid;

	if (vflag) {
		(void) fprintf(vfile, gettext("Decompressing '%s' with "
		    "'%s'...\n"), usefile, compress_opt);
	}

	if (pipe(fd) < 0) {
		vperror(1, gettext("Could not create pipe"));
	}
	if ((pid = fork()) > 0) {
		mt = fd[0];
		(void) close(fd[1]);
		return (pid);
	}
	/* child */
	(void) dup2(fd[1], STDOUT_FILENO);
	(void) close(fd[0]);
	(void) dup2(mt, STDIN_FILENO);
	verify_compress_opt(compress_opt);
	(void) execlp(compress_opt, compress_opt, NULL);
	vperror(1, gettext("Could not exec %s"), compress_opt);
	return (0);	/*NOTREACHED*/
}

/* Checking suffix validity */
char *
check_suffix(char **suf, int size)
{
	int 	i;
	int	slen;
	int	nlen = strlen(usefile);

	for (i = 0; i < size; i++) {
		slen = strlen(suf[i]);
		if (nlen < slen)
			return (NULL);
		if (strcmp(usefile + nlen - slen, suf[i]) == 0)
			return (suf[i]);
	}
	return (NULL);
}

/* Checking valid 'bzip2' suffix */
char *
bz_suffix(void)
{
	return (check_suffix(bsuffix, BSUF));
}

/* Checking valid 'gzip' suffix */
char *
gz_suffix(void)
{
	return (check_suffix(gsuffix, GSUF));
}

/* Checking valid 'xz' suffix */
char *
xz_suffix(void)
{
	return (check_suffix(xsuffix, XSUF));
}

void *
compress_malloc(size_t size)
{
	void *opt;

	if ((opt = malloc(size)) == NULL) {
		vperror(1, "%s",
		    gettext("Could not allocate compress buffer\n"));
	}
	return (opt);
}

void
wait_pid(pid_t pid)
{
	int status;

	while (waitpid(pid, &status, 0) == -1 && errno == EINTR)
		;
}

static void
verify_compress_opt(const char *t)
{
	struct stat statbuf;

	if (stat(t, &statbuf) == -1)
		vperror(1, "%s %s: %s\n", gettext("Could not stat"),
		    t, strerror(errno));
}

static void
detect_compress(void)
{
	char *zsuf[] = {".Z"};
	if (check_suffix(zsuf, 1) != NULL) {
		Zflag = 1;
	} else if (check_suffix(bsuffix, BSUF) != NULL) {
		jflag = 1;
	} else if (check_suffix(gsuffix, GSUF) != NULL) {
		zflag = 1;
	} else if (check_suffix(xsuffix, XSUF) != NULL) {
		Jflag = 1;
	} else {
		vperror(1, "%s\n", gettext("No compression method detected"));
	}
}
