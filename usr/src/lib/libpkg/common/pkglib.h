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
 * Copyright (c) 2017 Peter Tribble.
 */

/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/* Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T */
/* All Rights Reserved */

#ifndef	_PKGLIB_H
#define	_PKGLIB_H


#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <limits.h>
#include <stdio.h>
#include <pkgdev.h>
#include <pkgstrct.h>
#include "cfext.h"

/*
 * The contents database file interface.
 */

typedef struct pkg_server *PKGserver;

/* Some commands modify the internal database: add them here */
#define	PKG_WRITE_COMMAND(cmd)	((cmd) == PKG_ADDLINES)

#define	PKG_EXIT		0x0
#define	PKG_FINDFILE		0x1
#define	PKG_DUMP		0x2
#define	PKG_PKGSYNC		0x3
#define	PKG_FILTER		0x4
#define	PKG_ADDLINES		0x5
#define	PKG_NOP			0x6

#define	SUNW_PKG_SERVERMODE	"SUNW_PKG_SERVERMODE"

#define	PKGSERV_MODE		"pkg-server-mode="
#define	PKGSERV_MODE_LEN	(sizeof (PKGSERV_MODE) - 1)

#define	MODE_PERMANENT		"permanent"
#define	MODE_RUN_ONCE		"run_once"
#define	MODE_TIMEOUT		"timeout"

#define	MAXLOGFILESIZE		(20 * 1024 * 1024)

#define	PKGLOG			"pkglog"
#define	PKGDOOR			".door"

typedef enum {
	INVALID,		/* Not initialized */
	NEVER,			/* Don't start, does check if it is running. */
	FLUSH_LOG,		/* Run it once to incorporate the log. */
	RUN_ONCE,		/* Run until the current client stops. */
	TIMEOUT,		/* Run until a timeout occurs. */
	PERMANENT,		/* Run until it is externally terminated. */
	DEFAULTMODE = TIMEOUT	/* The default mode, must come last */
} start_mode_t;

typedef struct pkgcmd {
	int cmd;
	char buf[1];
} pkgcmd_t;

typedef struct pkgfilter {
	int cmd;
	int len;
	char buf[1];
} pkgfilter_t;

/*
 * Virtual File Protocol definitions
 */

/*
 * flags associated with virtual file protocol operations; note that these flags
 * may only occupy the low order 16 bits of the 32-bit unsigned flag.
 */

typedef unsigned long VFPFLAGS_T;

#define	VFP_NONE	0x00000000	/* no special flags */
#define	VFP_NEEDNOW	0x00000001	/* need memory now */
#define	VFP_SEQUENTIAL	0x00000002	/* sequential access */
#define	VFP_RANDOM	0x00000004	/* random access */
#define	VFP_NOMMAP	0x00000008	/* do not use mmap to access file */
#define	VFP_NOMALLOC	0x00000010	/* do not use malloc to buffer file */

/* virtual file protocol object */

typedef struct _vfp VFP_T;

/* structure behind the virtual file protocol object */

struct _vfp {
	FILE		*_vfpFile;	/* -> opened FILE */
	char		*_vfpCurr;	/* -> current byte to read/write */
	char		*_vfpHighWater;	/* -> last byte modified */
	char		*_vfpEnd;	/* -> last data byte */
	char		*_vfpPath;	/* -> path associated with FILE */
	char		*_vfpStart;	/* -> first data byte */
	void		*_vfpExtra;	/* undefined */
	size_t		_vfpSize;	/* size of mapped/allocated area */
	size_t		_vfpMapSize;	/* # mapped bytes */
	VFPFLAGS_T	_vfpFlags;	/* flags associated with vfp/data */
	int		_vfpOverflow;	/* non-zero if buffer write overflow */
	blkcnt_t	_vfpCkStBlocks;	/* checkpoint # blocks */
	dev_t		_vfpCkDev;	/* checkpoint device i.d. */
	ino_t		_vfpCkIno;	/* checkpoint inode # */
	off_t		_vfpCkSize;	/* checkpoint size */
	time_t		_vfpCkMtime;	/* checkpoint modification time */
};

/*
 * get highest modified byte (length) contained in vfp
 *
 * determine number of bytes to write - it will be the highest of:
 *  -- the current pointer into the file - this is updated whenever
 *	the location of the file is changed by a single byte
 *  -- the last "high water mark" - the last known location that
 *	was written to the file - updated only when the location
 *	of the file is directly changed - e.g. vfpSetCurrCharPtr,
 *	vfpTruncate, vfpRewind.
 * this reduces the "bookkeeping" that needs to be done to know
 * how many bytes to write out to the file - typically a file is
 * written sequentially so the current file pointer is sufficient
 * to determine how many bytes to write out.
 */

#define	vfpGetModifiedLen(VFP)						\
	(size_t)(((VFP)->_vfpHighWater > (VFP)->_vfpCurr) ?		\
		(((ptrdiff_t)(VFP)->_vfpHighWater -			\
				(ptrdiff_t)(VFP)->_vfpStart)) :		\
		(((ptrdiff_t)(VFP)->_vfpCurr -				\
				(ptrdiff_t)(VFP)->_vfpStart)))

/*
 * increment current pointer by specified delta
 * if the delta exceeds the buffer size, set pointer to buffer end
 */
#define	vfpIncCurrPtrBy(VFP, INC)					\
	{								\
		((VFP)->_vfpCurr) += (INC);				\
		if (((VFP)->_vfpCurr) > ((VFP)->_vfpEnd)) {		\
			(VFP)->_vfpCurr = (VFP)->_vfpEnd;		\
			(VFP)->_vfpOverflow = 1;			\
		}							\
		if ((VFP)->_vfpHighWater < (VFP)->_vfpCurr) {		\
			(VFP)->_vfpHighWater = (VFP)->_vfpCurr;		\
		}							\
	}

/* get the path associated with the vfp */
#define	vfpGetPath(VFP)		((VFP)->_vfpPath)

/* get a string from the vfp into a fixed size buffer */
#define	vfpGets(VFP, PTR, LEN)						\
	{								\
		char	*XXpXX = (PTR);					\
		size_t	XXlXX = (LEN);					\
		while ((*(VFP)->_vfpCurr != '\0') &&			\
				(*(VFP)->_vfpCurr != '\n')) {		\
			if (XXlXX > 1) {				\
				*XXpXX++ = *(VFP)->_vfpCurr;		\
				XXlXX--;				\
			}						\
			(VFP)->_vfpCurr++;				\
		}							\
		*XXpXX++ = '\0';					\
		if (*(VFP)->_vfpCurr != '\0') {				\
			(VFP)->_vfpCurr++;				\
		}							\
	}

/* get number of bytes remaining to read */
#define	vfpGetBytesRemaining(VFP)	\
	(((((VFP)->_vfpHighWater) <= ((VFP)->_vfpCurr))) ? 0 : 		\
	((((ptrdiff_t)(VFP)->_vfpHighWater)-((ptrdiff_t)(VFP)->_vfpCurr))))

/* get number of bytes remaining to write */
#define	vfpGetBytesAvailable(VFP)	\
	(((((VFP)->_vfpEnd) <= ((VFP)->_vfpCurr))) ? 0 : 		\
	((((ptrdiff_t)(VFP)->_vfpEnd)-((ptrdiff_t)(VFP)->_vfpCurr))))

/* put current character and increment to next */
#define	vfpPutc(VFP, C)							\
	{								\
		(*(VFP)->_vfpCurr) = ((char)(C));			\
		vfpIncCurrPtrBy((VFP), 1);				\
	}

/* put integer to current character and increment */
#define	vfpPutInteger(VFP, NUMBER)	vfpPutFormat((VFP), "%d", (NUMBER))

/* put long to current character and increment */
#define	vfpPutLong(VFP, NUMBER)	vfpPutFormat((VFP), "%ld", (NUMBER))

/* get current character and increment to next */
#define	vfpGetc(VFP)		(*(VFP)->_vfpCurr++)

/* get current character - do not increment */
#define	vfpGetcNoInc(VFP)	(*(VFP)->_vfpCurr)

/* get pointer to current character */
#define	vfpGetCurrCharPtr(VFP)	((VFP)->_vfpCurr)

/* increment current character pointer */
#define	vfpIncCurrPtr(VFP)	vfpIncCurrPtrBy((VFP), 1)

/* decrement current character pointer */
#define	vfpDecCurrPtr(VFP)	((VFP)->_vfpCurr--)

/* get pointer to first data byte in buffer */
#define	vfpGetFirstCharPtr(VFP)	((VFP)->_vfpStart)

/* get pointer to last data byte in buffer */
#define	vfpGetLastCharPtr(VFP)	((VFP)->_vfpHighWater)

/* set pointer to current character */
#define	vfpSetCurrCharPtr(VFP, PTR)					\
	if ((VFP)->_vfpCurr > (VFP)->_vfpHighWater) {			\
		(VFP)->_vfpHighWater = (VFP)->_vfpCurr;			\
	}								\
	((VFP)->_vfpCurr = (PTR))

/* set pointer to last data byte in buffer */
#define	vfpSetLastCharPtr(VFP, PTR)					\
	if ((PTR) >= (VFP)->_vfpStart) {				\
		(VFP)->_vfpHighWater = (PTR);				\
		if ((VFP)->_vfpCurr > (VFP)->_vfpHighWater) {		\
			(VFP)->_vfpCurr = (VFP)->_vfpHighWater;		\
		}							\
	}

/* seek to end of file - one past last data byte in file */
#define	vfpSeekToEnd(VFP)	((VFP)->_vfpCurr = ((VFP)->_vfpHighWater)+1)

/* get number of bytes between current char and specified char */
#define	vfpGetCurrPtrDelta(VFP, P)	\
	(((ptrdiff_t)(P))-((ptrdiff_t)(VFP)->_vfpCurr))

/* put string to current character and increment */
#define	vfpPuts(VFP, S)							\
	{								\
		size_t	xxLen;						\
		size_t	xxResult;					\
		xxLen = vfpGetBytesAvailable((VFP));			\
		xxResult = strlcpy(((VFP)->_vfpCurr), (S), xxLen);	\
		vfpIncCurrPtrBy((VFP), xxResult);			\
	}

/* put fixed number of bytes to current character and increment */
#define	vfpPutBytes(VFP, PTR, LEN)					\
	{								\
		size_t	xxLen;						\
		xxLen = vfpGetBytesAvailable((VFP));			\
		if (xxLen > (LEN)) {					\
			xxLen = (LEN);					\
		} else {						\
			(VFP)->_vfpOverflow = 1;			\
		}							\
		memcpy((VFP)->_vfpCurr, (PTR), (xxLen));		\
		vfpIncCurrPtrBy((VFP), (xxLen));			\
	}

/* put format one arg to current character and increment */
#define	vfpPutFormat(VFP, FORMAT, ARG)					\
	{								\
	char	xxTeMpXX[256];						\
	(void) snprintf(xxTeMpXX, sizeof (xxTeMpXX), (FORMAT), (ARG));	\
	vfpPuts((VFP), xxTeMpXX);					\
	}

struct dm_buf {
	char *text_buffer;	/* start of allocated buffer */
	int offset;		/* number of bytes into the text_buffer */
	int allocation;		/* size of buffer in bytes */
};

/* This structure is used to hold a dynamically growing string */

struct dstr {
	char *pc;
	int   len;
	int   max;
};

/* setmapmode() defines */
#define	MAPALL		0	/* resolve all variables */
#define	MAPBUILD	1	/* map only build variables */
#define	MAPINSTALL	2	/* map only install variables */
#define	MAPNONE		3	/* map no variables */

#define	NON_ABI_NAMELNGTH	33	/* 32 chars for name + 1 for NULL */

#define	BLK_SIZE	512	/* size of logical block */

/* max length for printed attributes */
#define	ATTR_MAX	80

/*
 * These three defines indicate that the prototype file contains a '?'
 * meaning do not specify this data in the pkgmap entry.
 */
#define	CURMODE		BADMODE		/* current mode has been specified */
#define	CUROWNER	BADOWNER	/* ... same for owner ... */
#define	CURGROUP	BADGROUP	/* ... and group. */

#define	WILDCARD		BADMODE >> 1
#define	DB_UNDEFINED_ENTRY	"?"

#define	DEFAULT_MODE		0755
#define	DEFAULT_MODE_FILE	0644
#define	DEFAULT_OWNER	"root"
#define	DEFAULT_GROUP	"other"

#define	INST_RELEASE "var/sadm/system/admin/INST_RELEASE"

#define	RANDOM			"/dev/urandom"
#define	BLOCK			256

#define	TERM_WIDTH		60
#define	SMALL_DIVISOR		4
#define	MED_DIVISOR		5
#define	LARGE_DIVISOR		10

#define	PKGADD			"pkgadd"

/* package header magic tokens */
#define	HDR_PREFIX	"# PaCkAgE DaTaStReAm"
#define	HDR_SUFFIX	"# end of header"

#define	GROUP	"/etc/group"
#define	PASSWD	"/etc/passwd"

/*
 * The next three mean that no mode, owner or group was specified or that the
 * one specified is invalid for some reason. Sometimes this is an error in
 * which case it is generally converted to CUR* with a warning. Other times
 * it means "look it up" by stating the existing file system object pointred
 * to in the prototype file.
 */
#define	NOMODE		(BADMODE-1)
#define	NOOWNER		"@"
#define	NOGROUP		"@"

/* string comparitor abbreviators */

#define	ci_streq(a, b)		(strcasecmp((a), (b)) == 0)
#define	ci_strneq(a, b, c)	(strncasecmp((a), (b), (c)) == 0)
#define	streq(a, b)		(strcmp((a), (b)) == 0)
#define	strneq(a, b, c)		(strncmp((a), (b), (c)) == 0)

extern FILE	*epopen(char *cmd, char *mode);
extern char	**gpkglist(char *dir, char **pkg, char **catg);
extern int	is_not_valid_length(char **category);
extern int	is_not_valid_category(char **category, char *progname);
extern int	is_same_CATEGORY(char **category, char *installed_category);
extern char **get_categories(char *catg_arg);

extern void	pkglist_cont(char *keyword);
extern char	**pkgalias(char *pkg);
extern char	*get_prog_name(void);
extern char 	*set_prog_name(char *name);
extern int	averify(int fix, char *ftype, char *path, struct ainfo *ainfo);
extern int	ckparam(char *param, char *value);
extern int	ckvolseq(char *dir, int part, int nparts);
extern int	cverify(int fix, char *ftype, char *path, struct cinfo *cinfo,
			int allow_checksum);
extern unsigned long	compute_checksum(int *r_cksumerr, char *a_path);
extern int	fverify(int fix, char *ftype, char *path, struct ainfo *ainfo,
		    struct cinfo *cinfo);
extern char	*getErrbufAddr(void);
extern int	getErrbufSize(void);
extern char	*getErrstr(void);
extern void	setErrstr(char *errstr);
extern int	devtype(char *alias, struct pkgdev *devp);
extern int	ds_totread;	/* total number of parts read */
extern int	ds_close(int pkgendflg);
extern int	ds_findpkg(char *device, char *pkg);
extern int	ds_getinfo(char *string);
extern int	ds_getpkg(char *device, int n, char *dstdir);
extern int	ds_ginit(char *device);
extern boolean_t	ds_fd_open(void);
extern int	ds_init(char *device, char **pkg, char *norewind);
extern int	ds_next(char *, char *);
extern int	ds_readbuf(char *device);
extern int	epclose(FILE *pp);
extern int	esystem(char *cmd, int ifd, int ofd);
extern int	e_ExecCmdArray(int *r_status, char **r_results,
			char *a_inputFile, char *a_cmd, char **a_args);
extern int	e_ExecCmdList(int *r_status, char **r_results,
			char *a_inputFile, char *a_cmd, ...);
extern int	gpkgmap(struct cfent *ept, FILE *fp);
extern int	gpkgmapvfp(struct cfent *ept, VFP_T *fpv);
extern void	setmapmode(int mode_no);
extern int	isFdRemote(int a_fd);
extern int	isFstypeRemote(char *a_fstype);
extern int	isPathRemote(char *a_path);
extern int	iscpio(char *path, int *iscomp);
extern int	isdir(char *path);
extern int	isfile(char *dir, char *file);
extern int	fmkdir(char *a_path, int a_mode);
extern int	pkgexecl(char *filein, char *fileout, char *uname, char *gname,
			...);
extern int	pkgexecv(char *filein, char *fileout, char *uname, char *gname,
			char *arg[]);
extern int	pkghead(char *device);
extern int	pkgmount(struct pkgdev *devp, char *pkg, int part, int nparts,
			int getvolflg);
extern int	pkgtrans(char *device1, char *device2, char **pkg,
			int options);
extern int	pkgumount(struct pkgdev *devp);
extern int	ppkgmap(struct cfent *ept, FILE *fp);
extern int	putcfile(struct cfent *ept, FILE *fp);
extern int	putcvfpfile(struct cfent *ept, VFP_T *vfp);
extern int	rrmdir(char *path);
extern void	set_memalloc_failure_func(void (*)(int));
extern void	*xmalloc(size_t size);
extern void	*xrealloc(void *ptr, size_t size);
extern char	*xstrdup(char *str);

extern int	srchcfile(struct cfent *ept, char *path, PKGserver server);
extern struct	group *cgrgid(gid_t gid);
extern struct	group *cgrnam(char *nam);
extern struct	passwd *cpwnam(char *nam);
extern struct	passwd *cpwuid(uid_t uid);
extern struct	group *clgrgid(gid_t gid);
extern struct	group *clgrnam(char *nam);
extern struct	passwd *clpwnam(char *nam);
extern struct	passwd *clpwuid(uid_t uid);
extern void	basepath(char *path, char *basedir, char *ir);
extern void	canonize(char *file);
extern void	canonize_slashes(char *file);
extern void	checksum_off(void);
extern void	checksum_on(void);
extern void	cvtpath(char *path, char *copy);
extern void	ds_order(char *list[]);
extern void	ds_putinfo(char *buf, size_t);
extern void	ds_skiptoend(char *device);
extern void	ecleanup(void);
/*PRINTFLIKE1*/
extern void	logerr(char *fmt, ...);
extern int	mappath(int flag, char *path);
extern int	mapvar(int flag, char *varname);
/*PRINTFLIKE1*/
extern void	progerr(char *fmt, ...);
extern void	rpterr(void);
extern void	tputcfent(struct cfent *ept, FILE *fp);
extern void	set_nonABI_symlinks(void);
extern int	nonABI_symlinks(void);
extern void	disable_attribute_check(void);
extern int	get_disable_attribute_check(void);

/* pkgstr.c */
void		pkgstrConvertUllToTimeString_r(unsigned long long a_time,
			char *a_buf, int a_bufLen);
char		*pkgstrConvertPathToBasename(char *a_path);
char		*pkgstrConvertPathToDirname(char *a_path);
char		*pkgstrDup(char *a_str);
char		*pkgstrLocatePathBasename(char *a_path);
void		pkgstrScaleNumericString(char *a_buf, unsigned long long scale);
void		pkgstrAddToken(char **a_old, char *a_new, char a_separator);
boolean_t	pkgstrContainsToken(char *a_string, char *a_token,
			char *a_separators);
void		pkgstrExpandTokens(char **a_old, char *a_string,
			char a_separator, char *a_separators);
char		*pkgstrGetToken(char *r_sep, char *a_string, int a_index,
			char *a_separators);
void		pkgstrGetToken_r(char *r_sep, char *a_string, int a_index,
			char *a_separators, char *a_buf, int a_bufLen);
unsigned long	pkgstrNumTokens(char *a_string, char *a_separators);
char		*pkgstrPrintf(char *a_format, ...);
void		pkgstrPrintf_r(char *a_buf, int a_bufLen, char *a_format, ...);
void		pkgstrRemoveToken(char **r_string, char *a_token,
			char *a_separators, int a_index);
void		pkgstrRemoveLeadingWhitespace(char **a_str);
/* vfpops.c */
extern int	vfpCheckpointFile(VFP_T **r_destVfp, VFP_T **a_vfp,
			char *a_path);
extern int	vfpCheckpointOpen(VFP_T **a_cvfp, VFP_T **r_vfp, char *a_path,
			char *a_mode, VFPFLAGS_T a_flags);
extern int	vfpClearModified(VFP_T *a_vfp);
extern int	vfpClose(VFP_T **r_vfp);
extern int	vfpGetModified(VFP_T *a_vfp);
extern int	vfpOpen(VFP_T **r_vfp, char *a_path, char *a_mode,
			VFPFLAGS_T a_flags);
extern void	vfpRewind(VFP_T *a_vfp);
extern ssize_t	vfpSafePwrite(int a_fildes, void *a_buf,
			size_t a_nbyte, off_t a_offset);
extern ssize_t	vfpSafeWrite(int a_fildes, void *a_buf, size_t a_nbyte);
extern int	vfpSetFlags(VFP_T *a_vfp, VFPFLAGS_T a_flags);
extern int	vfpSetModified(VFP_T *a_vfp);
extern int	vfpSetSize(VFP_T *a_vfp, size_t a_size);
extern void	vfpTruncate(VFP_T *a_vfp);
extern int	vfpWriteToFile(VFP_T *a_vfp, char *a_path);

/* handlelocalfs.c */
boolean_t	enable_local_fs(void);
boolean_t	restore_local_fs(void);

/* path_valid.c */
extern boolean_t	path_valid(char *);

/* pkgserv.c */
extern PKGserver	pkgopenserver(const char *, const char *, boolean_t);
extern void		pkgcloseserver(PKGserver);
extern int		pkgcmd(PKGserver, void *, size_t, char **, size_t *,
    int *);
extern boolean_t	pkgsync_needed(const char *, const char *, boolean_t);
extern int		pkgsync(const char *, const char *, boolean_t);
extern int		pkgservercommitfile(VFP_T *, PKGserver);
extern int		pkgopenfilter(PKGserver server, const char *pkginst);
extern void		pkgclosefilter(PKGserver);
extern char 		*pkggetentry(PKGserver, int *, int *);
extern char 		*pkggetentry_named(PKGserver, const char *, int *,
    int *);
extern void		pkgserversetmode(start_mode_t);
extern start_mode_t	pkgservergetmode(void);
extern start_mode_t	pkgparsemode(const char *);
extern char 		*pkgmodeargument(start_mode_t);

#ifdef	__cplusplus
}
#endif

#endif	/* _PKGLIB_H */
