/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * Copyright (c) 1980, 1986, 1990 The Regents of the University of California.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted
 * provided that: (1) source distributions retain this entire copyright
 * notice and comment, and (2) distributions including binaries display
 * the following acknowledgement:  ``This product includes software
 * developed by the University of California, Berkeley and its contributors''
 * in the documentation or other materials provided with the distribution
 * and in all advertising materials mentioning features or use of this
 * software. Neither the name of the University nor the names of its
 * contributors may be used to endorse or promote products derived
 * from this software without specific prior written permission.
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */

/*
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_FSCK_FSCK_H
#define	_FSCK_FSCK_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.3   */

#ifdef	__cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <stdarg.h>
#include <search.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/mnttab.h>
#include <sys/vfstab.h>
#include <sys/fs/ufs_fs.h>
#include <sys/fs/ufs_inode.h>

#define	MAXDUP		10	/* limit on dup blks (per inode) */
#define	MAXBAD		10	/* limit on bad blks (per inode) */
#define	MAXBUFSPACE	40*1024 /* initial space to allocate to buffers */
#define	INOBUFSIZE	56*1024	/* size of buffer to read inodes in pass1 */

#ifndef BUFSIZ
#define	BUFSIZ MAXPATHLEN
#endif

/*
 * Inode states in statemap[].
 */
#define	USTATE	0x01		/* inode not allocated */
#define	FSTATE	0x02		/* inode is file */
#define	DSTATE	0x04		/* inode is directory */
#define	SSTATE	0x08		/* inode is a shadow/acl */
#define	STMASK	0x0f		/* pick off the basic state/type */

/* flags OR'd into the above */
#define	INZLINK  0x0010		/* inode has zero links */
#define	INFOUND  0x0020		/* inode was found during descent */
#define	INCLEAR  0x0040		/* inode is to be cleared */
#define	INORPHAN 0x0080		/* inode is a known orphan (pass3 only) */
#define	INDELAYD 0x0200		/* link count update delayed */
#define	INMASK   0xfff0		/* pick off the modifiers */

#define	FZLINK	(FSTATE | INZLINK)
#define	DZLINK	(DSTATE | INZLINK)
#define	SZLINK	(SSTATE | INZLINK)

#define	DFOUND	(DSTATE | INFOUND)

#define	DCLEAR	(DSTATE | INCLEAR)
#define	FCLEAR	(FSTATE | INCLEAR)
#define	SCLEAR	(SSTATE | INCLEAR)

/*
 * These tests depend on the state/type defines above not overlapping bits.
 *
 *     	DUNFOUND === (state == DSTATE || state == DZLINK)
 *          INCLEAR is irrelevant to the determination of
 *          connectedness, so it's not included in this test.
 *
 *     	DVALID   === (state == DSTATE || state == DZLINK || state == DFOUND)
 */
#define	S_IS_DUNFOUND(state)	(((state) & (DSTATE | INZLINK)) \
				== (state))
#define	S_IS_DVALID(state)	(((state) & (DSTATE | INZLINK | INFOUND | \
				INORPHAN)) == (state))
#define	S_IS_ZLINK(state)	(((state) & INZLINK) != 0)
#define	INO_IS_DUNFOUND(ino)	S_IS_DUNFOUND(statemap[ino])
#define	INO_IS_DVALID(ino)	S_IS_DVALID(statemap[ino])

/*
 * buffer cache structure.
 */
struct bufarea {
	struct bufarea	*b_next;		/* free list queue */
	struct bufarea	*b_prev;		/* free list queue */
	diskaddr_t	b_bno;			/* physical sector number */
	int	b_size;
	int	b_errs;
	int	b_flags;
	int	b_cnt;				/* reference cnt */
	union {
		char	*b_buf;			/* buffer space */
		daddr32_t	*b_indir;	/* indirect block */
		struct	fs *b_fs;		/* super block */
		struct	cg *b_cg;		/* cylinder group */
		struct	dinode *b_dinode;	/* inode block */
	} b_un;
	char	b_dirty;
};

#define	B_INUSE 1

#define	MINBUFS		5	/* minimum number of buffers required */
struct bufarea bufhead;		/* head of list of other blks in filesys */
struct bufarea sblk;		/* file system superblock */
struct bufarea asblk;		/* alternate superblock */
struct bufarea cgblk;		/* cylinder group blocks */
struct bufarea *pbp;		/* pointer to inode data in buffer pool */
struct bufarea *pdirbp;		/* pointer to directory data in buffer pool */

#define	sbdirty()	dirty(&sblk)
#define	cgdirty()	dirty(&cgblk)
#define	sblock		(*sblk.b_un.b_fs)
#define	cgrp		(*cgblk.b_un.b_cg)

/*
 * inodesc.id_fix values.  See inode.c for a description of their usage.
 */
enum fixstate {
	DONTKNOW, NOFIX, FIX, IGNORE
};

/*
 * Tells truncino() whether or not to attempt to update the parent
 * directory's link count.  Also, TI_NODUP flags when we're discarding
 * fragments that are beyond the original end of the file, and so
 * should not be considered duplicate-claim candidates.
 */
#define	TI_NOPARENT	0x0001	/* leave parent's di_nlink alone */
#define	TI_PARENT	0x0002	/* update parent's di_nlink */
#define	TI_NODUP	0x0004	/* not a dup candidate */

/*
 * Modes for ckinode() and ckinode_common().
 *
 * CKI_TRAVERSE is the common case, and requests a traditional
 * traversal of blocks or directory entries.
 *
 * CKI_TRUNCATE indicates that we're truncating the file, and that any
 * block indices beyond the end of the target length should be cleared
 * after the callback has returned (i.e., this is a superset of
 * CKI_TRAVERSE).  idesc->id_truncto is the first logical block number
 * to clear.  If it is less than zero, then the traversal will be
 * equivalent to a simple CKI_TRAVERSE.
 */
enum cki_action { CKI_TRAVERSE, CKI_TRUNCATE };

/*
 * The general definition of an ino_t is an unsigned quantity.
 * However, the on-disk version is an int32_t, which is signed.
 * Since we really want to be able to detect wrapped-around
 * inode numbers and such, we'll use something that's compatible
 * with what's on disk since that's the only context that really
 * matters.  If an int32_t is found not to be sufficiently large,
 * this will make it much easier to change later.
 *
 * Note that there is one unsigned inode field in the on-disk
 * inode, ic_oeftflag.  Since all other inode fields are signed,
 * no legitimate inode number can be put into ic_oeftflag that
 * would overflow into the high bit.  Essentially, it should
 * actually be declared as int32_t just like all the others, and
 * we're going to pretend that it was.
 *
 * None of the routines that we use in ufs_subr.c do anything with
 * inode numbers.  If that changes, then great care will be needed
 * to deal with the differences in definition of ino_t and fsck_ino_t.
 * Lint is your friend.
 */
typedef int32_t		fsck_ino_t;

/*
 * See the full discussion of the interactions between struct inodesc
 * and ckinode() in inode.c
 */
struct inodesc {
	enum fixstate id_fix;	/* policy on fixing errors */
	int (*id_func)(struct inodesc *);
				/* function to be applied to blocks of inode */
	fsck_ino_t id_number;	/* inode number described */
	fsck_ino_t id_parent;	/* for DATA nodes, their parent */
				/* also used for extra (*id_func) parameter */
				/* and return values */
	daddr32_t id_lbn;	/* logical fragment number of current block */
	daddr32_t id_blkno;	/* physical fragment number being examined */
	int id_numfrags;	/* number of frags contained in block */
	daddr32_t id_truncto;	/* # blocks to truncate to, -1 for no trunc. */
	offset_t id_filesize;	/* for DATA nodes, the size of the directory */
	uint_t id_loc;		/* for DATA nodes, current location in dir */
	daddr32_t id_entryno;	/* for DATA nodes, current dir entry number */
	daddr32_t id_firsthole;	/* for DATA inode, logical block that is */
				/* zero but shouldn't be, -1 for no holes */
	struct direct *id_dirp;	/* for DATA nodes, ptr to current entry */
	caddr_t id_name;	/* for DATA nodes, name to find or enter */
	char id_type;		/* type of descriptor, DATA or ADDR */
};

/* file types (0 is reserved for catching bugs) */
#define	DATA	1	/* a directory */
#define	ACL	2	/* an acl/shadow */
#define	ADDR	3	/* anything but a directory or an acl/shadow */

/*
 * OR'd flags for find_dup_ref()'s mode argument
 */
#define	DB_CREATE	0x01	/* if dup record found, make one */
#define	DB_INCR		0x02	/* increment block's reference count */
#define	DB_DECR		0x04	/* decrement block's reference count */

/*
 * Cache data structures
 */
struct inoinfo {
	struct inoinfo	*i_nextlist;	/* next inode/acl cache entry */
	fsck_ino_t	i_number;	/* inode number of this entry */
	fsck_ino_t	i_parent;	/* inode number of parent */
	fsck_ino_t	i_dotdot;	/* inode number of .. */
	fsck_ino_t	i_extattr;	/* inode of hidden attr dir */
	offset_t	i_isize;	/* size of inode */
	size_t		i_blkssize;	/* size of block array in bytes */
	daddr32_t	i_blks[1];	/* actually longer */
};

/*
 * Inode cache
 */
struct inoinfo **inphead, **inpsort;
int64_t numdirs, listmax, inplast;

/*
 * ACL cache
 */
struct inoinfo **aclphead, **aclpsort;
int64_t numacls, aclmax, aclplast;

/*
 * Tree of directories we haven't reconnected or cleared.  Any
 * dir inode that linkup() fails on gets added, any that clri()
 * succeeds on gets removed.  If there are any left at the end of
 * pass four, then we have a user-forced corrupt filesystem, and
 * need to set iscorrupt.
 *
 * Elements are fsck_ino_t instances (not pointers).
 */
void *limbo_dirs;

/*
 * Number of directories we actually found in the filesystem,
 * as opposed to how many the superblock claims there are.
 */
fsck_ino_t countdirs;

/*
 * shadowclients and shadowclientinfo are structures for keeping track of
 * shadow inodes that exist, and which regular inodes use them (i.e. are
 * their clients).
 */

struct shadowclients {
	fsck_ino_t *client;	/* an array of inode numbers */
	int nclients; /* how many inodes in the array are in use (valid) */
	struct shadowclients *next; /* link to more client inode numbers */
};
struct shadowclientinfo {
	fsck_ino_t shadow;	/* the shadow inode that this info is for */
	int totalClients;	/* how many inodes total refer to this */
	struct shadowclients *clients; /* a linked list of wads of clients */
	struct shadowclientinfo *next; /* link to the next shadow inode */
};
/* global pointer to this shadow/client information */
struct shadowclientinfo *shadowclientinfo;
struct shadowclientinfo *attrclientinfo;

/*
 * In ufs_inode.h ifdef _KERNEL, this is defined as `/@/'.  However,
 * to avoid all sorts of potential confusion (you can't actually use
 * `foo/@/bar' to get to an attribute), we use something that doesn't
 * look quite so much like a simple pathname.
 */
#define	XATTR_DIR_NAME	" <xattr> "

/*
 * granularity -- how many client inodes do we make space for at a time
 * initialized in setup.c;
 */
extern int maxshadowclients;

/*
 * Initialized global variables.
 */
extern caddr_t lfname;

/*
 * Unitialized globals.
 */
char	*devname;		/* name of device being checked */
size_t	dev_bsize;		/* computed value of DEV_BSIZE */
int	secsize;		/* actual disk sector size */
char	nflag;			/* assume a no response */
char	yflag;			/* assume a yes response */
daddr32_t	bflag;		/* location of alternate super block */
int	debug;			/* output debugging info */
int	rflag;			/* check raw file systems */
int	roflag;			/* do normal checks but don't update disk */
int	fflag;			/* check regardless of clean flag (force) */
int	mflag;			/* sanity check only */
int	verbose;		/* be chatty */
char	preen;			/* just fix normal inconsistencies */
char	mountedfs;		/* checking mounted device */
int	exitstat;		/* exit status (see EX* defines below) */
char	hotroot;		/* checking root device */
char	rerun;			/* rerun fsck. Only used in non-preen mode */
int	interrupted;		/* 1 => exit EXSIGNAL on exit */
char	havesb;			/* superblock has been read */
int	fsmodified;		/* 1 => write done to file system */
int	fsreadfd;		/* file descriptor for reading file system */
int	fswritefd;		/* file descriptor for writing file system */
int	iscorrupt;		/* known to be corrupt/inconsistent */
				/* -1 means mark clean so user can mount+fix */
int	isdirty;		/* 1 => write pending to file system */

int	islog;			/* logging file system */
int	islogok;		/* log is okay */

int	errorlocked;		/* set => mounted fs has been error-locked */
				/* implies fflag "force check flag" */
char	*elock_combuf;		/* error lock comment buffer */
char	*elock_mountp;		/* mount point; used to unlock error-lock */
int	pid;			/* fsck's process id (put in lockfs comment) */
int	mountfd;		/* fd of mount point */
struct lockfs	*lfp;		/* current lockfs status */

daddr32_t	maxfsblock;	/* number of blocks in the file system */
uint_t	largefile_count;	/* global largefile counter */
char	*mount_point;		/* if mounted, this is where */
char	*blockmap;		/* ptr to primary blk allocation map */
fsck_ino_t	maxino;		/* number of inodes in file system */
fsck_ino_t	lastino;	/* last inode in use */
ushort_t *statemap;		/* ptr to inode state table */
short	*lncntp;		/* ptr to link count table */

fsck_ino_t	lfdir;		/* lost & found directory inode number */
int		overflowed_lf;	/* tried to wrap lost & found's link count */
int		reattached_dir;	/* reconnected at least one directory */
int		broke_dir_link;	/* broke at least one directory hardlink */

daddr32_t	n_blks;		/* number of blocks in use */
fsck_ino_t	n_files;	/* number of files in use */

#define	clearinode(dp)	{ \
	*(dp) = zino; \
}
struct	dinode zino;

#define	testbmap(blkno)	isset(blockmap, blkno)
#define	setbmap(blkno)	setbit(blockmap, blkno)
#define	clrbmap(blkno)	clrbit(blockmap, blkno)

#define	STOP	0x01
#define	SKIP	0x02
#define	KEEPON	0x04
#define	ALTERED	0x08
#define	FOUND	0x10

/*
 * Support relatively easy debugging of lncntp[] updates.  This can't
 * be a function, because of the (_op) step.  Normally, we just do that.
 */
#define	TRACK_LNCNTP(_ino, _op) (_op)

/*
 * See if the net link count for an inode has gone outside
 * what can be represented on disk.  Returning text as NULL
 * indicates no.
 *
 * Remember that link counts are effectively inverted, so
 * underflow and overflow are reversed as well.
 *
 * This check should be done before modifying the actual link
 * count.
 */
#define	LINK_RANGE(text, current, offset) { \
	int net = ((int)(current)) + ((int)(offset)); \
	text = NULL; \
	if (net > (MAXLINK)) \
		text = "UNDERFLOW"; \
	else if (net < -(MAXLINK)) \
		text = "OVERFLOW"; \
}

/*
 * If LINK_RANGE() indicated a problem, this is the boiler-plate
 * for dealing with it.  Usage is:
 *
 *     LINK_RANGE(text, current, offset);
 *     if (text != NULL) {
 *         LINK_CLEAR(text, ino, mode, idp);
 *         if (statemap[ino] == USTATE)
 *             ...inode was cleared...
 *     }
 *
 * Note that clri() will set iscorrupt if the user elects not to
 * clear the problem inode, so the filesystem won't get reported
 * as clean when it shouldn't be.
 */
#define	LINK_CLEAR(text, ino, mode, idp) { \
	pwarn("%s LINK COUNT %s", file_id((ino), (mode)), (text)); \
	pinode((ino)); \
	pfatal(""); \
	init_inodesc((idp)); \
	(idp)->id_type = ADDR; \
	(idp)->id_func = pass4check; \
	(idp)->id_number = ino; \
	(idp)->id_fix = DONTKNOW; \
	clri((idp), (text), CLRI_QUIET, CLRI_NOP_CORRUPT); \
}

/*
 * Used for checking link count under/overflow specifically on
 * the lost+found directory.  If the user decides not to do the
 * clri(), then flag that we've hit this problem and refuse to do
 * the reconnect.
 */
#define	LFDIR_LINK_RANGE_RVAL(text, current, offset, idp, rval) { \
	LINK_RANGE(text, current, offset); \
	if (text != NULL) { \
		LINK_CLEAR(text, lfdir, IFDIR, idp); \
		if (statemap[lfdir] == USTATE) { \
			lfdir = 0; \
			return (rval); \
		} else { \
			overflowed_lf++; \
		} \
	} \
}

#define	LFDIR_LINK_RANGE_NORVAL(text, current, offset, idp) { \
	LINK_RANGE(text, current, offset); \
	if (text != NULL) { \
		LINK_CLEAR(text, lfdir, IFDIR, idp); \
		if (statemap[lfdir] == USTATE) { \
			lfdir = 0; \
			return; \
		} else { \
			overflowed_lf++; \
		} \
	} \
}

/*
 * Values for mounted() and mountedfs.
 */
#define	M_NOMNT		0	/* filesystem is not mounted */
#define	M_RO		1	/* filesystem is mounted read-only */
#define	M_RW		2	/* filesystem is mounted read-write */

#define	EXOKAY		0	/* file system is unmounted and ok */
#define	EXBADPARM	1	/* bad parameter(s) given */
#define	EXUMNTCHK	32	/* fsck -m: unmounted, needs checking */
#define	EXMOUNTED	33	/* file system already mounted, not magic, */
				/* or it is magic and mounted read/write */
#define	EXNOSTAT	34	/* cannot stat device */
#define	EXREBOOTNOW	35	/* modified root or something equally scary */
#define	EXFNDERRS	36	/* uncorrectable errors, terminate normally */
#define	EXSIGNAL	37	/* a signal was caught during processing */
#define	EXERRFATAL	39	/* uncorrectable errors, exit immediately */
#define	EXROOTOKAY	40	/* for root, same as 0 */

/*
 * Values for clri()'s `verbose' and `corrupting' arguments (third
 * and fourth, respectively).
 */
#define	CLRI_QUIET		1
#define	CLRI_VERBOSE		2

#define	CLRI_NOP_OK		1
#define	CLRI_NOP_CORRUPT	2

/*
 * Filesystems that are `magical' - if they exist in vfstab,
 * then they have to be mounted for the system to have gotten
 * far enough to be able to run fsck.  Thus, don't get all
 * bent out of shape if we're asked to check it and it is mounted.
 * Actual initialization of the array is in main.c
 */
enum magic {
	MAGIC_NONE = 0,
	MAGIC_ROOT = 1,
	MAGIC_USR = 2,
	MAGIC_LIMIT = 3
};
extern char *magic_fs[];

/*
 * Paths needed by calcsb().
 */
#define	MKFS_PATH	"/usr/lib/fs/ufs/mkfs"
#define	NEWFS_PATH	"/usr/lib/fs/ufs/newfs"

int		acltypeok(struct dinode *);
void		add_orphan_dir(fsck_ino_t);
void		adjust(struct inodesc *, int);
daddr32_t	allocblk(int);
fsck_ino_t	allocdir(fsck_ino_t, fsck_ino_t, int, int);
fsck_ino_t	allocino(fsck_ino_t, int);
void		blkerror(fsck_ino_t, caddr_t, daddr32_t, daddr32_t);
void		brelse(struct bufarea *);
void		bufinit(void);
void		bwrite(int, caddr_t, diskaddr_t, int64_t);
void		cacheacl(struct dinode *, fsck_ino_t);
void		cacheino(struct dinode *, fsck_ino_t);
void		catch(int);
void		catchquit(int);
caddr_t		cg_sanity(struct cg *, int);
void		cgflush(void);
int		cgisdirty(void);
int		changeino(fsck_ino_t, caddr_t, fsck_ino_t);
int		check_mnttab(caddr_t, caddr_t, size_t);
int		check_vfstab(caddr_t, caddr_t, size_t);
int		chkrange(daddr32_t, int);
void		ckfini(void);
int		ckinode(struct dinode *, struct inodesc *, enum cki_action);
void		clearattrref(fsck_ino_t);
int		cleardirentry(fsck_ino_t, fsck_ino_t);
void		clearshadow(fsck_ino_t, struct shadowclientinfo **);
void		clri(struct inodesc *, caddr_t, int, int);
void		deshadow(struct shadowclientinfo *, void (*)(fsck_ino_t));
void		direrror(fsck_ino_t, caddr_t, ...);
int		dirscan(struct inodesc *);
void		dirty(struct bufarea *);
int		do_errorlock(int);
int		dofix(struct inodesc *, caddr_t, ...);
void		examinelog(void (*)(daddr32_t));
void		errexit(caddr_t, ...);
void		fileerror(fsck_ino_t, fsck_ino_t, caddr_t, ...);
caddr_t		file_id(fsck_ino_t, mode_t);
int		find_dup_ref(daddr32_t, fsck_ino_t, daddr32_t, int);
int		findino(struct inodesc *);
int		findname(struct inodesc *);
void		fix_cg(struct cg *, int);
void		flush(int, struct bufarea *);
void		free_dup_state(void);
void		freeblk(fsck_ino_t, daddr32_t, int);
void		freeino(fsck_ino_t, int);
void		freeinodebuf(void);
int		fsck_asprintf(caddr_t *, caddr_t, ...);
int		fsck_bread(int, caddr_t, diskaddr_t, size_t);
int		ftypeok(struct dinode *);
struct bufarea	*getblk(struct bufarea *, daddr32_t, size_t);
struct bufarea	*getdatablk(daddr32_t, size_t size);
diskaddr_t	getdisksize(caddr_t, int);
struct inoinfo	*getinoinfo(fsck_ino_t);
struct dinode	*getnextinode(fsck_ino_t);
struct dinode	*getnextrefresh(void);
void		getpathname(caddr_t, fsck_ino_t, fsck_ino_t);
struct dinode	*ginode(fsck_ino_t);
caddr_t		hasvfsopt(struct vfstab *, caddr_t);
int		have_dups(void);
void		init_inodesc(struct inodesc *);
void		init_inoinfo(struct inoinfo *, struct dinode *, fsck_ino_t);
void		initbarea(struct bufarea *);
int		ino_t_cmp(const void *, const void *);
int		inocached(fsck_ino_t);
void		inocleanup(void);
void		inodirty(void);
int		is_errorlocked(caddr_t);
int		linkup(fsck_ino_t, fsck_ino_t, caddr_t);
int		lookup_named_ino(fsck_ino_t, caddr_t);
int		makeentry(fsck_ino_t, fsck_ino_t, caddr_t);
void		maybe_convert_attrdir_to_dir(fsck_ino_t);
int		mounted(caddr_t, caddr_t, size_t);
void		pass1(void);
void		pass1b(void);
int		pass1check(struct inodesc *);
void		pass2(void);
void		pass3a(void);
void		pass3b(void);
int		pass3bcheck(struct inodesc *);
void		pass4(void);
int		pass4check(struct inodesc *);
void		pass5(void);
void		pfatal(caddr_t, ...);
void		pinode(fsck_ino_t);
void		printclean(void);
void		propagate(void);
void		pwarn(caddr_t, ...);
caddr_t		rawname(caddr_t);
void		registershadowclient(fsck_ino_t, fsck_ino_t,
		    struct shadowclientinfo **);
void		remove_orphan_dir(fsck_ino_t);
int		reply(caddr_t, ...);
int		report_dups(int);
void		resetinodebuf(void);
char		*setup(caddr_t);
void		truncino(fsck_ino_t, offset_t, int);
void		unbufinit(void);
caddr_t		unrawname(caddr_t);
void		unregistershadow(fsck_ino_t, struct shadowclientinfo **);
int		updateclean(void);
int		writable(caddr_t);
void		write_altsb(int);

/*
 * Functions from the kernel sources (ufs_subr.c, etc).
 */
extern void	fragacct(struct fs *, int, int32_t *, int);

#ifdef	__cplusplus
}
#endif

#endif	/* _FSCK_FSCK_H */
