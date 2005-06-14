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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_FSCK_FSCK_H
#define	_FSCK_FSCK_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.3   */

#ifdef	__cplusplus
extern "C" {
#endif

#define	MAXDUP		10	/* limit on dup blks (per inode) */
#define	MAXBAD		10	/* limit on bad blks (per inode) */
#define	MaxCPG		100000	/* sanity limit on # of cylinders / group */
#define	MAXBUFSPACE	40*1024	/* maximum space to allocate to buffers */
#define	INOBUFSIZE	56*1024	/* size of buffer to read inodes in pass1 */

#ifndef BUFSIZ
#define	BUFSIZ 1024
#endif

#define	USTATE	01		/* inode not allocated */
#define	FSTATE	02		/* inode is file */
#define	DSTATE	03		/* inode is directory */
#define	DFOUND	04		/* directory found during descent */
#define	DCLEAR	05		/* directory is to be cleared */
#define	FCLEAR	06		/* file is to be cleared */
#define	SSTATE	07		/* inode is a shadow */
#define	SCLEAR	10		/* shadow is to be cleared */

/*
 * buffer cache structure.
 */
struct bufarea {
	struct bufarea	*b_next;		/* free list queue */
	struct bufarea	*b_prev;		/* free list queue */
	diskaddr_t	b_bno;
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
struct bufarea cgblk;		/* cylinder group blocks */
struct bufarea *pbp;		/* pointer to inode data in buffer pool */
struct bufarea *pdirbp;		/* pointer to directory data in buffer pool */
struct bufarea *getdatablk(daddr32_t, int);

#define	dirty(bp)	(bp)->b_dirty = isdirty = 1
#define	initbarea(bp) \
	(bp)->b_dirty = 0; \
	(bp)->b_bno = -1LL; \
	(bp)->b_flags = 0;	\
	(bp)->b_cnt = 0;

#define	sbdirty()	sblk.b_dirty = isdirty = 1
#define	cgdirty()	cgblk.b_dirty = isdirty = 1
#define	sblock		(*sblk.b_un.b_fs)
#define	cgrp		(*cgblk.b_un.b_cg)

enum fixstate {DONTKNOW, NOFIX, FIX};

struct inodesc {
	enum fixstate id_fix;	/* policy on fixing errors */
	int (*id_func)();	/* function to be applied to blocks of inode */
	ino_t id_number;	/* inode number described */
	ino_t id_parent;	/* for DATA nodes, their parent */
	ino_t id_client;	/* base file for attribute */
	daddr32_t id_blkno;	/* current block number being examined */
	int id_numfrags;	/* number of frags contained in block */
	offset_t id_filesize;	/* for DATA nodes, the size of the directory */
	uint_t id_loc;	/* for DATA nodes, current location in dir */
	uint_t id_entryno;	/* for DATA nodes, current entry number */
	int id_hasholes;	/* for DATA inode, 1 == dir has holes */
	int id_llbna;		/* for DATA nodes, last logical block alloc'd */
	struct direct *id_dirp;	/* for DATA nodes, ptr to current entry */
	char *id_name;		/* for DATA nodes, name to find or enter */
	char id_type;		/* type of descriptor, DATA or ADDR */
};
/* file types */
#define	DATA	1
#define	ADDR	2
#define	ACL	3

/*
 * Linked list of duplicate blocks.
 *
 * The list is composed of two parts. The first part of the
 * list (from duplist through the node pointed to by muldup)
 * contains a single copy of each duplicate block that has been
 * found. The second part of the list (from muldup to the end)
 * contains duplicate blocks that have been found more than once.
 * To check if a block has been found as a duplicate it is only
 * necessary to search from duplist through muldup. To find the
 * total number of times that a block has been found as a duplicate
 * the entire list must be searched for occurences of the block
 * in question. The following diagram shows a sample list where
 * w (found twice), x (found once), y (found three times), and z
 * (found once) are duplicate block numbers:
 *
 *    w -> y -> x -> z -> y -> w -> y
 *    ^		     ^
 *    |              |
 * duplist	  muldup
 */
struct dups {
	struct dups *next;
	daddr32_t dup;
};
struct dups *duplist;		/* head of dup list */
struct dups *muldup;		/* end of unique duplicate dup block numbers */

/*
 * Linked list of inodes with zero link counts.
 */
struct zlncnt {
	struct zlncnt *next;
	ino_t zlncnt;
};
struct zlncnt *zlnhead;		/* head of zero link count list */

/*
 * Inode cache data structures.
 */
struct inoinfo {
	struct	inoinfo *i_nexthash;	/* next entry in hash chain */
	ino_t	i_number;		/* inode number of this entry */
	ino_t	i_parent;		/* inode number of parent */
	ino_t	i_dotdot;		/* inode number of `..' */
	ino_t	i_extattr;		/* inode of hidden attr dir */
	offset_t i_isize;		/* size of inode */
	uint_t	i_numblks;		/* size of block array in bytes */
	daddr32_t	i_blks[1];	/* actually longer */
} **inphead, **inpsort;
int64_t numdirs, listmax, inplast;

/*
 * Acl cache data structures.
 */
struct aclinfo {
	struct	aclinfo *i_nexthash;	/* next entry in hash chain */
	ino_t	i_number;		/* inode number of this entry */
	offset_t i_isize;		/* size of inode */
	uint_t	i_numblks;		/* size of block array in bytes */
	daddr32_t	i_blks[1];		/* actually longer */
} **aclphead, **aclpsort;
int64_t numacls, aclmax, aclplast;

/*
 * shadowclients and shadowclientinfo are structures for keeping track of
 * shadow inodes that exist, and which regular inodes use them (i.e. are
 * their clients).
 */

struct shadowclients {
	ino_t *client;	/* an array of inode numbers */
	int nclients; /* how many inodes in the array are in use (valid) */
	struct shadowclients *next; /* link to more client inode numbers */
};
struct shadowclientinfo {
	ino_t shadow;		/* the shadow inode that this info is for */
	int totalClients;	/* how many inodes total refer to this */
	struct shadowclients *clients; /* a linked list of wads of clients */
	struct shadowclientinfo *next; /* link to the next shadow inode */
};
/* global pointer to this shadow/client information */
extern struct shadowclientinfo *shadowclientinfo;
extern struct shadowclientinfo *attrclientinfo;
/* granularity -- how many client inodes do we make space for at a time */
/* initialized in setup.c; changable with adb should anyone ever have a need */
extern int maxshadowclients;
void registershadowclients(ino_t, ino_t, struct shadowclientinfo **);

char	*devname;		/* name of device being checked */
int	dev_bsize;		/* computed value of DEV_BSIZE */
int	secsize;		/* actual disk sector size */
char	nflag;			/* assume a no response */
char	yflag;			/* assume a yes response */
int	bflag;			/* location of alternate super block */
int	debug;			/* output debugging info */
int	rflag;			/* check raw file systems */
int	wflag;			/* check only writable filesystems */
int	fflag;			/* check regardless of clean flag (force) */
int	cvtflag;		/* convert to old file system format */
char	preen;			/* just fix normal inconsistencies */
char	mountedfs;		/* checking mounted device */
int	exitstat;		/* exit status (set to 8 if 'No' response) */
char	hotroot;		/* checking root device */
char	havesb;			/* superblock has been read */
int	fsmodified;		/* 1 => write done to file system */
int	fsreadfd;		/* file descriptor for reading file system */
int	fswritefd;		/* file descriptor for writing file system */

int	iscorrupt;		/* known to be corrupt/inconsistent */
int	isdirty;		/* 1 => write pending to file system */
int	isconvert;		/* converting */

int	dirholes;		/* Found dirs with holes in indirect blks */

int	islog;			/* logging file system */
int	islogok;		/* log is okay */
int	ismdd;			/* metadevice */
int	isreclaim;		/* reclaiming is set in the superblock */
int	willreclaim;		/* reclaim thread will run at mount */

int	errorlocked;		/* set => mounted fs has been error-locked */
				/* implies fflag "force check flag" */
char	*elock_combuf;		/* error lock comment buffer */
char	*elock_mountp;		/* mount point; used to unlock error-lock */
int	pid;			/* fsck's process id (put in lockfs comment) */
int	needs_reclaim;		/* files were deleted, hence reclaim needed */
int	mountfd;		/* fd of mount point */
struct lockfs	*lfp;		/* current lockfs status */

daddr32_t	maxfsblock;	/* number of blocks in the file system */
char	*blockmap;		/* ptr to primary blk allocation map */
ino_t	maxino;			/* number of inodes in file system */
ino_t	lastino;		/* last inode in use */
char	*statemap;		/* ptr to inode state table */
short	*lncntp;		/* ptr to link count table */

ino_t	lfdir;			/* lost & found directory inode number */
char	*lfname;		/* lost & found directory name */
int	lfmode;			/* lost & found directory creation mode */

char	*aclbuf;		/* hold acl's for parsing */
int64_t	aclbufoff;		/* offset into aclbuf */

daddr32_t	n_blks;			/* number of blocks in use */
daddr32_t	n_files;		/* number of files in use */

#define	clearinode(dp)	(*(dp) = zino), (needs_reclaim = errorlocked)
struct	dinode zino;

#define	setbmap(blkno)	setbit(blockmap, blkno)
#define	testbmap(blkno)	isset(blockmap, blkno)
#define	clrbmap(blkno)	clrbit(blockmap, blkno)

#define	STOP	0x01
#define	SKIP	0x02
#define	KEEPON	0x04
#define	ALTERED	0x08
#define	FOUND	0x10

time_t time();
struct dinode *ginode(ino_t);
struct inoinfo *getinoinfo(ino_t);
struct bufarea *getblk(struct bufarea *, daddr32_t, int);
ino_t allocino(ino_t, int);
int findino(struct inodesc *);
char *setup(char *);
struct bufarea *getdirblk(daddr32_t blkno, int size);
struct bufarea *getdatablk(daddr32_t blkno, int size);
daddr32_t allocblk(int frags);
extern int bread(int, char *, diskaddr_t, long);
extern int bwrite(int, char *, diskaddr_t, long);
extern int reply(char *);
extern int errexit();
extern int pfatal();
extern int pwarn();
extern int mounted(char *);
extern int do_errorlock(int);
extern int printclean(void);
extern int bufinit(void);
extern int ckfini(void);


#ifdef	__cplusplus
}
#endif

#endif	/* _FSCK_FSCK_H */
