/*
 * Copyright (c) 1983 Regents of the University of California.
 * All rights reserved.  The Berkeley software License Agreement
 * specifies the terms and conditions for redistribution.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved	*/

/*
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _RESTORE_H
#define	_RESTORE_H

#include <stdio.h>
#include <string.h>
#include <malloc.h>
#include <netdb.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <sys/time.h>
#include <sys/vnode.h>
#include <locale.h>
#include <stdlib.h>
#include <sys/fs/ufs_inode.h>
#include <sys/fs/ufs_fs.h>
#include <sys/fs/ufs_fsdir.h>
#include <note.h>

#ifdef	__cplusplus
extern "C" {
#endif

#define	ROOTINO	UFSROOTINO
#define	SUPPORTS_MTB_TAPE_FORMAT
#include <protocols/dumprestore.h>
#include <memutils.h>
#include <assert.h>

/*
 * Flags
 */
extern int	cvtflag;	/* convert from old to new tape format */
extern int	bflag;		/* set input block size */
extern int	dflag;		/* print out debugging info */
extern int	hflag;		/* restore heirarchies */
extern int	mflag;		/* restore by name instead of inode number */
extern int	vflag;		/* print out actions taken */
extern int	yflag;		/* always try to recover from tape errors */
extern int	paginating;	/* paginate bulk interactive output */
extern int	offline;	/* take tape offline when closing */
extern int	autoload;	/* wait for tape to autoload; implies offline */
/*
 * Global variables
 */
extern int	autoload_tries;	/* number of times to check on autoload */
extern int	autoload_period; /* seconds, tries*period = total wait time */
extern struct byteorder_ctx *byteorder;
extern char	*progname;	/* our name */
extern char	*dumpmap; 	/* map of inodes on this dump tape */
extern char	*clrimap; 	/* map of inodes to be deleted */
extern char	*c_label;	/* label we expect to see on the tape */
extern ino_t	maxino;		/* highest numbered inode in this file system */
extern long	dumpnum;	/* location of the dump on this tape */
extern int	volno;		/* current volume being read */
extern uint_t	ntrec;		/* number of tp_bsize records per tape block */
extern uint_t	saved_ntrec;	/* number of tp_bsize records per tape block */
extern ssize_t	tape_rec_size;	/* tape record size (tp_bsize * ntrec) */
extern time_t	dumptime;	/* time that this dump begins */
extern time_t	dumpdate;	/* time that this dump was made */
extern char	command;	/* opration being performed */
extern FILE	*terminal;	/* file descriptor for the terminal input */
extern char	*tmpdir;	/* where to put the rst{dir,mode}... files */
extern char	*pager_catenated; /* pager command and args */
extern char	**pager_vector;	/* pager_catenated split up for execve() */
extern int	pager_len;	/* # elements in pager_vector; includes NULL */
extern int	inattrspace;	/* true if currently scanning attribute space */
extern int	savepwd;	/* this is where restore is running from */

/*
 * Each file in the file system is described by one of these entries
 * Note that the e_next field is used by the symbol table hash lists
 * and then reused by the remove code after the entry is removed from
 * the symbol table.
 */
struct entry {
	char	*e_name;		/* the current name of this entry */
	ushort_t e_namlen;		/* length of this name */
	char	e_type;			/* type of this entry, see below */
	short	e_flags;		/* status flags, see below */
	ino_t	e_ino;			/* inode number in previous file sys */
	long	e_index;		/* unique index (for dumpped table) */
	struct	entry *e_parent;	/* pointer to parent directory (..) */
	struct	entry *e_sibling;	/* next element in this directory (.) */
	struct	entry *e_links;		/* hard links to this inode */
	struct	entry *e_entries;	/* for directories, their entries */
	struct	entry *e_xattrs;	/* pointer to extended attribute root */
	struct	entry *e_next;		/* hash chain list and removelist */
};
/* types */
#define	LEAF 1			/* non-directory entry */
#define	NODE 2			/* directory entry */
#define	LINK 4			/* synthesized type, stripped by addentry */
#define	ROOT 8			/* synthesized type, stripped by addentry */
/* flags */
#define	EXTRACT		0x0001	/* entry is to be replaced from the tape */
#define	NEW		0x0002	/* a new entry to be extracted */
#define	KEEP		0x0004	/* entry is not to change */
#define	REMOVED		0x0010	/* entry has been removed */
#define	TMPNAME		0x0020	/* entry has been given a temporary name */
#define	EXISTED		0x0040	/* directory already existed during extract */
#define	XATTR		0x0080	/* file belongs in an attribute tree */
#define	XATTRROOT	0x0100	/* directory is root of an attribute tree */
/*
 * functions defined on entry structs
 */
#ifdef __STDC__
extern struct entry *lookupino(ino_t);
extern struct entry *lookupname(char *);
extern struct entry *addentry(char *, ino_t, int);
extern void deleteino(ino_t);
extern char *myname(struct entry *);
extern void freeentry(struct entry *);
extern void moveentry(struct entry *, char *);
extern char *savename(char *);
extern void freename(char *);
extern void dumpsymtable(char *, int);
extern void initsymtable(char *);
extern void mktempname(struct entry *);
extern char *gentempname(struct entry *);
extern void newnode(struct entry *);
extern void removenode(struct entry *);
extern void removeleaf(struct entry *);
extern ino_t lowerbnd(ino_t);
extern ino_t upperbnd(ino_t);
extern void badentry(struct entry *, char *);
extern char *flagvalues(struct entry *);
extern ino_t dirlookup(char *);
#else
extern struct entry *lookupino();
extern struct entry *lookupname();
extern struct entry *addentry();
extern void deleteino();
extern char *myname();
extern void freeentry();
extern void moveentry();
extern char *savename();
extern void freename();
extern void dumpsymtable();
extern void initsymtable();
extern void mktempname();
extern char *gentempname();
extern void newnode();
extern void removenode();
extern void removeleaf();
extern ino_t lowerbnd();
extern ino_t upperbnd();
extern void badentry();
extern char *flagvalues();
extern ino_t dirlookup();
#endif
#define	NIL ((struct entry *)(0))

/*
 * Definitions for library routines operating on directories.
 * These definitions are used only for reading fake directory
 * entries from restore's temporary file "restoresymtable"
 * These have little to do with real directory entries.
 */
#if !defined(DEV_BSIZE)
#define	DEV_BSIZE	512
#endif
#define	DIRBLKSIZ	DEV_BSIZE
typedef struct _rstdirdesc {
	int	dd_fd;
	int	dd_refcnt;  /* so rst_{open,close}dir() avoid leaking memory */
	off64_t	dd_loc;
	off64_t	dd_size;
	char	dd_buf[DIRBLKSIZ];
} RST_DIR;

/*
 * Constants associated with entry structs
 */
#define	HARDLINK	1
#define	SYMLINK		2
#define	TMPHDR		"RSTTMP"

/*
 * The entry describes the next file available on the tape
 */
struct context {
	char	*name;		/* name of file */
	ino_t	ino;		/* inumber of file */
	struct	dinode *dip;	/* pointer to inode */
	int	action;		/* action being taken on this file */
	int	ts;		/* TS_* type of tape record */
} curfile;
/* actions */
#define	USING	1	/* extracting from the tape */
#define	SKIP	2	/* skipping */
#define	UNKNOWN 3	/* disposition or starting point is unknown */

/*
 * Structure and routines associated with listing directories
 * and expanding meta-characters in pathnames.
 */
struct afile {
	ino_t	fnum;		/* inode number of file */
	char	*fname;		/* file name */
	short	fflags;		/* extraction flags, if any */
	char	ftype;		/* file type, e.g. LEAF or NODE */
};
struct arglist {
	struct afile	*head;	/* start of argument list */
	struct afile	*last;	/* end of argument list */
	struct afile	*base;	/* current list arena */
	int		nent;	/* maximum size of list */
	char		*cmd;	/* the current command */
};

/*
 * Other exported routines
 */
#ifdef __STDC__
extern int mkentry(char *, ino_t, struct arglist *);
extern int expand(char *, int, struct arglist *);
extern ino_t psearch(char *);
extern void metaget(char **data, size_t *size);
extern void metaproc(char *, char *, size_t);
extern long listfile(char *, ino_t, int);
extern long addfile(char *, ino_t, int);
extern long deletefile(char *, ino_t, int);
extern long nodeupdates(char *, ino_t, int);
extern long verifyfile(char *, ino_t, int);
extern void extractdirs(int genmode);
extern void skipdirs(void);
extern void treescan(char *, ino_t, long (*)(char *, ino_t, int));
extern RST_DIR *rst_opendir(char *);
extern void rst_closedir(RST_DIR *);
extern struct direct *rst_readdir(RST_DIR *);
extern void setdirmodes(void);
extern int genliteraldir(char *, ino_t);
extern int inodetype(ino_t);
extern void done(int) __NORETURN;
extern void runcmdshell(void);
extern void canon(char *, char *, size_t);
extern void onintr(int);
extern void removeoldleaves(void);
extern void findunreflinks(void);
extern void removeoldnodes(void);
extern void createleaves(char *);
extern void createfiles(void);
extern void createlinks(void);
extern void checkrestore(void);
extern void setinput(char *, char *);
extern void newtapebuf(size_t);
extern void setup(void);
extern void setupR(void);
extern void getvol(int);
extern void printdumpinfo(void);
extern int extractfile(char *);
extern void skipmaps(void);
extern void skipfile(void);
extern void getfile(void (*)(char *, size_t), void (*)(char *, size_t));
extern void null(char *, size_t);
extern void findtapeblksize(int);
extern void flsht(void);
extern void closemt(int);
extern int readhdr(struct s_spcl *);
extern int gethead(struct s_spcl *);
extern int volnumber(ino_t);
extern void findinode(struct s_spcl *);
extern void pathcheck(char *);
extern void renameit(char *, char *);
extern int linkit(char *, char *, int);
extern int lf_linkit(char *, char *, int);
extern int reply(char *);
/*PRINTFLIKE1*/
extern void panic(const char *, ...);
extern char *lctime(time_t *);
extern int safe_open(int, const char *file, int mode, int perms);
extern FILE *safe_fopen(const char *filename, const char *smode, int perms);
extern void reset_dump(void);
extern void get_next_device(void);
extern void initpagercmd(void);
extern void resolve(char *, int *, char **);
extern int complexcopy(char *, char *, int);
#else	/* !STDC */
extern int mkentry();
extern int expand();
extern ino_t psearch();
extern void metaget();
extern void metaproc();
extern long listfile();
extern long addfile();
extern long deletefile();
extern long nodeupdates();
extern long verifyfile();
extern void extractdirs();
extern void skipdirs();
extern void treescan();
extern RST_DIR *rst_opendir();
extern void rst_closedir();
extern struct direct *rst_readdir();
extern void setdirmodes();
extern int genliteraldir();
extern int inodetype();
extern void done();
extern void runcmdshell();
extern void canon();
extern void onintr();
extern void removeoldleaves();
extern void findunreflinks();
extern void removeoldnodes();
extern void createleaves();
extern void createfiles();
extern void createlinks();
extern void checkrestore();
extern void setinput();
extern void newtapebuf();
extern void setup();
extern void setupR();
extern void getvol();
extern void printdumpinfo();
extern int extractfile();
extern void skipmaps();
extern void skipfile();
extern void getfile();
extern void null();
extern void findtapeblksize();
extern void flsht();
extern void closemt();
extern int readhdr();
extern int gethead();
extern int volnumber();
extern void findinode();
extern void pathcheck();
extern void renameit();
extern int linkit();
extern int lf_linkit();
extern int reply();
extern void panic();
extern char *lctime();
extern int safe_open();
extern FILE *safe_fopen();
extern void reset_dump();
extern void get_next_device();
extern void initpagercmd();
extern void resolve();
extern int complexcopy();
#endif	/* STDC */

/*
 * Useful macros
 */
#define	MWORD(m, i)	((m)[(ino_t)((i)-1)/NBBY])
#define	MBIT(i)		(1<<((ino_t)((i)-1)%NBBY))
#define	BIS(i, w)	(MWORD((w), (i)) |=  MBIT(i))
#define	BIC(i, w)	(MWORD((w), (i)) &= ~MBIT(i))
#define	BIT(i, w)	(MWORD((w), (i)) & MBIT(i))

/*
 * Macro used to get to the last segment of a complex string
 */
#define	LASTPART(s)	{int len = strlen(s)+1;\
				while (s[len] != '\0')\
					{s += len; len = strlen(s)+1; }\
			}

/*
 * Define maximum length of complex string.  For now we use
 * MAXPATHLEN * 2 since recursion is not (yet) supported.
 * (add 3 for the 3 NULL characters in a two-part path)
 * Note that each component of a complex string is still
 * limited to MAXPATHLEN length.
 */
#define	MAXCOMPLEXLEN	(MAXPATHLEN*2 + 3)

/*
 * Define an overflow-free version of howmany so that we don't
 * run into trouble with large files.
 */
#define	d_howmany(x, y)	((x) / (y) + ((x) % (y) != 0))

/*
 * Defines used by findtapeblksize()
 */
#define	TAPE_FILE	0
#define	ARCHIVE_FILE	1

#undef	setjmp
#define	setjmp(b)		sigsetjmp((b), 1)
#define	longjmp			siglongjmp
#define	jmp_buf			sigjmp_buf
#define	chown			lchown

/*
 * Defaults
 */
#define	TAPE	"/dev/rmt/0b"		/* default tape device */
#define	RESTORESYMTABLE	"./restoresymtable"

#define	dprintf		if (dflag) (void) fprintf
#define	vprintf		if (vflag) (void) fprintf

#define	GOOD 1
#define	FAIL 0

#define	ALLOW_OFFLINE	0
#define	FORCE_OFFLINE	1		/* offline drive for autoload */

#define	DEF_PAGER	"/usr/bin/more"

#ifdef	__cplusplus
}
#endif

#endif /* _RESTORE_H */
