/*
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved	*/

/*
 * Copyright (c) 1980 Regents of the University of California.
 * All rights reserved.  The Berkeley Software License Agreement
 * specifies the terms and conditions for redistribution.
 */

#include <stdlib.h>	 /* MB_xxx, mbxxx(), wcxxx() etc. */
#include <limits.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/siginfo.h>
#include <sys/ucontext.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/termios.h>
#include <sys/ttold.h>
#include <errno.h>
#include <signal.h>	/* std sysV signal.h */
#include <setjmp.h>
#include <sys/resource.h>
#include <netdb.h> /* for MAXHOSTNAMELEN */
#include "signal.h"	/* mainly BSD related signal.h */
#include "sh.local.h"
#include "sh.char.h"


#ifdef MBCHAR
#if !defined(MB_LEN_MAX) || !defined(MB_CUR_MAX)
	Error: I need both ANSI macros!
#endif
#else
#if !defined(MB_LEN_MAX)
#define	MB_LEN_MAX	1
#endif
#if !defined(MB_CUR_MAX)
#define	MB_CUR_MAX	1
#endif
#endif

#ifndef MBCHAR /* Let's replace the ANSI functions with our own macro
		* for efficiency!
		*/
#define	mbtowc(pwc, pmb, n_is_ignored)	((*(pwc) = *(pmb)), 1)
#define	wctomb(pmb, wc)			((*(pmb) = ((char)wc)), 1)
#endif /* !MBCHAR */

/*
 * C shell
 *
 * Bill Joy, UC Berkeley
 * October, 1978; May 1980
 *
 * Jim Kulp, IIASA, Laxenburg Austria
 * April, 1980
 */

/*
 * If we are setting the $cwd variable becuz we did a
 * cd, chdir, pushd, popd command, then set didchdir to
 * 1.  This prevents globbing down when setting $cwd.
 * However, if the user set $cwd, we want the globbing
 * done; so, didchdir would be equal to 0 in that case.
 */
extern int didchdir;

#define	isdir(d)	((d.st_mode & S_IFMT) == S_IFDIR)

typedef	char	bool;

/*
 * tchar (Tagged CHARacter) is a place holder to keep a QUOTE bit and
 * a character.
 * For European language handling, lower 8 bits of tchar is used
 * to store a character.  For other languages, especially Asian, 16 bits
 * are used to store a character.
 * Following typedef's assume short int is a 16-bit entity and long int is
 * a 32-bit entity.
 * The QUOTE bit tells whether the character is subject to further
 * interpretation such as history substitution, file mathing, command
 * subsitution.  TRIM is a mask to strip off the QUOTE bit.
 */
#ifdef MBCHAR		/* For multibyte character handling. */
typedef long int	tchar;
#define	QUOTE	0x80000000
#define	TRIM	0x7fffffff
#else /* !MBCHAR */	/* European language requires only 8 bits. */
typedef unsigned short int	tchar;
#define	QUOTE	0x8000
#define	TRIM	0x00ff
#endif /* !MBCHAR */
#define	eq(a, b)	(strcmp_(a, b) == 0)


/*
 * Global flags
 */
extern bool	chkstop;	/* Warned of stopped jobs... allow exit */
extern bool	didfds;		/* Have setup i/o fd's for child */
extern bool	doneinp;	/* EOF indicator after reset from readc */
extern bool	exiterr;	/* Exit if error or non-zero exit status */
extern bool	child;		/* Child shell ... errors cause exit */
extern bool	haderr;		/* Reset was because of an error */
extern bool	intty;		/* Input is a tty */
extern bool	cflg;		/* invoked with -c option */
extern bool	justpr;		/* Just print because of :p hist mod */
extern bool	loginsh;	/* We are a loginsh -> .login/.logout */
extern bool	neednote;	/* Need to pnotify() */
extern bool	noexec;		/* Don't execute, just syntax check */
extern bool	pjobs;		/* want to print jobs if interrupted */
extern bool	setintr;	/* Set interrupts on/off -> Wait intr... */
extern bool	havhash;	/* path hashing is available */
extern bool	havhash2;	/* cdpath hashing is available */
#ifdef FILEC
extern bool	filec;		/* doing filename expansion */
#endif

/*
 * Global i/o info
 */
extern tchar	*arginp;	/* Argument input for sh -c and internal `xx` */
extern int	onelflg;	/* 2 -> need line for -t, 1 -> exit on read */
extern tchar	*file;		/* Name of shell file for $0 */

extern char	*err_msg;	/* Error message from scanner/parser */
extern struct	timeval time0;	/* Time at which the shell started */

/*
 * Miscellany
 */
extern tchar	*doldol;	/* Character pid for $$ */
extern int	uid;		/* Invokers uid */
extern int	shpgrp;		/* Pgrp of shell */
extern int	tpgrp;		/* Terminal process group */
/* If tpgrp is -1, leave tty alone! */
extern int	opgrp;		/* Initial pgrp and tty pgrp */

/*
 * These are declared here because they want to be
 * initialized in sh.init.c (to allow them to be made readonly)
 */

extern struct	biltins {
	tchar	*bname;
	int	(*bfunct)();
	short	minargs, maxargs;
} bfunc[];
extern int nbfunc;

extern struct srch {
	tchar	*s_name;
	short	s_value;
} srchn[];
extern int nsrchn;

/*
 * To be able to redirect i/o for builtins easily, the shell moves the i/o
 * descriptors it uses away from 0,1,2.
 * Ideally these should be in units which are closed across exec's
 * (this saves work) but for version 6, this is not usually possible.
 * The desired initial values for these descriptors are defined in
 * sh.local.h.
 */
extern short	SHIN;		/* Current shell input (script) */
extern short	SHOUT;		/* Shell output */
extern short	SHDIAG;		/* Diagnostic output... shell errs go here */
extern short	OLDSTD;		/* Old standard input (def for cmds) */

/*
 * Error control
 *
 * Errors in scanning and parsing set up an error message to be printed
 * at the end and complete.  Other errors always cause a reset.
 * Because of source commands and .cshrc we need nested error catches.
 */

extern jmp_buf	reslab;

#define	setexit()	((void) setjmp(reslab))
#define	reset()		longjmp(reslab, 0)
	/* Should use structure assignment here */
#define	getexit(a)	copy((void *)(a), (void *)reslab, sizeof reslab)
#define	resexit(a)	copy((void *)reslab, ((void *)(a)), sizeof reslab)

extern tchar	*gointr;		/* Label for an onintr transfer */
extern void	(*parintr)();		/* Parents interrupt catch */
extern void	(*parterm)();		/* Parents terminate catch */


/*
 * Each level of input has a buffered input structure.
 * There are one or more blocks of buffered input for each level,
 * exactly one if the input is seekable and tell is available.
 * In other cases, the shell buffers enough blocks to keep all loops
 * in the buffer.
 */
extern struct	Bin {
	off_t	Bfseekp;		/* Seek pointer */
	off_t	Bfbobp;			/* Seekp of beginning of buffers */
	off_t	Bfeobp;			/* Seekp of end of buffers */
	short	Bfblocks;		/* Number of buffer blocks */
	tchar	**Bfbuf;		/* The array of buffer blocks */
} B;

#define	fseekp	B.Bfseekp
#define	fbobp	B.Bfbobp
#define	feobp	B.Bfeobp
#define	fblocks	B.Bfblocks
#define	fbuf	B.Bfbuf

#define	btell()	fseekp

#ifndef btell
extern off_t	btell(void);
#endif

/*
 * The shell finds commands in loops by reseeking the input
 * For whiles, in particular, it reseeks to the beginning of the
 * line the while was on; hence the while placement restrictions.
 */
extern off_t	lineloc;

#ifdef	TELL
extern bool	cantell;			/* Is current source tellable ? */
#endif

/*
 * Input lines are parsed into doubly linked circular
 * lists of words of the following form.
 */
struct	wordent {
	tchar	*word;
	struct	wordent *prev;
	struct	wordent *next;
};

/*
 * During word building, both in the initial lexical phase and
 * when expanding $ variable substitutions, expansion by `!' and `$'
 * must be inhibited when reading ahead in routines which are themselves
 * processing `!' and `$' expansion or after characters such as `\' or in
 * quotations.  The following flags are passed to the getC routines
 * telling them which of these substitutions are appropriate for the
 * next character to be returned.
 */
#define	DODOL	1
#define	DOEXCL	2
#define	DOALL	DODOL|DOEXCL

extern tchar	*lap;

/*
 * Parser structure
 *
 * Each command is parsed to a tree of command structures and
 * flags are set bottom up during this process, to be propagated down
 * as needed during the semantics/exeuction pass (sh.sem.c).
 */
struct	command {
	short	t_dtyp;				/* Type of node */
	short	t_dflg;				/* Flags, e.g. FAND|... */
	union {
		tchar	*T_dlef;		/* Input redirect word */
		struct	command *T_dcar;	/* Left part of list/pipe */
	} L;
	union {
		tchar	*T_drit;		/* Output redirect word */
		struct	command *T_dcdr;	/* Right part of list/pipe */
	} R;
#define	t_dlef	L.T_dlef
#define	t_dcar	L.T_dcar
#define	t_drit	R.T_drit
#define	t_dcdr	R.T_dcdr
	tchar	**t_dcom;			/* Command/argument vector */
	char	*cfname;			/* char pathname for execv */
	char	**cargs;			/* char arg vec  for execv */
	struct	command *t_dspr;		/* Pointer to ()'d subtree */
	short	t_nice;
};

#define	TCOM	1		/* t_dcom <t_dlef >t_drit	*/
#define	TPAR	2		/* ( t_dspr ) <t_dlef >t_drit	*/
#define	TFIL	3		/* t_dlef | t_drit		*/
#define	TLST	4		/* t_dlef ; t_drit		*/
#define	TOR	5		/* t_dlef || t_drit		*/
#define	TAND	6		/* t_dlef && t_drit		*/

#define	FSAVE	(FNICE|FTIME|FNOHUP)	/* save these when re-doing */

#define	FAND	(1<<0)		/* executes in background	*/
#define	FCAT	(1<<1)		/* output is redirected >>	*/
#define	FPIN	(1<<2)		/* input is a pipe		*/
#define	FPOU	(1<<3)		/* output is a pipe		*/
#define	FPAR	(1<<4)		/* don't fork, last ()ized cmd	*/
#define	FINT	(1<<5)		/* should be immune from intr's */
/* spare */
#define	FDIAG	(1<<7)		/* redirect unit 2 with unit 1	*/
#define	FANY	(1<<8)		/* output was !			*/
#define	FHERE	(1<<9)		/* input redirection is <<	*/
#define	FREDO	(1<<10)		/* reexec aft if, repeat,...	*/
#define	FNICE	(1<<11)		/* t_nice is meaningful */
#define	FNOHUP	(1<<12)		/* nohup this command */
#define	FTIME	(1<<13)		/* time this command */

/*
 * The keywords for the parser
 */
#define	ZBREAK		0
#define	ZBRKSW		1
#define	ZCASE		2
#define	ZDEFAULT	3
#define	ZELSE		4
#define	ZEND		5
#define	ZENDIF		6
#define	ZENDSW		7
#define	ZEXIT		8
#define	ZFOREACH	9
#define	ZGOTO		10
#define	ZIF		11
#define	ZLABEL		12
#define	ZLET		13
#define	ZSET		14
#define	ZSWITCH		15
#define	ZTEST		16
#define	ZTHEN		17
#define	ZWHILE		18

/*
 * Structure defining the existing while/foreach loops at this
 * source level.  Loops are implemented by seeking back in the
 * input.  For foreach (fe), the word list is attached here.
 */
extern struct	whyle {
	off_t	w_start;		/* Point to restart loop */
	off_t	w_end;			/* End of loop (0 if unknown) */
	tchar	**w_fe, **w_fe0;	/* Current/initial wordlist for fe */
	tchar	*w_fename;		/* Name for fe */
	struct	whyle *w_next;		/* Next (more outer) loop */
} *whyles;

/*
 * Variable structure
 *
 * Aliases and variables are stored in AVL balanced binary trees.
 */
extern struct	varent {
	tchar	**vec;		/* Array of words which is the value */
	tchar	*v_name;	/* Name of variable/alias */
	struct	varent *v_link[3];	/* The links, see below */
	int	v_bal;		/* Balance factor */
} shvhed, aliases;
#define	v_left		v_link[0]
#define	v_right		v_link[1]
#define	v_parent	v_link[2]

struct varent *adrof1();
#define	adrof(v)	adrof1(v, &shvhed)
#define	value(v)	value1(v, &shvhed)

/*
 * MAX_VAR_LEN - maximum variable name defined by csh man page to be 128
 */
#define	MAX_VAR_LEN	128

/*
 * MAX_VREF_LEN - maximum variable reference $name[...]
 * it can be as big as a csh word, which is 1024
 */
#define	MAX_VREF_LEN	1024


/*
 * The following are for interfacing redo substitution in
 * aliases to the lexical routines.
 */
extern struct	wordent *alhistp;	/* Argument list (first) */
extern struct	wordent *alhistt;	/* Node after last in arg list */
extern tchar	**alvec;		/* The (remnants of) alias vector */

/*
 * Filename/command name expansion variables
 */
extern short	gflag;			/* After tglob -> is globbing needed? */

/*
 * A reasonable limit on number of arguments would seem to be
 * the maximum number of characters in an arg list / 6.
 *
 * XXX:	With the new VM system, NCARGS has become enormous, making
 *	it impractical to allocate arrays with NCARGS / 6 entries on
 *	the stack.  The proper fix is to revamp code elsewhere (in
 *	sh.dol.c and sh.glob.c) to use a different technique for handling
 *	command line arguments.  In the meantime, we simply fall back
 *	on using the old value of NCARGS.
 */
#ifdef	notyet
#define	GAVSIZ	(NCARGS / 6)
#else	/* notyet */
#define	GAVSIZ	(10240 / 6)
#endif	/* notyet */

/*
 * Variables for filename expansion
 */
extern tchar	**gargv;		/* Pointer to the (stack) arglist */
extern long	gargc;			/* Number args in gargv */

/*
 * Variables for command expansion.
 */
extern tchar	**pargv;		/* Pointer to the argv list space */

/*
 * History list
 *
 * Each history list entry contains an embedded wordlist
 * from the scanner, a number for the event, and a reference count
 * to aid in discarding old entries.
 *
 * Essentially "invisible" entries are put on the history list
 * when history substitution includes modifiers, and thrown away
 * at the next discarding since their event numbers are very negative.
 */
extern struct	Hist {
	struct	wordent Hlex;
	int	Hnum;
	int	Href;
	struct	Hist *Hnext;
} Histlist;

extern struct	wordent	paraml;		/* Current lexical word list */
extern int	eventno;		/* Next events number */

extern tchar	HIST;			/* history invocation character */
extern tchar	HISTSUB;		/* auto-substitute character */

extern void	*xalloc(size_t);
extern void	*xcalloc(size_t, size_t);
extern void	*xrealloc(void *, size_t);
extern void	xfree(void *);

extern void	Putchar(tchar);
extern void	bferr(char *)	__NORETURN;
extern void	error()	__NORETURN;
extern void	exitstat(void)	__NORETURN;
extern tchar	*Dfix1(tchar *);
extern tchar	**blkcpy(tchar **, tchar **);
extern tchar	**blkspl(tchar **, tchar **);
extern char	**blkspl_(char **, char **);
extern tchar	**copyblk(tchar **);
extern tchar	**dobackp(tchar *, bool);
extern tchar	*domod(tchar *, int);
extern struct	Hist *enthist(int, struct wordent *, bool);
extern tchar	*getenv_(tchar *);
extern tchar	*getenvs_(char *);
extern tchar	*getwd_(tchar *);
extern tchar	**glob(tchar **);
extern tchar	*globone(tchar *);
extern tchar	*index_(tchar *, tchar);
extern struct biltins	*isbfunc(struct command *);
extern void	pintr(void);
extern void	pchild(int);
extern tchar	*putn(int);
extern tchar	*rindex_(tchar *, tchar);
extern tchar	**saveblk(tchar **);
extern tchar	*savestr(tchar *);
extern tchar	*strcat_(tchar *, tchar *);
extern int	strlen_(tchar *);
extern tchar	*strcpy_(tchar *, tchar *);
extern tchar	*strend(tchar *);
extern tchar	*strip(tchar *);
extern tchar	*strspl(tchar *, tchar *);
extern struct command	*syntax(struct wordent *, struct wordent *, int);
extern tchar	*value1(tchar *, struct varent *);

#define	NOSTR	((tchar *) 0)

/*
 * setname is a macro to copy the path in bname. (see sh.err.c)
 * Here we are dynamically reallocating the bname to the new length
 * to store the new path
 */
extern tchar	*bname;
#define	setname(a)	 { \
	bname = xrealloc(bname, (strlen_(a)+1) * sizeof (tchar)); \
	strcpy_(bname, a); \
	bname[strlen_(a)] = '\0'; \
}

#ifdef VFORK
extern tchar	*Vsav;
extern tchar	**Vav;
extern tchar	*Vdp;
#endif

extern tchar	**evalvec;
extern tchar	*evalp;

/* Conversion functions between char and tchar strings. */
tchar	*strtots(tchar *, char *);
char	*tstostr(char *, tchar *);

#ifndef NULL
#define	NULL	0
#endif


/*
 * Xhash is an array of HSHSIZ bits (HSHSIZ / 8 chars), which are used
 * to hash execs.  If it is allocated (havhash true), then to tell
 * whether ``name'' is (possibly) present in the i'th component
 * of the variable path, you look at the bit in xhash indexed by
 * hash(hashname("name"), i).  This is setup automatically
 * after .login is executed, and recomputed whenever ``path'' is
 * changed.
 * The two part hash function is designed to let texec() call the
 * more expensive hashname() only once and the simple hash() several
 * times (once for each path component checked).
 * Byte size is assumed to be 8.
 */
#define	HSHSIZ		(32*1024)	/* 4k bytes */
#define	HSHMASK		(HSHSIZ - 1)
#define	HSHMUL		243

/*
 * The following two arrays are used for caching.  xhash
 * is for caching path variable and xhash2 is for cdpath
 * variable.
 */

extern char xhash[HSHSIZ / 8];
extern char xhash2[HSHSIZ / 8];
#define	hash(a, b)	((a) * HSHMUL + (b) & HSHMASK)
#define	bit(h, b)	((h)[(b) >> 3] & 1 << ((b) & 7))	/* bit test */
#define	bis(h, b)	((h)[(b) >> 3] |= 1 << ((b) & 7))	/* bit set */
