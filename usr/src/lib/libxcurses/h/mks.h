/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright 2014 Garrett D'Amore <garrett@damore.org>
 */

/*
 * MKS header file.  Defines that make programming easier for us.
 * Includes MKS-specific things and posix routines.
 *
 * Copyright 1985, 1993 by Mortice Kern Systems Inc.  All rights reserved.
 *
 * $Header: /rd/h/rcs/mks.h 1.233 1995/09/28 19:45:19 mark Exp $
 */

#ifndef	__M_MKS_H__
#define	__M_MKS_H__

/*
 * This should be a feature test macro defined in the Makefile or
 * cc command line.
 */
#ifndef	MKS
#define	MKS	1
#endif

/*
 * Write function declarations as follows:
 *	extern char	*function ANSI((char *cp, int flags, NODE *np));
 * Expansion of this happens only when __STDC__ is set.
 */
#ifdef	__STDC__
#define	ANSI(x)	x
#define	_VOID	void		/* Used in VOID *malloc() */
#else
#define	const
#define	signed
#define	volatile
#define	ANSI(x)	()
#define	_VOID	char		/* Used in _VOID *malloc() */
#endif

#ifndef	STATIC
#  define	STATIC	static		/* Used for function definition */
#endif	/*STATIC*/

#ifndef	STATREF
#  ifdef	__STDC__
#    define	STATREF	static
#  else
#    define	STATREF		/* Used in local function forward declaration */
#  endif
#endif	/*STATREF*/

#define	LEXTERN	extern		/* Library external reference */
#define	LDEFN			/* Define Loadable library entry */

typedef	void	(*_sigfun_t)(int);

#include <mkslocal.h>
#include <stdio.h>
#include <unistd.h>
#include <limits.h>
#include <sys/stat.h>	/* required for m_samefile() prototype. */
#include <m_wchar.h>
#include <m_i18n.h>
#include <m_invari.h>

#if M_TFGETC || M_STTY_CC
#include <termios.h>
#endif

#ifndef	M_LIBDIR
 # error "You must define M_LIBDIR in mkslocal.h"
#endif

#ifndef M_ETCDIR
 # error "You must define M_ETCDIR in mkslocal.h"
#endif

#ifndef M_SPOOLDIR
 # error "You must define M_SPOOLDIR in mkslocal.h"
#endif

#ifndef	M_MANPATH
 # error "You must define M_MANPATH in mkslocal.h"
#endif

#if defined(I18N) && !defined(M_NLSDIR)
 # error "You must define M_NLSDIR in mkslocal.h"
#endif

#if (defined(M_I18N_MKS_FULL) || defined(M_I18N_MKS_XPG)) && !defined(I18N)
 # error I18N must be defined
#endif

/* P_tmpdir - used by tmpnam.c and tempnam.c.
 * Could be in <stdio.h>. But in case it is not ..
 */
#ifndef P_tmpdir
#  ifndef M_TMPDIR
     # error  M_TMPDIR must be defined in mkslocal.h
#  endif
#  define P_tmpdir        M_TMPDIR
#endif /* P_tmpdir */

/* L_cuserid - used by cuserid.c
 * Could be in <stdio.h>. But in case it is not ..
 */
#ifndef L_cuserid
#  ifndef M_L_CUSERID
     # error  M_L_CUSERID must be defined in mkslocal.h
#  endif
#  define L_cuserid        M_L_CUSERID
#endif /* L_cuserid */

#ifdef	M_AUDIT
LEXTERN	char	*m_audmode (int, int);
#if !defined(M_AUDITW1) || !defined(M_AUDITW2)
 # error "With M_AUDIT set, you must define M_AUDITW1 and M_AUDITW2"
#endif
#endif  /*M_AUDIT*/

#ifndef M_CS_PATH
 # error "You must define M_CS_PATH in mkslocal.h"
#endif

#ifndef M_CS_SHELL
 # error "You must define M_CS_SHELL in mkslocal.h"
#endif

#ifndef M_SH_USER_FDS
/*
 * default number of user file descriptors to be used in the shell
 * Must be >= 10, should be <= OPEN_MAX/2.
 */
#define M_SH_USER_FDS   10
#endif /*M_SH_USER_FDS*/

#ifndef M_SH_MAX_FUNCTION_EVAL_DEPTH
#define M_SH_MAX_FUNCTION_EVAL_DEPTH	100
#endif

#ifndef M_MANPAGER
#define M_MANPAGER	"more -A -s"
#endif

/* set up alert and verticalTab characters - This assumes an ANSI-C compiler */
#undef	M_ALERT
#undef	M_VTAB
#define	M_ALERT	'\a'
#define	M_VTAB	'\v'

#ifndef M_ESCAPE
#  define	M_ESCAPE '\033'		/* default to ASCII code for <ESC> */
#endif /*M_ESCAPE*/

#ifndef	SETVBUF
/* if SETVBUF not previously defined, then use default ANSI-C definition */
#  define	SETVBUF	setvbuf
#endif

#ifdef M_NULL
/* if M_NULL defined in <mkslocal.h> then want to redefine NULL */
#undef        NULL
#define       NULL    (M_NULL)
#endif /*M_NULL*/

/*
 * Useful additions to sys/stat.h.
 */
#ifndef S_IRALL
#define	S_IRALL		(S_IRUSR|S_IRGRP|S_IROTH)
#endif
#ifndef S_IWALL
#define	S_IWALL		(S_IWUSR|S_IWGRP|S_IWOTH)
#endif
#ifndef S_IXALL
#define	S_IXALL		(S_IXUSR|S_IXGRP|S_IXOTH)
#endif

#ifndef M_DEFMODE	/* Default directory creation mode */
#define	M_DEFMODE	((mode_t)S_IRALL|S_IWALL)/* Default file creation mode*/
#endif
#ifndef M_DIRMODE
#define	M_DIRMODE	((mode_t)S_IRALL|S_IWALL|S_IXALL)
#endif

#ifndef	M_FLDSEP
#define	M_FLDSEP	':'	/* UNIX field separator for passwd, PATH */
#endif

#ifndef M_TTYNAME
#define M_TTYNAME "/dev/tty"
#endif

#ifndef	M_NULLNAME
#define	M_NULLNAME "/dev/null"
#endif

#ifndef	M_FSDELIM
#define	M_FSDELIM(c)	((c)=='/')
#endif

#ifndef	M_DRDELIM
#define	M_DRDELIM(c)	(0)
#endif

#ifndef	M_DIRSTAT
#define	M_DIRSTAT(name, dp, sb)	stat((name), (sb))
#endif

#ifndef	M_HIDDEN
#define	M_HIDDEN(dirp, dp)	((dp)->d_name[0] == '.')
#endif

#ifndef M_FSMOUNT		/* for use by setmnt routine */
#define M_FSMOUNT M_ETCDIR(mtab)
#endif

#ifndef M_FSALL			/* for use by setmnt routine */
#define M_FSALL M_ETCDIR(fstab)
#endif

#ifndef	M_NLSCHARMAP		/* Default charmap file for localedef */
#define	M_NLSCHARMAP	M_NLSDIR(charmap/ISO_8859-1)
#endif

#ifndef M_POSIXPATH	/* used when I18N undefined, default posix path */
#define	M_POSIXPATH	M_NLSDIR(locale/POSIX)
#endif

#ifndef	M_ISEOV
#define	M_ISEOV(error)	0
#endif

#ifndef	M_IS_NATIVE_LOCALE
#define	M_IS_NATIVE_LOCALE(s)	(strcmp(s, "POSIX")==0 || strcmp(s, "C")==0)
#endif

#ifndef	M_FSCLOSE
#define	M_FSCLOSE(fp)
#endif

#ifndef ROOTUID		/* default superuser uid = 0 */
#define	ROOTUID	0
#endif

#ifndef ROOTGID		/* default superuser gid = 0 */
#define	ROOTGID	0
#endif

#ifndef M_GROUP_PASSWD
#define M_GROUP_PASSWD(grp)  (grp->gr_passwd)
#endif


#ifndef M_NUMSIZE
/*
 * define the expected max length of a printed number. (used in awk)
 * This should be the longest expected size for any type of number
 * ie. float, long etc.
 * This number is used to calculate the approximate
 * number of bytes needed to hold the number.
 */
#define	M_NUMSIZE	30
#endif /* M_NUMSIZE */

/*
 * VARARG[12345]: declare variadic functions.
 * Expands to either a standard C prototype or a K&R declaration.
 * For example:
 *
 * #include <stdarg.h>
 * int
 * fprintf VARARG2(FILE*, fp, char*, fmt)
 * {
 *	va_list	ap;
 *
 *	va_start(ap, fmt);
 *	cp = va_arg(ap, char*);
 *	va_end(ap);
 * }
 */
#ifndef VARARG1
#ifdef	__STDC__
#define VARARG1(type, name) (type name, ...)
#define	VARARG2(t1, n1, t2, n2) (t1 n1, t2 n2, ...)
#define	VARARG3(t1, n1, t2, n2, t3, n3) (t1 n1, t2 n2, t3 n3, ...)
#define	VARARG4(t1, n1, t2, n2, t3, n3, t4, n4) \
		(t1 n1, t2 n2, t3 n3, t4 n4, ...)
#define	VARARG5(t1, n1, t2, n2, t3, n3, t4, n4, t5, n5) \
		(t1 n1, t2 n2, t3 n3, t4 n4, t5 n5, ...)
#else
#define	VARARG1(type, name) (name, va_alist) type name; int va_alist
#define VARARG2(t1, n1, t2, n2) (n1, n2, va_alist) t1 n1; t2 n2; int va_alist
#define VARARG3(t1, n1, t2, n2, t3, n3) (n1, n2, n3, va_alist) \
		t1 n1; t2 n2; t3 n3; int va_alist
#define VARARG4(t1, n1, t2, n2, t3, n3, t4, n4) (n1, n2, n3, n4, va_alist) \
		t1 n1; t2 n2; t3 n3; t4 n4; int va_alist
#define VARARG5(t1, n1, t2, n2, t3, n3, t4, n4, t5, n5) \
		(n1, n2, n3, n4, n5, va_alist) \
		t1 n1; t2 n2; t3 n3; t4 n4; t5 n5; int va_alist
#endif
#endif


/*
 * MKS-specific library entry points.
 */
extern	char	*_cmdname;
LEXTERN	char	*basename (char *);
LEXTERN	void	crc16 (ushort *, ushort);
LEXTERN	void	crcccitt (ushort *, ushort);
LEXTERN	int	eprintf (const char *, ...);
LEXTERN	void	eputs (const char *);
LEXTERN int	execvep (const char *, char *const *, char *const *);
LEXTERN	int	isabsname (const char *);
LEXTERN	const char *m_cescape (wint_t);
LEXTERN	int	m_escapec (char **);
LEXTERN	const char *m_toprint (wint_t);
#if M_STTY_CC
LEXTERN	int	m_stty_cc (cc_t* cp, char *str);
#endif
LEXTERN	char	*m_cmdname (char *);
LEXTERN	char	*m_strmode (mode_t);
LEXTERN	char	*m_readmode (const char *);
LEXTERN	char	*m_readnum (long *, char *, char **, int);
LEXTERN	char	*m_readunum (unsigned long *, char *, char **, int);
LEXTERN	mode_t	m_getmode (mode_t);
LEXTERN	int	m_wallow (int, const char *);
LEXTERN	char	*m_pathcat (const char *, const char *);
LEXTERN	void	m_sigcleanup (void (*__handler)(int __signo) );
LEXTERN	void	m_defaction (int __signo);
LEXTERN	char	*m_strdup (const char *s);
LEXTERN int     m_stricmp (const char *, const char *);
LEXTERN	char	*m_self (int, char *, char *);
LEXTERN	int	m_grouplist (char *user, gid_t *gidlist[]);
LEXTERN	int	m_setgroups (int gidsetsize, gid_t grouplist[]);
LEXTERN	uint	m_binsrch (uint n, int (*cmp)(uint i));
LEXTERN	char	*m_dirname (const char*);
LEXTERN	char	*m_confstr (int);

LEXTERN	void	m_crcposix (ulong *, const uchar *, size_t);
LEXTERN	int	m_setprio (int, unsigned int, int);
LEXTERN	int	m_getprio (int, unsigned int);
LEXTERN int	m_incrnice (int, unsigned int, int);
LEXTERN	char	*m_devname (dev_t);
LEXTERN char	*m_mountdir (const char *);
LEXTERN int	m_absname(char *, char *, char *, size_t);
LEXTERN int	m_samefile(char *, struct stat *, char *, struct stat *);

/* __m_system() : alternate interface into system() */
LEXTERN int	__m_system (const char *, const char *, const char *);


/* conversion routines - between single byte and UNICODE (wide) strings.
 * These return a pointer to malloc'd memory.
 * It is the caller's responsiblity to free() it, if necessary
 * These are for use primarily on NT
 */
extern char *m_unicodetosb(const wchar_t*);
extern wchar_t *m_sbtounicode(const char*);


/*
 * things that could go into an "m_stdio.h"
 */

/* m_unlink() : alternate unlink() for use with vendor-provided
 * libraries that do not have a satisfactory unlink() */
#ifndef M_UNLINK
#define m_unlink(s)	unlink(s)
#endif

/* __m_popen() : alternate interface into popen() */
LEXTERN FILE	*__m_popen (const char *, const char *,
			    const char *, const char *);
LEXTERN FILE	*__m_popenvp (const char *mode, const char *shell,
			      char const * const *args);

#if M_TFGETC
LEXTERN int	m_tfgetc (FILE *fp, struct termios *tp);
#else
#define		m_tfgetc(fp,tp)	fgetc(fp)
#endif

/* m_fsopen() - special routine for curses */
LEXTERN	FILE	*m_fsopen (char *, size_t, const char *, FILE *);

#ifndef M_FFLUSH_NOT_POSIX_1
# define	m_fflush fflush
#else
  LEXTERN	int	m_fflush (FILE *);
#endif

/* m_fgets return values */
enum {
	M_FGETS_OK,	/* Normal return */
	M_FGETS_EOF,	/*
			 * Regular EOF (same as NULL from fgets).
			 * Buffer is *untouched*.
			 */
	M_FGETS_SHORT,	/*
			 * Short input (buf[strlen(buf)-1] != '\n')
			 * This is a trailing line, without a newline at the
			 * end of the file.  The buffer is valid, ending in
			 * a \0, with no newline.  The case of terminal input
			 * ending with an EOF in the middle of the line will
			 * restart -- typing two EOF's will result in this
			 * case.
			 */
	M_FGETS_LONG,	/*
			 * Line too long: newline not found within len bytes
			 * (buf[len-1] != '\n').
			 * At this point, while((c=getc(fp)) != '\n') ...
			 * is a valid method to get the rest of the line.
			 */
	M_FGETS_BINARY,	/*
			 * Input contained an invalid character (e.g. \0)
			 * Buffer contents *undefined*.
			 */
	M_FGETS_ERROR	/*
			 * A system call returned an error, errno is set.
			 * Buffer contents *undefined*.
			 */
};
LEXTERN int	m_fgets (char *, size_t, FILE *);

/*
 * end of things that could go into an "m_stdio.h"
 */

LEXTERN	int	m_winsize (int *, int *);
LEXTERN	char	*m_cuserid ();

/* m_ctype: generic character classification */
typedef	int	m_ctype_t;		/* ctype property */
LEXTERN	m_ctype_t	m_ctype (const char *property);
LEXTERN	int	m_isctype (int c, m_ctype_t ctype);
LEXTERN	char	*m_readdate (char *, time_t *, int);

#ifndef M_READDATE_SYSV
#define M_READDATE_SYSV 0
#endif
#ifndef M_READDATE_BSD
#define M_READDATE_BSD  1
#endif

#ifdef M_MALLOC
  LEXTERN _VOID *m_malloc (size_t size);
#else
# define m_malloc(size)	malloc(size)
#endif /*M_MALLOC*/

#ifdef M_REALLOC
  LEXTERN _VOID *m_realloc (void* ptr, size_t size);
#else
# define m_realloc	realloc
#endif /*M_MALLOC*/

#ifdef NAME_MAX
#define		m_namemax(path) NAME_MAX
#else
LEXTERN int	m_namemax (char *path);
#endif /*NAME_MAX*/

#ifdef PATH_MAX
#define		m_pathmax(path)	PATH_MAX
#else
LEXTERN	int	m_pathmax (char *path);
#endif /* PATH_MAX */

#ifdef M_DEVBIN
 LEXTERN int     m_devbin (int fd);	    /* begin raw I/O transfer */
 LEXTERN void    m_devstd (int fd, int mode); /* end raw I/O transfer */
#else
# define	m_devbin(fd)	0
# define	m_devstd(fd, mode)
#endif /*M_DEVBIN*/

#ifndef	m_setbinary
#define	m_setbinary(fp)
#endif /*m_setbinary*/

#ifndef M_PRIO_PROCESS
#define M_PRIO_PROCESS	0
#endif
#ifndef M_PRIO_PGRP
#define M_PRIO_PGRP	1
#endif
#ifndef M_PRIO_USER
#define M_PRIO_USER	2
#endif

/* m_wallow type values */
#ifndef MWA_NO
#define	MWA_NO	0		/* Deny talk, write */
#endif
#ifndef MWA_YES
#define	MWA_YES	1		/* Allow talk, write */
#endif
#ifndef MWA_TEST
#define	MWA_TEST 2		/* Test for YES/NO */
#endif

/* Interface for compression (m_cm_*) and decompression (m_dc_*) */
LEXTERN int	m_cm_open (int (*wrtfn) (const uchar *,int), int);
LEXTERN	int	m_cm_write (const uchar *, int);
LEXTERN	int	m_cm_close (int);
LEXTERN char	*m_cm_error (void);
LEXTERN int	m_dc_open (ssize_t (*rdfn)(uchar *, int));
LEXTERN	ssize_t	m_dc_read (uchar *, size_t);
LEXTERN	int	m_dc_close (int);
LEXTERN char	*m_dc_error (void);

LEXTERN	int	m_mkpardir (char *);

/*
 * Some UNIX routines that aren't in SVID
 */
LEXTERN	void	cfree (void *, size_t, size_t);
LEXTERN void	swaw (const short *, short *, int);

/* Some dos routines we sometimes want from posix utilities */
LEXTERN	void	_uttoof (time_t, ushort *, ushort *);
LEXTERN	time_t	_oftout (ushort, ushort);


#ifndef	M_SETENV
#define	m_setenv()	environ
#endif

#ifdef M_NON_STATIC_GETENV
#define __m_getenv getenv
#else
LEXTERN	char	*__m_getenv(char const *);  /* Library safe getenv() */
#endif

#ifndef M_CRON_MAILER
/*
 * Default case: assume only POSIX.2 mailx is available.
 * Must be careful when cron sends output to mailx.
 * We must ensure that lines with leading '~' are escaped
 * so mailx doesn't interpret these lines
 * This string MUST include a trailing space character.
 */
#define M_CRON_MAILER	"sed -e s/^~/~~/ | mailx "
#endif

/*
 * m_cp() - copy a file in an O/S specific way.  See m_cp.3
 * for details
 */

/* Return codes */
#define M_CP_ERR	-1
#define M_CP_NOOP	-2

/* processing flags */
#define M_CP_PRESERVE	1

/*
 * MKS MEMORY MANIPULATIONS:
 *      Specific to MKS and non-portable.
 */
LEXTERN _VOID   *membtst (const char *s, size_t m, int c);

#ifdef M_LDATA
#define memLchr         memchr
#define memSLccpy       memccpy
#define memLbtst        membtst
#define memLset         memset
#define memLLcpy        memcpy
#define memLLrlcpy      memrlcpy
#define memLLcmp        memcmp
#else
/* for machines with small data models (e.g PC's - DOS, OS2) */
LEXTERN void    far*memLchr (const void far*s, int c, size_t n);
LEXTERN void    *memSLccpy (_VOID *s1, const _VOID far*s2, int, size_t n);
LEXTERN void    far*memLbtst (const char far*s, size_t m, int n);
LEXTERN void    far*memLset (void far*s, int c, size_t n);
LEXTERN void    far*memLsetl (void far*p, int value, long count);
LEXTERN void    far*memLLcpy (void far*s1, const void far*s2, size_t n);
LEXTERN void    far*memLLrlcpy (void far*s1, const void far*s2, size_t);
LEXTERN int     memLLcmp (const void far *s1,const void far *s2,size_t n);
#endif /* M_LDATA */


/* mks error handling routines */
#include <stdarg.h>
LEXTERN	void	m_error (const char * fmt, ...);
LEXTERN	void	m_errorexit (const char *fmt, va_list args);
LEXTERN	void	m_errorret (const char *fmt, va_list args);
LEXTERN	void	m_errorjmp (const char *fmt, va_list args);
LEXTERN	void	m_errornull (const char *fmt, va_list args);
LEXTERN	void	(*m_errorfn) (const char *fmt, va_list args);
#define	M_ERROR(fn)	void (*m_errorfn) (const char *fmt, va_list args) = fn

/*
 * The filesystem type and attribute routine
 */
#ifndef	M_FSTYPE
#define	m_fstype(path)	M_FSTYPE_POSIX
#endif

/* File system types */
#define	M_FSTYPE_MASK	0x1
#define	M_FSTYPE_POSIX	0
#define	M_FSTYPE_FAT	1

/* File system attributes */
#define	M_FSATTR_NO_LEADING_DOT	0x08
#define	M_FSATTR_ONE_DOT	0x10
#define	M_FSATTR_SHORT_FILENAME	0x20
#define	M_FSATTR_SHORT_EXT	0x40
#define	M_FSATTR_LOWER_CASE	0x80

/* This one should be ifdef'ed on something else */
#ifndef	M_FNMATCH_DUALCASE
#define	m_get_original_filename_case(path)	/* nil */
#endif

/*
 * m_tempname() generates a filename for a temp file using "code"
 * in the name.
 */
#ifndef M_TEMPNAME
#define m_tempname(code)	tempnam(__m_getenv("TMPDIR"), (code))
#else
char *m_tempname(char const *code);
#endif

/*
 * __m_getopt() alternate "stateless" entry into getopt().
 */

struct getopt_state {
        char    *optarg;                /* Argument */
        int     optind;                 /* Index into argv */
        int     opterr;                 /* Print error message */
        int     optopt;                 /* Invalid option */
        int     index;                  /* argv[optind] index */
#ifdef  M_I18N_MB
        mbstate_t st;                   /* State of argv[optind][index] */
#endif
};

int __m_getopt(int argc, char * const *argv, char const *optstring,
               struct getopt_state *state);


#ifdef M_MKSEXTRA_H
/* Any overrides etcetera for a particular system can go in here */
#include <mksextra.h>
#endif /* M_MKSEXTRA_H */

#endif	/* __M_MKS_H__ */
