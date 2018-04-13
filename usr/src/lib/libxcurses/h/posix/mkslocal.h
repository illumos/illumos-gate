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
 * Copyright 1996-2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * <mkslocal.h>, POSIX Version - local <mks.h> requirements
 *
 * This generic POSIX version should be used as a template for creation of
 * any new <mkslocal.h> file.
 *
 * Copyright 1985, 1993 by Mortice Kern Systems Inc.  All rights reserved.
 *
 * $Header: /rd/h/posix/rcs/mkslocal.h 1.168 1995/06/21 20:33:29 jeffhe Exp mark $
 */

#if 0	/* not required for POSIX systems; here for documentation only */

#include <sys/types.h>

#ifndef VERSION
#define VERSION "MKS InterOpen I/XCU 4.3 SB"     /* Used for version# */
#endif


#define name-of-system 1	/* for identifying system (i.e. BSD, SYSV,
				 * DOS, etc)
				 */

#ifndef __STDC__
/* For non-ANSI C compilers, we need to define
 * the character encoding for some special control characters
 * If these are NOT defined here, then <mks.h> will use
 * the ASCII encodings as the default values.
 *
 * For ANSI C compilers, there are special C character constants supported
 * by the compiler.  <mks.h> will properly handle this.
 *
 */
#define     M_ALERT '\7'            /* ASCII encoding for \a */
#define     M_VTAB  '\13'           /* ASCII encoding for <VT> */
#endif /* __STDC__ */


/* M_ESCAPE - the system default character encoding for the <ESC> character
 * If this is not defined here, then <mks.h> will
 * default to use the ASCII encodings.
 */
#define     M_ESCAPE '\033'         /* ASCII default code for <ESC> */

#define	SETVBUF(fp,bp,f,s) setvbuf(fp,f,bp,s)	/* for some SysV and Xenix 
						 * systems, which have unusual
						 * calling sequences 
						 */

#define	M_DEFAULT_PATH	"/bin:/usr/bin"
				/* Default PATH. Not used yet.
				 */


#define M_CS_PATH	"/bin:/usr/bin"
				/* This string is a list of directories where
				 * all the POSIX.2 utilities can be found.
				 * Returned by constr(_CS_PATH, buf, len).
				 * The shell uses this search path in
				 *	command -p util ...
				 * The list plus "." is used by login
				 * and sh as the default $PATH.
				 */

#define M_CS_SHELL	"/bin/sh"
				/* The pathname of the shell utility.
				 * Returned by confstr(_CS_SHELL, buf, len).
				 * This string defines the path to the
				 * the POSIX.2 command language interpreter,
				 * so we do not have to search M_CS_PATH.
				 */

#define M_CS_BINDIR     "/bin"
#define M_CS_LIBDIR     "/lib"
#define M_CS_TMPDIR     "/tmp"
#define M_CS_ETCDIR     "/etc"
#define M_CS_SPOOLDIR   "/spool"
#define M_CS_NLSDIR     "/lib/nls"
#define M_CS_MANPATH    "/man"
				/* the M_CS_* strings are used by MKS's version
				 * of the POSIX.2 confstr() API.
				 * The M_CS_*DIR strings point to system
				 * default directories.
				 * The M_CS_*PATH strings may be a list of
				 * colon seperated system directories
				 */


#define	M_BINDIR(path)	"/bin/" # path
				/* M_BINDIR - directory where the POSIX.2
				 * utilities live. (e.g ed, ...)
				 */

#define	M_LIBDIR(path)	M_CS_LIBDIR # path
				/* Define to convert a pathname relative to the
				 * library directory to an absolute pathname.
				 * Traditional systems would use "/usr/lib/"
				 * <mks.h> should always be overridden.
				 *
				 * Used by bc, cron
				 */

#define	M_ETCDIR(path)	M_CS_ETCDIR # path
				/* Define to convert a pathname relative to the
				 * etcetera directory to an absolute pathname.
				 * Traditional systems would use "/etc/"
				 * <mks.h> should always be overridden.
				 * Used by file, vi, sh, ccg, lex, awk
				 */

#define	M_SPOOLDIR(path) M_CS_SPOOLDIR # path
				/* Define to convert a pathname relative to the
				 * spool directory to an absolute pathname.
				 * Traditional systems would use "/usr/spool/"
				 * <mks.h> should always be overridden.
				 */

#define	M_NLSDIR(path)	"M_CS_NLSDIR # path
				/* Directory name used by the locale program
				 * to locate specific compiled locales.
				 * Should always be set, if using the mks
				 * supplied i18n package.  Possible location
				 * might be /usr/lib/nls.
				 */
#define	M_TMPDIR	M_CS_TMPDIR	/* Temporary file storage directory.
				 * Used for P_tmpdir in case its not defined
				 * in <stdio.h>
				 */

#define	M_MANPATH	M_CS_MANPATH
				/* a list of colon seperated pathnames
				 * which the man utility uses
				 * as the default search path
				 * (e.g when MANPATH environment variable
				 * not initialized.
				 */



#define M_SYSTEM_HELP "help.cmd"/* help command only: If the help command
				 * doesn't know about a given request for help
				 * then pass the help request on to another
				 * help program.  Note that if the name for
				 * the other is also help, there must be
				 * some form of name qualification.  No attempt
				 * will be made if this is not defined.
				 * <mks.h> will default to undefined
				 */

#define DEF_NLSPATH     "/lib/nls/locale/%L/%N.cat"
				/* define the default path that should be used
				 * by MKS's implementation of catopen() when
				 * trying to open the message cataloges
				 * If you are not using MKS's implementation
				 * of catopen(), then this definition
				 * is not required.
				 */

#define M_ENDPWENT	1	/* set to 1 if system provides a endpwent()
				 * routine.
				 * Normally, systems provide this routine
				 * only if getpw*() routines allocate
				 * some resources which a user may want
				 * to deallocate when finished accessing the
				 * user getpw*() routines
				 * This is the case for conventional
				 * UNIX systems 
				 */

#undef M_SHBLTIN_ANYCMD 	/* set to 1 if you want ability to create an
				 * executable with any name, using shbltin.c.
				 * [ shbltin.c was created to satisfy 
				 *   POSIX.2-1992 Section 2.3 "regular built-in
				 *   utilities". ]
				 * If this is undefined, then the only valid
				 * command names are those listed in an
				 * internal table in shbltin.c which are
				 * are checked at run-time against 
				 * basename(argv[0]).
				 * If the command name is not listed in the
				 * table, then program will exit
				 * with an error message. 
				 *
				 * Normally, this is undefined, since
				 * it becomes too easy to get into an infinite
				 * loop if you name this executable to a 
				 * non-bltin command.
				 */

/* shbltin:
 *   shbltin.c is configurable but its configuration is done
 *   in mkslocal.mk.
 *   See M_SHBLTIN_ULIMIT
 *   See M_SHBLTIN_HASH
 *   See M_SHBLTIN_TYPE
 *   See M_SHBLTIN_XPG4
 */

#undef	M_FNMATCH_DUALCASE	/* fnmatch(): If this #define is set, then
				 * fnmatch will ignore case in file name
				 * matches *unless* the environment variable
				 * at runtime has DUALCASE set.
				 * For a conforming system, this should *not*
				 * be defined. <mks.h> will default to 
				 * undefined.
				 */

#undef	M_SMALLSTACK		/* Define this to 1 on systems that have
				 * a fixed size stack compiled into programs,
				 * and a small (probably 64k) data segment.
				 */

#undef M_NULL			/* define this if you want to change the
				 * system default defintion of NULL.
				 * (e.g #define M_NULL  ((void*)0)
				 */
#define M_MALLOC	1	/* Define M_MALLOC if your system has either
				 * of the following two problems:
				 * 1) ANSI does not specify returning a valid
				 *    errno if malloc() returns NULL.
				 *    But, MKS code assumes a valid errno
				 *    as is returned in most UNIX systems. 
				 * 2) ANSI says it is implementation defined
				 *    whether or not malloc(0) returns a valid
				 *    pointer.
				 *    MKS code assumes that a valid pointer
				 *    is returned.
				 *
				 * Defining M_MALLOC requires an m_malloc()
				 * function, which MKS provides.
				 * Undefining M_MALLOC causes m_malloc() to be
				 * renamed to malloc().  (See mks.h)
				 */

#define M_REALLOC	1	/* Defining M_REALLOC will cause
				 * m_realloc() to be used in place of the 
				 * systems realloc().
				 * This is necessary:
				 *  a) if you do not have an ANSI realloc()
				 *  b) if the system realloc()
				 *     has the following problem:
				 *     - ANSI does not specify returning a valid
				 *       errno if malloc() returns NULL.
				 *       But, MKS code assumes a valid errno
				 *       as is returned in most UNIX systems. 
				 *
				 * Defining M_REALLOC requires an m_realloc()
				 * function, which MKS provides.
				 * Undefining M_MALLOC causes m_malloc() to be
				 * renamed to malloc().  (See mks.h)
				 */
#ifdef M_REALLOC
#define M_WANT_ANSI_REALLOC  1	/* Use #undef M_WANT_ANSI_REALLOC 
				 * if your system has an ANSI realloc() function
				 *
				 * Defining M_WANT_ANSI_REALLOC can only be
				 * done if M_REALLOC is also defined.
				 * Use M_WANT_ANSI_REALLOC if your system
				 * does not support either of the following
				 * 2 features:
				 *
				 * 1) ANSI says that if the ptr passed to 
				 *    realloc is NULL, then it will act like
				 *    a malloc() 
				 * 2) ANSI says that if the ptr passed is 
				 *    not NULL and the size is 0, then the
				 *    object that ptr points to is freed.
				 *
				 * Defining M_REALLOC requires an m_realloc()
				 * function, which MKS provides.
				 * Undefining M_MALLOC causes m_realloc() to be
				 * renamed to realloc().  (See mks.h)
				 */
#endif /* M_REALLOC */


#define	M_MAXMALLOC	64	/* Define the maximum number of kilobytes (K)
				 * that can be requested from malloc().
				 * This is intended for segmented systems
				 * where max allocation by malloc() is smaller
				 * than the total mallocable memory;
				 * some programs will assume they can do
				 * multiple mallocs of this # of K to allocate
				 * a large data structure.
				 * By default, this is not defined; malloc can
				 * allocate up to MAX_INT bytes.
				 */

#define	__LDATA__	1	/* DEPRECATED */
#define	M_LDATA		1	/* For most modern systems this will be set.
				 * Some systems (e.g DOS) have a large and
				 * small program model.
				 * Thus, various programs have two buffer sizes
				 * built into them -- large and small.  The
				 * small buffer size is normally sub-optimal,
				 * but permits the data to fit in the small
				 * buffer (say 64k)
				 */

#ifndef PATH_MAX
#define	M_PATH_MAX	2048	/* For systems where pathconf(file,_PC_PATH_MAX)
				 * can return -1 and NOT set errno 
				 * (which means that PATH_MAX for 'file' 
				 *  is unlimited),
				 * we provide a suitable LARGE value
				 * that can be returned by m_pathmax().
				 * This number should be sufficiently large
				 * to handle most (if not all) reasonable
				 * pathnames for a particular system.
				 * m_pathmax() is usually used to determine
				 * how large a buffer must be allocated to store
				 * pathnames.
				 */
#endif /* PATH_MAX */

#define	M_EXPTIME	1	/* For systems whose files maintain an
				 * additional time field, generally expiry time.
				 * The stat structure must have a member
				 * st_etime and the utimbuf a member exptime.
				 * <mks.h> will default to undefined.
				 */

#undef ROOTGID
#undef ROOTUID			/* Some systems may use a different user id
				 * to indicate the superuser.
				 * If it is not defined here, then <mks.h>
				 * will define it to be 0 which is the 
				 * value used in conventional UNIX.
				 */

#define	M_AUDIT		1	/* For systems which maintain file auditing
				 * information.  M_AUDITW1 and M_AUDITW2 must
				 * be defined, and return one or two audit
				 * words from the stat structure.  m_audmode
				 * must be defined in the local libraries
				 * to convert from these two words, to ls style
				 * letter information.  <mks.h> will default to
				 * undefined.
				 */
#define	M_AUDITW1(sbp)	?	/* Fetch first audit word from stat pointer,
				 * if M_AUDIT defined.
				 */
#define	M_AUDITW2(sbp)	?	/* Fetch second audit word from stat pointer,
				 * if M_AUDIT defined.  Define as `0' if no
				 * second audit word.
				 */
				
#undef M_DEVIO			/* use #define	M_DEVIO	1  on systems that
				 * requires special interfaces
				 * to perform I/O on devices.
				 * (e.g cannot use the standard open,read,write
				 *      interface)
				 * See <devio.h> for details on this
				 * special interface.
				 * Default is undefined; no special device i/o
				 * interface is used.
				 */

#undef	M_DEVBIN		/* Use #define M_DEVBIN 1 
				 * on systems that have devices that do not
				 * allow raw I/O be written directly
				 * to the device.
				 * These systems tend to process the data
				 * before actually writing the data to the
				 * device.
				 * (e.g DOS disk devices do some character
				 *      translations. This routine is intended
				 *      to disable this behaviour.)
				 * The definition of m_devbin() and m_devstd()
				 * is done in <mks.h>.
				 * If this is defined, then <mks.h> defines
				 * the prototypes m_devbin() and m_devstd()
				 * Otherwise it undefines m_devstd()
				 * and set m_devbin to return a dummy value of 0
				 * 
				 * MKS has selected some utilities
				 * to recognize this fact and to handle
				 * these I/O cases specially.
				 * Such utilities include cp, mv, and pax
				 */

#define	M_SETENV	1	/* Some systems require special preparation */
char	**m_setenv ANSI((void));/* for use of the environment variables via
				 * environ; m_setenv call makes sure that
				 * environ is set up.  <mks.h> will default to
				 * m_setenv returning environ.  M_SETENV
				 * must be set to indicate to mks.h that a C
				 * function has been defined.
				 */

#define	m_setbinary(fp)		/* On systems supporting text and binary files,
				 * (i.e. "rb" and "wb" to fopen work different
				 * from "r" and "w"), there is a requirement
				 * to be able to set stdin/stdout to binary
				 * mode.  m_setbinary on such systems should
				 * perform this action.  On other systems, this
				 * macro should define itself out of existence.
				 * Normally this macro would be defined in
				 * <stdio.h>.  <mks.h> defaults to defining
				 * it out of existence, if not defined.
				 */

#define	M_TFGETC	0	/* Do we have POSIX.1-deficient termios?
				 * On POSIX.1 or SVID compliant systems,
				 * define it as 0 and mks.h will
				 * map m_tfgetc(fp,tp) to fgetc(fp).
				 * On deficient systems (e.g. BSD),
				 * define it as 1 and ensure a m_tfgetc()
				 * routine is provided.
				 */

#define M_STTY_CC       1       /* The stty command control-character setting
				 * is very system specific.  The default code
				 * in stty.c works only for the ascii character
				 * set.  <mks.h> will default to M_STTY_CC
				 * being undefined, resulting using the default
				 * code. arg is the string passed to stty; *cp
				 * should have the resulting value stored in it.
				 * A 0 return value indicates success; other-
				 * wise an error message will be printed.
				 */

#define	M_LOGIN_GETTY	1	/* Use #define M_LOGIN_GETTY 1
				 * on systems that do not provide a
				 * getty utility.
				 * This is for use in the login utility to
				 * display a banner that would conventionally
				 * be displayed by the UNIX getty utility
				 * that would have run before login.
				 * If M_LOGIN_GETTY is not defined here,
				 * then login will not print this banner info.
				 */

#define M_MANPAGER	"more -A -s"
				/* default command that is executed
				 * by the man utility to display a man page
				 * when the user's PAGER environment
				 * variable is not set.
				 */

#define M_TTYGROUP	"tty"	/* Name of the group that owns tty's.
				 * If this isn't defined, then <mks.h>
				 * will leave it undefined.
				 * This is related to the MKS default
				 * access enforcment policy for use
				 * by m_wallow(), mesg, talk, and write.
				 * If undefined, it is assumed that no security
				 * is available on tty's.
				 */ 

#undef M_CONSOLE		/* This is defined to indicate that a pc
				 * style console is used instead of a tty.
				 * This allows for the elimination of
				 * unnecessary calls to m_wallow() from 
				 * pc compiles.
				 * Default is undef; m_wallow calls are made.
				 */

#define M_LKSUFFIX	".lock"	/* Suffix for lock file used by mailx and
				 * tsmail (name of mailbox to be locked
				 * is the prefix).  ".lock" is typically
				 * used by UNIX sendmail.  This should be
				 * set to the same suffix as used by other
				 * mail agents on the machine.
				 */

#define	M_LS_OPT_D	1	/* ls command: Support -D (list only dirs)
				 * This option is non-standard on any unix
				 * system, so is only an option.
				 * Default is not defined, so ls doesn't support
				 * this option.
				 */

#define	M_LOGGER_OPTIONS	(log_pid|log_user)
				/* Set up default options for the logger utility
				 * The logger utility allows the log lines to
				 * be prefixed by pid, ppid, a timestamp,
				 * and/or the login username.
				 * If an implementation wishes to
				 * force some of these prefixes then it
				 * should OR together one or more of the
				 * appropriate constants:
				 *   log_pid
				 *   log_ppid
				 *   log_timestamp
				 *   log_user
				 * If M_LOGGER_OPTIONS is not defined here then
				 * logger.c uses the default:
				 *   (log_pid|log_user).
				 */

#define	M_LOGGER_CONSOLE "/dev/console"
				/* logger command: If you wish to use the
				 * default, trivial, logging routines, then
				 * define M_LOGGER_CONSOLE to the name of
				 * a device or file, to which logger may
				 * append the log messages.
				 * If this variable is *not* defined, then
				 * the local system must have m_logger, and
				 * m_logger_close defined and retrieve
				 * either by the make process, or in the
				 * libraries.  See the documentation for
				 * the calling sequence of these routines.
				 */

#undef M_COMPRESSION_AVAIL	/* 
				 * Not defining M_COMPRESSION_AVAIL indicates
				 * that the compression libary code is not
				 * available.
				 * Changing the #undef to #define should only
				 * be done if the code in libc/mks/m_comp.c
				 * is implemented.
				 *
				 * Because UNiSYS holds the patent on the
				 * adaptive Lempel-Ziv compression algorithm,
				 * MKS may not provide the compression
				 * source code (see libc/mks/m_comp.c)
				 * in which case the -z option in pax/tar/cpio
				 * must be disabled.
				 * If the compression algorithm is implemented
				 * in m_comp.c, then this macro can be defined.
				 */

#define	M_TAR_TAPENAME	"/dev/mt/%c%c"
				/* Set up default file name that the pax/tar
				 * utilities will use (e.g when 'f' option
				 * not specified)
				 * This file name is usually a tape device name
				 * Two %c's field specifiers can be included
				 * in the file name;
				 * the first is replaced with tapenumber,
				 * the 2nd with tape density 
				 *    (l, m, or h, for low, medium or high).
				 * If you either don't have multiple
				 * tapes, or densities, you can leave off extra
				 * %c's.
				 *
				 * If this is not defined then pax/tar.h
				 * will use "/dev/mt/%c%c"
				 */

#undef M_GUNZIP			/* When defined, m_dc_open() will test for
				 * gzip-compressed files, and call the
				 * appropriate routines to uncompress them,
				 * in addition the normal operation of testing
				 * for compress-compressed files.
				 */

#undef M_VI_NO_RECOVER		/* vi command: when defined will not include the
				 * :preserve and :recover commands.
				 */

#define	M_VI_COPYRIGHT	1	/* vi command: When sold as a separate product,
				 * vi prints a copyright notice.  This flag
				 * causes the notice to be printed. Default is
				 * not defined, which causes vi to NOT print
				 * the copyright notice.
				 */

#define M_MAKEOS	"OS:=POSIX"	/*for $(OS) in "make" */
				/* make command: builtin rule which defines the
				 * $(OS) variable expansion.
				 * Default is not defined, which is an error.
				 */

#undef M_MAKE_EXIT_DIRECT	/* If this is defined, make will call exit()
				 * directly when it receives a signal, rather
				 * than clearing the handler and re-sending
				 * itself the signal. For 1003.2 conformance,
				 * this must not be defined.
				 */

#define M_MAKEFILES     ".MAKEFILES:makefile Makefile"
				/* rule that make uses when trying to locate
				 * the default makefile to run
				 */

#define M_MAKEDIRSEPSTR "/"	/* Default string of characters that make
				 * will look at and use when manipulating
				 * path names.
				 */
#define M_GETSWITCHAR   '-'	/* Default character used to indicate an
				 * option to a command. Note - on some
				 * systems, this may actually be a system-call
				 * instead of a constant. As a consequence
				 * this define should not be used as a
				 * global initializer.
				 */
#define M_MAKE_BUFFER_SIZE 8192 /* max line length handled by make parser */
#define M_MAKE_STRING_SIZE 8192	/* make macro expansion max string size */
#define M_MAKE_PATSUB_SIZE 1024	/* make pattern/substitution max string size */

#define	M_FLDSEP	':'	/* The field separator character used in 
				 * the PATH environment variable (for sh),
				 * and for the entries in the group database
				 * (e.g /etc/group) and the user database
				 * (e.g /etc/passwd) files.
				 * If this is not defined here, then <mks.h>
			 	 * will default to ':'.
				 */

#undef M_TEXT_CR		/* Some systems use <cr><lf> pairs rather than
				 * simple <lf>s to delimit text lines.  On
				 * these systems, this should be defined.
				 * Default is undefined.
				 */

#define	M_FPPSLOW 1		/* This should be defined for systems whose
				 * floating point operations
				 * are slower than integral operations.
				 * If this in undefined, the assumption will
				 * be fast floating point.
				 */

#define __CLK_TCK 100		/* units for times() */

#undef	M_NOOWNER		/* for systems which don't have user/group
				 * owners on files. 
				 * <mks.h> will default to undefined.
				 * Used by pax
				 */

#define	M_FSDELIM(ch) ((ch)=='/') /* for systems who have special characters to
				 * delimit file systems, this returns true if
				 * the given character is a file system
				 * delimiter; <mks.h> will default to '/'.
				 * ispathdelim() is a deprecated form.
				 */

#define	M_DRDELIM(ch)	(0)	/* for systems whose names parse with a leading
				 * drive separated by a drive delimiter char,
				 * (e.g. ':' on dos systems); posix systems
				 * simply return false, i.e. no, character
				 * is not a drive delimiter.
				 * <mks.h> will default to (0).
				 */

#define	M_DIRSTAT(pathname, dirp, statbuf)	stat((pathname), (statbuf))
				/* prototype definition:
				 * int M_DIRSTAT(char*	pathname, 
				 *               DIR*  	dirp,
				 *               struct stat*	statbuf);
				 * On POSIX and conventional UNIX systems
				 * this macro is defined as:
				 *    stat((pathname), (statbuf))
				/* On systems where the file information is
				 * maintained in the directory (not the inode)
				 * the DIR structure may contain this info,
				 * in which case the information can be returned
				 * without doing a stat(). This may be a
				 * performance enhancement.
				 * dirp is the DIR * pointer returned by opendir
				 */

#define	M_HIDDEN(dirp, dp)	((dp)->d_name[0] == '.')
				/* prototype definition:
				 *  int M_HIDDEN(DIR* dirp, struct* dirent)
				 *
				 * Some utilities (e.g ls) recognize certain
				 * filenames as being "hidden" files.
				 * In conventional UNIX systems this has been
				 * the '.' prefix.
				 * On other systems, with other conventions
				 * the M_HIDDEN macro should be suitably
				 * modified
				 *
				 * If this is not defined, then
				 * <mks.h> defaults to traditional unix, a 
				 * leading `.'.
				 */

#undef M_NO_FORK		/* Define for non-POSIX systems that do not
				 * have a true fork(), and must use some sort
				 * of spawn call (for example, DOS).
				 * By default undefined; there is a fork.
				 */

#undef	M_SYNC_FORK		/* fork() is synchronous (DOS). (sh)
				 * Default is undefined; posix.1 fork provided.
				 */

#undef	M_FEXEC			/* Use fexec[ve] when possible.
				 * Only define if fexec is faster than fork/exec
				 * (sh, ...)
				 * By default undefined; fork is reasonable
				 * performance.
				 */

#undef	M_EXEC_FILETYPE		/* File name types for executables.
				 * For example, .exe and .ksh.
				 * For the shell, you need to define shexecve()
				 * and testpath() in sh$(ORG).c.
				 * By default undefined; no file name types.
				 */

#undef	M_NO_IDS		/* POSIX uids and gids.
				 * (sh: set -p; umask; test -[rwx])
				 */

#undef	M_NO_ST_INO		/* stat's st_ino is meaningless. (pax; test -ef)
				 */

#undef M_SVFS_INO		/* statvfs() provides valid f_ffree and
				 * f_files fields which describe the number
				 * of free file slots and the total number
				 * of file slots in a filesystem.  Used
				 * by df.
				 */

#undef	M_NO_PIPE		/* no pipe(), use temp files. (sh, popen)
				 * Default is undefined; posix.1 pipes provided.
				 */

#undef	M_LOCKING_OPEN		/* Open'd files are locked, (DOS, OS2)
				 * and cannot be unlink'd or rename'd.
				 */

#undef	M_USE_SIGNAL		/* Has no sigaction, use signal (SVR3).
				 * (sh, ...)
				 */

#undef	M_NO_IO_EINTR		/* Tty I/O does not return EINTR
				 * when SIGINT signal handler returns.
				 * (sh, ?)
				 */

#undef	M_TTY_ICANON		/* Tty is always in ICANON mode.
				 * (sh,ex,mailx)
				 */

#define	M_TTYNAME "/dev/tty"	/* Device to open to access the controlling
				 * tty; posix.2 does require this to be /dev/tty
				 * but dos for example calls it /dev/con.
				 * <mks.h> will default to /dev/tty.
				 */

#define	M_NULLNAME "/dev/null"	/* Device to open for the null device as defined
				 * by posix.2.  It is required to be named
				 * /dev/null, but dos for example calls it
				 * /dev/nul.  <mks.h> will default to /dev/null.
				 */

#define	M_FCLOSE_NOT_POSIX_1 1	/* fclose() does not conform to posix.1 section
				 * 8.2. An explicit lseek must be done on the
				 * stream prior to an fclose for the seek
				 * pointer to be correct. <mks.h> will default
				 * to undefined.
				 */

#define	M_FFLUSH_NOT_POSIX_1 1	/* fflush() does not conform to posix.1 section
				 * 8.2.  <mks.h> will default to undefined.
				 * If undefined, then mks.h will turn m_fflush
				 * into fflush.  If defined, then mks.h will
				 * leave m_fflush alone, and a stdio-specific
				 * routine m_fflush() must be provided which
				 * actually conforms to the standard.
				 */


#define	M_NL_DOM	"mks"	/* String used as default name (domain name)
				 * to get mks utility messages via the xpg
				 * catopen/catgets message translation functions
				 * For example, in XPG:
				 *     catopen (M_NL_DOM, ...)
				 */


#define	M_L_CUSERID	16	/* Length of longest user id returned by
				 * cuserid() routine.
				 * Used for L_cuserid in case its not
				 * defined in <stdio.h>
				 */

#define	M_FSMOUNT	"/etc/mtab"
				/* This pathname is passed as the 1st argument
				 * to setmntent() routine.
				 * On conventional UNIX systems, this
				 * pathname identifies a file that contains
				 * a list of all the actively mounted systems.
				 * The mount utility is normally responsible
				 * for adding entries to this file
				 * and umount utility deletes the entries.
				 */
#define	M_FSALL		"/etc/fstab"
				/* this pathname identifies a file that
				 * is similar to M_FSMOUNT, but instead of 
				 * the actively mounted file systems, it 
				 * has a list of ALL possible filesystems
				 * that could be mounted.
				 * This file normally used by the mount 
				 * command to find all the file systems
				 * to mount by default.
				 */

#define	M_NLSCHARMAP	"/usr/lib/nls/charmap/ISO_8859-1"
				/* Name of default charmap file to use in
				 * localedef if -f charmap option isn't
				 * used.
				 */

#define	M_ISEOV(error)	(error == EINVAL)
				/* This macro is used after an unsuccessful
				 * read() or m_devread() to determine
				 * if end-of-volume has been encountered.
				 * This macro should be invoked using the 
				 * errno returned by the read().
				 * The macro should evaluate to 1 (true)
				 * if it can determine the EOV condition
				 * from this errno.
				 * Otherwise, should evaluate to 0 (false)
				 * <mks.h> defaults to 0, i.e. never EOV
				 */

#define	M_COMPRESS_DEFBITS	16
				/* Default # of bits to compress in compress.
				 * If not defined, compress defaults to 16.
				 * Probably only useful on systems with limited
				 * memory capacity.
				 */

#define M_CURSES_VERSION	"MKS Interopen Curses"
				/* Curses product version string.  This
				 * string will be imbedded in the excutable
				 * for an application.  This string should
				 * be set to the vendor's product code used
				 * for Curses.
				 */
 
#undef	M_CURSES_MEMMAPPED	/* Define this symbol to compile up curses
				 * for a memory mapped display, such as the PC.
				 * Rather than allocating memory for the main
				 * screen window, this is compiled to point
				 * directly at the mapped memory.  This will
				 * require some custom code.
				 */

#define M_TERM_NAME		"dumb"
				/* Default terminal name used if TERM is
				 * not set in the environment.
				 */

#define M_TERMINFO_DIR		"/usr/lib/terminfo"
				/* Default location for the terminfo database
				 * if TERMINFO is not set in the environment.
				 *
				 * NOTE: Only define this macro if curses
				 *	 is available on this system since
				 *	 this macro is also used to
				 *       determine if "curses" is available 
				 */

#define M_BSD_SPRINTF	1	/* Defined if sprintf on this system has BSD
				 * semantics ie. if sprintf() returns a pointer
				 * to the string rather than the number of
				 * characters printed.
				 */

#define	M_IS_NATIVE_LOCALE(s)	(strcmp(s, "POSIX") == 0 || strcmp(s, "C") == 0)
				/* Change this definition to define the locale
				 * that the machine level comparison function
				 * strcmp conforms to.  On all ascii machines,
				 * strcmp will order the same as the POSIX
				 * locale.  <mks.h> defaults to the def'n given
				 * here.
				 */

#undef	M_NOT_646		/* Define this symbol if the local invariant
				 * character set does not conform to ISO646.
				 * Normally, this would only be set for
				 * EBCDIC systems.
				 * Several utilities (e.g pax/tar/cpio)
				 * are explicitly required to use 646,
				 * so if this flag is defined, then there
				 * is special code  which will be
				 * compiled in to do the appropriate
				 * character set translation.
				 */

#define	M_FILENAME_CODESET	"IS8859"
				/* If M_NOT_646 is defined, then you must
				 * define the codeset that filenames are
				 * stored in.  This must be a string value,
				 * that can be passed into iconv.
				 * Theoretically, this could be a call to
				 * setlocale, to some extention that would
				 * return the name of the charmap.
				 */

#define	M_STKCHK expression	/* Define this macro on systems that have a
				 * fixed size stack.
				 * This macro should define an expression
				 * that can be used to check if the current
				 * C function stack is within some distance
				 * from the end of available stack size.
				 * Return 0 if it is -- i.e. unsafe to
				 * recurse further.
				 * <mks.h> defaults to undefined; 
				 * i.e. no stack bounds checking.
				 * This is only called from a few programs
				 * which allow the user to perform recursion.
				 */

#define M_ST_RDEV(sb)	((sb).st_rdev)
#define M_DEVMAJOR(statp)	((uint)major((statp)->st_rdev))
				/* Prototype: uint M_DEVMAJOR(struct stat *);
				 *
				 * Return the major device number given
				 * a "struct stat *".
				 * Assumes the stat structure pointer 
				 * represents a special device file.
				 * MKS recommends all systems define
				 * some method of extracting this information
				 * from this structure
				 * (eg. define a st_rdev or st_major member
				 *       in the struct stat.)
				 * This macro must be defined to return some
				 * unsigned integer value.
				 */

#define M_DEVMINOR(statp)	((uint)minor((statp)->st_rdev))
				/* Prototype: uint M_DEVMINOR(struct stat *);
				 * 
				 * Return the minor device number given
				 * a "struct stat *".
				 * Same recommendations as M_DEVMAJOR above.
				 */

#define	M_DEVMAKE(mjr, mnr)	(makedev((mjr), (mnr)))
				/* Build a dev_t from a major and minor #
				 * M_DEVMAKE(M_DEVMAJOR(sbp), M_DEVMINOR(sbp))
				 * just returns the dev_t from the stat buf
				 */

#define M_INODIRENT(name, dirbuf)	((ino_t)((dirbuf)->d_ino))
				/* Prototype: 
				 *  ino_t M_INODIRENT(char *, struct dirent *);
				 *
				 * Return the inode belonging to the directory
				 * entry corresponding to dirbuf.  The name
				 * parameter is the path name given to a 
				 * previous call to opendir().
				 */

#define	M_ST_BLOCKS(sbp)  ((sbp)->st_blocks)
#define	M_ST_BLKSIZE(sbp) ((sbp)->st_blksize)
				/* If the implementation supports, in the stat
				 * structure, the actual disk space allocation
				 * to a given file, then M_ST_BLOCKS should
				 * be defined to return that member from the
				 * passed stat structure pointer.
				 * M_ST_BLKSIZE should be the number of bytes
				 * in a M_ST_BLOCKS unit; normally a
				 * different member of the stat structure.
				 *
				 * These macros are not required.
				 * Programs that use these macros 
				 * will fall back on computing these
				 * values from the st_size field.
				 */

#define M_MATHERR	0	/* If the math library supports matherr(),
				 * define with a non-zero value.
				 * MKS recommends that all ANSI-C libraries
				 * support this.
				 * By default, not defined.
				 */

#define M_AWK_SUBSEP	"\034"	/* Default SUBSEP value in awk. This value
				 * is appropriate for ASCII based character
				 * sets.
				 */

#define M_FSCLOSE(fp)	fclose(fp)
				/* define M_FSCLOSE(fp) to be the function
				 * that cleans up the resources allocated
				 * by m_fsopen().
				 * Since m_fsopen() implementation is system
				 * specific, so is M_FSCLOSE().
				 */

#define M_LEX_8BIT	1	/* If this is defined, lex will produce
				 * 8-bit tables by default (the normal
				 * default is 7-bit tables).
				 */

#define M_NUMSIZE	30	/* M_NUMSIZE should be defined to the length
				 * in character positions, of the longest
				 * number that can be sprintf()'d into a string
				 * (longest of any type of number,
				 *   eg. float, long, double ...)
				 * For example, if your system prints
				 * 30 characters for sprintf(str, "%le", float)
				 * then M_NUMSIZE should be set to at least 30.
				 *
				 * This is used in awk to guess at the size
				 * that each element of an sprintf() will be
				 * so that it can internally allocate enough
				 * storage.
				 *
				 * If this is not defined, then a default
				 * value is used from <mks.h>
				 */

/*
 * File System (Naming) Attributes.
 * M_ONE_DOT, M_NO_LEADING_DOT, and M_SHORT_EXT are deprecated, in favour
 * of the m_fstype() function.  However, until all code has been converted
 * they must be set appropriately.  The obsolescent versions do not permit
 * supporting a system with multiple filesystem types: they are all statically
 * tested via pre-processor directives.  The new version permits mixing for
 * example of a posix file system, with say a dos floppy file system, such
 * as is available on many unix systems today.
 * If your system is posix conformant, do not set any of these variables
 * or functions; <mks.h> will default to a #define for m_fstype to 
 * a POSIX style naming convention.
 */
#undef	M_FSTYPE		/* If m_fstype is defined in mkslocal.h,
				 * either as a #define, or a function decl.
				 * then define M_FSTYPE, so <mks.h> won't
				 * define m_fstype into M_FSTYPE_POSIX.
				 */

#undef	m_fstype(path)		/* Either #define, or function returning a
				 * combination of file naming attributes,
				 * and the file system type.  On a system
				 * with only one file system type, this would
				 * be a #define; on a system with multiple a
				 * function which would decide based on the
				 * path arg given.  Either M_FSTYPE_POSIX or
				 * M_FSTYPE_FAT, should be or'ed with any of
				 * M_FSATTR_ONE_DOT, M_FSATTR_SHORT_EXT and
				 * M_FSATTR_NO_LEADING_DOT.  These three 
				 * M_FSATTR_ bit flags conform to the three
				 * following obsolete defines.
				 */

#undef	M_ONE_DOT		/* Use	#define M_ONE_DOT 1
				 * for non-posix files systems which
				 * permit only one dot in a filename.
				 * Thus, for example, y.tab.c, will become
				 * ytab.c, based on this #define.
				 * <mks.h> will default to undefined.
				 */

#undef	M_NO_LEADING_DOT	/* Use	#define M_NO_LEADING_DOT 1 for
				 * non-posix file systems which do not
				 * permit a leading dot in a filename.
				 * Thus, for example, .profile will become
				 * profile.ksh based on this #define.
				 * <mks.h> will default to undefined.
				 */

#undef M_SHORT_EXT		/* Use	#define M_SHORT_EXT 1
				 * for non-posix file systems which
				 * permit only a limited number of characters
				 * after a dot in a filename.
				 * Defining M_SHORT_EXT will limit filenames
				 * to 3 characters after the dot.
				 * For example, y.output will become y.out
				 * <mks.h> will default to undefined.
				 */

/*
 * customizations for ps field specifiers and widths
 * This will vary from system to system depending on the max size 
 * of the values in the different fields
 * The following are UNIX (e.g SYSV and BSD) std defaults
 */
#define M_PS_FFMT	{ m_textstr(4865, "ruser=UID", "I"),\
			 m_textstr(4866, "pid,ppid,pcpu=C", "I"),\
			 m_textstr(4861, "stime,tty=TTY", "I"), "atime,args",\
			 NULL };
#define M_PS_JFMT	{ m_textstr(4867, "pid,sid,pgid=PGRP", "I"),\
			  m_textstr(4862, "tty=TTY", "I"), "atime,args", NULL };
#define M_PS_LFMT	{ m_textstr(4868, "flags,state,ruid=UID", "I"),\
			 m_textstr(4866, "pid,ppid,pcpu=C", "I"),\
			 m_textstr(4869, "pri,nice,addr,vsz=SZ", "I"),\
			 m_textstr(4870, "wchan,tty=TTY", "I"),\
			 m_textstr(4863, "atime,comm=COMD", "I"), NULL };
#define M_PS_DEFFMT	{ m_textstr(4864, "pid,tty=TTY", "I"), "atime,comm",\
			 NULL };
#define M_PS_PID_WIDTH  5
#define M_PS_XPID_WIDTH 8
#define M_PS_GID_WIDTH  5
#define M_PS_UID_WIDTH  5
#define M_PS_TTY_WIDTH  7
/*
 * The syntax for specifying and displaying terminal names in ps and who
 * is required to be the same.
 * Since who gets the names from the utmp file, the ps utility
 * (and the m_psread() function) needs to know what format these terminal
 * names are presented in the utmp file.
 * It would appear that all systems have devices in the /dev/ file system
 * and that terminal names are displayed as the name rooted from "/dev".
 * Since ttyname() returns a full pathname, we can just strip
 * off the "/dev/" prefix and we will get the correct name.
 *
 * The ps utility uses ttyname() to get the name of the controlling terminal.
 * M_PS_TTY_PREFIX_TOSTRIP is a prefix string that must be removed from
 * the name that ttyname() returns in order to match the name returned
 * by m_psread().
 * If no prefix is to be removed, then a zero length string ("") should be used
 */
#define M_PS_TTY_PREFIX_TOSTRIP "/dev/"


#define M_LOCALE_NLS_DIR        "/usr/lib"
			/* Define this if you have a system that
			 * implements the MKS rootname() function
			 * (e.g not a no-op)
			 * and you want to specify the absolute
			 * pathname to the NLS directory
			 * which is independent of semantics of rootname().
			 * Depending on the implementation of rootname(),
			 * it may prefix the path with $ROOTDIR environment
			 * variable or it may return a path relative to 
			 * the know location of where the product has
			 * been installed (or maybe something else!)
			 *
			 * If this is not defined, then locale will
			 * call confstr(_CS_NLSDIR), which in turn calls
			 * rootname(M_NLSDIR), and you get this resultant
			 * pathname.
			 *
			 * Thus, if you want locale to look in the system native
			 * nls directory, then define this.
			 * Otherwise, it will probably look in a user
			 * specified directory, or the product installation
			 * directory.
			 */


/* Cron configuration options:
 * M_CRON_USESFIFO	define this (to 1) if your cron is implemented 
 *			using a FIFO (normally found in /usr/lib/cron/FIFO)
 *			to accept communication from the at/batch/crontab
 *			utilities when notifying cron of changes to the
 *			at/batch queues or the user crontabs.
 *			If this is not defined, then cron will expect
 *			a signal (SIGUSR) from at/batch/crontab to indicate
 *			a change in the at/batch queues or the crontabs
 *
 * M_CRONVARS_DEFINED	define this if you define the pathnames below.
 *		        If you don't define this, then the pathnames that cron
 *                      uses is defined in src/cron/cronvars.c.
 *			(e.g it uses the rootname() and the M_SPOOLDIR,
 *                           M_LIBDIR macros )
 *
 *			This can be used to override cronvars.c definitions
 *			This is useful on systems that you don't want to 
 *			use MKS's cron daemon and thus, you have to define
 *			the directories/files where the system cron expects
 *			things.
 */
#undef M_CRON_USESFIFO

#undef M_CRONVARS_DEFINED

/* the following M_CRON_* macros necessary only
 * if M_CRONVARS_DEFINED is defined above
 */
#undef M_CRON_SPOOLDIR		/* usually /usr/spool/cron */
#undef M_CRON_LIBDIR		/* usually /usr/lib/cron */
#undef M_CRON_CRONTABSDIR	/* usually /usr/spool/cron/crontabs */
#undef M_CRON_ATJOBSDIR		/* usually /usr/spool/cron/atjobs */
#undef M_CRON_LOGFILE		/* usually /usr/lib/cron/log */
#undef M_CRON_PIDFILE		/* usually /usr/lib/cron/pid */
#undef M_CRON_QUEUEDEFSFILE	/* usually /usr/lib/cron/queuedefs */
#undef M_CRON_FIFOFILE		/* usually /usr/lib/cron/FIFO */
				/* FIFOFILE only necessary if M_CRON_USESFIFO
				 * is defined
				 */
/*
 * M_CRON_MAILER: 
 *     This is a string that specifies a utility names
 *     or a shell filter (e.g pipeline) that gets executed by the
 *     cron daemon to deliver mail messages.
 *     If this is NOT defined here, the the default case is used (see <mks.h>)
 *
 * Default case:
 *     #define M_CRON_MAILER   "sed -e s/^~/~~/ | mailx "
 *
 * Assumes only POSIX.2 mailx is available.
 * Must be careful when cron sends output to mailx.
 * We must ensure that lines with leading '~' are escaped
 * so mailx doesn't interpret these lines
 * This string MUST include a trailing space character.
 */
#define M_CRON_MAILER   "sed -e s/^~/~~/ | mailx "


/*
 * Defining M_SYSTEM_TMPDIR indicates that a system global
 * temporary directory should be used on this system.
 * This will override M_TMPDIR, and any calls to rootname(M_TMPDIR)
 * which is relative to the product installation directory
 */
#define M_SYSTEM_TMPDIR  "/tmp"

/*
 * ex/vi's recover command (and the program of the same name)
 * requires a directory in which to store any preserved tmp files.
 * Normally these are stored in rootname(M_ETCDIR(recover))
 * which is becomes a directory name relative to ROOTDIR env variable (on DOS)
 * or relative to the product installation directory.
 * Defining M_PRESERVEDIR will ensure that this directory is used
 * and calls to rootname() are bypassed.
 * (e.g the absolute directory name defined by M_PRESERVEDIR will be used)
 */
#define M_PRESERVEDIR    "/var/recover"
 
/*
 * Defining M_SYSTEM_MAILDIR will cause mailx to use this 
 * absolute directory name - e.g bypass the call to rootname() so
 * it doesn't become relative to product installation directory.
 */
#define M_SYSTEM_MAILDIR       "/usr/mail"
 

#undef M_ULIMIT_AVAIL	/* define this if your system provides the SystemV
			 * ulimit() API and the <ulimit.h> header file
			 *
			 * This information is used by 'at' utility
			 */

/*
 * Shell configuration options.
 * NOTE: If not defined here, then there may be
 * a default defined in src/sh/sh.h; NOT <mks.h>.
 *
 * You must configure built-in utilities in sh/sh.mk.
 * Currently, test and printf can be built-in.
 * If you just compile the shell without -D's,
 * you do not get these built-in utilities.
 */
#define	M_SH_ULIMIT	0	/* Shell SVR4 ulimit built-in.
				 * Uses getrlimit/setrlimit(2).
				 *
				 * NOTE: This may be defined in mkslocal.mk
				 * along with the build configuration required
				 * for shbltin.c.  
				 */
/* M_SH_GETCWD removed, no longer used. default for physical cd/pwd */
#define	M_SH_BGNICE	0	/* Set -o bgnice for interactive shell.
				 */
#define	M_SH_BUILTIN_SEARCH 1	/* Do path search for utility built-ins.
				 * See POSIX.2/D12, section 3.9.1.1.
				 * Currently they are:
				 * [, echo, test, time, printf, pwd.
				 */
#define	M_SH_RSH	0	/* rsh is installed as a link to sh.
				 * Vendor option, not required by any standard.
				 * Not recommended on UNIX.
				 */
#define	M_SH_USER_FDS	10	/* Number of user file descriptors.
				 * The value for [n] in redirection
				 * can be between 0 and M_SH_USER_FDS-1.
				 * Must be >= 10, should be <= OPEN_MAX/2.
				 */
#define	M_SH_LINE_MAX	LINE_MAX /* Shell input line buffer size.
				  */
#undef	M_JOB_CONTROL_OFF	/* Disable job control,
				 * were _POSIX_JOB_CONTROL is defined.
				 */
#undef	M_COPYRIGHT		/* MKS Toolkit.
				 * Print MKS copyright on startup (sh).
				 */
#undef	M_SH_CRITERROR		/* MKS Toolkit.
				 * set -o criterror (DOS, OS/2).
				 */

#define M_SH_MAX_FUNCTION_EVAL_DEPTH	100
				/* The limit on how deep function
				 * evaluation can go when shell
				 * functions execute shell functions.
				 * This stops the shell from crashing
				 * if an infinitely recursive function
				 * is evaluated.  If the value is 0
				 * then functions can't be executed at
				 * all, if the value is 1 then
				 * functions can't execute other
				 * functions, and so on.  If the macro
				 * M_STKCHK is defined then there will
				 * be no limit and M_STKCHK will be
				 * used to prevent a crash.
				 */

#undef M_SPAWN			/* This code is prototype code only.  It 
				 * has not been tested, and should not be
				 * used.
				 * This code is not supported, except through
				 * special arrangements with MKS.
				 */


#define M_EXPR_POSIX	1
				/*
				 * POSIX requires that numbers on the
				 * expr command line always be considered
				 * decimal.  We support octal and hex as
				 * as well.  Defining this will turn that
				 * extension off by default, but it is still
				 * accessible by specifying the new '-W' flag
				 */

#undef M_RE_SUB_ANCHOR		/* Define this if you wish your baisc regular 
				 * expressions to support anchors
				 * (^ and $) inside of subexpressions.
				 * See POSIX.2 section 2.8.3.5.
				 */


/*
 * In order to get full Posix.2 i18n, then you must either:
 *
 * i) Use the full mks ansi-c library; mks localedef, mks locale.h file...
 * ii) Extend your own ansi-c library to contain the mks specified functions
 * as described in the mks Porting and Tuning Guide.
 *
 * Otherwise, it is not possible to conform to posix .2.
 *
 * You may still turn on I18N, and get as much internationalization as is
 * possible using a standard ANSI-C compiler.
 *
 * Your options are:
 * i)   Full posix conformance. You must have i or ii above, and must define
 *      M_I18N and M_I18N_MKS_{FULL,XPG}.
 * ii)  I18N at ANSI-C level.  You must define I18N, do not
 *      define M_I18N_MKS_{FULL,XPG}.
 * iii) No I18N.  Do not define I18N, do not define M_I18N_MKS_{FULL,XPG}. */
#define	I18N	1		/* OBSOLESCENT version of I18N
				 * This should be removed when all occurances
				 * of I18N are removed from the MKS code
				 */
#define	M_I18N	1		/* Do we want internationalized code?  To build
			 	 * a system where everything gets deleted at
				 * compile time via #define's when possible,
				 * this flag should be set.  <mks.h> does not
				 * define I18N, but it is normal to set it.
				 */
#define	M_I18N_MKS_FULL	1	/* Defining this, indicates you are using
				 * MKS i18n extension routines
				 *  (e.g m_collrange(), m_collequiv() ...
				 *       localedtconv, localeldconv() ...)
				 * Defining this to 2 indicates that you
				 * want to use MKS's implementation of these
				 * routines and the implementation of MKS's
				 * format of the locale data files.
				 * Defining this to 1 indicates you don't want
				 * MKS's implementation, and you must write
				 * your own code for m_collrange(), collequiv()
				 * ...
				 *   note: there are some routines like 
				 *         localedtconv which can  obtain the
				 *         necessary info from nl_langinfo()
				 *         if this is supported
				 *         See M_I18N_MKS_XPG below
				 */
#define	M_I18N_MKS_XPG	1	/* This is only useful if M_I18N_MKS_FULL == 1.
				 * This flag indicates that nl_langinfo()
				 * is available and can be used to
				 * retrieve some of the locale information.
				 * ( used in localeldconv() and localedtconv()
				 *  routines)
				 */

#define	M_I18N_M_	1	/* MKS has defined some additions i18n API's.
				 * (e.g m_collequiv, m_collrange ...)
				 * This flag indicates that these API's start
				 * with "m_".
				 * It is the MKS intention that if these
				 * extentions get approved/standardized
				 * (by POSIX or ANSI or ...)
				 * all code will have  the m_ removed.
				 * Since it is not yet approved,
				 * we are maintaining the mks conventions of
				 * prefixing our private libraries with m_.
				 * If you have chosen to implement these
				 * routines without the m_ do not define
				 * M_I18N_M_
				 */

#define M_I18N_MB	1	/* Define if multibyte character support
				 * is required.
				 */

#define  M_LOCALEINFO_IN_DIRECTORY  1
				/* This macro indicates if the locale
				 * information is stored in a directory,
				 * or in a file.
				 * For instance, many systems use
				 *   /usr/lib/locale
				 * as a directory to store all their locale
				 * information.
				 * In this directory is stored the info
				 * for each supported locale.
				 * (e.g POSIX, C, en_US, fr, ...)
				 * It is assumed that there is one entry here
				 * for each supported locale.
				 * If these entries are sub-directories, 
				 * then this macro is defined.
				 * If these entries are files, then do not
				 * define this macro.
				 */

#undef M_I18N_LOCKING_SHIFT	/* Define if any multibyte character sets
				 * used are locking-shift character sets.
				 */


#undef M_VARIANTS		/* This can be defined on EBCDIC systems
				 * where the POSIX.2 portable characters are not
				 * invariant across all the code pages 
				 * supported.
				 * By defineing this, user is allowed
				 * to define the encodings
				 * for these characters as they switch between
				 * the various code pages by setting up
				 * the VARIANTS environment variable.. 
				 * so that the various utilities will cope
				 * with the different encodings gracefully.
				 */
				 /* Source code hints:
				  * if you define this, you will need
				  *    h/variant.h, h/m_invari.h
				  *    libc/mks/getsyntx.c, 
				  *    libc/mks/m_varian.c
				  *
				  * If this is not defined, then all you need
				  * is
				  *    h/m_invar.h
				  */

/*
 * Define the following if you want the corresponding posix define with
 * a single leading underscore
 */
#define	__POSIX_JOB_CONTROL	_POSIX_JOB_CONTROL
#define	__POSIX_SAVED_IDS	_POSIX_SAVED_IDS
#define	__POSIX_NO_TRUNC	(-1)
#define	__POSIX_VDISABLE	0xff

/*
 * On some systems where code size and performance are problems, it
 * may be desirable to use a simplified version of the m_loxclose() routine
 * in programs that don't require the full functionality. If this is the
 * case and routine m_loxqclose() has been provided, define the following
 * macro. (Refer to the Library/eXecutable/Object interface documentation
 * for more information.
 */
#undef M_LOXQCLOSE

/*
 * some systems require overrides after <mks.h> is read.
 * If your system requires this, define M_MKSEXTRA_H here
 * so that the "#include <mksextra.h>" is exposed in <mks.h>
 */
#undef M_MKSEXTRA_H

/*
 * mailx configuration
 */

/*
 * Many mail systems support the non-standard "Content-Length" header
 * which contains the length of the body of the message (not including
 * the headers) in bytes.  Defining M_MAILX_CONTENT_LENGTH_ENABLE will
 * turn on code in mailx to generate this header when mail is sent and
 * honour it when scanning mailboxes.
 */
#undef M_MAILX_CONTENT_LENGHT_ENABLE

#endif /* 0. not required for POSIX systems; here for documentation only */


#define	halloc(n,s)	malloc((size_t)((n)*(s)))/* alloc big chunk of mem*/
#define	hfree(ptr)	free(ptr)		/* free big chunk of mem */
#define m_cp(src, dest, ssb, flags)	(M_CP_NOOP)
#define	rootname(fn)	fn			/* make relative to root */


/*
 * MKS makes use of types that may or may not already be defined in the
 * system <sys/types.h> file.  If not defined, then they must be defined
 * here.  (The problem is a lack of #if directive to determine an existing
 * typedef.
 */
typedef unsigned char	uchar;
typedef	unsigned short	ushort;
typedef unsigned int	uint;
typedef unsigned long	ulong;

/*
 * Define any Optional Facility Configuration Values here.
 * See POSIX.2, 2.13.2, Table 2-18
 * We define them here as M_ entries; this allows unistd.h to test the
 * M_ variable, and if defined, define the official _POSIX2_ variable.
 * **Note: It isn't permitted for a real conforming unistd.h to #include <mks.h>
 * due to name space contamination problems.  A real, conforming implementation
 * will manually modify their unistd.h to define the _POSIX2 variables
 * appropriately.
 */
#define	M_POSIX2_C_BIND		1
#define	M_POSIX2_C_DEV		1
#undef	M_POSIX2_FORT_DEV
#undef	M_POSIX2_FORT_RUN
#define	M_POSIX2_LOCALEDEF	1
#define	M_POSIX2_SW_DEV		1

/*
 * New definitions for I/PSU 3.3
 */

#undef M_POSIX_PFNCS_ONLY	/* define this to be true if the implementation
				 * only supports the portable filename
				 * set as defined in POSIX.1
				 */

#undef M_NO_STIME		/* set this define to be true if the system
				 * does not support the stime() API.
				 */

#undef M_TTYSTREAM		/* if it isn't possible to open a new console
				 * stream through device names, define this
				 * macro to be true. The support library must
				 * define a routine "m_ttystream()" that can
				 * return the required stream.
				 */

#undef M_NOT_ROOT		/* this should be defined to be the name of a
				 * library routine that returns true if the
				 * process has appropriate privileges
				 */

#undef M_NO_VI_KEYPAD		/* this should be defined when the system
				 * can't support keypad and cursor-key
				 * functions in vi.
				 */

#undef M_USERID_FMT		/* format string for printing out the user
				 * name. It is "%-8.8s" by default.
				 */

#undef M_USE_M_CP		/* indicates that code is to use the m_cp()
				 * interface.
				 * (Note - this API is not fully supported
				 *  in the IPSU.3.X development line.  Full
				 *  support will be available in a future
				 *  major release.)
				 */

#undef M_GUESS_FILE_TYPE	/* If the system provides alternative
				 * mechanisms for determining the type of a
				 * file, define this macro to true.  If you are
				 * using this feature, you must provide a new
				 * function int m_guess_file_type(char *name);
				 * Returns true if type of file name is
				 * successfully identified.
				 * (Note - this API is not fully supported in
				 *  the IPSU.3.X development line.  Full
				 *  support will be available in a future
				 *  major release.)
				 */

#undef M_INCR_NICE		/* default nice incr, if this macro is not
				 * defined a builtin default will be used
				 * (see the source for nice for more details.)
				 */

#undef M_INCR_RENICE		/* default renice incr, if this macro is
				 * not defined a builtin default will be
				 * used (see the source for renice for more
				 * details.)
				 */

#undef M_PS_COMM_WIDTH		/* width of command field printed by PS */

#undef M_PS_USER_WIDTH		/* width of user and ruser fields printed by
				 * PS
				 */

#undef M_PS_PRI_WIDTH		/* width of PRI field printed by PS */

#undef M_UT_TIME_STRING		/* true if utmp ut_time struct is a string
				 * instead of a number.
				 */

#undef M_SH_ENTRY1
#undef M_SH_ENTRY2
#undef M_SH_ENTRY3
				/* The above 3 macros are provide in the
				 * shell to allow system-specific extensions
				 * to be added.
				 * (Note - this API is not fully supported in
				 * the IPSU.3.X development line.  Full
				 * support will be available in a future
				 * major release.)
				 */

#undef M_NO_CANONICAL_MODE	/* set this macro to true if the system
				 * doesn't support tty buffering in
				 * canonical mode.
				 */

#undef M_NO_PASSWD_SCAN		/* true if system doesn't provide a
				 * mechanism for scanning a list of all
				 * users on the system.
				 */

#define M_GROUP_PASSWD(grp)	""
	/* prototype:
	 *         char *M_GROUP_PASSWD(struct group *grp)
	 * This api returns a pointer to a string
	 * that contains the password for group 'grp'.
	 * If no password is available, then an empty string should be
	 * returned.
	 * 
	 * On historical UNIX systems, group passwords are found in 
	 * the gr_passwd member in struct group.
	 * Thus, this macro should be defined as
	 *    #define M_GROUP_PASSWD(grp)	grp->gr_passwd
	 *
	 * On systems that do not provide group passwords,
	 * then macro can be defined as an empty string:
	 *    #define M_GROUP_PASSWD(grp)	""
	 *
	 */


#undef M_RCS_NORCSLIB 	/* Set this macro to true in order
			 * remove rcslib dependency of utilities
			 * such as ident.
			 */

#undef M_CHMOD_LINK	/* Set this macro to true if the system is
			 * able to perform a chmod() of a link as
			 * opposed to following the link.
			 */
/*
 * Include any system-specific prototypes here
 */

/*
 * Include any #define's to avoid name clashes with namespace polluting
 * operating system routines
 *
 * e.g.: #define openfile MKSopenfile
 */

