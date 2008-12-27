/***********************************************************************
*                                                                      *
*               This software is part of the ast package               *
*          Copyright (c) 1985-2008 AT&T Intellectual Property          *
*                      and is licensed under the                       *
*                  Common Public License, Version 1.0                  *
*                    by AT&T Intellectual Property                     *
*                                                                      *
*                A copy of the License is available at                 *
*            http://www.opensource.org/licenses/cpl1.0.txt             *
*         (with md5 checksum 059e8cd6165cb4c31e351f2b69388fd9)         *
*                                                                      *
*              Information and Software Systems Research               *
*                            AT&T Research                             *
*                           Florham Park NJ                            *
*                                                                      *
*                 Glenn Fowler <gsf@research.att.com>                  *
*                  David Korn <dgk@research.att.com>                   *
*                   Phong Vo <kpv@research.att.com>                    *
*                                                                      *
***********************************************************************/
/* : : generated from /home/gisburn/ksh93/ast_ksh_20081104/build_sparc_32bit/src/lib/libast/features/tty by iffe version 2008-01-31 : : */
#ifndef _def_tty_ast
#define _def_tty_ast	1
#define _sys_types	1	/* #include <sys/types.h> ok */
#define _hdr_termios	1	/* #include <termios.h> ok */
#define _hdr_termio	1	/* #include <termio.h> ok */
#define _hdr_sgtty	1	/* #include <sgtty.h> ok */
#define _sys_termios	1	/* #include <sys/termios.h> ok */
#define _sys_termio	1	/* #include <sys/termio.h> ok */
#define _sys_ioctl	1	/* #include <sys/ioctl.h> ok */
#define _lib_tcgetattr	1	/* tcgetattr() in default lib(s) */
#define _lib_tcgetpgrp	1	/* tcgetpgrp() in default lib(s) */
#define _mac__POSIX_VDISABLE	1	/* _POSIX_VDISABLE is a macro */

#ifdef _hdr_termios
#   if _mac__POSIX_VDISABLE
#	undef _POSIX_VDISABLE
#   endif
#   include	<termios.h>
#else
#   if defined(_sys_termios) && defined(_lib_tcgetattr)
#	include	<sys/termios.h>
#	define _hdr_termios	1
#   else
#	undef _sys_termios
#   endif /* _sys_termios */
#endif /* _hdr_termios */

#ifdef _hdr_termios
#   undef _hdr_sgtty
#   undef tcgetattr
#   undef tcsetattr
#   undef tcgetpgrp
#   undef tcsetpgrp
#   undef cfgetospeed
#   ifndef TCSANOW
#	define TCSANOW		TCSETS
#	define TCSADRAIN	TCSETSW
#	define TCSAFLUSH	TCSETSF
#   endif /* TCSANOW */
   /* The following corrects bugs in some implementations */
#   if defined(TCSADFLUSH) && !defined(TCSAFLUSH)
#	define TCSAFLUSH	TCSADFLUSH
#   endif /* TCSADFLUSH */
#   ifndef _lib_tcgetattr
#	undef  tcgetattr
#	define tcgetattr(fd,tty)	ioctl(fd, TCGETS, tty)
#	undef  tcsetattr
#	define tcsetattr(fd,action,tty)	ioctl(fd, action, tty)
#	undef  cfgetospeed
#	define cfgetospeed(tp)		((tp)->c_cflag & CBAUD)
#   endif /* _lib_tcgetattr */
#   undef TIOCGETC
#else
#   define cfgetospeed(tp)	((tp)->c_cflag & CBAUD)
#   define cfgetispeed(tp)	((tp)->c_cflag & CBAUD)
#   define cfsetispeed(tp,val)	((tp)->c_cflag &=~ CBAUD,(tp)->c_cflag|=(val))
#   define cfsetospeed(tp,val)	((tp)->c_cflag &=~ CBAUD,(tp)->c_cflag|=(val))
#   ifdef _hdr_termio
#	include	<termio.h>
#   else
#	ifdef _sys_termio
#	    include	<sys/termio.h>
#	    define _hdr_termio 1
#	endif /* _sys_termio */
#   endif /* _hdr_termio */
#   ifdef _hdr_termio
#	define termios termio
#	undef TIOCGETC
#	define tcgetattr(fd,tty)	ioctl(fd, TCGETA, tty)
#	define tcsetattr(fd,action,tty)	ioctl(fd, action, tty)

#	ifdef _sys_bsdtty
#	   include	<sys/bsdtty.h>
#	endif /* _sys_bsdtty */
#   else
#	ifdef _hdr_sgtty
#	    include	<sgtty.h>
#	    ifndef LPENDIN
#	        ifdef _sys_nttyio
#		    include	<sys/nttyio.h>
#	        endif /* _sys_nttyio */
#	    endif /* LPENDIN */
#	    define termios sgttyb
#	    ifdef TIOCSETN
#	 	undef TCSETAW
#	    endif /* TIOCSETN */
#	    ifdef TIOCGETP
#		define tcgetattr(fd,tty)	ioctl(fd, TIOCGETP, tty)
#		define tcsetattr(fd,action,tty)	ioctl(fd, action, tty)
#	    else
#		define tcgetattr(fd,tty)	gtty(fd, tty)
#		define tcsetattr(fd,action,tty)	stty(fd, tty)
#	    endif /* TIOCGETP */
#	else
#		ifdef _sys_ttyio
#			include <sys/ttyio.h>
#		endif
#	endif /* _hdr_sgtty */
#   endif /* hdr_termio */

#   ifndef TCSANOW
#	ifdef TCSETAW
#	    define TCSANOW		TCSETA
#	    define TCSAFLUSH		TCSETAF
#	else
#	    ifdef TIOCSETN
#		define TCSANOW		TIOCSETN
#		define TCSADRAIN	TIOCSETN
#		define TCSAFLUSH	TIOCSETP
#	    endif /* TIOCSETN */
#	endif /* TCSETAW */
#   endif /* TCSANOW */
#endif /* _hdr_termios */

/* set ECHOCTL if driver can echo control charaters as ^c */
#ifdef LCTLECH
#   ifndef ECHOCTL
#	define ECHOCTL	LCTLECH
#   endif /* !ECHOCTL */
#endif /* LCTLECH */
#ifdef LNEW_CTLECH
#   ifndef ECHOCTL
#	define ECHOCTL  LNEW_CTLECH
#   endif /* !ECHOCTL */
#endif /* LNEW_CTLECH */
#ifdef LNEW_PENDIN
#   ifndef PENDIN
#	define PENDIN LNEW_PENDIN
#  endif /* !PENDIN */
#endif /* LNEW_PENDIN */


#endif
