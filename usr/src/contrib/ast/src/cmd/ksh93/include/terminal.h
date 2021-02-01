/***********************************************************************
*                                                                      *
*               This software is part of the ast package               *
*          Copyright (c) 1982-2012 AT&T Intellectual Property          *
*                      and is licensed under the                       *
*                 Eclipse Public License, Version 1.0                  *
*                    by AT&T Intellectual Property                     *
*                                                                      *
*                A copy of the License is available at                 *
*          http://www.eclipse.org/org/documents/epl-v10.html           *
*         (with md5 checksum b35adb5213ca9657e911e9befb180842)         *
*                                                                      *
*              Information and Software Systems Research               *
*                            AT&T Research                             *
*                           Florham Park NJ                            *
*                                                                      *
*                  David Korn <dgk@research.att.com>                   *
*                                                                      *
***********************************************************************/
#pragma prototyped

#ifndef _terminal_
#define _terminal_	1

#include	"FEATURE/ttys"
/*
 * terminal interface
 * complicated by the fact that there are so many variations
 * This will use POSIX <termios.h> interface where available
 */

#ifdef _hdr_termios
#   include	<termios.h>
#   if __sgi__ || sgi	/* special hack to eliminate ^M problem */
#	ifndef ECHOCTL
#	    define ECHOCTL	ECHOE
#	endif /* ECHOCTL */
#	ifndef CNSUSP
#	    define CNSUSP	CNSWTCH
#	endif /* CNSUSP */
#   endif /* sgi */
#   ifdef _NEXT_SOURCE
#	define _lib_tcgetattr	1
#	define _lib_tcgetpgrp	1
#   endif /* _NEXT_SOURCE */
#else
#   if defined(_sys_termios) && defined(_lib_tcgetattr)
#	include	<sys/termios.h>
#	define _hdr_termios
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
#   if SHOPT_OLDTERMIO  /* use both termios and termio */
#	ifdef _hdr_termio
#	    include	<termio.h>
#	else
#	    ifdef _sys_termio
#		include	<sys/termio.h>
#		define _hdr_termio 1
#	    else
#		undef SHOPT_OLDTERMIO
#	    endif /* _sys_termio */
#	endif /* _hdr_termio */
#   endif /* SHOPT_OLDTERMIO */
#else
#   define cfgetospeed(tp)	((tp)->c_cflag & CBAUD)
#   undef SHOPT_OLDTERMIO
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
#	define tcgetattr(fd,tty)		ioctl(fd, TCGETA, tty)
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
#		define tcgetattr(fd,tty)		ioctl(fd, TIOCGETP, tty)
#		define tcsetattr(fd,action,tty)	ioctl(fd, action, tty)
#	    else
#		define tcgetattr(fd,tty)	gtty(fd, tty)
#		define tcsetattr(fd,action,tty)	stty(fd, tty)
#	    endif /* TIOCGETP */
#	endif /* _hdr_sgtty */
#   endif /* hdr_termio */

#   ifndef TCSANOW
#	ifdef TCSETAW
#	    define TCSANOW	TCSETA
#	    ifdef u370
	    /* delays are too long, don't wait for output to drain */
#		define TCSADRAIN	TCSETA
#	    else
#		define TCSADRAIN	TCSETAW
#	    endif /* u370 */
#	    define TCSAFLUSH	TCSETAF
#	else
#	    ifdef TIOCSETN
#		define TCSANOW	TIOCSETN
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
#ifndef ECHOCTL
#   ifndef VEOL
#	define RAWONLY	1
#   endif /* !VEOL */
#endif /* !ECHOCTL */

#ifdef _sys_filio
#   ifndef FIONREAD
#	include	<sys/filio.h>
#   endif /* FIONREAD */
#endif /* _sys_filio */
/* set FIORDCHK if you can check for characters in input queue */
#ifdef FIONREAD
#   ifndef FIORDCHK
#	define FIORDCHK	FIONREAD
#   endif /* !FIORDCHK */
#endif /* FIONREAD */

extern int	tty_alt(int);
extern void	tty_cooked(int);
extern int	tty_get(int,struct termios*);
extern int	tty_raw(int,int);
extern int	tty_check(int);
extern int	tty_set(int, int, struct termios*);
extern int	sh_ioctl(int,int,void*,int);
#define ioctl(a,b,c)	sh_ioctl(a,b,c,sizeof(c))
#ifdef _lib_tcgetattr
    extern int	sh_tcgetattr(int,struct termios*);
    extern int	sh_tcsetattr(int,int,struct termios*);
#   define tcgetattr(a,b)	sh_tcgetattr(a,b)
#   define tcsetattr(a,b,c)	sh_tcsetattr(a,b,c)
#endif

#endif /* _terminal_ */
