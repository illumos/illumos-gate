/***********************************************************************
*                                                                      *
*               This software is part of the ast package               *
*          Copyright (c) 1982-2010 AT&T Intellectual Property          *
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
*                  David Korn <dgk@research.att.com>                   *
*                                                                      *
***********************************************************************/
#pragma prototyped
/*
 *  edit.c - common routines for vi and emacs one line editors in shell
 *
 *   David Korn				P.D. Sullivan
 *   AT&T Labs
 *
 *   Coded April 1983.
 */

#include	<ast.h>
#include	<errno.h>
#include	<ccode.h>
#include	"FEATURE/options"
#include	"FEATURE/time"
#include	"FEATURE/cmds"
#ifdef _hdr_utime
#   include	<utime.h>
#   include	<ls.h>
#endif

#if KSHELL
#   include	"defs.h"
#   include	"variables.h"
#else
#   include	<ctype.h>
    extern char ed_errbuf[];
    char e_version[] = "\n@(#)$Id: Editlib version 1993-12-28 r $\0\n";
#endif	/* KSHELL */
#include	"io.h"
#include	"terminal.h"
#include	"history.h"
#include	"edit.h"

static char CURSOR_UP[20] = { ESC, '[', 'A', 0 };



#if SHOPT_MULTIBYTE
#   define is_cntrl(c)	((c<=STRIP) && iscntrl(c))
#   define is_print(c)	((c&~STRIP) || isprint(c))
#else
#   define is_cntrl(c)	iscntrl(c)
#   define is_print(c)	isprint(c)
#endif

#if	(CC_NATIVE == CC_ASCII)
#   define printchar(c)	((c) ^ ('A'-cntl('A')))
#else
    static int printchar(int c)
    {
	switch(c)
	{
	    
	    case cntl('A'): return('A');
	    case cntl('B'): return('B');
	    case cntl('C'): return('C');
	    case cntl('D'): return('D');
	    case cntl('E'): return('E');
	    case cntl('F'): return('F');
	    case cntl('G'): return('G');
	    case cntl('H'): return('H');
	    case cntl('I'): return('I');
	    case cntl('J'): return('J');
	    case cntl('K'): return('K');
	    case cntl('L'): return('L');
	    case cntl('M'): return('M');
	    case cntl('N'): return('N');
	    case cntl('O'): return('O');
	    case cntl('P'): return('P');
	    case cntl('Q'): return('Q');
	    case cntl('R'): return('R');
	    case cntl('S'): return('S');
	    case cntl('T'): return('T');
	    case cntl('U'): return('U');
	    case cntl('V'): return('V');
	    case cntl('W'): return('W');
	    case cntl('X'): return('X');
	    case cntl('Y'): return('Y');
	    case cntl('Z'): return('Z');
	    case cntl(']'): return(']');
	    case cntl('['): return('[');
	}
	return('?');
    }
#endif
#define MINWINDOW	15	/* minimum width window */
#define DFLTWINDOW	80	/* default window width */
#define RAWMODE		1
#define ALTMODE		2
#define ECHOMODE	3
#define	SYSERR	-1

#if SHOPT_OLDTERMIO
#   undef tcgetattr
#   undef tcsetattr
#endif /* SHOPT_OLDTERMIO */

#ifdef RT
#   define VENIX 1
#endif	/* RT */


#ifdef _hdr_sgtty
#   ifdef TIOCGETP
	static int l_mask;
	static struct tchars l_ttychars;
	static struct ltchars l_chars;
	static  char  l_changed;	/* set if mode bits changed */
#	define L_CHARS	4
#	define T_CHARS	2
#	define L_MASK	1
#   endif /* TIOCGETP */
#endif /* _hdr_sgtty */

#if KSHELL
     static int keytrap(Edit_t *,char*, int, int, int);
#else
     Edit_t editb;
#endif	/* KSHELL */


#ifndef _POSIX_DISABLE
#   define _POSIX_DISABLE	0
#endif

#ifdef future
    static int compare(const char*, const char*, int);
#endif  /* future */
#if SHOPT_VSH || SHOPT_ESH
#   define ttyparm	(ep->e_ttyparm)
#   define nttyparm	(ep->e_nttyparm)
    static const char bellchr[] = "\a";	/* bell char */
#endif /* SHOPT_VSH || SHOPT_ESH */


/*
 * This routine returns true if fd refers to a terminal
 * This should be equivalent to isatty
 */
int tty_check(int fd)
{
	register Edit_t *ep = (Edit_t*)(sh_getinterp()->ed_context);
	struct termios tty;
	ep->e_savefd = -1;
	return(tty_get(fd,&tty)==0);
}

/*
 * Get the current terminal attributes
 * This routine remembers the attributes and just returns them if it
 *   is called again without an intervening tty_set()
 */

int tty_get(register int fd, register struct termios *tty)
{
	register Edit_t *ep = (Edit_t*)(sh_getinterp()->ed_context);
	if(fd == ep->e_savefd)
		*tty = ep->e_savetty;
	else
	{
		while(tcgetattr(fd,tty) == SYSERR)
		{
			if(errno !=EINTR)
				return(SYSERR);
			errno = 0;
		}
		/* save terminal settings if in cannonical state */
		if(ep->e_raw==0)
		{
			ep->e_savetty = *tty;
			ep->e_savefd = fd;
		}
	}
	return(0);
}

/*
 * Set the terminal attributes
 * If fd<0, then current attributes are invalidated
 */

int tty_set(int fd, int action, struct termios *tty)
{
	register Edit_t *ep = (Edit_t*)(sh_getinterp()->ed_context);
	if(fd >=0)
	{
#ifdef future
		if(ep->e_savefd>=0 && compare(&ep->e_savetty,tty,sizeof(struct termios)))
			return(0);
#endif
		while(tcsetattr(fd, action, tty) == SYSERR)
		{
			if(errno !=EINTR)
				return(SYSERR);
			errno = 0;
		}
		ep->e_savetty = *tty;
	}
	ep->e_savefd = fd;
	return(0);
}

#if SHOPT_ESH || SHOPT_VSH
/*{	TTY_COOKED( fd )
 *
 *	This routine will set the tty in cooked mode.
 *	It is also called by error.done().
 *
}*/

void tty_cooked(register int fd)
{
	register Edit_t *ep = (Edit_t*)(sh_getinterp()->ed_context);
	if(ep->e_raw==0)
		return;
	if(fd < 0)
		fd = ep->e_savefd;
#ifdef L_MASK
	/* restore flags */
	if(l_changed&L_MASK)
		ioctl(fd,TIOCLSET,&l_mask);
	if(l_changed&T_CHARS)
		/* restore alternate break character */
		ioctl(fd,TIOCSETC,&l_ttychars);
	if(l_changed&L_CHARS)
		/* restore alternate break character */
		ioctl(fd,TIOCSLTC,&l_chars);
	l_changed = 0;
#endif	/* L_MASK */
	/*** don't do tty_set unless ttyparm has valid data ***/
	if(tty_set(fd, TCSANOW, &ttyparm) == SYSERR)
		return;
	ep->e_raw = 0;
	return;
}

/*{	TTY_RAW( fd )
 *
 *	This routine will set the tty in raw mode.
 *
}*/

int tty_raw(register int fd, int echomode)
{
	int echo = echomode;
#ifdef L_MASK
	struct ltchars lchars;
#endif	/* L_MASK */
	register Edit_t *ep = (Edit_t*)(sh_getinterp()->ed_context);
	if(ep->e_raw==RAWMODE)
		return(echo?-1:0);
	else if(ep->e_raw==ECHOMODE)
		return(echo?0:-1);
#if !SHOPT_RAWONLY
	if(ep->e_raw != ALTMODE)
#endif /* SHOPT_RAWONLY */
	{
		if(tty_get(fd,&ttyparm) == SYSERR)
			return(-1);
	}
#if  L_MASK || VENIX
	if(ttyparm.sg_flags&LCASE)
		return(-1);
	if(!(ttyparm.sg_flags&ECHO))
	{
		if(!echomode)
			return(-1);
		echo = 0;
	}
	nttyparm = ttyparm;
	if(!echo)
		nttyparm.sg_flags &= ~(ECHO | TBDELAY);
#   ifdef CBREAK
	nttyparm.sg_flags |= CBREAK;
#   else
	nttyparm.sg_flags |= RAW;
#   endif /* CBREAK */
	ep->e_erase = ttyparm.sg_erase;
	ep->e_kill = ttyparm.sg_kill;
	ep->e_eof = cntl('D');
	ep->e_werase = cntl('W');
	ep->e_lnext = cntl('V');
	if( tty_set(fd, TCSADRAIN, &nttyparm) == SYSERR )
		return(-1);
	ep->e_ttyspeed = (ttyparm.sg_ospeed>=B1200?FAST:SLOW);
#   ifdef TIOCGLTC
	/* try to remove effect of ^V  and ^Y and ^O */
	if(ioctl(fd,TIOCGLTC,&l_chars) != SYSERR)
	{
		lchars = l_chars;
		lchars.t_lnextc = -1;
		lchars.t_flushc = -1;
		lchars.t_dsuspc = -1;	/* no delayed stop process signal */
		if(ioctl(fd,TIOCSLTC,&lchars) != SYSERR)
			l_changed |= L_CHARS;
	}
#   endif	/* TIOCGLTC */
#else
	if (!(ttyparm.c_lflag & ECHO ))
	{
		if(!echomode)
			return(-1);
		echo = 0;
	}
#   ifdef FLUSHO
	ttyparm.c_lflag &= ~FLUSHO;
#   endif /* FLUSHO */
	nttyparm = ttyparm;
#  ifndef u370
	nttyparm.c_iflag &= ~(IGNPAR|PARMRK|INLCR|IGNCR|ICRNL);
	nttyparm.c_iflag |= BRKINT;
#   else
	nttyparm.c_iflag &= 
			~(IGNBRK|PARMRK|INLCR|IGNCR|ICRNL|INPCK);
	nttyparm.c_iflag |= (BRKINT|IGNPAR);
#   endif	/* u370 */
	if(echo)
		nttyparm.c_lflag &= ~ICANON;
	else
		nttyparm.c_lflag &= ~(ICANON|ECHO|ECHOK);
	nttyparm.c_cc[VTIME] = 0;
	nttyparm.c_cc[VMIN] = 1;
#   ifdef VREPRINT
	nttyparm.c_cc[VREPRINT] = _POSIX_DISABLE;
#   endif /* VREPRINT */
#   ifdef VDISCARD
	nttyparm.c_cc[VDISCARD] = _POSIX_DISABLE;
#   endif /* VDISCARD */
#   ifdef VDSUSP
	nttyparm.c_cc[VDSUSP] = _POSIX_DISABLE;
#   endif /* VDSUSP */
#   ifdef VWERASE
	if(ttyparm.c_cc[VWERASE] == _POSIX_DISABLE)
		ep->e_werase = cntl('W');
	else
		ep->e_werase = nttyparm.c_cc[VWERASE];
	nttyparm.c_cc[VWERASE] = _POSIX_DISABLE;
#   else
	    ep->e_werase = cntl('W');
#   endif /* VWERASE */
#   ifdef VLNEXT
	if(ttyparm.c_cc[VLNEXT] == _POSIX_DISABLE )
		ep->e_lnext = cntl('V');
	else
		ep->e_lnext = nttyparm.c_cc[VLNEXT];
	nttyparm.c_cc[VLNEXT] = _POSIX_DISABLE;
#   else
	ep->e_lnext = cntl('V');
#   endif /* VLNEXT */
	ep->e_eof = ttyparm.c_cc[VEOF];
	ep->e_erase = ttyparm.c_cc[VERASE];
	ep->e_kill = ttyparm.c_cc[VKILL];
	if( tty_set(fd, TCSADRAIN, &nttyparm) == SYSERR )
		return(-1);
	ep->e_ttyspeed = (cfgetospeed(&ttyparm)>=B1200?FAST:SLOW);
#endif
	ep->e_raw = (echomode?ECHOMODE:RAWMODE);
	return(0);
}

#if !SHOPT_RAWONLY

/*
 *
 *	Get tty parameters and make ESC and '\r' wakeup characters.
 *
 */

#   ifdef TIOCGETC
int tty_alt(register int fd)
{
	register Edit_t *ep = (Edit_t*)(sh_getinterp()->ed_context);
	int mask;
	struct tchars ttychars;
	switch(ep->e_raw)
	{
	    case ECHOMODE:
		return(-1);
	    case ALTMODE:
		return(0);
	    case RAWMODE:
		tty_cooked(fd);
	}
	l_changed = 0;
	if( ep->e_ttyspeed == 0)
	{
		if((tty_get(fd,&ttyparm) != SYSERR))
			ep->e_ttyspeed = (ttyparm.sg_ospeed>=B1200?FAST:SLOW);
		ep->e_raw = ALTMODE;
	}
	if(ioctl(fd,TIOCGETC,&l_ttychars) == SYSERR)
		return(-1);
	if(ioctl(fd,TIOCLGET,&l_mask)==SYSERR)
		return(-1);
	ttychars = l_ttychars;
	mask =  LCRTBS|LCRTERA|LCTLECH|LPENDIN|LCRTKIL;
	if((l_mask|mask) != l_mask)
		l_changed = L_MASK;
	if(ioctl(fd,TIOCLBIS,&mask)==SYSERR)
		return(-1);
	if(ttychars.t_brkc!=ESC)
	{
		ttychars.t_brkc = ESC;
		l_changed |= T_CHARS;
		if(ioctl(fd,TIOCSETC,&ttychars) == SYSERR)
			return(-1);
	}
	return(0);
}
#   else
#	ifndef PENDIN
#	    define PENDIN	0
#	endif /* PENDIN */
#	ifndef IEXTEN
#	    define IEXTEN	0
#	endif /* IEXTEN */

int tty_alt(register int fd)
{
	register Edit_t *ep = (Edit_t*)(sh_getinterp()->ed_context);
	switch(ep->e_raw)
	{
	    case ECHOMODE:
		return(-1);
	    case ALTMODE:
		return(0);
	    case RAWMODE:
		tty_cooked(fd);
	}
	if((tty_get(fd, &ttyparm)==SYSERR) || (!(ttyparm.c_lflag&ECHO)))
		return(-1);
#	ifdef FLUSHO
	    ttyparm.c_lflag &= ~FLUSHO;
#	endif /* FLUSHO */
	nttyparm = ttyparm;
	ep->e_eof = ttyparm.c_cc[VEOF];
#	ifdef ECHOCTL
	    /* escape character echos as ^[ */
	    nttyparm.c_lflag |= (ECHOE|ECHOK|ECHOCTL|PENDIN|IEXTEN);
	    nttyparm.c_cc[VEOL] = ESC;
#	else
	    /* switch VEOL2 and EOF, since EOF isn't echo'd by driver */
	    nttyparm.c_lflag |= (ECHOE|ECHOK);
	    nttyparm.c_cc[VEOF] = ESC;	/* make ESC the eof char */
#	    ifdef VEOL2
		nttyparm.c_iflag &= ~(IGNCR|ICRNL);
		nttyparm.c_iflag |= INLCR;
		nttyparm.c_cc[VEOL] = '\r';	/* make CR an eol char */
		nttyparm.c_cc[VEOL2] = ep->e_eof; /* make EOF an eol char */
#	    else
		nttyparm.c_cc[VEOL] = ep->e_eof; /* make EOF an eol char */
#	    endif /* VEOL2 */
#	endif /* ECHOCTL */
#	ifdef VREPRINT
		nttyparm.c_cc[VREPRINT] = _POSIX_DISABLE;
#	endif /* VREPRINT */
#	ifdef VDISCARD
		nttyparm.c_cc[VDISCARD] = _POSIX_DISABLE;
#	endif /* VDISCARD */
#	ifdef VWERASE
	    if(ttyparm.c_cc[VWERASE] == _POSIX_DISABLE)
		    nttyparm.c_cc[VWERASE] = cntl('W');
	    ep->e_werase = nttyparm.c_cc[VWERASE];
#	else
	    ep->e_werase = cntl('W');
#	endif /* VWERASE */
#	ifdef VLNEXT
	    if(ttyparm.c_cc[VLNEXT] == _POSIX_DISABLE )
		    nttyparm.c_cc[VLNEXT] = cntl('V');
	    ep->e_lnext = nttyparm.c_cc[VLNEXT];
#	else
	    ep->e_lnext = cntl('V');
#	endif /* VLNEXT */
	ep->e_erase = ttyparm.c_cc[VERASE];
	ep->e_kill = ttyparm.c_cc[VKILL];
	if( tty_set(fd, TCSADRAIN, &nttyparm) == SYSERR )
		return(-1);
	ep->e_ttyspeed = (cfgetospeed(&ttyparm)>=B1200?FAST:SLOW);
	ep->e_raw = ALTMODE;
	return(0);
}

#   endif /* TIOCGETC */
#endif	/* SHOPT_RAWONLY */

/*
 *	ED_WINDOW()
 *
 *	return the window size
 */
int ed_window(void)
{
	int	rows,cols;
	register char *cp = nv_getval(COLUMNS);
	if(cp)
		cols = (int)strtol(cp, (char**)0, 10)-1;
	else
	{
		astwinsize(2,&rows,&cols);
		if(--cols <0)
			cols = DFLTWINDOW-1;
	}
	if(cols < MINWINDOW)
		cols = MINWINDOW;
	else if(cols > MAXWINDOW)
		cols = MAXWINDOW;
	return(cols);
}

/*	E_FLUSH()
 *
 *	Flush the output buffer.
 *
 */

void ed_flush(Edit_t *ep)
{
	register int n = ep->e_outptr-ep->e_outbase;
	register int fd = ERRIO;
	if(n<=0)
		return;
	write(fd,ep->e_outbase,(unsigned)n);
	ep->e_outptr = ep->e_outbase;
}

/*
 * send the bell character ^G to the terminal
 */

void ed_ringbell(void)
{
	write(ERRIO,bellchr,1);
}

/*
 * send a carriage return line feed to the terminal
 */

void ed_crlf(register Edit_t *ep)
{
#ifdef cray
	ed_putchar(ep,'\r');
#endif /* cray */
#ifdef u370
	ed_putchar(ep,'\r');
#endif	/* u370 */
#ifdef VENIX
	ed_putchar(ep,'\r');
#endif /* VENIX */
	ed_putchar(ep,'\n');
	ed_flush(ep);
}
 
/*	ED_SETUP( max_prompt_size )
 *
 *	This routine sets up the prompt string
 *	The following is an unadvertised feature.
 *	  Escape sequences in the prompt can be excluded from the calculated
 *	  prompt length.  This is accomplished as follows:
 *	  - if the prompt string starts with "%\r, or contains \r%\r", where %
 *	    represents any char, then % is taken to be the quote character.
 *	  - strings enclosed by this quote character, and the quote character,
 *	    are not counted as part of the prompt length.
 */

void	ed_setup(register Edit_t *ep, int fd, int reedit)
{
	Shell_t *shp = ep->sh;
	register char *pp;
	register char *last, *prev;
	char *ppmax;
	int myquote = 0, n;
	register int qlen = 1, qwid;
	char inquote = 0;
	ep->e_fd = fd;
	ep->e_multiline = sh_isoption(SH_MULTILINE)!=0;
#ifdef SIGWINCH
	if(!(shp->sigflag[SIGWINCH]&SH_SIGFAULT))
	{
		signal(SIGWINCH,sh_fault);
		shp->sigflag[SIGWINCH] |= SH_SIGFAULT;
	}
	pp = shp->st.trapcom[SIGWINCH];
	shp->st.trapcom[SIGWINCH] = 0;
	sh_fault(SIGWINCH);
	shp->st.trapcom[SIGWINCH] = pp;
	ep->sh->winch = 0;
#endif
#if KSHELL
	ep->e_stkptr = stakptr(0);
	ep->e_stkoff = staktell();
	if(!(last = shp->prompt))
		last = "";
	shp->prompt = 0;
#else
	last = ep->e_prbuff;
#endif /* KSHELL */
	if(shp->hist_ptr)
	{
		register History_t *hp = shp->hist_ptr;
		ep->e_hismax = hist_max(hp);
		ep->e_hismin = hist_min(hp);
	}
	else
	{
		ep->e_hismax = ep->e_hismin = ep->e_hloff = 0;
	}
	ep->e_hline = ep->e_hismax;
	if(!sh_isoption(SH_VI) && !sh_isoption(SH_EMACS) && !sh_isoption(SH_GMACS))
		ep->e_wsize = MAXLINE;
	else
		ep->e_wsize = ed_window()-2;
	ep->e_winsz = ep->e_wsize+2;
	ep->e_crlf = 1;
	ep->e_plen = 0;
	pp = ep->e_prompt;
	ppmax = pp+PRSIZE-1;
	*pp++ = '\r';
	{
		register int c;
		while(prev = last, c = mbchar(last)) switch(c)
		{
			case ESC:
			{
				int skip=0;
				ep->e_crlf = 0;
				*pp++ = c;
				for(n=1; c = *last++; n++)
				{
					if(pp < ppmax)
						*pp++ = c;
					if(c=='\a' || c==ESC || c=='\r')
						break;
					if(skip || (c>='0' && c<='9'))
						continue;
					if(n>1 && c==';')
						skip = 1;
					else if(n>2 || (c!= '[' &&  c!= ']'))
						break;
				}
				if(c==0 || c==ESC || c=='\r')
					last--;
				qlen += (n+1);
				break;
			}
			case '\b':
				if(pp>ep->e_prompt+1)
					pp--;
				break;
			case '\r':
				if(pp == (ep->e_prompt+2)) /* quote char */
					myquote = *(pp-1);
				/*FALLTHROUGH*/

			case '\n':
				/* start again */
				ep->e_crlf = 1;
				qlen = 1;
				inquote = 0;
				pp = ep->e_prompt+1;
				break;

			case '\t':
				/* expand tabs */
				while((pp-ep->e_prompt)%TABSIZE)
				{
					if(pp >= ppmax)
						break;
					*pp++ = ' ';
				}
				break;

			case '\a':
				/* cut out bells */
				break;

			default:
				if(c==myquote)
				{
					qlen += inquote;
					inquote ^= 1;
				}
				if(pp < ppmax)
				{
					if(inquote)
						qlen++;
					else if(!is_print(c))
						ep->e_crlf = 0;
					if((qwid = last - prev) > 1)
						qlen += qwid - mbwidth(c);
					while(prev < last && pp < ppmax)
						*pp++ = *prev++;
				}
				break;
		}
	}
	if(pp-ep->e_prompt > qlen)
		ep->e_plen = pp - ep->e_prompt - qlen;
	*pp = 0;
	if(!ep->e_multiline && (ep->e_wsize -= ep->e_plen) < 7)
	{
		register int shift = 7-ep->e_wsize;
		ep->e_wsize = 7;
		pp = ep->e_prompt+1;
		strcpy(pp,pp+shift);
		ep->e_plen -= shift;
		last[-ep->e_plen-2] = '\r';
	}
	sfsync(sfstderr);
	if(fd == sffileno(sfstderr))
	{
		/* can't use output buffer when reading from stderr */
		static char *buff;
		if(!buff)
			buff = (char*)malloc(MAXLINE);
		ep->e_outbase = ep->e_outptr = buff;
		ep->e_outlast = ep->e_outptr + MAXLINE;
		return;
	}
	qlen = sfset(sfstderr,SF_READ,0);
	/* make sure SF_READ not on */
	ep->e_outbase = ep->e_outptr = (char*)sfreserve(sfstderr,SF_UNBOUND,SF_LOCKR);
	ep->e_outlast = ep->e_outptr + sfvalue(sfstderr);
	if(qlen)
		sfset(sfstderr,SF_READ,1);
	sfwrite(sfstderr,ep->e_outptr,0);
	ep->e_eol = reedit;
	if(ep->e_multiline)
	{
#ifdef _cmd_tput
		char *term;
		if(!ep->e_term)
			ep->e_term = nv_search("TERM",shp->var_tree,0);
		if(ep->e_term && (term=nv_getval(ep->e_term)) && strlen(term)<sizeof(ep->e_termname) && strcmp(term,ep->e_termname))
		{
			sh_trap(".sh.subscript=$(tput cuu1 2>/dev/null)",0);
			if(pp=nv_getval(SH_SUBSCRNOD))
				strncpy(CURSOR_UP,pp,sizeof(CURSOR_UP)-1);
			nv_unset(SH_SUBSCRNOD);
			strcpy(ep->e_termname,term);
		}
#endif
		ep->e_wsize = MAXLINE - (ep->e_plen+1);
	}
	if(ep->e_default && (pp = nv_getval(ep->e_default)))
	{
		n = strlen(pp);
		if(n > LOOKAHEAD)
			n = LOOKAHEAD;
		ep->e_lookahead = n;
		while(n-- > 0)
			ep->e_lbuf[n] = *pp++;
		ep->e_default = 0;
	}
}

static void ed_putstring(register Edit_t *ep, const char *str)
{
	register int c;
	while(c = *str++)
		ed_putchar(ep,c);
}

static void ed_nputchar(register Edit_t *ep, int n, int c)
{
	while(n-->0)
		ed_putchar(ep,c);
}

/*
 * Do read, restart on interrupt unless SH_SIGSET or SH_SIGTRAP is set
 * Use sfpkrd() to poll() or select() to wait for input if possible
 * Unfortunately, systems that get interrupted from slow reads update
 * this access time for for the terminal (in violation of POSIX).
 * The fixtime() macro, resets the time to the time at entry in
 * this case.  This is not necessary for systems that can handle
 * sfpkrd() correctly (i,e., those that support poll() or select()
 */
int ed_read(void *context, int fd, char *buff, int size, int reedit)
{
	register Edit_t *ep = (Edit_t*)context;
	register int rv= -1;
	register int delim = (ep->e_raw==RAWMODE?'\r':'\n');
	Shell_t *shp = ep->sh;
	int mode = -1;
	int (*waitevent)(int,long,int) = shp->waitevent;
	if(ep->e_raw==ALTMODE)
		mode = 1;
	if(size < 0)
	{
		mode = 1;
		size = -size;
	}
	sh_onstate(SH_TTYWAIT);
	errno = EINTR;
	shp->waitevent = 0;
	while(rv<0 && errno==EINTR)
	{
		if(shp->trapnote&(SH_SIGSET|SH_SIGTRAP))
			goto done;
		if(ep->sh->winch && sh_isstate(SH_INTERACTIVE) && (sh_isoption(SH_VI) || sh_isoption(SH_EMACS)))
		{
			Edpos_t	lastpos;
			int	n, rows, newsize;
			/* move cursor to start of first line */
			ed_putchar(ep,'\r');
			ed_flush(ep);
			astwinsize(2,&rows,&newsize);
			n = (ep->e_plen+ep->e_cur)/++ep->e_winsz;
			while(n--)
				ed_putstring(ep,CURSOR_UP);
			if(ep->e_multiline && newsize>ep->e_winsz && (lastpos.line=(ep->e_plen+ep->e_peol)/ep->e_winsz))
			{
				/* clear the current command line */
				n = lastpos.line;
				while(lastpos.line--)
				{
					ed_nputchar(ep,ep->e_winsz,' ');
					ed_putchar(ep,'\n');
				}
				ed_nputchar(ep,ep->e_winsz,' ');
				while(n--)
					ed_putstring(ep,CURSOR_UP);
			}
	                ep->sh->winch = 0;
			ed_flush(ep);
			sh_delay(.05);
			astwinsize(2,&rows,&newsize);
			ep->e_winsz = newsize-1;
			if(!ep->e_multiline && ep->e_wsize < MAXLINE)
				ep->e_wsize = ep->e_winsz-2;
			ep->e_nocrnl=1;
			if(*ep->e_vi_insert)
			{
				buff[0] = ESC;
				buff[1] = cntl('L');
				buff[2] = 'a';
				return(3);
			}
			if(sh_isoption(SH_EMACS) || sh_isoption(SH_VI))
				buff[0] = cntl('L');
			return(1);
		}
		else
			ep->sh->winch = 0;
		/* an interrupt that should be ignored */
		errno = 0;
		if(!waitevent || (rv=(*waitevent)(fd,-1L,0))>=0)
			rv = sfpkrd(fd,buff,size,delim,-1L,mode);
	}
	if(rv < 0)
	{
#ifdef _hdr_utime
#		define fixtime()	if(isdevtty)utime(ep->e_tty,&utimes)
		int	isdevtty=0;
		struct stat statb;
		struct utimbuf utimes;
	 	if(errno==0 && !ep->e_tty)
		{
			if((ep->e_tty=ttyname(fd)) && stat(ep->e_tty,&statb)>=0)
			{
				ep->e_tty_ino = statb.st_ino;
				ep->e_tty_dev = statb.st_dev;
			}
		}
		if(ep->e_tty_ino && fstat(fd,&statb)>=0 && statb.st_ino==ep->e_tty_ino && statb.st_dev==ep->e_tty_dev)
		{
			utimes.actime = statb.st_atime;
			utimes.modtime = statb.st_mtime;
			isdevtty=1;
		}
#else
#		define fixtime()
#endif /* _hdr_utime */
		while(1)
		{
			rv = read(fd,buff,size);
			if(rv>=0 || errno!=EINTR)
				break;
			if(shp->trapnote&(SH_SIGSET|SH_SIGTRAP))
				goto done;
			/* an interrupt that should be ignored */
			fixtime();
		}
	}
	else if(rv>=0 && mode>0)
		rv = read(fd,buff,rv>0?rv:1);
done:
	shp->waitevent = waitevent;
	sh_offstate(SH_TTYWAIT);
	return(rv);
}


/*
 * put <string> of length <nbyte> onto lookahead stack
 * if <type> is non-zero,  the negation of the character is put
 *    onto the stack so that it can be checked for KEYTRAP
 * putstack() returns 1 except when in the middle of a multi-byte char
 */
static int putstack(Edit_t *ep,char string[], register int nbyte, int type) 
{
	register int c;
#if SHOPT_MULTIBYTE
	char *endp, *p=string;
	int size, offset = ep->e_lookahead + nbyte;
	*(endp = &p[nbyte]) = 0;
	endp = &p[nbyte];
	do
	{
		c = (int)((*p) & STRIP);
		if(c< 0x80 && c!='<')
		{
			if (type)
				c = -c;
#   ifndef CBREAK
			if(c == '\0')
			{
				/*** user break key ***/
				ep->e_lookahead = 0;
#	if KSHELL
				sh_fault(SIGINT);
				siglongjmp(ep->e_env, UINTR);
#	endif   /* KSHELL */
			}
#   endif /* CBREAK */

		}
		else
		{
		again:
			if((c=mbchar(p)) >=0)
			{
				p--;	/* incremented below */
				if(type)
					c = -c;
			}
#ifdef EILSEQ
			else if(errno == EILSEQ)
				errno = 0;
#endif
			else if((endp-p) < mbmax())
			{
				if ((c=ed_read(ep,ep->e_fd,endp, 1,0)) == 1)
				{
					*++endp = 0;
					goto again;
				}
				return(c);
			}
			else
			{
				ed_ringbell();
				c = -(int)((*p) & STRIP);
				offset += mbmax()-1;
			}
		}
		ep->e_lbuf[--offset] = c;
		p++;
	}
	while (p < endp);
	/* shift lookahead buffer if necessary */
	if(offset -= ep->e_lookahead)
	{
		for(size=offset;size < nbyte;size++)
			ep->e_lbuf[ep->e_lookahead+size-offset] = ep->e_lbuf[ep->e_lookahead+size];
	}
	ep->e_lookahead += nbyte-offset;
#else
	while (nbyte > 0)
	{
		c = string[--nbyte] & STRIP;
		ep->e_lbuf[ep->e_lookahead++] = (type?-c:c);
#   ifndef CBREAK
		if( c == '\0' )
		{
			/*** user break key ***/
			ep->e_lookahead = 0;
#	if KSHELL
			sh_fault(SIGINT);
			siglongjmp(ep->e_env, UINTR);
#	endif	/* KSHELL */
		}
#   endif /* CBREAK */
	}
#endif /* SHOPT_MULTIBYTE */
	return(1);
}

/*
 * routine to perform read from terminal for vi and emacs mode
 * <mode> can be one of the following:
 *   -2		vi insert mode - key binding is in effect
 *   -1		vi control mode - key binding is in effect
 *   0		normal command mode - key binding is in effect
 *   1		edit keys not mapped
 *   2		Next key is literal
 */
int ed_getchar(register Edit_t *ep,int mode)
{
	register int n, c;
	char readin[LOOKAHEAD+1];
	if(!ep->e_lookahead)
	{
		ed_flush(ep);
		ep->e_inmacro = 0;
		/* The while is necessary for reads of partial multbyte chars */
		*ep->e_vi_insert = (mode==-2);
		if((n=ed_read(ep,ep->e_fd,readin,-LOOKAHEAD,0)) > 0)
			n = putstack(ep,readin,n,1);
		*ep->e_vi_insert = 0;
	}
	if(ep->e_lookahead)
	{
		/* check for possible key mapping */
		if((c = ep->e_lbuf[--ep->e_lookahead]) < 0)
		{
			if(mode<=0 && ep->sh->st.trap[SH_KEYTRAP])
			{
				n=1;
				if((readin[0]= -c) == ESC)
				{
					while(1)
					{
						if(!ep->e_lookahead)
						{
							if((c=sfpkrd(ep->e_fd,readin+n,1,'\r',(mode?400L:-1L),0))>0)
								putstack(ep,readin+n,c,1);
						}
						if(!ep->e_lookahead)
							break;
						if((c=ep->e_lbuf[--ep->e_lookahead])>=0)
						{
							ep->e_lookahead++;
							break;
						}
						c = -c;
						readin[n++] = c;
						if(c>='0' && c<='9' && n>2)
							continue;
						if(n>2 || (c!= '['  &&  c!= 'O'))
							break;
					}
				}
				if(n=keytrap(ep,readin,n,LOOKAHEAD-n,mode))
				{
					putstack(ep,readin,n,0);
					c = ep->e_lbuf[--ep->e_lookahead];
				}
				else
					c = ed_getchar(ep,mode);
			}
			else
				c = -c;
		}
		/*** map '\r' to '\n' ***/
		if(c == '\r' && mode!=2)
			c = '\n';
		if(ep->e_tabcount && !(c=='\t'||c==ESC || c=='\\' || c=='=' || c==cntl('L') || isdigit(c)))
			ep->e_tabcount = 0;
	}
	else
		siglongjmp(ep->e_env,(n==0?UEOF:UINTR));
	return(c);
}

void ed_ungetchar(Edit_t *ep,register int c)
{
	if (ep->e_lookahead < LOOKAHEAD)
		ep->e_lbuf[ep->e_lookahead++] = c;
	return;
}

/*
 * put a character into the output buffer
 */

void	ed_putchar(register Edit_t *ep,register int c)
{
	char buf[8];
	register char *dp = ep->e_outptr;
	register int i,size=1;
	if(!dp)
		return;
	buf[0] = c;
#if SHOPT_MULTIBYTE
	/* check for place holder */
	if(c == MARKER)
		return;
	if((size = mbconv(buf, (wchar_t)c)) > 1)
	{
		for (i = 0; i < (size-1); i++)
			*dp++ = buf[i];
		c = buf[i];
	}
	else
	{
		buf[0] = c;
		size = 1;
	}
#endif	/* SHOPT_MULTIBYTE */
	if (buf[0] == '_' && size==1)
	{
		*dp++ = ' ';
		*dp++ = '\b';
	}
	*dp++ = c;
	*dp = '\0';
	if(dp >= ep->e_outlast)
		ed_flush(ep);
	else
		ep->e_outptr = dp;
}

/*
 * returns the line and column corresponding to offset <off> in the physical buffer
 * if <cur> is non-zero and <= <off>, then correspodning <curpos> will start the search 
 */
Edpos_t ed_curpos(Edit_t *ep,genchar *phys, int off, int cur, Edpos_t curpos)
{
	register genchar *sp=phys;
	register int c=1, col=ep->e_plen;
	Edpos_t pos;
#if SHOPT_MULTIBYTE
	char p[16];
#endif /* SHOPT_MULTIBYTE */
	if(cur && off>=cur)
	{
		sp += cur; 
		off -= cur;
		pos = curpos;
		col = pos.col;
	}
	else
	{
		pos.line = 0;
		while(col > ep->e_winsz)
		{
			pos.line++;
			col -= (ep->e_winsz+1);
		}
	}
	while(off-->0)
	{
		if(c)
			c = *sp++;
#if SHOPT_MULTIBYTE
		if(c && (mbconv(p, (wchar_t)c))==1 && p[0]=='\n')
#else
		if(c=='\n')
#endif /* SHOPT_MULTIBYTE */
			col = 0;
		else
			col++;
		if(col >  ep->e_winsz)
			col = 0;
		if(col==0)
			pos.line++;
	}
	pos.col = col;
	return(pos);
}

int ed_setcursor(register Edit_t *ep,genchar *physical,register int old,register int new,int first)
{
	static int oldline;
	register int delta;
	int clear = 0;
	Edpos_t newpos;

	delta = new - old;
	if(first < 0)
	{
		first = 0;
		clear = 1;
	}
	if( delta == 0  &&  !clear)
		return(new);
	if(ep->e_multiline)
	{
		ep->e_curpos = ed_curpos(ep, physical, old,0,ep->e_curpos);
		if(clear && old>=ep->e_peol && (clear=ep->e_winsz-ep->e_curpos.col)>0)
		{
			ed_nputchar(ep,clear,' ');
			ed_nputchar(ep,clear,'\b');
			return(new);
		}
		newpos =     ed_curpos(ep, physical, new,old,ep->e_curpos);
		if(ep->e_curpos.col==0 && ep->e_curpos.line>0 && oldline<ep->e_curpos.line && delta<0)
			ed_putstring(ep,"\r\n");
		oldline = newpos.line;
		if(ep->e_curpos.line > newpos.line)
		{
			int n,pline,plen=ep->e_plen;
			for(;ep->e_curpos.line > newpos.line; ep->e_curpos.line--)
				ed_putstring(ep,CURSOR_UP);
			pline = plen/(ep->e_winsz+1);
			if(newpos.line <= pline)
				plen -= pline*(ep->e_winsz+1);
			else
				plen = 0;
			if((n=plen- ep->e_curpos.col)>0)
			{
				ep->e_curpos.col += n;
				ed_putchar(ep,'\r');
				if(!ep->e_crlf && pline==0)
					ed_putstring(ep,ep->e_prompt);
				else
				{
					int m = ep->e_winsz+1-plen;
					ed_putchar(ep,'\n');
					n = plen;
					if(m < ed_genlen(physical))
					{
						while(physical[m] && n-->0)
							ed_putchar(ep,physical[m++]);
					}
					ed_nputchar(ep,n,' ');
					ed_putstring(ep,CURSOR_UP);
				}
			}
		}
		else if(ep->e_curpos.line < newpos.line)
		{
			ed_nputchar(ep, newpos.line-ep->e_curpos.line,'\n');
			ep->e_curpos.line = newpos.line;
			ed_putchar(ep,'\r');
			ep->e_curpos.col = 0;
		}
		delta = newpos.col - ep->e_curpos.col;
		old   =  new - delta;
	}
	else
		newpos.line=0;
	if(delta<0)
	{
		int bs= newpos.line && ep->e_plen>ep->e_winsz;
		/*** move to left ***/
		delta = -delta;
		/*** attempt to optimize cursor movement ***/
		if(!ep->e_crlf || bs || (2*delta <= ((old-first)+(newpos.line?0:ep->e_plen))) )
		{
			ed_nputchar(ep,delta,'\b');
			delta = 0;
		}
		else
		{
			if(newpos.line==0)
				ed_putstring(ep,ep->e_prompt);
			else
			{
				first = 1+(newpos.line*ep->e_winsz - ep->e_plen);
				ed_putchar(ep,'\r');
			}
			old = first;
			delta = new-first;
		}
	}
	while(delta-->0)
		ed_putchar(ep,physical[old++]);
	return(new);
}

/*
 * copy virtual to physical and return the index for cursor in physical buffer
 */
int ed_virt_to_phys(Edit_t *ep,genchar *virt,genchar *phys,int cur,int voff,int poff)
{
	register genchar *sp = virt;
	register genchar *dp = phys;
	register int c;
	genchar *curp = sp + cur;
	genchar *dpmax = phys+MAXLINE;
	int d, r;
	sp += voff;
	dp += poff;
	for(r=poff;c= *sp;sp++)
	{
		if(curp == sp)
			r = dp - phys;
#if SHOPT_MULTIBYTE
		d = mbwidth((wchar_t)c);
		if(d==1 && is_cntrl(c))
			d = -1;
		if(d>1)
		{
			/* multiple width character put in place holders */
			*dp++ = c;
			while(--d >0)
				*dp++ = MARKER;
			/* in vi mode the cursor is at the last character */
			if(dp>=dpmax)
				break;
			continue;
		}
		else
#else
		d = (is_cntrl(c)?-1:1);
#endif	/* SHOPT_MULTIBYTE */
		if(d<0)
		{
			if(c=='\t')
			{
				c = dp-phys;
				if(sh_isoption(SH_VI))
					c += ep->e_plen;
				c = TABSIZE - c%TABSIZE;
				while(--c>0)
					*dp++ = ' ';
				c = ' ';
			}
			else
			{
				*dp++ = '^';
				c = printchar(c);
			}
			/* in vi mode the cursor is at the last character */
			if(curp == sp && sh_isoption(SH_VI))
				r = dp - phys;
		}
		*dp++ = c;
		if(dp>=dpmax)
			break;
	}
	*dp = 0;
	ep->e_peol = dp-phys;
	return(r);
}

#if SHOPT_MULTIBYTE
/*
 * convert external representation <src> to an array of genchars <dest>
 * <src> and <dest> can be the same
 * returns number of chars in dest
 */

int	ed_internal(const char *src, genchar *dest)
{
	register const unsigned char *cp = (unsigned char *)src;
	register int c;
	register wchar_t *dp = (wchar_t*)dest;
	if(dest == (genchar*)roundof(cp-(unsigned char*)0,sizeof(genchar)))
	{
		genchar buffer[MAXLINE];
		c = ed_internal(src,buffer);
		ed_gencpy((genchar*)dp,buffer);
		return(c);
	}
	while(*cp)
		*dp++ = mbchar(cp);
	*dp = 0;
	return(dp-(wchar_t*)dest);
}

/*
 * convert internal representation <src> into character array <dest>.
 * The <src> and <dest> may be the same.
 * returns number of chars in dest.
 */

int	ed_external(const genchar *src, char *dest)
{
	register genchar wc;
	register int c,size;
	register char *dp = dest;
	char *dpmax = dp+sizeof(genchar)*MAXLINE-2;
	if((char*)src == dp)
	{
		char buffer[MAXLINE*sizeof(genchar)];
		c = ed_external(src,buffer);

#ifdef _lib_wcscpy
		wcscpy((wchar_t *)dest,(const wchar_t *)buffer);
#else
		strcpy(dest,buffer);
#endif
		return(c);
	}
	while((wc = *src++) && dp<dpmax)
	{
		if((size = mbconv(dp, wc)) < 0)
		{
			/* copy the character as is */
			size = 1;
			*dp = wc;
		}
		dp += size;
	}
	*dp = 0;
	return(dp-dest);
}

/*
 * copy <sp> to <dp>
 */

void	ed_gencpy(genchar *dp,const genchar *sp)
{
	dp = (genchar*)roundof((char*)dp-(char*)0,sizeof(genchar));
	sp = (const genchar*)roundof((char*)sp-(char*)0,sizeof(genchar));
	while(*dp++ = *sp++);
}

/*
 * copy at most <n> items from <sp> to <dp>
 */

void	ed_genncpy(register genchar *dp,register const genchar *sp, int n)
{
	dp = (genchar*)roundof((char*)dp-(char*)0,sizeof(genchar));
	sp = (const genchar*)roundof((char*)sp-(char*)0,sizeof(genchar));
	while(n-->0 && (*dp++ = *sp++));
}

/*
 * find the string length of <str>
 */

int	ed_genlen(register const genchar *str)
{
	register const genchar *sp = str;
	sp = (const genchar*)roundof((char*)sp-(char*)0,sizeof(genchar));
	while(*sp++);
	return(sp-str-1);
}
#endif /* SHOPT_MULTIBYTE */
#endif /* SHOPT_ESH || SHOPT_VSH */

#ifdef future
/*
 * returns 1 when <n> bytes starting at <a> and <b> are equal
 */
static int compare(register const char *a,register const char *b,register int n)
{
	while(n-->0)
	{
		if(*a++ != *b++)
			return(0);
	}
	return(1);
}
#endif

#if SHOPT_OLDTERMIO

#   include	<sys/termio.h>

#ifndef ECHOCTL
#   define ECHOCTL	0
#endif /* !ECHOCTL */
#define ott	ep->e_ott

/*
 * For backward compatibility only
 * This version will use termios when possible, otherwise termio
 */

int tcgetattr(int fd, struct termios *tt)
{
	register Edit_t *ep = (Edit_t*)(sh_getinterp()->ed_context);
	register int r,i;
	ep->e_tcgeta = 0;
	ep->e_echoctl = (ECHOCTL!=0);
	if((r=ioctl(fd,TCGETS,tt))>=0 ||  errno!=EINVAL)
		return(r);
	if((r=ioctl(fd,TCGETA,&ott)) >= 0)
	{
		tt->c_lflag = ott.c_lflag;
		tt->c_oflag = ott.c_oflag;
		tt->c_iflag = ott.c_iflag;
		tt->c_cflag = ott.c_cflag;
		for(i=0; i<NCC; i++)
			tt->c_cc[i] = ott.c_cc[i];
		ep->e_tcgeta++;
		ep->e_echoctl = 0;
	}
	return(r);
}

int tcsetattr(int fd,int mode,struct termios *tt)
{
	register Edit_t *ep = (Edit_t*)(sh_getinterp()->ed_context);
	register int r;
	if(ep->e_tcgeta)
	{
		register int i;
		ott.c_lflag = tt->c_lflag;
		ott.c_oflag = tt->c_oflag;
		ott.c_iflag = tt->c_iflag;
		ott.c_cflag = tt->c_cflag;
		for(i=0; i<NCC; i++)
			ott.c_cc[i] = tt->c_cc[i];
		if(tt->c_lflag&ECHOCTL)
		{
			ott.c_lflag &= ~(ECHOCTL|IEXTEN);
			ott.c_iflag &= ~(IGNCR|ICRNL);
			ott.c_iflag |= INLCR;
			ott.c_cc[VEOF]= ESC;  /* ESC -> eof char */
			ott.c_cc[VEOL] = '\r'; /* CR -> eol char */
			ott.c_cc[VEOL2] = tt->c_cc[VEOF]; /* EOF -> eol char */
		}
		switch(mode)
		{
			case TCSANOW:
				mode = TCSETA;
				break;
			case TCSADRAIN:
				mode = TCSETAW;
				break;
			case TCSAFLUSH:
				mode = TCSETAF;
		}
		return(ioctl(fd,mode,&ott));
	}
	return(ioctl(fd,mode,tt));
}
#endif /* SHOPT_OLDTERMIO */

#if KSHELL
/*
 * Execute keyboard trap on given buffer <inbuff> of given size <isize>
 * <mode> < 0 for vi insert mode
 */
static int keytrap(Edit_t *ep,char *inbuff,register int insize, int bufsize, int mode)
{
	register char *cp;
	int savexit;
	Shell_t *shp = ep->sh;
#if SHOPT_MULTIBYTE
	char buff[MAXLINE];
	ed_external(ep->e_inbuf,cp=buff);
#else
	cp = ep->e_inbuf;
#endif /* SHOPT_MULTIBYTE */
	inbuff[insize] = 0;
	ep->e_col = ep->e_cur;
	if(mode== -2)
	{
		ep->e_col++;
		*ep->e_vi_insert = ESC;
	}
	else
		*ep->e_vi_insert = 0;
	nv_putval(ED_CHRNOD,inbuff,NV_NOFREE);
	nv_putval(ED_COLNOD,(char*)&ep->e_col,NV_NOFREE|NV_INTEGER);
	nv_putval(ED_TXTNOD,(char*)cp,NV_NOFREE);
	nv_putval(ED_MODENOD,ep->e_vi_insert,NV_NOFREE);
	savexit = shp->savexit;
	sh_trap(shp->st.trap[SH_KEYTRAP],0);
	shp->savexit = savexit;
	if((cp = nv_getval(ED_CHRNOD)) == inbuff)
		nv_unset(ED_CHRNOD);
	else if(bufsize>0)
	{
		strncpy(inbuff,cp,bufsize);
		inbuff[bufsize-1]='\0';
		insize = strlen(inbuff);
	}
	else
		insize = 0;
	nv_unset(ED_TXTNOD);
	return(insize);
}
#endif /* KSHELL */

void	*ed_open(Shell_t *shp)
{
	Edit_t *ed = newof(0,Edit_t,1,0);
	ed->sh = shp;
	strcpy(ed->e_macro,"_??");
	return((void*)ed);
}
