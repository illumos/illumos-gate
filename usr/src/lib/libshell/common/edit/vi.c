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
/* Adapted for ksh by David Korn */
/*+	VI.C			P.D. Sullivan
 *
 *	One line editor for the shell based on the vi editor.
 *
 *	Questions to:
 *		P.D. Sullivan
 *		cbosgd!pds
-*/


#if KSHELL
#   include	"defs.h"
#else
#   include	<ast.h>
#   include	"FEATURE/options"
#   include	<ctype.h>
#endif	/* KSHELL */
#include	"io.h"

#include	"history.h"
#include	"edit.h"
#include	"terminal.h"
#include	"FEATURE/time"

#if SHOPT_OLDTERMIO
#   undef ECHOCTL
#   define echoctl	(vp->ed->e_echoctl)
#else
#   ifdef ECHOCTL
#	define echoctl	ECHOCTL
#   else
#	define echoctl	0
#   endif /* ECHOCTL */
#endif /*SHOPT_OLDTERMIO */

#ifndef FIORDCHK
#   define NTICKS	5		/* number of ticks for typeahead */
#endif /* FIORDCHK */

#define	MAXCHAR	MAXLINE-2		/* max char per line */

#if SHOPT_MULTIBYTE
#   include	"lexstates.h"
#   define gencpy(a,b)	ed_gencpy(a,b)
#   define genncpy(a,b,n)	ed_genncpy(a,b,n)
#   define genlen(str)	ed_genlen(str)
#   define digit(c)	((c&~STRIP)==0 && isdigit(c))
#   define is_print(c)	((c&~STRIP) || isprint(c))
#   if !_lib_iswprint && !defined(iswprint)
#	define iswprint(c)	((c&~0177) || isprint(c))
#   endif
    static int _isalph(int);
    static int _ismetach(int);
    static int _isblank(int);
#   undef  isblank
#   define isblank(v)	_isblank(virtual[v])
#   define isalph(v)	_isalph(virtual[v])
#   define ismetach(v)	_ismetach(virtual[v])
#else
    static genchar	_c;
#   define gencpy(a,b)	strcpy((char*)(a),(char*)(b))
#   define genncpy(a,b,n) strncpy((char*)(a),(char*)(b),n)
#   define genlen(str)	strlen(str)
#   define isalph(v)	((_c=virtual[v])=='_'||isalnum(_c))
#   undef  isblank
#   define isblank(v)	isspace(virtual[v])
#   define ismetach(v)	ismeta(virtual[v])
#   define digit(c)	isdigit(c)
#   define is_print(c)	isprint(c)
#endif	/* SHOPT_MULTIBYTE */

#if ( 'a' == 97) /* ASCII? */
#   define fold(c)	((c)&~040)	/* lower and uppercase equivalent */
#else
#   define fold(c)	((c)|0100)	/* lower and uppercase equivalent */
#endif

#ifndef iswascii
#define iswascii(c)	(!((c)&(~0177)))
#endif

typedef struct _vi_
{
	int direction;
	int lastmacro;
	char addnl;		/* boolean - add newline flag */
	char last_find;		/* last find command */
	char last_cmd;		/* last command */
	char repeat_set;
	char nonewline;
	int findchar;		/* last find char */
	genchar *lastline;
	int first_wind;		/* first column of window */
	int last_wind;		/* last column in window */
	int lastmotion;		/* last motion */
	int long_char; 		/* line bigger than window */
	int long_line;		/* line bigger than window */
	int ocur_phys;		/* old current physical position */
	int ocur_virt;		/* old last virtual position */
	int ofirst_wind;	/* old window first col */
	int o_v_char;		/* prev virtual[ocur_virt] */
	int repeat;		/* repeat count for motion cmds */
	int lastrepeat;		/* last repeat count for motion cmds */
	int u_column;		/* undo current column */
	int U_saved;		/* original virtual saved */
	genchar *U_space;	/* used for U command */
	genchar *u_space;	/* used for u command */
#ifdef FIORDCHK
	clock_t typeahead;	/* typeahead occurred */
#else
	int typeahead;		/* typeahead occurred */
#endif	/* FIORDCHK */
#if SHOPT_MULTIBYTE
	int bigvi;
#endif
	Edit_t	*ed;		/* pointer to edit data */
} Vi_t;

#define editb	(*vp->ed)

#undef putchar
#define putchar(c)	ed_putchar(vp->ed,c)

#define crallowed	editb.e_crlf
#define cur_virt	editb.e_cur		/* current virtual column */
#define cur_phys	editb.e_pcur	/* current phys column cursor is at */
#define curhline	editb.e_hline		/* current history line */
#define first_virt	editb.e_fcol		/* first allowable column */
#define	globals		editb.e_globals		/* local global variables */
#define histmin		editb.e_hismin
#define histmax		editb.e_hismax
#define last_phys	editb.e_peol		/* last column in physical */
#define last_virt	editb.e_eol		/* last column */
#define lsearch		editb.e_search		/* last search string */
#define lookahead	editb.e_lookahead	/* characters in buffer */
#define previous	editb.e_lbuf		/* lookahead buffer */
#define max_col		editb.e_llimit		/* maximum column */
#define Prompt		editb.e_prompt		/* pointer to prompt */
#define plen		editb.e_plen		/* length of prompt */
#define physical	editb.e_physbuf		/* physical image */
#define usreof		editb.e_eof		/* user defined eof char */
#define usrerase	editb.e_erase		/* user defined erase char */
#define usrlnext	editb.e_lnext		/* user defined next literal */
#define usrkill		editb.e_kill		/* user defined kill char */
#define virtual		editb.e_inbuf	/* pointer to virtual image buffer */
#define	window		editb.e_window		/* window buffer */
#define	w_size		editb.e_wsize		/* window size */
#define	inmacro		editb.e_inmacro		/* true when in macro */
#define yankbuf		editb.e_killbuf		/* yank/delete buffer */


#define	ABORT	-2			/* user abort */
#define	APPEND	-10			/* append chars */
#define	BAD	-1			/* failure flag */
#define	BIGVI	-15			/* user wants real vi */
#define	CONTROL	-20			/* control mode */
#define	ENTER	-25			/* enter flag */
#define	GOOD	0			/* success flag */
#define	INPUT	-30			/* input mode */
#define	INSERT	-35			/* insert mode */
#define	REPLACE	-40			/* replace chars */
#define	SEARCH	-45			/* search flag */
#define	TRANSLATE	-50		/* translate virt to phys only */

#define	INVALID	(-1)			/* invalid column */

static const char paren_chars[] = "([{)]}";   /* for % command */

static void	cursor(Vi_t*, int);
static void	del_line(Vi_t*,int);
static int	getcount(Vi_t*,int);
static void	getline(Vi_t*,int);
static int	getrchar(Vi_t*);
static int	mvcursor(Vi_t*,int);
static void	pr_string(Vi_t*,const char*);
static void	putstring(Vi_t*,int, int);
static void	refresh(Vi_t*,int);
static void	replace(Vi_t*,int, int);
static void	restore_v(Vi_t*);
static void	save_last(Vi_t*);
static void	save_v(Vi_t*);
static int	search(Vi_t*,int);
static void	sync_cursor(Vi_t*);
static int	textmod(Vi_t*,int,int);

/*+	VI_READ( fd, shbuf, nchar )
 *
 *	This routine implements a one line version of vi and is
 * called by _filbuf.c
 *
-*/

/*
 * if reedit is non-zero, initialize edit buffer with reedit chars
 */
int ed_viread(void *context, int fd, register char *shbuf, int nchar, int reedit)
{
	Edit_t *ed = (Edit_t*)context;
	register int i;			/* general variable */
	register int term_char;		/* read() termination character */
	register Vi_t *vp = ed->e_vi;
	char prompt[PRSIZE+2];		/* prompt */
	genchar Physical[2*MAXLINE];	/* physical image */
	genchar Ubuf[MAXLINE];	/* used for U command */
	genchar ubuf[MAXLINE];	/* used for u command */
	genchar Window[MAXLINE];	/* window image */
	int Globals[9];			/* local global variables */
	int esc_or_hang=0;		/* <ESC> or hangup */
	char cntl_char=0;		/* TRUE if control character present */
#if SHOPT_RAWONLY
#   define viraw	1
#else
	int viraw = (sh_isoption(SH_VIRAW) || sh.st.trap[SH_KEYTRAP]);
#   ifndef FIORDCHK
	clock_t oldtime, newtime;
	struct tms dummy;
#   endif /* FIORDCHK */
#endif /* SHOPT_RAWONLY */
	if(!vp)
	{
		ed->e_vi = vp =  newof(0,Vi_t,1,0);
		vp->lastline = (genchar*)malloc(MAXLINE*CHARSIZE);
		vp->direction = -1;
		vp->ed = ed;
	}
	
	/*** setup prompt ***/

	Prompt = prompt;
	ed_setup(vp->ed,fd, reedit);
	shbuf[reedit] = 0;

#if !SHOPT_RAWONLY
	if(!viraw)
	{
		/*** Change the eol characters to '\r' and eof  ***/
		/* in addition to '\n' and make eof an ESC	*/
		if(tty_alt(ERRIO) < 0)
			return(reexit?reedit:ed_read(context, fd, shbuf, nchar,0));

#ifdef FIORDCHK
		ioctl(fd,FIORDCHK,&vp->typeahead);
#else
		/* time the current line to determine typeahead */
		oldtime = times(&dummy);
#endif /* FIORDCHK */
#if KSHELL
		/* abort of interrupt has occurred */
		if(sh.trapnote&SH_SIGSET)
			i = -1;
		else
#endif /* KSHELL */
		/*** Read the line ***/
		i = ed_read(context, fd, shbuf, nchar, 0);
#ifndef FIORDCHK
		newtime = times(&dummy);
		vp->typeahead = ((newtime-oldtime) < NTICKS);
#endif /* FIORDCHK */
	    if(echoctl)
	    {
		if( i <= 0 )
		{
			/*** read error or eof typed ***/
			tty_cooked(ERRIO);
			return(i);
		}
		term_char = shbuf[--i];
		if( term_char == '\r' )
			term_char = '\n';
		if( term_char=='\n' || term_char==ESC )
			shbuf[i--] = '\0';
		else
			shbuf[i+1] = '\0';
	    }
	    else
	    {
		register int c = shbuf[0];

		/*** Save and remove the last character if its an eol, ***/
		/* changing '\r' to '\n' */

		if( i == 0 )
		{
			/*** ESC was typed as first char of line ***/
			esc_or_hang = 1;
			term_char = ESC;
			shbuf[i--] = '\0';	/* null terminate line */
		}
		else if( i<0 || c==usreof )
		{
			/*** read error or eof typed ***/
			tty_cooked(ERRIO);
			if( c == usreof )
				i = 0;
			return(i);
		}
		else
		{
			term_char = shbuf[--i];
			if( term_char == '\r' )
				term_char = '\n';
#if !defined(VEOL2) && !defined(ECHOCTL)
			if(term_char=='\n')
			{
				tty_cooked(ERRIO);
				return(i+1);
			}
#endif
			if( term_char=='\n' || term_char==usreof )
			{
				/*** remove terminator & null terminate ***/
				shbuf[i--] = '\0';
			}
			else
			{
				/** terminator was ESC, which is not xmitted **/
				term_char = ESC;
				shbuf[i+1] = '\0';
			}
		}
	    }
	}
	else
#endif /* SHOPT_RAWONLY */
	{
		/*** Set raw mode ***/

#if !SHOPT_RAWONLY
		if( editb.e_ttyspeed == 0 )
		{
			/*** never did TCGETA, so do it ***/
			/* avoids problem if user does 'sh -o viraw' */
			tty_alt(ERRIO);
		}
#endif /* SHOPT_RAWONLY */
		if(tty_raw(ERRIO,0) < 0 )
			return(reedit?reedit:ed_read(context, fd, shbuf, nchar,0));
		i = last_virt-1;
	}

	/*** Initialize some things ***/

	virtual = (genchar*)shbuf;
#if SHOPT_MULTIBYTE
	virtual = (genchar*)roundof((char*)virtual-(char*)0,sizeof(genchar));
	shbuf[i+1] = 0;
	i = ed_internal(shbuf,virtual)-1;
#endif /* SHOPT_MULTIBYTE */
	globals = Globals;
	cur_phys = i + 1;
	cur_virt = i;
	first_virt = 0;
	vp->first_wind = 0;
	last_virt = i;
	last_phys = i;
	vp->last_wind = i;
	vp->long_line = ' ';
	vp->long_char = ' ';
	vp->o_v_char = '\0';
	vp->ocur_phys = 0;
	vp->ocur_virt = MAXCHAR;
	vp->ofirst_wind = 0;
	physical = Physical;
	vp->u_column = INVALID - 1;
	vp->U_space = Ubuf;
	vp->u_space = ubuf;
	window = Window;
	window[0] = '\0';

	if(!yankbuf)
		yankbuf = (genchar*)malloc(MAXLINE*CHARSIZE);
	if( vp->last_cmd == '\0' )
	{
		/*** first time for this shell ***/

		vp->last_cmd = 'i';
		vp->findchar = INVALID;
		vp->lastmotion = '\0';
		vp->lastrepeat = 1;
		vp->repeat = 1;
		*yankbuf = 0;
	}

	/*** fiddle around with prompt length ***/
	if( nchar+plen > MAXCHAR )
		nchar = MAXCHAR - plen;
	max_col = nchar - 2;

	if( !viraw )
	{
		int kill_erase = 0;
		for(i=(echoctl?last_virt:0); i<last_virt; ++i )
		{
			/*** change \r to \n, check for control characters, ***/
			/* delete appropriate ^Vs,			*/
			/* and estimate last physical column */

			if( virtual[i] == '\r' )
				virtual[i] = '\n';
		    if(!echoctl)
		    {
			register int c = virtual[i];
			if( c<=usrerase)
			{
				/*** user typed escaped erase or kill char ***/
				cntl_char = 1;
				if(is_print(c))
					kill_erase++;
			}
			else if( !is_print(c) )
			{
				cntl_char = 1;

				if( c == usrlnext )
				{
					if( i == last_virt )
					{
						/*** eol/eof was escaped ***/
						/* so replace ^V with it */
						virtual[i] = term_char;
						break;
					}

					/*** delete ^V ***/
					gencpy((&virtual[i]), (&virtual[i+1]));
					--cur_virt;
					--last_virt;
				}
			}
		    }
		}

		/*** copy virtual image to window ***/
		if(last_virt > 0)
			last_phys = ed_virt_to_phys(vp->ed,virtual,physical,last_virt,0,0);
		if( last_phys >= w_size )
		{
			/*** line longer than window ***/
			vp->last_wind = w_size - 1;
		}
		else
			vp->last_wind = last_phys;
		genncpy(window, virtual, vp->last_wind+1);

		if( term_char!=ESC  && (last_virt==INVALID
			|| virtual[last_virt]!=term_char) )
		{
			/*** Line not terminated with ESC or escaped (^V) ***/
			/* eol, so return after doing a total update */
			/* if( (speed is greater or equal to 1200 */
			/* and something was typed) and */
			/* (control character present */
			/* or typeahead occurred) ) */

			tty_cooked(ERRIO);
			if( editb.e_ttyspeed==FAST && last_virt!=INVALID
				&& (vp->typeahead || cntl_char) )
			{
				refresh(vp,TRANSLATE);
				pr_string(vp,Prompt);
				putstring(vp,0, last_phys+1);
				if(echoctl)
					ed_crlf(vp->ed);
				else
					while(kill_erase-- > 0)
						putchar(' ');
			}

			if( term_char=='\n' )
			{
				if(!echoctl)
					ed_crlf(vp->ed);
				virtual[++last_virt] = '\n';
			}
			vp->last_cmd = 'i';
			save_last(vp);
#if SHOPT_MULTIBYTE
			virtual[last_virt+1] = 0;
			last_virt = ed_external(virtual,shbuf);
			return(last_virt);
#else
			return(++last_virt);
#endif /* SHOPT_MULTIBYTE */
		}

		/*** Line terminated with escape, or escaped eol/eof, ***/
		/*  so set raw mode */

		if( tty_raw(ERRIO,0) < 0 )
		{
			tty_cooked(ERRIO);
			/*
			 * The following prevents drivers that return 0 on
			 * causing an infinite loop
			 */
			if(esc_or_hang)
				return(-1);
			virtual[++last_virt] = '\n';
#if SHOPT_MULTIBYTE
			virtual[last_virt+1] = 0;
			last_virt = ed_external(virtual,shbuf);
			return(last_virt);
#else
			return(++last_virt);
#endif /* SHOPT_MULTIBYTE */
		}

		if(echoctl) /*** for cntl-echo erase the ^[ ***/
			pr_string(vp,"\b\b\b\b      \b\b");


		if(crallowed)
		{
			/*** start over since there may be ***/
			/*** a control char, or cursor might not ***/
			/*** be at left margin (this lets us know ***/
			/*** where we are ***/
			cur_phys = 0;
			window[0] = '\0';
			pr_string(vp,Prompt);
			if( term_char==ESC && (last_virt<0 || virtual[last_virt]!=ESC))
				refresh(vp,CONTROL);
			else
				refresh(vp,INPUT);
		}
		else
		{
			/*** just update everything internally ***/
			refresh(vp,TRANSLATE);
		}
	}

	/*** Handle usrintr, usrquit, or EOF ***/

	i = sigsetjmp(editb.e_env,0);
	if( i != 0 )
	{
		if(vp->ed->e_multiline)
		{
			cur_virt = last_virt;
			sync_cursor(vp);
		}
		virtual[0] = '\0';
		tty_cooked(ERRIO);

		switch(i)
		{
		case UEOF:
			/*** EOF ***/
			return(0);

		case UINTR:
			/** interrupt **/
			return(-1);
		}
		return(-1);
	}

	/*** Get a line from the terminal ***/

	vp->U_saved = 0;
	if(reedit)
	{
		cur_phys = vp->first_wind;
		vp->ofirst_wind = INVALID;
		refresh(vp,INPUT);
	}
	if(viraw)
		getline(vp,APPEND);
	else if(last_virt>=0 && virtual[last_virt]==term_char)
		getline(vp,APPEND);
	else
		getline(vp,ESC);
	if(vp->ed->e_multiline)
		cursor(vp, last_phys);
	/*** add a new line if user typed unescaped \n ***/
	/* to cause the shell to process the line */
	tty_cooked(ERRIO);
	if(ed->e_nlist)
	{
		ed->e_nlist = 0;
		stakset(ed->e_stkptr,ed->e_stkoff);
	}
	if( vp->addnl )
	{
		virtual[++last_virt] = '\n';
		ed_crlf(vp->ed);
	}
	if( ++last_virt >= 0 )
	{
#if SHOPT_MULTIBYTE
		if(vp->bigvi)
		{
			vp->bigvi = 0;
			shbuf[last_virt-1] = '\n';
		}
		else
		{
			virtual[last_virt] = 0;
			last_virt = ed_external(virtual,shbuf);
		}
#endif /* SHOPT_MULTIBYTE */
		return(last_virt);
	}
	else
		return(-1);
}


/*{	APPEND( char, mode )
 *
 *	This routine will append char after cur_virt in the virtual image.
 * mode	=	APPEND, shift chars right before appending
 *		REPLACE, replace char if possible
 *
}*/

static void append(Vi_t *vp,int c, int mode)
{
	register int i,j;

	if( last_virt<max_col && last_phys<max_col )
	{
		if( mode==APPEND || (cur_virt==last_virt  && last_virt>=0))
		{
			j = (cur_virt>=0?cur_virt:0);
			for(i = ++last_virt;  i > j; --i)
				virtual[i] = virtual[i-1];
		}
		virtual[++cur_virt] = c;
	}
	else
		ed_ringbell();
	return;
}

/*{	BACKWORD( nwords, cmd )
 *
 *	This routine will position cur_virt at the nth previous word.
 *
}*/

static void backword(Vi_t *vp,int nwords, register int cmd)
{
	register int tcur_virt = cur_virt;
	while( nwords-- && tcur_virt > first_virt )
	{
		if( !isblank(tcur_virt) && isblank(tcur_virt-1)
			&& tcur_virt>first_virt )
			--tcur_virt;
		else if(cmd != 'B')
		{
			register int last = isalph(tcur_virt-1);
			register int cur = isalph(tcur_virt);
			if((!cur && last) || (cur && !last))
				--tcur_virt;
		}
		while( isblank(tcur_virt) && tcur_virt>=first_virt )
			--tcur_virt;
		if( cmd == 'B' )
		{
			while( !isblank(tcur_virt) && tcur_virt>=first_virt )
				--tcur_virt;
		}
		else
		{
			if(isalph(tcur_virt))
				while( isalph(tcur_virt) && tcur_virt>=first_virt )
					--tcur_virt;
			else
				while( !isalph(tcur_virt) && !isblank(tcur_virt)
					&& tcur_virt>=first_virt )
					--tcur_virt;
		}
		cur_virt = ++tcur_virt;
	}
	return;
}

/*{	CNTLMODE()
 *
 *	This routine implements the vi command subset.
 *	The cursor will always be positioned at the char of interest.
 *
}*/

static int cntlmode(Vi_t *vp)
{
	register int c;
	register int i;
	genchar tmp_u_space[MAXLINE];	/* temporary u_space */
	genchar *real_u_space;		/* points to real u_space */
	int tmp_u_column = INVALID;	/* temporary u_column */
	int was_inmacro;

	if(!vp->U_saved)
	{
		/*** save virtual image if never done before ***/
		virtual[last_virt+1] = '\0';
		gencpy(vp->U_space, virtual);
		vp->U_saved = 1;
	}

	save_last(vp);

	real_u_space = vp->u_space;
	curhline = histmax;
	first_virt = 0;
	vp->repeat = 1;
	if( cur_virt > INVALID )
	{
		/*** make sure cursor is at the last char ***/
		sync_cursor(vp);
	}

	/*** Read control char until something happens to cause a ***/
	/* return to APPEND/REPLACE mode	*/

	while( c=ed_getchar(vp->ed,-1) )
	{
		vp->repeat_set = 0;
		was_inmacro = inmacro;
		if( c == '0' )
		{
			/*** move to leftmost column ***/
			cur_virt = 0;
			sync_cursor(vp);
			continue;
		}

		if( digit(c) )
		{
			c = getcount(vp,c);
			if( c == '.' )
				vp->lastrepeat = vp->repeat;
		}

		/*** see if it's a move cursor command ***/

		if(mvcursor(vp,c))
		{
			sync_cursor(vp);
			vp->repeat = 1;
			continue;
		}

		/*** see if it's a repeat of the last command ***/

		if( c == '.' )
		{
			c = vp->last_cmd;
			vp->repeat = vp->lastrepeat;
			i = textmod(vp,c, c);
		}
		else
		{
			i = textmod(vp,c, 0);
		}

		/*** see if it's a text modification command ***/

		switch(i)
		{
		case BAD:
			break;

		default:		/** input mode **/
			if(!was_inmacro)
			{
				vp->last_cmd = c;
				vp->lastrepeat = vp->repeat;
			}
			vp->repeat = 1;
			if( i == GOOD )
				continue;
			return(i);
		}

		switch( c )
		{
			/***** Other stuff *****/

		case cntl('L'):		/** Redraw line **/
			/*** print the prompt and ***/
			/* force a total refresh */
			if(vp->nonewline==0 && !vp->ed->e_nocrnl)
				putchar('\n');
			vp->nonewline = 0;
			pr_string(vp,Prompt);
			window[0] = '\0';
			cur_phys = vp->first_wind;
			vp->ofirst_wind = INVALID;
			vp->long_line = ' ';
			break;

		case cntl('V'):
		{
			register const char *p = fmtident(e_version);
			save_v(vp);
			del_line(vp,BAD);
			while(c = *p++)
				append(vp,c,APPEND);
			refresh(vp,CONTROL);
			ed_getchar(vp->ed,-1);
			restore_v(vp);
			break;
		}

		case '/':		/** Search **/
		case '?':
		case 'N':
		case 'n':
			save_v(vp);
			switch( search(vp,c) )
			{
			case GOOD:
				/*** force a total refresh ***/
				window[0] = '\0';
				goto newhist;

			case BAD:
				/*** no match ***/
					ed_ringbell();
				/* FALLTHROUGH */

			default:
				if( vp->u_column == INVALID )
					del_line(vp,BAD);
				else
					restore_v(vp);
				break;
			}
			break;

		case 'j':		/** get next command **/
		case '+':		/** get next command **/
			curhline += vp->repeat;
			if( curhline > histmax )
			{
				curhline = histmax;
				goto ringbell;
			}
			else if(curhline==histmax && tmp_u_column!=INVALID )
			{
				vp->u_space = tmp_u_space;
				vp->u_column = tmp_u_column;
				restore_v(vp);
				vp->u_space = real_u_space;
				break;
			}
			save_v(vp);
			cur_virt = INVALID;
			goto newhist;

		case 'k':		/** get previous command **/
		case '-':		/** get previous command **/
			if( curhline == histmax )
			{
				vp->u_space = tmp_u_space;
				i = vp->u_column;
				save_v(vp);
				vp->u_space = real_u_space;
				tmp_u_column = vp->u_column;
				vp->u_column = i;
			}

			curhline -= vp->repeat;
			if( curhline <= histmin )
			{
				curhline += vp->repeat;
				goto ringbell;
			}
			save_v(vp);
			cur_virt = INVALID;
		newhist:
			if(curhline!=histmax || cur_virt==INVALID)
				hist_copy((char*)virtual, MAXLINE, curhline,-1);
			else
			{
				strcpy((char*)virtual,(char*)vp->u_space);
#if SHOPT_MULTIBYTE
				ed_internal((char*)vp->u_space,vp->u_space);
#endif /* SHOPT_MULTIBYTE */
			}
#if SHOPT_MULTIBYTE
			ed_internal((char*)virtual,virtual);
#endif /* SHOPT_MULTIBYTE */
			if((last_virt=genlen(virtual)-1) >= 0  && cur_virt == INVALID)
				cur_virt = 0;
			break;


		case 'u':		/** undo the last thing done **/
			restore_v(vp);
			break;

		case 'U':		/** Undo everything **/
			save_v(vp);
			if( virtual[0] == '\0' )
				goto ringbell;
			else
			{
				gencpy(virtual, vp->U_space);
				last_virt = genlen(vp->U_space) - 1;
				cur_virt = 0;
			}
			break;

#if KSHELL
		case 'v':
			if(vp->repeat_set==0)
				goto vcommand;
#endif /* KSHELL */
			/* FALLTHROUGH */

		case 'G':		/** goto command repeat **/
			if(vp->repeat_set==0)
				vp->repeat = histmin+1;
			if( vp->repeat <= histmin || vp->repeat > histmax )
			{
				goto ringbell;
			}
			curhline = vp->repeat;
			save_v(vp);
			if(c == 'G')
			{
				cur_virt = INVALID;
				goto newhist;
			}

#if KSHELL
		vcommand:
			if(ed_fulledit(vp->ed)==GOOD)
				return(BIGVI);
			else
				goto ringbell;
#endif	/* KSHELL */

		case '#':	/** insert(delete) # to (no)comment command **/
			if( cur_virt != INVALID )
			{
				register genchar *p = &virtual[last_virt+1];
				*p = 0;
				/*** see whether first char is comment char ***/
				c = (virtual[0]=='#');
				while(p-- >= virtual)
				{
					if(*p=='\n' || p<virtual)
					{
						if(c) /* delete '#' */
						{
							if(p[1]=='#')
							{
								last_virt--;
								gencpy(p+1,p+2);
							}
						}
						else
						{
							cur_virt = p-virtual;
							append(vp,'#', APPEND);
						}
					}
				}
				if(c)
				{
					curhline = histmax;
					cur_virt = 0;
					break;
				}
				refresh(vp,INPUT);
			}
			/* FALLTHROUGH */

		case '\n':		/** send to shell **/
			return(ENTER);

	        case ESC:
			/* don't ring bell if next char is '[' */
			if(!lookahead)
			{
				char x;
				if(sfpkrd(editb.e_fd,&x,1,'\r',400L,-1)>0)
					ed_ungetchar(vp->ed,x);
			}
			if(lookahead)
			{
				ed_ungetchar(vp->ed,c=ed_getchar(vp->ed,1));
				if(c=='[')
				{
					vp->repeat = 1;
					continue;
				}
			}
			/* FALLTHROUGH */
		default:
		ringbell:
			ed_ringbell();
			vp->repeat = 1;
			continue;
		}

		refresh(vp,CONTROL);
		vp->repeat = 1;
	}
/* NOTREACHED */
	return(0);
}

/*{	CURSOR( new_current_physical )
 *
 *	This routine will position the virtual cursor at
 * physical column x in the window.
 *
}*/

static void cursor(Vi_t *vp,register int x)
{
#if SHOPT_MULTIBYTE
	while(physical[x]==MARKER)
		x++;
#endif /* SHOPT_MULTIBYTE */
	cur_phys = ed_setcursor(vp->ed, physical, cur_phys,x,vp->first_wind);
}

/*{	DELETE( nchars, mode )
 *
 *	Delete nchars from the virtual space and leave cur_virt positioned
 * at cur_virt-1.
 *
 *	If mode	= 'c', do not save the characters deleted
 *		= 'd', save them in yankbuf and delete.
 *		= 'y', save them in yankbuf but do not delete.
 *
}*/

static void cdelete(Vi_t *vp,register int nchars, int mode)
{
	register int i;
	register genchar *cp;

	if( cur_virt < first_virt )
	{
		ed_ringbell();
		return;
	}
	if( nchars > 0 )
	{
		cp = virtual+cur_virt;
		vp->o_v_char = cp[0];
		if( (cur_virt-- + nchars) > last_virt )
		{
			/*** set nchars to number actually deleted ***/
			nchars = last_virt - cur_virt;
		}

		/*** save characters to be deleted ***/

		if( mode != 'c' )
		{
			i = cp[nchars];
			cp[nchars] = 0;
			gencpy(yankbuf,cp);
			cp[nchars] = i;
		}

		/*** now delete these characters ***/

		if( mode != 'y' )
		{
			gencpy(cp,cp+nchars);
			last_virt -= nchars;
		}
	}
	return;
}

/*{	DEL_LINE( mode )
 *
 *	This routine will delete the line.
 *	mode = GOOD, do a save_v()
 *
}*/
static void del_line(register Vi_t *vp, int mode)
{
	if( last_virt == INVALID )
		return;

	if( mode == GOOD )
		save_v(vp);

	cur_virt = 0;
	first_virt = 0;
	cdelete(vp,last_virt+1, BAD);
	refresh(vp,CONTROL);

	cur_virt = INVALID;
	cur_phys = 0;
	vp->findchar = INVALID;
	last_phys = INVALID;
	last_virt = INVALID;
	vp->last_wind = INVALID;
	vp->first_wind = 0;
	vp->o_v_char = '\0';
	vp->ocur_phys = 0;
	vp->ocur_virt = MAXCHAR;
	vp->ofirst_wind = 0;
	window[0] = '\0';
	return;
}

/*{	DELMOTION( motion, mode )
 *
 *	Delete thru motion.
 *
 *	mode	= 'd', save deleted characters, delete
 *		= 'c', do not save characters, change
 *		= 'y', save characters, yank
 *
 *	Returns 1 if operation successful; else 0.
 *
}*/

static int delmotion(Vi_t *vp,int motion, int mode)
{
	register int begin, end, delta;
	/* the following saves a register */

	if( cur_virt == INVALID )
		return(0);
	if( mode != 'y' )
		save_v(vp);
	begin = cur_virt;

	/*** fake out the motion routines by appending a blank ***/

	virtual[++last_virt] = ' ';
	end = mvcursor(vp,motion);
	virtual[last_virt--] = 0;
	if(!end)
		return(0);

	end = cur_virt;
	if( mode=='c' && end>begin && strchr("wW", motion) )
	{
		/*** called by change operation, user really expects ***/
		/* the effect of the eE commands, so back up to end of word */
		while( end>begin && isblank(end-1) )
			--end;
		if( end == begin )
			++end;
	}

	delta = end - begin;
	if( delta >= 0 )
	{
		cur_virt = begin;
		if( strchr("eE;,TtFf%", motion) )
			++delta;
	}
	else
	{
		delta = -delta + (motion=='%');
	}

	cdelete(vp,delta, mode);
	if( mode == 'y' )
		cur_virt = begin;
	return(1);
}


/*{	ENDWORD( nwords, cmd )
 *
 *	This routine will move cur_virt to the end of the nth word.
 *
}*/

static void endword(Vi_t *vp, int nwords, register int cmd)
{
	register int tcur_virt = cur_virt;
	while( nwords-- )
	{
		if( !isblank(tcur_virt) && tcur_virt<=last_virt )
			++tcur_virt;
		while( isblank(tcur_virt) && tcur_virt<=last_virt )
			++tcur_virt;	
		if( cmd == 'E' )
		{
			while( !isblank(tcur_virt) && tcur_virt<=last_virt )
				++tcur_virt;
		}
		else
		{
			if( isalph(tcur_virt) )
				while( isalph(tcur_virt) && tcur_virt<=last_virt )
					++tcur_virt;
			else
				while( !isalph(tcur_virt) && !isblank(tcur_virt)
					&& tcur_virt<=last_virt )
					++tcur_virt;
		}
		if( tcur_virt > first_virt )
			tcur_virt--;
	}
	cur_virt = tcur_virt;
	return;
}

/*{	FORWARD( nwords, cmd )
 *
 *	This routine will move cur_virt forward to the next nth word.
 *
}*/

static void forward(Vi_t *vp,register int nwords, int cmd)
{
	register int tcur_virt = cur_virt;
	while( nwords-- )
	{
		if( cmd == 'W' )
		{
			while( !isblank(tcur_virt) && tcur_virt < last_virt )
				++tcur_virt;
		}
		else
		{
			if( isalph(tcur_virt) )
			{
				while( isalph(tcur_virt) && tcur_virt<last_virt )
					++tcur_virt;
			}
			else
			{
				while( !isalph(tcur_virt) && !isblank(tcur_virt)
					&& tcur_virt < last_virt )
					++tcur_virt;
			}
		}
		while( isblank(tcur_virt) && tcur_virt < last_virt )
			++tcur_virt;
	}
	cur_virt = tcur_virt;
	return;
}



/*{	GETCOUNT(c)
 *
 *	Set repeat to the user typed number and return the terminating
 * character.
 *
}*/

static int getcount(register Vi_t *vp,register int c)
{
	register int i;

	/*** get any repeat count ***/

	if( c == '0' )
		return(c);

	vp->repeat_set++;
	i = 0;
	while( digit(c) )
	{
		i = i*10 + c - '0';
		c = ed_getchar(vp->ed,-1);
	}

	if( i > 0 )
		vp->repeat *= i;
	return(c);
}


/*{	GETLINE( mode )
 *
 *	This routine will fetch a line.
 *	mode	= APPEND, allow escape to cntlmode subroutine
 *		  appending characters.
 *		= REPLACE, allow escape to cntlmode subroutine
 *		  replacing characters.
 *		= SEARCH, no escape allowed
 *		= ESC, enter control mode immediately
 *
 *	The cursor will always be positioned after the last
 * char printed.
 *
 *	This routine returns when cr, nl, or (eof in column 0) is
 * received (column 0 is the first char position).
 *
}*/

static void getline(register Vi_t* vp,register int mode)
{
	register int c;
	register int tmp;
	int	max_virt=0, last_save=0;
	genchar saveline[MAXLINE];

	vp->addnl = 1;

	if( mode == ESC )
	{
		/*** go directly to control mode ***/
		goto escape;
	}

	for(;;)
	{
		if( (c=ed_getchar(vp->ed,mode==SEARCH?1:-2)) == usreof )
			c = UEOF;
		else if( c == usrerase )
			c = UERASE;
		else if( c == usrkill )
			c = UKILL;
		else if( c == editb.e_werase )
			c = UWERASE;
		else if( c == usrlnext )
			c = ULNEXT;

		if( c == ULNEXT)
		{
			/*** implement ^V to escape next char ***/
			c = ed_getchar(vp->ed,2);
			append(vp,c, mode);
			refresh(vp,INPUT);
			continue;
		}

		switch( c )
		{
		case ESC:		/** enter control mode **/
			if(!sh_isoption(SH_VI))
			{
				append(vp,c, mode);
				break;
			}
			if( mode == SEARCH )
			{
				ed_ringbell();
				continue;
			}
			else
			{
	escape:
				if( mode == REPLACE )
				{
					c = max_virt-cur_virt;
					if(c > 0 && last_save>=cur_virt)
					{
						genncpy((&virtual[cur_virt]),&saveline[cur_virt],c);
						if(last_virt>=last_save)
							last_virt=last_save-1;
						refresh(vp,INPUT);
					}
					--cur_virt;
				}
				tmp = cntlmode(vp);
				if( tmp == ENTER || tmp == BIGVI )
				{
#if SHOPT_MULTIBYTE
					vp->bigvi = (tmp==BIGVI);
#endif /* SHOPT_MULTIBYTE */
					return;
				}
				if( tmp == INSERT )
				{
					mode = APPEND;
					continue;
				}
				mode = tmp;
				if(mode==REPLACE)
				{
					c = last_save = last_virt+1;
					if(c >= MAXLINE)
						c = MAXLINE-1;
					genncpy(saveline, virtual, c);
				}
			}
			break;

		case UERASE:		/** user erase char **/
				/*** treat as backspace ***/

		case '\b':		/** backspace **/
			if( virtual[cur_virt] == '\\' )
			{
				cdelete(vp,1, BAD);
				append(vp,usrerase, mode);
			}
			else
			{
				if( mode==SEARCH && cur_virt==0 )
				{
					first_virt = 0;
					cdelete(vp,1, BAD);
					return;
				}
				if(mode==REPLACE || (last_save>0 && last_virt<=last_save))
				{
					if(cur_virt<=first_virt)
						ed_ringbell();
					else if(mode==REPLACE)
						--cur_virt;
					mode = REPLACE;
					sync_cursor(vp);
					continue;
				}
				else
					cdelete(vp,1, BAD);
			}
			break;

		case UWERASE:		/** delete back word **/
			if( cur_virt > first_virt && 
				!isblank(cur_virt) &&
				!ispunct(virtual[cur_virt]) &&
				isblank(cur_virt-1) )
			{
				cdelete(vp,1, BAD);
			}
			else
			{
				tmp = cur_virt;
				backword(vp,1, 'W');
				cdelete(vp,tmp - cur_virt + 1, BAD);
			}
			break;

		case UKILL:		/** user kill line char **/
			if( virtual[cur_virt] == '\\' )
			{
				cdelete(vp,1, BAD);
				append(vp,usrkill, mode);
			}
			else
			{
				if( mode == SEARCH )
				{
					cur_virt = 1;
					delmotion(vp, '$', BAD);
				}
				else if(first_virt)
				{
					tmp = cur_virt;
					cur_virt = first_virt;
					cdelete(vp,tmp - cur_virt + 1, BAD);
				}
				else
					del_line(vp,GOOD);
			}
			break;

		case UEOF:		/** eof char **/
			if( cur_virt != INVALID )
				continue;
			vp->addnl = 0;
			/* FALLTHROUGH */

		case '\n':		/** newline or return **/
			if( mode != SEARCH )
				save_last(vp);
			refresh(vp,INPUT);
			last_phys++;
			return;

		case '\t':		/** command completion **/
			if(mode!=SEARCH && last_virt>=0 && (vp->ed->e_tabcount|| !isblank(cur_virt)) && vp->ed->sh->nextprompt)
			{
				if(vp->ed->e_tabcount==0)
				{
					ed_ungetchar(vp->ed,'\\');
					vp->ed->e_tabcount=1;
					goto escape;
				}
				else if(vp->ed->e_tabcount==1)
				{
					ed_ungetchar(vp->ed,'=');
					goto escape;
				}
				vp->ed->e_tabcount = 0;
			}
			/* FALL THRU*/
		default:
			if( mode == REPLACE )
			{
				if( cur_virt < last_virt )
				{
					replace(vp,c, 1);
					if(cur_virt>max_virt)
						max_virt = cur_virt;
					continue;
				}
				cdelete(vp,1, BAD);
				mode = APPEND;
				max_virt = last_virt+3;
			}
			append(vp,c, mode);
			break;
		}
		refresh(vp,INPUT);

	}
}

/*{	MVCURSOR( motion )
 *
 *	This routine will move the virtual cursor according to motion
 * for repeat times.
 *
 * It returns GOOD if successful; else BAD.
 *
}*/

static int mvcursor(register Vi_t* vp,register int motion)
{
	register int count;
	register int tcur_virt;
	register int incr = -1;
	register int bound = 0;

	switch(motion)
	{
		/***** Cursor move commands *****/

	case '0':		/** First column **/
		tcur_virt = 0;
		break;

	case '^':		/** First nonblank character **/
		tcur_virt = first_virt;
		while( isblank(tcur_virt) && tcur_virt < last_virt )
			++tcur_virt;
		break;

	case '|':
		tcur_virt = vp->repeat-1;
		if(tcur_virt <= last_virt)
			break;
		/* fall through */

	case '$':		/** End of line **/
		tcur_virt = last_virt;
		break;

	case '[':
		switch(motion=getcount(vp,ed_getchar(vp->ed,-1)))
		{
		    case 'A':
			if(cur_virt>=0  && cur_virt<(SEARCHSIZE-2) && cur_virt == last_virt)
			{
				virtual[last_virt + 1] = '\0';
#if SHOPT_MULTIBYTE
				ed_external(virtual,lsearch+1);
#else
				strcpy(lsearch+1,virtual);
#endif /* SHOPT_MULTIBYTE */
				*lsearch = '^';
				vp->direction = -2;
				ed_ungetchar(vp->ed,'n');
			}
			else if(cur_virt==0 && vp->direction == -2)
				ed_ungetchar(vp->ed,'n');
			else
				ed_ungetchar(vp->ed,'k');
			return(1);
		    case 'B':
			ed_ungetchar(vp->ed,'j');
			return(1);
		    case 'C':
			motion = last_virt;
			incr = 1;
			goto walk;
		    case 'D':
			motion = first_virt;
			goto walk;
		    case 'H':
			tcur_virt = 0;
			break;
		    case 'Y':
			tcur_virt = last_virt;
			break;
		    default:
			ed_ungetchar(vp->ed,motion);
			return(0);
		}
		break;

	case 'h':		/** Left one **/
	case '\b':
		motion = first_virt;
		goto walk;

	case ' ':
	case 'l':		/** Right one **/
		motion = last_virt;
		incr = 1;
	walk:
		tcur_virt = cur_virt;
		if( incr*tcur_virt < motion)
		{
			tcur_virt += vp->repeat*incr;
			if( incr*tcur_virt > motion)
				tcur_virt = motion;
		}
		else
			return(0);
		break;

	case 'B':
	case 'b':		/** back word **/
		tcur_virt = cur_virt;
		backword(vp,vp->repeat, motion);
		if( cur_virt == tcur_virt )
			return(0);
		return(1);

	case 'E':
	case 'e':		/** end of word **/
		tcur_virt = cur_virt;
		if(tcur_virt >=0)
			endword(vp, vp->repeat, motion);
		if( cur_virt == tcur_virt )
			return(0);
		return(1);

	case ',':		/** reverse find old char **/
	case ';':		/** find old char **/
		switch(vp->last_find)
		{
		case 't':
		case 'f':
			if(motion==';')
			{
				bound = last_virt;
				incr = 1;
			}
			goto find_b;

		case 'T':
		case 'F':
			if(motion==',')
			{
				bound = last_virt;
				incr = 1;
			}
			goto find_b;

		default:
			return(0);
		}


	case 't':		/** find up to new char forward **/
	case 'f':		/** find new char forward **/
		bound = last_virt;
		incr = 1;
		/* FALLTHROUGH */

	case 'T':		/** find up to new char backward **/
	case 'F':		/** find new char backward **/
		vp->last_find = motion;
		if((vp->findchar=getrchar(vp))==ESC)
			return(1);
find_b:
		tcur_virt = cur_virt;
		count = vp->repeat;
		while( count-- )
		{
			while( incr*(tcur_virt+=incr) <= bound
				&& virtual[tcur_virt] != vp->findchar );
			if( incr*tcur_virt > bound )
			{
				return(0);
			}
		}
		if( fold(vp->last_find) == 'T' )
			tcur_virt -= incr;
		break;

        case '%':
	{
		int nextmotion;
		int nextc;
		tcur_virt = cur_virt;
		while( tcur_virt <= last_virt
			&& strchr(paren_chars,virtual[tcur_virt])==(char*)0)
				tcur_virt++;
		if(tcur_virt > last_virt )
			return(0);
		nextc = virtual[tcur_virt];
		count = strchr(paren_chars,nextc)-paren_chars;
		if(count < 3)
		{
			incr = 1;
			bound = last_virt;
			nextmotion = paren_chars[count+3];
		}
		else
			nextmotion = paren_chars[count-3];
		count = 1;
		while(count >0 &&  incr*(tcur_virt+=incr) <= bound)
		{
		        if(virtual[tcur_virt] == nextmotion)
		        	count--;
		        else if(virtual[tcur_virt]==nextc)
		        	count++;
		}
		if(count)
			return(0);
		break;
	}

	case 'W':
	case 'w':		/** forward word **/
		tcur_virt = cur_virt;
		forward(vp,vp->repeat, motion);
		if( tcur_virt == cur_virt )
			return(0);
		return(1);

	default:
		return(0);
	}
	cur_virt = tcur_virt;

	return(1);
}

/*
 * print a string
 */

static void pr_string(register Vi_t *vp, register const char *sp)
{
	/*** copy string sp ***/
	register char *ptr = editb.e_outptr;
	while(*sp)
		*ptr++ = *sp++;
	editb.e_outptr = ptr;
	return;
}

/*{	PUTSTRING( column, nchars )
 *
 *	Put nchars starting at column of physical into the workspace
 * to be printed.
 *
}*/

static void putstring(register Vi_t *vp,register int col, register int nchars)
{
	while( nchars-- )
		putchar(physical[col++]);
	return;
}

/*{	REFRESH( mode )
 *
 *	This routine will refresh the crt so the physical image matches
 * the virtual image and display the proper window.
 *
 *	mode	= CONTROL, refresh in control mode, ie. leave cursor
 *			positioned at last char printed.
 *		= INPUT, refresh in input mode; leave cursor positioned
 *			after last char printed.
 *		= TRANSLATE, perform virtual to physical translation
 *			and adjust left margin only.
 *
 *		+-------------------------------+
 *		|   | |    virtual	  | |   |
 *		+-------------------------------+
 *		  cur_virt		last_virt
 *
 *		+-----------------------------------------------+
 *		|	  | |	        physical	 | |    |
 *		+-----------------------------------------------+
 *			cur_phys			last_phys
 *
 *				0			w_size - 1
 *				+-----------------------+
 *				| | |  window		|
 *				+-----------------------+
 *				cur_window = cur_phys - first_wind
}*/

static void refresh(register Vi_t* vp, int mode)
{
	register int p;
	register int regb;
	register int first_w = vp->first_wind;
	int p_differ;
	int new_lw;
	int ncur_phys;
	int opflag;			/* search optimize flag */

#	define	w	regb
#	define	v	regb

	/*** find out if it's necessary to start translating at beginning ***/

	if(lookahead>0)
	{
		p = previous[lookahead-1];
		if(p != ESC && p != '\n' && p != '\r')
			mode = TRANSLATE;
	}
	v = cur_virt;
	if( v<vp->ocur_virt || vp->ocur_virt==INVALID
		|| ( v==vp->ocur_virt
			&& (!is_print(virtual[v]) || !is_print(vp->o_v_char))) )
	{
		opflag = 0;
		p = 0;
		v = 0;
	}
	else
	{
		opflag = 1;
		p = vp->ocur_phys;
		v = vp->ocur_virt;
		if( !is_print(virtual[v]) )
		{
			/*** avoid double ^'s ***/
			++p;
			++v;
		}
	}
	virtual[last_virt+1] = 0;
	ncur_phys = ed_virt_to_phys(vp->ed,virtual,physical,cur_virt,v,p);
	p = genlen(physical);
	if( --p < 0 )
		last_phys = 0;
	else
		last_phys = p;

	/*** see if this was a translate only ***/

	if( mode == TRANSLATE )
		return;

	/*** adjust left margin if necessary ***/

	if( ncur_phys<first_w || ncur_phys>=(first_w + w_size) )
	{
		cursor(vp,first_w);
		first_w = ncur_phys - (w_size>>1);
		if( first_w < 0 )
			first_w = 0;
		vp->first_wind = cur_phys = first_w;
	}

	/*** attempt to optimize search somewhat to find ***/
	/*** out where physical and window images differ ***/

	if( first_w==vp->ofirst_wind && ncur_phys>=vp->ocur_phys && opflag==1 )
	{
		p = vp->ocur_phys;
		w = p - first_w;
	}
	else
	{
		p = first_w;
		w = 0;
	}

	for(; (p<=last_phys && w<=vp->last_wind); ++p, ++w)
	{
		if( window[w] != physical[p] )
			break;
	}
	p_differ = p;

	if( (p>last_phys || p>=first_w+w_size) && w>vp->last_wind
		&& cur_virt==vp->ocur_virt )
	{
		/*** images are identical ***/
		return;
	}

	/*** copy the physical image to the window image ***/

	if( last_virt != INVALID )
	{
		while( p <= last_phys && w < w_size )
			window[w++] = physical[p++];
	}
	new_lw = w;

	/*** erase trailing characters if needed ***/

	while( w <= vp->last_wind )
		window[w++] = ' ';
	vp->last_wind = --w;

	p = p_differ;

	/*** move cursor to start of difference ***/

	cursor(vp,p);

	/*** and output difference ***/

	w = p - first_w;
	while( w <= vp->last_wind )
		putchar(window[w++]);

	cur_phys = w + first_w;
	vp->last_wind = --new_lw;

	if( last_phys >= w_size )
	{
		if( first_w == 0 )
			vp->long_char = '>';
		else if( last_phys < (first_w+w_size) )
			vp->long_char = '<';
		else
			vp->long_char = '*';
	}
	else
		vp->long_char = ' ';

	if( vp->long_line != vp->long_char )
	{
		/*** indicate lines longer than window ***/
		while( w++ < w_size )
		{
			putchar(' ');
			++cur_phys;
		}
		putchar(vp->long_char);
		++cur_phys;
		vp->long_line = vp->long_char;
	}

	if(vp->ed->e_multiline &&  vp->ofirst_wind==INVALID && !vp->ed->e_nocrnl)
		ed_setcursor(vp->ed, physical, last_phys+1, last_phys+1, -1);
	vp->ed->e_nocrnl = 0;
	vp->ocur_phys = ncur_phys;
	vp->ocur_virt = cur_virt;
	vp->ofirst_wind = first_w;

	if( mode==INPUT && cur_virt>INVALID )
		++ncur_phys;

	cursor(vp,ncur_phys);
	ed_flush(vp->ed);
	return;
}

/*{	REPLACE( char, increment )
 *
 *	Replace the cur_virt character with char.  This routine attempts
 * to avoid using refresh().
 *
 *	increment	= 1, increment cur_virt after replacement.
 *			= 0, leave cur_virt where it is.
 *
}*/

static void replace(register Vi_t *vp, register int c, register int increment)
{
	register int cur_window;

	if( cur_virt == INVALID )
	{
		/*** can't replace invalid cursor ***/
		ed_ringbell();
		return;
	}
	cur_window = cur_phys - vp->first_wind;
	if( vp->ocur_virt == INVALID || !is_print(c)
		|| !is_print(virtual[cur_virt])
		|| !is_print(vp->o_v_char)
#if SHOPT_MULTIBYTE
		|| !iswascii(c) || mbwidth(vp->o_v_char)>1
		|| !iswascii(virtual[cur_virt])
#endif /* SHOPT_MULTIBYTE */
		|| (increment && (cur_window==w_size-1)
			|| !is_print(virtual[cur_virt+1])) )
	{
		/*** must use standard refresh routine ***/

		cdelete(vp,1, BAD);
		append(vp,c, APPEND);
		if( increment && cur_virt<last_virt )
			++cur_virt;
		refresh(vp,CONTROL);
	}
	else
	{
		virtual[cur_virt] = c;
		physical[cur_phys] = c;
		window[cur_window] = c;
		putchar(c);
		if(increment)
		{
			c = virtual[++cur_virt];
			++cur_phys;
		}
		else
		{
			putchar('\b');
		}
		vp->o_v_char = c;
		ed_flush(vp->ed);
	}
	return;
}

/*{	RESTORE_V()
 *
 *	Restore the contents of virtual space from u_space.
 *
}*/

static void restore_v(register Vi_t *vp)
{
	register int tmpcol;
	genchar tmpspace[MAXLINE];

	if( vp->u_column == INVALID-1 )
	{
		/*** never saved anything ***/
		ed_ringbell();
		return;
	}
	gencpy(tmpspace, vp->u_space);
	tmpcol = vp->u_column;
	save_v(vp);
	gencpy(virtual, tmpspace);
	cur_virt = tmpcol;
	last_virt = genlen(tmpspace) - 1;
	vp->ocur_virt = MAXCHAR;	/** invalidate refresh optimization **/
	return;
}

/*{	SAVE_LAST()
 *
 *	If the user has typed something, save it in last line.
 *
}*/

static void save_last(register Vi_t* vp)
{
	register int i;

	if( (i = cur_virt - first_virt + 1) > 0 )
	{
		/*** save last thing user typed ***/
		if(i >= MAXLINE)
			i = MAXLINE-1;
		genncpy(vp->lastline, (&virtual[first_virt]), i);
		vp->lastline[i] = '\0';
	}
	return;
}

/*{	SAVE_V()
 *
 *	This routine will save the contents of virtual in u_space.
 *
}*/

static void save_v(register Vi_t *vp)
{
	if(!inmacro)
	{
		virtual[last_virt + 1] = '\0';
		gencpy(vp->u_space, virtual);
		vp->u_column = cur_virt;
	}
	return;
}

/*{	SEARCH( mode )
 *
 *	Search history file for regular expression.
 *
 *	mode	= '/'	require search string and search new to old
 *	mode	= '?'	require search string and search old to new
 *	mode	= 'N'	repeat last search in reverse direction
 *	mode	= 'n'	repeat last search
 *
}*/

/*
 * search for <string> in the current command
 */
static int curline_search(Vi_t *vp, const char *string)
{
	register int len=strlen(string);
	register const char *dp,*cp=string, *dpmax;
#if SHOPT_MULTIBYTE
	ed_external(vp->u_space,(char*)vp->u_space);
#endif /* SHOPT_MULTIBYTE */
	for(dp=(char*)vp->u_space,dpmax=dp+strlen(dp)-len; dp<=dpmax; dp++)
	{
		if(*dp==*cp && memcmp(cp,dp,len)==0)
			return(dp-(char*)vp->u_space);
	}
#if SHOPT_MULTIBYTE
	ed_internal((char*)vp->u_space,vp->u_space);
#endif /* SHOPT_MULTIBYTE */
	return(-1);
}

static int search(register Vi_t* vp,register int mode)
{
	register int new_direction;
	register int oldcurhline;
	register int i;
	Histloc_t  location;

	if( vp->direction == -2 && mode != 'n')
		vp->direction = -1;
	if( mode == '/' || mode == '?')
	{
		/*** new search expression ***/
		del_line(vp,BAD);
		append(vp,mode, APPEND);
		refresh(vp,INPUT);
		first_virt = 1;
		getline(vp,SEARCH);
		first_virt = 0;
		virtual[last_virt + 1] = '\0';	/*** make null terminated ***/
		vp->direction = mode=='/' ? -1 : 1;
	}

	if( cur_virt == INVALID )
	{
		/*** no operation ***/
		return(ABORT);
	}

	if( cur_virt==0 ||  fold(mode)=='N' )
	{
		/*** user wants repeat of last search ***/
		del_line(vp,BAD);
		strcpy( ((char*)virtual)+1, lsearch);
#if SHOPT_MULTIBYTE
		*((char*)virtual) = '/';
		ed_internal((char*)virtual,virtual);
#endif /* SHOPT_MULTIBYTE */
	}

	if( mode == 'N' )
		new_direction = -vp->direction;
	else
		new_direction = vp->direction;


	/*** now search ***/

	oldcurhline = curhline;
#if SHOPT_MULTIBYTE
	ed_external(virtual,(char*)virtual);
#endif /* SHOPT_MULTIBYTE */
	if(mode=='?' && (i=curline_search(vp,((char*)virtual)+1))>=0)
	{
		location.hist_command = curhline;
		location.hist_char = i;
	}
	else
	{
		i = INVALID;
		if( new_direction==1 && curhline >= histmax )
			curhline = histmin + 1;
		location = hist_find(sh.hist_ptr,((char*)virtual)+1, curhline, 1, new_direction);
	}
	cur_virt = i;
	strncpy(lsearch, ((char*)virtual)+1, SEARCHSIZE);
	if( (curhline=location.hist_command) >=0 )
	{
		vp->ocur_virt = INVALID;
		return(GOOD);
	}

	/*** could not find matching line ***/

	curhline = oldcurhline;
	return(BAD);
}

/*{	SYNC_CURSOR()
 *
 *	This routine will move the physical cursor to the same
 * column as the virtual cursor.
 *
}*/

static void sync_cursor(register Vi_t *vp)
{
	register int p;
	register int v;
	register int c;
	int new_phys;

	if( cur_virt == INVALID )
		return;

	/*** find physical col that corresponds to virtual col ***/

	new_phys = 0;
	if(vp->first_wind==vp->ofirst_wind && cur_virt>vp->ocur_virt && vp->ocur_virt!=INVALID)
	{
		/*** try to optimize search a little ***/
		p = vp->ocur_phys + 1;
#if SHOPT_MULTIBYTE
		while(physical[p]==MARKER)
			p++;
#endif /* SHOPT_MULTIBYTE */
		v = vp->ocur_virt + 1;
	}
	else
	{
		p = 0;
		v = 0;
	}
	for(; v <= last_virt; ++p, ++v)
	{
#if SHOPT_MULTIBYTE
		int d;
		c = virtual[v];
		if((d = mbwidth(c)) > 1)
		{
			if( v != cur_virt )
				p += (d-1);
		}
		else if(!iswprint(c))
#else
		c = virtual[v];
		if(!isprint(c))
#endif	/* SHOPT_MULTIBYTE */
		{
			if( c == '\t' )
			{
				p -= ((p+editb.e_plen)%TABSIZE);
				p += (TABSIZE-1);
			}
			else
			{
				++p;
			}
		}
		if( v == cur_virt )
		{
			new_phys = p;
			break;
		}
	}

	if( new_phys < vp->first_wind || new_phys >= vp->first_wind + w_size )
	{
		/*** asked to move outside of window ***/

		window[0] = '\0';
		refresh(vp,CONTROL);
		return;
	}

	cursor(vp,new_phys);
	ed_flush(vp->ed);
	vp->ocur_phys = cur_phys;
	vp->ocur_virt = cur_virt;
	vp->o_v_char = virtual[vp->ocur_virt];

	return;
}

/*{	TEXTMOD( command, mode )
 *
 *	Modify text operations.
 *
 *	mode != 0, repeat previous operation
 *
}*/

static int textmod(register Vi_t *vp,register int c, int mode)
{
	register int i;
	register genchar *p = vp->lastline;
	register int trepeat = vp->repeat;
	genchar *savep;

	if(mode && (fold(vp->lastmotion)=='F' || fold(vp->lastmotion)=='T')) 
		vp->lastmotion = ';';

	if( fold(c) == 'P' )
	{
		/*** change p from lastline to yankbuf ***/
		p = yankbuf;
	}

addin:
	switch( c )
	{
			/***** Input commands *****/

#if KSHELL
        case '\t':
		if(vp->ed->e_tabcount!=1)
			return(BAD);
		c = '=';
		/* FALLTHROUGH */
	case '*':		/** do file name expansion in place **/
	case '\\':		/** do file name completion in place **/
		if( cur_virt == INVALID )
			return(BAD);
		/* FALLTHROUGH */
	case '=':		/** list file name expansions **/
		save_v(vp);
		i = last_virt;
		++last_virt;
		mode = cur_virt-1;
		virtual[last_virt] = 0;
		if(ed_expand(vp->ed,(char*)virtual, &cur_virt, &last_virt, c, vp->repeat_set?vp->repeat:-1)<0)
		{
			if(vp->ed->e_tabcount)
			{
				vp->ed->e_tabcount=2;
				ed_ungetchar(vp->ed,'\t');
				--last_virt;
				return(APPEND);
			}
			last_virt = i;
			ed_ringbell();
		}
		else if(c == '=' && !vp->repeat_set)
		{
			last_virt = i;
			vp->nonewline++;
			ed_ungetchar(vp->ed,cntl('L'));
			return(GOOD);
		}
		else
		{
			--cur_virt;
			--last_virt;
			vp->ocur_virt = MAXCHAR;
			if(c=='=' || (mode<cur_virt && (virtual[cur_virt]==' ' || virtual[cur_virt]=='/')))
				vp->ed->e_tabcount = 0;
			return(APPEND);
		}
		break;

	case '@':		/** macro expansion **/
		if( mode )
			c = vp->lastmacro;
		else
			if((c=getrchar(vp))==ESC)
				return(GOOD);
		if(!inmacro)
			vp->lastmacro = c;
		if(ed_macro(vp->ed,c))
		{
			save_v(vp);
			inmacro++;
			return(GOOD);
		}
		ed_ringbell();
		return(BAD);

#endif	/* KSHELL */
	case '_':		/** append last argument of prev command **/
		save_v(vp);
		{
			genchar tmpbuf[MAXLINE];
			if(vp->repeat_set==0)
				vp->repeat = -1;
			p = (genchar*)hist_word((char*)tmpbuf,MAXLINE,vp->repeat);
			if(p==0)
			{
				ed_ringbell();
				break;
			}
#if SHOPT_MULTIBYTE
			ed_internal((char*)p,tmpbuf);
			p = tmpbuf;
#endif /* SHOPT_MULTIBYTE */
			i = ' ';
			do
			{
				append(vp,i,APPEND);
			}
			while(i = *p++);
			return(APPEND);
		}

	case 'A':		/** append to end of line **/
		cur_virt = last_virt;
		sync_cursor(vp);
		/* FALLTHROUGH */

	case 'a':		/** append **/
		if( fold(mode) == 'A' )
		{
			c = 'p';
			goto addin;
		}
		save_v(vp);
		if( cur_virt != INVALID )
		{
			first_virt = cur_virt + 1;
			cursor(vp,cur_phys + 1);
			ed_flush(vp->ed);
		}
		return(APPEND);

	case 'I':		/** insert at beginning of line **/
		cur_virt = first_virt;
		sync_cursor(vp);
		/* FALLTHROUGH */

	case 'i':		/** insert **/
		if( fold(mode) == 'I' )
		{
			c = 'P';
			goto addin;
		}
		save_v(vp);
		if( cur_virt != INVALID )
 		{
 			vp->o_v_char = virtual[cur_virt];
			first_virt = cur_virt--;
  		}
		return(INSERT);

	case 'C':		/** change to eol **/
		c = '$';
		goto chgeol;

	case 'c':		/** change **/
		if( mode )
			c = vp->lastmotion;
		else
			c = getcount(vp,ed_getchar(vp->ed,-1));
chgeol:
		vp->lastmotion = c;
		if( c == 'c' )
		{
			del_line(vp,GOOD);
			return(APPEND);
		}

		if(!delmotion(vp, c, 'c'))
			return(BAD);

		if( mode == 'c' )
		{
			c = 'p';
			trepeat = 1;
			goto addin;
		}
		first_virt = cur_virt + 1;
		return(APPEND);

	case 'D':		/** delete to eol **/
		c = '$';
		goto deleol;

	case 'd':		/** delete **/
		if( mode )
			c = vp->lastmotion;
		else
			c = getcount(vp,ed_getchar(vp->ed,-1));
deleol:
		vp->lastmotion = c;
		if( c == 'd' )
		{
			del_line(vp,GOOD);
			break;
		}
		if(!delmotion(vp, c, 'd'))
			return(BAD);
		if( cur_virt < last_virt )
			++cur_virt;
		break;

	case 'P':
		if( p[0] == '\0' )
			return(BAD);
		if( cur_virt != INVALID )
		{
			i = virtual[cur_virt];
			if(!is_print(i))
				vp->ocur_virt = INVALID;
			--cur_virt;
		}
		/* FALLTHROUGH */

	case 'p':		/** print **/
		if( p[0] == '\0' )
			return(BAD);

		if( mode != 's' && mode != 'c' )
		{
			save_v(vp);
			if( c == 'P' )
			{
				/*** fix stored cur_virt ***/
				++vp->u_column;
			}
		}
		if( mode == 'R' )
			mode = REPLACE;
		else
			mode = APPEND;
		savep = p;
		for(i=0; i<trepeat; ++i)
		{
			while(c= *p++)
				append(vp,c,mode);
			p = savep;
		}
		break;

	case 'R':		/* Replace many chars **/
		if( mode == 'R' )
		{
			c = 'P';
			goto addin;
		}
		save_v(vp);
		if( cur_virt != INVALID )
			first_virt = cur_virt;
		return(REPLACE);

	case 'r':		/** replace **/
		if( mode )
			c = *p;
		else
			if((c=getrchar(vp))==ESC)
				return(GOOD);
		*p = c;
		save_v(vp);
		while(trepeat--)
			replace(vp,c, trepeat!=0);
		return(GOOD);

	case 'S':		/** Substitute line - cc **/
		c = 'c';
		goto chgeol;

	case 's':		/** substitute **/
		save_v(vp);
		cdelete(vp,vp->repeat, BAD);
		if( mode )
		{
			c = 'p';
			trepeat = 1;
			goto addin;
		}
		first_virt = cur_virt + 1;
		return(APPEND);

	case 'Y':		/** Yank to end of line **/
		c = '$';
		goto yankeol;

	case 'y':		/** yank thru motion **/
		if( mode )
			c = vp->lastmotion;
		else
			c = getcount(vp,ed_getchar(vp->ed,-1));
yankeol:
		vp->lastmotion = c;
		if( c == 'y' )
		{
			gencpy(yankbuf, virtual);
		}
		else if(!delmotion(vp, c, 'y'))
		{
			return(BAD);
		}
		break;

	case 'x':		/** delete repeat chars forward - dl **/
		c = 'l';
		goto deleol;

	case 'X':		/** delete repeat chars backward - dh **/
		c = 'h';
		goto deleol;

	case '~':		/** invert case and advance **/
		if( cur_virt != INVALID )
		{
			save_v(vp);
			i = INVALID;
			while(trepeat-->0 && i!=cur_virt)
			{
				i = cur_virt;
				c = virtual[cur_virt];
#if SHOPT_MULTIBYTE
				if((c&~STRIP)==0)
#endif /* SHOPT_MULTIBYTE */
				if( isupper(c) )
					c = tolower(c);
				else if( islower(c) )
					c = toupper(c);
				replace(vp,c, 1);
			}
			return(GOOD);
		}
		else
			return(BAD);

	default:
		return(BAD);
	}
	refresh(vp,CONTROL);
	return(GOOD);
}


#if SHOPT_MULTIBYTE
    static int _isalph(register int v)
    {
#ifdef _lib_iswalnum
	return(iswalnum(v) || v=='_');
#else
	return((v&~STRIP) || isalnum(v) || v=='_');
#endif
    }


    static int _isblank(register int v)
    {
	return((v&~STRIP)==0 && isspace(v));
    }

    static int _ismetach(register int v)
    {
	return((v&~STRIP)==0 && ismeta(v));
    }

#endif	/* SHOPT_MULTIBYTE */

/*
 * get a character, after ^V processing
 */
static int getrchar(register Vi_t *vp)
{
	register int c;
	if((c=ed_getchar(vp->ed,1))== usrlnext)
		c = ed_getchar(vp->ed,2);
	return(c);
}
