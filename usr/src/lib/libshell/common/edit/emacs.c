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
/* Original version by Michael T. Veach 
 * Adapted for ksh by David Korn */
/* EMACS_MODES: c tabstop=4 

One line screen editor for any program

*/


/*	The following is provided by:
 *
 *			Matthijs N. Melchior
 *			AT&T Network Systems International
 *			APT Nederland
 *			HV BZ335 x2962
 *			hvlpb!mmelchio
 *
 *  These are now on by default
 *
 *  ESH_NFIRST
 *	-  A ^N as first history related command after the prompt will move
 *	   to the next command relative to the last known history position.
 *	   It will not start at the position where the last command was entered
 *	   as is done by the ^P command.  Every history related command will
 *	   set both the current and last position.  Executing a command will
 *	   only set the current position.
 *
 *  ESH_KAPPEND
 *	-  Successive kill and delete commands will accumulate their data
 *	   in the kill buffer, by appending or prepending as appropriate.
 *	   This mode will be reset by any command not adding something to the
 *	   kill buffer.
 *
 *  ESH_BETTER
 *	-  Some enhancements:
 *		- argument for a macro is passed to its replacement
 *		- ^X^H command to find out about history position (debugging)
 *		- ^X^D command to show any debugging info
 *
 *  I do not pretend these for changes are completely independent,
 *  but you can use them to seperate features.
 */

#include	<ast.h>
#include	"FEATURE/cmds"
#if KSHELL
#   include	"defs.h"
#else
#   include	<ctype.h>
#endif	/* KSHELL */
#include	"io.h"

#include	"history.h"
#include	"edit.h"
#include	"terminal.h"

#define ESH_NFIRST
#define ESH_KAPPEND
#define ESH_BETTER

#undef putchar
#define putchar(ed,c)	ed_putchar(ed,c)
#define beep()		ed_ringbell()


#if SHOPT_MULTIBYTE
#   define gencpy(a,b)	ed_gencpy(a,b)
#   define genncpy(a,b,n)	ed_genncpy(a,b,n)
#   define genlen(str)	ed_genlen(str)
    static int	print(int);
    static int	_isword(int);
#   define  isword(c)	_isword(out[c])

#else
#   define gencpy(a,b)	strcpy((char*)(a),(char*)(b))
#   define genncpy(a,b,n)	strncpy((char*)(a),(char*)(b),n)
#   define genlen(str)	strlen(str)
#   define print(c)	isprint(c)
#   define isword(c)	(isalnum(out[c]) || (out[c]=='_'))
#endif /*SHOPT_MULTIBYTE */

typedef struct _emacs_
{
	genchar *screen;	/* pointer to window buffer */
	genchar *cursor;	/* Cursor in real screen */
	int 	mark;
	int 	in_mult;
	char	cr_ok;
	char	CntrlO;
	char	overflow;		/* Screen overflow flag set */
	char	scvalid;		/* Screen is up to date */
	char	lastdraw;	/* last update type */
	int	offset;		/* Screen offset */
	enum
	{
		CRT=0,	/* Crt terminal */
		PAPER	/* Paper terminal */
	} terminal;
	Histloc_t _location;
	int	prevdirection; 
	Edit_t	*ed;	/* pointer to edit data */
} Emacs_t;

#define	editb		(*ep->ed)
#define eol		editb.e_eol
#define cur		editb.e_cur
#define hline		editb.e_hline
#define hloff		editb.e_hloff
#define hismin		editb.e_hismin
#define usrkill		editb.e_kill
#define usrlnext	editb.e_lnext
#define usreof		editb.e_eof
#define usrerase	editb.e_erase
#define crallowed	editb.e_crlf
#define Prompt		editb.e_prompt
#define plen		editb.e_plen
#define kstack		editb.e_killbuf
#define lstring		editb.e_search
#define lookahead	editb.e_lookahead
#define env		editb.e_env
#define raw		editb.e_raw
#define histlines	editb.e_hismax
#define w_size		editb.e_wsize
#define drawbuff	editb.e_inbuf
#define killing		editb.e_mode
#define location	ep->_location

#define LBUF	100
#define KILLCHAR	UKILL
#define ERASECHAR	UERASE
#define EOFCHAR		UEOF
#define LNEXTCHAR		ULNEXT
#define DELETE		('a'==97?0177:7)

/**********************
A large lookahead helps when the user is inserting
characters in the middle of the line.
************************/


typedef enum
{
	FIRST,		/* First time thru for logical line, prompt on screen */
	REFRESH,	/* Redraw entire screen */
	APPEND,		/* Append char before cursor to screen */
	UPDATE,		/* Update the screen as need be */
	FINAL		/* Update screen even if pending look ahead */
} Draw_t;

static void draw(Emacs_t*,Draw_t);
static int escape(Emacs_t*,genchar*, int);
static void putstring(Emacs_t*,char*);
static void search(Emacs_t*,genchar*,int);
static void setcursor(Emacs_t*,int, int);
static void show_info(Emacs_t*,const char*);
static void xcommands(Emacs_t*,int);

int ed_emacsread(void *context, int fd,char *buff,int scend, int reedit)
{
	Edit_t *ed = (Edit_t*)context;
	register int c;
	register int i;
	register genchar *out;
	register int count;
	register Emacs_t *ep = ed->e_emacs;
	int adjust,oadjust;
	char backslash;
	genchar *kptr;
	char prompt[PRSIZE];
	genchar Screen[MAXLINE];
	if(!ep)
	{
		ep = ed->e_emacs = newof(0,Emacs_t,1,0);
		ep->ed = ed;
		ep->prevdirection =  1;
		location.hist_command =  -5;
	}
	Prompt = prompt;
	ep->screen = Screen;
	ep->lastdraw = FINAL;
	if(tty_raw(ERRIO,0) < 0)
	{
		 return(reedit?reedit:ed_read(context, fd,buff,scend,0));
	}
	raw = 1;
	/* This mess in case the read system call fails */
	
	ed_setup(ep->ed,fd,reedit);
	out = (genchar*)buff;
#if SHOPT_MULTIBYTE
	out = (genchar*)roundof(buff-(char*)0,sizeof(genchar));
	if(reedit)
		ed_internal(buff,out);
#endif /* SHOPT_MULTIBYTE */
	if(!kstack)
	{
		kstack = (genchar*)malloc(CHARSIZE*MAXLINE);
		kstack[0] = '\0';
	}
	drawbuff = out;
#ifdef ESH_NFIRST
	if (location.hist_command == -5)		/* to be initialized */
	{
		kstack[0] = '\0';		/* also clear kstack... */
		location.hist_command = hline;
		location.hist_line = hloff;
	}
	if (location.hist_command <= hismin)	/* don't start below minimum */
	{
		location.hist_command = hismin + 1;
		location.hist_line = 0;
	}
	ep->in_mult = hloff;			/* save pos in last command */
#endif /* ESH_NFIRST */
	i = sigsetjmp(env,0);
	if (i !=0)
	{
		if(ep->ed->e_multiline)
		{
			cur = eol;
			draw(ep,FINAL);
			ed_flush(ep->ed);
		}
		tty_cooked(ERRIO);
		if (i == UEOF)
		{
			return(0); /* EOF */
		}
		return(-1); /* some other error */
	}
	out[reedit] = 0;
	if(scend+plen > (MAXLINE-2))
		scend = (MAXLINE-2)-plen;
	ep->mark = 0;
	cur = eol;
	draw(ep,reedit?REFRESH:FIRST);
	adjust = -1;
	backslash = 0;
	if (ep->CntrlO)
	{
#ifdef ESH_NFIRST
		ed_ungetchar(ep->ed,cntl('N'));
#else
		location = hist_locate(sh.hist_ptr,location.hist_command,location.hist_line,1);
		if (location.hist_command < histlines)
		{
			hline = location.hist_command;
			hloff = location.hist_line;
			hist_copy((char*)kstack,MAXLINE, hline,hloff);
#   if SHOPT_MULTIBYTE
			ed_internal((char*)kstack,kstack);
#   endif /* SHOPT_MULTIBYTE */
			ed_ungetchar(ep->ed,cntl('Y'));
		}
#endif /* ESH_NFIRST */
	}
	ep->CntrlO = 0;
	while ((c = ed_getchar(ep->ed,0)) != (-1))
	{
		if (backslash)
		{
			backslash = 0;
			if (c==usrerase||c==usrkill||(!print(c) &&
				(c!='\r'&&c!='\n')))
			{
				/* accept a backslashed character */
				cur--;
				out[cur++] = c;
				out[eol] = '\0';
				draw(ep,APPEND);
				continue;
			}
		}
		if (c == usrkill)
		{
			c = KILLCHAR ;
		}
		else if (c == usrerase)
		{
			c = ERASECHAR ;
		} 
		else if (c == usrlnext)
		{
			c = LNEXTCHAR ;
		}
		else if ((c == usreof)&&(eol == 0))
		{
			c = EOFCHAR;
		}
#ifdef ESH_KAPPEND
		if (--killing <= 0)	/* reset killing flag */
			killing = 0;
#endif
		oadjust = count = adjust;
		if(count<0)
			count = 1;
		adjust = -1;
		i = cur;
		switch(c)
		{
		case LNEXTCHAR:
			c = ed_getchar(ep->ed,2);
			goto do_default_processing;
		case cntl('V'):
			show_info(ep,fmtident(e_version));
			continue;
		case '\0':
			ep->mark = i;
			continue;
		case cntl('X'):
			xcommands(ep,count);
			continue;
		case EOFCHAR:
			ed_flush(ep->ed);
			tty_cooked(ERRIO);
			return(0);
#ifdef u370
		case cntl('S') :
		case cntl('Q') :
			continue;
#endif	/* u370 */
		case '\t':
			if(cur>0  && ep->ed->sh->nextprompt)
			{
				if(ep->ed->e_tabcount==0)
				{
					ep->ed->e_tabcount=1;
					ed_ungetchar(ep->ed,ESC);
					goto do_escape;
				}
				else if(ep->ed->e_tabcount==1)
				{
					ed_ungetchar(ep->ed,'=');
					goto do_escape;
				}
				ep->ed->e_tabcount = 0;
			}
			/* FALLTHROUGH */
		do_default_processing:
		default:

			if ((eol+1) >= (scend)) /*  will not fit on line */
			{
				ed_ungetchar(ep->ed,c); /* save character for next line */
				goto process;
			}
			for(i= ++eol; i>cur; i--)
				out[i] = out[i-1];
			backslash =  (c == '\\');
			out[cur++] = c;
			draw(ep,APPEND);
			continue;
		case cntl('Y') :
			{
				c = genlen(kstack);
				if ((c + eol) > scend)
				{
					beep();
					continue;
				}
				ep->mark = i;
				for(i=eol;i>=cur;i--)
					out[c+i] = out[i];
				kptr=kstack;
				while (i = *kptr++)
					out[cur++] = i;
				draw(ep,UPDATE);
				eol = genlen(out);
				continue;
			}
		case '\n':
		case '\r':
			c = '\n';
			goto process;

		case DELETE:	/* delete char 0x7f */
		case '\b':	/* backspace, ^h */
		case ERASECHAR :
			if (count > i)
				count = i;
#ifdef ESH_KAPPEND
			kptr = &kstack[count];	/* move old contents here */
			if (killing)		/* prepend to killbuf */
			{
				c = genlen(kstack) + CHARSIZE; /* include '\0' */
				while(c--)	/* copy stuff */
					kptr[c] = kstack[c];
			}
			else
				*kptr = 0;	/* this is end of data */
			killing = 2;		/* we are killing */
			i -= count;
			eol -= count;
			genncpy(kstack,out+i,cur-i);
#else
			while ((count--)&&(i>0))
			{
				i--;
				eol--;
			}
			genncpy(kstack,out+i,cur-i);
			kstack[cur-i] = 0;
#endif /* ESH_KAPPEND */
			gencpy(out+i,out+cur);
			ep->mark = i;
			goto update;
		case cntl('W') :
#ifdef ESH_KAPPEND
			++killing;		/* keep killing flag */
#endif
			if (ep->mark > eol )
				ep->mark = eol;
			if (ep->mark == i)
				continue;
			if (ep->mark > i)
			{
				adjust = ep->mark - i;
				ed_ungetchar(ep->ed,cntl('D'));
				continue;
			}
			adjust = i - ep->mark;
			ed_ungetchar(ep->ed,usrerase);
			continue;
		case cntl('D') :
			ep->mark = i;
#ifdef ESH_KAPPEND
			if (killing)
				kptr = &kstack[genlen(kstack)];	/* append here */
			else
				kptr = kstack;
			killing = 2;			/* we are now killing */
#else
			kptr = kstack;
#endif /* ESH_KAPPEND */
			while ((count--)&&(eol>0)&&(i<eol))
			{
				*kptr++ = out[i];
				eol--;
				while(1)
				{
					if ((out[i] = out[(i+1)])==0)
						break;
					i++;
				}
				i = cur;
			}
			*kptr = '\0';
			goto update;
		case cntl('C') :
		case cntl('F') :
		{
			int cntlC = (c==cntl('C'));
			while (count-- && eol>i)
			{
				if (cntlC)
				{
					c = out[i];
#if SHOPT_MULTIBYTE
					if((c&~STRIP)==0 && islower(c))
#else
					if(islower(c))
#endif /* SHOPT_MULTIBYTE */
					{
						c += 'A' - 'a';
						out[i] = c;
					}
				}
				i++;
			}
			goto update;
		}
		case cntl(']') :
			c = ed_getchar(ep->ed,1);
			if ((count == 0) || (count > eol))
                        {
                                beep();
                                continue;
                        }
			if (out[i])
				i++;
			while (i < eol)
			{
				if (out[i] == c && --count==0)
					goto update;
				i++;
			}
			i = 0;
			while (i < cur)
			{
				if (out[i] == c && --count==0)
					break;
				i++;
			};

update:
			cur = i;
			draw(ep,UPDATE);
			continue;

		case cntl('B') :
			if (count > i)
				count = i;
			i -= count;
			goto update;
		case cntl('T') :
			if ((sh_isoption(SH_EMACS))&& (eol!=i))
				i++;
			if (i >= 2)
			{
				c = out[i - 1];
				out[i-1] = out[i-2];
				out[i-2] = c;
			}
			else
			{
				if(sh_isoption(SH_EMACS))
					i--;
				beep();
				continue;
			}
			goto update;
		case cntl('A') :
			i = 0;
			goto update;
		case cntl('E') :
			i = eol;
			goto update;
		case cntl('U') :
			adjust = 4*count;
			continue;
		case KILLCHAR :
			cur = 0;
			oadjust = -1;
			/* FALLTHROUGH */
		case cntl('K') :
			if(oadjust >= 0)
			{
#ifdef ESH_KAPPEND
				killing = 2;		/* set killing signal */
#endif
				ep->mark = count;
				ed_ungetchar(ep->ed,cntl('W'));
				continue;
			}
			i = cur;
			eol = i;
			ep->mark = i;
#ifdef ESH_KAPPEND
			if (killing)			/* append to kill buffer */
				gencpy(&kstack[genlen(kstack)], &out[i]);
			else
				gencpy(kstack,&out[i]);
			killing = 2;			/* set killing signal */
#else
			gencpy(kstack,&out[i]);
#endif /* ESH_KAPPEND */
			out[i] = 0;
			draw(ep,UPDATE);
			if (c == KILLCHAR)
			{
				if (ep->terminal == PAPER)
				{
					putchar(ep->ed,'\n');
					putstring(ep,Prompt);
				}
				c = ed_getchar(ep->ed,0);
				if (c != usrkill)
				{
					ed_ungetchar(ep->ed,c);
					continue;
				}
				if (ep->terminal == PAPER)
					ep->terminal = CRT;
				else
				{
					ep->terminal = PAPER;
					putchar(ep->ed,'\n');
					putstring(ep,Prompt);
				}
			}
			continue;
		case cntl('L'):
			if(!ep->ed->e_nocrnl)
				ed_crlf(ep->ed);
			draw(ep,REFRESH);
			ep->ed->e_nocrnl = 0;
			continue;
		case cntl('[') :
		do_escape:
			adjust = escape(ep,out,oadjust);
			continue;
		case cntl('R') :
			search(ep,out,count);
			goto drawline;
		case cntl('P') :
                        if (count <= hloff)
                                hloff -= count;
                        else
                        {
                                hline -= count - hloff;
                                hloff = 0;
                        }
#ifdef ESH_NFIRST
			if (hline <= hismin)
#else
			if (hline < hismin)
#endif /* ESH_NFIRST */
			{
				hline = hismin+1;
				beep();
#ifndef ESH_NFIRST
				continue;
#endif
			}
			goto common;

		case cntl('O') :
			location.hist_command = hline;
			location.hist_line = hloff;
			ep->CntrlO = 1;
			c = '\n';
			goto process;
		case cntl('N') :
#ifdef ESH_NFIRST
			hline = location.hist_command;	/* start at saved position */
			hloff = location.hist_line;
#endif /* ESH_NFIRST */
			location = hist_locate(sh.hist_ptr,hline,hloff,count);
			if (location.hist_command > histlines)
			{
				beep();
#ifdef ESH_NFIRST
				location.hist_command = histlines;
				location.hist_line = ep->in_mult;
#else
				continue;
#endif /* ESH_NFIRST */
			}
			hline = location.hist_command;
			hloff = location.hist_line;
		common:
#ifdef ESH_NFIRST
			location.hist_command = hline;	/* save current position */
			location.hist_line = hloff;
#endif
			cur = 0;
			draw(ep,UPDATE);
			hist_copy((char*)out,MAXLINE, hline,hloff);
#if SHOPT_MULTIBYTE
			ed_internal((char*)(out),out);
#endif /* SHOPT_MULTIBYTE */
		drawline:
			eol = genlen(out);
			cur = eol;
			draw(ep,UPDATE);
			continue;
		}
		
	}
	
process:

	if (c == (-1))
	{
		lookahead = 0;
		beep();
		*out = '\0';
	}
	draw(ep,FINAL);
	tty_cooked(ERRIO);
	if(ed->e_nlist)
	{
		ed->e_nlist = 0;
		stakset(ed->e_stkptr,ed->e_stkoff);
	}
	if(c == '\n')
	{
		out[eol++] = '\n';
		out[eol] = '\0';
		ed_crlf(ep->ed);
	}
#if SHOPT_MULTIBYTE
	ed_external(out,buff);
#endif /* SHOPT_MULTIBYTE */
	i = strlen(buff);
	if (i)
		return(i);
	return(-1);
}

static void show_info(Emacs_t *ep,const char *str)
{
	register genchar *out = drawbuff;
	register int c;
	genchar string[LBUF];
	int sav_cur = cur;
	/* save current line */
	genncpy(string,out,sizeof(string)/sizeof(*string));
	*out = 0;
	cur = 0;
#if SHOPT_MULTIBYTE
	ed_internal(str,out);
#else
	gencpy(out,str);
#endif	/* SHOPT_MULTIBYTE */
	draw(ep,UPDATE);
	c = ed_getchar(ep->ed,0);
	if(c!=' ')
		ed_ungetchar(ep->ed,c);
	/* restore line */
	cur = sav_cur;
	genncpy(out,string,sizeof(string)/sizeof(*string));
	draw(ep,UPDATE);
}

static void putstring(Emacs_t* ep,register char *sp)
{
	register int c;
	while (c= *sp++)
		 putchar(ep->ed,c);
}


static int escape(register Emacs_t* ep,register genchar *out,int count)
{
	register int i,value;
	int digit,ch;
	digit = 0;
	value = 0;
	while ((i=ed_getchar(ep->ed,0)),isdigit(i))
	{
		value *= 10;
		value += (i - '0');
		digit = 1;
	}
	if (digit)
	{
		ed_ungetchar(ep->ed,i) ;
#ifdef ESH_KAPPEND
		++killing;		/* don't modify killing signal */
#endif
		return(value);
	}
	value = count;
	if(value<0)
		value = 1;
	switch(ch=i)
	{
		case cntl('V'):
			show_info(ep,fmtident(e_version));
			return(-1);
		case ' ':
			ep->mark = cur;
			return(-1);

#ifdef ESH_KAPPEND
		case '+':		/* M-+ = append next kill */
			killing = 2;
			return -1;	/* no argument for next command */
#endif

		case 'p':	/* M-p == ^W^Y (copy stack == kill & yank) */
			ed_ungetchar(ep->ed,cntl('Y'));
			ed_ungetchar(ep->ed,cntl('W'));
#ifdef ESH_KAPPEND
			killing = 0;	/* start fresh */
#endif
			return(-1);

		case 'l':	/* M-l == lower-case */
		case 'd':
		case 'c':
		case 'f':
		{
			i = cur;
			while(value-- && i<eol)
			{
				while ((out[i])&&(!isword(i)))
					i++;
				while ((out[i])&&(isword(i)))
					i++;
			}
			if(ch=='l')
			{
				value = i-cur;
				while (value-- > 0)
				{
					i = out[cur];
#if SHOPT_MULTIBYTE
					if((i&~STRIP)==0 && isupper(i))
#else
					if(isupper(i))
#endif /* SHOPT_MULTIBYTE */
					{
						i += 'a' - 'A';
						out[cur] = i;
					}
					cur++;
				}
				draw(ep,UPDATE);
				return(-1);
			}

			else if(ch=='f')
				goto update;
			else if(ch=='c')
			{
				ed_ungetchar(ep->ed,cntl('C'));
				return(i-cur);
			}
			else
			{
				if (i-cur)
				{
					ed_ungetchar(ep->ed,cntl('D'));
#ifdef ESH_KAPPEND
					++killing;	/* keep killing signal */
#endif
					return(i-cur);
				}
				beep();
				return(-1);
			}
		}
		
		
		case 'b':
		case DELETE :
		case '\b':
		case 'h':
		{
			i = cur;
			while(value-- && i>0)
			{
				i--;
				while ((i>0)&&(!isword(i)))
					i--;
				while ((i>0)&&(isword(i-1)))
					i--;
			}
			if(ch=='b')
				goto update;
			else
			{
				ed_ungetchar(ep->ed,usrerase);
#ifdef ESH_KAPPEND
				++killing;
#endif
				return(cur-i);
			}
		}
		
		case '>':
			ed_ungetchar(ep->ed,cntl('N'));
#ifdef ESH_NFIRST
			if (ep->in_mult)
			{
				location.hist_command = histlines;
				location.hist_line = ep->in_mult - 1;
			}
			else
			{
				location.hist_command = histlines - 1;
				location.hist_line = 0;
			}
#else
			hline = histlines-1;
			hloff = 0;
#endif /* ESH_NFIRST */
			return(0);
		
		case '<':
			ed_ungetchar(ep->ed,cntl('P'));
			hloff = 0;
#ifdef ESH_NFIRST
			hline = hismin + 1;
			return 0;
#else
			return(hline-hismin);
#endif /* ESH_NFIRST */


		case '#':
			ed_ungetchar(ep->ed,'\n');
			ed_ungetchar(ep->ed,(out[0]=='#')?cntl('D'):'#');
			ed_ungetchar(ep->ed,cntl('A'));
			return(-1);
		case '_' :
		case '.' :
		{
			genchar name[MAXLINE];
			char buf[MAXLINE];
			char *ptr;
			ptr = hist_word(buf,MAXLINE,(count?count:-1));
			if(ptr==0)
			{
				beep();
				break;
			}
			if ((eol - cur) >= sizeof(name))
			{
				beep();
				return(-1);
			}
			ep->mark = cur;
			gencpy(name,&out[cur]);
			while(*ptr)
			{
				out[cur++] = *ptr++;
				eol++;
			}
			gencpy(&out[cur],name);
			draw(ep,UPDATE);
			return(-1);
		}
#if KSHELL

		/* file name expansion */
		case cntl('[') :	/* filename completion */
			i = '\\';
			/* FALLTHROUGH */
		case '*':		/* filename expansion */
		case '=':	/* escape = - list all matching file names */
			ep->mark = cur;
			if(ed_expand(ep->ed,(char*)out,&cur,&eol,i,count) < 0)
			{
				if(ep->ed->e_tabcount==1)
				{
					ep->ed->e_tabcount=2;
					ed_ungetchar(ep->ed,cntl('\t'));
					return(-1);
				}
				beep();
			}
			else if(i=='=')
			{
				draw(ep,REFRESH);
				if(count>0)
					ep->ed->e_tabcount=0;
				else
				{
					i=ed_getchar(ep->ed,0);
					ed_ungetchar(ep->ed,i);
					if(isdigit(i))
						ed_ungetchar(ep->ed,ESC);
				}
			}
			else
			{
				if(i=='\\' && cur>ep->mark && (out[cur-1]=='/' || out[cur-1]==' '))
					ep->ed->e_tabcount=0;
				draw(ep,UPDATE);
			}
			return(-1);

		/* search back for character */
		case cntl(']'):	/* feature not in book */
		{
			int c = ed_getchar(ep->ed,1);
			if ((value == 0) || (value > eol))
			{
				beep();
				return(-1);
			}
			i = cur;
			if (i > 0)
				i--;
			while (i >= 0)
			{
				if (out[i] == c && --value==0)
					goto update;
				i--;
			}
			i = eol;
			while (i > cur)
			{
				if (out[i] == c && --value==0)
					break;
				i--;
			};

		}
		update:
			cur = i;
			draw(ep,UPDATE);
			return(-1);

#ifdef _cmd_tput
		case cntl('L'): /* clear screen */
			sh_trap("tput clear", 0);
			draw(ep,REFRESH);
			return(-1);
#endif
		case '[':	/* feature not in book */
			switch(i=ed_getchar(ep->ed,1))
			{
			    case 'A':
				if(cur>0 && eol==cur && (cur<(SEARCHSIZE-2) || ep->prevdirection == -2))
				{
					if(ep->lastdraw==APPEND && ep->prevdirection != -2)
					{
						out[cur] = 0;
						gencpy(&((genchar*)lstring)[1],out);
#if SHOPT_MULTIBYTE
						ed_external(&((genchar*)lstring)[1],lstring+1);
#endif /* SHOPT_MULTIBYTE */
						*lstring = '^';
						ep->prevdirection = -2;
					}
					if(*lstring)
					{
						ed_ungetchar(ep->ed,'\r');
						ed_ungetchar(ep->ed,cntl('R'));
						return(-1);
					}
				}
				*lstring = 0;
				ed_ungetchar(ep->ed,cntl('P'));
				return(-1);
			    case 'B':
				ed_ungetchar(ep->ed,cntl('N'));
				return(-1);
			    case 'C':
				ed_ungetchar(ep->ed,cntl('F'));
				return(-1);
			    case 'D':
				ed_ungetchar(ep->ed,cntl('B'));
				return(-1);
			    case 'H':
				ed_ungetchar(ep->ed,cntl('A'));
				return(-1);
			    case 'Y':
				ed_ungetchar(ep->ed,cntl('E'));
				return(-1);
			    default:
				ed_ungetchar(ep->ed,i);
			}
			i = '_';
			/* FALLTHROUGH */

		default:
			/* look for user defined macro definitions */
			if(ed_macro(ep->ed,i))
#   ifdef ESH_BETTER
				return(count);	/* pass argument to macro */
#   else
				return(-1);
#   endif /* ESH_BETTER */
#else
		update:
			cur = i;
			draw(ep,UPDATE);
			return(-1);

		default:
#endif	/* KSHELL */
		beep();
		return(-1);
	}
	return(-1);
}


/*
 * This routine process all commands starting with ^X
 */

static void xcommands(register Emacs_t *ep,int count)
{
        register int i = ed_getchar(ep->ed,0);
	NOT_USED(count);
        switch(i)
        {
                case cntl('X'):	/* exchange dot and mark */
                        if (ep->mark > eol)
                                ep->mark = eol;
                        i = ep->mark;
                        ep->mark = cur;
                        cur = i;
                        draw(ep,UPDATE);
                        return;

#if KSHELL
#   ifdef ESH_BETTER
                case cntl('E'):	/* invoke emacs on current command */
			if(ed_fulledit(ep->ed)==-1)
				beep();
			else
			{
#if SHOPT_MULTIBYTE
				ed_internal((char*)drawbuff,drawbuff);
#endif /* SHOPT_MULTIBYTE */
				ed_ungetchar(ep->ed,'\n');
			}
			return;

#	define itos(i)	fmtbase((long)(i),0,0)/* want signed conversion */

		case cntl('H'):		/* ^X^H show history info */
			{
				char hbuf[MAXLINE];

				strcpy(hbuf, "Current command ");
				strcat(hbuf, itos(hline));
				if (hloff)
				{
					strcat(hbuf, " (line ");
					strcat(hbuf, itos(hloff+1));
					strcat(hbuf, ")");
				}
				if ((hline != location.hist_command) ||
				    (hloff != location.hist_line))
				{
					strcat(hbuf, "; Previous command ");
					strcat(hbuf, itos(location.hist_command));
					if (location.hist_line)
					{
						strcat(hbuf, " (line ");
						strcat(hbuf, itos(location.hist_line+1));
						strcat(hbuf, ")");
					}
				}
				show_info(ep,hbuf);
				return;
			}
#	if 0	/* debugging, modify as required */
		case cntl('D'):		/* ^X^D show debugging info */
			{
				char debugbuf[MAXLINE];

				strcpy(debugbuf, "count=");
				strcat(debugbuf, itos(count));
				strcat(debugbuf, " eol=");
				strcat(debugbuf, itos(eol));
				strcat(debugbuf, " cur=");
				strcat(debugbuf, itos(cur));
				strcat(debugbuf, " crallowed=");
				strcat(debugbuf, itos(crallowed));
				strcat(debugbuf, " plen=");
				strcat(debugbuf, itos(plen));
				strcat(debugbuf, " w_size=");
				strcat(debugbuf, itos(w_size));

				show_info(ep,debugbuf);
				return;
			}
#	endif /* debugging code */
#   endif /* ESH_BETTER */
#endif /* KSHELL */

                default:
                        beep();
                        return;
	}
}

static void search(Emacs_t* ep,genchar *out,int direction)
{
#ifndef ESH_NFIRST
	Histloc_t location;
#endif
	register int i,sl;
	genchar str_buff[LBUF];
	register genchar *string = drawbuff;
	/* save current line */
	int sav_cur = cur;
	genncpy(str_buff,string,sizeof(str_buff)/sizeof(*str_buff));
	string[0] = '^';
	string[1] = 'R';
	string[2] = '\0';
	sl = 2;
	cur = sl;
	draw(ep,UPDATE);
	while ((i = ed_getchar(ep->ed,1))&&(i != '\r')&&(i != '\n'))
	{
		if (i==usrerase || i==DELETE || i=='\b' || i==ERASECHAR)
		{
			if (sl > 2)
			{
				string[--sl] = '\0';
				cur = sl;
				draw(ep,UPDATE);
			}
			else
				beep();
			continue;
		}
		if (i==usrkill)
		{
			beep();
			goto restore;
		}
		if (i == '\\')
		{
			string[sl++] = '\\';
			string[sl] = '\0';
			cur = sl;
			draw(ep,APPEND);
			i = ed_getchar(ep->ed,1);
			string[--sl] = '\0';
		}
		string[sl++] = i;
		string[sl] = '\0';
		cur = sl;
		draw(ep,APPEND);
	}
	i = genlen(string);
	
	if(ep->prevdirection == -2 && i!=2 || direction!=1)
		ep->prevdirection = -1;
	if (direction < 1)
	{
		ep->prevdirection = -ep->prevdirection;
		direction = 1;
	}
	else
		direction = -1;
	if (i != 2)
	{
#if SHOPT_MULTIBYTE
		ed_external(string,(char*)string);
#endif /* SHOPT_MULTIBYTE */
		strncpy(lstring,((char*)string)+2,SEARCHSIZE);
		ep->prevdirection = direction;
	}
	else
		direction = ep->prevdirection ;
	location = hist_find(sh.hist_ptr,(char*)lstring,hline,1,direction);
	i = location.hist_command;
	if(i>0)
	{
		hline = i;
#ifdef ESH_NFIRST
		hloff = location.hist_line = 0;	/* display first line of multi line command */
#else
		hloff = location.hist_line;
#endif /* ESH_NFIRST */
		hist_copy((char*)out,MAXLINE, hline,hloff);
#if SHOPT_MULTIBYTE
		ed_internal((char*)out,out);
#endif /* SHOPT_MULTIBYTE */
		return;
	}
	if (i < 0)
	{
		beep();
#ifdef ESH_NFIRST
		location.hist_command = hline;
		location.hist_line = hloff;
#else
		hloff = 0;
		hline = histlines;
#endif /* ESH_NFIRST */
	}
restore:
	genncpy(string,str_buff,sizeof(str_buff)/sizeof(*str_buff));
	cur = sav_cur;
	return;
}


/* Adjust screen to agree with inputs: logical line and cursor */
/* If 'first' assume screen is blank */
/* Prompt is always kept on the screen */

static void draw(register Emacs_t *ep,Draw_t option)
{
#define	NORMAL ' '
#define	LOWER  '<'
#define	BOTH   '*'
#define	UPPER  '>'

	register genchar *sptr;		/* Pointer within screen */
	genchar nscreen[2*MAXLINE];	/* New entire screen */
	genchar *ncursor;		/* New cursor */
	register genchar *nptr;		/* Pointer to New screen */
	char  longline;			/* Line overflow */
	genchar *logcursor;
	genchar *nscend;		/* end of logical screen */
	register int i;
	
	nptr = nscreen;
	sptr = drawbuff;
	logcursor = sptr + cur;
	longline = NORMAL;
	ep->lastdraw = option;
	
	if (option == FIRST || option == REFRESH)
	{
		ep->overflow = NORMAL;
		ep->cursor = ep->screen;
		ep->offset = 0;
		ep->cr_ok = crallowed;
		if (option == FIRST)
		{
			ep->scvalid = 1;
			return;
		}
		*ep->cursor = '\0';
		putstring(ep,Prompt);	/* start with prompt */
	}
	
	/*********************
	 Do not update screen if pending characters
	**********************/
	
	if ((lookahead)&&(option != FINAL))
	{
		
		ep->scvalid = 0; /* Screen is out of date, APPEND will not work */
		
		return;
	}
	
	/***************************************
	If in append mode, cursor at end of line, screen up to date,
	the previous character was a 'normal' character,
	and the window has room for another character.
	Then output the character and adjust the screen only.
	*****************************************/
	

	i = *(logcursor-1);	/* last character inserted */
	
	if ((option == APPEND)&&(ep->scvalid)&&(*logcursor == '\0')&&
	    print(i)&&((ep->cursor-ep->screen)<(w_size-1)))
	{
		putchar(ep->ed,i);
		*ep->cursor++ = i;
		*ep->cursor = '\0';
		return;
	}

	/* copy the line */
	ncursor = nptr + ed_virt_to_phys(ep->ed,sptr,nptr,cur,0,0);
	nptr += genlen(nptr);
	sptr += genlen(sptr);
	nscend = nptr - 1;
	if(sptr == logcursor)
		ncursor = nptr;
	
	/*********************
	 Does ncursor appear on the screen?
	 If not, adjust the screen offset so it does.
	**********************/
	
	i = ncursor - nscreen;
	
	if ((ep->offset && i<=ep->offset)||(i >= (ep->offset+w_size)))
	{
		/* Center the cursor on the screen */
		ep->offset = i - (w_size>>1);
		if (--ep->offset < 0)
			ep->offset = 0;
	}
			
	/*********************
	 Is the range of screen[0] thru screen[w_size] up-to-date
	 with nscreen[offset] thru nscreen[offset+w_size] ?
	 If not, update as need be.
	***********************/
	
	nptr = &nscreen[ep->offset];
	sptr = ep->screen;
	
	i = w_size;
	
	while (i-- > 0)
	{
		
		if (*nptr == '\0')
		{
			*(nptr + 1) = '\0';
			*nptr = ' ';
		}
		if (*sptr == '\0')
		{
			*(sptr + 1) = '\0';
			*sptr = ' ';
		}
		if (*nptr == *sptr)
		{
			nptr++;
			sptr++;
			continue;
		}
		setcursor(ep,sptr-ep->screen,*nptr);
		*sptr++ = *nptr++;
#if SHOPT_MULTIBYTE
		while(*nptr==MARKER)
		{
			if(*sptr=='\0')
				*(sptr + 1) = '\0';
			*sptr++ = *nptr++;
			i--;
			ep->cursor++;
		}
#endif /* SHOPT_MULTIBYTE */
	}
	if(ep->ed->e_multiline && option == REFRESH && ep->ed->e_nocrnl==0)
		ed_setcursor(ep->ed, ep->screen, ep->cursor-ep->screen, ep->ed->e_peol, -1);

	
	/******************
	
	Screen overflow checks 
	
	********************/
	
	if (nscend >= &nscreen[ep->offset+w_size])
	{
		if (ep->offset > 0)
			longline = BOTH;
		else
			longline = UPPER;
	}
	else
	{
		if (ep->offset > 0)
			longline = LOWER;
	}
	
	/* Update screen overflow indicator if need be */
	
	if (longline != ep->overflow)
	{
		setcursor(ep,w_size,longline);
		ep->overflow = longline;
	}
	i = (ncursor-nscreen) - ep->offset;
	setcursor(ep,i,0);
	if(option==FINAL && ep->ed->e_multiline)
		setcursor(ep,nscend+1-nscreen,0);
	ep->scvalid = 1;
	return;
}

/*
 * put the cursor to the <newp> position within screen buffer
 * if <c> is non-zero then output this character
 * cursor is set to reflect the change
 */

static void setcursor(register Emacs_t *ep,register int newp,int c)
{
	register int oldp = ep->cursor - ep->screen;
	newp  = ed_setcursor(ep->ed, ep->screen, oldp, newp, 0);
	if(c)
	{
		putchar(ep->ed,c);
		newp++;
	}
	ep->cursor = ep->screen+newp;
	return;
}

#if SHOPT_MULTIBYTE
static int print(register int c)
{
	return((c&~STRIP)==0 && isprint(c));
}

static int _isword(register int c)
{
	return((c&~STRIP) || isalnum(c) || c=='_');
}
#endif /* SHOPT_MULTIBYTE */
