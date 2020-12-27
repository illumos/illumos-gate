/***********************************************************************
*                                                                      *
*               This software is part of the ast package               *
*          Copyright (c) 1992-2012 AT&T Intellectual Property          *
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
*                 Glenn Fowler <gsf@research.att.com>                  *
*                  David Korn <dgk@research.att.com>                   *
*                                                                      *
***********************************************************************/
#pragma prototyped
/*
 * David Korn
 * AT&T Bell Laboratories
 *
 * fold
 */

static const char usage[] =
"[-?\n@(#)$Id: fold (AT&T Research) 2004-11-18 $\n]"
USAGE_LICENSE
"[+NAME?fold - fold lines]"
"[+DESCRIPTION?\bfold\b is a filter that folds lines from its input, "
	"breaking the lines to have a maximum of \awidth\a column "
	"positions (or bytes if the \b-b\b option is specified).  Lines "
	"are broken by the insertion of a newline character such that "
	"each output line is the maximum width possible that does not "
	"exceed the specified number of column positions, (or bytes).  A line "
	"will not be broken in the middle of a character.] "
"[+?Unless the \b-b\b option is specified, the following will be treated "
	"specially:]{"
	"[+carriage-return?The current count of line width will be set "
		"to zero.  \bfold\b will not insert a newline immediately "
		"before or after a carriage-return.]"
	"[+backspace?If positive, the current count of line width will be "
		"decremented by  one.  \bfold\b will not insert a newline "
		"immediately before or after a backspace.]"
	"[+tab?Each tab character encountered will advance the column "
		"position to the next tab stop.  Tab stops are at each "
		"column position \an\a, where \an\a modulo 8 equals 1.]"
	"}"
"[+?If no \afile\a is given, or if the \afile\a is \b-\b, \bfold\b "
        "reads from standard input.   The start of the file is defined "
        "as the current offset.]"

"[b:bytes?Count bytes rather than columns so that each carriage-return, "
	"backspace, and tab counts as 1.]"
"[c:continue?Emit \atext\a at line splits.]:[text:='\\n']"
"[d:delimiter?Break at \adelim\a boundaries.]:[delim]"
"[s:spaces?Break at word boundaries.  If the line contains any blanks, "
	"(spaces or tabs), within the first \awidth\a column positions or "
	"bytes, the line is broken after the last blank meeting the "
	"\awidth\a constraint.]"
"[w:width]#[width:=80?Use a maximum line length of \awidth\a columns "
	"instead of the default.]"
"\n"
"\n[file ...]\n"
"\n"
"[+EXIT STATUS?]{"
	"[+0?All files processed successfully.]"
	"[+>0?An error occurred.]"
"}"
"[+SEE ALSO?\bpaste\b(1)]"
;


#include <cmd.h>

#define WIDTH	80
#define TABSIZE	8

#define T_EOF	1
#define T_NL	2
#define T_BS	3
#define T_TAB	4
#define T_SP	5
#define T_RET	6

static void fold(Sfio_t *in, Sfio_t *out, register int width, const char *cont, size_t contsize, char *cols)
{
	register char *cp, *first;
	register int n, col=0, x=0;
	register char *last_space=0;
	cols[0] = 0;
	for (;;)
	{
		if (!(cp  = sfgetr(in,'\n',0)))
		{
			if (!(cp = sfgetr(in,'\n',-1)) || (n = sfvalue(in)) <= 0)
				break;
			x = cp[--n];
			cp[n] = '\n';
		}
		/* special case -b since no column adjustment is needed */ 
		if(cols['\b']==0 && (n=sfvalue(in))<=width)
		{
			sfwrite(out,cp,n);
			continue;
		}
		first = cp;
		col = 0;
		last_space = 0;
		for(;;)
		{
			while((n=cols[*(unsigned char*)cp++])==0);
			while((cp-first) > (width-col))
			{
				if(last_space)
					col = last_space - first;
				else
					col = width-col;
				sfwrite(out,first,col);
				first += col;
				col = 0;
				last_space = 0;
				if(cp>first+1 || (n!=T_NL && n!=T_BS))
					sfwrite(out, cont, contsize);
			}
			switch(n)
			{
			    case T_NL:
				if(x)
					*(cp-1) = x;
				break;
			    case T_RET:
				col = 0;
				continue;
			    case T_BS:
				if((cp+(--col)-first)>0) 
					col--;
				continue;
			    case T_TAB:
				n = (TABSIZE-1) - (cp+col-1-first)&(TABSIZE-1);
				col +=n;
				if((cp-first) > (width-col))
				{
					sfwrite(out,first,(--cp)-first);
					sfwrite(out, cont, contsize);
					first = cp;
					col =  TABSIZE-1;
					last_space = 0;
					continue;
				}
				if(cols[' '])
					last_space = cp;
				continue;
			    case T_SP:
				last_space = cp;
				continue;
			    default:
				continue;
			}
			break;
		}
		sfwrite(out,first,cp-first);
	}
}

int
b_fold(int argc, char** argv, Shbltin_t* context)
{
	register int n, width=WIDTH;
	register Sfio_t *fp;
	register char *cp;
	char *cont="\n";
	size_t contsize = 1;
	char cols[1<<CHAR_BIT];

	cmdinit(argc, argv, context, ERROR_CATALOG, 0);
	memset(cols, 0, sizeof(cols));
	cols['\t'] = T_TAB;
	cols['\b'] = T_BS;
	cols['\n'] = T_NL;
	cols['\r'] = T_RET;
	for (;;)
	{
		switch (optget(argv, usage))
		{
		case 'b':
			cols['\r'] = cols['\b'] = 0;
			cols['\t'] = cols[' '];
			continue;
		case 'c':
			contsize = stresc(cont = strdup(opt_info.arg));
			continue;
		case 'd':
			if (n = *opt_info.arg)
				cols[n] = T_SP;
			continue;
		case 's':
			cols[' '] = T_SP;
			if(cols['\t']==0)
				cols['\t'] = T_SP;
			continue;
		case 'w':
			if ((width = opt_info.num) <= 0)
				error(2, "%d: width must be positive", opt_info.num);
			continue;
		case ':':
			error(2, "%s", opt_info.arg);
			continue;
		case '?':
			error(ERROR_usage(2), "%s", opt_info.arg);
			continue;
		}
		break;
	}
	argv += opt_info.index;
	argc -= opt_info.index;
	if(error_info.errors)
		error(ERROR_usage(2),"%s", optusage(NiL));
	if(cp = *argv)
		argv++;
	do
	{
		if(!cp || streq(cp,"-"))
			fp = sfstdin;
		else if(!(fp = sfopen(NiL,cp,"r")))
		{
			error(ERROR_system(0),"%s: cannot open",cp);
			error_info.errors = 1;
			continue;
		}
		fold(fp,sfstdout,width,cont,contsize,cols);
		if(fp!=sfstdin)
			sfclose(fp);
	}
	while(cp= *argv++);
	return(error_info.errors);
}
