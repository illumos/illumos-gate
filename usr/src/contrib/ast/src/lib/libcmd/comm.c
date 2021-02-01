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
 * comm
 */

static const char usage[] =
"[-?\n@(#)$Id: comm (AT&T Research) 1999-04-28 $\n]"
USAGE_LICENSE
"[+NAME?comm - select or reject lines common to two files]"
"[+DESCRIPTION?\bcomm\b reads two files \afile1\a and \afile2\a "
	"which should be ordered in the collating sequence of the "
	"current locale, and produces three text columns as output:]{"
	"[+1?Lines only in \afile1\a.]"
	"[+2?Lines only in \afile2\a.]"
	"[+3?Lines in both files.]"
	"}"
"[+?If lines in either file are not ordered according to the collating "
	"sequence of the current locale, the results are not specified.]"
"[+?If either \afile1\a or \afile2\a is \b-\b, \bcomm\b "
        "uses standard input starting at the current location.]"

"[1?Suppress the output column of lines unique to \afile1\a.]"
"[2?Suppress the output column of lines unique to \afile2\a.]"
"[3?Suppress the output column of lines duplicate in \afile1\a and \afile2\a.]"
"\n"
"\nfile1 file2\n"
"\n"
"[+EXIT STATUS?]{"
	"[+0?Both files processed successfully.]"
	"[+>0?An error occurred.]"
"}"
"[+SEE ALSO?\bcmp\b(1), \bdiff\b(1)]"
;


#include <cmd.h>

#define C_FILE1		1
#define C_FILE2		2
#define C_COMMON	4
#define C_ALL		(C_FILE1|C_FILE2|C_COMMON)

static int comm(Sfio_t *in1, Sfio_t *in2, register Sfio_t *out,register int mode)
{
	register char *cp1, *cp2;
	register int n1, n2, n, comp;
	if(cp1 = sfgetr(in1,'\n',0))
		n1 = sfvalue(in1);
	if(cp2 = sfgetr(in2,'\n',0))
		n2 = sfvalue(in2);
	while(cp1 && cp2)
	{
		n=(n1<n2?n1:n2);
		if((comp=memcmp(cp1,cp2,n-1))==0 && (comp=n1-n2)==0)
		{
			if(mode&C_COMMON)
			{
				if(mode!=C_COMMON)
				{
					sfputc(out,'\t');
					if(mode==C_ALL)
						sfputc(out,'\t');
				}
				if(sfwrite(out,cp1,n) < 0)
					return(-1);
			}
			if(cp1 = sfgetr(in1,'\n',0))
				n1 = sfvalue(in1);
			if(cp2 = sfgetr(in2,'\n',0))
				n2 = sfvalue(in2);
		}
		else if(comp > 0)
		{
			if(mode&C_FILE2)
			{
				if(mode&C_FILE1)
					sfputc(out,'\t');
				if(sfwrite(out,cp2,n2) < 0)
					return(-1);
			}
			if(cp2 = sfgetr(in2,'\n',0))
				n2 = sfvalue(in2);
		}
		else
		{
			if((mode&C_FILE1) && sfwrite(out,cp1,n1) < 0)
				return(-1);
			if(cp1 = sfgetr(in1,'\n',0))
				n1 = sfvalue(in1);
		}
	}
	n = 0;
	if(cp2)
	{
		cp1 = cp2;
		in1 = in2;
		n1 = n2;
		if(mode&C_FILE1)
			n = 1;
		mode &= C_FILE2;
	}
	else
		mode &= C_FILE1;
	if(!mode || !cp1)
	{
		if(cp1 && in1==sfstdin)
			sfseek(in1,(Sfoff_t)0,SEEK_END);
		return(0);
	}
	/* process the remaining stream */
	while(1)
	{
		if(n)
			sfputc(out,'\t');
		if(sfwrite(out,cp1,n1) < 0)
			return(-1);
		if(!(cp1 = sfgetr(in1,'\n',0)))
			return(0);
		n1 = sfvalue(in1);
	}
	/* NOT REACHED */
}

int
b_comm(int argc, char *argv[], Shbltin_t* context)
{
	register int mode = C_FILE1|C_FILE2|C_COMMON;
	register char *cp;
	Sfio_t *f1, *f2;

	cmdinit(argc, argv, context, ERROR_CATALOG, 0);
	for (;;)
	{
		switch (optget(argv, usage))
		{
 		case '1':
			mode &= ~C_FILE1;
			continue;
		case '2':
			mode &= ~C_FILE2;
			continue;
		case '3':
			mode &= ~C_COMMON;
			continue;
		case ':':
			error(2, "%s",opt_info.arg);
			break;
		case '?':
			error(ERROR_usage(2), "%s",opt_info.arg);
			break;
		}
		break;
	}
	argv += opt_info.index;
	argc -= opt_info.index;
	if(error_info.errors || argc!=2)
		error(ERROR_usage(2),"%s",optusage(NiL));
	cp = *argv++;
	if(streq(cp,"-"))
		f1 = sfstdin;
	else if(!(f1 = sfopen(NiL, cp,"r")))
		error(ERROR_system(1),"%s: cannot open",cp);
	cp = *argv;
	if(streq(cp,"-"))
		f2 = sfstdin;
	else if(!(f2 = sfopen(NiL, cp,"r")))
		error(ERROR_system(1),"%s: cannot open",cp);
	if(mode)
	{
		if(comm(f1,f2,sfstdout,mode) < 0)
			error(ERROR_system(1)," write error");
	}
	else if(f1==sfstdin || f2==sfstdin)
		sfseek(sfstdin,(Sfoff_t)0,SEEK_END);
	if(f1!=sfstdin)
		sfclose(f1);
	if(f2!=sfstdin)
		sfclose(f2);
	return error_info.errors;
}
