/***********************************************************************
*                                                                      *
*               This software is part of the ast package               *
*          Copyright (c) 1982-2011 AT&T Intellectual Property          *
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
/*
 * David Korn
 * AT&T Labs
 *
 * shell script to shell binary converter
 *
 */

static const char usage[] =
"[-?\n@(#)$Id: shcomp (AT&T Research) 2003-03-02 $\n]"
USAGE_LICENSE
"[+NAME?shcomp - compile a shell script]"
"[+DESCRIPTION?Unless \b-D\b is specified, \bshcomp\b takes a shell script, "
	"\ainfile\a, and creates a binary format file, \aoutfile\a, that "
	"\bksh\b can read and execute with the same effect as the original "
	"script.]"
"[+?Since aliases are processed as the script is read, alias definitions "
	"whose value requires variable expansion will not work correctly.]"
"[+?If \b-D\b is specified, all double quoted strings that are preceded by "
	"\b$\b are output.  These are the messages that need to be "
	"translated to locale specific versions for internationalization.]"
"[+?If \aoutfile\a is omitted, then the results will be written to "
	"standard output.  If \ainfile\a is also omitted, the shell script "
	"will be read from standard input.]"
"[D:dictionary?Generate a list of strings that need to be placed in a message "
	"catalog for internationalization.]"
"[n:noexec?Displays warning messages for obsolete or non-conforming "
	"constructs.] "
"[v:verbose?Displays input from \ainfile\a onto standard error as it "
	"reads it.]"
"\n"
"\n[infile [outfile]]\n"
"\n"
"[+EXIT STATUS?]{"
        "[+0?Successful completion.]"
        "[+>0?An error occurred.]"
"}"   
"[+SEE ALSO?\bksh\b(1)]"
;

#include	<shell.h>
#include	"defs.h"
#include	"shnodes.h"
#include	"sys/stat.h"

#define CNTL(x)	((x)&037)
#define VERSION	3
static const char header[6] = { CNTL('k'),CNTL('s'),CNTL('h'),0,VERSION,0 };

int main(int argc, char *argv[])
{
	Sfio_t *in, *out;
	Shell_t	*shp;
	Namval_t *np;
	Shnode_t *t;
	char *cp;
	int n, nflag=0, vflag=0, dflag=0;
	error_info.id = argv[0];
	while(n = optget(argv, usage )) switch(n)
	{
	    case 'D':
		dflag=1;
		break;
	    case 'v':
		vflag=1;
		break;
	    case 'n':
		nflag=1;
		break;
	    case ':':
		errormsg(SH_DICT,2,"%s",opt_info.arg);
		break;
	    case '?':
		errormsg(SH_DICT,ERROR_usage(2),"%s",opt_info.arg);
		break;
	}
	shp = sh_init(argc,argv,(Shinit_f)0);
	shp->shcomp = 1;
	argv += opt_info.index;
	argc -= opt_info.index;
	if(error_info.errors || argc>2)
		errormsg(SH_DICT,ERROR_usage(2),"%s",optusage((char*)0));
	if(cp= *argv)
	{
		argv++;
		in = sh_pathopen(cp);
	}
	else
		in = sfstdin;
	if(cp= *argv)
	{
		struct stat statb;
		if(!(out = sfopen((Sfio_t*)0,cp,"w")))
			errormsg(SH_DICT,ERROR_system(1),"%s: cannot create",cp);
		if(fstat(sffileno(out),&statb) >=0)
			chmod(cp,(statb.st_mode&~S_IFMT)|S_IXUSR|S_IXGRP|S_IXOTH);
	}
	else
		out = sfstdout;
	if(dflag)
	{
		sh_onoption(SH_DICTIONARY);
		sh_onoption(SH_NOEXEC);
	}
	if(nflag)
		sh_onoption(SH_NOEXEC);
	if(vflag)
		sh_onoption(SH_VERBOSE);
	if(!dflag)
		sfwrite(out,header,sizeof(header));
	shp->inlineno = 1;
#if SHOPT_BRACEPAT
        sh_onoption(SH_BRACEEXPAND);
#endif
	while(1)
	{
		stakset((char*)0,0);
		if(t = (Shnode_t*)sh_parse(shp,in,0))
		{
			if((t->tre.tretyp&(COMMSK|COMSCAN))==0 && t->com.comnamp && strcmp(nv_name((Namval_t*)t->com.comnamp),"alias")==0)
				sh_exec(t,0);
			if(!dflag && sh_tdump(out,t) < 0)
				errormsg(SH_DICT,ERROR_exit(1),"dump failed");
		}
		else if(sfeof(in))
			break;
		if(sferror(in))
			errormsg(SH_DICT,ERROR_system(1),"I/O error");
		if(t && ((t->tre.tretyp&COMMSK)==TCOM) && (np=t->com.comnamp) && (cp=nv_name(np)))
		{
			if(strcmp(cp,"exit")==0)
				break;
			/* check for exec of a command */
			if(strcmp(cp,"exec")==0)
			{
				if(t->com.comtyp&COMSCAN)
				{
					if(t->com.comarg->argnxt.ap)
						break;
				}
				else
				{
					struct dolnod *ap = (struct dolnod*)t->com.comarg;
					if(ap->dolnum>1)
						break;
				}
			}
		}
	}
	/* copy any remaining input */
	sfmove(in,out,SF_UNBOUND,-1);
	if(in!=sfstdin)
		sfclose(in);
	if(out!=sfstdout)
		sfclose(out);
	return(0);
}
