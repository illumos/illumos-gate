/***********************************************************************
*                                                                      *
*               This software is part of the ast package               *
*          Copyright (c) 1992-2008 AT&T Intellectual Property          *
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
*                                                                      *
***********************************************************************/
#pragma prototyped
/*
 * pathchk
 *
 * Written by David Korn
 */

static const char usage[] =
"[-?\n@(#)$Id: pathchk (AT&T Research) 2006-09-19 $\n]"
USAGE_LICENSE
"[+NAME?pathchk - check pathnames for portability]"
"[+DESCRIPTION?\bpathchk\b checks each \apathname\a to see if it "
	"is valid and/or portable.  A \apathname\a is valid if it "
	"can be used to access or create a file without causing syntax "
	"errors.  A file is portable, if no truncation will result on "
	"any conforming POSIX.1 implementation.]"
"[+?By default \bpathchk\b checks each component of each \apathname\a "
	"based on the underlying file system.  A diagnostic is written "
	"to standard error for each pathname that:]{"
	"[+-?Is longer than \b$(getconf PATH_MAX)\b bytes.]"
	"[+-?Contains any component longer than \b$(getconf NAME_MAX)\b bytes.]"
	"[+-?Contains any directory component in a directory that is "
		"not searchable.]"
	"[+-?Contains any character in any component that is not valid in "
		"its containing directory.]"
	"[+-?Is empty.]"
	"}"
"[p:portability?Instead of performing length checks on the underlying "
	"file system, write a diagnostic for each pathname operand that:]{"
	"[+-?Is longer than \b$(getconf _POSIX_PATH_MAX)\b bytes.]"
	"[+-?Contains any component longer than "
		"\b$(getconf _POSIX_NAME_MAX)\b bytes.]"
        "[+-?Contains any character in any component that is not in the "
		"portable filename character set.]"
#if 0
	"[+-?Contains any component with \b-\b as the first character.]"
#endif
	"[+-?Is empty.]"
	"}"
"\n"
"\npathname ...\n"
"\n"
"[+EXIT STATUS?]{"
        "[+0?All \apathname\a operands passed all of the checks.]"
        "[+>0?An error occurred.]"
"}"
"[+SEE ALSO?\bgetconf\b(1), \bcreat\b(2), \bpathchk\b(2)]"
;


#include	<cmd.h>
#include	<ls.h>

#define isport(c)	(((c)>='a' && (c)<='z') || ((c)>='A' && (c)<='Z') || ((c)>='0' && (c)<='9') || (strchr("._-",(c))!=0) )

/*
 * call pathconf and handle unlimited sizes
 */ 
static long mypathconf(const char *path, int op)
{
	register long			r;

	static const char* const	ops[] = { "NAME_MAX", "PATH_MAX" };

	errno=0;
	if((r=strtol(astconf(ops[op], path, NiL), NiL, 0))<0 && errno==0)
		return(LONG_MAX);
	return(r);
}

/*
 * returns 1 if <path> passes test
 */
static int pathchk(char* path, int mode)
{
	register char *cp=path, *cpold;
	register int c;
	register long r,name_max,path_max;
	char buf[2];

	if(!*path)
	{
		error(2,"path is empty");
		return(0);
	}
	if(mode)
	{
		name_max = _POSIX_NAME_MAX;
		path_max = _POSIX_PATH_MAX;
	}
	else
	{
		char tmp[2];
		name_max = path_max = 0;
		tmp[0] = (*cp=='/'? '/': '.');
		tmp[1] = 0;
		if((r=mypathconf(tmp, 0)) > _POSIX_NAME_MAX)
			name_max = r;
		if((r=mypathconf(tmp, 1)) > _POSIX_PATH_MAX)
			path_max = r;
		if(*cp!='/')
		{
			if(name_max==0||path_max==0)
			{
				if(!(cpold = getcwd((char*)0, 0)) && errno == EINVAL && (cpold = newof(0, char, PATH_MAX, 0)) && !getcwd(cpold, PATH_MAX))
				{
					free(cpold);
					cpold = 0;
				}
				if(cpold)
				{
					cp = cpold + strlen(cpold);
					while(name_max==0 || path_max==0)
					{
						if(cp>cpold)
							while(--cp>cpold && *cp=='/');
						*++cp = 0;
						if(name_max==0 && (r=mypathconf(cpold, 0)) > _POSIX_NAME_MAX)
							name_max = r;
						if(path_max==0 && (r=mypathconf(cpold, 1)) > _POSIX_PATH_MAX)
							path_max=r;
						if(--cp==cpold)
						{
							free(cpold);
							break;
						}
						while(*cp!='/')
							cp--;
					}
					cp=path;
				}
			}
			while(*cp=='/')
				cp++;
		}
		if(name_max==0)
			name_max=_POSIX_NAME_MAX;
		if(path_max==0)
			path_max=_POSIX_PATH_MAX;
		while(*(cpold=cp))
		{
			while((c= *cp++) && c!='/');
			if((cp-cpold) > name_max)
				goto err;
			errno=0;
			cp[-1] = 0;
			r = mypathconf(path, 0);
			if((cp[-1]=c)==0)
				cp--;
			else while(*cp=='/')
				cp++;
			if(r>=0)
				name_max=(r<_POSIX_NAME_MAX?_POSIX_NAME_MAX:r);
			else if(errno==EINVAL)
				continue;
#ifdef ENAMETOOLONG
			else if(errno==ENAMETOOLONG)
			{
				error(2,"%s: pathname too long",path);
				return(0);
			}
#endif /*ENAMETOOLONG*/
			else
				break;
		}
	}
	while(*(cpold=cp))
	{
		if(mode && *cp == '-')
		{
			error(2,"%s: path component begins with '-'",path,fmtquote(buf, NiL, "'", 1, 0));
			return(0);
		}
		while((c= *cp++) && c!='/')
			if(mode && !isport(c))
			{
				buf[0] = c;
				buf[1] = 0;
				error(2,"%s: '%s' not in portable character set",path,fmtquote(buf, NiL, "'", 1, 0));
				return(0);
			}
		if((cp-cpold) > name_max)
			goto err;
		if(c==0)
			break;
		while(*cp=='/')
			cp++;
	}
	if((cp-path) >= path_max)
	{
		error(2,"%s: pathname too long",path);
		return(0);
	}
	return(1);
err:
	error(2,"%s: component name %.*s too long",path,cp-cpold-1,cpold);
	return(0);
}

int
b_pathchk(int argc, char** argv, void* context)
{
	register int n, mode=0;
	register char *cp;

	cmdinit(argc, argv, context, ERROR_CATALOG, 0);
	while (n = optget(argv, usage)) switch (n)
	{
  	    case 'p':
		mode = 1;
		break;
	    case ':':
		error(2, "%s", opt_info.arg);
		break;
	    case '?':
		error(ERROR_usage(2), "%s", opt_info.arg);
		break;
	}
	argv += opt_info.index;
	if(*argv==0 || error_info.errors)
		error(ERROR_usage(2),"%s", optusage((char*)0));
	while(cp = *argv++)
	{
		if(!pathchk(cp,mode))
			error_info.errors=1;
	}
	return(error_info.errors);
}
