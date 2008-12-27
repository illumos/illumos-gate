/***********************************************************************
*                                                                      *
*               This software is part of the ast package               *
*          Copyright (c) 1982-2007 AT&T Intellectual Property          *
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

#include	<shell.h>
#include	<stdio.h>
#include	<stdbool.h>
#include	<option.h>
#include	<stk.h>
#include	<tm.h>
#include	"name.h"
#undef nv_isnull
#ifndef SH_DICT
#   define SH_DICT     "libshell"
#endif
#include	<poll.h>

#define sh_contexttoshb(context)	((Shbltin_t*)(context))
#define sh_contexttoshell(context)	((context)?(sh_contexttoshb(context)->shp):(NULL))

/*
 * time formatting related 
*/ 
struct dctime
{
	Namfun_t	fun;
	Namval_t 	*format;
	char		buff[256]; /* Must be large enougth for |tmfmt()| */
};

static char *get_time(Namval_t* np, Namfun_t* nfp)
{
	struct dctime *dp = (struct dctime*)nfp;
	time_t t = nv_getn(np,nfp);
	char *format = nv_getval(dp->format);
	tmfmt(dp->buff,sizeof(dp->buff),format,(time_t*)0);
	return(dp->buff);
}

static void put_time(Namval_t* np, const char* val, int flag, Namfun_t* nfp)
{
	struct dctime *dp = (struct dctime*)nfp;
	char *last;
	if(val)
	{
		int32_t t;
		if(flag&NV_INTEGER)
		{
			if(flag&NV_LONG)
				t = *(Sfdouble_t*)val;
			else
				t = *(double*)val;
		}
		else
		{
			t = tmdate(val, &last, (time_t*)0);
			if(*last)
				errormsg(SH_DICT, ERROR_exit(1),"%s: invalid date/time string", val);
		}
		nv_putv(np, (char*)&t,NV_INTEGER, nfp);
	}
	else
	{
		nv_unset(dp->format);
		free((void*)dp->format);
		nv_putv(np, val, flag, nfp);
	}
}

static Namval_t *create_time(Namval_t *np, const char *name, int flags, Namfun_t *nfp)
{
	struct dctime *dp = (struct dctime*)nfp;
	if(strcmp(name, "format"))
		return((Namval_t*)0);
	return(dp->format);
}

static const Namdisc_t timedisc =
{
        sizeof(struct dctime),
        put_time,
        get_time,
        0,
        0,
        create_time,
};


static Namval_t *make_time(Namval_t* np)
{
	int offset = stktell(stkstd);
	char *name = nv_name(np);
	struct dctime *dp = newof(NULL,struct dctime,1,0); 
	if(!dp)
		return((Namval_t*)0);
	sfprintf(stkstd,"%s.format\0",name);
	sfputc(stkstd,0);
	dp->format = nv_search(stkptr(stkstd,offset),sh.var_tree,NV_ADD);
	dp->fun.disc = &timedisc;
	nv_stack(np,&dp->fun);
	return(np);
}

/*
 * mode formatting related 
*/ 
static char *get_mode(Namval_t* np, Namfun_t* nfp)
{
	mode_t mode = nv_getn(np,nfp);
	return(fmtperm(mode));
}

static void put_mode(Namval_t* np, const char* val, int flag, Namfun_t* nfp)
{
	if(val)
	{
		int32_t mode;
		char *last;
		if(flag&NV_INTEGER)
		{
			if(flag&NV_LONG)
				mode = *(Sfdouble_t*)val;
			else
				mode = *(double*)val;
		}
		else
		{
			mode = strperm(val, &last,0);
			if(*last)
				errormsg(SH_DICT, ERROR_exit(1),"%s: invalid mode string", val);
		}
		nv_putv(np,(char*)&mode,NV_INTEGER,nfp);
	}
	else
		nv_putv(np,val,flag,nfp);
}

static const Namdisc_t modedisc =
{
	0,
        put_mode,
        get_mode,
};

static Namval_t *make_mode(Namval_t* np)
{
	char *name = nv_name(np);
	Namfun_t *nfp = newof(NULL,Namfun_t,1,0); 
	if(!nfp)
		return((Namval_t*)0);
	nfp->disc = &modedisc;
	nv_stack(np,nfp);
	return(np);
}

/*
 *  field related typese and functions
 */
typedef struct _field_
{
	char		*name;		/* field name */
	int		flags;		/* flags */
	short		offset;		/* offset of field into data */
	short		size;		/* size of field */
	Namval_t	*(*make)(Namval_t*);	/* discipline constructor */
} Shfield_t;

/*
 * lookup field in field table
 */
static Shfield_t *sh_findfield(Shfield_t *ftable, int nelem, const char *name)
{
	Shfield_t *fp = ftable;
	register int i,n;
	register const char *cp;
	for(cp=name; *cp; cp++)
	{
		if(*cp=='.')
			break;
	}
	n = cp-name;
	for(i=0; i < nelem; i++,fp++)
	{
		if(memcmp(fp->name,name,n)==0 && fp->name[n]==0)
			return(fp);
	}
	return(0);
}

/*
 * class types and functions
 */

typedef struct _class_
{
	int		nelem;		/* number of elements */
	int		dsize;		/* size for data structure */
	Shfield_t 	*fields;	/* field description table */
} Shclass_t;

struct dcclass
{
	Namfun_t	fun;
	Shclass_t	sclass;
};

static Namval_t *sh_newnode(register Shfield_t *fp, Namval_t *np)
{
	char *val = np->nvalue + fp->offset;
	char *name = nv_name(np);
	register Namval_t *nq;
	int offset = stktell(stkstd);
	sfprintf(stkstd,"%s.%s\0",name,fp->name);
	sfputc(stkstd,0);
	nq = nv_search(stkptr(stkstd,offset),sh.var_tree,NV_ADD);
	if(fp->size<0)
		val = *(char**)val;
	nv_putval(nq,val,fp->flags|NV_NOFREE);
	if(fp->make)
		(*fp->make)(nq);
	return(nq);
}

static Namval_t *fieldcreate(Namval_t *np, const char *name, int flags, Namfun_t *nfp)
{
	struct dcclass *dcp = (struct dcclass*)nfp;
	Shclass_t *sp = &dcp->sclass;
	Shfield_t *fp = sh_findfield(sp->fields,sp->nelem,name);
	Namval_t *nq,**nodes = (Namval_t**)(dcp+1);
	int n = fp-sp->fields;
	int len =  strlen(fp->name);
	void *data = (void*)np->nvalue;
	if(!(nq=nodes[n]))
	{
		nodes[n] = nq = sh_newnode(fp,np);
		nfp->last = "";
	}
	if(name[len]==0)
		return(nq);
	return(nq);
}

static void genvalue(Sfio_t *out, Shclass_t *sp, int indent, Namval_t *npar)
{
	Shfield_t *fp = sp->fields;
	Namval_t *np, **nodes= (Namval_t**)(sp+1);
	register int i,isarray;
	if(out)
	{
		sfwrite(out,"(\n",2);
		indent++;
	}
	for(i=0; i < sp->nelem; i++,fp++)
	{
#if 0
		/* handle recursive case */
#endif
		if(!(np=nodes[i]) && out)
			np = sh_newnode(fp,npar);
		if(np)
		{
			isarray=0;
			if(nv_isattr(np,NV_ARRAY))
			{
				isarray=1;
				if(array_elem(nv_arrayptr(np))==0)
					isarray=2;
				else
					nv_putsub(np,(char*)0,ARRAY_SCAN);
			}
			sfnputc(out,'\t',indent);
			sfputr(out,fp->name,(isarray==2?'\n':'='));
			if(isarray)
			{
				if(isarray==2)
					continue;
				sfwrite(out,"(\n",2);
				sfnputc(out,'\t',++indent);
			}
			while(1)
			{
				char *fmtq;
				if(isarray)
				{
					sfprintf(out,"[%s]",sh_fmtq(nv_getsub(np)));
					sfputc(out,'=');
				}
				if(!(fmtq=nv_getval(np)) || !(fmtq=sh_fmtq(fmtq)))
					fmtq = "";
				sfputr(out,fmtq,'\n');
				if(!nv_nextsub(np))
					break;
				sfnputc(out,'\t',indent);
			}
			if(isarray)
			{
				sfnputc(out,'\t',--indent);
				sfwrite(out,")\n",2);
			}
		}
	}
	if(out)
	{
		if(indent>1)
			sfnputc(out,'\t',indent-1);
		sfputc(out,')');
	}
}

static char *walk_class(register Namval_t *np, int dlete, struct dcclass *dcp)
{
	static Sfio_t *out;
	Sfio_t *outfile;
	int savtop = stktell(stkstd);
	char *savptr =  stkfreeze(stkstd,0);
	if(dlete)
		outfile = 0;
	else if(!(outfile=out))
                outfile = out =  sfnew((Sfio_t*)0,(char*)0,-1,-1,SF_WRITE|SF_STRING);
	else
		sfseek(outfile,0L,SEEK_SET);
	genvalue(outfile,&dcp->sclass,0,np);
	stkset(stkstd,savptr,savtop);
	if(!outfile)
		return((char*)0);
	sfputc(out,0);
	return((char*)out->_data);
}

static char *get_classval(Namval_t* np, Namfun_t* nfp)
{
	return(walk_class(np,0,(struct dcclass *)nfp));
}

static void put_classval(Namval_t* np, const char* val, int flag, Namfun_t* nfp)
{
	walk_class(np,1,(struct dcclass *)nfp);
	if(nfp = nv_stack(np,(Namfun_t*)0))
	{
		free((void*)nfp);
		if(np->nvalue && !nv_isattr(np,NV_NOFREE))
			free((void*)np->nvalue);
	}
	if(val)
		nv_putval(np,val,flag);
}

static const Namdisc_t classdisc =
{
        sizeof(struct dcclass),
        put_classval,
        get_classval,
        0,
        0,
	fieldcreate
};

static int mkclass(Namval_t *np, Shclass_t *sp)
{
	struct dcclass *tcp = newof(NULL,struct dcclass,1,sp->nelem*sizeof(Namval_t*)); 
	if(!tcp)
		return(0);
	memset((void*)(tcp+1),0,sp->nelem*sizeof(Namval_t*));
	tcp->fun.disc = &classdisc;
	tcp->sclass = *sp;
	np->nvalue = (char*)calloc(sp->dsize,1);
	nv_stack(np,&tcp->fun);
	return(1);
}

/*
 * ====================from here down is file class specific
 */
static struct stat *Sp;

struct filedata
{
	struct stat	statb;
	int		fd;
	char		*name;
};

static Shfield_t filefield[] =
{
	{ "atime", NV_INTEGER|NV_RDONLY, offsetof(struct stat,st_atime), sizeof(Sp->st_atime), make_time},
	{ "ctime", NV_INTEGER|NV_RDONLY, offsetof(struct stat,st_ctime), sizeof(Sp->st_ctime), make_time},
	{ "dev",   NV_INTEGER|NV_RDONLY, offsetof(struct stat,st_dev),sizeof(Sp->st_dev)},
	{ "fd",    NV_INTEGER|NV_RDONLY, offsetof(struct filedata,fd), 		sizeof(int)},
	{ "gid",   NV_INTEGER|NV_RDONLY, offsetof(struct stat,st_gid), sizeof(Sp->st_gid)},
	{ "ino",   NV_LONG|NV_INTEGER|NV_RDONLY, offsetof(struct stat,st_ino), sizeof(Sp->st_ino)},
	{ "mode",  NV_INTEGER|NV_RDONLY, offsetof(struct stat,st_mode), sizeof(Sp->st_mode), make_mode},
	{ "mtime", NV_INTEGER|NV_RDONLY, offsetof(struct stat,st_mtime), sizeof(Sp->st_mtime), make_time},
	{ "name",   NV_RDONLY, offsetof(struct filedata,name), 	-1 },
	{ "nlink", NV_INTEGER|NV_RDONLY, offsetof(struct stat,st_nlink), sizeof(Sp->st_nlink)},
	{ "size",  NV_LONG|NV_INTEGER|NV_RDONLY, offsetof(struct stat,st_size), sizeof(Sp->st_size)},
	{ "uid",   NV_INTEGER|NV_RDONLY, offsetof(struct stat,st_uid), sizeof(Sp->st_uid)}
};

static Shclass_t Fileclass =
{
	sizeof(filefield)/sizeof(*filefield),
	sizeof(struct filedata),
	filefield
};


#define letterbit(bit)	(1<<((bit)-'a'))

static const char sh_optopen[] =
"[-?\n@(#)$Id: open (AT&T Labs Research) 2007-05-07 $\n]"
"[-author?David Korn <dgk@research.att.com>]"
"[-author?Roland Mainz <roland.mainz@nrubsig.org>]"
"[-license?http://www.opensource.org/licenses/cpl1.0.txt]"
"[+NAME? open - create a shell variable correspnding to a file]"
"[+DESCRIPTION?\bopen\b creates the compound variable \avar\a correspinding "
	"to the file given by the pathname \afile\a.  The elements of \avar\a "
	"are the names of elements in the \astat\a structure with the \bst_\b "
	"prefix removed.]"
"[+?\afile\a is opened (based on \b-r\b and/or \b-w\b) and the variable "
	"\avar\a\b.fd\b is the file descriptor.]"
"[a:append?Open for append.]"
"[b:binary?Open in binary mode"
#ifndef O_BINARY
	" (not supported/ignored on this platform)"
#endif
	".]"
"[t:text?Open in text mode"
#ifndef O_TEXT
	" (not supported/ignored on this platform)"
#endif
	".]"
"[c:create?Open for create.]"
"[i:inherit?Open without the close-on-exec bit set.]"
"[I:noinherit?Open with the close-on-exec bit set.]"
"[r:read?Open with read access.]"
"[w:write?Open with write access.]"
"[m:mode]:[mode:=rwrwrw?Open with access mode \amode\a.]"
"[x:exclusive?Open exclusive.]"

"[N:nofollow?If the path names a symbolic link, open fails with ELOOP "
#ifndef O_NOFOLLOW
	" (not supported/ignored on this platform)"
#endif
	".]"
"[S:sync?Write I/O operations on the file descriptor complete as "
	"defined by synchronized I/O file integrity completion"
#ifndef O_SYNC
	" (not supported/ignored on this platform)"
#endif
	".]"
"[T:trunc?If the file exists and is a regular file, and  the  file "
        "is successfully opened read/write or write-only, its length is "
        "truncated to 0 and the mode and owner are unchanged.  It "
        "has  no  effect on FIFO special files or terminal device "
        "files.   Its   effect   on   other   file    types    is "
        "implementation-dependent.  The  result  of using -T "
        "with read-only files is undefined"
#ifndef O_TRUNC
	" (not supported/ignored on this platform)"
#endif
	".]"
"\n"
"\nvar file\n"
"\n"
"[+EXIT STATUS?]{"
        "[+0?Success.]"
        "[+>0?An error occurred.]"
"}"
"[+SEE ALSO?\btmpfile\b(1),\bdup\b(1),\bclose\b(1),\bstat\b(1),\bpoll\b(1),\bstat\b(2)]"
;


extern int b_open(int argc, char *argv[], void *extra)
{
	register Namval_t *np;
	register int n,oflag=0;
	Shell_t *shp = sh_contexttoshell(extra);
	struct filedata *fdp;
	mode_t mode = 0666;
	long flags = 0;
	int fd = -1;
	char *arg;

	while (n = optget(argv, sh_optopen)) switch (n)
	{
	    case 'r':
	    case 'w':
	    case 'i':
		flags |= letterbit(n);
		break;
	    case 'I':
		flags &= ~(letterbit('i'));
		break;
	    case 'b':
#ifdef O_BINARY
		oflag |= O_BINARY;
#endif
		break;
	    case 't':
#ifdef O_TEXT
		oflag |= O_TEXT;
#endif
		break;
	    case 'N':
#ifdef O_NOFOLLOW
		oflag |= O_NOFOLLOW;
#endif
		break;
	    case 'T':
#ifdef O_TRUNC
		oflag |= O_TRUNC;
#endif
		break;
	    case 'x':
		oflag |= O_EXCL;
		break;
	    case 'c':
		oflag |= O_CREAT;
		break;
	    case 'a':
		oflag |= O_APPEND;
		break;
	    case 'S':
#ifdef O_SYNC
		oflag |= O_SYNC;
#endif
		break;
	    case 'm':
		mode = strperm(arg = opt_info.arg, &opt_info.arg, mode);
		if (*opt_info.arg)
			errormsg(SH_DICT, ERROR_system(1), "%s: invalid mode", arg);
	    	break;
	    case ':':
		errormsg(SH_DICT, 2, "%s", opt_info.arg);
		break;
	    case '?':
		errormsg(SH_DICT, ERROR_usage(2), "%s", opt_info.arg);
		break;
	}
	argc -= opt_info.index;
	argv += opt_info.index;
	if(argc!=2 || !(flags&(letterbit('r')|letterbit('w'))))
		errormsg(SH_DICT, ERROR_usage(2), optusage((char*)0));
		
	if(flags&letterbit('r'))
	{
		if(flags&letterbit('w'))
			oflag |= O_RDWR;
		else
			oflag |= O_RDONLY;
	}
	else if(flags&letterbit('w'))
		oflag |= O_WRONLY;

	fd = sh_open(argv[1], oflag, mode);
	if(fd<0)
		errormsg(SH_DICT, ERROR_system(1), "%s: open failed", argv[1]);
	
	if(!(flags&letterbit('i')))
		fcntl(fd, F_SETFL, 0);

	np = nv_open(argv[0], shp->var_tree, NV_ARRAY|NV_VARNAME|NV_NOASSIGN);
	if(!nv_isnull(np))
		nv_unset(np);
	mkclass(np, &Fileclass);
	fdp = (struct filedata*)np->nvalue;
	fstat(fd, &fdp->statb);
	fdp->fd = fd;
	fdp->name = strdup(argv[1]);
	return(0);
}

static const char sh_optclose[] =
"[-?\n@(#)$Id: close (AT&T Labs Research) 2007-04-21 $\n]"
"[-author?Roland Mainz <roland.mainz@nrubsig.org>]"
"[-license?http://www.opensource.org/licenses/cpl1.0.txt]"
"[+NAME? close - close a file descriptor]"
"[+DESCRIPTION?\bclose\b closes the file descriptor specified by fd.]"
"\n"
"\nfd\n"
"\n"
"[+EXIT STATUS?]{"
        "[+0?Success.]"
        "[+>0?An error occurred.]"
"}"
"[+SEE ALSO?\bopen\b(1),\bdup\b(1),\btmpfile\b(1),\bpoll\b(1),\bstat\b(1)]"
;

extern int b_close(int argc, char *argv[], void *extra)
{
	register int n=0;
	int fd = -1;

	while (n = optget(argv, sh_optclose)) switch (n)
	{
	    case ':':
		errormsg(SH_DICT, 2, "%s", opt_info.arg);
		break;
	    case '?':
		errormsg(SH_DICT, ERROR_usage(2), "%s", opt_info.arg);
		break;
	}
	argc -= opt_info.index;
	argv += opt_info.index;
	if(argc!=1)
		errormsg(SH_DICT, ERROR_usage(2), optusage((char*)0));

	errno = 0;
	fd = strtol(argv[0], (char **)NULL, 0);
	if (errno != 0 || fd < 0)
		errormsg(SH_DICT, ERROR_system(1), "%s: invalid descriptor", argv[0]);

        n = sh_close(fd);

	if (n < 0)
		errormsg(SH_DICT, ERROR_system(1), "%s: close error", argv[0]);

	return(n==0?0:1);
}


static const char sh_opttmpfile[] =
"[-?\n@(#)$Id: tmpfile (AT&T Labs Research) 2007-05-07 $\n]"
"[-author?Roland Mainz <roland.mainz@nrubsig.org>]"
"[-license?http://www.opensource.org/licenses/cpl1.0.txt]"
"[+NAME? tmpfile - create a shell variable correspnding to a temporary file]"
"[+DESCRIPTION?\btmpfile\b creates the compound variable \avar\a correspinding "
	"to a temporary file.  The elements of \avar\a "
	"are the names of elements in the \astat\a structure with the \bst_\b "
	"prefix removed.]"
"[i:inherit?Open without the close-on-exec bit set.]"
"[I:noinherit?Open with the close-on-exec bit set.]"
"\n"
"\nvar\n"
"\n"
"[+EXIT STATUS?]{"
        "[+0?Success.]"
        "[+>0?An error occurred.]"
"}"
"[+SEE ALSO?\bopen\b(1),\bdup\b(1),\bclose\b(1),\bstat\b(1),\bstat\b(2)]"
;


extern int b_tmpfile(int argc, char *argv[], void *extra)
{
	register Namval_t *np;
	register int n;
	Shell_t *shp = sh_contexttoshell(extra);
	struct filedata *fdp;
	bool inherit = false;
	FILE *file = NULL;
	int ffd, fd = -1;
	while (n = optget(argv, sh_opttmpfile)) switch (n)
	{
	    case 'i':
		inherit = true;
		break;
	    case 'I':
		inherit = false;
		break;
	    case ':':
		errormsg(SH_DICT, 2, "%s", opt_info.arg);
		break;
	    case '?':
		errormsg(SH_DICT, ERROR_usage(2), "%s", opt_info.arg);
		break;
	}
	argc -= opt_info.index;
	argv += opt_info.index;
	if(argc!=1)
		errormsg(SH_DICT, ERROR_usage(2), optusage((char*)0));

	file = tmpfile();
	if(!file)
		errormsg(SH_DICT, ERROR_system(1), "%s: tmpfile failed", argv[1]);
	ffd = fileno(file);
	fd = sh_dup(ffd);
	if(fd<0)
		errormsg(SH_DICT, ERROR_system(1), "%s: tmpfile failed", argv[1]);
	fclose(file);

	if(!inherit)
		fcntl(fd, F_SETFL, 0);

	np = nv_open(argv[0], shp->var_tree, NV_ARRAY|NV_VARNAME|NV_NOASSIGN);
	if(!nv_isnull(np))
		nv_unset(np);
	mkclass(np,&Fileclass);
	fdp = (struct filedata*)np->nvalue;

	fstat(fd, &fdp->statb);
	fdp->fd = fd;
	fdp->name = NULL;
	return(0);
}

static const char sh_optdup[] =
"[-?\n@(#)$Id: dup (AT&T Labs Research) 2007-05-07 $\n]"
"[-author?Roland Mainz <roland.mainz@nrubsig.org>]"
"[-license?http://www.opensource.org/licenses/cpl1.0.txt]"
"[+NAME? dup - duplicate an open file descriptor]"
"[+DESCRIPTION?The \bdup\b commands returns a new file descriptor having the "
     "following in common with the original open file descriptor "
     "fd: same open file (or pipe), same file pointer (that is, both  file descriptors "
     "share one file pointer) same access mode (read, write or read/write). "
     "The file descriptor returned is the lowest one available.]"
"[i:inherit?Open without the close-on-exec bit set.]"
"[I:noinherit?Open with the close-on-exec bit set.]"
"\n"
"\nvar fd\n"
"\n"
"[+EXIT STATUS?]{"
        "[+0?Success.]"
        "[+>0?An error occurred.]"
"}"
"[+SEE ALSO?\bopen\b(1),\btmpfile\b(1),\bclose\b(1),\bpoll\b(1),\bstat\b(1)]"
;


extern int b_dup(int argc, char *argv[], void *extra)
{
	register Namval_t *np;
	register int n;
	Shell_t *shp = sh_contexttoshell(extra);
	struct filedata *fdp;
	bool inherit = false;
	int ffd, fd = -1;
	while (n = optget(argv, sh_optdup)) switch (n)
	{
	    case 'i':
		inherit = true;
		break;
	    case 'I':
		inherit = false;
		break;
	    case ':':
		errormsg(SH_DICT, 2, "%s", opt_info.arg);
		break;
	    case '?':
		errormsg(SH_DICT, ERROR_usage(2), "%s", opt_info.arg);
		break;
	}
	argc -= opt_info.index;
	argv += opt_info.index;
	if(argc!=2)
		errormsg(SH_DICT, ERROR_usage(2), optusage((char*)0));

	errno = 0;
	ffd = strtol(argv[1], (char **)NULL, 0);
	if (errno != 0 || ffd < 0)
		errormsg(SH_DICT, ERROR_system(1), "%s: invalid fd", argv[1]);

	fd = sh_dup(ffd);
	if(fd<0)
		errormsg(SH_DICT, ERROR_system(1), "%s: dup failed", argv[1]);

	if(!inherit)
		fcntl(fd,F_SETFL,0);

	np = nv_open(argv[0],shp->var_tree,NV_ARRAY|NV_VARNAME|NV_NOASSIGN);
	if(!nv_isnull(np))
		nv_unset(np);
	mkclass(np, &Fileclass);
	fdp = (struct filedata*)np->nvalue;

	fstat(fd, &fdp->statb);
	fdp->fd = fd;
	fdp->name = NULL;
	return(0);
}

static const char sh_optstat[] =
"[-?\n@(#)$Id: stat (AT&T Labs Research) 2007-05-07 $\n]"
"[-author?David Korn <dgk@research.att.com>]"
"[-author?Roland Mainz <roland.mainz@nrubsig.org>]"
"[-license?http://www.opensource.org/licenses/cpl1.0.txt]"
"[+NAME? stat - get file status]"
"[+DESCRIPTION?\bstat\b creates the compound variable \avar\a correspinding "
	"to the file given by the pathname \afile\a.  The elements of \avar\a "
	"are the names of elements in the \astat\a structure with the \bst_\b "
	"prefix removed.]"
"[l:lstat?If the the named file is a symbolic link returns information about "
	"the link itself.]"
"\n"
"\nvar file\n"
"\n"
"[+EXIT STATUS?]{"
        "[+0?Success.]"
        "[+>0?An error occurred.]"
"}"
"[+SEE ALSO?\bopen\b(1),\btmpfile\b(1),\bdup\b(1),\bclose\b(1),\bpoll\b(1),\bstat\b(2),\blstat\b(2)]"
;


extern int b_stat(int argc, char *argv[], void *extra)
{
	register Namval_t *np;
	register int n;
	Shell_t *shp = sh_contexttoshell(extra);
	struct filedata *fdp;
	long flags = 0;
	struct stat statb;
	while (n = optget(argv, sh_optstat)) switch (n)
	{
	    case 'l':
		flags |= letterbit(n);
		break;
	    case ':':
		errormsg(SH_DICT, 2, "%s", opt_info.arg);
		break;
	    case '?':
		errormsg(SH_DICT, ERROR_usage(2), "%s", opt_info.arg);
		break;
	}
	argc -= opt_info.index;
	argv += opt_info.index;
	if(argc!=2)
		errormsg(SH_DICT, ERROR_usage(2), optusage((char*)0));

	if(flags&letterbit('l'))
	{
		if(lstat(argv[1], &statb) < 0)
			errormsg(SH_DICT, ERROR_system(1), "%s: stat failed", argv[1]);
	}
	else
	{
		if(stat(argv[1], &statb) < 0)
			errormsg(SH_DICT, ERROR_system(1), "%s: stat failed", argv[1]);

	}

	np = nv_open(argv[0],shp->var_tree,NV_ARRAY|NV_VARNAME|NV_NOASSIGN);
	if(!nv_isnull(np))
		nv_unset(np);
	mkclass(np,&Fileclass);
	fdp = (struct filedata*)np->nvalue;
	fdp->statb = statb;
	fdp->fd = -1;
	fdp->name = strdup(argv[1]);
	return(0);
}

static const char sh_optpoll[] =
"[-?\n@(#)$Id: poll (AT&T Labs Research) 2007-12-20 $\n]"
"[-author?Roland Mainz <roland.mainz@nrubsig.org]"
"[-license?http://www.opensource.org/licenses/cpl1.0.txt]"
"[+NAME? poll - input/output multiplexing]"
"[+DESCRIPTION?The poll command provides applications with a mechanism "
	"for multiplexing input/output over a set of file descriptors. "
	"For each member of the array variable \bvar\b, "
	"poll examines the given file descriptor in the subscript \b.fd\b "
	"for the event(s) specified in the subscript \b.events\b."
	"The poll command identifies those file descriptors on which an "
	"application can read or write data, or on which certain events have "
	"occurred.]"
"[+?The \bvar\b argument specifies the file descriptors to be examined "
	"and the events of interest for each file descriptor. "
	"It is a array of structured variables with one member for each open "
	"file descriptor of interest. The array's members contain the following "
	"subscripts:]{"
		"[+?\b.fd\b       # file descriptor]"
		"[+?\b.events\b   # requested events]"
		"[+?\b.revents\b  # returned event]"
	"}"
"[+?The \bfd\b variable specifies an open file descriptor and the "
	"\bevents\b and \brevents\b members are strings constructed from "
	"a concaternation of the following event flags, seperated by '|':]"
	"{ "
	"[+POLLIN?Data other than high priority data may be "
		"read without blocking. For STREAMS, this "
		"flag is set in revents even if the message "
		"is of zero length.]"
	"[+POLLRDNORM?Normal data (priority band equals 0) may be "
		"read without blocking. For STREAMS, this "
		"flag is set in revents even if the message "
		"is of zero length.]"
	"[+POLLRDBAND?Data from a non-zero priority band may be "
		"read without blocking. For STREAMS, this "
		"flag is set in revents even if the message "
		"is of zero length.]"
	"[+POLLPRI?High priority data may be received without "
		"blocking. For STREAMS, this flag is set in "
		"revents even if the message is of zero "
		"length.]"
	"[+POLLOUT?Normal data (priority band equals 0) may be "
		"written without blocking.]"
	"[+POLLWRNORM?The same as POLLOUT.]"
	"[+POLLWRBAND?Priority data (priority band > 0) may be "
		"written.  This event only examines bands "
		"that have been written to at least once.]"
	"[+POLLERR?An error has occurred on the device or "
		"stream.  This flag is only valid in the "
		"revents bitmask; it is not used in the "
		"events member.]"
	"[+POLLHUP?A hangup has occurred on the stream. This "
		"event and POLLOUT are mutually exclusive; a "
		"stream can never be writable if a hangup has "
		"occurred. However, this event and POLLIN, "
		", POLLRDBAND, or POLLPRI are not "
		"mutually exclusive. This flag is only valid "
		"in the revents bitmask; it is not used in "
		"the events member.]"
	"[+POLLNVAL?The specified fd value does not belong to an "
		"open file. This flag is only valid in the "
		"revents member; it is not used in the events "
		"member.]"
   "}"
"]"

"[+?If the value fd is less than 0, events is ignored and "
	"revents is set to 0 in that entry on return from poll.]"

"[+?The results of the poll query are stored in the revents "
	"member in the \bvar\b structure. POLL*-strings are set in the \brevents\b "
	"variable to indicate which of the requested events are true. "
	"If none are true, the \brevents\b will be an empty string when "
	"the poll command returns. The event flags "
	"POLLHUP, POLLERR, and POLLNVAL are always set in \brevents\b "
	"if the conditions they indicate are true; this occurs even "
	"though these flags were not present in events.]"

"[+?If none of the defined events have occurred on any selected "
	"file descriptor, poll waits at least timeout milliseconds "
	"for an event to occur on any of the selected file descriptors. "
	"On a computer where millisecond timing accuracy is not "
	"available, timeout is rounded up to the nearest legal value "
	"available on that system. If the value timeout is 0, poll "
	"returns immediately. If the value of timeout is -1, poll "
	"blocks until a requested event occurs or until the call is "
	"interrupted.]"

"[+?The poll function supports regular files, terminal and "
	"pseudo-terminal devices, STREAMS-based files, FIFOs and "
	"pipes. The behavior of poll on elements of fds that refer "
	"to other types of file is unspecified.]"

"[+?The poll function supports sockets.]"

"[+?A file descriptor for a socket that is listening for connections "
	"will indicate that it is ready for reading, once connections "
	"are available. A file descriptor for a socket that "
	"is connecting asynchronously will indicate that it is ready "
	"for writing, once a connection has been established.]"
 
"[+?Regular files always poll TRUE for reading and writing.]"

"[c:fdcount]:[fdcount?Upon successful completion, a non-negative value is "
	"returned. A positive value indicates the total number of "
	"file descriptors that has been selected (that is, file "
	"descriptors for which the revents member is non-zero). A "
	"value of 0 indicates that the call timed out and no file "
	"descriptors have been selected. Upon failure, -1 is returned.]"
"[t:timeout]:[seconds?Timeout in seconds. If the value timeout is 0, "
	"poll returns immediately. If the value of timeout is -1, poll "
	"blocks until a requested event occurs or until the call is "
	"interrupted.]"
"[T:mtimeout]:[milliseconds?Timeout in milliseconds. If the value timeout is 0, "
	"poll returns immediately. If the value of timeout is -1, poll "
	"blocks until a requested event occurs or until the call is "
	"interrupted.]"
"\n"
"\nvar\n"
"\n"
"[+EXIT STATUS?]{"
        "[+0?Success.]"
        "[+>0?An error occurred.]"
"}"
"[+SEE ALSO?\bopen\b(1),\btmpfile\b(1),\bdup\b(1),\bclose\b(1),\bpoll\b(2)]"
;

/*
 * |mystpcpy| - like |strcpy()| but returns the end of the buffer
 *
 * Copy string s2 to s1.  s1 must be large enough.
 * return s1-1 (position of string terminator ('\0') in destnation buffer).
 */
static
char *mystpcpy(char *s1, const char *s2)
{
        while (*s1++ = *s2++)
                ;
        return (s1-1);
}

static
Namval_t *nv_open_fmt(Dt_t *dict, int flags, const char *namefmt, ...)
{
	char 	varnamebuff[PATH_MAX];
	va_list	ap;

	va_start(ap, namefmt);
	vsnprintf(varnamebuff, sizeof(varnamebuff), namefmt, ap);
	va_end(ap);
	
	return nv_open(varnamebuff, dict, flags);
}

static
int poll_strtoevents(const char *str)
{
	int events = 0;
    
	if (strstr(str, "POLLIN"))     events |= POLLIN;
	if (strstr(str, "POLLRDNORM")) events |= POLLRDNORM;
	if (strstr(str, "POLLRDBAND")) events |= POLLRDBAND;
	if (strstr(str, "POLLPRI"))    events |= POLLPRI;
	if (strstr(str, "POLLOUT"))    events |= POLLOUT;
	if (strstr(str, "POLLWRNORM")) events |= POLLWRNORM;
	if (strstr(str, "POLLWRBAND")) events |= POLLWRBAND;
	if (strstr(str, "POLLERR"))    events |= POLLERR;
	if (strstr(str, "POLLHUP"))    events |= POLLHUP;
	if (strstr(str, "POLLNVAL"))   events |= POLLNVAL;

	return events;
}


static
void poll_eventstostr(char *s, int events)
{
	*s='\0';
	if (!events)
		return;
	
	if (events & POLLIN)		s=mystpcpy(s, "POLLIN|");
	if (events & POLLRDNORM)	s=mystpcpy(s, "POLLRDNORM|");
	if (events & POLLRDBAND)	s=mystpcpy(s, "POLLRDBAND|");
	if (events & POLLPRI)		s=mystpcpy(s, "POLLPRI|");
	if (events & POLLOUT)		s=mystpcpy(s, "POLLOUT|");
	if (events & POLLWRNORM)	s=mystpcpy(s, "POLLWRNORM|");
	if (events & POLLWRBAND)	s=mystpcpy(s, "POLLWRBAND|");
	if (events & POLLERR)		s=mystpcpy(s, "POLLERR|");
	if (events & POLLHUP)		s=mystpcpy(s, "POLLHUP|");
	if (events & POLLNVAL)		s=mystpcpy(s, "POLLNVAL|");

	/* Remove trailling '|' */
	s--;
	if(*s=='|')
		*s='\0';
}

#undef  getconf
#define getconf(x)      strtol(astconf(x,NiL,NiL),NiL,0)
		
extern int b_poll(int argc, char *argv[], void *extra)
{
	register Namval_t *np;
	register int n;
	Shell_t *shp = sh_contexttoshell(extra);
	char *varname;
	int fd;
	unsigned int numpollfd = 0;
	int i;
	char *s;
	double timeout = -1.;
	char buff[256];
	char *pollfdcountvarname = NULL;
	long open_max,
	     bpoll_max;

	if ((open_max = getconf("OPEN_MAX")) <= 0)
		open_max = OPEN_MAX;
	/* |bpoll_max| needs to be larger than |OPEN_MAX| to make sure we
	 * can listen to different sets of events per fd.
	 */
	bpoll_max = open_max*2L;

	while (n = optget(argv, sh_optpoll)) switch (n)
	{
	    case 't':
	    case 'T':
		errno = 0;
		timeout = strtod(opt_info.arg, (char **)NULL);	
		if (errno != 0)
			errormsg(SH_DICT, ERROR_system(1), "%s: invalid timeout", opt_info.arg);

		/* -t uses seconds, -T milliseconds */
		if (n == 't')
			timeout *= 1000.;
		break;
	    case 'c':
	    	pollfdcountvarname = opt_info.arg;
		break;
	    case ':':
		errormsg(SH_DICT, 2, "%s", opt_info.arg);
		break;
	    case '?':
		errormsg(SH_DICT, ERROR_usage(2), "%s", opt_info.arg);
		break;
	}
	argc -= opt_info.index;
	argv += opt_info.index;
	if(argc!=1)
		errormsg(SH_DICT, ERROR_usage(2), optusage((char*)0));

        varname = argv[0];

	struct pollfd pollfd[bpoll_max];
	
	for(i=0 ; i < bpoll_max ; i++)
	{	
		np = nv_open_fmt(shp->var_tree, NV_VARNAME|NV_NOFAIL|NV_NOADD, "%s[%d].fd", varname, i);
		if (!np)
			break;
		fd = (int)nv_getnum(np);
		if (fd < 0 || fd > OPEN_MAX)
			errormsg(SH_DICT, ERROR_system(1), "invalid pollfd fd");
		nv_close(np);
		pollfd[i].fd = fd;

		np = nv_open_fmt(shp->var_tree, NV_VARNAME|NV_NOFAIL|NV_NOADD, "%s[%d].events", varname, i);
		if (!np)
			errormsg(SH_DICT, ERROR_system(1), "missing pollfd events");

		s = nv_getval(np);
		if (!s)
			errormsg(SH_DICT, ERROR_system(1), "missing pollfd events value");
		pollfd[i].events  = poll_strtoevents(s);
		nv_close(np);

		pollfd[i].revents = 0;
			
		numpollfd++;
        }
	
	if (i == bpoll_max)
		errormsg(SH_DICT, ERROR_system(1), "cannot handle more than %d entries.", bpoll_max);

	n = poll(pollfd, numpollfd, timeout);
	/* FixMe: EGAIN and EINTR may require extra handling */
	if (n < 0)
		errormsg(SH_DICT, ERROR_system(1), "failure");

	if (pollfdcountvarname)
	{
		int32_t v = n;

		np = nv_open_fmt(shp->var_tree, NV_VARNAME|NV_NOFAIL, "%s", pollfdcountvarname);
		if (!np)
			errormsg(SH_DICT, ERROR_system(1), "couldn't create poll count variable %s", pollfdcountvarname);
		nv_putval(np, (char *)&v, NV_INTEGER);
		nv_close(np);
	}

	for(i=0 ; i < numpollfd ; i++)
	{	
		np = nv_open_fmt(shp->var_tree, NV_VARNAME|NV_NOFAIL, "%s[%d].revents", varname, i);
		if (!np)
			errormsg(SH_DICT, ERROR_system(1), "couldn't create pollfd %s[%d].revents", varname, i);

		poll_eventstostr(buff, pollfd[i].revents);
	
		nv_putval(np, buff, 0);
		nv_close(np);
        }
	
	return(0);
}

static const char sh_optrewind[] =
"[-?\n@(#)$Id: rewind (AT&T Labs Research) 2007-05-07 $\n]"
"[-author?Roland Mainz <roland.mainz@nrubsig.org>]"
"[-license?http://www.opensource.org/licenses/cpl1.0.txt]"
"[+NAME? rewind - reset file position indicator in a stream]"
"[+DESCRIPTION?The \brewind\b command will move the file pointer of fd to position 0.]"
"\n"
"\nfd\n"
"\n"
"[+EXIT STATUS?]{"
        "[+0?Success.]"
        "[+>0?An error occurred.]"
"}"
"[+SEE ALSO?\bopen\b(1),\btmpfile\b(1),\bdup\b(1),\bclose\b(1),\bstat\b(1),\bstat\b(2)]"
;


extern int b_rewind(int argc, char *argv[], void *extra)
{
	Shell_t *shp = sh_contexttoshell(extra);
	int fd = -1;
	register int n;
	while (n = optget(argv, sh_optrewind)) switch (n)
	{
	    case ':':
		errormsg(SH_DICT, 2, "%s", opt_info.arg);
		break;
	    case '?':
		errormsg(SH_DICT, ERROR_usage(2), "%s", opt_info.arg);
		break;
	}
	argc -= opt_info.index;
	argv += opt_info.index;
	if(argc!=1)
		errormsg(SH_DICT, ERROR_usage(2), optusage((char*)0));

	errno = 0;
	fd = strtol(argv[0], (char **)NULL, 0);
	if (errno != 0 || fd < 0)
		errormsg(SH_DICT, ERROR_system(1), "%s: invalid fd", argv[0]);

	if (sh_seek(fd, 0, SEEK_SET) == (off_t)-1)
		errormsg(SH_DICT, ERROR_system(1), "seek error");

	return(0);
}
