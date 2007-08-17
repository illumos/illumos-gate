/***********************************************************************
*                                                                      *
*               This software is part of the ast package               *
*           Copyright (c) 1982-2007 AT&T Knowledge Ventures            *
*                      and is licensed under the                       *
*                  Common Public License, Version 1.0                  *
*                      by AT&T Knowledge Ventures                      *
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

static const char id[] = "\n@(#)$Id: open (AT&T Research) 1998-07-07 $\0\n";

#include	<shell.h>
#include	<option.h>
#include	<stk.h>
#include	<tm.h>
#ifndef SH_DICT
#   define SH_DICT     "libshell"
#endif

/*
 * time formatting related 
*/ 
struct dctime
{
	Namfun_t	fun;
	Namval_t 	*format;
};

static char *get_time(Namval_t* np, Namfun_t* nfp)
{
	static char buff[256];
	struct dctime *dp = (struct dctime*)nfp;
	time_t t = nv_getn(np,nfp);
	char *format = nv_getval(dp->format);
	tmfmt(buff,sizeof(buff),format,(time_t*)0);
	return(buff);
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
				errormsg(SH_DICT,ERROR_exit(1),"%s: invalid date/time string",val);
		}
		nv_putv(np,(char*)&t,NV_INTEGER,nfp);
	}
	else
	{
		nv_unset(dp->format);
		free((void*)dp->format);
		nv_putv(np,val,flag,nfp);
	}
}

static Namval_t *create_time(Namval_t *np, const char *name, int flags, Namfun_t *nfp)
{
	struct dctime *dp = (struct dctime*)nfp;
	if(strcmp(name,"format"))
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
				errormsg(SH_DICT,ERROR_exit(1),"%s: invalid mode string",val);
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
"[-?\n@(#)$Id: open (AT&T Labs Research) 2007-03-11 $\n]"
"[-author?David Korn <dgk@research.att.com>]"
"[-license?http://www.opensource.org/licenses/cpl1.0.txt]"
"[+NAME? open - create a shell variable correspnding to a file]"
"[+DESCRIPTION?\bopen\b creates the compound variable \avar\a correspinding "
	"to the file given by the pathname \afile\a.  The elements of \avar\a "
	"are the names of elements in the \astat\a structure with the \bst_\b "
	"prefix removed.]"
"[+?If the \b-r\b and/or \b-w\b mode is specified, then \afile\a is opened and "
	"the variable \avar\a\b.fd\b is the file descriptor.]"
"[a:append?Open for append.]"
"[b:binary?Open in binary mode.]"
"[c:create?Open for create.]"
"[i:inherit?Open without the close-on-exec bit set.]"
"[r:read?Open with read access.]"
"[w:write?Open with write access.]"
"[m:mode]:[mode:=rwrwrw?Open with access mode \amode\a.]"
"[x:exclusive?Open exclusive.]"
"\n"
"\nvar file\n"
"\n"
"[+EXIT STATUS?]{"
        "[+0?Success.]"
        "[+>0?An error occurred.]"
"}"
"[+SEE ALSO?\bstat\b(2)]"
;


extern int b_open(int argc, char *argv[], void *extra)
{
	register Namval_t *np;
	register int n,oflag=0;
	Shell_t *shp = (Shell_t*)extra;
	struct filedata *fdp;
	struct stat statb;
	mode_t mode = 0666;
	long flags = 0;
	int fd = -1;
	while (n = optget(argv, sh_optopen)) switch (n)
	{
	    case 'r':
	    case 'i':
	    case 'w':
		flags |= letterbit(n);
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
	    case 'x':
		oflag |= O_EXCL;
		break;
	    case 'c':
		oflag |= O_CREAT;
		break;
	    case 'a':
		oflag |= O_APPEND;
		break;
	    case 'm':
		break;
	    case ':':
		errormsg(SH_DICT,2, "%s", opt_info.arg);
		break;
	    case '?':
		errormsg(SH_DICT,ERROR_usage(2), "%s", opt_info.arg);
		break;
	}
	argc -= opt_info.index;
	argv += opt_info.index;
	if(argc!=2)
		errormsg(SH_DICT,ERROR_usage(2),optusage((char*)0));
	if(!(flags&(letterbit('r')|letterbit('w'))))
	{
		if(stat(argv[1],&statb)<0)
			errormsg(SH_DICT,ERROR_system(1),"%s: open failed",argv[1]);
	}
	else
	{
		if(flags&letterbit('r'))
		{
			if(flags&letterbit('w'))
				oflag |= O_RDWR;
			else
				oflag |= O_RDONLY;
		}
		else if(flags&letterbit('w'))
			oflag |= O_WRONLY;
		fd = open(argv[1],oflag,mode);
		if(fd<0)
			errormsg(SH_DICT,ERROR_system(1),"%s: open failed",argv[1]);
	}
	if(!(flags&letterbit('i')))
		fcntl(fd,F_SETFL,0);
	np = nv_open(argv[0],shp->var_tree,NV_ARRAY|NV_VARNAME|NV_NOASSIGN);
	if(!nv_isnull(np))
		nv_unset(np);
	mkclass(np,&Fileclass);
	fdp = (struct filedata*)np->nvalue;
	if(!(flags&(letterbit('r')|letterbit('w'))))
		fdp->statb = statb;
	else
		fstat(fd,&fdp->statb);
	fdp->fd = fd;
	fdp->name = strdup(argv[1]);
	return(0);
}
