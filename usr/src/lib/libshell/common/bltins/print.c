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
 * echo [arg...]
 * print [-nrps] [-f format] [-u filenum] [arg...]
 * printf  format [arg...]
 *
 *   David Korn
 *   AT&T Labs
 */

#include	"defs.h"
#include	<error.h>
#include	<stak.h>
#include	"io.h"
#include	"name.h"
#include	"history.h"
#include	"builtins.h"
#include	"streval.h"
#include	<tmx.h>
#include	<ccode.h>

union types_t
{
	unsigned char	c;
	short		h;
	int		i;
	long		l;
	Sflong_t	ll;
	Sfdouble_t	ld;
	double		d;
	float		f;
	char		*s;
	int		*ip;
	char		**p;
};

struct printf
{
	Sffmt_t		hdr;
	int		argsize;
	int		intvar;
	char		**nextarg;
	char		*lastarg;
	char		cescape;
	char		err;
	Shell_t		*sh;
};

static int		extend(Sfio_t*,void*, Sffmt_t*);
static const char   	preformat[] = "";
static char		*genformat(char*);
static int		fmtvecho(const char*, struct printf*);
static ssize_t		fmtbase64(Sfio_t*, char*, int);

struct print
{
	Shell_t         *sh;
	const char	*options;
	char		raw;
	char		echon;
};

static char* 	nullarg[] = { 0, 0 };

#if !SHOPT_ECHOPRINT
   int    B_echo(int argc, char *argv[],void *extra)
   {
	static char bsd_univ;
	struct print prdata;
	prdata.options = sh_optecho+5;
	prdata.raw = prdata.echon = 0;
	prdata.sh = ((Shbltin_t*)extra)->shp;
	NOT_USED(argc);
	/* This mess is because /bin/echo on BSD is different */
	if(!prdata.sh->universe)
	{
		register char *universe;
		if(universe=astconf("UNIVERSE",0,0))
			bsd_univ = (strcmp(universe,"ucb")==0);
		prdata.sh->universe = 1;
	}
	if(!bsd_univ)
		return(b_print(0,argv,&prdata));
	prdata.options = sh_optecho;
	prdata.raw = 1;
	while(argv[1] && *argv[1]=='-')
	{
		if(strcmp(argv[1],"-n")==0)
			prdata.echon = 1;
#if !SHOPT_ECHOE
		else if(strcmp(argv[1],"-e")==0)
			prdata.raw = 0;
		else if(strcmp(argv[1],"-ne")==0 || strcmp(argv[1],"-en")==0)
		{
			prdata.raw = 0;
			prdata.echon = 1;
		}
#endif /* SHOPT_ECHOE */
		else
			break;
		argv++;
	}
	return(b_print(0,argv,&prdata));
   }
#endif /* SHOPT_ECHOPRINT */

int    b_printf(int argc, char *argv[],void *extra)
{
	struct print prdata;
	NOT_USED(argc);
	memset(&prdata,0,sizeof(prdata));
	prdata.sh = ((Shbltin_t*)extra)->shp;
	prdata.options = sh_optprintf;
	return(b_print(-1,argv,&prdata));
}

/*
 * argc==0 when called from echo
 * argc==-1 when called from printf
 */

int    b_print(int argc, char *argv[], void *extra)
{
	register Sfio_t *outfile;
	register int exitval=0,n, fd = 1;
	register Shell_t *shp = ((Shbltin_t*)extra)->shp;
	const char *options, *msg = e_file+4;
	char *format = 0;
	int sflag = 0, nflag=0, rflag=0, vflag=0;
	if(argc>0)
	{
		options = sh_optprint;
		nflag = rflag = 0;
		format = 0;
	}
	else
	{
		struct print *pp = (struct print*)extra;
		shp = pp->sh;
		options = pp->options;
		if(argc==0)
		{
			nflag = pp->echon;
			rflag = pp->raw;
			argv++;
			goto skip;
		}
	}
	while((n = optget(argv,options))) switch(n)
	{
		case 'n':
			nflag++;
			break;
		case 'p':
			fd = shp->coutpipe;
			msg = e_query;
			break;
		case 'f':
			format = opt_info.arg;
			break;
		case 's':
			/* print to history file */
			if(!sh_histinit((void*)shp))
				errormsg(SH_DICT,ERROR_system(1),e_history);
			fd = sffileno(shp->hist_ptr->histfp);
			sh_onstate(SH_HISTORY);
			sflag++;
			break;
		case 'e':
			rflag = 0;
			break;
		case 'r':
			rflag = 1;
			break;
		case 'u':
			fd = (int)strtol(opt_info.arg,&opt_info.arg,10);
			if(*opt_info.arg)
				fd = -1;
			else if(fd<0 || fd >= shp->lim.open_max)
				fd = -1;
			else if(!(sh.inuse_bits&(1<<fd)) && (sh_inuse(fd) || (shp->hist_ptr && fd==sffileno(shp->hist_ptr->histfp))))

				fd = -1;
			break;
		case 'v':
			vflag='v';
			break;
		case 'C':
			vflag='C';
			break;
		case ':':
			/* The following is for backward compatibility */
#if OPT_VERSION >= 19990123
			if(strcmp(opt_info.name,"-R")==0)
#else
			if(strcmp(opt_info.option,"-R")==0)
#endif
			{
				rflag = 1;
				if(error_info.errors==0)
				{
					argv += opt_info.index+1;
					/* special case test for -Rn */
					if(strchr(argv[-1],'n'))
						nflag++;
					if(*argv && strcmp(*argv,"-n")==0)
					{

						nflag++;
						argv++;
					}
					goto skip2;
				}
			}
			else
				errormsg(SH_DICT,2, "%s", opt_info.arg);
			break;
		case '?':
			errormsg(SH_DICT,ERROR_usage(2), "%s", opt_info.arg);
			break;
	}
	argv += opt_info.index;
	if(error_info.errors || (argc<0 && !(format = *argv++)))
		errormsg(SH_DICT,ERROR_usage(2),"%s",optusage((char*)0));
	if(vflag && format)
		errormsg(SH_DICT,ERROR_usage(2),"-%c and -f are mutually exclusive",vflag);
skip:
	if(format)
		format = genformat(format);
	/* handle special case of '-' operand for print */
	if(argc>0 && *argv && strcmp(*argv,"-")==0 && strcmp(argv[-1],"--"))
		argv++;
skip2:
	if(fd < 0)
	{
		errno = EBADF;
		n = 0;
	}
	else if(!(n=shp->fdstatus[fd]))
		n = sh_iocheckfd(shp,fd);
	if(!(n&IOWRITE))
	{
		/* don't print error message for stdout for compatibility */
		if(fd==1)
			return(1);
		errormsg(SH_DICT,ERROR_system(1),msg);
	}
	if(!(outfile=shp->sftable[fd]))
	{
		sh_onstate(SH_NOTRACK);
		n = SF_WRITE|((n&IOREAD)?SF_READ:0);
		shp->sftable[fd] = outfile = sfnew(NIL(Sfio_t*),shp->outbuff,IOBSIZE,fd,n);
		sh_offstate(SH_NOTRACK);
		sfpool(outfile,shp->outpool,SF_WRITE);
	}
	/* turn off share to guarantee atomic writes for printf */
	n = sfset(outfile,SF_SHARE|SF_PUBLIC,0);
	if(format)
	{
		/* printf style print */
		Sfio_t *pool;
		struct printf pdata;
		memset(&pdata, 0, sizeof(pdata));
		pdata.sh = shp;
		pdata.hdr.version = SFIO_VERSION;
		pdata.hdr.extf = extend;
		pdata.nextarg = argv;
		sh_offstate(SH_STOPOK);
		pool=sfpool(sfstderr,NIL(Sfio_t*),SF_WRITE);
		do
		{
			if(shp->trapnote&SH_SIGSET)
				break;
			pdata.hdr.form = format;
			sfprintf(outfile,"%!",&pdata);
		} while(*pdata.nextarg && pdata.nextarg!=argv);
		if(pdata.nextarg == nullarg && pdata.argsize>0)
			sfwrite(outfile,stakptr(staktell()),pdata.argsize);
		if(sffileno(outfile)!=sffileno(sfstderr))
			sfsync(outfile);
		sfpool(sfstderr,pool,SF_WRITE);
		exitval = pdata.err;
	}
	else if(vflag)
	{
		while(*argv)
		{
			fmtbase64(outfile,*argv++,vflag=='C');
			if(!nflag)
				sfputc(outfile,'\n');
		}
	}
	else
	{
		/* echo style print */
		if(nflag && !argv[0])
			sfsync((Sfio_t*)0);
		else if(sh_echolist(outfile,rflag,argv) && !nflag)
			sfputc(outfile,'\n');
	}
	if(sflag)
	{
		hist_flush(shp->hist_ptr);
		sh_offstate(SH_HISTORY);
	}
	else if(n&SF_SHARE)
	{
		sfset(outfile,SF_SHARE|SF_PUBLIC,1);
		sfsync(outfile);
	}
	return(exitval);
}

/*
 * echo the argument list onto <outfile>
 * if <raw> is non-zero then \ is not a special character.
 * returns 0 for \c otherwise 1.
 */

int sh_echolist(Sfio_t *outfile, int raw, char *argv[])
{
	register char	*cp;
	register int	n;
	struct printf pdata;
	pdata.cescape = 0;
	pdata.err = 0;
	while(!pdata.cescape && (cp= *argv++))
	{
		if(!raw  && (n=fmtvecho(cp,&pdata))>=0)
		{
			if(n)
				sfwrite(outfile,stakptr(staktell()),n);
		}
		else
			sfputr(outfile,cp,-1);
		if(*argv)
			sfputc(outfile,' ');
		sh_sigcheck();
	}
	return(!pdata.cescape);
}

/*
 * modified version of stresc for generating formats
 */
static char strformat(char *s)
{
        register char*  t;
        register int    c;
        char*           b;
        char*           p;

        b = t = s;
        for (;;)
        {
                switch (c = *s++)
                {
                    case '\\':
			if(*s==0)
				break;
                        c = chresc(s - 1, &p);
                        s = p;
#if SHOPT_MULTIBYTE
			if(c>UCHAR_MAX && mbwide())
			{
				t += wctomb(t, c);
				continue;
			}
#endif /* SHOPT_MULTIBYTE */
			if(c=='%')
				*t++ = '%';
			else if(c==0)
			{
				*t++ = '%';
				c = 'Z';
			}
                        break;
                    case 0:
                        *t = 0;
                        return(t - b);
                }
                *t++ = c;
        }
}


static char *genformat(char *format)
{
	register char *fp;
	stakseek(0);
	stakputs(preformat);
	stakputs(format);
	fp = (char*)stakfreeze(1);
	strformat(fp+sizeof(preformat)-1);
	return(fp);
}

static char *fmthtml(const char *string)
{
	register const char *cp = string;
	register int c, offset = staktell();
	while(c= *(unsigned char*)cp++)
	{
#if SHOPT_MULTIBYTE
		register int s;
		if((s=mbsize(cp-1)) > 1)
		{
			cp += (s-1);
			continue;
		}
#endif /* SHOPT_MULTIBYTE */
		if(c=='<')
			stakputs("&lt;");
		else if(c=='>')
			stakputs("&gt;");
		else if(c=='&')
			stakputs("&amp;");
		else if(c=='"')
			stakputs("&quot;");
		else if(c=='\'')
			stakputs("&apos;");
		else if(c==' ')
			stakputs("&nbsp;");
		else if(!isprint(c) && c!='\n' && c!='\r')
			sfprintf(stkstd,"&#%X;",CCMAPC(c,CC_NATIVE,CC_ASCII));
		else
			stakputc(c);
	}
	stakputc(0);
	return(stakptr(offset));
}

#if 1
static ssize_t fmtbase64(Sfio_t *iop, char *string, int alt)
#else
static void *fmtbase64(char *string, ssize_t *sz, int alt)
#endif
{
	char			*cp;
	Sfdouble_t		d;
	ssize_t			size;
	Namval_t		*np = nv_open(string, NiL, NV_VARNAME|NV_NOASSIGN|NV_NOADD);
	static union types_t	number;
	if(!np || nv_isnull(np))
	{
		if(sh_isoption(SH_NOUNSET))
			errormsg(SH_DICT,ERROR_exit(1),e_notset,string);
		return(0);
	}
	if(nv_isattr(np,NV_INTEGER))
	{
		d = nv_getnum(np);
		if(nv_isattr(np,NV_DOUBLE))
		{
			if(nv_isattr(np,NV_LONG))
			{
				size = sizeof(Sfdouble_t);
				number.ld = d;
			}
			else if(nv_isattr(np,NV_SHORT))
			{
				size = sizeof(float);
				number.f = (float)d;
			}
			else
			{
				size = sizeof(double);
				number.d = (double)d;
			}
		}
		else
		{
			if(nv_isattr(np,NV_LONG))
			{
				size =  sizeof(Sflong_t);
				number.ll = (Sflong_t)d;
			}
			else if(nv_isattr(np,NV_SHORT))
			{
				size =  sizeof(short);
				number.h = (short)d;
			}
			else
			{
				size =  sizeof(short);
				number.i = (int)d; 
			}
		}
#if 1
		return(sfwrite(iop, (void*)&number, size));
#else
		if(sz)
			*sz = size;
		return((void*)&number);
#endif
	}
	if(nv_isattr(np,NV_BINARY))
#if 1
	{
		Namfun_t *fp;
		for(fp=np->nvfun; fp;fp=fp->next)
		{
			if(fp->disc && fp->disc->writef)
				break;
		}
		if(fp)
			return (*fp->disc->writef)(np, iop, 0, fp); 		
		else
		{
			int n = nv_size(np);
			if(nv_isarray(np))
			{
				nv_onattr(np,NV_RAW);
				cp = nv_getval(np);
				nv_offattr(np,NV_RAW);
			}
			else
				cp = (char*)np->nvalue.cp;
			if((size = n)==0)
				size = strlen(cp);
			size = sfwrite(iop, cp, size);
			return(n?n:size);
		}
	}
	else if(nv_isarray(np) && nv_arrayptr(np))
	{
		nv_outnode(np,iop,(alt?-1:0),0);
		sfputc(iop,')');
		return(sftell(iop));
	}
	else
	{
		if(alt && nv_isvtree(np))
			nv_onattr(np,NV_EXPORT);
		if(!(cp = nv_getval(np)))
			return(0);
		size = strlen(cp);
		return(sfwrite(iop,cp,size));
	}
#else
		nv_onattr(np,NV_RAW);
	cp = nv_getval(np);
	if(nv_isattr(np,NV_BINARY))
		nv_offattr(np,NV_RAW);
	if((size = nv_size(np))==0)
		size = strlen(cp);
	if(sz)
		*sz = size;
	return((void*)cp);
#endif
}

static int varname(const char *str, int n)
{
	register int c,dot=1,len=1;
	if(n < 0)
	{
		if(*str=='.')
			str++;
		n = strlen(str);
	}
	for(;n > 0; n-=len)
	{
#ifdef SHOPT_MULTIBYTE
		len = mbsize(str);
		c = mbchar(str);
#else
		c = *(unsigned char*)str++;
#endif
		if(dot && !(isalpha(c)||c=='_'))
			break;
		else if(dot==0 && !(isalnum(c) || c=='_' || c == '.'))
			break;
		dot = (c=='.');
	}
	return(n==0);
}

static int extend(Sfio_t* sp, void* v, Sffmt_t* fe)
{
	char*		lastchar = "";
	register int	neg = 0;
	Sfdouble_t	d;
	Sfdouble_t	longmin = LDBL_LLONG_MIN;
	Sfdouble_t	longmax = LDBL_LLONG_MAX;
	int		format = fe->fmt;
	int		n;
	int		fold = fe->base;
	union types_t*	value = (union types_t*)v;
	struct printf*	pp = (struct printf*)fe;
	register char*	argp = *pp->nextarg;
	char*		w;

	if(fe->n_str>0 && varname(fe->t_str,fe->n_str) && (!argp || varname(argp,-1)))
	{
		if(argp)
			pp->lastarg = argp;
		else
			argp = pp->lastarg;
		if(argp)
		{
			sfprintf(pp->sh->strbuf,"%s.%.*s%c",argp,fe->n_str,fe->t_str,0);
			argp = sfstruse(pp->sh->strbuf);
		}
	}
	else
		pp->lastarg = 0;
	fe->flags |= SFFMT_VALUE;
	if(!argp || format=='Z')
	{
		switch(format)
		{
		case 'c':
			value->c = 0;
			fe->flags &= ~SFFMT_LONG;
			break;
		case 'q':
			format = 's';
			/* FALL THROUGH */
		case 's':
		case 'H':
		case 'B':
		case 'P':
		case 'R':
		case 'Z':
		case 'b':
			fe->fmt = 's';
			fe->size = -1;
			fe->base = -1;
			value->s = "";
			fe->flags &= ~SFFMT_LONG;
			break;
		case 'a':
		case 'e':
		case 'f':
		case 'g':
		case 'A':
		case 'E':
		case 'F':
		case 'G':
                        if(SFFMT_LDOUBLE)
				value->ld = 0.;
			else
				value->d = 0.;
			break;
		case 'n':
			value->ip = &pp->intvar;
			break;
		case 'Q':
			value->ll = 0;
			break;
		case 'T':
			fe->fmt = 'd';
			value->ll = tmxgettime();
			break;
		default:
			if(!strchr("DdXxoUu",format))
				errormsg(SH_DICT,ERROR_exit(1),e_formspec,format);
			fe->fmt = 'd';
			value->ll = 0;
			break;
		}
	}
	else
	{
		switch(format)
		{
		case 'p':
			value->p = (char**)strtol(argp,&lastchar,10);
			break;
		case 'n':
		{
			Namval_t *np;
			np = nv_open(argp,sh.var_tree,NV_VARNAME|NV_NOASSIGN|NV_NOARRAY);
			nv_unset(np);
			nv_onattr(np,NV_INTEGER);
			if (np->nvalue.lp = new_of(int32_t,0))
				*np->nvalue.lp = 0;
			nv_setsize(np,10);
			if(sizeof(int)==sizeof(int32_t))
				value->ip = (int*)np->nvalue.lp;
			else
			{
				int32_t sl = 1;
				value->ip = (int*)(((char*)np->nvalue.lp) + (*((char*)&sl) ? 0 : sizeof(int)));
			}
			nv_close(np);
			break;
		}
		case 'q':
		case 'b':
		case 's':
		case 'B':
		case 'H':
		case 'P':
		case 'R':
			fe->fmt = 's';
			fe->size = -1;
			if(format=='s' && fe->base>=0)
			{
				value->p = pp->nextarg;
				pp->nextarg = nullarg;
			}
			else
			{
				fe->base = -1;
				value->s = argp;
			}
			fe->flags &= ~SFFMT_LONG;
			break;
		case 'c':
			if(mbwide() && (n = mbsize(argp)) > 1)
			{
				fe->fmt = 's';
				fe->size = n;
				value->s = argp;
			}
			else if(fe->base >=0)
				value->s = argp;
			else
				value->c = *argp;
			fe->flags &= ~SFFMT_LONG;
			break;
		case 'o':
		case 'x':
		case 'X':
		case 'u':
		case 'U':
			longmax = LDBL_ULLONG_MAX;
			/* FALLTHROUGH */
		case '.':
			if(fe->size==2 && strchr("bcsqHPRQTZ",*fe->form))
			{
				value->ll = ((unsigned char*)argp)[0];
				break;
			}
			/* FALLTHROUGH */
		case 'd':
		case 'D':
		case 'i':
			switch(*argp)
			{
			case '\'':
			case '"':
				w = argp + 1;
				if(mbwide() && mbsize(w) > 1)
					value->ll = mbchar(w);
				else
					value->ll = *(unsigned char*)w++;
				if(w[0] && (w[0] != argp[0] || w[1]))
				{
					errormsg(SH_DICT,ERROR_warn(0),e_charconst,argp);
					pp->err = 1;
				}
				break;
			default:
				d = sh_strnum(argp,&lastchar,0);
				if(d<longmin)
				{
					errormsg(SH_DICT,ERROR_warn(0),e_overflow,argp);
					pp->err = 1;
					d = longmin;
				}
				else if(d>longmax)
				{
					errormsg(SH_DICT,ERROR_warn(0),e_overflow,argp);
					pp->err = 1;
					d = longmax;
				}
				value->ll = (Sflong_t)d;
				if(lastchar == *pp->nextarg)
				{
					value->ll = *argp;
					lastchar = "";
				}
				break;
			}
			if(neg)
				value->ll = -value->ll;
			fe->size = sizeof(value->ll);
			break;
		case 'a':
		case 'e':
		case 'f':
		case 'g':
		case 'A':
		case 'E':
		case 'F':
		case 'G':
			d = sh_strnum(*pp->nextarg,&lastchar,0);
			switch(*argp)
			{
			    case '\'':
			    case '"':
				d = ((unsigned char*)argp)[1];
				if(argp[2] && (argp[2] != argp[0] || argp[3]))
				{
					errormsg(SH_DICT,ERROR_warn(0),e_charconst,argp);
					pp->err = 1;
				}
				break;
			    default:
				d = sh_strnum(*pp->nextarg,&lastchar,0);
				break;
			}
                        if(SFFMT_LDOUBLE)
			{
				value->ld = d;
				fe->size = sizeof(value->ld);
			}
			else
			{
				value->d = d;
				fe->size = sizeof(value->d);
			}
			break;
		case 'Q':
			value->ll = (Sflong_t)strelapsed(*pp->nextarg,&lastchar,1);
			break;
		case 'T':
			value->ll = (Sflong_t)tmxdate(*pp->nextarg,&lastchar,TMX_NOW);
			break;
		default:
			value->ll = 0;
			fe->fmt = 'd';
			fe->size = sizeof(value->ll);
			errormsg(SH_DICT,ERROR_exit(1),e_formspec,format);
			break;
		}
		if (format == '.')
			value->i = value->ll;
		if(*lastchar)
		{
			errormsg(SH_DICT,ERROR_warn(0),e_argtype,format);
			pp->err = 1;
		}
		pp->nextarg++;
	}
	switch(format)
	{
	case 'Z':
		fe->fmt = 'c';
		fe->base = -1;
		value->c = 0;
		break;
	case 'b':
		if((n=fmtvecho(value->s,pp))>=0)
		{
			if(pp->nextarg == nullarg)
			{
				pp->argsize = n;
				return -1;
			}
			value->s = stakptr(staktell());
		}
		break;
	case 'B':
		if(!sh.strbuf2)
			sh.strbuf2 = sfstropen();
		fe->size = fmtbase64(sh.strbuf2,value->s, fe->flags&SFFMT_ALTER);
		value->s = sfstruse(sh.strbuf2);
		fe->flags |= SFFMT_SHORT;
		break;
	case 'H':
		value->s = fmthtml(value->s);
		break;
	case 'q':
		value->s = sh_fmtqf(value->s, !!(fe->flags & SFFMT_ALTER), fold);
		break;
	case 'P':
	{
		char *s = fmtmatch(value->s);
		if(!s || *s==0)
			errormsg(SH_DICT,ERROR_exit(1),e_badregexp,value->s);
		value->s = s;
		break;
	}
	case 'R':
		value->s = fmtre(value->s);
		if(*value->s==0)
			errormsg(SH_DICT,ERROR_exit(1),e_badregexp,value->s);
		break;
	case 'Q':
		if (fe->n_str>0)
		{
			fe->fmt = 'd';
			fe->size = sizeof(value->ll);
		}
		else
		{
			value->s = fmtelapsed(value->ll, 1);
			fe->fmt = 's';
			fe->size = -1;
		}
		break;
	case 'T':
		if(fe->n_str>0)
		{
			n = fe->t_str[fe->n_str];
			fe->t_str[fe->n_str] = 0;
			value->s = fmttmx(fe->t_str, value->ll);
			fe->t_str[fe->n_str] = n;
		}
		else value->s = fmttmx(NIL(char*), value->ll);
		fe->fmt = 's';
		fe->size = -1;
		break;
	}
	return 0;
}

/*
 * construct System V echo string out of <cp>
 * If there are not escape sequences, returns -1
 * Otherwise, puts null terminated result on stack, but doesn't freeze it
 * returns length of output.
 */

static int fmtvecho(const char *string, struct printf *pp)
{
	register const char *cp = string, *cpmax;
	register int c;
	register int offset = staktell();
#if SHOPT_MULTIBYTE
	int chlen;
	if(mbwide())
	{
		while(1)
		{
			if ((chlen = mbsize(cp)) > 1)
				/* Skip over multibyte characters */
				cp += chlen;
			else if((c= *cp++)==0 || c == '\\')
				break;
		}
	}
	else
#endif /* SHOPT_MULTIBYTE */
	while((c= *cp++) && (c!='\\'));
	if(c==0)
		return(-1);
	c = --cp - string;
	if(c>0)
		stakwrite((void*)string,c);
	for(; c= *cp; cp++)
	{
#if SHOPT_MULTIBYTE
		if (mbwide() && ((chlen = mbsize(cp)) > 1))
		{
			stakwrite(cp,chlen);
			cp +=  (chlen-1);
			continue;
		}
#endif /* SHOPT_MULTIBYTE */
		if( c=='\\') switch(*++cp)
		{
			case 'E':
				c = ('a'==97?'\033':39); /* ASCII/EBCDIC */
				break;
			case 'a':
				c = '\a';
				break;
			case 'b':
				c = '\b';
				break;
			case 'c':
				pp->cescape++;
				pp->nextarg = nullarg;
				goto done;
			case 'f':
				c = '\f';
				break;
			case 'n':
				c = '\n';
				break;
			case 'r':
				c = '\r';
				break;
			case 'v':
				c = '\v';
				break;
			case 't':
				c = '\t';
				break;
			case '\\':
				c = '\\';
				break;
			case '0':
				c = 0;
				cpmax = cp + 4;
				while(++cp<cpmax && *cp>='0' && *cp<='7')
				{
					c <<= 3;
					c |= (*cp-'0');
				}
				/* FALLTHROUGH */
			default:
				cp--;
		}
		stakputc(c);
	}
done:
	c = staktell()-offset;
	stakputc(0);
	stakseek(offset);
	return(c);
}
