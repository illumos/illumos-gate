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
 * read [-ACprs] [-d delim] [-u filenum] [-t timeout] [-n n] [-N n] [name...]
 *
 *   David Korn
 *   AT&T Labs
 *
 */

#include	<ast.h>
#include	<error.h>
#include	"defs.h"
#include	"variables.h"
#include	"lexstates.h"
#include	"io.h"
#include	"name.h"
#include	"builtins.h"
#include	"history.h"
#include	"terminal.h"
#include	"edit.h"

#define	R_FLAG	1	/* raw mode */
#define	S_FLAG	2	/* save in history file */
#define	A_FLAG	4	/* read into array */
#define N_FLAG	8	/* fixed size read at most */
#define NN_FLAG	0x10	/* fixed size read exact */
#define V_FLAG	0x20	/* use default value */
#define	C_FLAG	0x40	/* read into compound variable */
#define D_FLAG	8	/* must be number of bits for all flags */

struct read_save
{
        char	**argv;
	char	*prompt;
        short	fd;
        short	plen;
	int	flags;
        long	timeout;
};

int	b_read(int argc,char *argv[], void *extra)
{
	Sfdouble_t sec;
	register char *name;
	register int r, flags=0, fd=0;
	register Shell_t *shp = ((Shbltin_t*)extra)->shp;
	long timeout = 1000*shp->st.tmout;
	int save_prompt, fixargs=((Shbltin_t*)extra)->invariant;
	struct read_save *rp;
	static char default_prompt[3] = {ESC,ESC};
	rp = (struct read_save*)(((Shbltin_t*)extra)->data);
	if(argc==0)
	{
		if(rp)
			free((void*)rp);
		return(0);
	}
	if(rp)
	{
		flags = rp->flags;
		timeout = rp->timeout;
		fd = rp->fd;
		argv = rp->argv;
		name = rp->prompt;
		r = rp->plen;
		goto bypass;
	}
	while((r = optget(argv,sh_optread))) switch(r)
	{
	    case 'A':
		flags |= A_FLAG;
		break;
	    case 'C':
		flags |= C_FLAG;
		break;
	    case 't':
		sec = sh_strnum(opt_info.arg, (char**)0,1);
		timeout = sec ? 1000*sec : 1;
		break;
	    case 'd':
		if(opt_info.arg && *opt_info.arg!='\n')
		{
			char *cp = opt_info.arg;
			flags &= ~((1<<D_FLAG)-1);
			flags |= (mbchar(cp)<< D_FLAG);
		}
		break;
	    case 'p':
		if((fd = shp->cpipe[0])<=0)
			errormsg(SH_DICT,ERROR_exit(1),e_query);
		break;
	    case 'n': case 'N':
		flags &= ((1<<D_FLAG)-1);
		flags |= (r=='n'?N_FLAG:NN_FLAG);
		r = (int)opt_info.num;
		if((unsigned)r > (1<<((8*sizeof(int))-D_FLAG))-1)
			errormsg(SH_DICT,ERROR_exit(1),e_overlimit,opt_info.name);
		flags |= (r<< D_FLAG);
		break;
	    case 'r':
		flags |= R_FLAG;
		break;
	    case 's':
		/* save in history file */
		flags |= S_FLAG;
		break;
	    case 'u':
		fd = (int)opt_info.num;
		if(sh_inuse(fd))
			fd = -1;
		break;
	    case 'v':
		flags |= V_FLAG;
		break;
	    case ':':
		errormsg(SH_DICT,2, "%s", opt_info.arg);
		break;
	    case '?':
		errormsg(SH_DICT,ERROR_usage(2), "%s", opt_info.arg);
		break;
	}
	argv += opt_info.index;
	if(error_info.errors)
		errormsg(SH_DICT,ERROR_usage(2), "%s", optusage((char*)0));
	if(!((r=shp->fdstatus[fd])&IOREAD)  || !(r&(IOSEEK|IONOSEEK)))
		r = sh_iocheckfd(shp,fd);
	if(fd<0 || !(r&IOREAD))
		errormsg(SH_DICT,ERROR_system(1),e_file+4);
	/* look for prompt */
	if((name = *argv) && (name=strchr(name,'?')) && (r&IOTTY))
		r = strlen(name++);
	else
		r = 0;
	if(argc==fixargs && (rp=newof(NIL(struct read_save*),struct read_save,1,0)))
	{
		((Shbltin_t*)extra)->data = (void*)rp;
		rp->fd = fd;
		rp->flags = flags;
		rp->timeout = timeout;
		rp->argv = argv;
		rp->prompt = name;
		rp->plen = r;
	}
bypass:
	shp->prompt = default_prompt;
	if(r && (shp->prompt=(char*)sfreserve(sfstderr,r,SF_LOCKR)))
	{
		memcpy(shp->prompt,name,r);
		sfwrite(sfstderr,shp->prompt,r-1);
	}
	shp->timeout = 0;
	save_prompt = shp->nextprompt;
	shp->nextprompt = 0;
	r=sh_readline(shp,argv,fd,flags,timeout);
	shp->nextprompt = save_prompt;
	if(r==0 && (r=(sfeof(shp->sftable[fd])||sferror(shp->sftable[fd]))))
	{
		if(fd == shp->cpipe[0])
		{
			sh_pclose(shp->cpipe);
			return(1);
		}
	}
	sfclrerr(shp->sftable[fd]);
	return(r);
}

/*
 * here for read timeout
 */
static void timedout(void *handle)
{
	sfclrlock((Sfio_t*)handle);
	sh_exit(1);
}

/*
 * This is the code to read a line and to split it into tokens
 *  <names> is an array of variable names
 *  <fd> is the file descriptor
 *  <flags> is union of -A, -r, -s, and contains delimiter if not '\n'
 *  <timeout> is number of milli-seconds until timeout
 */

int sh_readline(register Shell_t *shp,char **names, int fd, int flags,long timeout)
{
	register ssize_t	c;
	register unsigned char	*cp;
	register Namval_t	*np;
	register char		*name, *val;
	register Sfio_t		*iop;
	Namfun_t		*nfp;
	char			*ifs;
	unsigned char		*cpmax;
	unsigned char		*del;
	char			was_escape = 0;
	char			use_stak = 0;
	volatile char		was_write = 0;
	volatile char		was_share = 1;
	int			rel, wrd;
	long			array_index = 0;
	void			*timeslot=0;
	int			delim = '\n';
	int			jmpval=0;
	ssize_t			size = 0;
	int			binary;
	struct	checkpt		buff;
	if(!(iop=shp->sftable[fd]) && !(iop=sh_iostream(shp,fd)))
		return(1);
	sh_stats(STAT_READS);
	if(names && (name = *names))
	{
		Namval_t *mp;
		if(val= strchr(name,'?'))
			*val = 0;
		np = nv_open(name,shp->var_tree,NV_NOASSIGN|NV_VARNAME);
		if(np && nv_isarray(np) && (mp=nv_opensub(np)))
			np = mp;
		if((flags&V_FLAG) && shp->ed_context)
			((struct edit*)shp->ed_context)->e_default = np;
		if(flags&A_FLAG)
		{
			flags &= ~A_FLAG;
			array_index = 1;
			nv_unset(np);
			nv_putsub(np,NIL(char*),0L);
		}
		else if(flags&C_FLAG)
		{
			delim = -1;
			nv_unset(np);
			nv_setvtree(np);
		}
		else
			name = *++names;
		if(val)
			*val = '?';
	}
	else
	{
		name = 0;
		if(dtvnext(shp->var_tree) || shp->namespace)
                	np = nv_open(nv_name(REPLYNOD),shp->var_tree,0);
		else
			np = REPLYNOD;
	}
	if(flags>>D_FLAG)	/* delimiter not new-line or fixed size read */
	{
		if(flags&(N_FLAG|NN_FLAG))
			size = ((unsigned)flags)>>D_FLAG;
		else
			delim = ((unsigned)flags)>>D_FLAG;
		if(shp->fdstatus[fd]&IOTTY)
			tty_raw(fd,1);
	}
	binary = nv_isattr(np,NV_BINARY);
	if(!binary && !(flags&(N_FLAG|NN_FLAG)))
	{
		Namval_t *mp;
		/* set up state table based on IFS */
		ifs = nv_getval(mp=sh_scoped(shp,IFSNOD));
		if((flags&R_FLAG) && shp->ifstable['\\']==S_ESC)
			shp->ifstable['\\'] = 0;
		else if(!(flags&R_FLAG) && shp->ifstable['\\']==0)
			shp->ifstable['\\'] = S_ESC;
		shp->ifstable[delim] = S_NL;
		if(delim!='\n')
		{
			shp->ifstable['\n'] = 0;
			nv_putval(mp, ifs, NV_RDONLY);
		}
		shp->ifstable[0] = S_EOF;
	}
	sfclrerr(iop);
	for(nfp=np->nvfun; nfp; nfp = nfp->next)
	{
		if(nfp->disc && nfp->disc->readf)
		{
			if((c=(*nfp->disc->readf)(np,iop,delim,nfp))>=0)
				return(c);
		}
	}
	if(binary && !(flags&(N_FLAG|NN_FLAG)))
	{
		flags |= NN_FLAG;
		size = nv_size(np);
	}
	was_write = (sfset(iop,SF_WRITE,0)&SF_WRITE)!=0;
	if(fd==0)
		was_share = (sfset(iop,SF_SHARE,1)&SF_SHARE)!=0;
	if(timeout || (shp->fdstatus[fd]&(IOTTY|IONOSEEK)))
	{
		sh_pushcontext(&buff,1);
		jmpval = sigsetjmp(buff.buff,0);
		if(jmpval)
			goto done;
		if(timeout)
	                timeslot = (void*)sh_timeradd(timeout,0,timedout,(void*)iop);
	}
	if(flags&(N_FLAG|NN_FLAG))
	{
		char buf[256],*var=buf,*cur,*end,*up,*v;
		/* reserved buffer */
		if((c=size)>=sizeof(buf))
		{
			if(!(var = (char*)malloc(c+1)))
				sh_exit(1);
			end = var + c;
		}
		else
			end = var + sizeof(buf) - 1;
		up = cur = var;
		if((sfset(iop,SF_SHARE,1)&SF_SHARE) && fd!=0)
			was_share = 1;
		if(size==0)
		{
			cp = sfreserve(iop,0,0);
			c = 0;
		}
		else
		{
			ssize_t	m;
			int	f;
			for (;;)
			{
				c = size;
				cp = sfreserve(iop,c,SF_LOCKR);
				f = 1;
				if(cp)
					m = sfvalue(iop);
				else if(flags&NN_FLAG)
				{
					c = size;
					m = (cp = sfreserve(iop,c,0)) ? sfvalue(iop) : 0;
					f = 0;
				}
				else
				{
					c = sfvalue(iop);
					m = (cp = sfreserve(iop,c,SF_LOCKR)) ? sfvalue(iop) : 0;
				}
				if(m>0 && (flags&N_FLAG) && !binary && (v=memchr(cp,'\n',m)))
				{
					*v++ = 0;
					m = v-(char*)cp;
				}
				if((c=m)>size)
					c = size;
				if(c>0)
				{
					if(c > (end-cur))
					{
						ssize_t	cx = cur - var, ux = up - var;
						m = (end - var) + (c - (end - cur));
						if (var == buf)
						{
							v = (char*)malloc(m+1);
							var = memcpy(v, var, cur - var);
						}
						else
							var = newof(var, char, m, 1);
						end = var + m;
						cur = var + cx;
						up = var + ux;
					}
					memcpy((void*)cur,cp,c);
					if(f)
						sfread(iop,cp,c);
					cur += c;
#if SHOPT_MULTIBYTE
					if(!binary && mbwide())
					{
						int	x;
						int	z;

						mbinit();
						*cur = 0;
						x = z = 0;
						while (up < cur && (z = mbsize(up)) > 0)
						{
							up += z;
							x++;
						}
						if((size -= x) > 0 && (up >= cur || z < 0) && ((flags & NN_FLAG) || z < 0 || m > c))
							continue;
					}
#endif
				}
#if SHOPT_MULTIBYTE
				if(!binary && mbwide() && (up == var || (flags & NN_FLAG) && size))
					cur = var;
#endif
				*cur = 0;
				if(c>=size || (flags&N_FLAG) || m==0)
				{
					if(m)
						sfclrerr(iop);
					break;
				}
				size -= c;
			}
		}
		if(timeslot)
			timerdel(timeslot);
		if(binary && !((size=nv_size(np)) && nv_isarray(np) && c!=size))
		{
			if((c==size) && np->nvalue.cp && !nv_isarray(np))
				memcpy((char*)np->nvalue.cp,var,c);
			else
			{
				Namval_t *mp;
				if(var==buf)
					var = memdup(var,c+1);
				nv_putval(np,var,NV_RAW);
				nv_setsize(np,c);
				if(!nv_isattr(np,NV_IMPORT|NV_EXPORT)  && (mp=(Namval_t*)np->nvenv))
					nv_setsize(mp,c);
			}
		}
		else
		{
			nv_putval(np,var,0);
			if(var!=buf)
				free((void*)var);
		}
		goto done;
	}
	else if(cp = (unsigned char*)sfgetr(iop,delim,0))
		c = sfvalue(iop);
	else if(cp = (unsigned char*)sfgetr(iop,delim,-1))
		c = sfvalue(iop)+1;
	if(timeslot)
		timerdel(timeslot);
	if((flags&S_FLAG) && !shp->hist_ptr)
	{
		sh_histinit((void*)shp);
		if(!shp->hist_ptr)
			flags &= ~S_FLAG;
	}
	if(cp)
	{
		cpmax = cp + c;
#if SHOPT_CRNL
		if(delim=='\n' && c>=2 && cpmax[-2]=='\r')
			cpmax--;
#endif /* SHOPT_CRNL */
		if(*(cpmax-1) != delim)
			*(cpmax-1) = delim;
		if(flags&S_FLAG)
			sfwrite(shp->hist_ptr->histfp,(char*)cp,c);
		c = shp->ifstable[*cp++];
#if !SHOPT_MULTIBYTE
		if(!name && (flags&R_FLAG)) /* special case single argument */
		{
			/* skip over leading blanks */
			while(c==S_SPACE)
				c = shp->ifstable[*cp++];
			/* strip trailing delimiters */
			if(cpmax[-1] == '\n')
				cpmax--;
			if(cpmax>cp)
			{
				while((c=shp->ifstable[*--cpmax])==S_DELIM || c==S_SPACE);
				cpmax[1] = 0;
			}
			else
				*cpmax =0;
			if(nv_isattr(np, NV_RDONLY))
			{
				errormsg(SH_DICT,ERROR_warn(0),e_readonly, nv_name(np));
				jmpval = 1;
			}
			else
				nv_putval(np,(char*)cp-1,0);
			goto done;
		}
#endif /* !SHOPT_MULTIBYTE */
	}
	else
		c = S_NL;
	shp->nextprompt = 2;
	rel= staktell();
	/* val==0 at the start of a field */
	val = 0;
	del = 0;
	while(1)
	{
		switch(c)
		{
#if SHOPT_MULTIBYTE
		   case S_MBYTE:
			if(val==0)
				val = (char*)(cp-1);
			if(sh_strchr(ifs,(char*)cp-1)>=0)
			{
				c = mbsize((char*)cp-1);
				if(name)
					cp[-1] = 0;
				if(c>1)
					cp += (c-1);
				c = S_DELIM;
			}
			else
				c = 0;
			continue;
#endif /*SHOPT_MULTIBYTE */
		    case S_ESC:
			/* process escape character */
			if((c = shp->ifstable[*cp++]) == S_NL)
				was_escape = 1;
			else
				c = 0;
			if(val)
			{
				stakputs(val);
				use_stak = 1;
				was_escape = 1;
				*val = 0;
			}
			continue;

		    case S_EOF:
			/* check for end of buffer */
			if(val && *val)
			{
				stakputs(val);
				use_stak = 1;
			}
			val = 0;
			if(cp>=cpmax)
			{
				c = S_NL;
				break;
			}
			/* eliminate null bytes */
			c = shp->ifstable[*cp++];
			if(!name && val && (c==S_SPACE||c==S_DELIM||c==S_MBYTE))
				c = 0;
			continue;
		    case S_NL:
			if(was_escape)
			{
				was_escape = 0;
				if(cp = (unsigned char*)sfgetr(iop,delim,0))
					c = sfvalue(iop);
				else if(cp=(unsigned char*)sfgetr(iop,delim,-1))
					c = sfvalue(iop)+1;
				if(cp)
				{
					if(flags&S_FLAG)
						sfwrite(shp->hist_ptr->histfp,(char*)cp,c);
					cpmax = cp + c;
					c = shp->ifstable[*cp++];
					val=0;
					if(!name && (c==S_SPACE || c==S_DELIM || c==S_MBYTE))
						c = 0;
					continue;
				}
			}
			c = S_NL;
			break;

		    case S_SPACE:
			/* skip over blanks */
			while((c=shp->ifstable[*cp++])==S_SPACE);
			if(!val)
				continue;
#if SHOPT_MULTIBYTE
			if(c==S_MBYTE)
			{
				if(sh_strchr(ifs,(char*)cp-1)>=0)
				{
					if((c = mbsize((char*)cp-1))>1)
						cp += (c-1);
					c = S_DELIM;
				}
				else
					c = 0;
			}
#endif /* SHOPT_MULTIBYTE */
			if(c!=S_DELIM)
				break;
			/* FALL THRU */

		    case S_DELIM:
			if(!del)
				del = cp - 1;
			if(name)
			{
				/* skip over trailing blanks */
				while((c=shp->ifstable[*cp++])==S_SPACE);
				break;
			}
			/* FALL THRU */

		    case 0:
			if(val==0 || was_escape)
			{
				val = (char*)(cp-1);
				was_escape = 0;
			}
			/* skip over word characters */
			wrd = -1;
			while(1)
			{
				while((c=shp->ifstable[*cp++])==0)
					if(!wrd)
						wrd = 1;
				if(!del&&c==S_DELIM)
					del = cp - 1;
				if(name || c==S_NL || c==S_ESC || c==S_EOF || c==S_MBYTE)
					break;
				if(wrd<0)
					wrd = 0;
			}
			if(wrd>0)
				del = (unsigned char*)"";
			if(c!=S_MBYTE)
				cp[-1] = 0;
			continue;
		}
		/* assign value and advance to next variable */
		if(!val)
			val = "";
		if(use_stak)
		{
			stakputs(val);
			stakputc(0);
			val = stakptr(rel);
		}
		if(!name && *val)
		{
			/* strip off trailing space delimiters */
			register unsigned char	*vp = (unsigned char*)val + strlen(val);
			while(shp->ifstable[*--vp]==S_SPACE);
			if(vp==del)
			{
				if(vp==(unsigned char*)val)
					vp--;
				else
					while(shp->ifstable[*--vp]==S_SPACE);
			}
			vp[1] = 0;
		}
		if(nv_isattr(np, NV_RDONLY))
		{
			errormsg(SH_DICT,ERROR_warn(0),e_readonly, nv_name(np));
			jmpval = 1;
		}
		else
			nv_putval(np,val,0);
		val = 0;
		del = 0;
		if(use_stak)
		{
			stakseek(rel);
			use_stak = 0;
		}
		if(array_index)
		{
			nv_putsub(np, NIL(char*), array_index++);
			if(c!=S_NL)
				continue;
			name = *++names;
		}
		while(1)
		{
			if(sh_isoption(SH_ALLEXPORT)&&!strchr(nv_name(np),'.') && !nv_isattr(np,NV_EXPORT))
			{
				nv_onattr(np,NV_EXPORT);
				sh_envput(sh.env,np);
			}
			if(name)
			{
				nv_close(np);
				np = nv_open(name,shp->var_tree,NV_NOASSIGN|NV_VARNAME);
				name = *++names;
			}
			else
				np = 0;
			if(c!=S_NL)
				break;
			if(!np)
				goto done;
			if(nv_isattr(np, NV_RDONLY))
			{
				errormsg(SH_DICT,ERROR_warn(0),e_readonly, nv_name(np));
				jmpval = 1;
			}
			else
				nv_putval(np, "", 0);
		}
	}
done:
	if(timeout || (shp->fdstatus[fd]&(IOTTY|IONOSEEK)))
		sh_popcontext(&buff);
	if(was_write)
		sfset(iop,SF_WRITE,1);
	if(!was_share)
		sfset(iop,SF_SHARE,0);
	nv_close(np);
	if((flags>>D_FLAG) && (shp->fdstatus[fd]&IOTTY))
		tty_cooked(fd);
	if(flags&S_FLAG)
		hist_flush(shp->hist_ptr);
	if(jmpval > 1)
		siglongjmp(*shp->jmplist,jmpval);
	return(jmpval);
}

