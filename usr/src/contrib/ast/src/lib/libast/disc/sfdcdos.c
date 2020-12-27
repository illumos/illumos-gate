/***********************************************************************
*                                                                      *
*               This software is part of the ast package               *
*          Copyright (c) 1985-2011 AT&T Intellectual Property          *
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
*                   Phong Vo <kpv@research.att.com>                    *
*                                                                      *
***********************************************************************/
#include	"sfdchdr.h"

/*	Discipline to turn \r\n into \n.
**	This is useful to deal with DOS text files.
**
**	Written by David Korn (03/18/1998).
*/

#define MINMAP	8
#define CHUNK	1024

struct map
{
	Sfoff_t	logical;
	Sfoff_t	physical;
};

typedef struct _dosdisc
{
	Sfdisc_t	disc;
	struct map	*maptable;
	int		mapsize;
	int		maptop;
	Sfoff_t		lhere;
	Sfoff_t		llast;
	Sfoff_t		lmax;
	Sfoff_t		pmax;
	Sfoff_t		phere;
	Sfoff_t		plast;
	Sfoff_t		begin;
	int		skip;
	void		*buff;
	char		last;
	char		extra;
	int		bsize;
} Dosdisc_t;

#if __STD_C
static void addmapping(register Dosdisc_t *dp)
#else
static void addmapping(dp)
register Dosdisc_t *dp;
#endif
{
	register int n;
	if((n=dp->maptop++)>=dp->mapsize)
	{
		dp->mapsize *= 2;
		if(!(dp->maptable=(struct map*)realloc((void*)dp->maptable,(dp->mapsize+1)*sizeof(struct map))))
		{
			dp->maptop--;
			dp->mapsize *= 2;
			return;
		}
	}
	dp->maptable[n].physical = dp->phere;
	dp->maptable[n].logical = dp->lhere;
	dp->maptable[dp->maptop].logical=0;
}

#if __STD_C
static struct map *getmapping(Dosdisc_t *dp, Sfoff_t offset, register int whence)
#else
static struct map *getmapping(dp, offset, whence)
Dosdisc_t *dp;
Sfoff_t offset;
register int whence;
#endif
{
	register struct map *mp;
	static struct map dummy;
	if(offset <= dp->begin)
	{
		dummy.logical = dummy.physical = offset;
		return(&dummy);
	}
	if(!(mp=dp->maptable))
	{
		dummy.logical = dp->begin;
		dummy.physical = dummy.logical+1;
		return(&dummy);
	}
	while((++mp)->logical && (whence==SEEK_CUR?mp->physical:mp->logical) <= offset);
	return(mp-1);
}

#if __STD_C
static ssize_t dos_read(Sfio_t *iop, void *buff, size_t size, Sfdisc_t* disc)
#else
static ssize_t dos_read(iop, buff, size, disc)
Sfio_t *iop;
void *buff;
size_t size;
Sfdisc_t* disc;
#endif
{
	register Dosdisc_t *dp = (Dosdisc_t*)disc;
	register char *cp = (char*)buff, *first, *cpmax;
	register int n, count, m;
	if(dp->extra)
	{
		dp->extra=0;
		*cp = dp->last;
		return(1);
	}
	while(1)
	{
		if((n = sfrd(iop,buff,size,disc)) <= 0)
			return(n);
		dp->plast=dp->phere;
		dp->phere +=n;
		dp->llast = dp->lhere;
		cpmax = cp+n-1;
		if(dp->last=='\r' && *cp!='\n')
		{
			/* should insert a '\r' */ ;
		}
		dp->last = *cpmax;
		if(n>1)
			break;
		if(dp->last!='\r')
		{
			dp->lhere++;
			return(1);
		}
	}
	if(dp->last=='\r')
		n--;
	else if(dp->last!='\n' || cpmax[-1]!='\r')
		*cpmax = '\r';
	dp->lhere += n;
	while(1)
	{
		while(*cp++ != '\r');
		if(cp > cpmax || *cp=='\n')
			break;
	}
	dp->skip = cp-1 - (char*)buff;
	/* if not \r\n in buffer, just return */
	if((count = cpmax+1-cp) <=0)
	{
		*cpmax = dp->last;
		if(!dp->maptable)
			dp->begin +=n;
		dp->skip++;
		count=0;
		goto done;
	}
	if(!dp->maptable)
	{
		dp->begin += cp - (char*)buff-1;
		if(dp->maptable=(struct map*)malloc((MINMAP+1)*sizeof(struct map)))
		{
			dp->mapsize = MINMAP;
			dp->maptable[0].logical=  dp->begin;
			dp->maptable[0].physical = dp->maptable[0].logical+1;
			dp->maptable[1].logical=0;
			dp->maptop = 1;
		}
	}
	/* save original discipline inside buffer */
	if(count>dp->bsize)
	{
		if(dp->bsize==0)
			dp->buff = malloc(count);
		else
			dp->buff = realloc(dp->buff,count);
		dp->bsize = count;
		if(!dp->buff)
			return(-1);
	}
	memcpy(dp->buff, cp, count);
	count=1;
	while(1)
	{
		first=cp;
		if(cp==cpmax)
			cp++;
		else
			while(*cp++ != '\r');
		if(cp<=cpmax && *cp!='\n')
			continue;
		if((m=(cp-first)-1) >0)
			memcpy(first-count, first, m);
		if(cp > cpmax)
			break;
		count++;
	}
	cpmax[-count] = dp->last;
	dp->lhere -= count;
done:
	if(dp->lhere>dp->lmax)
	{
		dp->lmax = dp->lhere;
		dp->pmax = dp->phere;
		if(dp->maptable && dp->lmax > dp->maptable[dp->maptop-1].logical+CHUNK)
			addmapping(dp);
	}
	return(n-count);
}

/*
 * returns the current offset
 * <offset> must be in the current buffer
 * if <whence> is SEEK_CUR, physical offset converted to logical offset
 *  otherwise, logical offset is converted to physical offset
 */
#if __STD_C
static Sfoff_t cur_offset(Dosdisc_t *dp, Sfoff_t offset,Sfio_t *iop,register int whence)
#else
static Sfoff_t cur_offset(dp, offset, iop, whence)
Dosdisc_t *dp;
Sfoff_t offset;
Sfio_t *iop;
register int whence;
#endif
{
	register Sfoff_t n,m=0;
	register char *cp;

	if(whence==SEEK_CUR)
	{
		whence= -1;
		n = offset - dp->plast;
		iop->next = iop->data + n;
		offset =  dp->llast;
	}
	else
	{
		whence = 1;
		n = offset - dp->llast;
		offset = dp->plast;
	}
	offset +=n;
	if((n -= dp->skip) > 0)
	{
		m=whence;
		cp = (char*)dp->buff;
		while(n--)
		{
			if(*cp++=='\r' && *cp=='\n')
			{
				m += whence;
				if(whence>0)
					n++;
			}
		}
	}
	if(whence<0)
		iop->next += m;
	return(offset+m);
}

#if __STD_C
static Sfoff_t dos_seek(Sfio_t *iop, Sfoff_t offset, register int whence, Sfdisc_t* disc)
#else
static Sfoff_t dos_seek(iop, offset, whence, disc)
Sfio_t *iop;
Sfoff_t offset;
register int whence;
Sfdisc_t* disc;
#endif
{
	register Dosdisc_t *dp = (Dosdisc_t*)disc;
	struct map dummy, *mp=0;
	Sfoff_t physical;
	register int n,size;
retry:
	switch(whence)
	{
	    case SEEK_CUR:
		offset = sfsk(iop, (Sfoff_t)0,SEEK_CUR,disc);
		if(offset<=dp->begin)
			return(offset);
		/* check for seek outside buffer */
		if(offset==dp->phere)
			return(dp->lhere);
		else if(offset==dp->plast)
			return(dp->llast);
		else if(offset<dp->plast || offset>dp->phere)
			mp = getmapping(dp,offset,whence);
		break;
	    case SEEK_SET:
		/* check for seek outside buffer */
		if(offset<dp->llast || offset > dp->lhere)
			mp = getmapping(dp,offset,whence);
		break;
	    case SEEK_END:
		if(!dp->maptable)
			return(sfsk(iop,offset,SEEK_END,disc));
		mp = &dummy;
		mp->physical = dp->plast;
		mp->logical = dp->llast;
		break;
	}
	if(sfsetbuf(iop,(char*)iop,0))
		size = sfvalue(iop);
	else
		size = iop->endb-iop->data;
	if(mp)
	{
		sfsk(iop,mp->physical,SEEK_SET,disc);
		dp->phere = mp->physical;
		dp->lhere = mp->logical;
		if((*disc->readf)(iop,iop->data,size,disc)<0)
			return(-1);
	}
	while(1)
	{
		if(whence==SEEK_CUR && dp->phere>=offset)
			break;
		if(whence==SEEK_SET && dp->lhere>=offset)
			break;
		n=(*disc->readf)(iop,iop->data,size,disc);
		if(n < 0)
			return(-1);
		if(n==0)
		{
			if(whence==SEEK_END && offset<0)
			{
				offset = dp->lhere;
				whence=SEEK_SET;
				goto retry;
			}
			break;
		}
	}
	if(whence==SEEK_END)
		offset += dp->lhere;
	else
	{
		physical = cur_offset(dp,offset,iop,whence);
		if(whence==SEEK_SET)
		{
			sfsk(iop, physical ,SEEK_SET,disc);
			dp->phere = physical;
			dp->lhere = offset;
		}
		else
			offset = physical;
	}
	return(offset);
}

#if __STD_C
static int dos_except(Sfio_t *iop, int type, void *arg, Sfdisc_t *disc)
#else
static int dos_except(iop, type, arg, disc)
Sfio_t *iop;
int type;
void *arg;
Sfdisc_t *disc;
#endif
{
	register Dosdisc_t *dp = (Dosdisc_t*)disc;
	if(type==SF_DPOP || type==SF_FINAL)
	{
		if(dp->bsize>0)
			free((void*)dp->buff);
		if(dp->mapsize)
			free((void*)dp->maptable);
		free((void*)disc);
	}
	return(0);
}

#if __STD_C
int sfdcdos(Sfio_t *f)
#else
int sfdcdos(f)
Sfio_t *f;
#endif
{
	Dosdisc_t *dos;

	/* this is a readonly discipline */
	if(sfset(f,0,0)&SF_WRITE)
		return(-1);

	if(!(dos = (Dosdisc_t*)malloc(sizeof(Dosdisc_t))) )
		return -1;
	memset(dos,'\0',sizeof(Dosdisc_t));

	dos->disc.readf = dos_read;
	dos->disc.writef = NIL(Sfwrite_f);
	dos->disc.seekf = dos_seek;
	dos->disc.exceptf = dos_except;

	if(sfdisc(f,(Sfdisc_t*)dos) != (Sfdisc_t*)dos)
	{	free(dos);
		return -1;
	}

	return(0);
}
