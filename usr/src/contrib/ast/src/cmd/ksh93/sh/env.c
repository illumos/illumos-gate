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

#include	<ast.h>
#include	<cdt.h>

#define	env_change()		(++ast.env_serial)

typedef struct _venv_ Evar_t;
struct _venv_
{
	union
	{
		Evar_t		*next;
		char		*ptr;
	}	un;
	Dtlink_t	link;
	int		index;
};

typedef  struct _env_
{
	Dt_t	*dt;
	Evar_t	*freelist;
	char	**env;
	int	count;
	int	extra;
	int	max;
	int	flags;
} Env_t;

#define _BLD_env	1
#include	<env.h>

#define ENV_VALID	2		/* set if env is valid */
#define ENV_PMALLOC	1		/* set if Evar_t->un.ptr  *s malloced */
#define ENV_VMALLOC	2		/* set of Evar_t was malloced */
#define ENV_BITS	3

/*
 * Compares the name portion of name=... only.
 */
static int compare(Dt_t *dt, Void_t* key1, Void_t* key2, Dtdisc_t* disc)
{
	register int c,d;
	const unsigned char *s1=(unsigned const char*)key1;
	const unsigned char *s2=(unsigned const char*)key2; 
	while((c= *s1++) && c!='=' && c==*s2) 
		s2++;
	if(c=='=')
		c = 0;
	if((d=*s2)=='=')
		d = 0;
	return(c-d);
}

static Dtdisc_t env_disc =
{
	0, -1,
	sizeof(char*),
	0,
	0,
	compare
};

/*
 *  return a pointer to the environment in sorted order
 *  NULL is returned if there if there is nospace
 */
char **env_get(Env_t* ep)
{
	register Evar_t *vp;
	register int n=ep->extra;
	if(ep->flags&ENV_VALID)
		return(ep->env+n);
	if(ep->count > ep->max)
	{
		if(ep->flags&ENV_MALLOCED)
			free((void*)ep->env);
		if(!(ep->env = (char**)malloc(sizeof(char*)*(ep->count+1))))
			return(0);
		ep->flags |= ENV_MALLOCED;
		ep->max = ep->count;
	}
	for(vp=(Evar_t*)dtfirst(ep->dt);vp; vp=(Evar_t*)dtnext(ep->dt,vp))
	{
		vp->index = (n<<ENV_BITS) | (vp->index&((1<<ENV_BITS)-1));
		ep->env[n++] = vp->un.ptr;
	}
	ep->env[n] = 0;
	ep->flags |= ENV_VALID;
	environ = ep->env+ep->extra;
	return(ep->env+ep->extra);
}

/*
 *  add name=value pair given by <str> to <ep>
 *  if malloced is set, the variable will be freed when reassigned
 *  The environment list may become invalidated
 *  Returns 1 for success, 0 for failure
 */
int env_add(Env_t *ep, const char *str, int flags)
{
	Evar_t *vp = (Evar_t*)dtmatch(ep->dt,(void*)str);
	if(vp && strcmp(str,vp->un.ptr)==0)
		return(1);
	if(flags&ENV_STRDUP)
		str = strdup(str);
	if(vp)
	{
		if(vp->index&ENV_PMALLOC)
			free((void*)vp->un.ptr);
		vp->un.ptr = (char*)str;
		if(ep->env && (ep->flags&ENV_VALID))
			ep->env[vp->index>>ENV_BITS] = vp->un.ptr;
	}
	else
	{
		ep->flags &= ~ENV_VALID;
		if(vp = ep->freelist)
			ep->freelist = vp->un.next;
		else if(vp = newof((Evar_t*)0,Evar_t,2,0))
		{
			vp->index = ENV_VMALLOC;
			ep->freelist = (vp+1);
			ep->freelist->un.next = 0;
		}
		else
			return(0);
		vp->un.ptr = (void*)str;
		if(!(vp=dtinsert(ep->dt,vp)))
			return(0);
		ep->count++;
	}
	if(flags)
		vp->index |= ENV_PMALLOC;
	else
		vp->index &= ~ENV_PMALLOC;
	env_change();
	return(1);
}

/*
 *  delete name  from <ep>
 *  The environment list may become invalidated
 *  Returns 1 for success, 0 for if name is not present 
 */
int env_delete(Env_t *ep, const char *str)
{
	Evar_t *vp = (Evar_t*)dtmatch(ep->dt,(void*)str);
	if(!vp)
		return(0);
	ep->flags &= ~ENV_VALID;
	if(vp->index&ENV_PMALLOC)
		free((void*)vp->un.ptr);
	dtdelete(ep->dt,vp);
	vp->un.next = ep->freelist;
	ep->freelist = vp;
	env_change();
	return(1);
}

/*
 * open up a structure to support environment variables
 * initialize with environment give by <envp>
 * If <extra> > 0, <extra> slots will be left at beginning of
 *    environment list when env_get() is involed.
 * If <extra>==ENV_USABLE, then the original environ can be
 *   used and returned.  Otherwise, a new one will be returned
 */
Env_t *env_open(char **envp, int extra)
{
	char **env;
	Env_t *ep;
	Evar_t *vp;
	int n=2;
	if(!(ep = newof((Env_t*)0,Env_t,1,0)))
		return(0);
	if(!(ep->dt = dtopen(&env_disc,Dtoset)))
		return(0);
	if(env=envp)
	{
		while(*env++);
		n = (env+2)-envp;
	}
	if(extra==ENV_STABLE)
	{
		ep->env = envp;
		ep->max = n-1;
	}
	else
		ep->count = ep->extra = extra;
	ep->freelist = vp = newof((Evar_t*)0,Evar_t,n,0);
	vp->index = ENV_VMALLOC;
	while(--n>0)
	{
		vp->un.next = (vp+1);
		vp++;
	}
	vp->un.next = 0;
	if(env)
	{
		for(env=envp; *env; env++)
			env_add(ep,*env,0);
	}
	return(ep);
}

/*
 * close <ep> and free up all space used by it
 */
void env_close(Env_t *ep)
{
	Evar_t *vp, *vpnext,*top;
	if(ep->env && (ep->flags&ENV_MALLOCED))
		free((void*)ep->env);
	for(vp=(Evar_t*)dtfirst(ep->dt);vp; vp=vpnext)
	{
		vpnext = (Evar_t*)dtnext(ep->dt,vp);
		env_delete(ep,vp->un.ptr);
	}
	for(top=0,vp = ep->freelist; vp; vp = vpnext)
	{
		vpnext = vp->un.next;
		if(vp->index&ENV_VMALLOC)
		{
			vp->un.next = top;
			top = vp;
		}
	}
	for(vp=top; vp; vp = vpnext)
	{
		vpnext = vp->un.next;
		free((void*)vp);
	}
	dtclose(ep->dt);
}
