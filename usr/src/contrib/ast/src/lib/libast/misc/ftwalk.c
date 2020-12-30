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
#pragma prototyped
/*
 * Glenn Fowler
 * AT&T Research
 *
 * ftwalk on top of fts
 */

#include <ast.h>
#include <ftwalk.h>

static struct
{
	int	(*comparf)(Ftw_t*, Ftw_t*);
} state;

/*
 * why does fts take FTSENT** instead of FTSENT*
 */

static int
ftscompare(Ftw_t* const* pf1, Ftw_t* const* pf2)
{
	return (*state.comparf)(*pf1, *pf2);
}

/*
 * the real thing -- well it used to be
 */

int
ftwalk(const char* path, int (*userf)(Ftw_t*), int flags, int (*comparf)(Ftw_t*, Ftw_t*))
{
	register FTS*		f;
	register FTSENT*	e;
	register int		children;
	register int		rv;
	int			oi;
	int			ns;
	int			os;
	int			nd;
	FTSENT*			x;
	FTSENT*			dd[2];

	flags ^= FTS_ONEPATH;
	if (flags & FTW_TWICE)
		flags &= ~(FTS_NOPREORDER|FTS_NOPOSTORDER);
	else if (flags & FTW_POST)
		flags |= FTS_NOPREORDER;
	else
		flags |= FTS_NOPOSTORDER;
	if (children = flags & FTW_CHILDREN)
		flags |= FTS_SEEDOT;
	state.comparf = comparf;
	if (!(f = fts_open((char* const*)path, flags, comparf ? ftscompare : 0)))
	{
		if (!path || !(flags & FTS_ONEPATH) && !(path = (const char*)(*((char**)path))))
			return -1;
		ns = strlen(path) + 1;
		if (!(e = newof(0, FTSENT, 1, ns)))
			return -1;
		e->fts_accpath = e->fts_name = e->fts_path = strcpy((char*)(e + 1), path);
		e->fts_namelen = e->fts_pathlen = ns;
		e->fts_info = FTS_NS;
		e->parent = e;
		e->parent->link = e;
		rv = (*userf)((Ftw_t*)e);
		free(e);
		return rv;
	}
	rv = 0;
	if (children && (e = fts_children(f, 0)))
	{
		nd = 0;
		for (x = e; x; x = x->link)
			if (x->info & FTS_DD)
			{
				x->statb = *x->fts_statp;
				x->info &= ~FTS_DD;
				dd[nd++] = x;
				if (nd >= elementsof(dd))
					break;
			}
		e->parent->link = e;
		rv = (*userf)((Ftw_t*)e->parent);
		e->parent->link = 0;
		while (nd > 0)
			dd[--nd]->info |= FTS_DD;
		for (x = e; x; x = x->link)
			if (!(x->info & FTS_D))
				x->status = FTS_SKIP;
	}
	while (!rv && (e = fts_read(f)))
	{
		oi = e->info;
		os = e->status;
		ns = e->status = e->path == e->fts_accpath ? FTW_PATH : FTW_NAME;
		nd = 0;
		switch (e->info)
		{
		case FTS_D:
		case FTS_DNX:
			if (children)
				for (x = fts_children(f, 0); x; x = x->link)
					if (x->info & FTS_DD)
					{
						x->statb = *x->fts_statp;
						x->info &= ~FTS_DD;
						dd[nd++] = x;
						if (nd >= elementsof(dd))
							break;
					}
			break;
		case FTS_DOT:
			continue;
		case FTS_ERR:
			e->info = FTS_NS;
			break;
		case FTS_NSOK:
			e->info = FTS_NSOK;
			break;
		case FTS_SLNONE:
			e->info = FTS_SL;
			break;
		}
		rv = (*userf)((Ftw_t*)e);
		e->info = oi;
		if (e->status == ns)
			e->status = os;
		while (nd > 0)
			dd[--nd]->info |= FTS_DD;
	}
	fts_close(f);
	return rv;
}
