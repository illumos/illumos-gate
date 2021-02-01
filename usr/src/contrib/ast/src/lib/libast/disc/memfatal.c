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
 * install error message handler for fatal malloc exceptions
 */

#include <ast.h>
#include <error.h>
#include <vmalloc.h>

#include "FEATURE/vmalloc"

#if _std_malloc

void
memfatal(void)
{
}

#else

/*
 * print message and fail on VM_BADADDR,VM_NOMEM
 */

static int
nomalloc(Vmalloc_t* region, int type, void* obj, Vmdisc_t* disc)
{
	Vmstat_t	st;

	NoP(disc);
	switch (type)
	{
#ifdef VM_BADADDR
	case VM_BADADDR:
		error(ERROR_SYSTEM|3, "invalid pointer %p passed to free or realloc", obj);
		return(-1);
#endif
	case VM_NOMEM:
		vmstat(region, &st);
		error(ERROR_SYSTEM|3, "storage allocator out of space on %lu byte request ( region %lu segments %lu busy %lu:%lu:%lu free %lu:%lu:%lu )", (size_t)obj, st.extent, st.n_seg, st.n_busy, st.s_busy, st.m_busy, st.n_free, st.s_free, st.m_free);
		return(-1);
	}
	return(0);
}

/*
 * initialize the malloc exception handler
 */

void
memfatal(void)
{
	Vmdisc_t*	disc;

	malloc(0);
	if (disc = vmdisc(Vmregion, NiL))
		disc->exceptf = nomalloc;
}

#endif
