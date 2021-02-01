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
 * standalone mini vmalloc implementation
 * no resize, no free, no disciplines, no methods
 */

#include <ast.h>
#include <vmalloc.h>

Vmalloc_t*	Vmregion;

Vmalloc_t*
_vm_open(void)
{
	Vmalloc_t*	vp;

	if (vp = newof(0, Vmalloc_t, 1, 0))
	{
		vp->current = &vp->base;
		vp->data = vp->current->data;
		vp->size = sizeof(vp->current->data);
	}
	return vp;
}

int
_vm_close(register Vmalloc_t* vp)
{
	register Vmchunk_t*	cp;
	register Vmchunk_t*	np;

	if (!vp)
		return -1;
	np = vp->base.next;
	while (cp = np)
	{
		np = cp->next;
		free(cp);
	}
	free(vp);
	return 0;
}

void*
_vm_resize(register Vmalloc_t* vp, void* o, unsigned long size)
{
	char*		p;
	unsigned long	n;
	unsigned long	z;

	z = vp->last;
	vp->last = size;
	if (o && size < z)
		return o;
	if ((o ? (size - z) : size) > vp->size)
	{
		n = (size > sizeof(vp->current->data)) ? (size - sizeof(vp->current->data)) : 0;
		if (!(vp->current->next = newof(0, Vmchunk_t, 1, n)))
			return 0;
		vp->current = vp->current->next;
		vp->data = vp->current->data;
		vp->size = n ? 0 : sizeof(vp->current->data);
		if (o)
		{
			memcpy(vp->data, o, z);
			o = (void*)vp->data;
		}
	}
	else if (o)
		size -= z;
	p = vp->data;
	size = roundof(size, VM_ALIGN);
	if (size >= vp->size)
		vp->size = 0;
	else
	{
		vp->size -= size;
		vp->data += size;
	}
	return p;
}
