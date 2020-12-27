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
#include	"dthdr.h"

/*	Close a dictionary
**
**	Written by Kiem-Phong Vo (11/15/2010)
*/
#if __STD_C
int dtclose(Dt_t* dt)
#else
int dtclose(dt)
Dt_t*	dt;
#endif
{
	int		ev, type;
	Dt_t		pdt;
	Dtdisc_t	*disc = dt->disc;

	if(!dt || dt->nview > 0 ) /* can't close if being viewed */
		return -1;

	if(disc && disc->eventf) /* announce closing event */
		ev = (*disc->eventf)(dt, DT_CLOSE, (Void_t*)1, disc);
	else	ev = 0;
	if(ev < 0) /* cannot close */
		return -1;

	if(dt->view) /* turn off viewing at this point */
		dtview(dt,NIL(Dt_t*));

	type = dt->data->type; /* save before memory is freed */
	memcpy(&pdt, dt, sizeof(Dt_t));

	if(ev == 0 ) /* release all allocated data */
	{	(void)(*(dt->meth->searchf))(dt,NIL(Void_t*),DT_CLEAR);
		(void)(*dt->meth->eventf)(dt, DT_CLOSE, (Void_t*)0);
		/**/DEBUG_ASSERT(!dt->data);
	}
	if(!(type&DT_INDATA) )
		(void)free(dt);

	if(disc && disc->eventf) /* announce end of closing activities */
		(void)(*disc->eventf)(&pdt, DT_ENDCLOSE, (Void_t*)0, disc);

	return 0;
}
