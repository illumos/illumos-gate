/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved  	*/


/*
 *      Copyright (c) 1997, by Sun Microsystems, Inc.
 *      All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*LINTLIBRARY*/

#include <sys/types.h>
#include <stdlib.h>
#include "utility.h"

typedef struct {
	char *leftarg;
	char *rightarg;
}
	LINK;

#define	ArgL(n)		(((LINK *)(n))->leftarg)
#define	ArgR(n)		(((LINK *)(n))->rightarg)

#define	Ref(t)		((t)->ref)
#define	TypeL(t)	((t)->left)
#define	TypeR(t)	((t)->right)
#define	MakeA(t)	((t)->makearg)
#define	CopyA(t)	((t)->copyarg)
#define	FreeA(t)	((t)->freearg)
#define	Fcheck(t)	((t)->fcheck)
#define	Ccheck(t)	((t)->ccheck)
#define	Next(t)		((t)->next)
#define	Prev(t)		((t)->prev)

	/*
	 *  default fieldtype
	 */

static FIELDTYPE default_fieldtype =
{
			0,			/* status	*/
			0,			/* ref		*/
			(FIELDTYPE *) 0,	/* left		*/
			(FIELDTYPE *) 0,	/* right	*/
			(PTF_charP) 0,		/* makearg	*/
			(PTF_charP) 0,		/* copyarg	*/
			(PTF_void) 0,		/* freearg	*/
			(PTF_int) 0,		/* fcheck	*/
			(PTF_int) 0,		/* ccheck	*/
			(PTF_int) 0,		/* next		*/
			(PTF_int) 0,		/* prev		*/
};

FIELDTYPE * _DEFAULT_FIELDTYPE	= &default_fieldtype;

/* new_fieldtype - field & character validation function */
FIELDTYPE *
new_fieldtype(PTF_int fcheck, PTF_int ccheck)
{
	FIELDTYPE *t = (FIELDTYPE *) 0;

	if ((fcheck || ccheck) && Alloc(t, FIELDTYPE)) {
		*t = *_DEFAULT_FIELDTYPE;

		Fcheck(t) = fcheck;
		Ccheck(t) = ccheck;
	}
	return (t);
}

FIELDTYPE *
link_fieldtype(FIELDTYPE *left, FIELDTYPE *right)
{
	FIELDTYPE *t = (FIELDTYPE *) 0;

	if ((left || right) && Alloc(t, FIELDTYPE)) {
		*t = *_DEFAULT_FIELDTYPE;

		Set(t, LINKED);

		if (Status(left, ARGS) || Status(right, ARGS))
			Set(t, ARGS);

		if (Status(left, CHOICE) || Status(right, CHOICE))
			Set(t, CHOICE);

		TypeL(t) = left;
		TypeR(t) = right;
		IncrType(left);	/* increment reference count */
		IncrType(right);	/* increment reference count */
	}
	return (t);
}

int
free_fieldtype(FIELDTYPE *t)
{
	if (!t)
		return (E_BAD_ARGUMENT);

	if (Ref(t))
		return (E_CONNECTED);

	if (Status(t, LINKED)) {
		DecrType(TypeL(t));	/* decrement reference count */
		DecrType(TypeR(t));	/* decrement reference count */
	}
	Free(t);
	return (E_OK);
}

int
set_fieldtype_arg(FIELDTYPE *t, PTF_charP makearg,
	PTF_charP copyarg, PTF_void freearg)
{
	if (t && makearg && copyarg && freearg) {
		Set(t, ARGS);
		MakeA(t) = makearg;
		CopyA(t) = copyarg;
		FreeA(t) = freearg;
		return (E_OK);
	}
	return (E_BAD_ARGUMENT);
}

/* set_fieldtype_choice next & prev choice function */
int
set_fieldtype_choice(FIELDTYPE *t, PTF_int next, PTF_int prev)
{
	if (t && next && prev) {
		Set(t, CHOICE);
		Next(t) = next;
		Prev(t) = prev;
		return (E_OK);
	}
	return (E_BAD_ARGUMENT);
}

char *
_makearg(FIELDTYPE *t, va_list *ap, int *err)
{
/*
 * invoke make_arg function associated with field type t.
 * return pointer to argument information or null if none.
 * increment err if an error is encountered.
 */
	char *p = (char *)0;

	if (! t || ! Status(t, ARGS))
		return (p);

	if (Status(t, LINKED)) {
		LINK *n = (LINK *) 0;

		if (Alloc(n, LINK)) {
			ArgL(n) = _makearg(TypeL(t), ap, err);
			ArgR(n) = _makearg(TypeR(t), ap, err);
			p = (char *)n;
		} else
			++(*err);		/* out of space */
	} else
		if (!(p = (*MakeA(t)) (ap)))
			++(*err);		/* make_arg had problem */
	return (p);
}

char *
_copyarg(FIELDTYPE *t, char *arg, int *err)
{
/*
 * invoke copy_arg function associated with field type t.
 * return pointer to argument information or null if none.
 * increment err if an error is encountered.
 */
	char *p = (char *)0;

	if (!t || !Status(t, ARGS))
		return (p);

	if (Status(t, LINKED)) {
		LINK *n = (LINK *) 0;

		if (Alloc(n, LINK)) {
			ArgL(n) = _copyarg(TypeL(t), ArgL(arg), err);
			ArgR(n) = _copyarg(TypeR(t), ArgR(arg), err);
			p = (char *)n;
		} else
			++(*err);		/* out of space */
	} else
		if (!(p = (*CopyA(t)) (arg)))
			++(*err);		/* copy_arg had problem */
	return (p);
}

/* _freearg - invoke free_arg function associated with field type t.  */
void
_freearg(FIELDTYPE *t, char *arg)
{
	if (!t || !Status(t, ARGS))
		return;

	if (Status(t, LINKED)) {
		_freearg(TypeL(t), ArgL(arg));
		_freearg(TypeR(t), ArgR(arg));
		Free(arg);
	} else
		(*FreeA(t)) (arg);
}

/* _checkfield - invoke check_field function associated with field type t.  */
int
_checkfield(FIELDTYPE *t, FIELD *f, char *arg)
{
	if (!t)
		return (TRUE);

	if (Opt(f, O_NULLOK)) {
		char *v = Buf(f);

		while (*v && *v == ' ')
			++v;
		if (!*v)
			return (TRUE);	/* empty field */
	}
	if (Status(t, LINKED))
		return	(_checkfield(TypeL(t), f, ArgL(arg)) ||
		    _checkfield(TypeR(t), f, ArgR(arg)));
	else
		if (Fcheck(t))
			return ((*Fcheck(t)) (f, arg));
	return (TRUE);
}

/* _checkchar - invoke check_char function associated with field type t.  */
int
_checkchar(FIELDTYPE *t, int c, char *arg)
{
	if (!t)
		return (TRUE);

	if (Status(t, LINKED))
		return	(_checkchar(TypeL(t), c, ArgL(arg)) ||
		    _checkchar(TypeR(t), c, ArgR(arg)));
	else
		if (Ccheck(t))
			return ((*Ccheck(t)) (c, arg));
	return (TRUE);
}

/* _nextchoice - invoke next_choice function associated with field type t.  */
int
_nextchoice(FIELDTYPE *t, FIELD *f, char *arg)
{
	if (!t || !Status(t, CHOICE))
		return (FALSE);

	if (Status(t, LINKED))
		return	(_nextchoice(TypeL(t), f, ArgL(arg)) ||
		    _nextchoice(TypeR(t), f, ArgR(arg)));
	else
		return ((*Next(t)) (f, arg));
}

/* _prevchoice - invoke prev_choice function associated with field type t. */
int
_prevchoice(FIELDTYPE *t, FIELD *f, char *arg)
{
	if (!t || !Status(t, CHOICE))
		return (FALSE);

	if (Status(t, LINKED))
		return	(_prevchoice(TypeL(t), f, ArgL(arg)) ||
		    _prevchoice(TypeR(t), f, ArgR(arg)));
	else
		return ((*Prev(t)) (f, arg));
}
