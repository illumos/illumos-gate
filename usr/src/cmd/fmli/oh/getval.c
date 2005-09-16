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
/*
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include	<stdio.h>
#include	<string.h>
#include	<sys/types.h>
#include	<sys/stat.h>
#include	<ctype.h>
#include        <signal.h>
#include        <curses.h>
#include	"wish.h"
#include	"token.h"
#include	"winp.h"
#include	"form.h"
#include	"fm_mn_par.h"
#include	"objform.h"
#include	"var_arrays.h"
#include	"terror.h"
#include	"eval.h"
#include	"ctl.h"
#include 	"moremacros.h"
#include	"interrupt.h"


extern void intr_handler();
void part_expand();
void set_def();
extern int EV_retcode;


#define SKIPLINES TRUE
#define NONE 0
#define BQMODE 1
#define DQMODE 2

#define getac(fp, Q) ((fp) ? Getc(fp) : *(Q)++)
#define UNGetac(C, fp, Q) ((fp) ? unGetc((C), (fp)) : *(Q)--)
void evalattr();


/*
** Evaluate one of the single occurrence attributes.
*/

/* Les: replace with MACRO

char *
sing_eval(fm_mn, fldtype)
struct fm_mn *fm_mn;
int fldtype;
{
	char *fld_eval();

	return(fld_eval(&fm_mn->single, fldtype, fm_mn->seqno));
}
*/

/*
** Evaluate one of the multi-occurrence attributes.
*/

/* Les: replace with 1 line function

char *
multi_eval(fm_mn, fldno, fldtype)
struct fm_mn *fm_mn;
int fldno, fldtype;
{
	char *fld_eval();

	return(fld_eval(fm_mn->multi + fldno, fldtype, fm_mn->seqno));
}
*/

/*
** Evaluate one attribute based on a seqno.
*/
/* only called within this file */
char *
fld_eval(fld, fldtype, seqno)
struct fld *fld;
int fldtype;
int seqno;
{
	char  *eval_string();
	struct attribute *attr, *tmp_attr;
	char  *intr, *onintr;
	int    flags;
	
/*	if this type of descriptor can ever be interrupted, then
 	update the interrupt structures based on the values for the
	current field, if defined else with the inherited values 
	If interrupts are suppose to be enabled, set up the
	interrupt handler.
*/
	Cur_intr.skip_eval =  FALSE;
	if (fld == (struct fld *)NULL)
		return (char *)NULL;
	attr = fld->attrs[fldtype];
        if (strcmp(attr->testring, "action") == 0 ||
	    strcmp(attr->testring, "done")   == 0)
	{
	    tmp_attr = fld->attrs[PAR_INTR];
	    if ((intr = tmp_attr->def) == NULL)
		intr = (char *)ar_ctl(AR_cur, CTGETINTR, NULL, NULL, NULL, NULL, NULL, NULL);
	    flags = RET_BOOL;
	    Cur_intr.interrupt = FALSE;	/* dont interrupt eval of intr */
	    Cur_intr.interrupt = (bool)(uintptr_t)eval_string(intr, &flags);

	    tmp_attr = fld->attrs[PAR_ONINTR];
	    if ((onintr = tmp_attr->def) == NULL)
		onintr = (char *)ar_ctl(AR_cur, CTGETONINTR, NULL, NULL, NULL, NULL, NULL, NULL);
	    Cur_intr.oninterrupt = onintr;
	}


/*
 * Decides whether to re_evaluate the attribute.
 */

	if (!(((attr->flags & EVAL_ONCE) && attr->seqno) ||
	   ((attr->flags & EVAL_SOMETIMES) && (attr->seqno >= seqno))))
	{
		if ((attr->flags & FREEIT) && attr->cur)
		{
		    if (((attr->flags & RETS) == RET_LIST) ||
			((attr->flags & RETS) == RET_ARGS))
			listfree(attr->cur);
		    else
			free(attr->cur);
		    attr->cur = NULL;
		}
		attr->cur = eval_string(attr->def, &attr->flags);
		attr->seqno = seqno;
	}

	return(attr->cur);
}

/*
** Forces reevaluation of current value for an attribute.
*/
void
de_const(fm_mn, fldno, fldtype)
struct fm_mn *fm_mn;
int fldno, fldtype;
{
	fm_mn->multi[fldno].attrs[fldtype]->seqno = 0;
}
	
/*
 * SET_SINGLE_DEFAULT will generate a new attribute structure
 * and set the "def" portion of the structure to "val" ...
 * (NOTE that the string passed is "strsaved" thus can/should be
 * static)
 */
int
set_single_default(fm, index, val)	
struct fm_mn *fm;
int index;
char *val;
{
	struct fld *single;
	struct attribute *hold;
	struct attribute *attr;

	if ((int)fm->single.attrs == 0)	/* abs k17 */
	    return(FAIL);		/* abs k17 */
	single = &fm->single;
	attr = single->attrs[index];
	hold = new(struct attribute);
	memcpy(hold, attr, sizeof(struct attribute));
	hold->flags |= FREEIT;
	hold->cur = NULL;
	hold->seqno = 0;
	if (attr->flags & FREEIT)
		freeattr(attr);		/* free old structure */
	set_def(single->attrs[index] = hold, strsave(val));
	return(SUCCESS);	/* abs k17 */
}

void
set_def(attr, str)
struct attribute *attr;
char *str;
{
	attr->def = str;
}

/*
** Set current value of an attribute (only used in "value" field of
** form).
*/
void
set_cur(fm_mn, fldno, fldtype, str)
register struct fm_mn *fm_mn;
register int fldno, fldtype;
char *str;
{
	struct attribute *attr;

	attr = fm_mn->multi[fldno].attrs[fldtype];
	if ((attr->flags & FREEIT) && attr->cur) {
		if (((attr->flags & RETS) == RET_LIST) ||
		    ((attr->flags & RETS) == RET_ARGS))
			listfree(attr->cur);
		else
			free(attr->cur);
	}
	attr->cur = str;
	attr->seqno = 1;
	attr->flags |= EVAL_ONCE;
}

/*
** Set current value of an attribute (only used in "text" objects) 
*/
void
set_sing_cur(fm_mn, desctype, str)
register struct fm_mn *fm_mn;
register int desctype;
char *str;
{
	struct attribute *attr;

	attr = fm_mn->single.attrs[desctype];
	if ((attr->flags & FREEIT) && attr->cur) {
		if (((attr->flags & RETS) == RET_LIST) ||
		    ((attr->flags & RETS) == RET_ARGS))
			listfree(attr->cur);
		else
			free(attr->cur);
	}
	attr->cur = str;
	attr->seqno = 1;
	attr->flags |= EVAL_ONCE;
}

/*
** Get default value of an multi-eval attribute
*/
char *
get_def(fm_mn, fldno, fldtype) 
register struct fm_mn *fm_mn;
register int fldno, fldtype;
{
	return(fm_mn->multi[fldno].attrs[fldtype]->def);
}



/*
** Get define value of an sing-eval attribute
*/
char *
get_sing_def(fm_mn, fldtype) 
register struct fm_mn *fm_mn;
register int fldtype;
{
	return(fm_mn->single.attrs[fldtype]->def);
}




/*
** Free a list of strings generated by parselist.
*/
int
listfree(list)
char **list;
{
	int i;
	int	lcv;

	if (!list)
		return (0);
	lcv = array_len(list);
	for (i = 0; i < lcv; i++)
		free(list[i]);
	array_destroy(list);
	return (0);
}
