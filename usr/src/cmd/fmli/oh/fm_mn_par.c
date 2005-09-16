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
#include	"wish.h"
#include	"token.h"
#include	"actrec.h"
#include	"fm_mn_par.h"
#include	"var_arrays.h"
#include	"terror.h"
#include	"eval.h"
#include	"vtdefs.h"
#include	"moremacros.h"

/*
** Frees one attribute.  This involves freeing the "def" if set,
** and the "cur" as an array if the flags say so, or as a string
** if set.
*/
void
freeattr(attr)
register struct attribute *attr;
{
    if (attr->flags & FREEIT) {
	if (attr->def) {
	    free(attr->def);
	    attr->def = (char *)NULL;
	}
	if (attr->cur) {
	    if (((attr->flags & RETS) == RET_LIST) ||
		((attr->flags & RETS) == RET_ARGS))
		   listfree(attr->cur);
	    else {
		   free(attr->cur);
		   attr->cur = (char *)NULL;
	    }
	}
	free(attr);
    }
}

/*
** If the "single" array is NULL then this structure does
** not contain any data to be freed
*/
void
freeitup(fm_mn)
register struct fm_mn *fm_mn;
{
    register int i, j;
    int	lcv, lcv2;

    if (fm_mn->single.attrs == NULL)
	return;
    lcv = array_len(fm_mn->single.attrs);
    for (i = 0; i < lcv; i++)
	freeattr(fm_mn->single.attrs[i]);
    array_destroy(fm_mn->single.attrs);
    fm_mn->single.attrs = NULL;
    if (!fm_mn->multi)
	return;
    lcv = array_len(fm_mn->multi);
    for (j = 0; j < lcv; j++)
	if (fm_mn->multi[j].attrs) {
	    lcv2 = array_len(fm_mn->multi[j].attrs);
	    for (i = 0; i < lcv2; i++)
		freeattr(fm_mn->multi[j].attrs[i]);
	    array_destroy(fm_mn->multi[j].attrs);
	}
    array_destroy(fm_mn->multi);
    fm_mn->multi = NULL;
}

/*
** Fills an array with the information from another (in this case, 
** the array of defaults.
*/
void
filldef(fld, defaults, no)
struct fld *fld;
struct attribute *defaults;
int no;
{
    int i;
    struct attribute *p;

    fld->attrs = (struct attribute **)
	array_create(sizeof(struct attribute *), no);

    for (i = 0; i < no; i++)
    {
	if (defaults[i].flags & MAKE_COPY)
	{
	    p = (struct attribute *)new(struct attribute);
	    *p = defaults[i];
	    if(defaults[i].def != NULL)     /* abs k14.1 */
	    {
		p->def = malloc(strlen(defaults[i].def)+1);
		if(p->def == NULL)
		{
		    fatal(NOMEM, nil);
		}
		strcpy(p->def, defaults[i].def);
	    }
	    p->flags |= FREEIT;
	}
	else
	    p = defaults + i;
	fld->attrs = (struct attribute **) array_append(fld->attrs, &p);
    }
}

/*
** Boosts a the sequence number for the whole object.  This will
** force every variable field to be evaluated.
*/
int
upseqno(fm_mn)
struct fm_mn *fm_mn;
{
    fm_mn->seqno++;
    return (0);
}

/*
** This parses an object.  The "flags" say whether info_or_file is 
** the information itself or the file of where the information sits.
** Sdfl, sdflsize, mdfl and mdflsize describe the default arrays and
** single and multi are the addresses of pointers to store the
** information in.
*/
int
parser(flags, info_or_file, sdfl, sdflsize, single, mdfl, mdflsize, multi, fp)
int flags;
char *info_or_file;
struct attribute *sdfl;
int sdflsize;
struct fld *single;
struct attribute *mdfl;
int mdflsize;
struct fld **multi;
FILE *fp;
{
    int i;
    register char *val, *kwd;
    char mybuf[BUFSIZ];
    int more;
    IOSTRUCT *in, *out;
    struct fld *multiptr, ptr;

    if (flags & INLINE) 
	in = io_open(EV_USE_STRING, info_or_file);
    else
    {
	setbuf(fp, mybuf);
	in = io_open(EV_USE_FP, fp);
    }
    out = io_open(EV_USE_STRING, NULL);
    while (more = eval(in, out, EV_GROUP))
    {
	kwd = io_ret_string(out);
	if (val = strchr(kwd, '='))
	    *val++ = '\0';
	else
	    val = nil;
	for (i = 0; i < sdflsize; i++)
	    if (strCcmp(kwd, sdfl[i].testring) == 0)
		break;
	if (i == sdflsize)
	{
	    if (strCcmp(kwd, mdfl[PAR_NAME].testring) == 0)
		break;
	}
	else
	{
	    struct attribute *hold;

	    hold = (struct attribute *)new(struct attribute);
	    memcpy(hold, single->attrs[i], sizeof(struct attribute));
	    hold->flags |= FREEIT;
	    hold->cur = NULL;
	    hold->seqno = 0;
	    set_def(single->attrs[i] = hold, strsave(val));
	}
	io_seek(out, 0);
    }

    multiptr = (struct fld *) array_create(sizeof(struct fld), 1024);
    for ( ; more; more = eval(in, out, EV_GROUP))
    {
	if (!kwd)
	{
	    kwd = io_ret_string(out);
	    if (val = strchr(kwd, '='))
		*val++ = '\0';
	    else
		val = nil;
	}
	for (i = 0; i < mdflsize; i++)
	    if (strCcmp(kwd, mdfl[i].testring) == 0)
		break;
	if (i == PAR_NAME) 	/* if its the first multi-descriptor */
	{
	    filldef(&ptr, mdfl, mdflsize);
	    multiptr = (struct fld *) array_append(multiptr, &ptr);
	}
	if (i != mdflsize) 	/* if its the one we're looking for */
	{
	    struct attribute *hold;

	    hold = (struct attribute *)new(struct attribute);
	    memcpy(hold, ptr.attrs[i], sizeof(struct attribute));
	    hold->flags |= FREEIT;
	    hold->cur = NULL;
	    hold->seqno = 0;
	    /* don't comment out until you're SURE 
	       if (mdfl[i].flags & MAKE_COPY)
	       free(ptr.attrs[i]);
	       */
	    set_def(ptr.attrs[i] = hold, strsave(val));
	}
	io_seek(out, 0);
	kwd = NULL;
    }
    multiptr = (struct fld *) array_shrink(multiptr);
    *multi = multiptr;
    io_close(out);
    io_close(in);
    return (0);
}

/*
** This puts the args into an altenv ($ARG1, $ARG2 and $ARG3)
*/
void
setupenv(flags, args, altenv)
int flags;
register char **args;
register char ***altenv;
{
    char buf[BUFSIZ];
    char argbuf[6];
    char *envbuf;
    register int i;

    strcpy(argbuf, "ARG1=");
    for (i = flags & INLINE ? 2 : 1; args[i]; i++, (argbuf[3])++) {
	int dofree, maxamt, amt;

	dofree = 0;
	maxamt = BUFSIZ - sizeof(argbuf) - 2;
	if ((amt = strlen(args[i])) > maxamt) { 
	    /*
	     * Value is greater than 1K so malloc 
	     * enough space to hold it. 
	     */
	    maxamt = amt + sizeof(argbuf) + 2;
	    if ((envbuf = (char *) malloc(maxamt)) == NULL)
		fatal(NOMEM, nil); 
	    dofree++;
	}
	else {
	    /*
	     * ... otherwise, use static 1K buffer
	     */
	    envbuf = buf;
	    dofree = 0;
	}
	strcpy(envbuf, argbuf);
	strncat(envbuf, args[i], maxamt);
	putaltenv(altenv, envbuf);
	if (dofree)		/* if buffer was malloc'd, free it */
	    free(envbuf);
    }
    argbuf[4] = '\0';
    while(delAltenv(argbuf) == SUCCESS)
	(argbuf[3])++;
    copyAltenv(*altenv);
}

/*
** This will setup the lifetime and positioning for an object.
*/
void
life_and_pos(a, life, begrow, begcol, prow, pcol, ptype)
register struct actrec *a;
register char *life;
register char *begrow;
register char *begcol;
int *prow;
int *pcol;
int *ptype;
{
    void setlifetime();

    *prow = VT_UNDEFINED;
    *pcol = VT_UNDEFINED;
    *ptype = 0;
    if (strCcmp(begrow, "center") == 0) {
	*ptype = VT_CENTER;
	if (!(*pcol = atoi(begcol)))
	    *pcol = VT_UNDEFINED;
    }
    else if (strCcmp(begcol, "center") == 0) {
	*ptype = VT_CENTER;
	if (!(*prow = atoi(begrow)))
	    *prow = VT_UNDEFINED;
    }
    else if (strCcmp(begrow, "current") == 0)
	*ptype = VT_COVERCUR;
    else if (strCcmp(begrow, "distinct") == 0)
	*ptype = VT_NOCOVERCUR;
    else {
	if (!(*prow = atoi(begrow))) {
	    *prow = VT_UNDEFINED;
	    *pcol = VT_UNDEFINED;
	}
	else {
	    if (!(*pcol = atoi(begcol)))
	        *pcol = VT_UNDEFINED;
	}
    }
    if (life) 
	setlifetime(a, life);
}

void
setlifetime(a, life)
struct actrec *a;
char *life;
{
    /* Added a check for a->id to be >= 0 for an active frame.  mek 112289 */
    if (a->id >= 0 && a->lifetime == AR_CLOSING) /* abs k17 */
	return;			   /* abs k17 */
    if (strCcmp(life, "shortterm") == 0)
	a->lifetime = AR_SHORTERM;
    else if (strCcmp(life, "permanent") == 0)
	a->lifetime = AR_PERMANENT;
    else if (strCcmp(life, "immortal") == 0)
	a->lifetime = AR_IMMORTAL;
    else
	a->lifetime = AR_LONGTERM;
}
