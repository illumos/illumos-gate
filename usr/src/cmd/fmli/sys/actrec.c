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

#include <stdio.h>
#include <sys/types.h>
#include "wish.h"
#include "token.h"
#include "slk.h"
#include "actrec.h"
#include "menudefs.h"
#include "ctl.h"
#include "terror.h"
#include "message.h"
#include "moremacros.h"

/* Functions for manipulating activation records */
static struct actrec *AR_head;
       struct actrec *AR_cur;
static int AR_serial = 0;

void ar_dump();
static void	ar_cur_end();

/* LES: becoming a MACRO

struct actrec *
ar_get_current()
{
	return(AR_cur);
}
*/

struct actrec *
ar_create(rec)
register struct actrec *rec;
{
	register struct actrec *newrec;
	register struct actrec	*ap;

	newrec = (struct actrec *)new(struct actrec);
	*newrec = *rec;
	newrec->serial = AR_serial++;

	/* link the new record right after the current record */

	if (AR_head == NULL) {
		/* nobody has been made yet, so make a degenerate list */
		AR_head = newrec;
		newrec->nextrec = newrec;
		newrec->prevrec = newrec;
		newrec->backup = newrec;
	}
	else {
		ap = (AR_cur ? AR_cur : AR_head);
		newrec->prevrec = ap;
		newrec->nextrec = ap->nextrec;
		newrec->backup = ap;
		ap->nextrec = newrec;
		newrec->nextrec->prevrec = newrec;
	}
	return(newrec);
}

struct actrec *
ar_reinit(rec)
register struct actrec *rec;
{
	struct actrec *ret;

	ret = (struct actrec *) arf_reinit(rec, rec);
	if (rec == AR_cur)
		ar_setslks(rec->slks, rec->flags & AR_ALTSLKS);
	return ret;
}

int
ar_reread(rec)
register struct actrec *rec;
{
	int ret;				   /* abs k15 */
	
	ret = arf_reread(rec, rec);
	if (rec == AR_cur && ret == SUCCESS)      /* abs k15 */
		ar_setslks(rec->slks, rec->flags & AR_ALTSLKS);
	return ret;
}

struct actrec *
ar_close(rec, logout)
register struct actrec *rec;
bool logout;
{
    register struct actrec	*ap;
    register struct actrec	*new_cur;
    struct actrec *ar_cur_prev();

    if (rec == NULL && ((rec = AR_cur) == NULL))
    {
	error(MUNGED, "NULL actrec");
	return(rec);
    }
    /* don't allow recursive closes! */
    if (rec->lifetime == AR_CLOSING) /* abs k17 */
	return(rec);		     /* abs k17 */

    /* re-evaluate lifetime - if immortal, don't close */
    if (rec->lifetime != AR_INITIAL)
	(void) ar_ctl(rec, CTSETLIFE, 0, NULL, NULL, NULL, NULL, NULL);
    if (rec->lifetime == AR_IMMORTAL ||
	rec->lifetime == AR_INITIAL)
    {
	mess_temp("Can't close this frame\n");
	return rec;
    }
    else
	rec->lifetime = AR_CLOSING; /* abs k17 */
    
    /* close the internals of the record */

    if (arf_close(rec, rec) == FAIL)
    {
	error(MUNGED, "can't close actrec");
	return(AR_cur);
    }

    /* if closing current record and not exiting fmli, choose a new one */
    if (rec == AR_cur && !logout)
	new_cur = AR_cur->backup;
    else {
	if ( logout )
	    AR_cur = AR_head;
	new_cur = NULL;
    }

    /* relink the lists */
    if (rec->nextrec == rec)
	AR_head = NULL;
    else
    {
	if (rec == AR_head)
	    AR_head = rec->prevrec;
	rec->nextrec->prevrec = rec->prevrec;
	rec->prevrec->nextrec = rec->nextrec;
	for (ap = AR_cur; ap; )
	{
	    if (ap->backup == rec)
	    {
		ap->backup = rec->backup;
		break;
	    }
	    if ((ap = ap->backup) == AR_cur)
	    {
		/* rec = NULL;  causes core dump.  abs k14 */
		break;
	    }
	}
    }
    if (new_cur == rec)
	AR_cur = NULL;
    else if (new_cur)
    {
	register struct actrec	*old_AR_cur;

	if (new_cur->lifetime == AR_CLOSING) 	/* abs k17 */
	    AR_cur = new_cur;			/* abs k17 */
	else					/* abs k17 */
	{
	    (void) arf_reinit(new_cur, new_cur);
	    old_AR_cur = AR_cur;
	    AR_cur = new_cur;
	    ar_cur_end(old_AR_cur);
	}
    }
#ifdef _DEBUG
    _debug(stderr, "FREEING ACTREC %x\n", rec);
#endif
    if (rec)
	free(rec);
#ifdef _DEBUG5
    ar_dump("AFTER ar_close");
#endif
    return AR_cur;
}

struct actrec *
ar_cur_next()
{
	register struct actrec	*ap;
	struct actrec *ar_current();

	for (ap = AR_cur->nextrec; ap && (ap->flags & AR_SKIP); ap = ap->nextrec)
		if (ap == AR_cur)
			break;
	if (ap != AR_cur)
		ap = ar_current(ap, TRUE); /* abs k15 */
	return ap;
}

struct actrec *
ar_cur_prev()
{
	register struct actrec	*ap;
	struct actrec *ar_current();

	for (ap = AR_cur->prevrec; ap && (ap->flags & AR_SKIP); ap = ap->prevrec)
		if (ap == AR_cur)
			break;
	if (ap != AR_cur)
		ap = ar_current(ap, TRUE); /* abs k15 */
	return ap;
}

/*
 * front end for ar_current and ar_backup
 * cleans up previously current actrec and calls reinit on new current one
 */
static void
ar_cur_front(ap, do_reinit)
register struct actrec	*ap;
bool do_reinit;
{
	/*
	 * if there is a current record, and that record is not the same
	 * as the one we are making current, then either close it or make
	 * it non-current, depending on its lifetime.
	 * (call ar_ctl with CTSETLIFE to determine whether
	 * the current object's "lifetime" has changed) 
	 * NOTE: lifetime can not change for initial objects
	 */
	if (AR_cur && AR_cur != ap) {
/* bug 1138884 - this code is not in the SVR3 version so...
		if (AR_cur->lifetime != AR_INITIAL)
			(void) ar_ctl(AR_cur, CTSETLIFE, 0, NULL, NULL, NULL, NULL, NULL);
*/
		if (AR_cur->lifetime == AR_SHORTERM) {
			mess_lock();		/* don't ask ... */
			(void) ar_close(AR_cur, FALSE);
			mess_unlock();
		}
		(void) arf_noncur(AR_cur, AR_cur);
		mess_frame("");			/* clear frame message */
	}
	if (do_reinit == TRUE)			/* abs k15 */
	    (void) arf_reinit(ap, ap);
}

/*
 * back end for ar_current and ar_backup
 * calls current function and sets slks
 * "ap" is actrec to make current if it fails
 */
static void
ar_cur_end(ap)
register struct actrec	*ap;
{
    ar_setslks(AR_cur->slks, AR_cur->flags & AR_ALTSLKS);
    if (arf_current(AR_cur, AR_cur) == FAIL)
    {
	if (AR_cur->lifetime == AR_INITIAL && AR_cur->nextrec == AR_cur)
	    fatal(MUNGED, "can't make only actrec current");
	else
	{
	    error(MUNGED, "can't make actrec current");
	    AR_cur = ap;
	    ar_setslks(AR_cur->slks, AR_cur->flags & AR_ALTSLKS);
	}
    }
    else
	(void) ar_ctl(AR_cur, CTSETMSG, FALSE, NULL, NULL, NULL, NULL, NULL);


#ifdef _DEBUG5
    ar_dump("at end of ar_current");
#endif
}

struct actrec *
ar_backup()
{
	register struct actrec	*ap;
	register struct actrec	*old_AR_cur;

	ap = AR_cur->backup;
	ar_cur_front( ap , TRUE ); /* miked k17 */
	old_AR_cur = AR_cur;
	AR_cur = ap;
	ar_cur_end(old_AR_cur);
	return AR_cur;
}

struct actrec *
ar_current(rec, do_reinit)
register struct actrec *rec;
bool do_reinit;			/* abs k15 */
{
	register struct actrec	*ap;
	pid_t pid;		/* miked k17 */
  
	/* do not make rec current if it's closing. abs k17 */
	if (rec && rec->lifetime == AR_CLOSING && /* abs k17 */
	    ar_ctl(rec, CTGETPID, &pid, NULL, NULL, NULL, NULL, NULL) == FAIL )	 /* miked k17 */
	    return(AR_cur);			 /* abs k17 */
	
	ar_cur_front(rec, do_reinit); /* abs k15 */
	/*
	 * backup is a circularly linked list
	 */
	if (AR_cur == NULL)
		/* produce degenerate list */
		rec->backup = rec;
	else if (AR_cur != rec) {
		/* traverse entire list */
		for (ap = AR_cur; ap->backup != AR_cur; ap = ap->backup) {
			/*
			 * if rec is in list and is not where we want it
			 *	unlink it from list
			 */
			if (ap->backup == rec && rec->backup != AR_cur)
				ap->backup = ap->backup->backup;
		}
		/* if rec is not where we want it, link it in befre cur */
		if (ap != rec) {
			rec->backup = ap->backup;
			ap->backup = rec;
		}
	}
	AR_cur = rec;
	ar_cur_end(AR_cur->backup);
	return AR_cur;
}



/* a minimal version  of ar_current for use when the frame is 
 * made current only for internal purposes. for example, used 
 * when doing a reread from ar_checkworld.  The user doesn't
 * see a change in what frame is current but internally we
 * make the frame current so we can update it.
 */

int
ar_cur_temp(rec)
register struct actrec *rec;
{

  
    /* do not make rec current if it's closing. abs k17 */
    if (rec && rec->lifetime == AR_CLOSING)  /* abs k17 */
	return(FAIL);			     /* abs k17 */
	
    if (AR_cur && AR_cur != rec)
	(void) arf_noncur(AR_cur, AR_cur);
    if (rec->backup == NULL)
	/* produce degenerate list */
	rec->backup = rec;
    AR_cur = rec;
    if (arf_temp_current(AR_cur, AR_cur) == FAIL)
    {
	if (AR_cur->lifetime == AR_INITIAL && AR_cur->nextrec == AR_cur)
	    fatal(MUNGED, "can't make only actrec current"); /* exit fmli */
	else
	{
	    error(MUNGED, "can't make actrec current");
	    AR_cur = AR_cur->backup;
	    return FAIL;
	}
    }
    return SUCCESS;
}


int
ar_setslks(s, flags)
struct slk	*s;
int flags;
{
	setslks(s, flags);
	return SUCCESS;
}

token
actrec_stream(t)
token t;
{
	return arf_odsh(AR_cur, t);
}

/* find an activation record via its window number */

struct actrec *
wdw_to_ar(wdw)
int wdw;
{
	struct actrec *p;

	for (p = AR_head; p; p = p->nextrec)
		if (wdw == ar_ctl(p, CTGETWDW, NULL, NULL, NULL, NULL, NULL, NULL))
			return p;
		else if (p->nextrec == AR_head)
			return NULL;
	return NULL;
}

/* find an activation record via its path */

struct actrec *
path_to_ar(s)
char *s;
{
	struct actrec *p;

	for (p = AR_head; p; p = p->nextrec)
		if ((p->path != NULL) && (s != NULL) && 
		    (strcmp(p->path, s) == 0))
			    return p;
		else if (p->nextrec == AR_head)
			return NULL;
	return NULL;
}

bool
path_isopen(s, op, exact)
char *s, *op;
bool exact;	/* if TRUE, don't allow exact match */
{
	struct actrec *p;
	int len = strlen(s);

	for (p = AR_head; p->path; p = p->nextrec) {
		if (exact && strcmp(p->path, s) == 0) {
			mess_temp(nstrcat("Can't ", op, 
				" an open object, close it first", NULL));
			return(TRUE);
		} else if (strncmp(p->path, s, len) == 0 && p->path[len] == '/') {
			mess_temp(nstrcat("Can't ", op, 
				" a folder with open sub-folders, close them first", NULL));
			return(TRUE);
		} else if (p->nextrec == AR_head)
			break;
	}
	return FALSE;
}

/* find the activation record past the argument given with a certain path */

struct actrec *
nextpath_to_ar(ar)
register struct actrec *ar;
{
	register struct actrec *p;

	for (p = ar->nextrec; p != ar; p = p->nextrec) {
		if ((p->path != NULL) && (ar->path != NULL)) {
			if (strcmp(p->path, ar->path) == 0)
				return(p);
		} else if ((p->path == NULL) && (ar->path == NULL))
			return(p);
	}
	return(NULL);
}

struct actrec *
ar_cleanup(life)		/* clean up all records with lifetime <= life */
register int life;
{
    register struct actrec *p, *nextp;
    register bool logout;
    
    logout = (life == AR_INITIAL) ? TRUE : FALSE; /* are we exiting fmli? */
/*    p = AR_head   miked k17+  */;
    nextp = AR_head->nextrec;		/* miked k17+ */
    do
    {
/*	p = p->nextrec;   miked k17+  */
	p = nextp;			/* miked k17+ */
	nextp = p->nextrec;		/* miked k17+ */
	if (p->lifetime <= life && !(life < AR_IMMORTAL && p->flags & AR_SKIP))
	    (void) ar_close(p, logout);
    } while ((AR_head != NULL) && (p != AR_head));

    return(AR_cur);
}

int
ar_help(rec)	/* do help on current actrec */
struct actrec *rec;
{
	return(arf_help(rec, rec));
}

void
ar_checkworld(force)
bool force;	/* if TRUE, forced check */
{
    struct actrec *rec, *start_rec, *sav_cur = AR_cur;
    static time_t last_check;      /* EFT abs k16 */
    static bool first_time = TRUE; /* abs k15 */
    extern long Mail_check;
    extern time_t Cur_time;        /* EFT abs k16 */

    if (force == FALSE &&
	(Cur_time <= last_check + Mail_check || first_time == TRUE)) /* abs k15 */
    {
	first_time = FALSE;	/* abs k15 */
	return;
    }
    last_check = Cur_time;

    start_rec = AR_cur->backup->backup;  /* miked k17+ */
    if ( start_rec == AR_cur )
        start_rec = AR_cur->backup;

/*    for (rec = AR_head; rec; rec = rec->nextrec) miked k17+ */
    for (rec = start_rec; rec; rec = rec->backup)
    {
	if (ar_cur_temp(rec) == SUCCESS) /* abs k15 */
	    (void) arf_reinit(rec, rec);
/*	if (rec->nextrec == AR_head)  miked k17+ */
	if (rec->backup == start_rec)
	    break;
    }
    (void) ar_cur_temp(sav_cur);
    (void) ar_ctl(AR_cur, CTSETMSG, FALSE, NULL, NULL, NULL, NULL, NULL);
}

int
ar_isfirst(ar1, ar2)
struct actrec *ar1, *ar2;
{
	register struct actrec *p;

	for (p = AR_cur; p->backup != AR_cur; p = p->backup) {
		if (p == ar1)
			return(TRUE);
		else if (p == ar2)
			return(FALSE);
	}
	return(TRUE);	/* should not get this far */ 
}

struct actrec *
menline_to_ar(n)
int n;
{
	register int i;
	register struct actrec *p;

	for (p = AR_head, i = -1; p; p = p->nextrec) {
		/* records with NULL path fields are not listed */
		if (p->path) {
			if (++i == n)
				return(p);
		}
		if (p->nextrec == AR_head)
			break;
	}
	return NULL;
}

struct menu_line
ar_menudisp(n, ptr)
register int n;
register char *ptr;
{
	register struct actrec *p;
	struct menu_line m;

	m.description = NULL;
	m.flags = 0;
	if (p = menline_to_ar(n))
		(void) ar_ctl(p, CTGETITLE, &m.highlight, NULL, NULL, NULL, NULL, NULL);
	else
		m.highlight = NULL;
	return m;
}

int	 /* >>>>>> NONPORTABLE!!! change to "char *" <<<<<<< */
ar_ctl(rec, cmd, arg1, arg2, arg3, arg4, arg5, arg6)
struct actrec *rec;
int cmd;
int arg1, arg2, arg3, arg4, arg5, arg6;
{
	if (rec == NULL)
		return(FAIL);
/*	if (cmd == CTSETLIFE && arg1 != 0)
	{
		rec->lifetime = arg1;
		return(SUCCESS);
	}
	else
		return((*(rec->fcntbl[AR_CTL]))
		     (rec, cmd, arg1, arg2, arg3, arg4, arg5, arg6));
abs */
	switch (cmd)
	{
	case CTSETLIFE:
	    if (arg1 != 0)
	    {
		rec->lifetime = arg1;
		return(SUCCESS);
	    }
	    else
		return((*(rec->fcntbl[AR_CTL]))
		     (rec, cmd, arg1, arg2, arg3, arg4, arg5, arg6));
	    break;
	case CTSETINTR:		/* >>> ADD FREE STR CODE <<< */
	    if ((char *)arg1 == NULL)
		rec->interrupt = (char *)strsave(init_ctl(CTGETINTR));
	    else
		rec->interrupt = (char *)strsave((char *)arg1);
	    return(SUCCESS);
	case CTGETINTR:
	    return((int)rec->interrupt);
	case CTSETONINTR: 	/* >>> ADD FREE STR CODE <<< */
	    if ((char *)arg1 == NULL)
		rec->oninterrupt = (char *)strsave(init_ctl(CTGETONINTR));
	    else
		rec->oninterrupt = (char *)strsave((char *)arg1);
	    return(SUCCESS);
	case CTGETONINTR:
	    return((int)rec->oninterrupt);
	default:
	    return((*(rec->fcntbl[AR_CTL]))
		   (rec, cmd, arg1, arg2, arg3, arg4, arg5, arg6));
	}
}
    
#ifdef _DEBUG5

/* for debugging - print out activation record info */
void
ar_dump(s)
char	*s;
{
	struct actrec *p;

	_debug5(stderr, "---------- Activation Record Dump: %s ----------\n", s);
	_debug5(stderr, " #\tprev\tnext\tbackup\tpath\n");

	for (p = AR_head; p; p = p->nextrec) {
		_debug5(stderr, "%2d\t", p->serial);
		_debug5(stderr, "%2d\t", p->prevrec?p->prevrec->serial:-1);
		_debug5(stderr, "%2d\t", p->nextrec?p->nextrec->serial:-1);
		_debug5(stderr, "%2d\t", p->backup?p->backup->serial:-1);
		_debug5(stderr, "%5.5s", (p==AR_cur)?"CUR>>":"     ");
		_debug5(stderr, "%s\n", p->path);
		if (p->nextrec == AR_head)
			break;
	}
	_debug5(stderr, "Current = %s\n", AR_cur?AR_cur->path:"NULL");
	_debug5(stderr, "Head    = %s\n", AR_head?AR_head->path:"NULL");
	_debug5(stderr, "-------------**Dump End**------------------\n");
}
#endif
