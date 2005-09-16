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
#include <string.h>
#include <ctype.h>
#include <sys/types.h>		/* EFT abs k16 */
#include "wish.h"
#include "vtdefs.h"
#include "ctl.h"
#include "menudefs.h"
#include "token.h"
#include "slk.h"
#include "actrec.h"
#include "typetab.h"
#include "fm_mn_par.h"
#include "objmenu.h"
#include "var_arrays.h"
#include "terror.h"
#include "moremacros.h"
#include "interrupt.h"
#include "sizes.h"
#include "message.h"

#define MN_INTR		PAR_INTR  
#define MN_ONINTR	PAR_ONINTR
#define MN_DONE		PAR_DONE
#define MN_MENU		3
#define MN_HELP		4 
#define MN_LIFE		5 
#define MN_INIT		6 
#define MN_BEGROW	7 
#define MN_BEGCOL	8 
#define MN_ROWS		9 
#define MN_COLUMNS	10
#define MN_CLOSE	11
#define MN_REREAD	12
#define MN_MULTI	13
#define MN_MSELECT	14
#define MN_ALTSLKS	15
#define MN_FRMMSG	16

/* defined above
#define MN_INTR		PAR_INTR
#define MN_ONINTR	PAR_ONINTR
abs */
#define MN_ACTI		PAR_ACTION
#define MN_NAME		PAR_NAME
#define MN_DESC		4
#define MN_BUTT		5
#define MN_LININFO	6
#define MN_SHOW		7
#define MN_ARG		8
#define MN_SELECTED	9
#define MN_ITEMMSG     10
#define MN_INACTIVE    11

#define MN_KEYS 17
static struct attribute Mn_tab[MN_KEYS] = {
	{ "interrupt",	RET_STR|EVAL_ALWAYS,    NULL, NULL, 0 },
	{ "oninterrupt",RET_STR|EVAL_ALWAYS,	NULL, NULL, 0 },
	{ "done",	RET_ARGS|EVAL_ALWAYS,	"", NULL, 0 },
	{ "menu",	RET_STR|EVAL_ONCE,	"Menu", NULL, 0 },
	{ "help",	RET_ARGS|EVAL_ALWAYS,	"", NULL, 0 },
	{ "lifetime",	RET_STR|EVAL_ALWAYS,	"longterm", NULL, 0 },
	{ "init",	RET_BOOL|EVAL_ALWAYS,	"", NULL, 0 },
	{ "begrow",	RET_STR|EVAL_ONCE,	"any", NULL, 0 },
	{ "begcol",	RET_STR|EVAL_ONCE,	"any", NULL, 0 },
	{ "rows",	RET_INT|EVAL_ONCE,	"0", NULL, 0 },
	{ "columns",	RET_INT|EVAL_ONCE,	"0", NULL, 0 },
	{ "close",	RET_BOOL|EVAL_ONCE,	NULL, NULL, 0 },
	{ "reread",	RET_BOOL|EVAL_ALWAYS,	NULL, NULL, 0 },
	{ "multicolumn",RET_BOOL|EVAL_ONCE,	"", NULL, 0 },
	{ "multiselect",RET_BOOL|EVAL_ONCE,	NULL, NULL, 0 },
	{ "altslks",	RET_BOOL|EVAL_ONCE,	NULL, NULL, 0 },
	{ "framemsg",	RET_STR|EVAL_ONCE,	"", NULL, 0 }
};

#define MN_FLD_KEYS 12
static struct attribute Mn_fld_tab[MN_FLD_KEYS] = {
	{ "interrupt",	RET_STR|EVAL_ALWAYS,    NULL, NULL, 0 },
	{ "oninterrupt",RET_STR|EVAL_ALWAYS,	NULL, NULL, 0 },
	{ "action",	RET_ARGS|EVAL_ALWAYS,	"", NULL, 0 },
	{ "name",	RET_STR|EVAL_ONCE,	NULL, NULL, 0 },
	{ "description",RET_STR|EVAL_ONCE,	NULL, NULL, 0 },
	{ "button",	RET_INT|EVAL_ONCE,	"0", NULL, 0 },
	{ "lininfo",	RET_STR|EVAL_ALWAYS,	NULL, NULL, 0 },
	{ "show",	RET_BOOL|EVAL_SOMETIMES,"", NULL, 0 },
	{ "arg",	RET_STR|EVAL_SOMETIMES,	NULL, NULL, 0 },
	{ "selected",   MAKE_COPY|RET_BOOL|EVAL_SOMETIMES, NULL, NULL, 0 },
	{ "itemmsg",    RET_STR|EVAL_ALWAYS,	NULL, NULL, 0 },
	{ "inactive",    RET_BOOL|EVAL_SOMETIMES, NULL, NULL, 0 }
};

#define CURmenu() (&(((menuinfo *) Cur_rec->odptr)->fm_mn))
#define CURmenuinfo() ((menuinfo *) Cur_rec->odptr)
#define NUMactive() (((menuinfo *) Cur_rec->odptr)->numactive)
#define DEVirt(X) (((menuinfo *) Cur_rec->odptr)->visible[X])
#define ARGS() (((menuinfo *) Cur_rec->odptr)->args)
static struct menu_line objmenu_disp();
static struct actrec *Cur_rec;
static int objmenu_noncur();
static int objmenu_reread();
static struct fm_mn parse_menu();

static token if_omsh();
extern	menu_id menu_make();

/*
** Calls setaction and returns the token.
*/
static token
objmenu_help(rec)
struct actrec *rec;
{
    token make_action();

    Cur_rec = rec;
    return(setaction(sing_eval(CURmenu(), MN_HELP)));
}

/*
** Calls close function and frees the structures.
*/
static int 
objmenu_close(a) 
struct actrec *a; 
{ 
    int lcv, i;
    char *p, *strchr();

    Cur_rec = a;
    copyAltenv(ARGS());		    /* in case MN_CLOSE references $ARGs */
    sing_eval(CURmenu(), MN_CLOSE); /* execute the close function  */
    freeitup(CURmenu());       /* free information IN the menuinfo structure */
    objmenu_noncur(a, FALSE);       /* delete ARGs from the Altenv */

     lcv = array_len(ARGS());	    /* delete ARGs from the menu data */
     for (i = 0; i < lcv; i++) {			
     	char namebuf[BUFSIZ];

     	if (p = strchr(ARGS()[i], '='))
     		*p = '\0';
     	strcpy(namebuf, ARGS()[i]);   
	if (p)
     		*p = '=';
     	delaltenv(&ARGS(), namebuf);
     }

    array_destroy(ARGS());	                    /* variable table */
    array_destroy(((menuinfo *)a->odptr)->slks);    /* visible slks  */
    array_destroy(((menuinfo *)a->odptr)->visible); /* visible items */

    /* 
     * Free information in the activation record
     */
    free(a->odptr); 		/* free the menuinfo structure */
    free(a->slks);		/* free the object specific SLKS */
    free(a->path);		/* free path of the definition file */

    return(menu_close(a->id));	/* close the menu */
}

/*
 * Rereads if reread is set
 */
static int
objmenu_reinit(a)
struct actrec *a;
{
	Cur_rec = a;
	if (sing_eval(CURmenu(), MN_REREAD))
		return(objmenu_reread(a));
	return(SUCCESS);
}

/*
** Front-end to parser(), it sets up defaults.
*/
static struct fm_mn
parse_menu(flags, info_or_file, fp)
int flags;
char *info_or_file;
FILE *fp;
{
    struct fm_mn fm_mn;

    fm_mn.single.attrs = NULL;
    fm_mn.multi = NULL;
    filldef(&fm_mn.single, Mn_tab, MN_KEYS);
    parser(flags, info_or_file, Mn_tab, MN_KEYS, &fm_mn.single,
	   Mn_fld_tab, MN_FLD_KEYS, &fm_mn.multi, fp);
    return(fm_mn);
}

/*
** If a->id >= 0 this is a reread.  If so it frees the old info.
** Either way it calls the parser.
*/
static int
objmenu_reread(a)
register struct actrec *a;
{
    struct fm_mn *fm_mn;
    extern struct slk Defslk[MAX_SLK + 1];
    extern struct slk Menuslk[];
    extern char * itoa();
    register int i, but;
    char buf[10];
    char *label, *intr,  *onintr, *get_def();
    menuinfo *mi;
    int	lcv;
    FILE  *fp = NULL;

    Cur_rec = a;
    fm_mn = CURmenu();
    mi = CURmenuinfo();

    /* make sure file exists and is readable (if there is a file) 
     * The "flags" say if a->path is  the information
     * itself or the file of where the information sits.  abs k15
     */
    if (!(mi->flags & INLINE))
	if ((fp = fopen(a->path, "r")) == NULL)
	{
	    if (a->id >= 0)	/* if frame is already posted */
		warn(NOT_UPDATED, a->path);
	    else
		warn(FRAME_NOPEN, a->path);
	    return(FAIL);
	}
    if (a->id >= 0)
	freeitup(CURmenu());
    mi->fm_mn = parse_menu(mi->flags, a->path, fp);	/* abs k14.0 */
    if (fm_mn->single.attrs == NULL) {
	if (a->id >= 0)
	    ar_close(a, FALSE);
	return(FAIL);
    }
    fm_mn->seqno = 1;
    mi->visible = NULL;
    mn_vislist(mi);
    strcpy(buf, "NR=");
    strncat(buf, itoa((long)array_len(mi->visible), 10), 6); /* abs k16 */
    putaltenv(&ARGS(), buf);
    putAltenv(buf);
    if (!sing_eval(CURmenu(), MN_INIT) || (int)array_len(mi->visible) <= 0 ||
	(NUMactive() <= 0)) 
    {
	if (a->id >= 0)		/* form is already posted */
	{
	    if (a->lifetime == AR_INITIAL)
	    {
		mess_temp("can't close this frame");
		mess_lock();
	    }
	    else
	    {
		ar_close(a, FALSE);
		return(FAIL);
	    }
	}
	else
	{
	    sing_eval(CURmenu(), MN_CLOSE);
	    freeitup(CURmenu());
	    objmenu_noncur(a, FALSE); /*  clean up Altenv. abs k14 */
	    return(FAIL);
	}
    }
    ar_ctl(a, CTSETINTR, get_sing_def(CURmenu(), MN_INTR), NULL, NULL, NULL, NULL, NULL);
    ar_ctl(a, CTSETONINTR, get_sing_def(CURmenu(), MN_ONINTR), NULL, NULL, NULL, NULL, NULL);

    set_top_slks(Menuslk);
    if (sing_eval(CURmenu(), MN_MSELECT))
	set_slk_mark(TRUE);
    else
	set_slk_mark(FALSE);
    memcpy((char *)a->slks, (char *)Defslk, sizeof(Defslk));
    lcv = array_len(mi->slks);
    for (i = 0; i < lcv; i++) {
	but = atoi(multi_eval(fm_mn, mi->slks[i], MN_BUTT)) - 1;
	if (but <  0 || but >= MAX_SLK)	/* abs */
	    continue;
	label = multi_eval(fm_mn, mi->slks[i], MN_NAME);
	intr  = get_def(CURmenu(),mi->slks[i], MN_INTR);
	onintr  = get_def(CURmenu(),mi->slks[i], MN_ONINTR);
	set_obj_slk(&(a->slks[but]), label, TOK_SLK1 + but, intr, onintr);
    }
    if (a->id >= 0) {
	objmenu_ctl(0, CTSETSTRT, a->id); /* go to 1st item.    abs */
	a->id = menu_reinit(a->id, 0, atoi(sing_eval(CURmenu(), MN_ROWS)),
			    atoi(sing_eval(CURmenu(), MN_COLUMNS)), objmenu_disp, a->odptr);
    }
    (void) ar_ctl(Cur_rec, CTSETMSG, FALSE, NULL, NULL, NULL, NULL, NULL); /* was AR_cur.  abs k15 */
    return(SUCCESS);
}

/*
** Takes this object's information out of the altenv.
*/
static int 
objmenu_noncur(a, all) 
struct actrec *a;
bool all;
{
    register int i;
    register char *p;
    int	lcv;

    Cur_rec = a;
    lcv = array_len(ARGS());
    for (i = 0; i < lcv; i++) {
	char namebuf[BUFSIZ];

	if (p = strchr(ARGS()[i], '='))
	    *p = '\0';
	strcpy(namebuf, ARGS()[i]);
	if (p)
	    *p = '=';
	delAltenv(namebuf);
    }
    if (all)
	return(menu_noncurrent(a->id));
    else
	return(SUCCESS);
}

/*
** Moves information in this object's altenv to the major altenv.
*/
static int 
objmenu_current(a) 
struct actrec *a; 
{
    int line;
    char *str;

    Cur_rec = a;
    copyAltenv(ARGS());
    menu_ctl(Cur_rec->id, CTGETPOS, &line);
    if ((str = multi_eval(CURmenu(), DEVirt(line), MN_ITEMMSG)) && *str)
	mess_temp(str);
    return(menu_current(a->id));
}


/*
** get  the right ARGS.  abs k18
*/
static int 
objmenu_temp_cur(a) 
struct actrec *a; 
{
    Cur_rec = a;
    copyAltenv(ARGS());
    return(menu_current(a->id));
}

/*
** Calculates the show functions to decide which menu lines and SLKs
** should be shown.
*/
int
mn_vislist(mi)
menuinfo *mi;
{
    int i;
    struct fm_mn *ptr;
    int	lcv;
	
    ptr = &(mi->fm_mn);
    if (!mi->visible) {
	mi->slks = (int *) array_create(sizeof(int), array_len(ptr->multi));
	mi->visible = (int *) array_create(sizeof(int), array_len(ptr->multi));
    }
    else {
	array_trunc(mi->slks);
	array_trunc(mi->visible);
    }

    lcv = array_len(ptr->multi);
    NUMactive() = 0;
    for (i = 0; i < lcv; i++)
	if (multi_eval(ptr, i, MN_SHOW)) {
	    if (atoi(multi_eval(ptr, i, MN_BUTT)))
		mi->slks = (int *) array_append(mi->slks, (char *) &i);
	    else
		mi->visible = (int *) array_append(mi->visible, (char *) &i);
		/*
		 *  Keep track of number of active menu items
		 */
		if (!multi_eval(ptr, i, MN_INACTIVE))
			NUMactive()++;
	}
	return (0);
}

/*
 * TOGGLE MARK will toggle the "mark" flag for a given menu
 * item indexed by i (Multiple Selection Menus).
 */
int
toggle_mark(ptr, i)
struct fm_mn *ptr;
int i;
{
	struct attribute *att;

	att = (ptr->multi + i)->attrs[MN_SELECTED];
	att->flags ^= MENU_MARKED;	/* toggle flag */
	return (0);
}

/*
 * ISMARKED will check for the "mark" flag
 */
int
ismarked(ptr, i)
struct fm_mn *ptr;
int i;
{
    struct attribute *att;

    att = (ptr->multi + i)->attrs[MN_SELECTED];
    if (!att)
	return(0);
    if (sing_eval(ptr, MN_MSELECT) && !(att->flags & MENU_CHECKED) &&
	multi_eval(ptr, i, MN_SELECTED)) {
	toggle_mark(ptr, i);
	att->flags |= MENU_CHECKED;
    }
    return (att->flags & MENU_MARKED);
}

/*
** Calculates NAME, FLAGS, and DESCRIPTION
*/
static struct menu_line
objmenu_disp(n, mi)
int n;
menuinfo *mi;
{
    register int i;
    struct fm_mn *ptr;
    struct menu_line m;

    if (n >= (int)array_len(mi->visible))
	m.highlight = m.description = NULL;
    else {
	i = mi->visible[n];
	ptr = &(mi->fm_mn);
	m.highlight = multi_eval(ptr, i, MN_NAME);
	m.lininfo = multi_eval(ptr, i, MN_LININFO);
	m.flags = 0;
	if (multi_eval(ptr, i, MN_INACTIVE)) 
		m.flags = MENU_INACT;
	if (ismarked(ptr, i)) {
		m.flags = MENU_MRK;
		if (multi_eval(ptr, i, MN_INACTIVE)) 
			m.flags = MENU_INACT|MENU_MRK;
	}
	m.description = multi_eval(ptr, i, MN_DESC);
    }
    return(m);
}

/*
** Shrinks the string (if needed) to max_len characters.
** Terminate the string with TRUNCATE_STR to show that  it was
** truncated.
*/
char *
shrink_str(str, max_len)
char *str;
int max_len;
{
    static char shrunk[MAX_WIDTH];
    int len;

    len = strlen(str);
    if (len <= max_len)
    {
	strncpy(shrunk, str, len);
	shrunk[len] = '\0';
    }
    else
    {
	strncpy(shrunk, str, max_len - LEN_TRUNC_STR);
	strcpy(shrunk + max_len - LEN_TRUNC_STR, TRUNCATE_STR);
    }
    return(shrunk);
}



int
objmenu_ctl(rec, cmd, arg1, arg2, arg3, arg4, arg5, arg6)
struct actrec *rec;
int cmd;
int arg1, arg2, arg3, arg4, arg5, arg6;
{
    int pos;

    switch (cmd)
    {
        case CTGETARG:
        {
	    char *str;

	    Cur_rec = rec;
	    if (menu_ctl(rec->id, CTGETPOS, &pos) == FAIL)
		return(FAIL);
	    pos = DEVirt(pos);
	    if ((str = multi_eval(CURmenu(), pos, MN_ARG)) && *str) /* abs k16 */
	    {
		**((char ***)(&arg1)) = strsave(str);
		return(SUCCESS);
	    }
	    return(FAIL);
	}
        case CTSETMSG:
        {
	    if (arg1 == TRUE) {
		/* 
		 * if arg1 == TRUE then the frame message was
		 * generated "externally" (i.e., via the message
		 * built-it).  Update the "framemsg" descriptor
		 * accordingly.
		 */
		char *newmsg, *get_mess_frame();

		newmsg = get_mess_frame();
		set_single_default(CURmenu(), MN_FRMMSG, newmsg);
	    }
	    else 
		mess_frame(sing_eval(CURmenu(), MN_FRMMSG));
	    return(SUCCESS);
	}
        case CTSETLIFE:
        { 
	    char *life;

	    /* used Cur_rec before.  abs  F15 */
	    life = sing_eval((&(((menuinfo *) rec->odptr)->fm_mn)), MN_LIFE);
	    setlifetime(rec, life);
	    return(SUCCESS);
	}
        case CTSETSTRT:
        {
	    char *str;

	    menu_ctl(arg1, CTSETSTRT);
	    if ((str = multi_eval(CURmenu(), DEVirt(0), MN_ITEMMSG)) && *str)
		mess_temp(str);
	    return(SUCCESS);
	}
/*      not needed (yet) afterall. to add must make this routine return char * 
        case CTGETDESCRIPTION:
        {
	    menuinfo *mi = (menuinfo *)arg2;
	    struct fm_mn *ptr = &(mi->fm_mn);

	    if (arg1 >= array_len(mi->visible))
		return(NULL);
	    else
		return(multi_eval(ptr, mi->visible[arg1], MN_DESC));
	}
*/	
        default:
	    return(menu_ctl(rec->id, cmd, arg1, arg2, arg3, arg4, arg5, arg6));
    }
}

/*
** Uses path_to_ar() and nextpath_to_ar() to see if it is a reopen
** and if so, makes it current.  Otherwise, it builds the actrec and
** calls ar_create().
*/
int
IF_omopen(args)
register char **args;
{
    register int i;
    int do_inline;
    struct actrec a, *first_rec, *ar_create(), *path_to_ar(), *nextpath_to_ar();
    struct fm_mn *fm_mn;
    extern struct slk Defslk[MAX_SLK + 1];
    menuinfo *mi;
    char *life;
    char envbuf[6];
    char *begcol, *begrow;
    int startrow, startcol, type;

    a.serial = 0;
    a.slks = (struct slk *)NULL;
    a.prevrec = (struct actrec *)NULL;
    a.nextrec = (struct actrec *)NULL;
    a.backup = (struct actrec *)NULL;

    if (strCcmp(args[0], "-i") == 0)
    {
	do_inline = TRUE;
	Cur_rec = path_to_ar(args[1]);
    }
    else
    {
	do_inline = FALSE;
	Cur_rec = path_to_ar(args[0]);
    }
    for (first_rec = Cur_rec; Cur_rec; ) {
	char *env, *getaltenv();

	strcpy(envbuf, "ARG1");
	for (i = do_inline ? 2 : 1;
	     (env = getaltenv(ARGS(), envbuf)) && args[i];
	     envbuf[3]++, i++)
	    if (strcmp(args[i], env))
		break;
	if (!args[i] && !env) {
	    ar_current(Cur_rec, TRUE); /* abs k15 */
	    return(SUCCESS);
	}
	Cur_rec = nextpath_to_ar(Cur_rec);
	if (Cur_rec == first_rec) /* circular list */
	    break;
    }
    mi = (menuinfo *)new(menuinfo);
    mi->flags = do_inline ? INLINE : 0;
    mi->args = NULL;
    a.odptr = (char *) mi;
    fm_mn = &(mi->fm_mn);
    fm_mn->single.attrs = NULL;
    if (do_inline)
	a.path = strsave(args[1]);
    else
	a.path = strsave(args[0]);
    if ((a.slks = (struct slk *) malloc(sizeof(Defslk))) == NULL)
	fatal(NOMEM, nil);
    a.id = -1;
    a.fcntbl[AR_CLOSE] = objmenu_close;
    a.fcntbl[AR_HELP] = (int (*)())objmenu_help; /* added cast abs 9/12/88 */
    a.fcntbl[AR_REREAD] = objmenu_reread;
    a.fcntbl[AR_REINIT] = objmenu_reinit;
    a.fcntbl[AR_CURRENT] = objmenu_current;
    a.fcntbl[AR_TEMP_CUR] = objmenu_temp_cur; /* abs k18 */
    a.fcntbl[AR_NONCUR] = objmenu_noncur;
    a.fcntbl[AR_ODSH] = (int (*)())if_omsh; /* added cast abs 9/12/88 */
    a.fcntbl[AR_CTL] = objmenu_ctl;
    Cur_rec = &a;
    setupenv(mi->flags, args, &ARGS());
    if (objmenu_reread(&a) == FAIL)
	return(FAIL);
    begrow = sing_eval(fm_mn, MN_BEGROW);
    begcol = sing_eval(fm_mn, MN_BEGCOL);
    life = sing_eval(CURmenu(), MN_LIFE);
    life_and_pos(&a, life, begrow, begcol, &startrow, &startcol, &type);

    /*
     * create the menu (menu frame)
     */
    a.id = menu_make(-1, shrink_str(sing_eval(fm_mn, MN_MENU), MAX_TITLE),
		     type, startrow, startcol, atoi(sing_eval(fm_mn, MN_ROWS)),
		     atoi(sing_eval(fm_mn, MN_COLUMNS)), objmenu_disp,
		     (char *)mi);

    if (a.id == FAIL)
	return(FAIL);
    if (sing_eval(fm_mn, MN_ALTSLKS))
	a.flags = AR_ALTSLKS;
    else
	a.flags = 0;
    if (sing_eval(fm_mn, MN_MSELECT))
	menu_ctl(a.id, CTSETATTR); /* multi-select menu */
    return(ar_current(Cur_rec = ar_create(&a), FALSE));	/* abs k15 */
}

/*
** Takes a line number and calls setaction on its ACTION.
** (re-evaluate the lifetime descriptor before actually performing
**  the specifie action via "setaction")
*/
token
linaction(n)
int n;
{
    return(setaction(multi_eval(CURmenu(), n, MN_ACTI)));
}

/*
** Catches SLKs and processes them.
*/
token
objmenu_stream(tok)
register token tok;
{
    int line; 
    char *tmp, *str;
    char *ott_to_path();
    int *slks;
    extern int	Arg_count;
    int	lcv;

    if (tok == TOK_NEXT) {
	/* kludge for per-item message (menu_stream passes TOK_NEXT) */
	menu_ctl(Cur_rec->id, CTGETPOS, &line);
	if ((str = multi_eval(CURmenu(), DEVirt(line), MN_ITEMMSG)) && *str)
	    mess_temp(str);
	return(TOK_NOP);
    }
    menu_ctl(Cur_rec->id, CTGETPOS, &line);
    tmp = multi_eval(CURmenu(), DEVirt(line), MN_LININFO);
    if (strlen(tmp)) {
	char buf[BUFSIZ];
		
	sprintf(buf, "LININFO=%s", tmp);
	putAltenv(buf);
    }
    else 
	delAltenv("LININFO");
	
    if (tok >= TOK_SLK1 && tok <= TOK_SLK16) {
	int num;
	int i;

	slks = CURmenuinfo()->slks;
	num = tok - TOK_SLK1 + 1;
	lcv = array_len(slks);
	for (i = 0; i < lcv; i++) {
	    if (atoi(multi_eval(CURmenu(), slks[i],MN_BUTT)) == num)
		tok = linaction(slks[i]);
	}
    }
    if (tok == TOK_MARK && sing_eval(CURmenu(), MN_MSELECT)) {
	/*
	 * If this is a multiple selection menu then 
	 * mark the item (and update the menu)
	 */
	toggle_mark(CURmenu(), DEVirt(line));
	menu_ctl(Cur_rec->id, CTSETPOS, DEVirt(line));
		
	/*
	 * SELECTED is updated in the alternate
	 * environment in case the "action" descriptor
	 * contains a reference to $SELECTED 
	 */
	if (ismarked(CURmenu(), DEVirt(line)))
	    putAltenv("SELECTED=true");
	else
	    putAltenv("SELECTED=false");
	multi_eval(CURmenu(), DEVirt(line), MN_ACTI);
	tok = TOK_NOP;
    }
    else if (tok == TOK_OPEN && Arg_count < 2) {
	if (sing_eval(CURmenu(), MN_MSELECT))
	    tok = setaction(sing_eval(CURmenu(), MN_DONE));
	else {
	    menu_ctl(Cur_rec->id, CTGETPOS, &line);
	    tok = linaction(DEVirt(line));
	}
    }
    return(tok);
}

/*
** Calls menu_stream and objmenu_stream()
*/
static token
if_omsh(a, t)
struct actrec *a;
register token t;
{
    token (*func[3])();
    extern token menu_stream();
    register int olifetime;

    Cur_rec = a;
    olifetime = Cur_rec->lifetime;
    Cur_rec->lifetime = AR_PERMANENT;
    func[0] = menu_stream;
    func[1] = objmenu_stream;
    func[2] = NULL;
    t = stream(t, func);
    Cur_rec->lifetime = olifetime; 
    return(t);
}
