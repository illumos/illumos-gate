/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


#include	<ctype.h>
#include	<stdio.h>
#include	<string.h>
#include        <curses.h>
#include	<sys/types.h>		/* EFT abs k16 */
#include	"wish.h"
#include	"menudefs.h"
#include	"message.h"
#include	"token.h"
#include	"vtdefs.h"
#include	"ctl.h"
#include	"slk.h"
#include	"actrec.h"
#include	"typetab.h"
#include	"winp.h"
#include	"form.h"
#include	"fm_mn_par.h"
#include	"objform.h"
#include	"eval.h"
#include	"terror.h"
#include	"var_arrays.h"
#include	"moremacros.h"
#include	"interrupt.h"
#include	"sizes.h"


#define FM_KEYS		13
#define FM_INTR		PAR_INTR  
#define FM_ONINTR	PAR_ONINTR
#define FM_DONE 	PAR_DONE
#define FM_TITLE	3
#define FM_LIFE		4 
#define FM_INIT		5 
#define FM_BEGROW	6 
#define FM_BEGCOL	7 
#define FM_HELP		8 
#define FM_REREAD	9	
#define FM_CLOSE	10
#define FM_ALTSLKS	11
#define FM_FRMMSG	12

#define FM_FLD_KEYS	27

/* defined above   abs
#define FM_INTR		PAR_INTR
#define FM_ONINTR	PAR_ONINTR
*/
#define FM_ACTI		PAR_ACTION
#define FM_NAME		PAR_NAME
#define FM_FROW		4 
#define FM_FCOL		5 
#define FM_NROW		6 
#define FM_NCOL		7 
#define FM_ROWS		8 
#define FM_COLS		9 
#define FM_FLEN		10
#define FM_VALUE	11
#define FM_RMENU	12
#define FM_CHOICEMSG	13
#define FM_VALID	14
#define FM_NOECHO	15
#define FM_MENUO	16
#define FM_SHOW		17
#define FM_SCROLL	18
#define FM_WRAP		19
#define FM_PAGE		20
#define FM_BUTT		21
#define FM_VALMSG	22
#define FM_INACTIVE	23
#define FM_FIELDMSG	24
#define FM_LININFO	25
#define FM_AUTOADVANCE  26

static struct attribute Fm_tab[FM_KEYS] = {
	{ "interrupt",	RET_STR|EVAL_ALWAYS,    NULL, NULL, 0 },
	{ "oninterrupt",RET_STR|EVAL_ALWAYS,	NULL, NULL, 0 },
	{ "done",	RET_ARGS|EVAL_ALWAYS,	"", NULL, 0 },
	{ "form",	RET_STR|EVAL_ONCE,	"Form", NULL, 0 },
	{ "lifetime",	RET_STR|EVAL_ALWAYS,	"longterm", NULL, 0 },
	{ "init",	RET_BOOL|EVAL_ALWAYS,	"", NULL, 0 },
	{ "begrow",	RET_INT|EVAL_ONCE,	"any", NULL, 0 },
	{ "begcol",	RET_INT|EVAL_ONCE,	"any", NULL, 0 },
	{ "help",	RET_ARGS|EVAL_ALWAYS,	"", NULL, 0 },
	{ "reread",	RET_BOOL|EVAL_ALWAYS,	NULL, NULL, 0 },
	{ "close",	RET_BOOL|EVAL_ONCE,	NULL, NULL, 0 },
	{ "altslks",	RET_BOOL|EVAL_ONCE,	NULL, NULL, 0 },
	{ "framemsg",	RET_STR|EVAL_ONCE,	"", NULL, 0 }
};

static struct attribute Fm_fld_tab[FM_FLD_KEYS] = {
	{ "interrupt",	RET_STR|EVAL_ALWAYS,    NULL, NULL, 0 },
	{ "oninterrupt",RET_STR|EVAL_ALWAYS,	NULL, NULL, 0 },
	{ "action",	RET_ARGS|EVAL_ALWAYS,	"", NULL, 0 },
	{ "name",	RET_STR|EVAL_ONCE,	NULL, NULL, 0 },
	{ "frow",	RET_INT|EVAL_ONCE,	"-1", NULL, 0 },
	{ "fcol",	RET_INT|EVAL_ONCE,	"-1", NULL, 0 },
	{ "nrow",	RET_INT|EVAL_ONCE,	"-1", NULL, 0 },
	{ "ncol",	RET_INT|EVAL_ONCE,	"-1", NULL, 0 },
	{ "rows",	RET_INT|EVAL_ONCE,	"1",  NULL, 0 }, /* abs f15 */
	{ "columns",	RET_INT|EVAL_ONCE,	"-1", NULL, 0 },
	{ "flen",	RET_INT|EVAL_ONCE,	NULL, NULL, 0 },
	{ "value",	MAKE_COPY|RET_STR|EVAL_SOMETIMES,"", NULL, 0 },
	{ "rmenu",	RET_LIST|EVAL_ONCE|EV_SQUIG,"", NULL, 0 },
	{ "choicemsg",	RET_STR|EVAL_ONCE,	NULL, NULL, 0 },
	{ "valid",	RET_BOOL|EVAL_SOMETIMES,"", NULL, 0 },
	{ "noecho",	RET_BOOL|EVAL_ONCE,	NULL, NULL, 0 },
	{ "menuonly",	RET_BOOL|EVAL_ONCE,	NULL, NULL, 0 },
	{ "show",	RET_BOOL|EVAL_SOMETIMES,"", NULL, 0 },
	{ "scroll",	RET_BOOL|EVAL_ONCE,	NULL, NULL, 0 },
	{ "wrap",	RET_BOOL|EVAL_ONCE,	NULL, NULL, 0 },
	{ "page", 	RET_STR|EVAL_ONCE,	"1", NULL, 0 },
	{ "button",	RET_INT|EVAL_ONCE,	"0", NULL, 0 },
	{ "invalidmsg",	RET_STR|EVAL_SOMETIMES,	NULL, NULL, 0 },
	{ "inactive",	RET_BOOL|EVAL_SOMETIMES,	NULL, NULL, 0 },
	{ "fieldmsg",	RET_STR|EVAL_ALWAYS,	NULL, NULL, 0 },
	{ "lininfo",	RET_STR|EVAL_ALWAYS,	NULL, NULL, 0 },
	{ "autoadvance",RET_BOOL|EVAL_ONCE,	NULL, NULL, 0 }
};

char *itoa();

#define DEVirt(X) (((forminfo *) Cur_rec->odptr)->visible[X])
#define CURforminfo() ((forminfo *) Cur_rec->odptr)
#define CURform() (&(((forminfo *) Cur_rec->odptr)->fm_mn))
#define CURattr(x, y) ((CURform()->multi + x)->attrs[y])
#define NUMvis() (array_len(((forminfo *) Cur_rec->odptr)->visible))
#define NUMactive() (((forminfo *) Cur_rec->odptr)->numactive)
#define VALS() (((forminfo *) Cur_rec->odptr)->mulvals)
#define PTRS() (((forminfo *) Cur_rec->odptr)->holdptrs)
#define NUMflds() (array_len(((forminfo *) Cur_rec->odptr)->fm_mn.multi))
#define CURfield() (((forminfo *) Cur_rec->odptr)->curfield)
#define CURffield() (objform_disp(DEVirt(((forminfo *) Cur_rec->odptr)->curfield), CURforminfo()))
#define SET_curfield(X) (((forminfo *) Cur_rec->odptr)->curfield) = X
#define CURpage() ((((forminfo *) Cur_rec->odptr)->curpage))
#define LASTpage() ((((forminfo *) Cur_rec->odptr)->lastpage))
#define NUMSTR(X) (strcpy(Field_str + 1, itoa((long)X, 10)), Field_str)	/* abs k16 */

extern int Mouse_row;		/* Row offset of the mouse */
extern int Mouse_col;		/* Column offset of the mouse */
extern int Toggle;		/* when to "toggle" field choices (if_init.c) */

#define NX_ANY		0	/* pseudo flag */
#define NX_NOCUR	1
#define NX_ADVANCE	2

extern char *shrink_str();
extern char *expand();
extern char *getaltenv();
extern struct actrec *ar_create(), *ar_current();

static void chg_curfield();
static int objform_close();
static int objform_reinit();
static int objform_reread();
static int objform_current();
static int objform_noncur();
static int objform_ctl();
static int objform_stream();
static int fld_ck();
static int is_valid();
static struct fm_mn parse_form();

static struct actrec *Cur_rec;		/* current activation record */
static char *Equal = "=";
static char *Field_str = "F000";

#define QUERY -1
#define TOOBIG 1000
#define TOOSMALL -1000

/*
 * Returns the virtual index of the given actual field number ........
 *
 * The ACTUAL number is the order that the field appears in the form's
 * definition file.
 *
 * The VIRTUAL number is the index into the VISIBLE array of fields
 * (i.e., the subset of ACTUAL fields that contains only those fields
 * that appear on the "current page" or whose "show" descriptor = "true").
 */
int
virt(i)
register int i;
{
    register int j;
    int	lcv;

    lcv = NUMvis();
    for (j = 0; j < lcv; j++)
	if (DEVirt(j) == i)
	    return(j);
    return(0);		/* not exactly right but better than garbage.. */
                        /* ..since no one checks the return value */
}

/*
** Starting with start, recalculate the values until they are
** all set.  This works by faking out each value into being
** a control sequence and then substituting the real value for
** the control sequence
*/
int
redo_vals(start)
int start;
{
    int changed;
    register char *envbuf;
    register int i;
    char *hold1, *hold2;
    char buf[BUFSIZ];
    int	lcv;

    upseqno(CURform());

    envbuf = buf;
    lcv = NUMflds();
    for (i = start; i < lcv; i++) {
	strcpy(envbuf, NUMSTR(i + 1));
	strcat(envbuf, "=\001");
	strcat(envbuf, NUMSTR(i + 1));
	putAltenv(envbuf);
    }

    changed = FALSE;
    lcv = NUMflds();
    for (i = start; i < lcv; i++) {
	int dofree, maxamt, amt;

	dofree = 0;
	hold1 = multi_eval(CURform(), i, FM_VALUE);
	maxamt = BUFSIZ - strlen(NUMSTR(i + 1)) - 2;
	if ((amt = strlen(hold1)) > maxamt) { 
	    /*
	     * Value is greater than 1K so malloc 
	     * enough space to hold it. 
	     */
	    maxamt = amt + strlen(NUMSTR(i + 1)) + 2;
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
	strcpy(envbuf, NUMSTR(i + 1));
	changed |= strcmp(hold1, (hold2 = getaltenv(VALS(), envbuf)) ?
			  hold2 : nil) == 0;
	strcat(envbuf, Equal);
	strncat(envbuf, hold1, maxamt); 
	putAltenv(envbuf);
	putaltenv(&VALS(), envbuf);
	if (dofree)		/* if buffer was malloc'd, free it */
	    free(envbuf);
    }
    while (changed) {
	changed = FALSE;
	lcv = NUMflds();
	for (i = start; i < lcv; i++) {
	    register char *p;
	    int dofree, amt, maxamt;

	    dofree = 0;
	    envbuf = buf;
	    strcpy(envbuf, NUMSTR(i + 1));
	    hold1 = getaltenv(VALS(), envbuf);
	    for (p = NULL; p = strchr(hold1, '\001'); )
		*p = '$';
	    if (!p)
		continue;
	    hold2 = expand(hold1);
	    maxamt = BUFSIZ - strlen(NUMSTR(i + 1)) - 2;
	    if ((amt = strlen(hold2)) > maxamt) { 
		/*
		 * Value is greater than 1K so malloc 
		 * enough space to hold it. 
		 */
		maxamt = amt + strlen(NUMSTR(i + 1)) + 2;
		if ((envbuf = (char *) malloc(maxamt)) == NULL)
		    fatal(NOMEM, nil); 
		strcpy(envbuf, NUMSTR(i + 1));
		dofree++;
	    }
	    else {
		/*
		 * ... otherwise, use static 1K buffer
		 */
		dofree = 0;
	    }
	    strcat(envbuf, Equal);
	    strncat(envbuf, hold2, maxamt); 
	    changed = TRUE;
	    free(hold2);
	    putaltenv(&VALS(), envbuf);
	    putAltenv(envbuf);
	    if (dofree)
		free(envbuf);
	}
    }
    return (0);
}

/*
** Returns the current value of the field, fieldno.
*/
char *
curval(fieldno)
int fieldno;
{
	return(getaltenv(VALS(), NUMSTR(fieldno + 1)));
}

/*
** Figure out which fields are on the screen as decided by the show
** function values.
*/
int 
fm_vislist(ptr)
forminfo *ptr;
{
    int i, num;
    struct fm_mn *fm_mn;
    char *page;
    int	lcv;

    fm_mn = &(ptr->fm_mn);
    if (!ptr->visible)  {
	ptr->slks = (int *) array_create(sizeof(int),array_len(fm_mn->multi));
	ptr->visible = (int *) array_create(sizeof(int), NUMflds());
    }
    else  {
	array_trunc(ptr->visible);
	array_trunc(ptr->slks);
    }

    lcv = NUMflds();
    NUMactive() = 0;
    for (i = 0; i < lcv; i++) {
	if (atoi(multi_eval(fm_mn, i, FM_BUTT))) {
	    /*
	     * SLK definition
	     */
	    if (multi_eval(fm_mn, i, FM_SHOW))
		ptr->slks = (int *) array_append(ptr->slks, (char *) &i);
	}
	else {
	    /*
	     * FIELD definition
	     */
	    page = multi_eval(fm_mn, i, FM_PAGE);
	    num = atoi(page);
	    if (num > LASTpage())
		LASTpage() = num; /* record last page */
	    /*
	     * Only make visible fields on the CURRENT 
	     * page ...
	     */ 
	    if ((num <= 0) || !page)
		continue;
	    else if ((num == CURpage()) ||
		     (strcmp(page, "all") == 0) || (*page == '*')) {
		/*
		 * add field to visible list ...
		 * keep track of the number of active fields
		 * for this page ...
		 */
		ptr->visible = (int *) array_append(ptr->visible, &i);
		if (multi_eval(fm_mn, i, FM_SHOW) &&
		    (!multi_eval(fm_mn, i, FM_INACTIVE)))
		    NUMactive()++;
	    }
	}
    }
    return (0);
}


static int
objform_reinit(a)
struct actrec *a;
{
    Cur_rec = a;
    if (sing_eval(CURform(), FM_REREAD))
	return(objform_reread(a));
    return(SUCCESS);
}

/*
** A front end to parser() which will set up most of the defaults for
** a form.
*/
static struct fm_mn
parse_form(flags, info_or_file, fp)
int flags;
char *info_or_file;
FILE *fp;
{
    struct fm_mn fm_mn;

    fm_mn.single.attrs = NULL;
    fm_mn.multi = NULL;
    filldef(&fm_mn.single, Fm_tab, FM_KEYS);
    parser(flags, info_or_file, Fm_tab, FM_KEYS, &fm_mn.single,
	   Fm_fld_tab, FM_FLD_KEYS, &fm_mn.multi, fp);
    return(fm_mn);
}

/*
** Read the form object indicated by this actrec, if a->id > 0
** then the object is being reread.
*/
static int
objform_reread(a)
struct actrec *a;
{
    extern struct slk Defslk[MAX_SLK + 1];
    extern struct slk Formslk[];
    forminfo *fi;
    register int i, but;
    char *label, *intr, *onintr, *get_def();
    int	  lcv;
    FILE *fp = NULL;

    Cur_rec = a;
    fi = CURforminfo();

    /* make sure file exists and is readable (if there is a file) 
     * The "flags" say if a->path is  the information
     * itself or the file of where the information sits.  abs k15
     */
    if (!(fi->flags & INLINE))
	if ((fp = fopen(a->path, "r")) == NULL)
	{
	    if (a->id >= 0)	/* if frame is already posted */
		warn(NOT_UPDATED, a->path);
	    else
		warn(FRAME_NOPEN, a->path);
	    return(FAIL);
	}
    if (a->id >= 0)
	freeitup(CURform());	/* if posted then free it old one */
    fi->fm_mn = parse_form(fi->flags, a->path, fp);	/* abs k14.0 */
    if ((CURform())->single.attrs == NULL) {
#ifdef _DEBUG4
	_debug4(stderr, "Couldn't parse it\n");
#endif
	return(FAIL);
    }
    (CURform())->seqno = 1;
    if (PTRS())
	free(PTRS());
    if (NUMflds() && (PTRS() = (char **) calloc(NUMflds(), sizeof(char *))) == NULL)
	fatal(NOMEM, nil);
    lcv = NUMflds();
    for (i = 0; i < lcv; i++)
	PTRS()[i] = (char *) NULL;

    fi->visible = NULL;		/* initialize array of visible fields */
    fi->slks = NULL;		/* initialize array of object's SLKS */
    redo_vals(0);		/* initialize field values */
    fm_vislist(CURforminfo());	/* set up visible field list */
    if (a->id < 0)
	SET_curfield(-1);

    /*
     * If "init=false" or Form is empty then cleanup
     */
    if (!sing_eval(CURform(), FM_INIT) || (NUMactive() <= 0))
    {
	if (a->id >= 0)	       /* form is already posted */
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
	    sing_eval(CURform(), FM_CLOSE);
	    objform_noncur(a, TRUE); /* takes ARGs out of Altenv */
	    freeitup(CURform());
	    return(FAIL);
	}
    }

    /*
     * update the interrupt descriptors in the activation rec
     */
    ar_ctl(a, CTSETINTR, get_sing_def(CURform(), FM_INTR), NULL, NULL, NULL, NULL, NULL);
    ar_ctl(a, CTSETONINTR, get_sing_def(CURform(), FM_ONINTR), NULL, NULL, NULL, NULL, NULL);
    /*
     * Set up object specific SLK array
     */
    set_top_slks(Formslk);
    memcpy((char *)a->slks, (char *)Defslk, sizeof(Defslk));
    lcv = array_len(fi->slks);
    for (i = 0; i < lcv; i++) {
	but = atoi(multi_eval(CURform(), fi->slks[i], FM_BUTT)) - 1;
	if (but <  0 || but >= MAX_SLK)	/* abs */
	    continue;
	label = multi_eval(CURform(), fi->slks[i], FM_NAME);
	intr  = get_def(CURform(),fi->slks[i], FM_INTR);
	onintr  = get_def(CURform(),fi->slks[i], FM_ONINTR);
	set_obj_slk(&(a->slks[but]), label, TOK_SLK1 + but, intr, onintr);
    }

    if (a->id >= 0)		/* go to first field, first page */
    {
	vt_current(form_ctl(a->id, CTGETVT));
	CURpage() = 1;
	fm_vislist(CURforminfo());
	form_ctl(a->id, CTSETPAGE, TRUE, 1, fi->lastpage);
	nextfield(0, 0, 1, NX_ANY);	
	form_ctl(a->id, CTSETDIRTY);

	/*          used to just  go to first field of current page..
		    ar_ctl(a, CTCLEARWIN, 0, NULL, NULL, NULL, NULL, NULL); 
		    nextfield(0, 0, 1, NX_ANY);	
		    form_ctl(a->id, CTSETDIRTY);
		    */
    }
    (void) ar_ctl(Cur_rec, CTSETMSG, FALSE, NULL, NULL, NULL, NULL, NULL); /* was AR_cur.  abs k15 */
    return(SUCCESS);
}

/*
** Frees up the structures and evaluates the "close" function.
*/
static int 
objform_close(a) 
struct actrec *a; 
{ 
    register int i, lcv;
    char *p, *strchr();

    Cur_rec = a;
    form_close(a->id);		/* remove the form FIRST */ 
    copyAltenv(VALS());
    sing_eval(CURform(), FM_CLOSE); /* evaluate close function */
    objform_noncur(a, FALSE);       /* remove ARGs from Altenv */

    /*
     * Free information IN the forminfo structure
     */
    freeitup(CURform());	/* the form parse table */
    if (PTRS())			/* holdptrs array */
	free(PTRS());
    lcv = array_len(VALS());
    for (i = 0; i < lcv; i++) {	/* form specific variables */
	char namebuf[BUFSIZ];	/* (e.g., F1, F2, .... ) */

	if (p = strchr(VALS()[0], '='))
	    *p = '\0';
	strcpy(namebuf, VALS()[0]);
	if (p)
	    *p = '=';
	delaltenv(&VALS(), namebuf);
    }
    array_destroy(VALS());	/* variables array */
    array_destroy(((forminfo *)a->odptr)->slks); /* visible SLKS */
    array_destroy(((forminfo *)a->odptr)->visible); /* visible fields */

    /*
     * Free information in the activation record
     */
    free(a->odptr);		/* the forminfo structure */
    free(a->slks);		/* object specific SLKS */
    free(a->path);		/* form definition file */

    return(SUCCESS);
}

/*
** Takes this objects's information out of the major altenv.
*/
static int 
objform_noncur(a, all) 
struct actrec *a; 
bool all;
{
    register int i;
    register char *p;
    int	lcv;

    Cur_rec = a;
    lcv = array_len(VALS());
    for (i = 0; i < lcv; i++) {
	char namebuf[BUFSIZ];

	if (p = strchr(VALS()[i], '='))
	    *p = '\0';
	strcpy(namebuf, VALS()[i]);
	if (p)
	    *p = '=';
	delAltenv(namebuf);
    }
    if (all)
	return(form_noncurrent());
    else
	return(SUCCESS);
}

/*
** Sets up the major alternate environment based on the values
** for the altenv that pertains to this object.
*/
static int 
objform_current(a) 
struct actrec *a; 
{
    char *choice;
    static char *Form_Choice = "Form_Choice";

    /*
     * Make the form "current" and make the first field
     * current if this is the first time.
     */
    Cur_rec = a;
    form_current(a->id);
    if (CURfield() == -1)
	nextfield(0, 0, 1, NX_ANY);
    /*
     * Initialize the field with the value of variable "Form_Choice"
     * (variable holds the selected item(s) from a choices menu)
     */
    if (choice = getAltenv(Form_Choice)) {
	copyAltenv(VALS());
	if (set_curval(strsave(choice)) == SUCCESS) {
	    fm_vislist(CURforminfo());
	    redo_vals(CURfield() + 1);
	    form_ctl(Cur_rec->id, CTSETDIRTY);
	    if (multi_eval(CURform(), CURfield(), FM_AUTOADVANCE))
		nextfield(atoi(CURattr(CURfield(),FM_FROW)->cur),
			  atoi(CURattr(CURfield(),FM_FCOL)->cur),
			  1, NX_NOCUR);
	}
	delAltenv(Form_Choice);
    }
    else
	copyAltenv(VALS());

    set_form_field(a->id, CURfield());
    return(SUCCESS);
}

/*
** Sets up the major alternate environment based on the values
** for the altenv that pertains to this object. 
** Does min neccessary to make object "temporarily" current,
** invisible to the user.
*/
static int 
objform_temp_cur(a) 
struct actrec *a; 
{
    /*
     * Make the form "current" 
     */
    Cur_rec = a;
    form_current(a->id);
    if (CURfield() == -1)
	nextfield(0, 0, 1, NX_ANY);
    copyAltenv(VALS());

    return(SUCCESS);
}

/*
** Evaluates many of the fields to return a form structure that includes
** name, value, their positions, editing capabilities and a structure
** that is held here and is used by the low-level form code to pertain
** to each field.
*/
static formfield
objform_disp(n, fi)
int n;
forminfo *fi;
{
    register int i;
    struct fm_mn *ptr;
    formfield m;

    ptr = &(fi->fm_mn);
    if (n >= (int)NUMvis() || n < 0) /* abs k17 */
	m.name = NULL;
    else
    {
	i = DEVirt(n);
	m.name = multi_eval(ptr, i, FM_NAME);
	m.value = (char *) curval(i);
	m.frow = atoi(multi_eval(ptr, i, FM_FROW));
	m.fcol = atoi(multi_eval(ptr, i, FM_FCOL));
	m.nrow = atoi(multi_eval(ptr, i, FM_NROW));
	m.ncol = atoi(multi_eval(ptr, i, FM_NCOL));
	m.rows = atoi(multi_eval(ptr, i, FM_ROWS));
	m.cols = atoi(multi_eval(ptr, i, FM_COLS));
	if (multi_eval(ptr, i, FM_INACTIVE))
	    m.flags = I_FANCY;
	else
	    m.flags = I_BLANK|I_FANCY|I_FILL;
	if (!multi_eval(ptr, i, FM_SHOW))
	    m.flags |= I_NOSHOW;
	m.ptr = PTRS() + i;
	if (multi_eval(ptr, i, FM_WRAP))
	    m.flags |= I_WRAP;
	if (multi_eval(ptr, i, FM_SCROLL))
	    m.flags |= I_SCROLL;
	if (LASTpage() > 1)
	    m.flags |= I_NOPAGE;
	if (multi_eval(ptr, i, FM_NOECHO)) {
	    m.flags |= I_INVISIBLE;
	    m.flags &= ~(I_BLANK | I_FILL);
	}
	if (multi_eval(ptr, i, FM_AUTOADVANCE))
	    m.flags |= I_AUTOADV;

	if (m.cols <= 0  || m.rows <= 0 || m.frow < 0 || m.fcol < 0)
	{			/* field not active */
	    m.cols = 1;
	    m.rows = 1;
	    m.frow = -1;	/* title bar line */
	    m.fcol = 0;
	    m.flags = I_NOEDIT;
	    m.value = "";
	}
    }
    return(m);
}

/*
** Evaluates the help field and returns a token for it.
*/
static token
objform_help(rec)
struct actrec *rec;
{
    token make_action();

    Cur_rec = rec;
    return(make_action(sing_eval(CURform(), FM_HELP)));
}

/*
** Forms have no arguments to give, so that must fail.  All else is
** passed on.
*/
static int
objform_ctl(rec, cmd, arg1, arg2, arg3, arg4, arg5, arg6)
struct actrec *rec;
int cmd;
int arg1, arg2, arg3, arg4, arg5, arg6;
{
    Cur_rec = rec;
    switch (cmd)
    {
    case CTGETARG:
	return(FAIL);
    case CTSETMSG:
	if (arg1 == TRUE) {
	    /* 
	     * if arg1 == TRUE then the frame message was
	     * generated "externally" (i.e., via the message
	     * built-it).  Update the "framemsg" descriptor
	     * accordingly.
	     */
	    char *newmsg, *get_mess_frame();

	    newmsg = get_mess_frame();
	    set_single_default(CURform(), FM_FRMMSG, newmsg);
	}
	else 
	    mess_frame(sing_eval(CURform(), FM_FRMMSG));
	return(SUCCESS);
    case CTSETLIFE:
    {
	char *life;

	/* used CURform, Cur_rec before F15.  abs */
	life = sing_eval((&(((forminfo *) rec->odptr)->fm_mn)), FM_LIFE);
	setlifetime(rec, life);
	return(SUCCESS);
    }
    default:
	return(form_ctl(rec->id, cmd, arg1, arg2, arg3, arg4, arg5, arg6));
    }
}

/*
** Calls path_to_ar() and nextpath_to_ar() to decide whether this is a
** reopen or a first open.  If it is the latter, it sets up the actrec
** and calls ar_create().
*/
int
IF_ofopen(args)
register char **args;
{
    register int i;
    struct actrec a, *first_rec, *path_to_ar(), *nextpath_to_ar();
    extern struct slk Defslk[MAX_SLK + 1];
    int startrow, startcol;
    int do_inline;
    int type;
    char *life;
    char *begcol, *begrow;
    register struct fm_mn *fm_mn;
    forminfo *fi;
    char envbuf[6];

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
	char *env;

	strcpy(envbuf, "ARG1");
	for (i = do_inline ? 2 : 1;
	     (env = getaltenv(VALS(), envbuf)) && args[i];
	     envbuf[3]++, i++)
	    if (strcmp(args[i], env))
		break;
	if (!args[i] && !env) {
	    ar_current(Cur_rec, TRUE); /* abs k15 */
	    return(SUCCESS);
	}
	Cur_rec = nextpath_to_ar(Cur_rec);
	if (Cur_rec == first_rec)
	    break;
    }
    fi = (forminfo *)new(forminfo);
    fi->flags = do_inline ? INLINE : 0;
    fi->mulvals = NULL;
    fm_mn = &(fi->fm_mn);
    a.odptr = (char *) fi;
    a.id = -1;
    fm_mn->single.attrs = NULL;
    if (do_inline)
	a.path = strsave(args[1]);
    else
	a.path = strsave(args[0]);
    if ((a.slks = (struct slk *) malloc(sizeof(Defslk))) == NULL)
	fatal(NOMEM, nil);
    a.fcntbl[AR_CLOSE] = objform_close;
    a.fcntbl[AR_HELP] = (int (*)())objform_help; /* added cast abs */
    a.fcntbl[AR_REREAD] = objform_reread;
    a.fcntbl[AR_REINIT] = objform_reinit;
    a.fcntbl[AR_CURRENT] = objform_current;
    a.fcntbl[AR_TEMP_CUR] = objform_temp_cur; /* abs k15 */
    a.fcntbl[AR_NONCUR] = objform_noncur;
    a.fcntbl[AR_CTL] = objform_ctl;
    a.fcntbl[AR_ODSH] = objform_stream;
    Cur_rec = &a;
    CURpage() = 1;
    setupenv(fi->flags, args, &VALS());
    if (objform_reread(&a) == FAIL)
	return(FAIL);
    /*		return(NULL);   abs */
    type = 0;
    life = sing_eval(CURform(), FM_LIFE);
    begrow = sing_eval(fm_mn, FM_BEGROW);
    begcol = sing_eval(fm_mn, FM_BEGCOL);
    life_and_pos(&a, life, begrow, begcol, &startrow, &startcol, &type);
    a.id = form_default(shrink_str(sing_eval(fm_mn, FM_TITLE), MAX_TITLE),
			type, startrow, startcol, objform_disp, (char *)fi);
    if (sing_eval(fm_mn, FM_ALTSLKS))
	a.flags = AR_ALTSLKS | AR_NORESHAPE;
    else
	a.flags = AR_NORESHAPE;
    if (a.id == FAIL)
	return(FAIL);
    form_ctl(a.id, CTSETPAGE, FALSE, CURpage(), LASTpage()); 
    return((int) ar_current(Cur_rec = (struct actrec *) ar_create(&a), FALSE));
}

/*
** Set the value of the current field.
*/
int
set_curval(str)
char *str;
{
    char *s;
    char *tmp=NULL;
    char buf[BUFSIZ];
    char *envbuf;

    strcpy(buf, NUMSTR(CURfield() + 1));
    form_ctl(Cur_rec->id, CTGETARG, &tmp);
    if (strcmp(str, s = getaltenv(VALS(), buf)) || strcmp(str,tmp)) {
	/*
	 * If the current value and the passed value are
	 * different then add the passed value (str) to
	 * the environment
	 */
	int dofree, maxamt, amt;

	dofree = 0;
	maxamt = BUFSIZ - strlen(NUMSTR(CURfield() + 1)) - 2;
	if ((amt = strlen(str)) > maxamt) { 
	    /*
	     * Value is greater than 1K so malloc 
	     * enough space to hold it. 
	     */
	    maxamt = amt + strlen(NUMSTR(CURfield() + 1)) + 2;
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
	set_cur(CURform(), CURfield(), FM_VALUE, strsave(str));
	strcpy(envbuf, NUMSTR(CURfield() + 1));
	strcat(envbuf, Equal);
	strncat(envbuf, str, maxamt); 
	putaltenv(&VALS(), envbuf);
	putAltenv(envbuf);
	if (dofree)
	    free(envbuf);
	return(SUCCESS);
    }
    return(FAIL);
}

static int chk_page();

/*
 * CHK_FORM returns the actual number of the FIRST field that
 * is invalid ....
 */ 
static int
chk_form()
{
    register int n, page, fldnum;
    int savefield, savepage, retval;

    /*
     * Save current form page/field
     */
    savepage = CURpage();
    savefield = CURfield();

    /*
     * if the current page has an invalid field then return
     * its field number
     */
    if ((fldnum = chk_page(CURpage())) >= 0) {
	SET_curfield(savefield);
	return(fldnum);
    }

    /*
     * For each page of the form, scan the list of
     * fields and validate those that were not touched.
     * (Start with the page AFTER the current page and wrap around) 
     */
    retval = -1;
    page = CURpage();
    for (n = 1; n < LASTpage(); n++) {
	page = (page % LASTpage()) + 1;
	if ((fldnum = chk_page(page)) >= 0) {
	    retval = fldnum;
	    break;
	}
    }

    /*
     * restore current form page/field
     */
    if (CURpage() != savepage) { 
	CURpage() = savepage; 
	fm_vislist(CURforminfo()); /* create new visible list */
    }
    SET_curfield(savefield);
    return(retval);
}

/*
 * CHK_PAGE will make sure that all visible fields of "page" are valid.
 */
static int
chk_page(page)
int page;
{
    register int i, j, lcv;
    register struct attribute *attr;

    if (page != CURpage()) {	/* compute new visible list? */
	CURpage() = page; 
	fm_vislist(CURforminfo());
    }
    for (i = 0, lcv = NUMvis(); i < lcv; i++) {
	j = DEVirt(i);
	/*
	 * check the flags of the appropriate "attribute"
	 * structure to see if the field has ever been "touched"
	 * (visited) ...
	 */
	if (multi_eval(CURform(), j, FM_MENUO)) 
	    attr = CURattr(j, FM_MENUO);
	else
	    attr = CURattr(j, FM_VALID);
	if (multi_eval(CURform(), j, FM_SHOW) && attr &&
	    !(attr->flags & ATTR_TOUCHED)) {
	    attr->flags |= ATTR_TOUCHED;
	    SET_curfield(j);
	    if (fld_ck(j) != SUCCESS) 
		return(j);
	}
    }
    return(-1);
}

/*
** Given a form_field structure, it will get the value of the current
** field and see if it is A) different and B) valid.  If the value is
** different all sorts of recalculation must go on (the show function,
** all the new values).  If the value is valid, it returns SUCCESS,
** so that the function calling it can navigate or close.
*/
int
fld_get_ck(form_field)
formfield *form_field;
{
    char *s;
    char buf[BUFSIZ];

    if ( form_field->flags & I_SCROLL )
	s = NULL;
    else
	s = (form_field->rows * form_field->cols >= BUFSIZ) ? NULL : buf;
    form_ctl(Cur_rec->id, CTGETARG, &s);
    if (set_curval(s) == SUCCESS) {
	redo_vals(CURfield() + 1);
	fm_vislist(CURforminfo());
	form_ctl(Cur_rec->id, CTSETDIRTY);
    }
    return(is_valid(s));
}

/*
 * FLD_IS_VALID will check to see if a field is valid by retrieving, and
 * not computing, the value of "$FN" ...
 */ 
static int
fld_ck(i)
int i;
{
    char *s;
    char buf[BUFSIZ];

    strcpy(buf, NUMSTR(i + 1));
    s = getaltenv(VALS(), buf);
    return(is_valid(s));
}

static int 
is_valid(s)
char *s;
{
    int ret;
    char *str;

    ret = SUCCESS;
    if (!multi_eval(CURform(), CURfield(), FM_VALID)) {
	if ((str=multi_eval(CURform(), CURfield(), FM_VALMSG)) && *str) 
	    mess_temp(str);
	else
	    warn(VALID, s);
	mess_lock();
	ret = FAIL;
    }
    else if (multi_eval(CURform(), CURfield(), FM_MENUO)) {
	char **list;

	if ((list = (char **) multi_eval(CURform(), CURfield(), FM_RMENU)) &&
	    *list != '\0')
	{
	    int i, lcv;

	    lcv = array_len(list) - 1;
	    for (i = 1; i < lcv; i++)
		if (strcmp(s, list[i]) == 0)
		    break;
	    if (i == lcv) {
		if ((str = multi_eval(CURform(), CURfield(), FM_VALMSG)) && *str) 
		    mess_temp(str);
		else
		    warn(VALID, s);
		mess_lock();
		ret = FAIL;
	    }
	}
	else {
	    if ((str = multi_eval(CURform(), CURfield(), FM_VALMSG)) && *str) 
		mess_temp(str);
	    else
		warn(VALID, s);
	    mess_lock();
	    ret = FAIL;
	}
    }
    return(ret);
}

/*
** Move to another field.
*/
static void
chg_curfield(virtnum)
int virtnum;
{
    int num;

    num = DEVirt(virtnum);
    if (CURfield() == num)
	return;
    SET_curfield(num);
    set_form_field(Cur_rec->id, num);
}

/*
** Calculates the next field to go to.  Mode is either positive or
** negative 1 for forward and backward navigation.  Canbecur
** decides whether the current field should be eliminated from the
** choices for nextfield().
*/
int
nextfield(currow, curcol, mode, flags)
int currow;
int curcol;
register int mode;
int flags;
{
    register int i, j, frow, fcol;
    int curi, rows, cols;
    int newcurrow, newcurcol;
    int leastcol, leastrow, leasti;
    struct fm_mn *curf;
    int no_current, page_advance;
    int	lcv;
    int f_error, oldfield, oldpage;			/* abs */
    int try;						/* abs k17 */

    oldfield = CURfield();	/* abs */
    oldpage  = CURpage();	/* abs */
    no_current = page_advance = 0;
    if (flags & NX_NOCUR)
	no_current++;
    if (flags & NX_ADVANCE)
	page_advance++;
    
    curf = CURform();
    leastrow = mode * TOOBIG;
    leastcol = mode * TOOBIG;
    newcurrow = mode * TOOBIG;
    newcurcol = mode * TOOBIG;
    curi = -1;
    leasti = -1;
    lcv = NUMvis();
    for (i = 0; i < lcv; i++)
    {
	/* 
	 * First eliminate fields that can be eliminated 
	 *
	 * IF ...
	 *	1. field is inactive/non showable   OR
	 *	2. field is current and isn't eligible  OR
	 * 	3. either rows or cols <= 0	OR
	 * 	4. frow or fcol < 0
	 *
	 * THEN skip the field 
	 *
	 * NOTE: The reason that fields that do not satisfy
	 *	 (3) and (4) are visible is that one can
	 * 	 have a field name with no field associated
	 *	 with it .... (ETI does not have such a
	 *	 field/field-name association)
	 *
	 */ 
	j = DEVirt(i);
	if (multi_eval(curf, j, FM_INACTIVE) ||
	    (!multi_eval(curf, j, FM_SHOW)) ||
	    ((j == CURfield()) && no_current))
	      continue;
	
	rows = atoi(multi_eval(curf, j, FM_ROWS));
	cols = atoi(multi_eval(curf, j, FM_COLS));
	frow = atoi(multi_eval(curf, j, FM_FROW));
	fcol = atoi(multi_eval(curf, j, FM_FCOL));
	if (rows <= 0 || cols <= 0 || frow < 0 || fcol < 0)
	    continue;
	
	/*
	 * Determine whether the "ith" visible field is next
	 * A few comments here would help !!!
	 */
	if ((mode * frow >= mode * currow) && (mode * frow <= mode * newcurrow))
	{
	    if (((mode * frow > mode * currow) ||
		 (mode * fcol >= mode * curcol)) &&
		((mode * frow < mode * newcurrow) ||
		 (mode * fcol < mode * newcurcol)))
	    {
		newcurcol = fcol;
		newcurrow = frow;
		curi = i;
		continue;
	    }
	}
	if ((mode * frow <= mode * leastrow))
	{
	    if ((mode * frow < mode * leastrow) ||
		(mode * fcol <= mode * leastcol))
	    {
		leastcol = fcol;
		leastrow = frow;
		leasti = i;
	    }
	}
    } /* end for i=0.. */
    if ((newcurrow == mode * TOOBIG) && (newcurcol == mode * TOOBIG))
    {
	/*
	 * User has reached a page boundary (i.e., there is no 
	 * next/previous field on the current page)
	 */ 
	if (LASTpage() != 1 && page_advance)
	{
	    /*
	     * If this is a multi-page form AND the page should be
	     * automatically advanced on page boundaries then ...
	     */
	    if (mode < 0) 		/* prev field */
	    {   /* find the prev page  with visible fields abs k17 */
		f_error = TRUE;				/* abs k17 */
		for (try = LASTpage(); try > 1; try--)	/* abs k17 */
		{					/* abs k17 */
		    if (CURpage() != 1)
			CURpage()--;
		    else
			CURpage() = LASTpage();
		    fm_vislist(CURforminfo());
		    if ((int)NUMvis() > 0) 		/* abs k17 */
		    {					/* abs k17 */
			f_error = FALSE; 		/* abs k17 */
			break;				/* abs k17 */
		    }					/* abs k17 */
		}					/* abs k17 */
		
		if (!f_error)				/* abs k17 */
		    f_error = form_ctl(Cur_rec->id, CTSETPAGE, TRUE, CURpage(),
				       LASTpage());
		if (f_error)
		{
		    CURpage() = oldpage;
		    CURfield() = oldfield;
		    fm_vislist(CURforminfo());
		    form_ctl(Cur_rec->id, CTSETPAGE, TRUE, oldpage, LASTpage());
		    mess_temp("Cannot display the previous page: page may be too large");
		    mess_lock();
		    return (0);
		}
		CURfield() = -1;	/* abs */
		nextfield(1000, 1000, -1, NX_ANY);
		return (0);
	    }
	    else  			/* next field */
	    {   /* find the next page  with visible fields abs k17 */
		f_error = TRUE;				/* abs k17 */
		for (try = LASTpage(); try > 1; try--)	/* abs k17 */
		{					/* abs k17 */
		    if (CURpage() != LASTpage())
			CURpage()++;
		    else
			CURpage() = 1;
		    fm_vislist(CURforminfo());
		    if ((int)NUMvis() > 0)	 	/* abs k17 */
		    {					/* abs k17 */
			f_error = FALSE; 		/* abs k17 */
			break;				/* abs k17 */
		    }					/* abs k17 */
		}					/* abs k17 */
		
		if (!f_error)				/* abs k17 */
		    f_error = form_ctl(Cur_rec->id, CTSETPAGE, TRUE, CURpage(),
				       LASTpage());
		if (f_error)
		{
		    CURpage() = oldpage;
		    CURfield() = oldfield;
		    fm_vislist(CURforminfo());
		    form_ctl(Cur_rec->id, CTSETPAGE, TRUE, oldpage, LASTpage());
		    mess_temp("Cannot display the next page: page may be too large");
		    mess_lock();
		    return (0);
		}
		CURfield() = -1;	/* abs */
		nextfield(0, 0, 1, NX_ANY);
		return (0);
	    }
	}
	else
	{
	    /*
	     * simply wrap around to the top/bottom of the page 
	     */
	    curi = leasti;
	}
    }
    if (curi < 0)
	curi = virt(CURfield());	/*  zero or one active field */

    chg_curfield(curi);
    return (0);
}

token
seek_field(row, col)
int row, col;
{
    register int i, j, lcv;
    struct fm_mn *curf;
    int frow, fcol, foundfield;

    curf = CURform();
    lcv = NUMvis();
    foundfield = -1;
    /*
     * since row,col is 0,0 use 1,1 scale for offset 
     */ 
    for (i = 0; i < lcv; i++) {
	/*
	 * First eliminate fields that can be eliminated 
	 */ 
	j = DEVirt(i);
	if ((multi_eval(curf, j, FM_SHOW)) &&
	    ((frow = atoi(multi_eval(curf, j, FM_FROW))) <= row) &&
	    (atoi(multi_eval(curf, j, FM_ROWS)) + frow > row) &&
	    ((fcol = atoi(multi_eval(curf, j, FM_FCOL))) <= col) &&
	    (atoi(multi_eval(curf, j, FM_COLS)) + fcol > col)) {
	    foundfield = i;
	    break;
	}
    }
    if (foundfield < 0 || multi_eval(curf, foundfield, FM_INACTIVE))
	return(TOK_BADCHAR);
    else {
	chg_curfield(foundfield);
	return(TOK_NOP);
    }
}

/* return values */
#define TOGGLE		1
#define LONGLIST	2
#define ACTION		3
 
/*
** Checks an "rmenu" to see if it is a small list (toggle choices 
** if less than "threshold" members), a large list or a command. 
*/
int
testlist(list)
char **list;
{
    if (list[0][0] == '{') {
	if (((int)array_len(list) - 2) <= Toggle) /* account for "{ }" */
	    return(TOGGLE);
	return(LONGLIST);
    }
    return(ACTION);
}

char *Choice_list[3] =
{
	"OPEN",
	"MENU",
	"-i"
};

/*
** Turns an rmenu field into a command.
*/
token
rmenuaction(list)
register char **list;
{
    extern char	*Args[];
    extern int	Arg_count;
    int	lcv;

    if (testlist(list) == LONGLIST) {
	register int i;
	register IOSTRUCT *out;
	/*		char **help;
	 */
	out = io_open(EV_USE_STRING, NULL);

	putastr("menu=Choices\n", out);
	putastr("lifetime=shortterm\n", out);

	/*		Shouldn't evaluate help when choices is pressed!! abs.
	 *		putastr("Help=", out);
	 *		help = (char **) sing_eval(CURform(), FM_HELP);
	 *		lcv = array_len(help);
	 *		for (i = 0; i < lcv; i++) {
	 *			putastr(help[i], out);
	 *			putac(' ', out);
	 *		}
	 *		putac('\n', out);
	 */
	lcv = array_len(list) - 1;
	for (i = 1; i < lcv; i++) {
	    putac('\n', out);
	    putastr("name=\"", out);
	    putastr(list[i], out);
	    putastr("\"\n", out);
	    putastr("lininfo=\"", out);
	    putastr(list[i], out);
	    putastr("\"\n", out);
	    putastr("action=`set -l Form_Choice=\"", out);
	    putastr(list[i], out);
	    putastr("\"`close", out);
	    putac('\n', out);
	    putac('\n', out);
	}
	putastr("name=\nbutton=1\naction=badchar\n", out);
	putastr("name=\nbutton=2\naction=badchar\n", out);
	putastr("name=\nbutton=4\naction=badchar\n", out);
	putastr("name=\nbutton=5\naction=badchar\n", out);
	putastr("name=\nbutton=7\naction=badchar\n", out);
	putastr("name=\nbutton=8\naction=badchar\n", out);

	for (Arg_count = 0; Arg_count < 3; Arg_count++) {
	    if (Args[Arg_count])
		free(Args[Arg_count]); /* les */

	    Args[Arg_count] = strsave(Choice_list[Arg_count]);
	}

	if (Args[Arg_count])
	    free(Args[Arg_count]); /* les */

	Args[Arg_count++] = io_string(out);
	io_close(out);

	if (Args[Arg_count])
	    free(Args[Arg_count]); /* les */

	Args[Arg_count] = NULL;
	return(TOK_OPEN);
    }
    return(setaction(list));
}

/*
** Processes characters after the editor.
*/
token
post_stream(t)
register token t;
{
    formfield form_field;
    char *str;
    char **list;
    int *slks;
    int i, len;
    int num, fnum;
    int nextflags, flag;
    char *s;
    int	lcv;
    int f_error;		/* abs */
    token make_action();

    nextflags = flag = 0;
    form_field = CURffield();
	
    s = NULL;
    if (t >= TOK_SLK1 && t <= TOK_SLK16) {
	slks = CURforminfo()->slks;
	num = t - TOK_SLK1 + 1;
	lcv = array_len(slks);
	for(i = 0; i < lcv; i++)
	    if (atoi(multi_eval(CURform(), slks[i], FM_BUTT)) == num) {
		form_ctl(Cur_rec->id, CTGETARG, &s);
		t = setaction(multi_eval(CURform(), slks[i], FM_ACTI));
		break;
	    }
    }
    switch(t) {
    case TOK_BPRESSED:
	return(TOK_NOP);	/* do nothing on a button press */ 
    case TOK_BRELEASED:
	return((token) seek_field(Mouse_row, Mouse_col));
    case TOK_OPTIONS:
	t = TOK_NOP;
	if (list = (char **) multi_eval(CURform(), CURfield(), FM_RMENU)) {
	    int i;
	    char *str;

	    if ((str = multi_eval(CURform(), CURfield(), FM_CHOICEMSG)) && *str) {
		mess_temp(str);
		mess_lock();	/* don't overwrite it !!! */
	    }
	    len  = array_len(list);
	    if (len == 0 || (len <= 2 && list[0][0] ==  '{')) {
		if (!(str && *str))
		    mess_temp("There are no choices available");
	    }
	    else if (testlist(list) == TOGGLE) {
		char *s;

		s = getaltenv(VALS(), NUMSTR(CURfield() + 1));
		len -= 2;
		list = list + 1;

		for (i = 0; i < len - 1; i++)
		    if (strcmp(s, list[i]) == 0)
			break;
		if (set_curval(strsave(list[(i + 1) % len])) == SUCCESS) {
		    fm_vislist(CURforminfo());
		    redo_vals(CURfield() + 1);
		    form_ctl(Cur_rec->id, CTSETDIRTY);
		}
	    }
	    else
		t = rmenuaction(list);
	}
	break;
    case TOK_RESET:
    {
	char *s = NULL;

	form_ctl(Cur_rec->id, CTGETARG, &s);
	de_const(CURform(), CURfield(), FM_VALUE);
	redo_vals(CURfield());
	fm_vislist(CURforminfo());
	form_ctl(Cur_rec->id, CTSETDIRTY);
	t = TOK_NOP;
	break;
    }
    case TOK_DONE:
	t = TOK_BADCHAR;
	if (fld_get_ck(&form_field) != SUCCESS)
	    t = TOK_NOP;
	else if ((fnum = chk_form()) >= 0) {
	    int page;

	    /*
	     * fnum is the actual (rather than the virtual)
	     * field num
	     */
	    page = atoi(multi_eval(CURform(), fnum, FM_PAGE));
	    if (page != CURpage()) {
		/*
		 * make the new page visible 
		 */
		CURpage() = page;
		fm_vislist(CURforminfo());
		form_ctl(Cur_rec->id, CTSETPAGE, TRUE, CURpage(), LASTpage()); 
	    }
	    chg_curfield(virt(fnum));
	    t = TOK_NOP;
	}
	else if (str = sing_eval(CURform(), FM_DONE))
	    t = make_action(str);
	else {
	    warn(VALID, "");
	    mess_lock();
	}
	break;
    case TOK_UP:
	nextflags |= NX_ADVANCE;
	/* fall through */
    case TOK_PREVIOUS:
    case TOK_BTAB:		/* added backtab mapping.  abs k16 */
	nextflags |= NX_NOCUR;
	if (fld_get_ck(&form_field) == SUCCESS)
	    nextfield(atoi(multi_eval(CURform(), CURfield(), FM_FROW)),
		      atoi(multi_eval(CURform(), CURfield(), FM_FCOL)),
		      -1, nextflags);
	else
	    set_form_field(Cur_rec->id, CURfield());
	t = TOK_NOP;
	break;
    case TOK_DOWN:
	nextflags |= NX_ADVANCE;
	/* fall through */
    case TOK_TIME:
    case TOK_SAVE:
    case TOK_NEXT:
	nextflags |= NX_NOCUR;
	if (fld_get_ck(&form_field) == SUCCESS)
	    nextfield(atoi(multi_eval(CURform(), CURfield(), FM_FROW)),
		      atoi(multi_eval(CURform(), CURfield(), FM_FCOL)),
		      1, nextflags);
	else
	    set_form_field(Cur_rec->id, CURfield());
	t = TOK_NOP;
	break;
    case TOK_PPAGE:
	if (fld_get_ck(&form_field) == SUCCESS) 
	{   /* find the prev page  with visible fields.    abs k17 */
	    int oldpage = CURpage(); 			/* abs k17 */
	    
	    if (CURpage() == 1)				/* abs k17 */
	    {
		set_form_field(Cur_rec->id, CURfield());
		t = TOK_BADCHAR;
		break;
	    }
	    else
	    {
		while (CURpage() != 1)			/* abs k17 */
		{					/* abs k17 */
		    CURpage()--;
		    fm_vislist(CURforminfo());
		    if ((int)NUMvis() > 0) 		/* abs k17 */
		    {					/* abs k17 */
			f_error = FALSE; 		/* abs k17 */
			break;				/* abs k17 */
		    }					/* abs k17 */
		    else				/* abs k17 */
			f_error = TRUE;			/* abs k17 */
		}					/* abs k17 */
		
		if (!f_error)				/* abs k17 */
		    f_error = form_ctl(Cur_rec->id, CTSETPAGE, TRUE,
				       CURpage(), LASTpage());
		if (f_error)	/* bad page .. go back to old one */
		{
		    CURpage() = oldpage; 		/* abs k17 */
		    fm_vislist(CURforminfo());
		    f_error = form_ctl(Cur_rec->id, CTSETPAGE, TRUE,
				       CURpage(), LASTpage());
		    mess_temp("Cannot display the previous page: page may be too large");
		    mess_lock();
		}
		else
		    nextfield(0, 0, 1, NX_ANY);
	    }
	}
	else 
	    set_form_field(Cur_rec->id, CURfield());
	t = TOK_NOP;
	break;
    case TOK_NPAGE:
	if (fld_get_ck(&form_field) == SUCCESS)
	{   /* find the next page  with visible fields.    abs k17 */
	    int oldpage = CURpage(); 			/* abs k17 */
	    
	    if (CURpage() == LASTpage())		/* abs k17 */
	    {
		set_form_field(Cur_rec->id, CURfield());
		t = TOK_BADCHAR;
		break;
	    }
	    else
	    {
		while (CURpage() != LASTpage() )	/* abs k17 */
		{					/* abs k17 */
		    CURpage()++;
		    fm_vislist(CURforminfo());
		    if ((int)NUMvis() > 0) 		/* abs k17 */
		    {					/* abs k17 */
			f_error = FALSE; 		/* abs k17 */
			break;				/* abs k17 */
		    }					/* abs k17 */
		    else				/* abs k17 */
			f_error = TRUE;			/* abs k17 */
		}					/* abs k17 */
		
		if (!f_error)				/* abs k17 */
		    f_error = form_ctl(Cur_rec->id, CTSETPAGE, TRUE,
				       CURpage(), LASTpage()); 
		if (f_error)	/* bad page .. go back to old one */
		{
		    CURpage() = oldpage;		 /* abs k17 */
		    fm_vislist(CURforminfo());
		    f_error = form_ctl(Cur_rec->id, CTSETPAGE, TRUE,
				       CURpage(), LASTpage());
		    mess_temp("Cannot display the next page: page may be too large");
		    mess_lock();
		}
		else
		    nextfield(0, 0, 1, NX_ANY);
	    }
	}
	else 
	    set_form_field(Cur_rec->id, CURfield());
	t = TOK_NOP;
	break;
    }
    return(t);
}

/*
** Processes characters before the editor.
*/
int
pre_stream(t)
register token t;
{
    formfield form_field;

    /* les */
/*    if ( isprint(t))	   ** only looks at 8 bits. abs k17 */
    if ( t > 037 && t < 0177 )
	return t;
    /*******/

    form_field = CURffield();
    switch(t) {
    case TOK_END:
	nextfield(1000, 1000, -1, NX_ANY);
	t = TOK_NOP;
	break;
    case TOK_BEG:
	nextfield(0, 0, 1, NX_ANY);
	t = TOK_NOP;
	break;
    case TOK_BTAB:
	if (fld_get_ck(&form_field) == SUCCESS)
	    nextfield(atoi(multi_eval(CURform(), CURfield(), FM_FROW)),
		      atoi(multi_eval(CURform(), CURfield(), FM_FCOL)),
		      -1, NX_NOCUR | NX_ADVANCE);
	else
	    set_form_field(Cur_rec->id, CURfield());
	t = TOK_NOP;
	break;
    case TOK_TAB:
	t = TOK_SAVE;
    case TOK_WDWMGMT:
	break;
    }
    return(t);
}

/*
** Sets up the stream for forms.
*/
static int
objform_stream(a, t)
struct actrec *a;
token t;
{
    int (*func[5])();
    register int olifetime;
    extern int field_stream();

    Cur_rec = a;
    olifetime = Cur_rec->lifetime;
    Cur_rec->lifetime = AR_PERMANENT;
    func[0] = pre_stream;
    func[1] = field_stream;
    func[2] = (int (*)())post_stream; /* added cast abs */
    func[3] = NULL;
    t = stream(t, func);
    Cur_rec->lifetime = olifetime;
    return(t);
}

int
set_form_field(id, field_num)
int id, field_num;
{
    char *str;
    char *lininfo;
    char buf[BUFSIZ];
    struct attribute *attr;

    /*
     * mark the attribute as touched (visited) ...
     */
    if (multi_eval(CURform(), field_num, FM_MENUO)) 
	attr = CURattr(field_num, FM_MENUO);
    else
	attr = CURattr(field_num, FM_VALID);
    if (attr)
	attr->flags |= ATTR_TOUCHED;

    /*
     * set "LININFO" variable to the value of the "lininfo"
     * descriptor for field_num
     */ 
    lininfo = multi_eval(CURform(), field_num, FM_LININFO);
    if (strlen(lininfo)) {
	sprintf(buf, "LININFO=%s", lininfo);
	putAltenv(buf);
    }
    else 
	delAltenv("LININFO");
	
    /*
     * display on the message line the "fieldmsg" for field_num
     */
    if ((str = multi_eval(CURform(), field_num, FM_FIELDMSG)) && *str)
	mess_temp(str);
    form_ctl(id, CTSETPOS, virt(field_num), 0, 0);
    return (0);
}
