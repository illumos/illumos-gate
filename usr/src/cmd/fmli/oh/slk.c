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

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/* microsecond delay timer not available before SVR4.0   abs k18 */
#ifdef PRE_SVR4_COMPILE
#define DO_NOT_DELAY		
#endif

#include	<stdio.h>
#include	<curses.h>
#include	<term.h>
#include	<string.h>	/* abs k17 */
#include 	<sys/types.h>	/* abs k17 */
#include	<unistd.h>	/* abs k18 */
#include	<stdlib.h>	/* abs k18 */
#ifndef DO_NOT_DELAY
#include 	<sys/time.h>	/* abs k18 */
#endif
#include	"wish.h"
#include	"token.h"
#include	"fm_mn_par.h"
#include	"slk.h"
#include	"ctl.h"
#include	"moremacros.h"
#include	"interrupt.h"

struct slk Moreslk = {
	"CHG-KEYS",	TOK_TOGSLK,	NULL,	NULL,	NULL
};

struct slk Markslk = {
	"MARK",		TOK_MARK,	NULL,	NULL,	NULL
};

struct slk Blankslk = {
	"",		TOK_NOP,	NULL,	NULL,	NULL
};

struct slk Formslk[] = {
	{"HELP",	TOK_HELP,	NULL,	NULL,	NULL},
	{"CHOICES",	TOK_OPTIONS,	NULL,	NULL,	NULL},
	{"SAVE",	TOK_DONE,	NULL,	NULL,	NULL},
	{"PREV-FRM",	TOK_PREV_WDW,	NULL,	NULL,	NULL},
	{"NEXT-FRM",	TOK_NEXT_WDW,	NULL,	NULL,	NULL},
	{"CANCEL",	TOK_CLOSE,	NULL,	NULL,	NULL},
	{"CMD-MENU",	TOK_CMD,	NULL,	NULL,	NULL},
	{"",		TOK_NOP,	NULL,	NULL,	NULL},
	{NULL, 		TOK_NOP, 	NULL,	NULL,	NULL}
};

#define MARK 1

struct slk Menuslk[] = {
	{"HELP",	TOK_HELP,	NULL,	NULL,	NULL},
	{"",		TOK_NOP,	NULL,	NULL,	NULL},/* MARK for mult. selections  */
	{"ENTER",	TOK_RETURN,	NULL,	NULL,	NULL},
	{"PREV-FRM",	TOK_PREV_WDW,	NULL,	NULL,	NULL},
	{"NEXT-FRM",	TOK_NEXT_WDW,	NULL,	NULL,	NULL},
	{"CANCEL",	TOK_CLOSE,	NULL,	NULL,	NULL},
	{"CMD-MENU",	TOK_CMD,	NULL,	NULL,	NULL},
	{"",		TOK_NOP,	NULL,	NULL,	NULL},
	{NULL,		TOK_NOP,	NULL,	NULL,	NULL}
};

struct slk Textslk[] = {
	{"HELP",	TOK_HELP,	NULL,	NULL,	NULL},
	{"PREVPAGE",	TOK_PPAGE,	NULL,	NULL,	NULL},
	{"NEXTPAGE",	TOK_NPAGE,	NULL,	NULL,	NULL},
	{"PREV-FRM",	TOK_PREV_WDW,	NULL,	NULL,	NULL},
	{"NEXT-FRM",	TOK_NEXT_WDW,	NULL,	NULL,	NULL},
	{"CANCEL",	TOK_CLOSE,	NULL,	NULL,	NULL},
	{"CMD-MENU",	TOK_CMD,	NULL,	NULL,	NULL},
	{"",		TOK_NOP,	NULL,	NULL,	NULL},
	{NULL,		TOK_NOP,	NULL,	NULL,	NULL}
};

struct slk Echslk[] = {		/* Enter/Cancel/Help slks */
	{"HELP",	TOK_HELP,	NULL,	NULL,	NULL},
	{"",		TOK_BADCHAR,	NULL,	NULL,	NULL},
	{"",		TOK_BADCHAR,	NULL,	NULL,	NULL},
	{"",		TOK_BADCHAR,	NULL,	NULL,	NULL},
	{"",		TOK_BADCHAR,	NULL,	NULL,	NULL},
	{"CANCEL",	TOK_CANCEL,	NULL,	NULL,	NULL},
	{"",		TOK_BADCHAR,	NULL,	NULL,	NULL},
	{"",		TOK_BADCHAR,	NULL,	NULL,	NULL},
	{"",		TOK_BADCHAR,	NULL,	NULL,	NULL},
	{"",		TOK_BADCHAR,	NULL,	NULL,	NULL},
	{"",		TOK_BADCHAR,	NULL,	NULL,	NULL},
	{"",		TOK_BADCHAR,	NULL,	NULL,	NULL},
	{"",		TOK_BADCHAR,	NULL,	NULL,	NULL},
	{"",		TOK_BADCHAR,	NULL,	NULL,	NULL},
	{"",		TOK_BADCHAR,	NULL,	NULL,	NULL},
	{"",		TOK_BADCHAR,	NULL,	NULL,	NULL},
	{NULL,		TOK_NOP,	NULL,	NULL,	NULL}
};


/*
 * FACE user interface Directory SLKS
 */
struct slk Vmslk[] = {
	{"HELP",	TOK_HELP,	NULL,	NULL,	NULL},
	{"",		TOK_NOP,	NULL,	NULL,	NULL},	
	{"ENTER",	TOK_RETURN,	NULL,	NULL,	NULL},
	{"PREV-FRM",	TOK_PREV_WDW,	NULL,	NULL,	NULL},
	{"NEXT-FRM",	TOK_NEXT_WDW,	NULL,	NULL,	NULL},
	{"CANCEL",	TOK_CLOSE,	NULL,	NULL,	NULL},
	{"CMD-MENU",	TOK_CMD,	NULL,	NULL,	NULL},
	{"",		TOK_NOP,	NULL,	NULL,	NULL},
	{"HELP",	TOK_HELP,	NULL,	NULL,	NULL},
	{"COPY",	TOK_COPY,	NULL,	NULL,	NULL},
	{"MOVE",	TOK_MOVE,	NULL,	NULL,	NULL},
	{"DELETE",	TOK_DELETE,	NULL,	NULL,	NULL},
	{"RENAME",	TOK_REPLACE,	NULL,	NULL,	NULL},
	{"CREATE",	TOK_CREATE,	NULL,	NULL,	NULL},
	{"SECURITY",	TOK_SECURITY,	NULL,	NULL,	NULL},
	{"",		TOK_NOP,	NULL,	NULL,	NULL},
	{NULL,		TOK_NOP,	NULL,	NULL,	NULL}
};

extern int Browse_mode;


/*
 * FACE user interface Browse Mode SLKS 
 */
struct slk Browslk[] = {	/* slks when browsing */
	{"HELP",	TOK_HELP,	NULL,	NULL,	NULL},
	{"",		TOK_NOP,	NULL,	NULL,	NULL},
	{"",		TOK_NOP,	NULL,	NULL,	NULL},
	{"PREV-FRM",	TOK_PREV_WDW,	NULL,	NULL,	NULL},
	{"NEXT-FRM",	TOK_NEXT_WDW,	NULL,	NULL,	NULL},
	{"CANCEL",	TOK_CANCEL,	NULL,	NULL,	NULL},
	{"CMD-MENU",	TOK_CMD,	NULL,	NULL,	NULL},
	{"SELECT",	TOK_SELECT,	NULL,	NULL,	NULL},
	{NULL,		TOK_NOP,	NULL,	NULL,	NULL}
};

#define CHG_KEYS	7	/* SLK number of first level CHG_KEYS */
#define SECOND_LEVEL	8	/* number of slks displayable */
#define ALT_CHG_KEYS	15	/* SLK number of second level CHG_KEYS */
#define MAX_SLKS	16	/* total number of slks */	

struct slk No_slks[1];
struct slk SLK_array[MAX_SLKS];
struct slk Defslk[MAX_SLKS];
struct slk *Curslk = &Defslk[0];
static int SLK_level = 0;

static void showslks();
static bool sfk_prompt();

extern int Vflag;

/*
 * init_sfk tries to initialize the screen function keys for terminals
 * (like the att630) which do not have pre-defined screen function keys
 * It will not do anything if:
 * 1) the environment variable LOADPFK is set to anything other than
 *    yes, true, or the null string (case insensitive) or
 * 2) the terminal does not support software downloading of these strings or
 * 3) if the terminal has predefined strings sent by the function keys.
 * 4) if, when prompted, the user responds with anything other than
 *    "yes", "y", or "" (whitespace & extra words ignored.)  Prompt only occurs 
 *    once per session and only if LOADPFK is not defined.
 *
 * NOTE:       if the terminfo entry indicates a mandatory delay is needed
 *             and there is no pad char then FMLI will insert the delay.
 *             For some terminals (ex dmd 5620) this delay is appreciable
 *             and should be avoided, when feasable, by downloading once then
 *             setting LOADPFK=no.
 * IMPORTANT:  remove the delay code (ifdef'd by DO_NOT_DELAY)
 *	       when curses gets smart enough to do delays right for
 *             terminals like the dmd 5620 which do not have pad characters
 */

int
init_sfk(do_prompt)
bool do_prompt;				/* abs k18 */
{
    char    sequence[3];
    int     i;
#ifndef DO_NOT_DELAY
    char   *sub_str;
    char   *end_str;			/* abs k18 */
    unsigned time_left;			/* abs k18 */
    static struct itimerval delay_time; /* abs k18 */
    static long Mandatory_delay = 0L; 	/* abs k18 */
    static bool First_time = TRUE;    	/* abs k18 */
#endif
    static bool Said_no = FALSE;    	/* abs k18 */
    char   *load;		 	/* abs k18 */

    sequence[0] = 'F' & 037;		/* <control f> */
    sequence[2] = '\0';
        
    /* if we already prompted user and they said no then don't do anything */

    if (Said_no == TRUE)		/* abs k18 */
	return (0);			/* abs k18 */

    /* if LOADPFK is set in the environment, don't download function keys,
     * unless it is set to yes, true, or the null string. abs k18
     */

    if ( (load = getenv("LOADPFK")) && *load &&
         strCcmp(load, "yes") && strCcmp(load, "true"))	/* abs k18 */
	   return (0); 	     /* user says don't mess with my keys! */

    if (load)
	do_prompt = FALSE;	/* don't prompt if LOADPFK is set. abs k18 */

    if (!pkey_xmit || pkey_xmit == NULL)   /* term can't transmit fn keys */
	   return (0);
#ifndef DO_NOT_DELAY
    if (First_time == TRUE)	/* this block added k18 abs. */
    {
	First_time = FALSE;
	if (no_pad_char)	/* can't create delay by sending pads */
	{
	    /* look for mandatory delay 
	     * delays are coded $<nnn/> where n is a digit and 
	     * the slash, if present, means the delay is mandatory.
             */

	    sub_str = pkey_xmit;
	    while (sub_str = strchr(sub_str, '$'))
		if (*(++sub_str) == '<')
		{
		    Mandatory_delay = strtol(&sub_str[1], &end_str, 10);
		    if (end_str[0] != '/' || end_str[1] != '>')
			Mandatory_delay = 0L;
		}
	    if (Mandatory_delay)
	    {
		/* convert milliseconds to microseconds and seconds.
		 * tv_usec must be less than 1,000,000.  abs k18.2 
		 */
		delay_time.it_value.tv_usec = (Mandatory_delay % 1000L) * 1000L;
		delay_time.it_value.tv_sec = Mandatory_delay  / 1000L;
		delay_time.it_interval.tv_sec = 0L;
		delay_time.it_interval.tv_usec = 0L;
	    }

	}
    }
    
    /* don't want mailcheck to intefere with timer. abs k18 */
    time_left = alarm((unsigned)0);	
#endif
    if (!key_f1 || *key_f1 == NULL) /* if no pre-defined key 1 then assume
				     * keys 2 - 8 not pre-defined either */
    {
	if (do_prompt == TRUE && (Said_no = sfk_prompt()) == TRUE)  /* abs k18 */
	    return (0);						/* abs k18 */

/*      The following line was moved from below.  This is where it belongs,
**      unfortunately the doupdate() to make the indicator visible
**      interferes with downloading 5620 pfk's (somehow?!) depending on whats
**      in the curses screen buffer.  abs k18.2
**      working(TRUE);	
*/
	for (i = 1; i < 9; i++)
	{
	    sequence[1] = '0' + i;
	    putp(tparm(pkey_xmit, i, sequence));
	    fflush(stdout);
#ifndef DO_NOT_DELAY
 	    if (Mandatory_delay) 				/* abs k18 */
	    {
		setitimer(ITIMER_REAL, &delay_time, NULL); 	/* abs k18 */
		pause();					/* abs k18 */
	    }
#endif
	}
    }
    else
    {
	if (!key_f2 || *key_f2 == NULL)
	{
	    if (do_prompt == TRUE && (Said_no = sfk_prompt()) == TRUE)   /* abs k18 */
		return (0);					/* abs k18 */
	    else						/* abs k18 */
		do_prompt = FALSE;				/* abs k18 */
	    sequence[1] = '2';
	    putp(tparm(pkey_xmit, 2, sequence));
	    fflush(stdout);
#ifndef DO_NOT_DELAY
 	    if (Mandatory_delay) 				/* abs k18 */
	    {
		setitimer(ITIMER_REAL, &delay_time, NULL); 	/* abs k18 */
		pause();					/* abs k18 */
	    }
#endif
	}
	if (!key_f3 || *key_f3 == NULL)
	{
	    if (do_prompt == TRUE && (Said_no = sfk_prompt()) == TRUE)   /* abs k18 */
		return (0);					/* abs k18 */
	    else						/* abs k18 */
		do_prompt = FALSE;				/* abs k18 */
	    sequence[1] = '3';
	    putp(tparm(pkey_xmit, 3, sequence));
	    fflush(stdout);
#ifndef DO_NOT_DELAY
 	    if (Mandatory_delay) 				/* abs k18 */
	    {
		setitimer(ITIMER_REAL, &delay_time, NULL); 	/* abs k18 */
		pause();					/* abs k18 */
	    }
#endif
	}
	if (!key_f4 || *key_f4 == NULL)
	{
	    if (do_prompt == TRUE && (Said_no = sfk_prompt()) == TRUE)   /* abs k18 */
		return (0);					/* abs k18 */
	    else						/* abs k18 */
		do_prompt = FALSE;				/* abs k18 */
	    sequence[1] = '4';
	    putp(tparm(pkey_xmit, 4, sequence));
	    fflush(stdout);
#ifndef DO_NOT_DELAY
 	    if (Mandatory_delay) 				/* abs k18 */
	    {
		setitimer(ITIMER_REAL, &delay_time, NULL); 	/* abs k18 */
		pause();					/* abs k18 */
	    }
#endif
	}
	if (!key_f5 || *key_f5 == NULL)
	{
	    if (do_prompt == TRUE && (Said_no = sfk_prompt()) == TRUE)   /* abs k18 */
		return (0);					/* abs k18 */
	    else						/* abs k18 */
		do_prompt = FALSE;				/* abs k18 */
	    sequence[1] = '5';
	    putp(tparm(pkey_xmit, 5, sequence));
	    fflush(stdout);
#ifndef DO_NOT_DELAY
 	    if (Mandatory_delay) 				/* abs k18 */
	    {
		setitimer(ITIMER_REAL, &delay_time, NULL); 	/* abs k18 */
		pause();					/* abs k18 */
	    }
#endif
	}
	if (!key_f6 || *key_f6 == NULL)
	{
	    if (do_prompt == TRUE && (Said_no = sfk_prompt()) == TRUE)   /* abs k18 */
		return (0);					/* abs k18 */
	    else						/* abs k18 */
		do_prompt = FALSE;				/* abs k18 */
	    sequence[1] = '6';
	    putp(tparm(pkey_xmit, 6, sequence));
	    fflush(stdout);
#ifndef DO_NOT_DELAY
 	    if (Mandatory_delay) 				/* abs k18 */
	    {
		setitimer(ITIMER_REAL, &delay_time, NULL); 	/* abs k18 */
		pause();					/* abs k18 */
	    }
#endif
	}
	if (!key_f7 || *key_f7 == NULL)
	{
	    if (do_prompt == TRUE && (Said_no = sfk_prompt()) == TRUE)   /* abs k18 */
		return (0);					/* abs k18 */
	    else						/* abs k18 */
		do_prompt = FALSE;				/* abs k18 */
	    sequence[1] = '7';
	    putp(tparm(pkey_xmit, 7, sequence));
	    fflush(stdout);
#ifndef DO_NOT_DELAY
 	    if (Mandatory_delay) 				/* abs k18 */
	    {
		setitimer(ITIMER_REAL, &delay_time, NULL); 	/* abs k18 */
		pause();					/* abs k18 */
	    }
#endif
	}
	if (!key_f8 || *key_f8 == NULL)
	{
	    if (do_prompt == TRUE && (Said_no = sfk_prompt()) == TRUE)   /* abs k18 */
		return (0);					/* abs k18 */
	    else						/* abs k18 */
		do_prompt = FALSE;				/* abs k18 */
	    sequence[1] = '8';
	    putp(tparm(pkey_xmit, 8, sequence));
	    fflush(stdout);
#ifndef DO_NOT_DELAY
 	    if (Mandatory_delay) 				/* abs k18 */
	    {
		setitimer(ITIMER_REAL, &delay_time, NULL); 	/* abs k18 */
		pause();					/* abs k18 */
	    }
#endif
	}
	    
    }
#ifndef DO_NOT_DELAY
    alarm(time_left);		/* reset alarm. abs k18 */
#endif
    return (0);
}


static bool
sfk_prompt()
{
    char raw_input[80];
    char *response, *word_end;
    WINDOW *win;
    int cursor, x, y;

    win = newwin(0,0,1,0);	/* almost full screen window */
    getmaxyx(win, y, x);
    wmove(win, y/2-6, 0);	/* go to about the center row */
    cursor = curs_set(1);	/* make cursor visible */
    flushinp();

    wprintw(win, "This terminal does not have usable default settings for its function keys;\nhowever, this application can download usable settings.\n\nIf you reply yes, function keys will work, BUT any values you may already \nhave programmed into them will be overwritten.\n\n");
    wprintw(win, "If you reply no,  function keys may not work, and you must use CTRL-f1 \nthru CTRL-f8 to simulate the function keys.\n\nThis prompt will not occur if you set LOADPFK=YES or LOADPFK=NO in \nyour environment.\n\nDownload usable settings into the function keys [default is yes]? ");

    wrefresh(win);
    echo();
    wgetnstr(win, raw_input, 79);
    noecho();
    werase(win);
    wrefresh(win);
    delwin(win);
    (void)curs_set(cursor);

    response = raw_input;
    while (isspace(*response))
	response++;
    word_end = response;				/* abs k18.2 */
    while (!isspace(*word_end) && *word_end !=  '\0') 	/* abs k18.2 */
	word_end++;					/* abs k18.2 */
    *word_end = '\0';					/* abs k18.2 */
    
    if (*response && strCcmp(response, "y") && strCcmp(response, "yes"))
    {
	putenv("LOADPFK=NO");	/* so child fmli's don't prompt. abs k18.2 */
	return(TRUE);		/* said no */
    }
    else
    {
	putenv("LOADPFK=YES");	/* so child fmli's don't prompt. abs k18.2 */
	return(FALSE);		/* said yes */
    }
}




/*
 * SETUP_SLK_ARRAY will initialize defaults for the SLKS
 */
int
setup_slk_array()
{
	register int i, j;

	for (i = 0; i < SECOND_LEVEL; i++)
		Defslk[i] = Menuslk[i];

	for (i = SECOND_LEVEL; i < MAX_SLKS; i++) {
		Defslk[i].label = nil; 
		Defslk[i].tok = TOK_NOP;
		Defslk[i].tokstr = NULL;
		Defslk[i].intr   = NULL;
		Defslk[i].onintr = NULL;
	}
	return (0);
}

#define REDEFINED(x)	 ((x).label && (*((x).label) != '\0' || (x).tok < 0))

/*
 * SETSLKS will make "slks" the currently displayed SLKS
 */
void
setslks(slks, flag)
struct slk	slks[];
int flag;
{
	register int	i, more_slks;
	static  void	showslks();

#ifdef _DEBUG
	_debug(stderr, "in setslk!\n");
#endif
	if (slks == NULL) {	/* e.g., directory object */
		if (Vflag) {	/* FACE specific slks */
			if (Browse_mode)
				setslks(Browslk, 0);
			else
				setslks(Vmslk, 0);
		}
		else {	/* use menu slks by default */
			set_top_slks(Menuslk);
			setslks(Defslk, 0);
		}
		return;
	}
	else if (slks == No_slks) {
#ifdef _DEBUG
		_debug(stderr, "slks are history\n");
#endif
		SLK_level = -1;
		slk_clear();
		return;
	}
	more_slks = 0;
	for (i = 0; slks[i].label && i < MAX_SLKS; i++) {
		if (i >= SECOND_LEVEL && *(slks[i].label) != '\0')
			more_slks++;
#ifdef _DEBUG
		_debug(stderr, "SLK_array[%d] = '%s'\n", i, slks[i].label);
#endif
		SLK_array[i] = slks[i];
	}
#ifdef _DEBUG
	if (slks[i].label)
		_debug(stderr, "setslks was passed an array without a NULL terminator\n");
#endif
	while (i < MAX_SLKS)
		SLK_array[i++].label = nil;
	if (more_slks && !(REDEFINED(SLK_array[CHG_KEYS]) ||
			 REDEFINED(SLK_array[ALT_CHG_KEYS]))) 
		SLK_array[CHG_KEYS] = SLK_array[ALT_CHG_KEYS] = Moreslk;
	showslks(flag);
}

int Refresh_slks = 0;

/*
 * SHOWSLKS will do the actial displaying
 */
static void
showslks(flag)
int flag;
{
	register int	i;
	register int	j;

	if (SLK_level < 0) {
		Refresh_slks++;
		/*slk_restore();    defer to vt_flush() */
	}
	if (flag)
		SLK_level = j = SECOND_LEVEL;
	else
		SLK_level = j = 0;
	for (i = 1; i <= SECOND_LEVEL; i++)
		slk_set(i, SLK_array[j++].label, 1);
	slk_noutrefresh();
}

/*
 * SLK_TOKEN will determine the token action for a given SLK
 */
token
slk_token(t)
token	t;
{
    register int	n;
    int flags;
    char **arglist, **eval_string();
    char  *intr, *onintr;

    n = t - TOK_SLK1 + SLK_level;
#ifdef _DEBUG
    _debug(stderr, "slk %d is labeled '%s' and returns token %d\n", t, SLK_array[n].label,SLK_array[n].tok);
#endif
    if (SLK_array[n].label && SLK_array[n].label[0])
    {
	if (SLK_array[n].tok >= 0)	/* internally-defined */
	    return(SLK_array[n].tok);
	else
	{

	    /* 	update the interrupt structures based on 
		the values for the current slk, if defined
		else with the inherited values.
	    */
	    Cur_intr.skip_eval =  FALSE;
	    if ((intr = SLK_array[n].intr) == NULL)
		intr = (char *)ar_ctl(AR_cur, CTGETINTR, NULL, NULL, NULL, NULL, NULL, NULL);
	    flags = RET_BOOL;
	    Cur_intr.interrupt = FALSE;	/* dont intrupt eval of intr */
	    Cur_intr.interrupt = (bool)(uintptr_t)eval_string(intr, &flags);

	    if ((onintr = SLK_array[n].onintr) == NULL)
		onintr = (char *)ar_ctl(AR_cur, CTGETONINTR, NULL, NULL, NULL, NULL, NULL, NULL);
	    Cur_intr.oninterrupt = onintr;

	    flags = RET_ARGS;
	    arglist = eval_string(SLK_array[n].tokstr, &flags);
	    return(make_action(arglist));
	}
    }
	return TOK_BADCHAR;
}

int
set_top_slks(slks)
struct slk slks[];
{
	register int i;

	for (i = 0; i < SECOND_LEVEL; i++)
		Defslk[i] = slks[i];
	return (0);
}

/*
 * SET_OBJ_SLK is called by objects that wish to redefine the
 * GLOBAL default SLKS ... 
 * The object will pass a "slktok" in the range SLK1 - SLK16.
 * If a token in this range is "caught" by the object,
 * the object itself will determine the appropriate action.
 */ 
int
set_obj_slk(slk, label, slktok, intr, onintr)
struct slk *slk;
char *label;
int slktok;
char *intr, *onintr;
{
	int slknum;

	if (label && (*label == '\0')) {     /* disable any SLK */
		slk->label = "";
		slk->tok = -1;
		slk->tokstr = NULL;
		slk->intr   = NULL;
		slk->onintr = NULL;
	}
	else {
		slknum = slktok - TOK_SLK1;  /* (adjust for array offset) */
		if (slknum >= CHG_KEYS) {    /* redefine certain SLKS */ 
			slk->label = strsave(label);
			/*
			 * unfortunately this test needs to be made ...
			 * (if odsh gets prevpage or nextpage its too late)
			 * We must search for a better way !!!
			 */
			if (strCcmp(label, "prevpage") == 0)
				slk->tok = TOK_PPAGE;
			else if (strCcmp(label, "nextpage") == 0)
				slk->tok = TOK_NPAGE;
			else if (strCcmp(label, "prev-frm") == 0)
				slk->tok = TOK_PREV_WDW;
			else if (strCcmp(label, "next-frm") == 0)
				slk->tok = TOK_NEXT_WDW;
			else if (strCcmp(label, "enter") == 0)
				slk->tok = TOK_RETURN;
			else
				slk->tok = slktok;
			slk->tokstr = NULL;
			slk->intr   = strsave(intr);
			slk->onintr = strsave(onintr);
		}
		else {			     /* must use the defaults! */ 
			slk->label = Defslk[slknum].label;
			slk->tok = Defslk[slknum].tok;
			slk->tokstr = Defslk[slknum].tokstr;
			slk->tokstr = Defslk[slknum].intr;
			slk->tokstr = Defslk[slknum].onintr;
		}
	}
	return (0);
}


/*
 * SET_DEF_SLK will over-write the GLOBAL default SLKS 
 */
int
set_def_slk(slknum, label, action, intr, onintr)
int slknum;
char *label;
char *action;
char *intr, *onintr;
{
	/*
	 * if less then CHG_KEYS do nothing (can't redefine first level)
	 */
	if (label && (*label == '\0')) {	/* disable any SLK */
		Defslk[slknum].label = "";
		Defslk[slknum].tok = -1;
		Defslk[slknum].tokstr = NULL;
		Defslk[slknum].intr   = NULL;
		Defslk[slknum].onintr = NULL;
	}
	else if (slknum >= CHG_KEYS) {		/* redefine certain SLKS */
		Defslk[slknum].label = strsave(label);
		Defslk[slknum].tok = -1;
		Defslk[slknum].tokstr = strsave(action);
		Defslk[slknum].intr   = strsave(intr);
		Defslk[slknum].onintr = strsave(onintr);
	}
	/*
	 * if SLK is at the first level, then change the object
	 * SLKS to reflect the redefined or disabled SLK 
	 */
	if (slknum <= CHG_KEYS) {	
		Formslk[slknum] = Defslk[slknum];
		Textslk[slknum] = Defslk[slknum];
		Menuslk[slknum] = Defslk[slknum];
	}
	return (0);
}

/*
 * SLK_TOGGLE will toggle the currently displayed SLKS
 */
int
slk_toggle(void)
{
	showslks(!SLK_level);
	return (0);
}

int
set_slk_mark(flag)
int flag;
{
	if (flag == TRUE)
		Menuslk[MARK] = Markslk;
	else
		Menuslk[MARK] = Blankslk;
	Defslk[MARK] = Menuslk[MARK];
	return (0);
}
