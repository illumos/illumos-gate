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
#include	<curses.h>
#include	<string.h>
#include	"wish.h"
#include	"fm_mn_par.h"
#include	"terror.h"
#include	"var_arrays.h"
#include	"vtdefs.h"
#include	"ctl.h"
#include	"attrs.h"
#include	"color_pair.h"
#include	"moremacros.h"
#include 	"interrupt.h"
#include	"token.h"
#include	"slk.h"

/* single instance desriptors in initialization file */
#define INIT_SING_KEYS		28

#define INIT_INTR		PAR_INTR
#define INIT_ONINTR		PAR_ONINTR
#define INIT_TITLE		2              
#define INIT_TEXT		3              
#define INIT_ROWS		4             
#define INIT_COLUMNS		5             
#define INIT_BANNER		6             
#define INIT_BANCOL		7             
#define INIT_WORKING		8             
#define COL_SCREEN		9             
#define COL_BANNER_TEXT		10            
#define COL_WINDOW_TEXT	 	11            
#define COL_ACTIVE_BORD		12            
#define COL_INACTIVE_BORD	13            
#define COL_ACTIVE_TITLE	14            
#define COL_ACTIVE_TITLE_BAR	15            
#define COL_INACTIVE_TITLE	16            
#define COL_INACTIVE_TITLE_BAR	17            
#define COL_BAR			18            
#define COL_BAR_TEXT		19            
#define COL_SLK_BAR		20            
#define COL_SLK_TEXT		21            
#define COL_FIELD_BAR		22            
#define COL_FIELD_TEXT		23
#define INIT_TOGGLE		24
#define INIT_NOBANG		25   /* abs */
#define INIT_DOUBLEVARS		26
#define INIT_PERMMSG		27

/* Multi-instance descriptors for initialization file */
#define INIT_MULT_KEYS 6

#define SLK_INTR		PAR_INTR
#define SLK_ONINTR		PAR_ONINTR
#define SLK_ACTION		PAR_ACTION
#define SLK_NAME		PAR_NAME
#define SLK_SHOW		4
#define SLK_BUTTON		5

/* Single-instance descriptors for commands file */
/*
 * there is none
 */
#define CMD_SING_KEYS		0

/* Multi-instance descriptors for commands file */
#define CMD_MULT_KEYS		6

#define CMD_INTR		PAR_INTR  
#define CMD_ONINTR		PAR_ONINTR
#define CMD_ACTION		PAR_ACTION
#define CMD_NAME		PAR_NAME
#define CMD_SHOW		4
#define CMD_HELP		5


#define WORKINGMSG		"Working"
#define FOURFOUR		"4-4"
#define DEFTOGGLE		3

static struct attribute Init_single_tab[INIT_SING_KEYS] = {
	{ "interrupt",	RET_STR|EVAL_ONCE, "false", "false", 0 },
	{ "oninterrupt",RET_STR|EVAL_ONCE,  DEF_ONINTR, DEF_ONINTR, 0 },
	{ "title",		RET_STR|EVAL_ONCE,	"", NULL, 0 },
	{ "text",		RET_STR|EVAL_ONCE,	"", NULL, 0 },
	{ "rows",		RET_STR|EVAL_ONCE,	"10", NULL, 0 },
	{ "columns",		RET_STR|EVAL_ONCE,	"50", NULL, 0 },
	{ "banner",		RET_STR|EVAL_ONCE,	"", NULL, 0 },
	{ "bancol",		RET_INT|EVAL_ONCE,	"", NULL, 0 },
	{ "working",		RET_STR|EVAL_ONCE,	"Working", NULL, 0 },
	{ "screen",		RET_STR|EVAL_ONCE,	"", NULL, 0 },	
	{ "banner_text",	RET_STR|EVAL_ONCE,	"", NULL, 0 },	
	{ "window_text",	RET_STR|EVAL_ONCE,	"", NULL, 0 },	
	{ "active_border",	RET_STR|EVAL_ONCE,	"", NULL, 0 },
	{ "inactive_border",	RET_STR|EVAL_ONCE,	"", NULL, 0 },
	{ "active_title_text",	RET_STR|EVAL_ONCE,	"", NULL, 0 },
	{ "active_title_bar",	RET_STR|EVAL_ONCE,	"", NULL, 0 },
	{ "inactive_title_text",RET_STR|EVAL_ONCE,	"", NULL, 0 },
	{ "inactive_title_bar",	RET_STR|EVAL_ONCE,	"", NULL, 0 },
	{ "highlight_bar",	RET_STR|EVAL_ONCE,	"", NULL, 0 },	
	{ "highlight_bar_text",	RET_STR|EVAL_ONCE,	"", NULL, 0 },
	{ "slk_bar",		RET_STR|EVAL_ONCE,	"", NULL, 0 },	
	{ "slk_text",		RET_STR|EVAL_ONCE,	"", NULL, 0 },
	{ "field_bar",		RET_STR|EVAL_ONCE,	"", NULL, 0 },
	{ "field_text",		RET_STR|EVAL_ONCE,	"", NULL, 0 },
	{ "toggle",		RET_STR|EVAL_ONCE,     "3", NULL, 0 },
	{ "nobang",		RET_BOOL|EVAL_ONCE,	FALSE, FALSE, 0 },
	{ "use_incorrect_pre4.0_behavior",
				RET_BOOL|EVAL_ONCE,	FALSE, FALSE, 0 },
	{ "permanentmsg",	RET_STR|EVAL_ONCE,	"", FALSE, 0 }
};

/*
 * Table for SLKS and CMDS
 */
static struct attribute Init_multi_tab[INIT_MULT_KEYS] = {
	{ "interrupt",	RET_STR|EVAL_ALWAYS,    NULL, NULL, 0 },
	{ "oninterrupt",RET_STR|EVAL_ALWAYS,	NULL, NULL, 0 },
	{ "action",	RET_ARGS|EVAL_ALWAYS,	NULL, NULL, 0 },
	{ "name",	RET_STR|EVAL_ALWAYS,	NULL, NULL, 0 },
	{ "show",	RET_BOOL|EVAL_ALWAYS,	"", NULL, 0 },
	{ "button",	RET_INT|EVAL_ALWAYS,	"0", NULL, 0 }
};


static struct attribute Cmd_multi_tab[CMD_MULT_KEYS] = {
	{ "interrupt",	RET_STR|EVAL_ALWAYS,    NULL, NULL, 0 },
	{ "oninterrupt",RET_STR|EVAL_ALWAYS,	NULL, NULL, 0 },
	{ "action",	RET_ARGS|EVAL_ALWAYS,	NULL, NULL, 0 },
	{ "name",	RET_STR|EVAL_ALWAYS,	NULL, NULL, 0 },
	{ "show",	RET_BOOL|EVAL_ALWAYS,	"", NULL, 0 },
	{ "help",	RET_ARGS|EVAL_ALWAYS,	NULL, NULL, 0 }
};

bool	Doublevars = FALSE;
/*
 * The variable "Doublevars" is set to TRUE/FALSE depending on the
 * true/false value of the descriptor "use_incorrect_pre4.0_behavior".
 * By default Doublevars = FALSE.
 *
 * If "Doublevars == TRUE" then the previously incorrect behavior of
 * "re-evaluating" an expanded environment variable will be
 * allowed (see eval_dollar() in eval.c for details).
 *
 * If "Doublevars == FALSE" then variables will be expanded as they
 * are in the UNIX shell.  In addition, the new construct "$!" will be
 * recognized so as to facilitate the "old" behavior.  The reason for
 * the new construct is that the "old" behavior of variable
 * "re-evaluation", though often damaging, is also quite useful.
 * 
 * NOTE: The descriptor "use_incorrect_pre4.0_behavior" was only added
 * to avoid "blind-siding" those applications that depend on the "old"
 * behavior.  Since it is expected that ALL applications conform to the
 * "new" behavior in the future, this descriptor will (most likely) be 
 * ignored by FMLI in post 4.0 releases.
 */ 
extern	int Vflag;
int Border_colors_differ;	/* do active/inactive border colors differ? */

/*
 * Introductory object attributes
 */
static	char *Intro_title;
static	char *Intro_text;
static  int  Intro_rows;
static 	int  Intro_cols;
static  char *Banner = NULL;
static  char *Bancolstr;
static  char *Col_screen;
static  char *Col_banner_text;
static  char *Col_window_text;
static  char *Col_active_bord;
static  char *Col_inactive_bord;
static  char *Col_active_title;
static  char *Col_active_title_bar;
static  char *Col_inactive_title;
static  char *Col_inactive_title_bar;
static  char *Col_bar;
static  char *Col_bar_text;
static  char *Col_slk_bar;
static  char *Col_slk_text;
static  char *Col_field_bar;
static  char *Col_field_text;
static  char *Intr = NULL;
static  char *Onintr = NULL;
/*
 * extern globals
 */
char	*Work_msg = NULL;
int	Work_col;
int	Mail_col;
int	Toggle = DEFTOGGLE;
bool    Nobang = FALSE;		/* defaults to bang enabled */

char *strnsave();
static int settoggle();
static struct fm_mn Inits;

/*
** Front-end to parser(), which sets up defaults.
*/
int
read_inits(initfile)
char *initfile;
{
	register int i, numslks;
	char  *permmsg, *get_def();
	static char *set_default();
	static int center_it();
	static int free_inits = FALSE;
	int sbutton;
	FILE *fp;

/*	if (access(initfile, 04) < 0)
**		return;                 abs k15 */

	/* make sure file exists and is readable  abs k15 */

	if (initfile && ((fp = fopen(initfile, "r")) == NULL)) {
	    mess_temp("error: initialization file missing or not readable");
	    mess_flash("error: initialization file missing or not readable");
	    doupdate();
	    return (0);
	}

	if (free_inits == TRUE)
		freeitup(&Inits);
	else
		free_inits = TRUE;

	/*
	 * Parse initialization file
	 */
	Inits.single.attrs = NULL;
	Inits.multi = NULL;
	filldef(&Inits.single, Init_single_tab, INIT_SING_KEYS);
	if (initfile)
		parser(0, initfile, Init_single_tab, INIT_SING_KEYS,
			&Inits.single, Init_multi_tab, INIT_MULT_KEYS,
			&Inits.multi, fp);

	numslks = array_len(Inits.multi);
	for (i = 0; i < numslks; i++)
	{
	    sbutton = atoi(multi_eval(&Inits, i, SLK_BUTTON)) - 1;
	    if (multi_eval(&Inits, i, SLK_SHOW) &&
		sbutton >= 0 && sbutton < MAX_SLK) /* abs */
	    {
		set_def_slk(sbutton,
			    multi_eval(&Inits, i, SLK_NAME),
			    get_def(&Inits, i, SLK_ACTION),
			    get_def(&Inits, i, SLK_INTR),
			    get_def(&Inits, i, SLK_ONINTR));
	    }
	}

	/*
	 * Introductory object info 
	 */
	Intro_title = set_default(INIT_TITLE);
	Intro_text = set_default(INIT_TEXT);
	Intro_rows = atoi(set_default(INIT_ROWS));
	Intro_cols = atoi(set_default(INIT_COLUMNS));

	/*
	 * Session interrupt info
	 */
	Intr = (char *)get_sing_def(&Inits, INIT_INTR);
	Onintr = (char *)get_sing_def(&Inits, INIT_ONINTR);

	/*
	 * BANNER line info
	 */
	Banner = set_default(INIT_BANNER);
	Bancolstr = set_default(INIT_BANCOL);
	Work_msg = set_default(INIT_WORKING);

	/*
	 * COLOR specifications
	 */
	if (Color_terminal == TRUE) {
		Col_screen = set_default(COL_SCREEN);
		Col_banner_text = set_default(COL_BANNER_TEXT);
		Col_window_text = set_default(COL_WINDOW_TEXT);
		Col_active_bord = set_default(COL_ACTIVE_BORD);
		Col_inactive_bord = set_default(COL_INACTIVE_BORD);
		Col_active_title = set_default(COL_ACTIVE_TITLE);
		Col_active_title_bar = set_default(COL_ACTIVE_TITLE_BAR);
		Col_inactive_title = set_default(COL_INACTIVE_TITLE);
		Col_inactive_title_bar = set_default(COL_INACTIVE_TITLE_BAR);
		Col_bar = set_default(COL_BAR);
		Col_bar_text = set_default(COL_BAR_TEXT);
		Col_slk_bar = set_default(COL_SLK_BAR);
		Col_slk_text = set_default(COL_SLK_TEXT);
		Col_field_bar = set_default(COL_FIELD_BAR);
		Col_field_text = set_default(COL_FIELD_TEXT);
	}

	/*
	 * Miscallaneous global attributes
	 */
	Toggle = settoggle(set_default(INIT_TOGGLE));
	set_default(INIT_NOBANG);
	Nobang = sing_eval(&Inits, INIT_NOBANG) ? TRUE: FALSE;
	
	set_default(INIT_DOUBLEVARS);
	if (sing_eval(&Inits, INIT_DOUBLEVARS))
		Doublevars = TRUE;
	else
		Doublevars = FALSE;

	permmsg = sing_eval(&Inits, INIT_PERMMSG);
	if (permmsg && permmsg[0] != '\0')
		mess_perm(permmsg);
/*	set_default(INIT_INTR);
	set_default(INIT_ONINTR);
*/
	return (0);
}

/*
 * SET_DEFAULT determines the value of the appropriate descriptor
 * and makes it the new default in the Initialization table.
 */
static char* 
set_default(index)
int index;
{
	char *tmp;
	
	tmp = sing_eval(&Inits, index);
	if (((tmp != 0) && (Init_single_tab[index].def != 0)) && 
	    (strcmp(tmp, Init_single_tab[index].def) != 0))
		Init_single_tab[index].def = strsave(tmp); 
	return(Init_single_tab[index].def);
}

int
read_cmds(cmdfile)
char *cmdfile;
{
	struct fm_mn cmds;
	char *command, *action;
	register int i, numcmds;
	FILE* fp, *fopen();
	char *get_def();

/*	if (access(cmdfile, 04) < 0)
 *		return (0);
 */

	/* make sure file exists and is readable  abs k15 */ 

	if ((fp = fopen(cmdfile, "r")) == NULL)
	{
	    mess_temp("error: commands file missing or not readable");
	    mess_flash("error: commands file missing or not readable");
	    doupdate();
	    return (0);
	}

	/*
	 * Parse commands file
	 */
	cmds.single.attrs = NULL;
	cmds.multi = NULL;
	parser(0, cmdfile, NULL, 0, NULL, Cmd_multi_tab, CMD_MULT_KEYS,
			&cmds.multi, fp);

	numcmds = array_len(cmds.multi);
	for (i = 0; i < numcmds; i++) {
		if ((command = multi_eval(&cmds, i, CMD_NAME)) == NULL)
			continue;
		action = get_def(&cmds, i, CMD_ACTION);
		if (action && strCcmp(action, "nop") == 0)  {
			del_cmd(command);	/* delete from command table */
/*
 * If one of the commands "unix" or "unix-system is disabled
 * the other one is disabled automatically.
*/
                        if (strCcmp(command, "unix-system") == 0)
                           del_cmd("unix");
                        else
                           if (strCcmp(command, "unix") == 0)
                              del_cmd("unix-system");
                  }
		else
			add_cmd(command, action,
				get_def(&cmds, i, CMD_HELP),
				get_def(&cmds, i, CMD_INTR),
				get_def(&cmds, i, CMD_ONINTR));
	}
	return (0);
}

/*
 * SETTOGGLE will determine the number of choices that must be present
 * for a form field before a choices "menu" is generated.
 */
static int
settoggle(str)
char *str;
{
	int threshold;

	if (strCcmp(str, "always") == 0) 
		threshold = BUFSIZ;	/* large number */
	else if (strCcmp(str, "never") == 0)
		threshold = 0;
	else if ((threshold = atoi(str)) <= 0)
		threshold = DEFTOGGLE;
	return(threshold);
}


#define MAKEpair(x, y, z)	setpair(x, getcolor_id(y), getcolor_id(z))
#define COL_STRSIZE	40

/*
 * SET_DEF_COLORS initializes the color attributes 
 */
int
set_def_colors()
{
	static int refresh_scr = TRUE;

	if (!Color_terminal)
		return (0);
	MAKEpair(WINDOW_PAIR, Col_window_text, Col_screen);
	MAKEpair(ACTIVE_TITLE_PAIR, Col_active_title, Col_active_title_bar);
	MAKEpair(INACTIVE_TITLE_PAIR, Col_inactive_title, Col_inactive_title_bar);
	MAKEpair(ACTIVE_BORD_PAIR, Col_active_bord, Col_screen);
	MAKEpair(INACTIVE_BORD_PAIR, Col_inactive_bord, Col_screen);
	MAKEpair(BAR_PAIR, Col_bar_text, Col_bar);
	MAKEpair(BANNER_PAIR, Col_banner_text, Col_screen);
	MAKEpair(SLK_PAIR, Col_slk_text, Col_slk_bar);
	MAKEpair(ACTIVE_SCROLL_PAIR, Col_screen, Col_active_bord);
	MAKEpair(INACTIVE_SCROLL_PAIR, Col_screen, Col_inactive_bord);
	if (MAKEpair(FIELD_PAIR, Col_field_text, Col_field_bar) == FALSE)
		MAKEpair(FIELD_PAIR, Col_screen, Col_window_text);
		
	set_slk_color(SLK_PAIR);
	set_scr_color(WINDOW_PAIR, refresh_scr);
	set_underline_attr(FIELD_PAIR);
	refresh_scr = FALSE;
	if (strcmp(Col_active_bord, Col_inactive_bord) == 0)
		Border_colors_differ = FALSE;
	else
		Border_colors_differ = TRUE;
	return (0);
}

/*
 * SET_DEF_STATUS initializes the status (banner) line
 */
int
set_def_status()
{
	int r, c, bancol;
	vt_id oldvid, vt_current();

	vt_ctl(STATUS_WIN, CTGETSIZ, &r, &c);
	if (Vflag) {
		Mail_col = 0;
		showmail(TRUE);
	}
	if (!Work_msg)
		Work_msg = WORKINGMSG; 
	Work_col = c - strlen(Work_msg);
	if (Banner) {
		if ((Bancolstr && *Bancolstr == '\0') ||
		    (strCcmp(Bancolstr, "center") == 0))
			bancol = center_it(Banner);
		else
			bancol = atoi(Bancolstr);
		if (bancol < 0 || bancol > c)
			bancol = c;
		oldvid = vt_current(STATUS_WIN);
		vt_ctl(STATUS_WIN, CTSETATTR, Attr_normal, BANNER_PAIR);
		wclrwin();
		wgo(0, bancol);
		winprintf(Banner);
		vt_current(oldvid);
	}
	return (0);
}

/*
 * GET_DESC_VAL scans the filename for the "target" descriptor ...
 * Though the function is generic, its primary use is the "slk_layout"
 * descriptor in the Initialization file....
 * Unfortunately this descriptor has to be evaluated BEFORE curses
 * is ever initialized, therefore, it must be accounted for before the
 * Initialization file is parsed completely.
 */ 
char *
get_desc_val(filename, descname)
char *filename;
char *descname;
{
	FILE *fp;
	int evalflags;
	char strbuf[BUFSIZ];
	static char *retstr = nil;
	char *ptr, *eval_string();

	if ((fp = fopen(filename, "r")) == NULL) {
		warn(NOPEN, filename);
		return(retstr);
	}
	while (fgets(strbuf, BUFSIZ, fp) != NULL) {
		if ((ptr = strchr(strbuf, '=')) != NULL) {
			*ptr = '\0';
			if (strCcmp(strbuf, descname) == 0) {
				evalflags = RET_STR;
				retstr = eval_string(++ptr, &evalflags);
				break;
			}
		}
	}
	return(retstr);
}

/*
 * COPYRIGHT puts up the initial text object which can be customized by
 * the application (e.g., FACE puts up a copyright notice)
 */ 
vt_id 
copyright()
{
	vt_id	vid, vt_create();
	char	*text;

	if ((Intro_text && (*Intro_text != '\0')) ||
	    (Intro_title && (*Intro_title != '\0'))) {
		if ((vid = vt_create(Intro_title, VT_CENTER | VT_NONUMBER,
			 -1, -1, Intro_rows, Intro_cols)) == FAIL)
				return((vt_id)NULL);
		text = Intro_text;
	}
	else
		return((vt_id)NULL);
	vt_current(vid);
	winputs(text, NULL);
	vt_flush();
	sleep(2);
	return(vid);
}

static int
center_it(str)
char *str;
{
	int	r, c;
	int	datecol;
	int	s;

	s = strlen(str);
	vt_ctl(STATUS_WIN, CTGETSIZ, &r, &c);
	if (s < c)
		datecol = (c - s) / 2;
	else
		datecol = 0;
	return(datecol);
}

/* init_ctl
           return value of initialization desriptors
	   implemented as minimal routine for values currently needed.
	   expand as needed if more complex situation need to be handled.
*/
char * 
init_ctl(cmd)
unsigned int cmd;
{
    switch(cmd)
    {
    case CTGETINTR:
	if (Intr == NULL)
	    return("false");	/* default behavior */
	else
	    return(Intr);
	break;
    case CTGETONINTR:
	if (Onintr == NULL)
	    return(DEF_ONINTR);	
	else
	    return(Onintr);
	break;
    default:
	return((char *)FAIL);
    }
}
