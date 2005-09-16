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

/*	Copyright (c) 1984, 1985, 1986, 1987, 1988, 1989 AT&T */
/*	  All Rights Reserved   */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include "wish.h"
#include "token.h"
#include "slk.h"
#include "actrec.h"
#include "terror.h"
#include "ctl.h"
#include "menudefs.h"
#include "vtdefs.h"
#include "fm_mn_par.h"
#include "moremacros.h"
#include "eval.h"
#include "interrupt.h"
#include "sizes.h"

extern	menu_id menu_make();
extern char *Args[];
extern char nil[];
extern int Arg_count;

struct cmdspec {
	char *name;
	token tok;
	int  helpindex;
	char *tokstr;
	char *helpaction;
	char *intr;
	char *onintr;
};

#define NOTEXT	((int) -1)
 
/*
 * NODISP is used for internal commands not to be displayed on the
 * command menu.
*/

#define NODISP	((int) -2)

/*
 * Table from which command defaults are selected
 */
static struct cmdspec Defaults[] = {
	{"cancel",	TOK_CLOSE,	0,	NULL, NULL, NULL, NULL },
	{"cleanup",	TOK_CLEANUP,	1,	NULL, NULL, NULL, NULL },
	{"copy",	TOK_COPY,	NOTEXT,	NULL, NULL, NULL, NULL },
	{"create",	TOK_CREATE,	NOTEXT,	NULL, NULL, NULL, NULL },
	{"delete",	TOK_DELETE,	NOTEXT,	NULL, NULL, NULL, NULL },
	{"display",	TOK_DISPLAY,	NOTEXT,	NULL, NULL, NULL, NULL },
	{"exit",	TOK_LOGOUT,	3,	NULL, NULL, NULL, NULL },
	{"find",	TOK_FIND,	NOTEXT,	NULL, NULL, NULL, NULL },
	{"frm-mgmt",	TOK_WDWMGMT,	4,	NULL, NULL, NULL, NULL },
	{"goto",	TOK_GOTO,	5,	NULL, NULL, NULL, NULL },
	{"help",	TOK_HELP,	6,	NULL, NULL, NULL, NULL },
	{"move",	TOK_MOVE,	NOTEXT,	NULL, NULL, NULL, NULL },
	{"next-frm",	TOK_NEXT_WDW,	7,	NULL, NULL, NULL, NULL },
	{"organize",	TOK_ORGANIZE,	NOTEXT,	NULL, NULL, NULL, NULL },
	{"prev-frm",	TOK_PREV_WDW,	8,	NULL, NULL, NULL, NULL },
	{"print",	TOK_PRINT,	NOTEXT,	NULL, NULL, NULL, NULL }, 
	{"redescribe",	TOK_SREPLACE,	NOTEXT,	NULL, NULL, NULL, NULL },
	{"refresh",	TOK_REFRESH,	9,	NULL, NULL, NULL, NULL },
	{"rename",	TOK_REPLACE,	NOTEXT,	NULL, NULL, NULL, NULL },
	{"run",		TOK_RUN,	NOTEXT,	NULL, NULL, NULL, NULL },
	{"security",	TOK_SECURITY,	NOTEXT,	NULL, NULL, NULL, NULL },
	{"show-path",   TOK_SHOW_PATH,  NOTEXT,	NULL, NULL, NULL, NULL },
	{"time",	TOK_TIME,	NOTEXT,	NULL, NULL, NULL, NULL },
	{"undelete", 	TOK_UNDELETE,	NOTEXT,	NULL, NULL, NULL, NULL },
	{"unix-system",	TOK_UNIX,	10,	NULL, NULL, NULL, NULL },
	{"update",	TOK_REREAD,	11,	NULL, NULL, NULL, NULL },
	{"unix",	TOK_UNIX,	NODISP,	NULL, NULL, NULL, NULL },
	{NULL, 		TOK_NOP,	NOTEXT,	NULL, NULL, NULL, NULL }
};

/*
 * Commands with NODISP have to be last in the above table befor the
 * NULL command.
*/

#define MAX_CMD	64

/*
 * Command table, presented to the user via the command menu.
 * This table, once initialized, is kept in alphabetical order.
 */
static struct cmdspec Commands[MAX_CMD];

/*
 * Commands that the user doesn't see in the cmd menu, but exist
 * none-the-less, (most are used for token translations from within
 * the FMLI language).
 */
static struct cmdspec Interncmd[] = {
	{"badchar",	TOK_BADCHAR,	NOTEXT,  NULL, NULL, NULL, NULL },
	{"choices",	TOK_OPTIONS,	NOTEXT,  NULL, NULL, NULL, NULL },
	{"checkworld",	TOK_CHECKWORLD,	NOTEXT,  NULL, NULL, NULL, NULL },
	{"close",	TOK_CLOSE,	NOTEXT,  NULL, NULL, NULL, NULL },
	{"cmd-menu",	TOK_CMD,	NOTEXT,	 NULL, NULL, NULL, NULL },
	{"done",	TOK_DONE,	NOTEXT,  NULL, NULL, NULL, NULL },
	{"enter",	TOK_RETURN,	NOTEXT,  NULL, NULL, NULL, NULL },
	{"exit_now",	TOK_LOGOUT,	NOTEXT,  NULL, NULL, NULL, NULL },
	{"mark",	TOK_MARK,	NOTEXT,  NULL, NULL, NULL, NULL },
	{"nextpage",	TOK_NPAGE,	NOTEXT,  NULL, NULL, NULL, NULL },
	{"nop",		TOK_NOP,	NOTEXT,  NULL, NULL, NULL, NULL },
	{"nunique", 	TOK_NUNIQUE,	NOTEXT,  NULL, NULL, NULL, NULL },
	{"objop",	TOK_OBJOP,	NOTEXT,  NULL, NULL, NULL, NULL },
	{"open",	TOK_OPEN,	NOTEXT,  NULL, NULL, NULL, NULL },	
	{"prevpage",	TOK_PPAGE,	NOTEXT,  NULL, NULL, NULL, NULL },
	{"release",	TOK_RELEASE,	NOTEXT,  NULL, NULL, NULL, NULL },
	{"reset",	TOK_RESET,	NOTEXT,  NULL, NULL, NULL, NULL },
	{"run",		TOK_RUN,	NOTEXT,  NULL, NULL, NULL, NULL },
	{"togslk",	TOK_TOGSLK,	NOTEXT,  NULL, NULL, NULL, NULL },

	/* Secret commands, they wouldn't let us document them... */
	/*{"?",		TOK_REDO,	NOTEXT,  NULL, NULL, NULL, NULL },*/
	/*{"%",		TOK_DEBUG,	NOTEXT,  NULL, NULL, NULL, NULL },*/
	{"=",		TOK_SET,	NOTEXT,  NULL, NULL, NULL, NULL },

	{NULL,		TOK_NOP,	NOTEXT,  NULL, NULL, NULL, NULL }
};

static int Numdefaults = sizeof(Defaults)/sizeof(struct cmdspec);
static int Numcommands = sizeof(Commands)/sizeof(struct cmdspec);
static struct actrec *Cmd_ar;
static char *Tokstr;
static int Cmd_index;

extern int Vflag;	/* is this the User Interface ?? */
extern char *init_ctl();	/* in if_init.c */
static struct cmdspec *get_cmd();

int
cmd_table_init()
{
	register int i, j;

	for (i = 0, j = 0; i < Numdefaults; i++) {
		if (Vflag || Defaults[i].helpindex != NOTEXT)
			Commands[j++] = Defaults[i];
	}
	Commands[j].name = NULL;
	return (0);
}

static struct menu_line
cmd_disp(n, ptr)
int n;
char *ptr;
{
	struct menu_line m;

	m.description = NULL;
	m.flags = 0;
 
/* Commands marked as NODISP do not go on the command menu */

	if (n >= Numcommands  || Commands[n].helpindex == NODISP)
		m.highlight = NULL;
	else
		m.highlight = Commands[n].name;
	return m;
}

static int
cmd_odsh(a, t)
struct actrec *a;
token t;
{
	extern int Arg_count;
	char **actstr, **eval_string();
	token tok, make_action();
	int flags;
	char *intr, *onintr;
	t = menu_stream(t);
	if (t == TOK_OPEN && Arg_count <= 1) {
		int line;

		(void) menu_ctl(a->id, CTGETPOS, &line);
		if (Commands[line].tok >= 0)		/* internal */
			tok = Commands[line].tok;
		else {
		    /* 	update the interrupt structures based on 
			the values for the current command, if
			defined else with the inherited values.
        	    */
		    Cur_intr.skip_eval =  FALSE;
		    if ((intr = Commands[line].intr) == NULL)
			intr = init_ctl(CTGETINTR);
		    flags = RET_BOOL;
		    Cur_intr.interrupt = FALSE;	/* dont intrupt eval of intr */
		    Cur_intr.interrupt =
		      (bool)(uintptr_t)eval_string(intr, &flags);

		    if ((onintr = Commands[line].onintr) == NULL)
			onintr = init_ctl(CTGETONINTR);
		    Cur_intr.oninterrupt = onintr;

		    flags = RET_ARGS;
		    actstr = eval_string(Commands[line].tokstr, &flags);
		    tok = make_action(actstr);
		}
		t = arf_odsh(a->backup, tok);
		(void) ar_close(a, FALSE);  /* Command execution causes close */
	}
	else if (t == TOK_NEXT)
		t = TOK_NOP;		/* eat it up */
	else if (t == TOK_CANCEL) {
		ar_backup();
		t = TOK_NOP;
	}
	return t;
}

static int
cmd_close(a)
struct actrec *a;
{
    Cmd_ar = NULL;
    return(AR_MEN_CLOSE(a));
}

int
cmd_help(cmd)
char *cmd;
{
    char help[PATHSIZ];
    int flags;
    char **helpaction, **eval_string();
    token tok, make_action(), generic_help();
    extern char *Filesys;
    char *cur_cmd(), *tok_to_cmd();
    struct cmdspec *command, *get_cmd();
    extern int Vflag;

    if (cmd && *cmd)
    {
/*      below cannot destinguish between user defined cmds.  abs k17
**	cmd = tok_to_cmd(cmd_to_tok(cmd));
*/
	if (cmd_to_tok(cmd) == TOK_NUNIQUE) 			/* abs k17 */
	{
	    mess_temp("Could not find help on that command"); 	/* abs k17 */
	    return(SUCCESS);					/* abs k17 */
	}

    }
    else
	cmd = cur_cmd();
    if (!cmd || ((command = get_cmd(cmd)) == NULL)) {
	mess_temp("Could not find help on that command");
	return(SUCCESS);
    }
	
    /*
     * If there is a help action defined then do it ...
     * else if there is a "hardcoded" help string use that
     * else if FACE is running use the FACE help files
     * else there is no help available ....
     */
    if (command->helpaction && command->helpaction[0] != '\0') {
	flags = RET_ARGS;
	helpaction = eval_string(command->helpaction, &flags);
	tok = make_action(helpaction);
	return(tok);
    }
    else if (command->helpindex >= 0)                    /* abs k18 */
	return(generic_help(cmd, command->helpindex));
    else if (Vflag) {		/* FACE has its own help file setup */
	sprintf(help, "%s/OBJECTS/Text.help", Filesys);
	objop("OPEN", "TEXT", help, cmd, cmd, NULL);
	return(SUCCESS);
    }
    else
	mess_temp("Could not find help on that command");
    return SUCCESS;
}

extern char *Help_text[];

char *Help_args[3] = {
	"OPEN",
	"TEXT",
	"-i"
};

token
generic_help(name, helpindex)
char *name;
int  helpindex;
{
	extern char	*Args[];
	extern int	Arg_count;
	extern int	Vflag;
	register IOSTRUCT *out;

	out = io_open(EV_USE_STRING, NULL);
	putastr("title=Help Facility: \"", out);
	putastr(name, out);
	putastr("\"\n", out);
	putastr("lifetime=shortterm\n", out); /* was longterm abs k18 */
	putastr("rows=12\n", out);
	putastr("columns=72\n", out);
	putastr("begrow=distinct\n", out);
	putastr("begcol=distinct\n", out);
	putastr("text=\"", out);
	putastr(Help_text[helpindex], out);
	putastr("\"\n", out);
	if (Vflag) {
		putastr("name=\"CONTENTS\"\n",out);
		putastr("button=8\n",out);
		putastr("action=OPEN MENU OBJECTS/Menu.h0.toc\n",out);
	}
	for (Arg_count = 0; Arg_count < 3; Arg_count++)
	{
		if ( Args[Arg_count])
			free( Args[Arg_count]); /* les 12/4 */
		Args[Arg_count] = strsave(Help_args[Arg_count]);
	}
	if ( Args[Arg_count])
		free( Args[Arg_count]); /* les 12/4 */
	Args[Arg_count++] = (char *) io_string(out);
	if ( Args[Arg_count])
		free( Args[Arg_count]); /* les 12/4 */
	Args[Arg_count] = NULL;
	io_close(out);
	return(TOK_OPEN);
}

struct actrec *
cmd_create()
{
	struct actrec a;
	struct actrec *ar_create(), *ar_current();

	if (Numcommands == 0) {
		mess_temp("There are no commands in the command menu");
		return(NULL);
	}

	a.id = (int) menu_make(-1, "Command Menu", VT_NONUMBER | VT_CENTER, 
			VT_UNDEFINED, VT_UNDEFINED, 0, 0, cmd_disp, NULL);

	ar_menu_init(&a);
	a.fcntbl[AR_CLOSE] = cmd_close;
	a.fcntbl[AR_ODSH] = cmd_odsh;
	a.fcntbl[AR_HELP] = cmd_help;
	a.flags = 0;

	/* theres no  frame level interrupt or oninterrupt  descriptors.. */
	/* .. so set up values in the  actrec now since they'll only ..   */
	/* .. change on a re-init. */
	ar_ctl(&a, CTSETINTR, init_ctl(CTGETINTR), NULL, NULL, NULL, NULL, NULL);
	ar_ctl(&a, CTSETONINTR, init_ctl(CTGETONINTR), NULL, NULL, NULL, NULL, NULL);

	Cmd_ar = ar_create(&a);
	return(ar_current(Cmd_ar, FALSE)); /* abs k15 */
}

token
_cmd_to_tok(cmd, partial, slk)
char *cmd;
bool partial;
bool slk;
{
    register int i;
    register int size = (cmd) ? strlen(cmd) : 0;
    register int cmdnumatch = 0, slknumatch = 0;	/* number of matches */
    register int cmdmatch= -1, slkmatch = -1;		/* index of last match */
    extern struct slk SLK_array[MAX_SLK];
    int strnCcmp(), strCcmp();
    
    Tokstr = NULL;
    Cmd_index = -1;
    if (!cmd)		/* no input (^j <return>) */
	return(TOK_CANCEL);
    if (slk) {
	for (i = 0; i < MAX_SLK; i++) {
	    if ((partial ? strnCcmp : strCcmp)(SLK_array[i].label, cmd, size) == 0) {
		/*
		 * If there is another match BUT ...
		 *    the command token is the same
		 *    OR the name strings match exactly
		 * then ignore the 'ith' SLK 
		 */
		if (slknumatch == 1 &&
		    (SLK_array[i].tok == SLK_array[slkmatch].tok ||
		     strCcmp(SLK_array[slkmatch].label, SLK_array[i].label) == 0))
		    continue;
		slknumatch++;
		slkmatch = i;
	    }
	}
    }
    
    for (i = 0; i < Numcommands; i++) {
        if (Commands[i].name == NULL)
		Commands[i].name = nil;
	if ((partial ? strnCcmp : strCcmp)(Commands[i].name, cmd, size) == 0) {
	    /*
	     * if there is an exact match then break
	     */
	    if (partial && strCcmp(Commands[i].name, cmd) == 0) { 
		cmdmatch = i;
		cmdnumatch = 1;
		break;
	    }
	    cmdnumatch++;
	    cmdmatch = i;
	}
    }
/* since "unix" is unadvertised, don't get confused by 2 partial matches 
 * for unix and unix-system. mek k17
 */
    if ((slknumatch == 0) && (cmdnumatch == 2) && 
	(strcmp(Commands[cmdmatch].name, "unix") == 0))
	    return(Commands[cmdmatch].tok);
    
    if (slknumatch + cmdnumatch == 0) {
	/*
	 * no matches, check internal command table 
	 */
	for (i = 0; Interncmd[i].name; i++)
	    if (strCcmp(Interncmd[i].name, cmd) == 0)
		return(Interncmd[i].tok);
	return(TOK_NOP);
    }
    else if (slknumatch > 1 || cmdnumatch > 1)	/* input not unique */
	return(TOK_NUNIQUE);
    else if (slknumatch == 1 && cmdnumatch == 0) {	/* matched slk only */
	Tokstr = SLK_array[slkmatch].tokstr;
	return(SLK_array[slkmatch].tok);
    }
    else if (cmdnumatch == 1 && slknumatch == 0) {  /* matched cmd only */
	Tokstr = Commands[cmdmatch].tokstr;
	Cmd_index = cmdmatch;
	return(Commands[cmdmatch].tok);
    }
    else {
	/*
	 * If there is only ONE match in both the
	 * SLKS and the Command Menu then
	 *  - the SLK takes precedence if both match exactly 
	 *  - match is not unique if both match "partially"
	 */
	if (strCcmp(SLK_array[slkmatch].label, Commands[cmdmatch].name) == 0) {
	    Tokstr = SLK_array[slkmatch].tokstr;
	    return(SLK_array[slkmatch].tok);
	}
	else
	    return(TOK_NUNIQUE);
    }	
}

/* LES: replace with MACRO's

token
cmd_to_tok(cmd)
char *cmd;
{
	return(_cmd_to_tok(cmd, TRUE, TRUE));
}

		NEVER CALLED
token
fullcmd_to_tok(cmd)
char *cmd;
{
	return(_cmd_to_tok(cmd, FALSE, TRUE));
}

token
mencmd_to_tok(cmd)
char *cmd;
{
	return(_cmd_to_tok(cmd, FALSE, FALSE));
}
*/

char *
tok_to_cmd(tok)
token tok;
{
	register int i;
	extern struct slk SLK_array[];

	/*  Most frequently referenced command is open, make it QUICK !!! */
	if (tok == TOK_OPEN)
		return("open");

	for (i = 0; i < Numcommands; i++)
		if (Commands[i].tok == tok)
			return Commands[i].name;
	for (i = 0; SLK_array[i].label; i++)
		if (SLK_array[i].tok == tok)
			return SLK_array[i].label;
	for (i = 0; Interncmd[i].name; i++)
		if (Interncmd[i].tok == tok)
			return Interncmd[i].name;
	return NULL;
}

char *
cur_cmd()
{
	int	line;
	/* char *cur_hist(); */

	if (ar_get_current() != Cmd_ar)
		return(NULL);
	menu_ctl(Cmd_ar->id, CTGETPOS, &line);
	return Commands[line].name;
}

/*
 * ADD_CMD will add a command to the command list preserving
 * alphabetical ordering
 */
int
add_cmd(name, tokstr, help, intr, onintr)
char *name;
char *tokstr;
char *help;
char *intr;
char *onintr;
{
	register int i, j, comp;

	for (i = 0; Interncmd[i].name; i++) {
		if (strcmp(Interncmd[i].name, name) == 0)
			return (0);	    /* internal command conflict */
	}
	for (i = 0; Commands[i].name; i++) {
		comp = strcmp(name, Commands[i].name);
		if (comp < 0) {
			/*
			 * shift list to make room for new entry
			 */
			for (j = MAX_CMD - 1; j > i; j--)
				Commands[j] = Commands[j - 1];

			Commands[i].name = strsave(name);
			Commands[i].tok = -1;	/* no token */ 
			Commands[i].helpindex = NOTEXT; 
			Commands[i].tokstr = strsave(tokstr);
			Commands[i].helpaction = strsave(help);
			Commands[i].intr = strsave(intr);
			Commands[i].onintr = strsave(onintr);
			break;
		}
		else if (comp == 0) {
			/*
			 * Command already exists
			 */
			if (Commands[i].tok >= 0) {
				/*
				 * Name conflict with a generic command,
				 * only accept redefinitions for helpaction
				 */
				if (help && (*help != '\0')) {
					Commands[i].helpindex = NOTEXT;
					Commands[i].helpaction= strsave(help);
				}
			}
			else {
				/*
				 * Redefine a previous definition
				 */
				Commands[i].name = strsave(name);
				Commands[i].tok = -1;	/* no token */ 
				Commands[i].helpindex = NOTEXT;
				Commands[i].tokstr = strsave(tokstr);
				Commands[i].helpaction = strsave(help);
				Commands[i].intr = strsave(intr);
				Commands[i].onintr = strsave(onintr);
			}
			break;
		}
	}
	return (0);
}


/*
 * DEL_CMD will remove a command from the command menu
 * (shifting the command menu accordingly)
 */
int
del_cmd(name)
char *name;
{
	register int i, j;

	for (i = 0; Commands[i].name; i++) {	/* if not end of list */
		if (strcmp(name, Commands[i].name) == 0) {
			/*
			 * scrunch list to remove entry
			 */
			for (j = i; j < MAX_CMD - 1; j++)
				Commands[j] = Commands[j + 1];
			break;
		}
	}
	return (0);
}

static struct cmdspec *
get_cmd(cmdstr)
char *cmdstr;
{
	register int i;

	for (i = 0; i < Numcommands && Commands[i].name; i++)
		if (strcmp(Commands[i].name, cmdstr) == 0)
			return(&(Commands[i]));
	return(NULL);
}
	
token
do_app_cmd()
{
	char **strlist, **eval_string();
	token t, make_action();
	int flags;
	char *intr, *onintr;

	if (Tokstr) 		  /* set in _cmd_to_tok */
	{
	    if (Cmd_index  >= 0)  /* set in _cmd_to_tok */
	    {
		/* 	update the interrupt structures based on 
			the values for the current command, if
			defined else with the inherited values.
        	*/
		Cur_intr.skip_eval =  FALSE;
		if ((intr = Commands[Cmd_index].intr) == NULL)
		    intr = init_ctl(CTGETINTR);
		flags = RET_BOOL;
		Cur_intr.interrupt = FALSE;	/* dont intrupt eval of intr */
		Cur_intr.interrupt =
		  (bool)(uintptr_t)eval_string(intr, &flags);
		
		if ((onintr = Commands[Cmd_index].onintr) == NULL)
		    onintr = init_ctl(CTGETONINTR);
		Cur_intr.oninterrupt = onintr;
	    }
	    flags = RET_ARGS; 
	    strlist = eval_string(Tokstr, &flags);
	    t = make_action(strlist);
	}
	else
	    t = TOK_NOP;
	return (t);
}



int
cmd_reinit(argc, argv, instr, outstr, errstr)
int argc;
char *argv[];
IOSTRUCT *instr;
IOSTRUCT *outstr;
IOSTRUCT *errstr;
{
	if (argv[1] && (*argv[1] != '\0') && (access(argv[1], 2) == 0))
	{
		read_inits(argv[1]);
		init_sfk(FALSE);  /* download PFK's for terms like 630. k17 */
		set_def_colors(); /* moved above next line. k17 */
		set_def_status();
		ar_ctl(Cmd_ar, CTSETINTR, init_ctl(CTGETINTR), NULL, NULL, NULL, NULL, NULL);
		ar_ctl(Cmd_ar, CTSETONINTR, init_ctl(CTGETONINTR), NULL, NULL, NULL, NULL, NULL);
		return(SUCCESS);
	}
	else
		return(FAIL);
}
