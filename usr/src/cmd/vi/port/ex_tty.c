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


/* Copyright (c) 1981 Regents of the University of California */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "ex.h"
#include "ex_tty.h"

static unsigned char allocspace[256];
static unsigned char *freespace;

/*
 * Terminal type initialization routines,
 * and calculation of flags at entry or after
 * a shell escape which may change them.
 */
static short GT;

void
gettmode(void)
{
	short speed;

	GT = 1;
	if(gTTY(2) == -1)
		return;
	if (termiosflag)
		speed = (short)cfgetospeed(&tty);
	else
		speed = tty.c_cflag & CBAUD;
	if (ospeed != speed)
		value(vi_SLOWOPEN) = (int)(speed) < B1200;
	ospeed = speed;
	normf = tty;
	UPPERCASE = (tty.c_iflag & IUCLC) != 0;
	if ((tty.c_oflag & TABDLY) == TAB3 || teleray_glitch)
		GT = 0;
	NONL = (tty.c_oflag & ONLCR) == 0;
}

void
setterm(unsigned char *type)
{
	char *tparm(); 
	unsigned char *chrptr;
	int unknown, i;
	int l;
	int errret;
	extern unsigned char termtype[];
	extern void setsize();

	unknown = 0;
	if (cur_term && exit_ca_mode)
		putpad((unsigned char *)exit_ca_mode);
	/*
	 * The code in this if statement is from 4.1.2 and fixes a bug where
	 * you couldn't change the term type using the ":set term" command.
	 */
	if (*termtype) {
#ifdef TRACE
                if (trace) fprintf(trace, "CALLED del_curterm with %s\n", termtype);
#endif
                del_curterm(cur_term); /* Zap the old data space which was allocated
                                        * previously (this is a set command)
                                        */
        }
	cur_term = 0;
	strcpy(termtype, type);

#ifdef XPG4
	use_env(1);		/* $LINES and $COLUMNS override terminfo */
#endif /* XPG4 */

	setupterm(type, 2, &errret);
	if (errret != 1) {
		unknown++;
		cur_term = 0;
		if (errret == 0) {
			setupterm("unknown", 1, &errret);
			if (errret == 0) {
			  perror(gettext("Unable to setup term:'unknown' missing in the terminfo database"));
			  exit(++errcnt);
			}
		}
		else if (errret == -1) {
			perror(gettext("Unable to find the terminfo database"));
			exit(++errcnt);
		}
	}
	if (errret == 1)
		resetterm();
#ifdef TRACE
	if (trace) fprintf(trace, "after setupterm, lines %d, columns %d, clear_screen '%s', cursor_address '%s'\n", lines, columns, clear_screen, cursor_address);
#endif
	setsize();
#ifdef OLD
	if(exit_attribute_mode)
		putpad(exit_attribute_mode);
#endif
	exit_bold = (exit_standout_mode ? exit_standout_mode : (exit_attribute_mode ? exit_attribute_mode : 0));
	i = lines;
	if (lines <= 1)
		lines = 24;
	if (lines > TUBELINES)
		lines = TUBELINES;
	l = lines;
	if (ospeed < B1200)
		l = 9;	/* including the message line at the bottom */
	else if (ospeed < B2400)
		l = 17;
	if (l > lines)
		l = lines;
	/*
	 * Initialize keypad arrow keys.
	 */
	freespace = allocspace;

#ifdef sun
	kpadd(arrows, (unsigned char *)key_ic, (unsigned char *)"i",
	    (unsigned char *)"inschar");
	kpadd(arrows, (unsigned char *)key_eic, (unsigned char *)"i",
	    (unsigned char *)"inschar");
	kpadd(arrows, (unsigned char *)key_up, (unsigned char *)"k",
	    (unsigned char *)"up");
	kpadd(arrows, (unsigned char *)key_down, (unsigned char *)"j",
	    (unsigned char *)"down");
	kpadd(arrows, (unsigned char *)key_left, (unsigned char *)"h",
	    (unsigned char *)"left");
	kpadd(arrows, (unsigned char *)key_right, (unsigned char *)"l",
	    (unsigned char *)"right");
	kpadd(arrows, (unsigned char *)key_home, (unsigned char *)"H",
	    (unsigned char *)"home");
#else
	kpadd(arrows, key_ic, "i", "inschar");
	kpadd(immacs, key_ic, "\033", "inschar");
	kpadd(arrows, key_eic, "i", "inschar");
	kpadd(immacs, key_eic, "\033", "inschar");

	kpboth(arrows, immacs, key_up, "k", "up");
	kpboth(arrows, immacs, key_down, "j", "down");
	kpboth(arrows, immacs, key_left, "h", "left");
	kpboth(arrows, immacs, key_right, "l", "right");
	kpboth(arrows, immacs, key_home, "H", "home");
	kpboth(arrows, immacs, key_il, "o\033", "insline");
	kpboth(arrows, immacs, key_dl, "dd", "delline");
	kpboth(arrows, immacs, key_clear, "\014", "clear");
	kpboth(arrows, immacs, key_eol, "d$", "clreol");
	kpboth(arrows, immacs, key_sf, "\005", "scrollf");
	kpboth(arrows, immacs, key_dc, "x", "delchar");
	kpboth(arrows, immacs, key_npage, "\006", "npage");
	kpboth(arrows, immacs, key_ppage, "\002", "ppage");
	kpboth(arrows, immacs, key_sr, "\031", "sr");
	kpboth(arrows, immacs, key_eos, "dG", "clreos");
#endif /* sun */

	/*
	 * Handle funny termcap capabilities
	 */
	/* don't understand insert mode with multibyte characters */
	if(MB_CUR_MAX > 1) {
		enter_insert_mode = NULL;
		exit_insert_mode = NULL;
#ifndef PRESUNEUC
		insert_character = NULL;
#endif /* PRESUNEUC */
	}

	if (change_scroll_region && save_cursor && restore_cursor) insert_line=delete_line="";
	if (parm_insert_line && insert_line==NULL) insert_line="";
	if (parm_delete_line && delete_line==NULL) delete_line="";
	if (insert_character && enter_insert_mode==NULL) enter_insert_mode="";
	if (insert_character && exit_insert_mode==NULL) exit_insert_mode="";
	if (GT == 0)
		tab = back_tab = NOSTR;

#ifdef SIGTSTP
	/*
	 * Now map users susp char to ^Z, being careful that the susp
	 * overrides any arrow key, but only for hackers (=new tty driver).
	 */
	{
		static unsigned char sc[2];
		int i;

		if (!value(vi_NOVICE)) {
			sc[0] = tty.c_cc[VSUSP];
			sc[1] = 0;
			if (sc[0] == CTRL('z')) {
				for (i=0; i<=4; i++)
					if (arrows[i].cap && arrows[i].cap[0] == CTRL('z'))
						addmac(sc, NULL, NULL, arrows);
			} else if(sc[0])
				addmac(sc, "\32", "susp", arrows);
		}
	}
#endif

	value(vi_WINDOW) = options[vi_WINDOW].odefault = l - 1;
	if (defwind)
		value(vi_WINDOW) = defwind;
	value(vi_SCROLL) = options[vi_SCROLL].odefault =
		hard_copy ? 11 : (value(vi_WINDOW) / 2);
	if (columns <= 4)
		columns = 1000;
	chrptr=(unsigned char *)tparm(cursor_address, 2, 2);
	if (chrptr==(unsigned char *)0 || chrptr[0] == 'O')	/* OOPS */
		cursor_address = 0;
	else
		costCM = cost(tparm(cursor_address, 10, 8));
	costSR = cost(scroll_reverse);
	costAL = cost(insert_line);
	costDP = cost(tparm(parm_down_cursor, 10));
	costLP = cost(tparm(parm_left_cursor, 10));
	costRP = cost(tparm(parm_right_cursor, 10));
	costCE = cost(clr_eol);
	costCD = cost(clr_eos);
	if (i <= 0)
		lines = 2;
	/* proper strings to change tty type */
	termreset();
	gettmode();
	value(vi_REDRAW) = insert_line && delete_line;
	value(vi_OPTIMIZE) = !cursor_address && !tab;
	if (ospeed == B1200 && !value(vi_REDRAW))
		value(vi_SLOWOPEN) = 1;	/* see also gettmode above */
	if (unknown)
		serror((unsigned char *)gettext("%s: Unknown terminal type"),
		    type);
}

#ifndef sun
/*
 * Map both map1 and map2 as below.  map2 surrounded by esc and 
 * the 'i', 'R', or 'a' mode.  However, because we don't know
 * the mode here we put in the escape and when the map() routine
 * is called for immacs mapping the mode is appended to the
 * macro. Therefore when you leave insert mode, to perform a
 * function key, it will (once the cursor movement is done)
 * restore you to the proper mode.
 */
kpboth(map1, map2, key, mapto, desc)
struct maps *map1, *map2;
unsigned char *key, *mapto, *desc;
{
	unsigned char surmapto[30];
	unsigned char *p;

	if (key == 0)
		return;
	kpadd(map1, key, mapto, desc);
	if (any(*key, "\b\n "))
		return;
	strcpy(surmapto, "\33");
	strcat(surmapto, mapto);
	p = freespace;
	strcpy(p, surmapto);
	freespace += strlen(surmapto) + 1;
	kpadd(map2, key, p, desc);
}
#endif /* !sun */

/*
 * Define a macro.  mapstr is the structure (mode) in which it applies.
 * key is the input sequence, mapto what it turns into, and desc is a
 * human-readable description of what's going on.
 */
void
kpadd(struct maps *mapstr, unsigned char *key, unsigned char *mapto,
unsigned char *desc)
{
	int i;

	for (i=0; i<MAXNOMACS; i++)
		if (mapstr[i].cap == 0)
			break;
	if (key == 0 || i >= MAXNOMACS)
		return;
	mapstr[i].cap = key;
	mapstr[i].mapto = mapto;
	mapstr[i].descr = desc;
}

unsigned char *
fkey(i)
	int i;
{
	if (i < 0 || i > 9)
		return ((unsigned char *)NOSTR);
	switch (i) {
	case 0: return ((unsigned char *)key_f0);
	case 1: return ((unsigned char *)key_f1);
	case 2: return ((unsigned char *)key_f2);
	case 3: return ((unsigned char *)key_f3);
	case 4: return ((unsigned char *)key_f4);
	case 5: return ((unsigned char *)key_f5);
	case 6: return ((unsigned char *)key_f6);
	case 7: return ((unsigned char *)key_f7);
	case 8: return ((unsigned char *)key_f8);
	case 9: return ((unsigned char *)key_f9);
	case 10: return ((unsigned char *)key_f0);
	}
	return ((unsigned char *)NOSTR);
}

/*
 * cost figures out how much (in characters) it costs to send the string
 * str to the terminal.  It takes into account padding information, as
 * much as it can, for a typical case.  (Right now the typical case assumes
 * the number of lines affected is the size of the screen, since this is
 * mainly used to decide if insert_line or scroll_reverse is better, and this always happens
 * at the top of the screen.  We assume cursor motion (cursor_address) has little
 * padding, if any, required, so that case, which is really more important
 * than insert_line vs scroll_reverse, won't be really affected.)
 */

static int costnum;

/* ARGSUSED */
int
countnum(char ch)
{
	costnum++;
	return (0);
}

int
cost(unsigned char *str)
{

	if (str == NULL || *str=='O')	/* OOPS */
		return 10000;	/* infinity */
	costnum = 0;
	tputs((char *)str, lines, countnum);
	return costnum;
}
