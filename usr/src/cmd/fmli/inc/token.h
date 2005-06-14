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
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


/*
 * Copyright  (c) 1985 AT&T
 *	All Rights Reserved
 *
 */

#ident	"%Z%%M%	%I%	%E% SMI"       /* SVr4.0 1.7 */

typedef long	token;

extern	token	_cmd_to_tok();

#define	cmd_to_tok(a)		_cmd_to_tok(a, TRUE, TRUE)
#define	mencmd_to_tok(a)	_cmd_to_tok(a, FALSE, FALSE)

/* Funny "characters" enabled for various special function keys for input */
/* This list is created from caps and curses.ed. Do not edit it! */
#define TOK_BREAK	0401		/* break key (unreliable) */
#define TOK_DOWN	0402		/* Sent by terminal down arrow key */
#define TOK_UP		0403		/* Sent by terminal up arrow key */
#define TOK_LEFT	0404		/* Sent by terminal left arrow key */
#define TOK_RIGHT	0405		/* Sent by terminal right arrow key */
#define TOK_HOME	0406		/* Sent by home key. */
#define TOK_BACKSPACE	0407		/* Sent by backspace key */
#define TOK_F0		0410		/* function key f0. */
#define TOK_F(n)	(KEY_F0+(n))	/* Space for 64 function keys is reserved. */
#define TOK_DL		0510		/* Sent by delete line key. */
#define TOK_IL		0511		/* Sent by insert line. */
#define TOK_DC		0512		/* Sent by delete character key. */
#define TOK_IC		0513		/* Sent by ins char/enter ins mode key. */
#define TOK_EIC		0514		/* Sent by rmir or smir in insert mode. */
#define TOK_CLEAR	0515		/* Sent by clear screen or erase key. */
#define TOK_EOS		0516		/* Sent by clear-to-end-of-screen key. */
#define TOK_EOL		0517		/* Sent by clear-to-end-of-line key. */
#define TOK_SF		0520		/* Sent by scroll-forward/down key */
#define TOK_SR		0521		/* Sent by scroll-backward/up key */
#define TOK_NPAGE	0522		/* Sent by next-page key */
#define TOK_PPAGE	0523		/* Sent by previous-page key */
#define TOK_STAB	0524		/* Sent by set-tab key */
#define TOK_CTAB	0525		/* Sent by clear-tab key */
#define TOK_CATAB	0526		/* Sent by clear-all-tabs key. */
#define TOK_ENTER	0527		/* Enter/send (unreliable) */
#define TOK_SRESET	0530		/* soft (partial) reset (unreliable) */
#define TOK_RESET	0531		/* reset or hard reset (unreliable) */
#define TOK_PRINT	0532		/* print or copy */
#define TOK_LL		0533		/* Sent by home-down key */
					/* The keypad is arranged like this: */
					/*    a1    up    a3   */
					/*   left   b2  right  */
					/*    c1   down   c3   */
#define TOK_A1		0534		/* Upper left of keypad */
#define TOK_A3		0535		/* Upper right of keypad */
#define TOK_B2		0536		/* Center of keypad */
#define TOK_C1		0537		/* Lower left of keypad */
#define TOK_C3		0540		/* Lower right of keypad */
#define TOK_BTAB	0541		/* Back tab key */
#define TOK_BEG		0542		/* beg(inning) key */
#define TOK_CANCEL	0543		/* cancel key */
#define TOK_CLOSE	0544		/* close key */
#define TOK_COMMAND	0545		/* cmd (command) key */
#define TOK_COPY	0546		/* copy key */
#define TOK_CREATE	0547		/* create key */
#define TOK_END		0550		/* end key */
#define TOK_EXIT	0551		/* exit key */
#define TOK_FIND	0552		/* find key */
#define TOK_HELP	0553		/* help key */
#define TOK_MARK	0554		/* mark key */
#define TOK_MESSAGE	0555		/* message key */
#define TOK_MOVE	0556		/* move key */
#define TOK_NEXT	0557		/* next object key */
#define TOK_OPEN	0560		/* open key */
#define TOK_OPTIONS	0561		/* options key */
#define TOK_PREVIOUS	0562		/* previous object key */
#define TOK_REDO	0563		/* redo key */
#define TOK_REFERENCE	0564		/* ref(erence) key */
#define TOK_REFRESH	0565		/* refresh key */
#define TOK_REPLACE	0566		/* replace key */
#define TOK_RESTART	0567		/* restart key */
#define TOK_RESUME	0570		/* resume key */
#define TOK_SAVE	0571		/* save key */
#define TOK_SBEG	0572		/* shifted beginning key */
#define TOK_SCANCEL	0573		/* shifted cancel key */
#define TOK_SCOMMAND	0574		/* shifted command key */
#define TOK_SCOPY	0575		/* shifted copy key */
#define TOK_SCREATE	0576		/* shifted create key */
#define TOK_SDC		0577		/* shifted delete char key */
#define TOK_SDL		0600		/* shifted delete line key */
#define TOK_SELECT	0601		/* select key */
#define TOK_SEND	0602		/* shifted end key */
#define TOK_SEOL	0603		/* shifted clear line key */
#define TOK_SEXIT	0604		/* shifted exit key */
#define TOK_SFIND	0605		/* shifted find key */
#define TOK_SHELP	0606		/* shifted help key */
#define TOK_SHOME	0607		/* shifted home key */
#define TOK_SIC		0610		/* shifted input key */
#define TOK_SLEFT	0611		/* shifted left arrow key */
#define TOK_SMESSAGE	0612		/* shifted message key */
#define TOK_SMOVE	0613		/* shifted move key */
#define TOK_SNEXT	0614		/* shifted next key */
#define TOK_SOPTIONS	0615		/* shifted options key */
#define TOK_SPREVIOUS	0616		/* shifted prev key */
#define TOK_SPRINT	0617		/* shifted print key */
#define TOK_SREDO	0620		/* shifted redo key */
#define TOK_SREPLACE	0621		/* shifted replace key */
#define TOK_SRIGHT	0622		/* shifted right arrow */
#define TOK_SRSUME	0623		/* shifted resume key */
#define TOK_SSAVE	0624		/* shifted save key */
#define TOK_SSUSPEND	0625		/* shifted suspend key */
#define TOK_SUNDO	0626		/* shifted undo key */
#define TOK_SUSPEND	0627		/* suspend key */
#define TOK_UNDO	0630		/* undo key */
#define TOK_MOUSE	0631		/* Mouse event has occured */

/* use these for redefining the slks */

#define TOK_SLK1	0700
#define TOK_SLK2	0701
#define TOK_SLK3	0702
#define TOK_SLK4	0703
#define TOK_SLK5	0704
#define TOK_SLK6	0705
#define TOK_SLK7	0706
#define TOK_SLK8	0707
#define TOK_SLK9	0710
#define TOK_SLK10	0711
#define TOK_SLK11	0712
#define TOK_SLK12	0713
#define TOK_SLK13	0714
#define TOK_SLK14	0715
#define TOK_SLK15	0716
#define TOK_SLK16	0717
#define TOK_TOGSLK	0720

/* FMLI TOKENS */

#define TOK_TAB		011
#define TOK_RETURN	015
#define TOK_ERASE	0177
#define TOK_NOP		0721
#define TOK_CMD		0722	/* brings up commands menu */
#define TOK_SCRAMBLE	0723
#define TOK_UNSCRAMBLE	0724
#define TOK_LOGOUT	0725
#define TOK_SECURITY	0726
#define TOK_ORGANIZE	0727
#define TOK_WDWMGMT	0730	/* brings up wdw-mgmt menu */
#define TOK_SHOW_PATH	0731
#define TOK_GOTO	0732
#define TOK_DELETE	TOK_DL
#define TOK_DISPLAY	0734
#define TOK_TIME	0735
#define TOK_UNIX	0736
#define TOK_BADCHAR	0737
#define TOK_LFULL	0740	/* editor line full */
#define TOK_WRAP	0741	/* editor word wrap */
#define TOK_FUNCTION	0742
#define TOK_PREV_WDW	0743
#define TOK_NEXT_WDW	0744
#define TOK_MENCMD	0745
#define TOK_CLEANUP	0746
#define TOK_UNK_CMD	0747
#define TOK_PRINTCHAR	0750
#define TOK_CHECKWORLD	0751
#define TOK_NUNIQUE	0752
#define TOK_UNDELETE	0753
#define TOK_REREAD	0754
#define TOK_DEBUG	0755
#define TOK_SET		0756
#define TOK_RUN		0757
#define TOK_OBJOP	0760
#define TOK_RELEASE	0761	/* release command */
#define TOK_DONE	0762	/* done key */
#define TOK_BPRESSED	0763	/* button pressed */
#define TOK_BRELEASED	0764	/* button released */

/* flags to be OR'ed in with token */
#define TOK_HASARGS	(0100000)	/* token has arguments */
#define TOK_ERROR	(0200000)	/* tok is bad */
