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

#include	<stdio.h>
#include	<curses.h>
#include	"wish.h"
#include	"vt.h"
#include	"message.h"
#include	"vtdefs.h"


static char	MESS_perm[MESSIZ] = "";
static char	SAVE_perm[MESSIZ] = "";
static char	MESS_frame[MESSIZ] = "";
static char	MESS_curr[MESSIZ] = "";
static char	MESS_temp[MESSIZ] = "";

/*
 * Mess_lock is used to avoid simultaneous writes to the message line
 * (i.e., subsequent calls to mess_temp() will be locked out until the
 *  "locked" temporary message is output to the message line ...
 *  see message.h)
 */
int Mess_lock = 0;

/*
 * Print the message "s" on the FMLI message line
 */
void
mess_flash(s)
register char	*s;
{
	WINDOW		*win;

	if (!s)
		s = nil;
	strncpy(MESS_curr, s, sizeof(MESS_curr) - 1);
	win = VT_array[ MESS_WIN ].win;
/*abs: change output routine to allow esc seq processing
	mvwaddstr( win, 0, 0, s ); 
*/
	wmove(win, 0, 0);
	winputs(s, win);
/****/
	wclrtobot( win );
	wnoutrefresh( win );
}

/*
 * Store the "temporary" message to be printed on the FMLI message line
 */ 
void
mess_temp(s)
register char	*s;
{
	if (!s)
		s = nil;
	if (!Mess_lock)
		strncpy(MESS_temp, s, sizeof(MESS_temp) - 1);
}

/*
 * Store the "temporary" message to be printed on the FMLI message line
 */ 
void
mess_frame(s)
register char	*s;
{
	if (!s)
		s = nil;
	strncpy(MESS_frame, s, sizeof(MESS_frame) - 1);
}

char *
get_mess_frame()
{
	return(MESS_frame);
}



/*
 * Store the "permanent" message to be printed on the FMLI message line
 */ 
char *
mess_perm(s)
register char	*s;
{
	char *sptr, *strcpy();

	if (!s)
		s = nil;
	sptr = strcpy(SAVE_perm, MESS_perm);
	strncpy(MESS_perm, s, sizeof(MESS_perm) - 1);
	return(sptr);		/* return previous perm message */
}

/*
 * Flush either the temporary or the permanent message
 */
int
mess_flush(permanent)
bool	permanent;
{
	int retval = FALSE;
	char *messstr;

	if (MESS_frame[0] != '\0')
		messstr = MESS_frame;	
	else
		messstr = MESS_perm;	
	if (permanent && strcmp(MESS_curr, messstr) != 0) {
		mess_flash(messstr);
		mess_temp("");		/* clear temp message string */
		retval = TRUE;
	}
	else if (!permanent) {		/* a temporary message */
		if (MESS_temp[0] == '\0') {
			/*
			 * If no temporary message, use permanent message
			 */
			if (strcmp(MESS_curr, messstr) != 0) {
				mess_flash(messstr);
				retval = TRUE;
			}
		}
		else if (strcmp(MESS_temp, MESS_curr) != 0) {
			/*
			 * If current message differs from temp message
			 */
			if (strcmp(MESS_curr, MESS_temp) != 0) {
				mess_flash(MESS_temp);
				retval = TRUE;
			}
		}
	}
	return(retval);	
}


/*
 * clear out the temp and frame messages that may be left as side-effects
 * of operations.  designed to be used at startup after all initial frames
 * have been opened but before the  1st frame is made current.  Since 
 * this frame is made current without any user input, messages generated
 * by the other initial frames may be present and would not otherwise be removed
 * --abs k18
*/

void 
mess_init()
{
    MESS_temp[0] = MESS_frame[0] = '\0';
    mess_flash(nil);
}
