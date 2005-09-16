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

#include	<curses.h>
#include	<fcntl.h>
#include	"wish.h"
#include	"token.h"
#include	"message.h"
#include	"vt.h"
#include	"var_arrays.h"
#include	"actrec.h"
#include	"moremacros.h"
#include	"vtdefs.h"

#ifdef	TIME_IT

#include	<sys/types.h>
#include	<sys/times.h>

#endif /* TIME_IT */

extern time_t	Cur_time;	/* abs k15, EFT k16*/
extern char Semaphore[];
extern int Coproc_active;
extern int Vflag;
extern time_t	time();	        /* EFT abs k16 */


/* #ifdef i386  abs k18 */

/*
 * redefine curses mouse position macros
 */
#define SCR_ROW		MOUSE_Y_POS
#define SCR_COL		MOUSE_X_POS

/*
 * Given a screen offset (r, c), PTS_to() will determine whether r,c 
 * points to a given frame (excluding the frame border).
 * (br, bc is the beginning offset of the frame on the screen and
 * mr, mc is the maximum rows and columns of the frame)
 */
#define PTS_to(r, c, br, bc, mr, mc) \
		((r > br) && (r < (br + mr - 1)) && \
		 (c > bc) && (c < (bc + mc - 1)))
/*
 * ON_border() will evaluate to true if the mouse points to the
 * frame border
 */
#define ON_border(r, c, br, bc, mr, mc) \
		(((r == br || (r == (br + mr - 1))) && \
		  (c >= bc && (c <= (bc + mc - 1)))) || \
		 ((c == bc || (c == (bc + mc - 1))) && \
		  (r >= br && (r <= (br + mr - 1)))))

/*
 * Determine the mouse offset within the frame (0,0 based)
 * (excluding the frame border). 
 */
#define FRAME_ROW(r1, r2)	(r1 - (r2 + 1))
#define FRAME_COL(c1, c2)	(c1 - (c2 + 1))

static token page_tok();
static token do_mouse(), do_open_mouse();
static int on_top();
/* #endif abs k18 */

int Mouse_row;
int Mouse_col;
int Open_mouse_mode = FALSE;

extern long	Mail_check;
extern long	Interupt_pending;

token
physical_stream(t)
register token	t;
{
    token	wgetchar();
    int	fd;

#ifdef PHYSICAL			/* i dont know what this does but since
				 * it was un-compilable until k17
				 * it must never have been used. abs */

    struct tms	tms1, tms2;
    clock_t		real1;	       /* EFT abs k16 */
    int		lcv1 = 10000;

    real1 = times( &tms1 );	/* ; added. abs k17 */
	
    while ( lcv1-- )
    {
#endif /* PHYSICAL */

	Cur_time = time((time_t)0);

	ar_checkworld(FALSE);
	working(FALSE);
	if (Vflag)
	    showmail( FALSE );

	(void) mess_flush(FALSE);

/* new les */
	vt_flush();

	alarm((int) Mail_check);
	if (Coproc_active)
	{
	    /*
	     * The call to open is to protect "vsig" from
	     * sending a signal to FACE when the screen
	     * is being painted ...
	     * Vsig will block on the semaphore until FACE
	     * is able to receive signals ..
	     * This code may be changed if a better solution
	     * is found ...
	     * Interupt_pending is definined in main.c and
	     * set in the interupt handler for a SIGUSR2 
	     * once a signal is encountered ...
	     */ 
	    fd = open(Semaphore, O_RDONLY|O_NDELAY);
	    if (Interupt_pending) 
	    {
		Interupt_pending = 0;
		ar_checkworld(TRUE);
		vt_flush();	/* abs k18.2 */
	    }
	    t = wgetchar();
	    close(fd);
	}	
	else
	    t = wgetchar();
	mess_unlock();		/* allow calls to mess_temp and mess_perm */

	if (t < 0)
	    t = TOK_NOP;
	else if (t >= TOK_F(1) && t <= TOK_F(8))
	    t = t - TOK_F(1) + TOK_SLK1;
/* #ifdef i386  abs k18*/
	else if (t == KEY_MOUSE)
	{ 
	    if (Open_mouse_mode)
		t = do_open_mouse();
	    else
		t = do_mouse();
	}
/* #endif  abs k18 */
	(void) mess_flush(TRUE);

	return t;

#ifdef PHYSICAL			/* abs k17 */
    }				/* abs k17 */
#endif /* PHYSICAL */           /* abs k17 */

}

/* #ifdef i386  abs k18 */

static token
do_mouse()
{
    register int brow, bcol, mrow, mcol;
    struct	 vt *v, *savev, *curvt;
    int	 num, onborder;
    token	 t;
    struct	 actrec *wdw_to_ar();

    if (BUTTON_CHANGED(2) || BUTTON_CHANGED(3))
	return(TOK_NOP);	/* only concerned about button 1 events */	
    if (BUTTON_CHANGED(1) && (BUTTON_STATUS(1) == BUTTON_PRESSED ||
			      BUTTON_STATUS(1) == BUTTON_CLICKED)) {
	/* 
	 * First check to see which frame (if any) the
	 * the mouse points to ...
	 */
	t = TOK_NOP;
	savev = curvt = &VT_array[VT_curid];
	getbegyx(curvt->win, brow, bcol);
	getmaxyx(curvt->win, mrow, mcol);
	if (ON_border(SCR_ROW, SCR_COL, brow, bcol, mrow, mcol)) {
	    /*
	     * Mouse points to the current frame border
	     */
	    onborder = TRUE;
	    t = TOK_BPRESSED;
	}
	else if (PTS_to(SCR_ROW, SCR_COL, brow, bcol, mrow, mcol)) {
	    /*
	     * Mouse points to the current frame
	     */
	    onborder = FALSE;
	    t = TOK_BPRESSED;
	}
	else {
	    /*
	     * Scan the list of VT's to find one that the 
	     * mouse points to ...
	     */
	    v = VT_array;
	    savev = NULL;
	    for (num = array_len(VT_array); num > 0; v++, num--) {
		if (v == curvt || !(v->flags & VT_USED) ||
		    (v->flags & VT_NOBORDER))
		    continue;	/* don't bother */
		getbegyx(v->win, brow, bcol);
		getmaxyx(v->win, mrow, mcol);
		if (ON_border(SCR_ROW, SCR_COL, brow, bcol, mrow, mcol)) {
		    if (on_top(v, savev)) {
			savev = v;
			onborder = TRUE;
		    }
		    t = TOK_BPRESSED;
		}
		else if (PTS_to(SCR_ROW, SCR_COL, brow, bcol, mrow, mcol)) {
		    if (on_top(v, savev)) {
			savev = v;
			onborder = FALSE;
		    }
		    t = TOK_BPRESSED;
		}
	    }
	}
	/*
	 * If the mouse doesn't point to a frame (t != TOK_BPRESSED)
	 * then return TOK_NOP 
	 */
	if (t != TOK_BPRESSED)
	    return(TOK_NOP);

	v = savev; 
	if (v != curvt) {
	    /*
	     * frame is not current so make it current
	     */
	    ar_current(wdw_to_ar(v->number), TRUE); /* abs k15 */
	    vt_flush();
	    curvt = &VT_array[VT_curid];
	    getbegyx(curvt->win, brow, bcol);
	    getmaxyx(curvt->win, mrow, mcol);
	}
	if (onborder == FALSE) {
	    /*
	     * If not on the frame border then
	     * do object specific action for 
	     * BUTTON PRESS 
	     */
	    Mouse_row = FRAME_ROW(SCR_ROW, brow);
	    Mouse_col = FRAME_COL(SCR_COL, bcol);
	    (void) arf_odsh(ar_get_current(), TOK_BPRESSED);
	    wrefresh(curvt->win);
	}
	if (mess_flush(FALSE))	/* update message line */
	    wrefresh(VT_array[MESS_WIN].win);

	if (BUTTON_STATUS(1) == BUTTON_PRESSED) {
	    /*
	     * Perform mouse tracking while the button is
	     * depressed ...  (if the mouse was "clicked" there
	     * is no need to track)
	     *
	     * NOTE: Do not map button release events to SLKS while
	     * tracking.
	     */
	    map_button(0);
	    for (; ;) {
		/* 
		 * No longer track on BUTTON_RELEASE
		 */
		if (BUTTON_STATUS(1) == BUTTON_RELEASED) {
		    Mouse_row = FRAME_ROW(SCR_ROW, brow);
		    Mouse_col = FRAME_COL(SCR_COL, bcol);
		    break;		
		}
		if (request_mouse_pos() == ERR)
		    break;
		if (MOUSE_MOVED && PTS_to(SCR_ROW, SCR_COL, brow, bcol, mrow, mcol)) {
		    Mouse_row = FRAME_ROW(SCR_ROW, brow);
		    Mouse_col = FRAME_COL(SCR_COL, bcol);
		    (void) arf_odsh(ar_get_current(), TOK_BPRESSED);
		    wrefresh(curvt->win);
		    if (mess_flush(FALSE))
			wrefresh(VT_array[MESS_WIN].win);
		}
	    }
	    map_button(BUTTON1_RELEASED);
	}
    }
    if (BUTTON_CHANGED(1) && (BUTTON_STATUS(1) == BUTTON_RELEASED ||
			      BUTTON_STATUS(1) == BUTTON_CLICKED)) {
	/*
	 * If XY points to the current frame return (TOK_BRELEASED)
	 * otherwise ignore the mouse event (TOK_NOP)
	 */
	flushinp();
	curvt = &VT_array[VT_curid];
	getbegyx(curvt->win, brow, bcol);
	getmaxyx(curvt->win, mrow, mcol);
	if ((SCR_COL - bcol + 1) == mcol) {
	    /* 
	     * The mouse points to the right frame border ...
	     * check to see if it is inside the scroll box 
	     */
	    t = page_tok(SCR_ROW, brow, mrow);
	}
	else if (PTS_to(SCR_ROW, SCR_COL, brow, bcol, mrow, mcol)) {
	    /*
	     * The mouse points to the current frame ...
	     * Determine the frame offset
	     */
	    Mouse_row = FRAME_ROW(SCR_ROW, brow);
	    Mouse_col = FRAME_COL(SCR_COL, bcol);
	    t = TOK_BRELEASED;
	}
	else 
	    t = TOK_NOP;
    }
    return(t);
}

/*
 * DO_OPEN_MOUSE is similar to DO_MOUSE except the mouse doesn't have 
 * to point inside a frame (e.g., frame management routines move and 
 * reshape)
 */
static token
do_open_mouse()
{
    token	 t;

    if (BUTTON_CHANGED(2) || BUTTON_CHANGED(3))
	return(TOK_NOP);	/* only concerned about button 1 events */	
    t = TOK_NOP;
    if (BUTTON_CHANGED(1) && BUTTON_STATUS(1) == BUTTON_PRESSED) {
	/*
	 * Perform mouse tracking while button is depressed
	 */
	map_button(0);
	for (; ;) {
	    t = TOK_NOP;
	    /* 
	     * No longer track on BUTTON_RELEASE
	     */
	    if (BUTTON_STATUS(1) == BUTTON_RELEASED) {
		Mouse_row = SCR_ROW;
		Mouse_row = SCR_ROW;
		t = TOK_BRELEASED;
		break;		
	    }
	    if (request_mouse_pos() == ERR)
		break;
	    if (MOUSE_MOVED) {
		Mouse_row = SCR_ROW;
		Mouse_col = SCR_COL;
		(void) arf_odsh(ar_get_current(), TOK_BPRESSED);
		vt_flush();
	    }
	}
	map_button(BUTTON1_RELEASED);
    }
    else if (BUTTON_CHANGED(1) && BUTTON_STATUS(1) == BUTTON_CLICKED) {
	/*
	 * Button was clicked so don't track ... interpret as
	 * Button press immediately followed by button release.
	 */
	Mouse_row = SCR_ROW;
	Mouse_col = SCR_COL;
	(void) arf_odsh(ar_get_current(), TOK_BPRESSED);
	vt_flush();
	t = TOK_BRELEASED;
    }
    return(t);
}

/*
 * Given that the mouse points to the right frame border,
 * PAGE_TOK() returns a page token if the mouse points to
 * the up/down arrow in the scroll box
 */
static token
page_tok(mouserow, brow, mrow)
int mouserow, brow, mrow;
{
    int uparrow, dnarrow, framerow;
    token rettok;

    uparrow = (mrow / 2) - 1;	/* location of up arrow */
    dnarrow = uparrow + 2;	/* location of down arrow */
    framerow = mouserow - brow;	/* location of the mouse */

    if (framerow == uparrow)
	rettok = TOK_PPAGE;
    else if (framerow == dnarrow)
	rettok = TOK_NPAGE; 
    else
	rettok = TOK_NOP;
    return(rettok);
}

/*
 * Given 2 frames ON_TOP will return TRUE if frame 1 (arg1) is
 * "on top of" frame 2 (arg2)
 */
static int
on_top(f1, f2)
struct vt *f1, *f2;
{
    struct	 actrec *wdw_to_ar();
    struct	 actrec *ar1, *ar2;

    if (f2 == (struct vt *)NULL)
	return(TRUE);
    ar1 = wdw_to_ar(f1->number);
    ar2 = wdw_to_ar(f2->number);
		
    if (ar_isfirst(ar1, ar2))
	return(TRUE);
    else
	return(FALSE);
}

/* #endif abs k18 */
