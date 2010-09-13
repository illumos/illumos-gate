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
/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved  	*/


/*
 * Copyright (c) 1999 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

typedef	struct {
	int	button;
	int	percent;
	int	x1;
	int	y1;
	int	x2;
	int	y2;
} MOUSEEVENT;

typedef	struct {
	char	*text;
	char	*value;
} MOUSEMENU;

typedef	enum {
	NONE,		/* must be first value */
	EMACSTERM,
	MYX,
	PC7300
} MOUSETYPE;

extern	MOUSETYPE mouse;

extern int mouseselection(MOUSEEVENT *p, int offset, int maxselection);
extern void cleanupmouse(void);
extern void drawscrollbar(int top, int bot, int total);
extern int getcoordinate(void);
extern MOUSEEVENT *getmouseevent(void);
extern int getpercent(void);
extern void initmouse(void);
extern int labelarea(char *s);
extern void reinitmouse(void);
extern void downloadmenu(MOUSEMENU *menu);
