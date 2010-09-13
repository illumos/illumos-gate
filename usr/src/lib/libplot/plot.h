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
 * Copyright (c) 1997 by Sun Microsystems, Inc.
 * All rights reserved
 */

#ifndef	_PLOT_H
#define	_PLOT_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.2	*/

#ifdef	__cplusplus
extern "C" {
#endif

#ifdef	__STDC__

extern	void arc(short, short, short, short, short, short);
extern	void box(short, short, short, short);
extern	void circle(short, short, short);
extern	void closepl(void);
extern	void closevt(void);
extern	void cont(short, short);
extern	void erase(void);
extern	void label(char *);
extern	void line(short, short, short, short);
extern	void linmod(char *);
extern	void move(short, short);
extern	void openpl(void);
extern	void openvt(void);
extern	void point(short, short);
extern	void space(short, short, short, short);

#else

extern	void arc();
extern	void box();
extern	void circle();
extern	void closepl();
extern	void closevt();
extern	void cont();
extern	void erase();
extern	void label();
extern	void line();
extern	void linmod();
extern	void move();
extern	void openpl();
extern	void openvt();
extern	void point();
extern	void space();

#endif /* __STDC__ */

#ifdef __cplusplus
}
#endif

#endif /* _PLOT_H */
