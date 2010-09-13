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
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


/*
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


#pragma ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.1.1.1 */

#include "mt.h"
#include <xti.h>
#include <sys/types.h>
#include <stropts.h>
#include "tx.h"

/*
 * State transition table for TLI/XTI user level states.
 */

#define	ers	T_BADSTATE	/* error state */

char tiusr_statetbl[T_NOEVENTS][T_NOSTATES] = {

/*
 *                                S    T    A    T    E    S
 *                                =    =    =    =    =    =
 *  E
 *  =                                              T		  T
 *  V                                              _		  _
 *  =                     T              T         D    T	  B
 *  E                     _    T         _    T    A    _    T    A
 *  =                     U    _    T    O    _    T    O    _    D
 *  N                     N    U    _    U    I    A    U    I    S
 *  =                     I    N    I    T    N    X    T    N    T
 *  T                     N    B    D    C    C    F    R    R    A
 *  =                     I    N    L    O    O    E    E    E    T
 *  S                     T    D    E    N    N    R    L    L    E
 *  =							        (err)
 *                       (0)  (1)  (2)  (3)  (4)  (5)  (6)  (7)  (8)
 */
/* BEGIN CSTYLED */
/* T_OPEN (0)        */ {  1, ers, ers, ers, ers, ers, ers, ers, ers},
/* T_BIND (1)        */ {ers,   2, ers, ers, ers, ers, ers, ers, ers},
/* T_OPTMGMT (2)     */ {ers,   1,   2,   3,   4,   5,   6,   7, ers},
/* T_UNBIND (3)      */ {ers, ers,   1, ers, ers, ers, ers, ers, ers},
/* T_CLOSE (4)       */ {ers,   0, ers, ers, ers, ers, ers, ers, ers},
/* T_SNDUDATA (5)    */ {ers, ers,   2, ers, ers, ers, ers, ers, ers},
/* T_RCVUDATA (6)    */ {ers, ers,   2, ers, ers, ers, ers, ers, ers},
/* T_RCVUDERR (7)    */ {ers, ers,   2, ers, ers, ers, ers, ers, ers},
/* T_CONNECT1 (8)    */ {ers, ers,   5, ers, ers, ers, ers, ers, ers},
/* T_CONNECT2 (9)    */ {ers, ers,   3, ers, ers, ers, ers, ers, ers},
/* T_RCVCONNECT (10) */ {ers, ers, ers,   5, ers, ers, ers, ers, ers},
/* T_LISTN (11)      */ {ers, ers,   4, ers,   4, ers, ers, ers, ers},
/* T_ACCEPT1 (12)    */ {ers, ers, ers, ers,   5, ers, ers, ers, ers},
/* T_ACCEPT2 (13)    */ {ers, ers, ers, ers,   2, ers, ers, ers, ers},
/* T_ACCEPT3 (14)    */ {ers, ers, ers, ers,   4, ers, ers, ers, ers},
/* T_SND (15)        */ {ers, ers, ers, ers, ers,   5, ers,   7, ers},
/* T_RCV (16)        */ {ers, ers, ers, ers, ers,   5,   6, ers, ers},
/* T_SNDDIS1 (17)    */ {ers, ers, ers,   2,   2,   2,   2,   2, ers},
/* T_SNDDIS2 (18)    */ {ers, ers, ers, ers,   4, ers, ers, ers, ers},
/* T_RCVDIS1 (19)    */ {ers, ers, ers,   2, ers,   2,   2,   2, ers},
/* T_RCVDIS2 (20)    */ {ers, ers, ers, ers,   2, ers, ers, ers, ers},
/* T_RCVDIS3 (21)    */ {ers, ers, ers, ers,   4, ers, ers, ers, ers},
/* T_SNDREL (22)     */ {ers, ers, ers, ers, ers,   6, ers,   2, ers},
/* T_RCVREL (23)     */ {ers, ers, ers, ers, ers,   7,   2, ers, ers},
/* T_PASSCON (24)    */ {ers,   5,   5, ers, ers, ers, ers, ers, ers},

/*
 * Following state transitions are as in printed specs but wrong
 * so only in comments for reference
 * - The incorrect T_OPTMGMT state is what TLI historically implied
 * - The incorrect T_PASSCON state is from the XTI spec.
 *
 * T_OPTMGMT (2)        {ers, ers,   2, ers, ers, ers, ers, ers,  ers},
 * T_PASSCON (24)       {ers, ers,   5, ers, ers, ers, ers, ers,  ers},
 */

/* END CSTYLED */
};
