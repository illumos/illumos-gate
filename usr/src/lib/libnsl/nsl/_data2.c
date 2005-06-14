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
 * Copyright 1993-2003 Sun Microsystems, Inc.  All rights reserved.
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

#define	err	T_BADSTATE	/* error state */

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
/* T_OPEN (0)        */ {  1, err, err, err, err, err, err, err, err},
/* T_BIND (1)        */ {err,   2, err, err, err, err, err, err, err},
/* T_OPTMGMT (2)     */ {err,   1,   2,   3,   4,   5,   6,   7, err},
/* T_UNBIND (3)      */ {err, err,   1, err, err, err, err, err, err},
/* T_CLOSE (4)       */ {err,   0, err, err, err, err, err, err, err},
/* T_SNDUDATA (5)    */ {err, err,   2, err, err, err, err, err, err},
/* T_RCVUDATA (6)    */ {err, err,   2, err, err, err, err, err, err},
/* T_RCVUDERR (7)    */ {err, err,   2, err, err, err, err, err, err},
/* T_CONNECT1 (8)    */ {err, err,   5, err, err, err, err, err, err},
/* T_CONNECT2 (9)    */ {err, err,   3, err, err, err, err, err, err},
/* T_RCVCONNECT (10) */ {err, err, err,   5, err, err, err, err, err},
/* T_LISTN (11)      */ {err, err,   4, err,   4, err, err, err, err},
/* T_ACCEPT1 (12)    */ {err, err, err, err,   5, err, err, err, err},
/* T_ACCEPT2 (13)    */ {err, err, err, err,   2, err, err, err, err},
/* T_ACCEPT3 (14)    */ {err, err, err, err,   4, err, err, err, err},
/* T_SND (15)        */ {err, err, err, err, err,   5, err,   7, err},
/* T_RCV (16)        */ {err, err, err, err, err,   5,   6, err, err},
/* T_SNDDIS1 (17)    */ {err, err, err,   2,   2,   2,   2,   2, err},
/* T_SNDDIS2 (18)    */ {err, err, err, err,   4, err, err, err, err},
/* T_RCVDIS1 (19)    */ {err, err, err,   2, err,   2,   2,   2, err},
/* T_RCVDIS2 (20)    */ {err, err, err, err,   2, err, err, err, err},
/* T_RCVDIS3 (21)    */ {err, err, err, err,   4, err, err, err, err},
/* T_SNDREL (22)     */ {err, err, err, err, err,   6, err,   2, err},
/* T_RCVREL (23)     */ {err, err, err, err, err,   7,   2, err, err},
/* T_PASSCON (24)    */ {err,   5,   5, err, err, err, err, err, err},

/*
 * Following state transitions are as in printed specs but wrong
 * so only in comments for reference
 * - The incorrect T_OPTMGMT state is what TLI historically implied
 * - The incorrect T_PASSCON state is from the XTI spec.
 *
 * T_OPTMGMT (2)        {err, err,   2, err, err, err, err, err,  err},
 * T_PASSCON (24)       {err, err,   5, err, err, err, err, err,  err},
 */

/* END CSTYLED */
};
