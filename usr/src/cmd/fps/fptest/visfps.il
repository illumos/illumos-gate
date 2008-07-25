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

/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __lint

/*ARGSUSED*/
unsigned long
setgsr(unsigned long arg1)
{

	return (0);
}

#else

.inline setgsr
	rd	%gsr,%o1
	wr	%o0,%gsr
	mov	%o1,%o0
.end

#endif

#ifdef __lint

/*ARGSUSED*/
float
fpackfix(double arg1)
{
	return (0);
}

#else

.inline	fpackfix
	fpackfix	%f0,%f0
.end

#endif

#ifdef __lint

/*ARGSUSED*/
unsigned long
fcmpne16(double arg1, double arg2)
{
	return (0);
}

#else

.inline	fcmpne16
	fcmpne16	%f0,%f2,%o0
.end

#endif

#ifdef __lint

/*ARGSUSED*/
unsigned long
fcmpgt16(double arg1, double arg2)
{
	return (0);
}

#else

.inline	fcmpgt16
	fcmpgt16	%f0,%f2,%o0
.end

#endif
