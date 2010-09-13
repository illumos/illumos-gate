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

int me;			/* an integer global variable */
this int foo;		/* an integer clause-local variable */

tick-1sec
{
	/*
	 * Set foo to be 10 if and only if this is the first clause executed.
	 */
	this->foo = (me % 3 == 0) ? 10 : this->foo;
	printf("Clause 1 is number %d; foo is %d\n", me++ % 3, this->foo++);
}

tick-1sec
{
	/*
	 * Set foo to be 20 if and only if this is the first clause executed. 
	 */
	this->foo = (me % 3 == 0) ? 20 : this->foo;
	printf("Clause 2 is number %d; foo is %d\n", me++ % 3, this->foo++);
}

tick-1sec
{
	/*
	 * Set foo to be 30 if and only if this is the first clause executed.
	 */
	this->foo = (me % 3 == 0) ? 30 : this->foo;
	printf("Clause 3 is number %d; foo is %d\n", me++ % 3, this->foo++);
}
