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
#pragma ident	"%Z%%M%	%I%	%E% SMI"  /* from UCB 5.2 3/9/86 */

/*
 * the call
 *	x = frexp(arg,&exp);
 * must return a double fp quantity x which is <1.0
 * and the corresponding binary exponent "exp".
 * such that
 *	arg = x*2^exp
 */
double
frexp(x, i)
	double x;
	int *i;
{
	int neg, j;

	j = 0;
	neg = 0;
	if (x<0) {
		x = -x;
		neg = 1;
	}
	if (x>=1.0)
		while (x>=1.0) {
			j = j+1;
			x = x/2;
		}
	else if (x < 0.5 && x != 0.0)
		while(x<0.5) {
			j = j-1;
			x = 2*x;
		}
	*i = j;
	if(neg)
		x = -x;
	return (x);
}
