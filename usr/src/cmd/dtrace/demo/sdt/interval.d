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

#pragma D option quiet

sdt:::callout-start
{
	self->callout = ((callout_t *)arg0)->c_func;
}

fbt::timeout:entry
/self->callout && arg2 <= 100/
{
	/*
	 * In this case, we are most interested in interval timeout(9F)s that
	 * are short.  We therefore do a linear quantization from 0 ticks to
	 * 100 ticks.  The system clock's frequency ? set by the variable
	 * "hz" ? defaults to 100, so 100 system clock ticks is one second. 
	 */
	@callout[self->callout] = lquantize(arg2, 0, 100);
}

sdt:::callout-end
{
	self->callout = NULL;
}

END
{
	printa("%a\n%@d\n\n", @callout);
}
