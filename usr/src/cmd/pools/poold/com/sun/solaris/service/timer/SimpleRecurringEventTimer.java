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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * ident	"%Z%%M%	%I%	%E% SMI"
 */

package com.sun.solaris.service.timer;

/**
 * A recurring event timer.  Like all Java time consumers, which rely on
 * wall time, adjustments to the time of day will adversely affect the
 * accuracy of the period.
 */
public class SimpleRecurringEventTimer implements RecurringEventTimer
{
	/**
	 * Next time the event is to occur.
	 */
	private long nextFiring;

	/**
	 * Period between recurrences of the event, in milliseconds.
	 */
	private long period;

	/**
	 * Multiplier to convert seconds to milliseconds.
	 */
	public static final int SEC = 1000;

	/**
	 * Establishes a timer which will fire every 'period'
	 * milliseconds starting from now.
	 */
	public SimpleRecurringEventTimer(long period)
	{
		this.period = period;
		nextFiring = System.currentTimeMillis() + period;
	}

	/**
	 * Cause the current thread to wait until at least the time of
	 * the next event, as near as possible, unless interrupted.
	 *
	 * @throws InterruptedException if the thread is interrupted
	 * while waiting for the next firing.  Subsequent calls to this
	 * method will wait for the same firing.
	 */
	public void waitUntilNextFiring() throws InterruptedException
	{
		long delta;

		while ((delta = nextFiring - System.currentTimeMillis()) > 0)
			Thread.sleep(delta);

		nextFiring += period;
	}
}
