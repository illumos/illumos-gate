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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/* ident	"%Z%%M%	%I%	%E% SMI" */

package com.sun.solaris.service.logging;

/**
 * <code>syslog(3C)</code> facility levels defined in
 * <code>sys/syslog.h</code>.
 */
public class Facility {
	/**
	 * LOG_KERN from <code>sys/syslog.h</code>
	 */
	private static final int LOG_KERN = 0 << 3;

	/**
	 * LOG_USER from <code>sys/syslog.h</code>
	 */
	private static final int LOG_USER = 1 << 3;

	/**
	 * LOG_MAIL from <code>sys/syslog.h</code>
	 */
	private static final int LOG_MAIL = 2 << 3;

	/**
	 * LOG_DAEMON from <code>sys/syslog.h</code>
	 */
	private static final int LOG_DAEMON = 3 << 3;

	/**
	 * LOG_AUTH from <code>sys/syslog.h</code>
	 */
	private static final int LOG_AUTH = 4 << 3;

	/**
	 * LOG_SYSLOG from <code>sys/syslog.h</code>
	 */
	private static final int LOG_SYSLOG = 5 << 3;

	/**
	 * LOG_LPR from <code>sys/syslog.h</code>
	 */
	private static final int LOG_LPR = 6 << 3;

	/**
	 * LOG_NEWS from <code>sys/syslog.h</code>
	 */
	private static final int LOG_NEWS = 7 << 3;

	/**
	 * LOG_UUCP from <code>sys/syslog.h</code>
	 */
	private static final int LOG_UUCP = 8 << 3;

	/**
	 * LOG_CRON from <code>sys/syslog.h</code>
	 */
	private static final int LOG_CRON = 15 << 3;

	/**
	 * LOG_LOCAL0 from <code>sys/syslog.h</code>
	 */
	private static final int LOG_LOCAL0 = 16 << 3;

	/**
	 * LOG_LOCAL1 from <code>sys/syslog.h</code>
	 */
	private static final int LOG_LOCAL1 = 17 << 3;

	/**
	 * LOG_LOCAL2 from <code>sys/syslog.h</code>
	 */
	private static final int LOG_LOCAL2 = 18 << 3;

	/**
	 * LOG_LOCAL3 from <code>sys/syslog.h</code>
	 */
	private static final int LOG_LOCAL3 = 19 << 3;

	/**
	 * LOG_LOCAL4 from <code>sys/syslog.h</code>
	 */
	private static final int LOG_LOCAL4 = 20 << 3;

	/**
	 * LOG_LOCAL5 from <code>sys/syslog.h</code>
	 */
	private static final int LOG_LOCAL5 = 21 << 3;

	/**
	 * LOG_LOCAL6 from <code>sys/syslog.h</code>
	 */
	private static final int LOG_LOCAL6 = 22 << 3;

	/**
	 * LOG_LOCAL7 from <code>sys/syslog.h</code>
	 */
	private static final int LOG_LOCAL7 = 23 << 3;

	/**
	 * LOG_KERN <code>syslog(3C)</code> facility
	 */
	public static final Facility KERN = new Facility(LOG_KERN, "KERN");

	/**
	 * LOG_USER <code>syslog(3C)</code> facility
	 */
	public static final Facility USER = new Facility(LOG_USER, "USER");

	/**
	 * LOG_MAIL <code>syslog(3C)</code> facility
	 */
	public static final Facility MAIL = new Facility(LOG_MAIL, "MAIL");

	/**
	 * LOG_DAEMON <code>syslog(3C)</code> facility
	 */
	public static final Facility DAEMON = new Facility(LOG_DAEMON,
	    "DAEMON");

	/**
	 * LOG_AUTH <code>syslog(3C)</code> facility
	 */
	public static final Facility AUTH = new Facility(LOG_AUTH, "AUTH");

	/**
	 * LOG_SYSLOG <code>syslog(3C)</code> facility
	 */
	public static final Facility SYSLOG = new Facility(LOG_SYSLOG,
	    "SYSLOG");

	/**
	 * LOG_LPR <code>syslog(3C)</code> facility
	 */
	public static final Facility LPR = new Facility(LOG_LPR, "LPR");

	/**
	 * LOG_NEWS <code>syslog(3C)</code> facility
	 */
	public static final Facility NEWS = new Facility(LOG_NEWS, "NEWS");

	/**
	 * LOG_UUCP <code>syslog(3C)</code> facility
	 */
	public static final Facility UUCP = new Facility(LOG_UUCP, "UUCP");

	/**
	 * LOG_CRON <code>syslog(3C)</code> facility
	 */
	public static final Facility CRON = new Facility(LOG_CRON, "CRON");

	/**
	 * LOG_LOCAL0 <code>syslog(3C)</code> facility
	 */
	public static final Facility LOCAL0 = new Facility(LOG_LOCAL0,
	    "LOCAL0");

	/**
	 * LOG_LOCAL1 <code>syslog(3C)</code> facility
	 */
	public static final Facility LOCAL1 = new Facility(LOG_LOCAL1,
	    "LOCAL1");

	/**
	 * LOG_LOCAL2 <code>syslog(3C)</code> facility
	 */
	public static final Facility LOCAL2 = new Facility(LOG_LOCAL2,
	    "LOCAL2");

	/**
	 * LOG_LOCAL3 <code>syslog(3C)</code> facility
	 */
	public static final Facility LOCAL3 = new Facility(LOG_LOCAL3,
	    "LOCAL3");

	/**
	 * LOG_LOCAL4 <code>syslog(3C)</code> facility
	 */
	public static final Facility LOCAL4 = new Facility(LOG_LOCAL4,
	    "LOCAL4");

	/**
	 * LOG_LOCAL5 <code>syslog(3C)</code> facility
	 */
	public static final Facility LOCAL5 = new Facility(LOG_LOCAL5,
	    "LOCAL5");

	/**
	 * LOG_LOCAL6 <code>syslog(3C)</code> facility
	 */
	public static final Facility LOCAL6 = new Facility(LOG_LOCAL6,
	    "LOCAL6");

	/**
	 * LOG_LOCAL7 <code>syslog(3C)</code> facility
	 */
	public static final Facility LOCAL7 = new Facility(LOG_LOCAL7,
	    "LOCAL7");

	/**
	 * Native facility of this instance.
	 */
	private int facility;

	/**
	 * Name of this facility.
	 */
	private String string;

	private Facility(int facility, String string)
	{
		this.facility = facility;
		this.string = string;
	}

	/**
	 * Returns the native <code>syslog(3C)</code> facility.
	 */
	public int getNative()
	{
		return (facility);
	}

	public boolean equals(Object o)
	{
		Facility f = (Facility)o;

		return (getNative() == f.getNative());
	}

	public String toString()
	{
		return (string);
	}
}
