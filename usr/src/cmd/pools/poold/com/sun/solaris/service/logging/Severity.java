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

import java.util.*;
import java.util.logging.*;

/**
 * <code>syslog(3C)</code> severity levels defined in
 * <code>sys/syslog.h</code>.
 */
public final class Severity extends Level {
	/**
	 * LOG_EMERG from <code>sys/syslog.h</code>
	 */
	private static final int LOG_EMERG = 0;

	/**
	 * LOG_ALERT from <code>sys/syslog.h</code>
	 */
	private static final int LOG_ALERT = 1;

	/**
	 * LOG_CRIT from <code>sys/syslog.h</code>
	 */
	private static final int LOG_CRIT = 2;

	/**
	 * LOG_ERR from <code>sys/syslog.h</code>
	 */
	private static final int LOG_ERR = 3;

	/**
	 * LOG_WARNING from <code>sys/syslog.h</code>
	 */
	private static final int LOG_WARNING = 4;

	/**
	 * LOG_NOTICE from <code>sys/syslog.h</code>
	 */
	private static final int LOG_NOTICE = 5;

	/**
	 * LOG_INFO from <code>sys/syslog.h</code>
	 */
	private static final int LOG_INFO = 6;

	/**
	 * LOG_DEBUG from <code>sys/syslog.h</code>
	 */
	private static final int LOG_DEBUG = 7;

	/**
	 * Maps static instances by name.
	 */
	private static final HashMap severityMap = new HashMap();

	/**
	 * LOG_EMERG
	 */
	public static final Severity EMERG = new Severity(LOG_EMERG,
	    Level.SEVERE.intValue() - 1, "EMERG");

	/**
	 * LOG_ALERT
	 */
	public static final Severity ALERT = new Severity(LOG_ALERT,
	    Level.SEVERE.intValue() - 2, "ALERT");

	/**
	 * LOG_CRIT
	 */
	public static final Severity CRIT = new Severity(LOG_CRIT,
	    Level.SEVERE.intValue() - 3, "CRIT");

	/**
	 * LOG_ERR
	 */
	public static final Severity ERR = new Severity(LOG_ERR,
	    Level.SEVERE.intValue() - 4, "ERR");

	/**
	 * LOG_WARNING
	 */
	public static final Severity WARNING = new Severity(LOG_WARNING,
	    Level.WARNING.intValue() - 1, "WARNING");

	/**
	 * LOG_NOTICE
	 */
	public static final Severity NOTICE = new Severity(LOG_NOTICE,
	    Level.INFO.intValue() - 1, "NOTICE");

	/**
	 * LOG_INFO
	 */
	public static final Severity INFO = new Severity(LOG_INFO,
	    Level.INFO.intValue() - 2, "INFO");

	/**
	 * LOG_DEBUG
	 */
	public static final Severity DEBUG = new Severity(LOG_DEBUG,
	    Level.FINE.intValue() - 1, "DEBUG");

	/**
	 * Add aliases.
	 */
	static {
		severityMap.put("WARN", Severity.WARNING);
		severityMap.put("ERROR", Severity.ERR);
	}

	/**
	 * Disallowed overidden constant Level
	 */
	private static final Level SEVERE = null;

	/**
	 * Disallowed overidden constant Level
	 */
	private static final Level CONFIG = null;

	/**
	 * Disallowed overidden constant Level
	 */
	private static final Level FINE = null;

	/**
	 * Disallowed overidden constant Level
	 */
	private static final Level FINER = null;

	/**
	 * Disallowed overidden constant Level
	 */
	private static final Level FINEST = null;

	/**
	 * See getNative().
	 */
	private int severity;

	/**
	 * Constructs a Severity with the given native severity, Java
	 * logging level, and name.
	 */
	private Severity(int severity, int level, String name)
	{
		super(name, level);
		this.severity = severity;

		Object displaced = severityMap.put(name, this);
		assert (displaced == null);
	}

	/**
	 * Returns the Severity closest in meaning to the given Level.
	 * This is meant to be used by SyslogHandler to determine a
	 * proper Severity for Records which only specify a Level.
	 *
	 * <ul>
	 * <li>Level.SEVERE or higher becomes Severity.ERR
	 * <li>Level.WARNING becomes Severity.WARNING
	 * <li>Level.INFO becomes Severity.INFO
	 * <li>Level.FINE becomes Severity.DEBUG
	 * </ul>
	 *
	 * If the level is below Level.FINE, i.e. the level is too low
	 * for syslog, then null is returned.
	 */
	public static Severity severityForLevel(Level l)
	{
		if (l instanceof Severity)
			return (Severity)l;
		else {
			if (l.intValue() >= Level.SEVERE.intValue())
				return (ERR);
			if (l.intValue() >= Level.WARNING.intValue())
				return (WARNING);
			if (l.intValue() >= Level.INFO.intValue())
				return (INFO);
			if (l.intValue() >= Level.CONFIG.intValue())
				return (INFO);
			if (l.intValue() >= Level.FINE.intValue())
				return (DEBUG);
			return (null);
		}
	}

	/**
	 * Returns the native <code>syslog(3C)</code> severity.
	 */
	public int getNative()
	{
		return (severity);
	}

	/**
	 * Returns the Severity object with the given name, interpreted
	 * case-insensitively.
	 *
	 * @throws IllegalArgumentException if the name isn't of a known
	 * severity.
	 */
	public static Level parse(String name)
	{
		Severity severity = (Severity)severityMap.get(
		    name.toUpperCase());

		if (severity == null)
			throw new IllegalArgumentException();
		else
			return (severity);
	}

	/**
	 * Returns the Severity object with the given name, interpreted
	 * case-insensitively.
	 *
	 * @throws IllegalArgumentException if the name isn't of a known
	 * severity.
	 */
	public static Severity getSeverityWithName(String name)
	{
		return ((Severity)parse(name));
	}
}
