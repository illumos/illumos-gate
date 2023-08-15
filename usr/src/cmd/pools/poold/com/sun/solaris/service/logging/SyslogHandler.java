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
 */

/* ident	"%Z%%M%	%I%	%E% SMI" */

package com.sun.solaris.service.logging;

import java.text.*;
import java.util.*;
import java.util.logging.Formatter;
import java.util.logging.Handler;
import java.util.logging.LogRecord;

import com.sun.solaris.service.exception.SuccinctStackTraceFormatter;

/**
 * This handler outputs LogRecords with <code>syslog(3C)</code> to the
 * given facility with a severity translated by Level with a fixed
 * table.  Formatters are not used.
 *
 * Multiple SyslogHandlers may not be in concurrent use in one virtual
 * machine.
 */
public final class SyslogHandler extends Handler {
	/**
	 * <code>syslog(3C)</code> ident string, prepended to every
	 * message.
	 */
	private String ident;

	/**
	 * <code>syslog</code> facility to be logged to.
	 */
	private Facility facility;

	/**
	 * Records the instance of this singleton.
	 */
	private static SyslogHandler instance = null;

	/**
	 * Flag whether stack traces should be output when a record's
	 * <code>thrown</code> field is set.  They will be formatted in
	 * a single line by <code>SuccinctStackTraceFormatter</code>,
	 * which does not include the Throwable's description, since
	 * it's presumably described by the log message).  Default
	 * <code>true</code>.
	 */
	private static boolean useStackTraces = true;

	/**
	 * Default logging option value.  Sets no options.  (Corresponds
	 * to the <code>logopt</code> argument to openlog(3c).)
	 */
	private static final int DEF_LOGOPT = 0;

	/**
	 * Flag to set whether log records should indicate the record's
	 * logger.  (default false)
	 */
	private boolean useLoggerName = false;

	/**
	 * Flag to set whether log records should indicate the last
	 * component of the record's logger name, if useLoggerName isn't
	 * set.  (default true)
	 */
	private boolean useShortLoggerName = true;

	static {
		System.loadLibrary("jsyslog");
	}

	private SyslogHandler(String ident, Facility facility)
	{
		if (ident == null || facility == null)
			throw new IllegalArgumentException();

		this.ident = ident;
		this.facility = facility;

		openlog(ident, DEF_LOGOPT, facility.getNative());
		instance = this;
	}

	/**
	 * Return this virtual machine's instance of SyslogHandler,
	 * creating one which logs with the given identity to the given
	 * facility if necessary, unless an instance with a different
	 * identity or facility is already open, in which case an
	 * IllegalArgumentException is thrown.
	 *
	 * @throws IllegalArgumentException if the requested identity or
	 * facility differs from a previously-created instance.
	 */
	public static SyslogHandler getInstance(String ident,
	   Facility facility)
	{
		if (instance != null) {
			if (!instance.ident.equals(ident) ||
			    !instance.facility.equals(facility))
				throw new IllegalArgumentException();
			else
				return (instance);
		} else
			return (instance = new SyslogHandler(ident, facility));
	}

	public void finalize()
	{
		try {
			close();
		} catch (Exception e) {
			// superclass-defined exceptions do not apply
		}
	}

	public String toString()
	{
		return ("SyslogHandler(" + ident + ", " + facility.toString() +
		    ")");
	}

	/**
	 * Calls <code>syslog(3C)</code>.
	 */
	private static native void syslog(int severity, String message);

	/**
	 * Calls <code>openlog(3C)</code>.
	 */
	private static native void openlog(String ident, int logopt,
	    int facility);

	/**
	 * Calls <code>closelog(3C)</code>.
	 */
	private static native void closelog();

	/**
	 * Publishes the given record with its associated Severity (or
	 * infers its severity with Severity.severityForLevel(), if
	 * another type of Level is used), if the result is non-null.
	 */
	public void publish(LogRecord record)
	{
		Severity severity;

		if (record.getLevel() instanceof Severity)
			severity = (Severity)record.getLevel();
		else
			severity = Severity.severityForLevel(record
			    .getLevel());

		if (getLevel().intValue() > severity.intValue())
			return;

		/*
		 * If the severity is null, the message isn't meant to
		 * be sent to syslog.
		 */
		if (severity == null)
			return;

		StringBuffer message = new StringBuffer();
		String loggerName = record.getLoggerName();
		if (useLoggerName) {
			if (loggerName != null) {
				message.append("(");
				message.append(record.getLoggerName());
				message.append(") ");
			}
		} else if (useShortLoggerName) {
			if (loggerName != null) {
				message.append("(");
				int lastDot = loggerName.lastIndexOf('.');
				if (lastDot >= 0)
					loggerName = loggerName.substring(
					    lastDot + 1);
				message.append(loggerName);
				message.append(") ");
			}
		}

		message.append(record.getMessage());

		/*
		 * If the Severity is null, it's not meant to be logged
		 * via syslog.
		 */
		if (record.getThrown() != null && useStackTraces == true) {
			/*
			 * Format the stack trace as one line and tack
			 * it onto the message.
			 */
			message.append(" ");
			message.append(SuccinctStackTraceFormatter
			    .formatWithDescription(record.getThrown(),
			    "with tracing information: ").toString());
		}
		syslog(severity.getNative(), message.toString());
	}

	public void flush()
	{
	}

	public void close() throws SecurityException
	{
		if (instance != null) {
			closelog();
			instance = null;
		}
	}

	/**
	 * Formatters may not be used with SyslogHandler.
	 *
	 * @throws IllegalArgumentException if the use of one is
	 * attempted.
	 */
	public void setFormatter(Formatter formatter)
	{
		throw new IllegalArgumentException();
	}

	/**
	 * Returns the <code>syslog(3C)</code> ident string, which is
	 * prepended to every message.
	 */
	public String getIdent()
	{
		return (ident);
	}

	/**
	 * Returns the <code>syslog</code> facility to be logged to.
	 */
	public Facility getFacility()
	{
		return (facility);
	}

}
