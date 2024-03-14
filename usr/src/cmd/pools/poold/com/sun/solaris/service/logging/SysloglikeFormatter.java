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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/* ident	"%Z%%M%	%I%	%E% SMI" */

package com.sun.solaris.service.logging;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.text.*;
import java.util.*;
import java.util.logging.Formatter;
import java.util.logging.LogRecord;

import com.sun.solaris.service.exception.SuccinctStackTraceFormatter;

/**
 * Formats a LogRecord in a human-readable, <code>syslog</code>-like
 * format, and is intended for use with non-syslog handlers, such as
 * FileHandler.
 *
 * Multi-line messages are automatically indented by four spaces to make
 * subsequent lines easier to differentiate from new records.
 */
public class SysloglikeFormatter extends Formatter {
	/**
	 * The date set for each published Record.
	 */
	private Date date = new Date();

	/**
	 * Format string for published dates.
	 */
	private final static String dateFormat =
	    "MMM d kk:mm:ss";

	/**
	 * For published dates, the formatter.
	 */
	private DateFormat dateFormatter;

	/**
	 * For published dates, the argument to date formatter.
	 */
	private Object args[] = { date };

	/**
	 * Line separator string.
	 */
	private String lineSeparator =
		System.getProperty("line.separator");

	/**
	 * Flag to set whether log records should indicate the name of
	 * the class generating the record, if possible.  (default
	 * false)
	 */
	private boolean useClassName = false;

	/**
	 * Flag to set whether log records should indicate the record's
	 * logger, if useClassName isn't set and the class name was
	 * available.  (default false)
	 */
	private boolean useLoggerName = false;

	/**
	 * Flag to set whether log records should indicate the last
	 * component of the record's logger name, if useLoggerName isn't
	 * set.  (default true)
	 */
	private boolean useShortLoggerName = true;

	/**
	 * Flag to set whether log records should indicate the method
	 * used to invoke the logger, if available.  (default false)
	 */
	private boolean useMethodName = false;

	/**
	 * Flag to set whether each record should be split into two
	 * lines such that the severity and message are on a line by
	 * themselves.  (default false)
	 */
	private boolean useTwoLineStyle = false;

	/**
	 * Format the given LogRecord.
	 * @param record the log record to be formatted.
	 * @return a formatted log record.
	 */
	public synchronized String format(LogRecord record)
	{
		StringBuffer sb = new StringBuffer();

		date.setTime(record.getMillis());
		StringBuffer text = new StringBuffer();
		if (dateFormatter == null)
			dateFormatter = new SimpleDateFormat(dateFormat);
		sb.append(dateFormatter.format(date));

		if (record.getSourceClassName() != null && useClassName) {
			sb.append(" ");
			sb.append(record.getSourceClassName());
		} else if (useLoggerName) {
			if (record.getLoggerName() != null) {
				sb.append(" ");
				sb.append(record.getLoggerName());
			}
		} else if (useShortLoggerName) {
			String loggerName = record.getLoggerName();

			if (loggerName != null) {
				sb.append(" ");
				int lastDot = loggerName.lastIndexOf('.');
				if (lastDot >= 0)
					loggerName = loggerName.substring(
					    lastDot + 1);
				sb.append(loggerName);
			}
		}

		if (record.getSourceMethodName() != null && useMethodName) {
			sb.append(" ");
			sb.append(record.getSourceMethodName());
		}
		if (useTwoLineStyle)
			sb.append(lineSeparator);
		else
			sb.append(" ");

		String message = formatMessage(record);
		message = message.replaceAll("\n", lineSeparator + "    ");

		sb.append(record.getLevel()).toString();
		sb.append(": ");
		sb.append(message);
		if (record.getThrown() != null) {
			sb.append(" ");
			sb.append(SuccinctStackTraceFormatter
			    .formatWithDescription(record.getThrown(),
			    "with tracing information: ").toString());
		}
		sb.append(lineSeparator);

		return sb.toString();
	}
}
