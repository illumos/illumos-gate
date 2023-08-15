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

package com.sun.solaris.service.exception;

import java.io.*;

/**
 * Formats a stack trace in a single line.  The format is meant to
 * convey the stack trace as a sequence of class names and line numbers,
 * with the topmost frame first, suitable for logging.  Beware, the
 * format may evolve.
 */
public class SuccinctStackTraceFormatter {
	/**
	 * Formats a Throwable and adds an optional description string.
	 * The string should be suitable to precede the top stack
	 * element, and include any punctuation that should
	 * differentiate it from the element.
	 */
	public static String formatWithDescription(Throwable t,
	    String description)
	{
		StringBuffer s = new StringBuffer();

		s.append("(");

		if (description != null)
			s.append(description);

		s.append(t.getClass().getName());
		s.append(", ");
		StackTraceElement[] trace = t.getStackTrace();
		for (int i = 0; i < trace.length; i++) {
			appendStackTraceElement(i > 0 ? trace[i - 1] : null,
			    trace[i], s);
			if (i != trace.length - 1)
				s.append(", ");
		}
		s.append(")");

		if (t.getCause() != null) {
			s.append(" caused by ");
			s.append(format(t.getCause()));
		}

		return (s.toString());
	}

	/**
	 * Formats a Throwable's stack trace.  The format is meant to be
	 * a single line of output, conveying the stack trace as a
	 * sequence of class names and line numbers, with the topmost
	 * frame first, suitable for logging.  If two adjacent stack
	 * trace elements share some portion of a class name, the
	 * bottommost element may have the common part replaced with an
	 * ampersand.
	 */
	public static String format(Throwable t)
	{
		return (formatWithDescription(t, null));
	}

	/**
	 * Formats a stack trace element as per <code>format()</code>.
	 */
	private static void appendStackTraceElement(StackTraceElement last,
	    StackTraceElement e, StringBuffer s)
	{
		/*
		 * This could grab more of a common class name.  (See
		 * SuccinctStackTraceFormatter.format())
		 */
		if (last == null || !last.getClassName().equals(
		    e.getClassName())) {
			s.append(e.getClassName());
			s.append(".");
		} else
			s.append("&.");

		s.append(e.getMethodName());
		if (e.getLineNumber() > 0) {
			s.append(":");
			s.append(e.getLineNumber());
		}
		if (e.isNativeMethod()) {
			s.append(":");
			s.append("native");
		}
	}

	public static void printStackTrace(Throwable t)
	{
		printStackTrace(t, System.err);
	}

	public static void printStackTrace(Throwable t, PrintStream out)
	{
		out.print(t);
		out.print(" at ");
		out.print(format(t));
	}

	public static final void main(String args[])
	{
		SuccinctStackTraceFormatter.printStackTrace(big());
	}

	public static final Throwable big() {
		return new Throwable().initCause(little());
	}

	public static final Throwable little() {
		return new Throwable();
	}

}
