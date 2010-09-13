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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * ident	"%Z%%M%	%I%	%E% SMI"
 */
package org.opensolaris.os.dtrace;

/**
 * Wraps a java exception encountered in native code for the purpose of
 * adding native source filename and line number, which are otherwise
 * not included in the stack trace of the wrapped exception.
 *
 * @author Tom Erickson
 */
class NativeException extends RuntimeException {
    static final long serialVersionUID = 4129171856987233185L;

    /** @serial */
    private String fileName;
    /** @serial */
    private int lineNumber;

    public
    NativeException(String file, int line, Throwable cause)
    {
	super(cause);
	fileName = file;
	lineNumber = line;
    }

    public String
    getMessage()
    {
	StringBuilder buf = new StringBuilder();
	buf.append(fileName);
	buf.append(" line ");
	buf.append(lineNumber);
	Throwable cause = getCause();
	if (cause != null) {
	    String message = cause.getMessage();
	    if (message != null) {
		buf.append(" ");
		buf.append(cause.getMessage());
	    }
	}
	return buf.toString();
    }
}
