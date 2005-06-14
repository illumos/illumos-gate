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
 * ident	"%Z%%M%	%I%	%E% SMI"
 *
 * Copyright (c) 1999 by Sun Microsystems, Inc.
 * All rights reserved.
 *
 */

package com.sun.slp;

import java.io.*;

/**
 * A logging class which writes to stderr. This class can be dynamically
 * loaded by SLPConfig and used as the log object by the writeLog and
 * writeLogLine methods.
 *
 * This class does not actually write anything until the flush() method
 * in invoked; this will write the concatenation of all messages
 * passed to the write() method since the last invokation of flush().
 *
 * The actual logging class used can be controlled via the
 * sun.net.slp.loggerClass property.
 *
 * See also the SLPLog (in slpd.java) and Syslog classes.
 */

class StderrLog extends Writer {

    private StringBuffer buf;

    public StderrLog() {
	buf = new StringBuffer();
    }

    public void write(char[] cbuf, int off, int len) throws IOException {
	buf.append(cbuf, off, len);
    }

    public void flush() {
	String date = SLPConfig.getDateString();

	System.err.println("********" +
			   date + "\n" +
			   buf + "\n" +
			   "********\n");
	buf = new StringBuffer();
    }

    public void close() {
    }
}
