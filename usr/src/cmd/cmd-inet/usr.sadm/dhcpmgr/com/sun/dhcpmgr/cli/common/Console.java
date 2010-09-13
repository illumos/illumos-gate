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
 * Copyright (c) 2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

package com.sun.dhcpmgr.cli.common;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.IOException;

/**
 * This class provides convenient methods to read from System.in.
 */
public class Console
{
    /**
     * Prompt the user for a yes/no reply and read the reply.
     * @param prompt the prompt message
     * @param trueValue the value that represents an affirmative response
     * @param falseValue the value that represents a negative response
     * @param defaultReturn indicates whether affirmative or negative is
     *        the default (true means affirmative, false means negative)
     * @return true if affirmative response, false if negative
     */
    public static boolean promptUser(String prompt,
        String trueValue, String falseValue, boolean defaultReturn) {

        boolean done = false;
        boolean result = defaultReturn;

	StringBuffer buffer = new StringBuffer(prompt);
	buffer.append(" (");
	if (defaultReturn) {
	    buffer.append('[');
	    buffer.append(trueValue);
	    buffer.append("]/");
	    buffer.append(falseValue);
	} else {
	    buffer.append(trueValue);
	    buffer.append("/[");
	    buffer.append(falseValue);
	    buffer.append(']');
	}
	buffer.append("): ");

        while (!done) {
	    System.out.print(buffer.toString());
	    System.out.flush();
            String line = readLine();
            if (line == null || line.length() == 0) {
                done = true;
	    } else if (line.equalsIgnoreCase(trueValue)) {
                result = true;
                done = true;
            } else if (line.equalsIgnoreCase(falseValue)) {
                result = false;
                done = true;
            }
        }

        return (result);

    } // promptUser

    /**
     * Read a line from System.in.
     * @return the line or null in case of exception
     */
    public static String readLine() {

	String line = null;

	try {
	    BufferedReader reader =
		new BufferedReader(new InputStreamReader(System.in));

	    line = reader.readLine();
	} catch (IOException e) {
	    // ignore and return null
	}

	return (line);
    } // readLine
}
