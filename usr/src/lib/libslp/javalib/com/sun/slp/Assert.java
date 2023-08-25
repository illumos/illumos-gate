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
 * Copyright (c) 2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

//
// Assert.java : Handles assertions in a central fashion.
//
//  Author:           Erik Guttman
//
//

package com.sun.slp;

import java.util.*;
import java.text.*;

/**
 * The Assert class is used to test assertions and end the program
 * execution if the assertion fails.
 *
 * @author  Erik Guttman
 */

class Assert {
    static void slpassert(boolean bool, String msgTag, Object[] params) {
	if (bool == false) {
	    SLPConfig conf = SLPConfig.getSLPConfig();
	    printMessageAndDie(conf, msgTag, params);
	}
    }

    // Print message and die. Used within SLPConfig during initialization.
    static void
	printMessageAndDie(SLPConfig conf, String msgTag, Object[] params) {
	ResourceBundle msgs = conf.getMessageBundle(conf.getLocale());
	String failed = msgs.getString("assert_failed");
	String msg = conf.formatMessage(msgTag, params);
	System.err.println(failed+msg);
	(new Exception()).printStackTrace();  // tells where we are at...
	System.exit(-1);
    }

    // Assert that a parameter is nonnull.
    // Throw IllegalArgumentException if so.

    static void nonNullParameter(Object obj, String param) {
	if (obj == null) {
	    SLPConfig conf = SLPConfig.getSLPConfig();
	    String msg =
		conf.formatMessage("null_parameter", new Object[] {param});
	    throw
		new IllegalArgumentException(msg);
	}
    }
}
