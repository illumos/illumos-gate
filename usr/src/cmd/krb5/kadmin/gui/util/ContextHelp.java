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
 * Copyright (c) 1999-2000 by Sun Microsystems, Inc.
 * All rights reserved.
 */

import java.awt.event.*;
import java.awt.*;
import java.util.ResourceBundle;
import java.util.MissingResourceException;

/**
 * Dialog box for displaying context sensitive help.
 * It is shared amongst the different frames when some frame is
 * already in context help mode. When all the frames return to
 * normal mode by dismissing the dialog box, this object is
 * destroyed.
 */
// The approach of simply hiding the context dialog box till the next
// time it is needed will not work too well. The problem arises
// because the dialog box is associated with a parent frame. Whenever
// the dialog box goes from invisible to visible this parent frame
// also pops to the top. This might be a little counter-intuitive to a
// user when he/she asks for help on frame A and has frame B popping
// up for no apparent reason.
public class ContextHelp extends HelpDialog {
  
    private KdcGui kdcGui;

    private static Cursor c = new Cursor(Cursor.DEFAULT_CURSOR);

    // For I18N
    private static ResourceBundle rb =
    ResourceBundle.getBundle("GuiResource" /* NOI18N */);

    public ContextHelp(Frame parent, KdcGui kdcGui) {
        super(parent, getString("Context-Sensitive Help"), false);
        this.kdcGui = kdcGui;
        setText(getString(
        "Click on GUI items to get help.\n\nClick on button below to dismiss"));
    }

    /**
     * Call rb.getString(), but catch exception and return English
     * key so that small spelling errors don't cripple the GUI
     *
     */
    private static final String getString(String key) {
        try {
  	    String res = rb.getString(key);
	    return res;
        } catch (MissingResourceException e) {
	    System.out.println("Missing resource "+key+", using English.");
	    return key;
        }
    }

    protected void quit() {
        if (kdcGui.loginHelpMode) {
            kdcGui.setupLoginNormalListeners();
            kdcGui.realLoginFrame.setCursor(c);
        }
    
        if (kdcGui.mainHelpMode) {
            kdcGui.setupMainNormalListeners();
            kdcGui.realMainFrame.setCursor(c);
        }
 
        if (kdcGui.defaultsHelpMode) {
            kdcGui.setupDefaultsNormalListeners();
            kdcGui.defaultsEditingFrame.setCursor(c);
        }
      
        // Set the reference to this to null to indicate to kdcGui that it
        // has to create a new ContextHelp object the next time one is
        // needed 
        kdcGui.cHelp = null;

        super.quit();
    }

}
