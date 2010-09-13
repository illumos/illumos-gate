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
 *
 * ident	"%Z%%M%	%I%	%E% SMI"
 *
 * Copyright(c) 1999 by Sun Microsystems, Inc.
 * All rights reserved.
 *
 * pmDialog.java
 * Extends JDialog to provide for better default location.
 */

package com.sun.admin.pm.client;

import java.net.*;
import java.awt.*;
import javax.swing.*;
import java.awt.event.*;

import com.sun.admin.pm.server.Debug;

public class pmDialog extends JDialog implements pmDialogConstraints {

    public pmDialog(Frame owner) {
	this(owner, null, false);
    }

    public pmDialog(Frame owner, boolean modal) {
	this(owner, null, modal);
    }

    public pmDialog(Frame owner, String title) {
	this(owner, title, false);
    }

    public pmDialog(Frame f, String title, boolean modal) {

	super(f, title, modal);

	// determine a nice location relative to parent frame
	Point newLocation = new Point(0, 0);	// default

	if (f == null) {
	    // centered on screen
	    Dimension screenSize = Toolkit.getDefaultToolkit().getScreenSize();
	    newLocation = new Point(screenSize.width / 2 - xoffset,
				    screenSize.height / 2 - yoffset);

	} else {
	    // centered over parent frame
	    Rectangle parentBounds = f.getBounds();
	    newLocation = new Point(
			    parentBounds.x + parentBounds.width / 2 - xoffset,
			    parentBounds.y + parentBounds.height / 2 - yoffset);
            f.addWindowListener(new WindowAdapter() {
                public void windowClosing(WindowEvent e) {
                    Debug.info("dialog Window closing");
                    cleanupButtons();
                }
                public void windowClosed(WindowEvent e) {
                    Debug.info("dialog Window closed");
                    cleanupButtons();
                }
                public void windowDeactivated(WindowEvent e) {
                    Debug.info("dialog Window deactivated");
                    // possible java bug: too many of these events generated!
                    // cleanupButtons();
                }
            });
	}
	setLocation(newLocation);

	// cannot set dialog icons under 1.1....
	/*
         * try {
         *  String iconName = new String("images/appicon.gif");
	 *  Class thisClass = this.getClass();
	 *  URL iconUrl = thisClass.getResource(iconName);
	 *  if (iconUrl == null)
	 *	Debug.warning("Unable to resolve URL for icon " + iconName);
	 *  else {		
	 * 	Toolkit tk = Toolkit.getDefaultToolkit();
	 * 	Image img = tk.getImage(iconUrl);
	 * 	// this.setIconImage(img);
	 *    }
         * } catch (Exception x) {
         *      Debug.warning(x.toString());
         * }
	 */
		
    }

    public void cleanupButtons() {
        // drop this rootPane from pmButton's hashtable
        pmButton.unreference(this.getRootPane());
    }
    
    public void setVisible(boolean b) {
        if (b == false)
            cleanupButtons();
        super.setVisible(b);
    }

}
        
