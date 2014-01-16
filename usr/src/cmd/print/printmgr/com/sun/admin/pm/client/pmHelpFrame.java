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
 *
 * ident	"%Z%%M%	%I%	%E% SMI"
 *
 * Copyright(c) 1999 by Sun Microsystems, Inc.
 * All rights reserved.
 *
 * pmHelpFrame.java
 * Container for help subsystem GUI
 */

package com.sun.admin.pm.client;

import java.lang.*;
import java.awt.*;
import java.awt.event.*;
import java.util.*;
import java.io.*;
import javax.swing.JPanel;
import javax.swing.border.*;
import javax.swing.*;
import com.sun.admin.pm.server.*;


public class pmHelpFrame extends pmFrame {

    protected pmHelpController theController = null;
    public pmButton dismiss = null;  // expose for default button hacks

    public pmHelpFrame() {
        super(pmUtility.getResource("SPM:Help"));

        theController = new pmHelpController(this);
        getContentPane().add("Center", theController.getTopPane());

        dismiss = new pmButton(
            pmUtility.getResource("Dismiss"));
        dismiss.setMnemonic(
            pmUtility.getIntResource("Dismiss.mnemonic"));
        dismiss.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                hideHelp();
            }
        });

        JPanel p = new JPanel();
        p.add(dismiss);

        getContentPane().add("South", p);

        this.pack();
        this.setVisible(false);
        this.repaint();

        // default button is dismiss
        // getRootPane().setDefaultButton(dismiss);
        dismiss.setAsDefaultButton();

        // handle Esc as dismiss
        getRootPane().registerKeyboardAction(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                Debug.message("HELP:  dismiss action");
                hideHelp();
            }},
            KeyStroke.getKeyStroke(KeyEvent.VK_ESCAPE, 0, false),
            JComponent.WHEN_IN_FOCUSED_WINDOW);
    }


    public void hideHelp() {
        this.setVisible(false);
    }


    public void showHelp(String tag) {
        theController.showHelpItem(tag);
        this.setVisible(true);
        this.repaint();
    }

}
