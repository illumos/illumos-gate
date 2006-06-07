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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * pmMessageDialog.java
 * Common info message dialog
 */

package com.sun.admin.pm.client;

import javax.swing.*;
import java.util.*;
import java.awt.*;
import java.awt.event.*;
import com.sun.admin.pm.server.*;

public class pmMessageDialog extends pmDialog {

    pmButton helpButton = null;
    pmButton okButton = null;
    JList theText = null;
    pmTop theTop = null;
    String helpTag = null;


    public pmMessageDialog(String title, String msg) {
        this(null, title, msg, null, null);
    }

    public pmMessageDialog(Frame f, String title, String msg) {
        this(f, title, msg, null, null);
    }

    public pmMessageDialog(Frame f,
			    String title,
			    String msg,
			    pmTop top,
			    String h) {

	super(f, title, true);	// modal

        theTop = top;
        helpTag = h;

        // initialize constraints
        GridBagConstraints c = new GridBagConstraints();
        c.gridx = 0;
        c.gridy = GridBagConstraints.RELATIVE;
        c.gridwidth = 1;
        c.gridheight = 1;
        c.insets = new Insets(10, 10, 10, 10);
        c.anchor = GridBagConstraints.EAST;

        // top panel
        JPanel p = new JPanel();
        p.setLayout(new GridBagLayout());
        // p.setLayout(new BoxLayout(BoxLayout.X_AXIS));

        // JLabel label = new JLabel(msg, SwingConstants.CENTER);
        JList theText = new JList() {
            public boolean isFocusable() {
                return false;
            }
        };

        Vector v = new Vector();

        Debug.message("CLNT:  MessageDialog: " + title + " , " + msg);

        if (msg != null) {
            StringTokenizer st = new StringTokenizer(msg, "\n", false);
            try {
                while (st.hasMoreTokens())
                    v.addElement(st.nextToken());
            } catch (Exception x) {
                Debug.warning("CLNT:  pmMessageDialog caught " + x);
            }
            theText.setListData(v);
        }

        theText.setBackground(p.getBackground());

        // p.add(theText, "Center");
        p.add(theText, c);

        this.getContentPane().add(p, "Center");

        okButton = new pmButton(
            pmUtility.getResource("Dismiss"));
        okButton.setMnemonic(
            pmUtility.getIntResource("Dismiss.mnemonic"));
        okButton.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent evt) {
                actionOKButton();
            }
        });

        // handle Esc as dismiss in any case
        this.getRootPane().registerKeyboardAction(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                Debug.message("CLNT:  default cancel action");
                actionOKButton();
            }},
            KeyStroke.getKeyStroke(KeyEvent.VK_ESCAPE, 0, false),
            JComponent.WHEN_IN_FOCUSED_WINDOW);

        p = new JPanel();
        p.add(okButton);

        if (theTop != null && helpTag != null) {
            helpButton = new pmButton(
                pmUtility.getResource("Help"));
            helpButton.setMnemonic(
                pmUtility.getIntResource("Help.mnemonic"));
            p.add(helpButton);
            helpButton.addActionListener(new ActionListener() {
                public void actionPerformed(ActionEvent evt) {
                    theTop.showHelpItem(helpTag);
                }
            });
        }

        this.getContentPane().add(p, "South");
        this.addWindowListener(new WindowAdapter() {
            public void windowClosing(WindowEvent evt) {
                actionOKButton();
            }
        });

        this.pack();

        // this.getRootPane().setDefaultButton(okButton);
        okButton.setAsDefaultButton();

        // okButton.requestFocus();
        okButton.grabFocus();

    }


    protected void actionOKButton() {
        returnValue = JOptionPane.OK_OPTION;
        pmMessageDialog.this.setVisible(false);
    }


    public int getValue() {
        return returnValue;
    }


    public static void main(String[] args) {
        JFrame f = new JFrame("Test Dialog");
        f.setSize(300, 100);

        f.addWindowListener(new WindowAdapter() {
            public void windowClosing(WindowEvent evt) {
                System.exit(0);
            }
        });

        f.setVisible(true);

        while (true) {
            System.out.println("creating a new dialog instance...");
            pmMessageDialog d =
                new pmMessageDialog(null,
                                    "Dialog Test",
                                    "Dumb test message.",
				    null,
                                    null);
            d.setVisible(true);
            System.out.println("Dialog returns " + d.getValue());

            d.dispose();

        }

    }


    protected int returnValue = JOptionPane.CLOSED_OPTION;
}
