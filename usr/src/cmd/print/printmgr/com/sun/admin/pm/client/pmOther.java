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
 * pmOther.java
 *
 */

package com.sun.admin.pm.client;

import java.awt.*;
import java.awt.event.*;
import javax.swing.JPanel;
import javax.swing.*;

import com.sun.admin.pm.server.*;


/*
 * panel dialog which captures "other"
 */

public class pmOther extends pmDialog {

    private pmTop theTop;
    private String theTag;
    pmButton okButton = null;
    pmButton cancelButton = null;
    pmButton helpButton = null;

    public pmOther(JFrame f, String title, String msg) {
        this(f, title, msg, null, null);
    }

    public pmOther(JFrame f, String title, String msg, pmTop t, String h) {

	super(f, title, true);		// modal

        theTop = t;
        theTag = h;

        JLabel l;
        pmButton b;
        JPanel p;

        Debug.message("CLNT:pmOther()");

        // initialize constraints
        GridBagConstraints c = new GridBagConstraints();
        c.gridx = 0;
        c.gridy = GridBagConstraints.RELATIVE;
        c.gridwidth = 1;
        c.gridheight = 1;
        c.insets = new Insets(10, 10, 5, 10);
        c.anchor = GridBagConstraints.WEST;
        c.fill = GridBagConstraints.HORIZONTAL;
        c.weightx = 1.0;

        // top panel contains the message
        p = new JPanel();
        p.setLayout(new GridBagLayout());

        l = new JLabel(msg, SwingConstants.LEFT);
        p.add(l, c);
        this.getContentPane().add(p, "North");

        c.insets = new Insets(5, 10, 5, 10);

        // middle panel contains "other" text field
        p = new JPanel();
        p.setLayout(new GridBagLayout());

        deviceName.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent evt) {
                okPressed();
            }
        });

        l.setLabelFor(deviceName);

        c.gridx = 1;
        c.gridy = 0;
        c.weightx = 1.0;
        c.fill = GridBagConstraints.HORIZONTAL;
        c.anchor = GridBagConstraints.CENTER;

        p.add(deviceName, c);

        c.gridy = GridBagConstraints.RELATIVE;

        this.getContentPane().add(p, "Center");

        // bottom panel contains buttons
        c.gridx = 0;
        c.weightx = 1.0;
        c.weighty = 0.0;
        c.gridwidth = GridBagConstraints.REMAINDER;
        c.fill = GridBagConstraints.HORIZONTAL;
        c.anchor = GridBagConstraints.CENTER;
        c.insets = new Insets(5, 10, 10, 10);

        JPanel thePanel = new JPanel();
        okButton = new pmButton(
            pmUtility.getResource("OK"));
        okButton.setMnemonic(
            pmUtility.getIntResource("OK.mnemonic"));
        thePanel.add(okButton, c);
        okButton.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent evt) {
                okPressed();
            }
        });

        cancelButton = new pmButton(
            pmUtility.getResource("Cancel"));
        cancelButton.setMnemonic(
            pmUtility.getIntResource("Cancel.mnemonic"));
        thePanel.add(cancelButton, c);
        cancelButton.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent evt) {
                cancelPressed();
            }
        });

        if (theTop != null && theTag != null) {
            helpButton = new pmButton(
                pmUtility.getResource("Help"));
            helpButton.setMnemonic(
                pmUtility.getIntResource("Help.mnemonic"));
            thePanel.add(helpButton, c);
            helpButton.addActionListener(new ActionListener() {
                public void actionPerformed(ActionEvent evt) {
                    theTop.showHelpItem(theTag);
                }
            });
        }


        this.getContentPane().add(thePanel, "South");

        // lay out the dialog
        this.pack();

        this.addWindowListener(new WindowAdapter() {
            public void windowClosing(WindowEvent evt) {
                returnValue = JOptionPane.CLOSED_OPTION;
                pmOther.this.setVisible(false);
            }
        });

        // this.getRootPane().setDefaultButton(okButton);
        okButton.setAsDefaultButton();

        // handle Esc as cancel in any case
        this.getRootPane().registerKeyboardAction(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                Debug.message("CLNT:  default cancel action");
                cancelPressed();
            }},
            KeyStroke.getKeyStroke(KeyEvent.VK_ESCAPE, 0, false),
            JComponent.WHEN_IN_FOCUSED_WINDOW);

        deviceName.requestFocus();

    }

    public int getValue() {
        return returnValue;
    }


    public void okPressed() {
        Debug.message("CLNT:pmOther: " + deviceName.getText());
        returnValue = JOptionPane.OK_OPTION;
        pmOther.this.setVisible(false);
    }

	public void cancelPressed() {
		Debug.message("CLNT:pmOther: cancelPressed");
		pmOther.this.dispose();
	}


    public static void main(String[] args) {
        JFrame f = new JFrame("Other test");

        f.setSize(300, 100);
        f.addWindowListener(new WindowAdapter() {
            public void windowClosing(WindowEvent e) {
                System.exit(0);
            }
        });
        f.setVisible(true);

	while (true) {
	    pmOther d = new pmOther(f, "Test pmOther", "Enter Printer Port");
        d.setVisible(true);

        Debug.message("CLNT:pmOther: Dialog login returns " + d.getValue());

    }
     // System.exit(0);
    }


    public pmTextField deviceName = new pmTextField(30);
    protected int returnValue = JOptionPane.CLOSED_OPTION;

}
