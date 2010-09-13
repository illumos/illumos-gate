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
 * Copyright (c) 1999 by Sun Microsystems, Inc.
 * All rights reserved.
 *
 * pmFindFrame.java
 * Find Printer dialog implementation
 */

package com.sun.admin.pm.client;

import java.awt.*;
import java.awt.event.*;
import javax.swing.JPanel;
import javax.swing.*;

import com.sun.admin.pm.server.*;


public class pmFindFrame extends pmFrame {

    JLabel statusText = null;
    pmButton okButton = null;
    pmButton cancelButton = null;
    pmButton helpButton = null;
    pmTop theTop = null;

    String label = pmUtility.getResource("Enter.name.of.printer.to.find");
    String helpTag = "ToFindPrinter";

    public pmFindFrame(pmTop t) {

        super(pmUtility.getResource("SPM:Find.Printer"));

        setLocation(100, 100);

        theTop = t;


        JLabel l;
        JPanel p;

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

        l = new JLabel(label, SwingConstants.LEFT);
        p.add(l, c);

        getContentPane().add(p, "North");

        // middle panel contains "other" text field
        p = new JPanel();
        p.setLayout(new GridBagLayout());

        printerName = new pmTextField(30);
        printerName.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                okPressed();
            }
        });
        l.setLabelFor(printerName);

        c.gridx = 1;
        c.gridy = 0;
        c.weightx = 1.0;
        c.fill = GridBagConstraints.HORIZONTAL;
        c.anchor = GridBagConstraints.CENTER;
        c.insets = new Insets(0, 10, 5, 10);

        p.add(printerName, c);

        statusText = new JLabel(" ", SwingConstants.LEFT);

        c.gridy = GridBagConstraints.RELATIVE;
        c.gridx = 0;
        c.gridwidth = 2;

        c.insets = new Insets(5, 10, 5, 10);
        p.add(statusText, c);

        getContentPane().add(p, "Center");

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
            pmUtility.getResource("Find"));
        okButton.setMnemonic(
            pmUtility.getIntResource("Find.mnemonic"));
        okButton.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent evt) {
                okPressed();
            }
        });
        thePanel.add(okButton, c);

        cancelButton = new pmButton(
            pmUtility.getResource("Dismiss"));
        cancelButton.setMnemonic(
            pmUtility.getIntResource("Dismiss.mnemonic"));
        cancelButton.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent evt) {
                cancelPressed();
            }
        });
        thePanel.add(cancelButton, c);

        helpButton = new pmButton(
            pmUtility.getResource("Help"));
        helpButton.setMnemonic(
            pmUtility.getIntResource("Help.mnemonic"));
        helpButton.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent evt) {
                theTop.showHelpItem(helpTag);
            }
        });
        thePanel.add(helpButton, c);

        getContentPane().add(thePanel, "South");

        // lay out the dialog
        pack();

        // handle Esc as dismiss in any case
        getRootPane().registerKeyboardAction(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                Debug.message("CLNT:  default cancel action");
                cancelPressed();
            }},
            KeyStroke.getKeyStroke(KeyEvent.VK_ESCAPE, 0, false),
            JComponent.WHEN_IN_FOCUSED_WINDOW);


        // set focus to initial field, depending on which action is tbd
        // this seems to work best after pack()

	/*
	 * frame.setVisible(true);
	 * frame.repaint();
	 */

        // getRootPane().setDefaultButton (okButton);
        okButton.setAsDefaultButton();

        printerName.requestFocus();

		// enable improved focus handling
		setDefaultComponent(printerName);

    }


	public void okPressed() {
	    Debug.message("CLNT:  pmFindFrame:okPressed():" +
			  printerName.getText());

	    String name = printerName.getText();
	    boolean result = theTop.findPrinterInList(name.trim());
	    if (!result)
		statusText.setText(new String(
                    pmUtility.getResource("Unable.to.find.printer") + name));
	    else
		statusText.setText(" ");

	// pmFindPanel.this.frame.setVisible (false);

	}

	public void cancelPressed() {
	    Debug.message("CLNT:  pmFindFrame: cancelPressed()");
	    statusText.setText(" ");
	    printerName.setText("");
	    pmFindFrame.this.setVisible(false);

	}

    public pmTextField printerName = null;

}
