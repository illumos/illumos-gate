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
 * pmButtonsScreen.java
 * Common dialog superclass
 */

package com.sun.admin.pm.client;

import java.awt.*;
import java.awt.event.*;
import javax.swing.JPanel;
import javax.swing.*;

import com.sun.admin.pm.server.*;


/*
 * Screen class for JPanels
 */

public class pmButtonScreen extends JPanel {

    final static int OK =  1;
    final static int APPLY =  2;
    final static int RESET =  3;
    final static int CANCEL =  4;
    final static int HELP =  5;

    pmButton okButton;
    pmButton applyButton;
    pmButton resetButton;
    pmButton cancelButton;
    pmButton helpButton;


    public void southPanel() {

	JPanel south = new JPanel();

	south.setLayout(new GridBagLayout());
	GridBagConstraints c = new GridBagConstraints();

	c.gridheight = 1;
	c.gridwidth = 1;
	c.weightx = c.weighty = 0.0;
	c.anchor = GridBagConstraints.CENTER;
	c.fill = GridBagConstraints.HORIZONTAL;
	c.gridy = 0;

	okButton = new pmButton(
            	pmUtility.getResource("OK"));
        okButton.setMnemonic(
        	pmUtility.getIntResource("OK.mnemonic"));

	applyButton = new pmButton(
		pmUtility.getResource("Apply"));
        applyButton.setMnemonic(
            pmUtility.getIntResource("Apply.mnemonic"));

        resetButton = new pmButton(
            pmUtility.getResource("Reset"));
        resetButton.setMnemonic(
            pmUtility.getIntResource("Reset.mnemonic"));

        cancelButton = new pmButton(
            pmUtility.getResource("Cancel"));
        cancelButton.setMnemonic(
            pmUtility.getIntResource("Cancel.mnemonic"));

        helpButton = new pmButton(
            pmUtility.getResource("Help"));
        helpButton.setMnemonic(
            pmUtility.getIntResource("Help.mnemonic"));

	okButton.addActionListener(new ButtonListener(OK));
	applyButton.addActionListener(new ButtonListener(APPLY));
	resetButton.addActionListener(new ButtonListener(RESET));
	cancelButton.addActionListener(new ButtonListener(CANCEL));
	helpButton.addActionListener(new ButtonListener(HELP));

	c.insets = new Insets(15, 5, 10, 5);
	c.gridx = 0;
	south.add(okButton, c);
	c.gridx = 1;
	south.add(applyButton, c);
	c.gridx = 2;
	south.add(resetButton, c);
	c.gridx = 3;
	south.add(cancelButton, c);
	c.gridx = 4;
	south.add(helpButton, c);

	add("South", south);
    }

    class ButtonListener implements ActionListener {
	int activeButton;

	// Constructor

	public ButtonListener(int aButton)
	{
		activeButton = aButton;
	}

	public void actionPerformed(ActionEvent e)
	{
		switch (activeButton) {
		case OK:
			actionokButton();
			break;
		case APPLY:
			actionapplyButton();
			break;
		case RESET:
			actionresetButton();
			break;
		case CANCEL:
			actioncancelButton();
			break;
		case HELP:
			actionhelpButton();
			break;
		}
	}
    }

    public void actionokButton()
    {
    }

    public void actionapplyButton()
    {
    }

    public void actionresetButton()
    {
    }

    public void actioncancelButton()
    {
    }

    public void actionhelpButton()
    {
    }



}
