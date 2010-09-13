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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * pmLoad.java
 * Load a Naming Context implementation
 */

package com.sun.admin.pm.client;

import java.awt.*;
import java.awt.event.*;
import javax.swing.JPanel;
import javax.swing.*;

import com.sun.admin.pm.server.*;

public class pmLoad extends JPanel {

	final static int OK =  1;
	final static int APPLY =  2;
	final static int RESET =  3;
	final static int CANCEL =  4;
	final static int HELP =  5;

	final static int NIS =  6;
	final static int NONE =  7;

	pmFrame frame = new pmFrame(
		pmUtility.getResource("SPM:Select.Naming.Service"));
	JComboBox nameserviceCombo = new JComboBox();
	pmTop mytop = null;
	int resetIndex;

    pmButton okButton = null;
    pmButton cancelButton = null;
    pmButton resetButton = null;
    pmButton helpButton = null;


    public pmLoad(pmTop mytop) {
	this.mytop = mytop;

	Debug.message("CLNT:pmLoad()");
	setLayout(new BorderLayout());
	resetIndex = mytop.actionindex;

	northPanel();
	southPanel();


    }

    public void northPanel() {
	JPanel north = new JPanel();
	north.setLayout(new GridBagLayout());
	GridBagConstraints c = new GridBagConstraints();
	c.weightx = c.weighty = 0.0;
	c.fill = GridBagConstraints.NONE;
	c.anchor = GridBagConstraints.WEST;
	c.insets = new Insets(15, 15, 5, 15);
	c.gridheight = 1;
	c.gridwidth = 1;

	c.gridy = 1;
	c.gridx = 0;
	north.add(new JLabel
		(pmUtility.getResource("Naming.Service:")), c);

	c.gridy = 1;
	c.gridx = 2;
	c.ipadx = 15;

	nameserviceCombo.addItem("files");

	if (mytop.nisns != null)
		nameserviceCombo.addItem("NIS");

	if (mytop.ldapns != null)
		nameserviceCombo.addItem("LDAP");

	nameserviceCombo.setSelectedIndex(mytop.actionindex);
	north.add(nameserviceCombo, c);

	nameserviceCombo.addActionListener(new nsListener());
	nameserviceCombo.addItemListener(mytop.new topnsListener());

	add("North", north);

    }

    class nsListener implements ActionListener {
	public nsListener() {}

	public void actionPerformed(ActionEvent e)
	{
		mytop.actionindex = nameserviceCombo.getSelectedIndex();
		if (mytop.actionindex == 0) {
			Debug.message("CLNT:pmLoad:0: NONE");
		} else if (mytop.actionindex == 1) {
			Debug.message("CLNT:pmLoad:1: NIS");
		} else if (mytop.actionindex == 4) {
			Debug.message("CLNT:pmLoad:2: LDAP");
		}
	};
    }

    public void southPanel() {
        JPanel south = new JPanel();

        south.setLayout(new GridBagLayout());
        GridBagConstraints c = new GridBagConstraints();

        c.gridheight = 1;
        c.gridwidth = 1;
        c.weightx = c.weighty = 1.0;
        c.anchor = GridBagConstraints.CENTER;
        c.fill = GridBagConstraints.HORIZONTAL;
        c.insets = new Insets(15, 15, 15, 15);
        c.gridy = 0;

	okButton = new pmButton(
            pmUtility.getResource("OK"));
        okButton.setMnemonic(
            pmUtility.getIntResource("OK.mnemonic"));

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
        resetButton.addActionListener(new ButtonListener(RESET));
        cancelButton.addActionListener(new ButtonListener(CANCEL));
        helpButton.addActionListener(new ButtonListener(HELP));

        c.gridx = 0;
        south.add(okButton, c);
        c.gridx = 1;
        south.add(resetButton, c);
        c.gridx = 2;
        south.add(cancelButton, c);
        c.gridx = 3;
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

	// Select Active Button and call routine

	public void actionPerformed(ActionEvent e)
	{

		switch (activeButton) {
		case OK:
			actionokButton();
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

    public void pmScreendispose() {
	frame.dispose();
    }

	// Action for buttons

    public void actionokButton() {
	Debug.message("CLNT:pmLoad:actionokButton()");
	mytop.pmsetNS();
	mytop.pmsetNSLabel();
	mytop.pmsetPrinterList();
	mytop.pmsetdefaultpLabel();
	frame.setVisible(false);
	frame.repaint();
	frame.dispose();
    }

    public void actionresetButton() {
	Debug.message("CLNT:pmLoad:actionresetButton()");
	nameserviceCombo.setSelectedIndex(resetIndex);
	frame.repaint();
    }

    public void actioncancelButton() {
	Debug.message("CLNT:pmLoad:actioncancelButton()");
	nameserviceCombo.setSelectedIndex(resetIndex);
	frame.setVisible(false);
	frame.repaint();
	frame.dispose();
    }

    public void actionhelpButton() {
	Debug.message("CLNT:pmLoad:actionhelpButton()");
	mytop.showHelpItem("NameService");
    }

    public void Show() {
	Debug.message("CLNT:pmLoad:Show()");

	frame.getContentPane().add("North", this);
	frame.pack();

        // handle Esc as cancel
        frame.getRootPane().registerKeyboardAction(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                Debug.message("CLNT:  default cancel action");
                actioncancelButton();
            }},
            KeyStroke.getKeyStroke(KeyEvent.VK_ESCAPE, 0, false),
            JComponent.WHEN_IN_FOCUSED_WINDOW);

        // default button is always OK, for now...
        okButton.setAsDefaultButton();

        frame.setDefaultComponent(nameserviceCombo);

        nameserviceCombo.requestFocus();

	frame.setVisible(true);
	frame.repaint();

    }

}
