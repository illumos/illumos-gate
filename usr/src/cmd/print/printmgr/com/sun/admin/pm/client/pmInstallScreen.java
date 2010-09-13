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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * pmInstallScreen.java
 * Create add/modify GUI
 */

package com.sun.admin.pm.client;

import java.awt.*;
import java.awt.event.*;
import java.util.Vector;
import javax.swing.JPanel;
import javax.swing.*;

import com.sun.admin.pm.server.*;

/*
 *	Screen for Installing/Modifying local and network printers
 */

public class pmInstallScreen extends pmButtonScreen {

	pmTextField pnameText;
	pmTextField snameText;
	pmTextField descText;
	pmTextField userText;
	JComboBox portCombo;
	JComboBox faultCombo;

// For printers configured without using make/model/PPD files
	JComboBox fileCombo;
	JComboBox typeCombo;

// For printers configured using make/model/PPD files
	JComboBox ppdCombo;
	JComboBox makeCombo;
	JComboBox modelCombo;

	pmTextField destText;
	JComboBox protocolCombo;
	JCheckBox defaultp;
	JComboBox bannerCombo;
	pmButton addButton;
	pmButton deleteButton;
	JList userList;
	Vector userData;

    public pmInstallScreen() {}


	public void printernameLabel(JPanel north, GridBagConstraints c) {
                north.add(new JLabel
                        (pmUtility.getResource("Printer.Name:")), c);
	}
	public void printernameTextField(JPanel north, GridBagConstraints c) {
                pnameText = new pmTextField(14);
                north.add(pnameText, c);
	}
	public void printernameStaticField(JPanel north, GridBagConstraints c) {
                north.add(new JLabel
                        (pmUtility.getResource("Printer.Server:")), c);
	}

	public void servernameLabel(JPanel north, GridBagConstraints c) {
		north.add(new JLabel
			(pmUtility.getResource("Printer.Server:")), c);
	}
	public void servernameTextField(JPanel north, GridBagConstraints c) {
                snameText = new pmTextField(30);
                north.add(snameText, c);
	}
	public void servernameStaticField(JPanel north, GridBagConstraints c) {
	}

	public void descriptionLabel(JPanel north, GridBagConstraints c) {
                north.add(new JLabel
                        (pmUtility.getResource("Description:")), c);
	}
	public void descriptionField(JPanel north, GridBagConstraints c) {
                descText = new pmTextField(25);
                north.add(descText, c);
	}

	public void printerportLabel(JPanel north, GridBagConstraints c) {
                north.add(new JLabel
                        (pmUtility.getResource("Printer.Port:")), c);
	}

	public void devnullLabel(JPanel north, GridBagConstraints c) {
		north.add(new JLabel("/dev/null"));
	}

	public void printerportField(JPanel north, GridBagConstraints c) {

	    String devices[];
	    int i;

	    try {
		    devices = PrinterUtil.getDeviceList();
	    } catch (Exception e) {
		    Debug.warning("CLNT:  pmAccess:getDeviceList caught " + e);
		    devices = new String[1];
		    devices[0] = "";
	    }
	    portCombo = new JComboBox(devices);
	    portCombo.insertItemAt(pmUtility.getResource("Not.Selected"), 0);
	    portCombo.setSelectedIndex(0);

	    portCombo.addItem(pmUtility.getResource("Other..."));
	    portCombo.addActionListener(new ComboListener(Constants.PORT));

	    north.add(portCombo, c);

	}
	public void printertypeLabel(JPanel north, GridBagConstraints c) {
		north.add(new JLabel
			(pmUtility.getResource("Printer.Type:")), c);
	}
	public void printertypeField(JPanel north, GridBagConstraints c) {
		typeCombo = new JComboBox();
		typeCombo.addItem("PostScript");
		typeCombo.addItem("HP Printer");
		typeCombo.addItem("Reverse PostScript");
		typeCombo.addItem("Epson 2500");
		typeCombo.addItem("IBM ProPrinter");
		typeCombo.addItem("Qume Sprint 5");
		typeCombo.addItem("Daisy");
		typeCombo.addItem("Diablo");
		typeCombo.addItem("Datagraphix");
		typeCombo.addItem("DEC LA100");
		typeCombo.addItem("DEC LN03");
		typeCombo.addItem("Dec Writer");
		typeCombo.addItem("Texas Instruments 800");
		typeCombo.addItem(pmUtility.getResource("Other..."));
		typeCombo.addActionListener(new ComboListener(Constants.TYPE));
		north.add(typeCombo, c);
	}

	public void filecontentsLabel(JPanel north, GridBagConstraints c) {
		north.add(new JLabel
			(pmUtility.getResource("File.Contents:")), c);
	}
	public void filecontentsField(JPanel north, GridBagConstraints c) {
		fileCombo = new JComboBox();
		fileCombo.addItem(pmUtility.getResource("PostScript"));
		fileCombo.addItem(pmUtility.getResource("ASCII"));
		fileCombo.addItem(
			pmUtility.getResource("Both.PostScript.and.ASCII"));
		fileCombo.addItem(pmUtility.getResource("None"));
		fileCombo.addItem(pmUtility.getResource("Any"));
		north.add(fileCombo, c);
	}


	public void printermakeLabel(JPanel north, GridBagConstraints c) {
		north.add(new JLabel
			(pmUtility.getResource("Printer.Make:")), c);
	}
	public void printermakeField(JPanel north, GridBagConstraints c) {

		String makes[];

		try {
			makes = PrinterUtil.getMakesList();
		} catch (Exception e) {
			Debug.warning("CLNT: pmAccess:getMakeList caught" +e);
			makes = new String[1];
			makes[0] = "";
		}

		makeCombo = new JComboBox(makes);
		makeCombo.insertItemAt(
			pmUtility.getResource("Not.Selected"), 0);
		makeCombo.setSelectedIndex(0);


		makeCombo.addActionListener(new ComboListener(Constants.MAKE));
		north.add(makeCombo, c);
	}

	public void printermodelsLabel(JPanel north, GridBagConstraints c) {
		north.add(new JLabel
			(pmUtility.getResource("Printer.Model:")), c);
	}

	public void printermodelsField(JPanel north, GridBagConstraints c) {
		String models[];
		modelCombo = new JComboBox();
		modelCombo.addItem("     ");
		modelCombo.addActionListener(
			new ComboListener(Constants.MODEL));
		north.add(modelCombo, c);
	}

	public void ppdcontentsLabel(JPanel north, GridBagConstraints c) {
		north.add(new JLabel
			(pmUtility.getResource("Printer.Driver:")), c);
	}
	public void ppdcontentsField(JPanel north, GridBagConstraints c) {
		ppdCombo = new JComboBox();
		ppdCombo.addItem("     ");
		ppdCombo.addActionListener(new ComboListener(Constants.PPD));
		north.add(ppdCombo, c);
	}

	public void faultnotLabel(JPanel north, GridBagConstraints c) {
		north.add(new JLabel
			(pmUtility.getResource("Fault.Notification:")), c);
	}
	public void faultnotField(JPanel north, GridBagConstraints c) {
		faultCombo = new JComboBox();

		faultCombo.addItem(pmUtility.getResource("Write.to.Superuser"));
		faultCombo.addItem(pmUtility.getResource("Mail.to.Superuser"));
		faultCombo.addItem(pmUtility.getResource("None"));
		north.add(faultCombo, c);
	}

	public void destinationLabel(JPanel north, GridBagConstraints c) {
		north.add(new JLabel
			(pmUtility.getResource("Destination:")), c);
	}
	public void destinationField(JPanel north, GridBagConstraints c) {
		destText = new pmTextField(25);
		north.add(destText, c);
	}

	public void protocolLabel(JPanel north, GridBagConstraints c) {
		north.add(new JLabel
			(pmUtility.getResource("Protocol:")), c);
	}
	public void protocolField(JPanel north, GridBagConstraints c) {
		protocolCombo = new JComboBox();
		protocolCombo.addItem("BSD");
		protocolCombo.addItem("TCP");
		protocolCombo.addItem("URI");
		north.add(protocolCombo, c);
	}

	public void optionsLabel(JPanel north, GridBagConstraints c) {
		north.add(new JLabel
			(pmUtility.getResource("Options:")), c);
	}

	public void bannerLabel(JPanel north, GridBagConstraints c) {
		north.add(new JLabel
			(pmUtility.getResource("Banner:")), c);
	}

	public void optionLabel(JPanel north, GridBagConstraints c) {
		north.add(new JLabel
			(pmUtility.getResource("Option:")), c);
	}

	public void optionsFields(JPanel north, GridBagConstraints c) {
		defaultp = new JCheckBox(
			pmUtility.getResource("Default.Printer"));

		north.add(defaultp, c);

		c.gridy++;
		bannerCombo = new JComboBox();
		bannerCombo.addItem(pmUtility.getResource
					("Always.Print.Banner"));
		bannerCombo.addItem(pmUtility.getResource
					("User.Selectable.Default.On"));
		bannerCombo.addItem(pmUtility.getResource
					("Never.Print.Banner"));

		north.add(bannerCombo, c);
	}

	public void defaultoptionField(JPanel north, GridBagConstraints c) {
		defaultp = new JCheckBox(
			pmUtility.getResource("Default.Printer"));

		north.add(defaultp, c);
	}

	public void northPanelConstraints(GridBagConstraints c) {
		c.weightx = c.weighty = 0.0;
		c.fill = GridBagConstraints.NONE;
		c.anchor = GridBagConstraints.WEST;
		c.insets = new Insets(8, 5, 5, 5);
		c.gridheight = 1;
		c.gridwidth = 1;
	}

	public void labelConstraints(GridBagConstraints c) {
		c.weightx = c.weighty = 0.0;
		c.fill = GridBagConstraints.NONE;
		c.anchor = GridBagConstraints.WEST;
	}
	public void TextFieldConstraints(GridBagConstraints c) {
		c.ipadx = 15;
		c.fill = GridBagConstraints.HORIZONTAL;
		// c.fill = GridBagConstraints.NONE;
		c.anchor = GridBagConstraints.WEST;
		c.weightx = c.weighty = 1.0;
	}
	public void comboboxConstraints(GridBagConstraints c) {
		c.weightx = c.weighty = 0.0;
		c.fill = GridBagConstraints.NONE;
		c.anchor = GridBagConstraints.WEST;
	}

	public void optionsConstraints(GridBagConstraints c) {
		c.fill = GridBagConstraints.NONE;
		c.weightx = c.weighty = 0.0;
	}

	class ComboListener implements ActionListener {
		int activeCombo;

		// Constructor
		public ComboListener(int aCombo)
		{
			activeCombo = aCombo;
		}

		public void actionPerformed(ActionEvent e) {

			switch (activeCombo)
			{
				case Constants.PORT:
					actionportCombo();
					break;

				case Constants.TYPE:
					actiontypeCombo();
					break;

				case Constants.MAKE:
					actionmakeCombo();
					break;

				case Constants.MODEL:
					actionmodelCombo();
					break;

				case Constants.PPD:
					actionppdCombo();
					break;

			}
		}
	}

	public void actionportCombo() {}

	public void actiontypeCombo() {}

	public void actionmakeCombo() {}

	public void actionmodelCombo() {}

	public void actionppdCombo() {}

	class adddelButtonListener implements ActionListener
	{
		int activeButton;

		public adddelButtonListener(int aButton)
		{
			activeButton = aButton;
		}

		public void actionPerformed(ActionEvent e) {

			switch (activeButton)
			{
				case Constants.ADD:
					actionaddButton();
					break;
				case Constants.DELETE:
					actiondeleteButton();
					break;
			}
		}
	}

	public void actionaddButton() {}

	public void actiondeleteButton() {}

	public void useraccessLabel(JPanel center, GridBagConstraints c) {
                center.add(new JLabel
                        (pmUtility.getResource("User.Access.List:")), c);
	}

	public void adButtons(GridBagConstraints c) {

	    c.anchor = GridBagConstraints.CENTER;
	    c.fill = GridBagConstraints.HORIZONTAL;

	    addButton = new pmButton(pmUtility.getResource("Add"));
	    deleteButton = new pmButton(pmUtility.getResource("Delete"));
	    addButton.addActionListener(
		new adddelButtonListener(Constants.ADD));
	    deleteButton.addActionListener(
		new adddelButtonListener(Constants.DELETE));
	}

        public void xxcenterPanel() {

                JPanel center = new JPanel();
                center.setLayout(new GridBagLayout());
                GridBagConstraints c = new GridBagConstraints();

                c.insets = new Insets(15, 15, 15, 15);
                c.anchor = GridBagConstraints.WEST;

		// Create the label
                c.gridx = 0;
                c.gridy = 0;
                c.fill = GridBagConstraints.NONE;
                c.weightx = c.weighty = 0.0;
                c.anchor = GridBagConstraints.NORTHWEST;
                center.add(new JLabel
                        (pmUtility.getResource("User.Access.List:")), c);

		// Create the User Access List as JList
                userList = new JList();
                JScrollPane scrollPane = new JScrollPane();
                scrollPane.getViewport().setView(userList);

                c.gridwidth = 2;
                c.gridx = 1;
                c.weightx = c.weighty = 1.0;
                c.fill = GridBagConstraints.BOTH;
                center.add(scrollPane, c);

		// Create the text field for adding users
                c.gridx = 1;
                c.gridy = 1;
		c.ipadx = 15;
		c.fill = GridBagConstraints.HORIZONTAL;
		c.anchor = GridBagConstraints.WEST;
		c.weightx = c.weighty = 1.0;

                userText = new pmTextField(25);
                center.add(userText, c);

		// Create the add/delete buttons
                c.gridx = 1;
                c.gridy = 2;

                c.anchor = GridBagConstraints.CENTER;
                c.fill = GridBagConstraints.HORIZONTAL;

                addButton = new pmButton(pmUtility.getResource("Add"));
                deleteButton = new pmButton(pmUtility.getResource("Delete"));
		addButton.addActionListener(
			new adddelButtonListener(Constants.ADD));
		deleteButton.addActionListener(
			new adddelButtonListener(Constants.DELETE));


                c.gridwidth = 1;
                center.add(addButton, c);

                c.gridx = 2;
                center.add(deleteButton, c);

                add("Center", center);

        }

}
