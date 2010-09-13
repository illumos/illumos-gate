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
 * Copyright (c) 2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */
package com.sun.dhcpmgr.client;

import java.awt.*;
import java.awt.event.*;
import java.util.*;
import java.text.MessageFormat;

import javax.swing.*;

import com.sun.dhcpmgr.data.DhcpDatastore;
import com.sun.dhcpmgr.server.*;
import com.sun.dhcpmgr.ui.*;

/**
 * This class defines a Wizard that configures a data store.
 */
public abstract class DSWizard extends Wizard implements DSModuleListener {

    /**
     * The collection of valid DSConf objects.
     */
    protected DSConfList dsconfList = null;

    /**
     * The selected DSConf
     */
    private DSConf dsconf = null;

    /**
     * This class is a holder for the set of DSConf objects.
     */
    protected class DSConfList extends ArrayList {

	/**
	 * Initializes the set of supported DSConfList.
	 * @param server handle to a service manager server
	 */
	public void init(DhcpServiceMgr server) {

	    DhcpDatastore [] dsArray = null;

	    try {
		dsArray = server.getDataStores();
	    } catch (Throwable e) {
		// ignore for now
	    }

	    for (int i = 0;
		dsArray != null && i < dsArray.length; i++) {
		String dsResource = dsArray[i].getResource();
		try {
		    
		    String className = server.getDataStoreClassname(dsResource);
		    DSConf dsconf = new DSConf(dsArray[i], className);
		    dsconfList.add(dsconf);
		} catch (Throwable e) {
		    MessageFormat form = new MessageFormat(
			    ResourceStrings.getString("ds_wiz_init_error"));
		    Object args = new Object[] {
			dsResource,
			e.getMessage()
		    };
		    JOptionPane.showMessageDialog(DSWizard.this,
			form.format(args),
			ResourceStrings.getString("server_error_title"),
			JOptionPane.ERROR_MESSAGE);
		}
	    }
	} // init

	/**
	 * Finds and returns a DSConf by resource.
	 * @param resource the resource of the DSConf.
	 * @return the DSConf if found or null if not found.
	 */
	public DSConf findDsconf(String resource) {

	    DSConf entry = null;
	    for (int i = 0; i < size(); i++) {
		DSConf dsconf = (DSConf) get(i);
		if (dsconf.getDS().getResource().equals(resource)) {
		    entry = dsconf;
		    break;
		}
	    }

	    return entry;

	} // findDSConf

    } // DSConfList
     
    /**
     * This class is a simple holder for a data store
     * and the module used to manage the data store.
     */
    protected class DSConf {

	/**
	 * DHCP datastore information.
	 */
	private DhcpDatastore ds = null;

	/**
	 * The module used to manage the data store.
	 */
	private DSModule dsm = null;

	/**
	 * Constructs a DSConf from a name and a classname.
	 * @param ds DHCP data store.
	 * @param className of the DSModule classname.
	 */
	public DSConf(DhcpDatastore ds, String className)
	    throws Exception {

	    Class dataStoreClass = Class.forName(className);

	    dsm = (DSModule)dataStoreClass.newInstance();
	    this.ds = ds;
	} // constructor

	/**
	 * Returns the DhcpDatastore for this DSConf
	 * @return the DhcpDatastore for this DSConf
	 */
	public DhcpDatastore getDS() {
	    return ds;
	} // getDS

	/**
	 * Returns the module used to manage the data store.
	 * @return the module used to manage the data store.
	 */
	public DSModule getModule() {
	    return dsm;
	} // getModule


	/**
	 * Sets the location from the module into the DhcpDatastore.
	 */
	public void setLocation() {
	    ds.setLocation(dsm.getPath());
	} // setLocation

	/**
	 * Sets the location from the module into the DhcpDatastore.
	 */
	public void setConfig() {
	    ds.setConfig(dsm.getAdditionalInfo());
	} // setConfig

    } // DSConf

    /**
     * This class maps a radio button and a DSConf.
     */
    private class DSConfButton extends JRadioButton {

	/**
	 * The data store to link to the radio button.
	 */
	DSConf dsconf = null;

	/**
	 * Constructs a DSConfButton from a DSConf and determines
	 * whether the button should be selected using the boolean argument.
	 * @param dsconf the data store to map to the radio button.
	 * @param selected select the radio button?
	 */
	public DSConfButton(DSConf dsconf, boolean selected) {
	    super(dsconf.getModule().getDescription(), selected);
	    setEnabled(dsconf.getDS().isEnabled());
	    this.dsconf = dsconf;
	} // constructor

	/**
	 * Returns the DSConf mapped to the radio button.
	 * @return the DSConf mapped to the radio button.
	 */
	public DSConf getDsconf() {
	    return dsconf;
	} // getDsconf

    } // DSConfButton


    /**
     * This class is the wizard step that presents the choice of
     * data stores to the user for selection.
     */
    protected class DatastoreStep implements WizardStep {

	/**
	 * The component provided to the wizard.
	 */
	private Box stepBox;
	
	/**
	 * The group of DSConfButton objects.
	 */
	private ButtonGroup buttonGroup;

	/**
	 * The basic constructor for the wizard step.
	 * @param wizardText the main explanatory text for the wizard.
	 * @param stepText the explanatory text for the step.
	 */
	public DatastoreStep(String wizardText, String stepText) {

	    super();

	    stepBox = Box.createVerticalBox();

	    // Explanatory wizard intro text
	    //
	    JComponent c = Wizard.createTextArea(wizardText, 2, 45);
	    c.setAlignmentX(Component.LEFT_ALIGNMENT);
	    stepBox.add(c);
	    stepBox.add(Box.createVerticalStrut(5));
	    
	    // Explanatory step text
	    //
	    c = Wizard.createTextArea(stepText, 3, 45);
	    c.setAlignmentX(Component.LEFT_ALIGNMENT);
	    stepBox.add(c);
	    stepBox.add(Box.createVerticalStrut(5));

	    // Create button listener, that will set the selected
	    // data store when the button is selected.
	    //
	    ActionListener buttonListener = new ActionListener() {
		public void actionPerformed(ActionEvent e) {
		    DSConfButton button = (DSConfButton)e.getSource();
		    if (button.isSelected()) {
			setDsconf(button.getDsconf());
		    }
		}
	    };

	    // Create panel that will contain the buttons.
	    //
	    JPanel boxPanel = new JPanel();
	    boxPanel.setAlignmentX(Component.LEFT_ALIGNMENT);
	    boxPanel.setLayout(new BoxLayout(boxPanel, BoxLayout.Y_AXIS));
	    boxPanel.setBorder(BorderFactory.createEmptyBorder(0, 20, 0, 20));

	    // List data store choices.
	    //
	    buttonGroup = new ButtonGroup();
	    for (int i = 0; i < dsconfList.size(); ++i) {
		DSConf dsconf = (DSConf)dsconfList.get(i);
		DSConfButton radioButton =
		    new DSConfButton(dsconf, false);
		radioButton.setAlignmentX(Component.LEFT_ALIGNMENT);
		radioButton.addActionListener(buttonListener);
		buttonGroup.add(radioButton);
		boxPanel.add(radioButton);
	    }

	    // Add the panel to the stepBox component.
	    //
	    stepBox.add(boxPanel);
	    stepBox.add(Box.createVerticalStrut(20));
	    stepBox.add(Box.createVerticalGlue());

	} // constructor
	
	public String getDescription() {
	    return ResourceStrings.getString("ds_wiz_datastore_desc");
	} // getDescription
	
	public Component getComponent() {
	    return stepBox;
	} // getComponent
	
	public void setActive(int direction) {
	    if (getDsconf() != null) {
		setForwardEnabled(true);
	    } else {
		setForwardEnabled(false);
	    }
	} // setActive
	
	public boolean setInactive(int direction) {
	    return true;
	} // setInactive


	public void enableButton(String resource, boolean enable) {

	    DSConfButton button = null;
	    Enumeration en = buttonGroup.getElements();
	    while (en.hasMoreElements()) {
		DSConfButton enButton = (DSConfButton)en.nextElement();
		DSConf DSConf = enButton.getDsconf();
		if (dsconf.getDS().getResource().equals(resource)) {
		    button = enButton;
		    break;
		}
	    }

	    if (button != null) {
		button.setEnabled(enable);
	    }

	} // enableButton

    } // DatastoreStep
    
    /**
     * This class is the wizard step that presents the data store module
     * bean to the user for data store configuration.
     */
    protected class DatastoreModuleStep implements WizardStep {
	
	/**
	 * The component provided to the wizard.
	 */
	private Box stepBox;

	/**
	 * Basic constructor. The component for the step will actually be
	 * built in the setActive method, as this step is dependant upon
	 * the data store selection made by the user in the DatastoreStep
	 * wizard step.
	 */
	public DatastoreModuleStep() {
	    stepBox = Box.createVerticalBox();
	    stepBox.add(Box.createVerticalGlue());
	} // constructor
	
	public String getDescription() {
	    return ResourceStrings.getString("ds_wiz_datastore_parm_desc");
	} // getDescription
	
	public Component getComponent() {
	    return stepBox;
	} // getComponent
	
	public void setActive(int direction) {
	    if (direction > 0) {
		stepBox.removeAll();
		Component component =
		    getDsconf().getModule().getComponent();
		if (component != null) {
		    stepBox.add(component);
		    stepBox.add(Box.createVerticalGlue());
		    validate();
		}
	    }

	    if (getDsconf().getModule().getForwardEnabled()) {
		setForwardEnabled(true);
	    } else {
		setForwardEnabled(false);
	    }
	} // setActive
	
	public boolean setInactive(int direction) {
	    return true;
	} // setInactive

    } // DatastoreModuleStep
    
    /**
     * Simple constructor.
     * @param owner frame for wizard.
     * @param title title of the wizard.
     */
    public DSWizard(Frame owner, String title) {
	super(owner, title);
    } // constructor

    /**
     * Sets dsconf.
     * @param dsconf the data store config value.
     */
    public void setDsconf(DSConf dsconf) {
	if (this.dsconf != null) {
	    this.dsconf.getModule().removeDSMListener(this);
	}
	setForwardEnabled(true);
	this.dsconf = dsconf;
	this.dsconf.getModule().addDSMListener(this);
    } // setDsconf

    /**
     * Returns the dsconf.
     * @return the dsconf.
     */
    public DSConf getDsconf() {
	return dsconf;
    } // getDsconf

    /**
     * Invoked when the DSModule has changed its state.
     * @param e the event.
     */
    public void stateChanged(DSModuleEvent e) {
	if (e.getState() == DSModuleEvent.DATA_VALID) {
	    setForwardEnabled(true);
	} else {
	    setForwardEnabled(false);
	}
    } // stateChanged

} // DSWizard
