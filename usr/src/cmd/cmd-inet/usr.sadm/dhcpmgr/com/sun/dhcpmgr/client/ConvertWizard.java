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
 * Copyright 2001-2002 by Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
package com.sun.dhcpmgr.client;

import java.awt.*;
import java.awt.event.*;
import java.util.*;
import java.text.MessageFormat;
import java.net.*;

import javax.swing.*;
import javax.swing.table.*;
import javax.swing.event.*;
import javax.swing.border.*;

import com.sun.dhcpmgr.ui.*;
import com.sun.dhcpmgr.data.*;
import com.sun.dhcpmgr.server.*;
import com.sun.dhcpmgr.bridge.BridgeException;
import com.sun.dhcpmgr.bridge.ExistsException;

/**
 * This wizard converts the DHCP service data store.
 */
public class ConvertWizard extends DSWizard {

    /**
     * Handle to the service server.
     */
    private DhcpServiceMgr svcServer;

    /**
     * Handle to the dhcptab table server.
     */
    private DhcptabMgr dhcptabServer;

    /**
     * Handle to the network tables server.
     */
    private DhcpNetMgr netServer;

    /**
     * The DHCP defaults.
     */
    private DhcpdOptions dhcpdOptions;

    /**
     * The old data store config.
     */
    private DSConf defaultDsconf;

    /**
     * The save tables wizard step
     */
    private SaveTablesStep saveTablesStep;

    /**
     * List of networks to be converted.
     */
    private Network[] networks = null;

    /**
     * This class is the wizard step that presents the user with
     * the option to save the tables after conversion.
     */
    protected class SaveTablesStep implements WizardStep {

        /**
         * The component provided to the wizard.
         */
        private Box stepBox;

	/**
	 * The checkbox that determines whether the DHCP tables should be
	 * saved after conversion.
	 */
	private JCheckBox saveTables;

        /**
         * Basic constructor.
         */
        public SaveTablesStep() {

            stepBox = Box.createVerticalBox();

            // Explanatory text at the top
	    //
            stepBox.add(Wizard.createTextArea(
                ResourceStrings.getString("cvt_wiz_save_explain"), 4, 45));
            stepBox.add(Box.createVerticalStrut(10));
            stepBox.add(Box.createVerticalGlue());

	    // Add the checkbox.
	    //
            saveTables = new JCheckBox(
                ResourceStrings.getString("cvt_wiz_save_label"), false);
	    saveTables.setToolTipText(
		ResourceStrings.getString("cvt_wiz_save_label"));
            saveTables.setAlignmentX(Component.LEFT_ALIGNMENT);
            stepBox.add(saveTables);
            stepBox.add(Box.createVerticalGlue());

            stepBox.add(Wizard.createTextArea(
                ResourceStrings.getString("cvt_wiz_save_note"), 4, 45));
            stepBox.add(Box.createVerticalStrut(10));
            stepBox.add(Box.createVerticalGlue());

        } // constructor

        public String getDescription() {
            return ResourceStrings.getString("cvt_wiz_save_tables_desc");
        } // getDescription

        public Component getComponent() {
            return stepBox;
        } // getComponent

        public void setActive(int direction) {
            setForwardEnabled(true);
        } // setActive

        public boolean setInactive(int direction) {
            return true;
        } // setInactive

	public boolean isSaveTablesSelected() {
	    return saveTables.isSelected();
	}

    } // SaveTablesStep

    /**
     * This class provides the review step for the conversion wizard.
     */
    class ReviewStep implements WizardStep {

	/**
	 * The label for the old data store.
	 */
	private JLabel oldStoreLabel;

	/**
	 * The label for the new data store.
	 */
	private JLabel newStoreLabel;

	/**
	 * The label for saving tables.
	 */
	private JLabel saveLabel;

	/**
	 * The component to provide to the conversion wizard.
	 */
	private Box stepBox;

	/**
	 * The panel used to create the review information.
	 */
	private JPanel panel;

	/**
	 * The constructor for the step.
	 */
	public ReviewStep() {

	    stepBox = Box.createVerticalBox();
	    stepBox.add(Wizard.createTextArea(
		ResourceStrings.getString("cvt_wiz_review_explain"),
		    3, 45));

	    panel = new JPanel(new FieldLayout());

	    addLabel("cvt_wiz_old_datastore").setToolTipText(
		ResourceStrings.getString("cvt_wiz_old_datastore"));
	    oldStoreLabel = addField("uninitialized");

	    addLabel("cvt_wiz_new_datastore").setToolTipText(
		ResourceStrings.getString("cvt_wiz_new_datastore"));
	    newStoreLabel = addField("uninitialized");

	    addLabel("cvt_wiz_save_tables").setToolTipText(
		ResourceStrings.getString("cvt_wiz_save_tables"));
	    saveLabel = addField("uninitialized");

	    stepBox.add(panel);
	    stepBox.add(Box.createVerticalGlue());

            stepBox.add(Wizard.createTextArea(
                ResourceStrings.getString("cvt_wiz_review_note"), 4, 45));
            stepBox.add(Box.createVerticalStrut(10));
            stepBox.add(Box.createVerticalGlue());

	} // constructor

	/**
	 * Adds a label to the review panel.
	 * @param s the label string.
	 */
	private JLabel addLabel(String s) {
	    JLabel addLbl =
		new JLabel(ResourceStrings.getString(s));
	    panel.add(FieldLayout.LABEL, addLbl);
	    return addLbl;
	} // addLabel

	/**
	 * Adds a field to the review panel.
	 * @param s the field value.
	 * @return the label of which the field consists.
	 */
	private JLabel addField(String s) {
	    JLabel l = new JLabel(s);
	    l.setForeground(Color.black);
	    panel.add(FieldLayout.FIELD, l);
	    return l;
	} // addField

	public String getDescription() {
	    return ResourceStrings.getString("cvt_wiz_review_desc");
	} // getDescription

	public Component getComponent() {
	    return stepBox;
	} // getComponent

	public void setActive(int direction) {

	    setFinishEnabled(true);

	    /**
	     * If no bean exists for the default data store, then use the
	     * name of the data store as the description.
	     */
	    String description = null;
	    if (defaultDsconf != null) {
		description = defaultDsconf.getModule().getDescription();
	    } else {
		description = dhcpdOptions.getResource();
	    }

	    oldStoreLabel.setText(description);
	    newStoreLabel.setText(getDsconf().getModule().getDescription());

	    String message = null;
	    if (saveTablesStep.isSaveTablesSelected()) {
		message = ResourceStrings.getString("yes");
	    } else {
		message = ResourceStrings.getString("no");
	    }
	    saveLabel.setText(message);

	} // setActive

	public boolean setInactive(int direction) {
	    return true;
	} // setInactive

    } // ReviewStep

    /**
     * Constructor for the ConvertWizard.
     * @param owner owner of the wizard.
     * @param title title of the wizard.
     */
    public ConvertWizard(Frame owner, String title) {

	super(owner, title);

	// Go ahead and grab handles to the different servers and
	// read the server defaults.
	//
	try {
	    svcServer = DataManager.get().getDhcpServiceMgr();
	    dhcptabServer = DataManager.get().getDhcptabMgr();
	    netServer = DataManager.get().getDhcpNetMgr();
	    dhcpdOptions = svcServer.readDefaults();
	} catch (Throwable e) {
	    e.printStackTrace();
	    return;
	}

	// Create the DSConfList and determine the default. Note that
	// if the current data store has no management bean, then the
	// defaultDsconf is null.
	//
	dsconfList = new DSConfList();
	dsconfList.init(svcServer);
	defaultDsconf =
	    dsconfList.findDsconf(dhcpdOptions.getResource());

	// If no bean exists for the default data store, then use the
	// name of the data store as the description.
	//
	String description = null;
	if (defaultDsconf != null) {
	    description = defaultDsconf.getModule().getDescription();
	} else {
	    description = dhcpdOptions.getResource();
	}


	// Build the wizard explanation message.
	//
	Object [] args = new Object[1];
	args[0] = description;
	MessageFormat form = new MessageFormat(
	    ResourceStrings.getString("cvt_wiz_explain"));
	String wizExplain = form.format(args);

	// Add the steps for the wizard.
	//
	DatastoreStep datastoreStep = new DatastoreStep(wizExplain,
	    ResourceStrings.getString("cvt_wiz_store_explain"));
	addStep(datastoreStep);
	addStep(new DatastoreModuleStep());
	addStep(saveTablesStep = new SaveTablesStep());
	addStep(new ReviewStep());
	showFirstStep();
    }

    public void doFinish() {
	/*
	 * To convert the data store, we have to do the following items:
	 * 1. Create the new location/path
	 * 2. Convert the dhcptab
	 * 3. Convert the network tables
	 * 4. Modify the DHCP defaults
	 * 5. Delete old tables if necessary
	 */

	getDsconf().setLocation();
	getDsconf().setConfig();
	final DhcpDatastore newDhcpDatastore = getDsconf().getDS();
	final DhcpDatastore oldDhcpDatastore = dhcpdOptions.getDhcpDatastore();

	if (newDhcpDatastore.equals(oldDhcpDatastore)) {
	    JOptionPane.showMessageDialog(ConvertWizard.this,
		ResourceStrings.getString("cvt_wiz_same_datastore_error"),
		ResourceStrings.getString("cvt_wiz_error"),
		JOptionPane.ERROR_MESSAGE);
	    return;
	}

	// Create the new location if it does not exist.
	//
	try {
	    svcServer.makeLocation(newDhcpDatastore);
	} catch (ExistsException e) {
	    // this is o.k.
	} catch (Throwable e) {
	    MessageFormat form = new MessageFormat(
		ResourceStrings.getString("cvt_wiz_location_error"));
	    Object [] args = new Object[1];
	    args[0] = newDhcpDatastore.getLocation();
	    String msg = form.format(args);
	    JOptionPane.showMessageDialog(ConvertWizard.this,
			msg,
			ResourceStrings.getString("cvt_wiz_error"),
			JOptionPane.ERROR_MESSAGE);

	    return;
	}

	// Go get a list of the network tables to convert.
	//
	try {
	    networks = netServer.getNetworks(oldDhcpDatastore);
	    if (networks == null) {
		networks = new Network[0];
	    }
	} catch (Throwable e) {
	    MessageFormat form = new MessageFormat(
		ResourceStrings.getString("cvt_wiz_networks_error"));
	    Object [] args = new Object[1];
	    args[0] = e.getMessage();
	    String msg = form.format(args);
	    JOptionPane.showMessageDialog(ConvertWizard.this,
			msg,
			ResourceStrings.getString("cvt_wiz_error"),
			JOptionPane.ERROR_MESSAGE);

	    reallyFinish();
	    return;
	}

	// Add 1 to tables count for dhcptab
	final int tables = networks.length + 1;
	// One update per table, plus one per table if deleting
	int updates =
	    !saveTablesStep.isSaveTablesSelected() ? tables * 2 : tables;
	// Add: one for shutdown, one for updating dhcpsvc.conf
	updates += 2;
	// If daemon will be restarted, then add 1 for start
	if (dhcpdOptions.isDaemonEnabled()) {
	    ++updates;
	}
	final ProgressManager progress = new ProgressManager(this,
	    ResourceStrings.getString("cvt_wiz_progress"),
	    "", 0, updates);

	// Called when doFinish() is really finished
	// (i.e., the thread completes).
	//
	final Runnable finisher = new Runnable() {
	    public void run() {
		reallyFinish();
	    }
	};


	// Here's the thread which does the conversion.
	//
	Thread convertThread = new Thread() {
	    public void run() {

		String message = null;
		MessageFormat form;
		MessageFormat errForm;
		Object [] args = new Object[1];
		boolean saveTables =
		    saveTablesStep.isSaveTablesSelected();

		// This is final so it can be used in the
		// errorDisplay Runnable.
		//
		final ErrorTable failedTable = new ErrorTable(
		    ResourceStrings.getString("cvt_wiz_table"),
		    String.class);

		// Shutdown the server.
		//
		int counter = 0;
		try {
		    svcServer.shutdown();
		    message = ResourceStrings.getString(
			"cvt_wiz_server_shutdown");
		} catch (Throwable e) {
		    message =
			ResourceStrings.getString("cvt_wiz_shutdown_err");
		    failedTable.addError("", e.getMessage());
		    saveTables = true;
		} finally {
		    try {
			progress.update(++counter, message);
		    } catch (InterruptedException e) {
			SwingUtilities.invokeLater(finisher);
			return;
		    }
		}

		// Convert the dhcptab.
		//
		try {
		    dhcptabServer.cvtDhcptab(newDhcpDatastore);
		    message = ResourceStrings.getString(
			"cvt_wiz_progress_dhcptab_cvt");
		} catch (Throwable e) {
		    message = ResourceStrings.getString(
			"cvt_wiz_progress_dhcptab_cvt_err");
		    failedTable.addError(ResourceStrings.getString(
			"cvt_wiz_dhcptab"), e.getMessage());
		    saveTables = true;
		} finally {
		    try {
			progress.update(++counter, message);
		    } catch (InterruptedException e) {
			SwingUtilities.invokeLater(finisher);
			return;
		    }
		}

		// Convert the network tables.
		//
		form = new MessageFormat(ResourceStrings.getString(
		    "cvt_wiz_progress_network_cvt"));
		errForm = new MessageFormat(ResourceStrings.getString(
		    "cvt_wiz_progress_network_cvt_err"));

		for (int i = 0; i < networks.length; ++i) {
		    String netString = networks[i].toString();
		    args[0] = netString;
		    try {
			netServer.cvtNetwork(netString, newDhcpDatastore);
			message = form.format(args);
		    } catch (Throwable e) {
			message = errForm.format(args);
			failedTable.addError(netString, e.getMessage());
			saveTables = true;
		    } finally {
			try {
			    progress.update(++counter, message);
			} catch (InterruptedException e) {
			    SwingUtilities.invokeLater(finisher);
			    return;
			}
		    }
		}

		// Update the DHCP defaults file with the new values.
		//
		dhcpdOptions.setDhcpDatastore(newDhcpDatastore);
		try {
		    svcServer.writeDefaults(dhcpdOptions);
		    message = ResourceStrings.getString(
			"cvt_wiz_progress_defaults");
		} catch (Throwable e) {
		    message = ResourceStrings.getString(
			"cvt_wiz_progress_defaults_err");
		    failedTable.addError(ResourceStrings.getString(
			"cvt_wiz_defaults"), e.getMessage());
		    saveTables = true;
		} finally {
		    try {
			progress.update(++counter, message);
		    } catch (InterruptedException e) {
			SwingUtilities.invokeLater(finisher);
			return;
		    }
		}

		if (!saveTables) {
		    // Delete the network tables
		    //
		    form = new MessageFormat(ResourceStrings.getString(
			"cvt_wiz_progress_network_del"));
		    errForm = new MessageFormat(ResourceStrings.getString(
			"cvt_wiz_progress_network_del_err"));

		    for (int i = 0; i < networks.length; ++i) {
			String netString = networks[i].toString();
			args[0] = netString;
			try {
			    netServer.deleteNetwork(netString, false,
				oldDhcpDatastore);
			    message = form.format(args);
			} catch (Throwable e) {
			    message = errForm.format(args);
			    failedTable.addError(netString, e.getMessage());
			} finally {
			    try {
				progress.update(++counter, message);
			    } catch (InterruptedException e) {
				SwingUtilities.invokeLater(finisher);
				return;
			    }
			}
		    }

		    // Delete the dhcptab
		    //
		    try {
			dhcptabServer.deleteDhcptab(oldDhcpDatastore);
			message = ResourceStrings.getString(
			    "cvt_wiz_progress_dhcptab_del");
		    } catch (Throwable e) {
			message = ResourceStrings.getString(
			    "cvt_wiz_progress_dhcptab_del_err");
			failedTable.addError(ResourceStrings.getString(
			    "cvt_wiz_dhcptab"), e.getMessage());
		    } finally {
			try {
			    progress.update(++counter, message);
			} catch (InterruptedException e) {
			    SwingUtilities.invokeLater(finisher);
			    return;
			}
		    }
		} else if (!saveTablesStep.isSaveTablesSelected()) {
		    try {
			counter += tables;
			progress.update(counter, "");
		    } catch (InterruptedException e) {
			SwingUtilities.invokeLater(finisher);
			return;
		    }
		}

		// Start the server.
		//
		if (dhcpdOptions.isDaemonEnabled()) {
		    try {
			svcServer.startup();
			message = ResourceStrings.getString(
			    "cvt_wiz_server_started");
		    } catch (Throwable e) {
			message =
			    ResourceStrings.getString("cvt_wiz_start_err");
			failedTable.addError("", e.getMessage());
		    } finally {
			try {
			    progress.update(++counter, message);
			} catch (InterruptedException e) {
			    SwingUtilities.invokeLater(finisher);
			    return;
			}
		    }
		}

		// If any errors occurred, display them all at once.
		//
		if (!failedTable.isEmpty()) {
		    Runnable errorDisplay = new Runnable() {
			public void run() {
			    Object [] objs = new Object[2];
			    objs[0] =
				ResourceStrings.getString("cvt_wiz_errors");
			    JScrollPane scrollPane =
				new JScrollPane(failedTable);

			    // Resize the table to something kind of small
			    //
			    Dimension d =
				failedTable.
				getPreferredScrollableViewportSize();
			    d.height = 80;
			    failedTable.setPreferredScrollableViewportSize(d);
			    objs[1] = scrollPane;
			    JOptionPane.showMessageDialog(ConvertWizard.this,
				objs,
				ResourceStrings.getString("server_error_title"),
				JOptionPane.ERROR_MESSAGE);
			}
		    };
		    try {
			SwingUtilities.invokeAndWait(errorDisplay);
		    } catch (Throwable e) {
			e.printStackTrace();
		    }
		}
		SwingUtilities.invokeLater(finisher);
	    }
	};
	convertThread.start();
    }

    public void doHelp() {
	DhcpmgrApplet.showHelp("convert_wizard");
    }

    /**
     * Called by the worker thread upon completion to exec the Wizard
     * doFinish().
     */
    protected void reallyFinish() {
	super.doFinish();
    } // reallyFinish

} // ConvertWizard
