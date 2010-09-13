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
 * Copyright 2001-2002 by Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

package com.sun.dhcpmgr.client;

import javax.swing.*;
import javax.swing.event.*;
import java.awt.*;
import java.util.Date;
import java.text.SimpleDateFormat;
import java.text.MessageFormat;
import java.lang.reflect.InvocationTargetException;
import java.io.FileNotFoundException;

import com.sun.dhcpmgr.ui.*;
import com.sun.dhcpmgr.data.ActionError;
import com.sun.dhcpmgr.data.ExportHeader;
import com.sun.dhcpmgr.common.*;

/**
 * ImportWizard provides an easy-to-use interface for importing configuration
 * data from one DHCP server to another.
 *
 * @see ExportWizard
 */
public class ImportWizard extends Wizard {

    // Step to get the location of the export file
    class LocationStep implements WizardStep {
	JPanel stepPanel;
	JTextField pathField;
	JCheckBox overrideBox;

	public LocationStep() {
	    GridBagLayout bag = new GridBagLayout();
	    GridBagConstraints con = new GridBagConstraints();
	    con.insets = new Insets(2, 2, 2, 2);
	    con.gridx = con.gridy = 0;
	    con.gridwidth = 2;
	    con.gridheight = 1;
	    con.weightx = 0;
	    con.weighty = 1.0;
	    con.fill = GridBagConstraints.BOTH;
	    con.anchor = GridBagConstraints.NORTHWEST;

	    stepPanel = new JPanel(bag);

	    Component c = Wizard.createTextArea(
		ResourceStrings.getString("imp_wiz_location_explain"), 8, 45);
	    bag.setConstraints(c, con);
	    stepPanel.add(c);

	    Mnemonic mnFile =
                new Mnemonic(ResourceStrings.getString("imp_wiz_file_label"));
            JLabel l = new JLabel(mnFile.getString());
            l.setToolTipText(mnFile.getString());
	    l.setDisplayedMnemonic(mnFile.getMnemonic());

	    ++con.gridy;
	    con.gridwidth = 1;
	    con.weighty = 0;
	    con.fill = GridBagConstraints.HORIZONTAL;
	    bag.setConstraints(l, con);
	    stepPanel.add(l);

	    pathField = new JTextField(importPath);
	    l.setLabelFor(pathField);
	    ++con.gridx;
	    con.weightx = 1.0;
	    bag.setConstraints(pathField, con);
	    stepPanel.add(pathField);

	    c = Wizard.createTextArea(
		ResourceStrings.getString("imp_wiz_override_explain"), 4, 45);
	    con.gridx = 0;
	    ++con.gridy;
	    con.weighty = 0.5;
	    con.weightx = 0;
	    con.fill = GridBagConstraints.BOTH;
	    con.gridwidth = 2;
	    bag.setConstraints(c, con);
	    stepPanel.add(c);

	    overrideBox = new JCheckBox(
		ResourceStrings.getString("imp_wiz_override_data"), false);
	    overrideBox.setToolTipText(
	        ResourceStrings.getString("imp_wiz_override_data"));
	    con.gridx = 0;
	    ++con.gridy;
	    con.gridwidth = 2;
	    con.weighty = 0;
	    con.weightx = 1.0;
	    con.fill = GridBagConstraints.HORIZONTAL;
	    bag.setConstraints(overrideBox, con);
	    stepPanel.add(overrideBox);

	    c = Box.createVerticalGlue();
	    ++con.gridy;
	    con.weighty = 1.0;
	    con.weightx = 0;
	    con.fill = GridBagConstraints.VERTICAL;
	    bag.setConstraints(c, con);
	    stepPanel.add(c);

	    // Enable forward only if something is entered in the file field
	    pathField.getDocument().addDocumentListener(new DocumentListener() {
		public void insertUpdate(DocumentEvent e) {
		    setForwardEnabled(pathField.getText().length() != 0);
		}
		public void changedUpdate(DocumentEvent e) {
		    insertUpdate(e);
		}
		public void removeUpdate(DocumentEvent e) {
		    insertUpdate(e);
		}
	    });
	}

	public String getDescription() {
	    return ResourceStrings.getString("imp_wiz_file_desc");
	}

	public Component getComponent() {
	    return stepPanel;
	}

	public void setActive(int direction) {
	    pathField.setText(importPath);
	    overrideBox.setSelected(conflictImport);
	    setForwardEnabled(importPath.length() != 0);
	}

	public boolean setInactive(int direction) {
	    importPath = pathField.getText();
	    conflictImport = overrideBox.isSelected();
	    /*
	     * Read the file header for display in next step; if we can't read
	     * it, display the errors and veto the forward step.
	     */
	    if (direction == FORWARD) {
		importController.setFile(importPath);
		try {
		    header = importController.getHeader();
		    if (header == null) {
			// Something wrong, but controller already displayed err
			return false;
		    }
		} catch (FileNotFoundException e) {
		    JOptionPane.showMessageDialog(ImportWizard.this,
			ResourceStrings.getString("imp_err_file_not_found"),
			ResourceStrings.getString("server_error_title"),
			JOptionPane.ERROR_MESSAGE);
		    return false;
		} catch (Exception e) {
		    String [] msgs = new String [] {
			ResourceStrings.getString("imp_err_reading_header"),
			e.getMessage()
		    };
		    JOptionPane.showMessageDialog(ImportWizard.this, msgs,
			ResourceStrings.getString("server_error_title"),
			JOptionPane.ERROR_MESSAGE);
		    return false;
		}
	    }
	    return true;
	}
    }

    // Allow user to review summary of file contents before proceeding.
    class ReviewStep implements WizardStep {
	private Box stepBox;
	private JLabel fileLabel, srcLabel, userLabel, dateLabel, overrideLabel;
	private JLabel infoLabel;
	private SimpleDateFormat dateFormat = new SimpleDateFormat();
	private MessageFormat infoFormat =
	    new MessageFormat(ResourceStrings.getString("imp_wiz_review_info"));

	public ReviewStep() {
	    stepBox = Box.createVerticalBox();
	    JComponent jc = Wizard.createTextArea(
		ResourceStrings.getString("imp_wiz_review_explain"), 6, 45);
	    jc.setAlignmentX(Component.LEFT_ALIGNMENT);
	    stepBox.add(jc);

	    Mnemonic mnFl =
                new Mnemonic(ResourceStrings.getString("imp_wiz_file_label"));
            JPanel fieldPanel = new JPanel(new FieldLayout());
            JLabel l = new JLabel(mnFl.getString());
            l.setLabelFor(fieldPanel);
            l.setToolTipText(mnFl.getString());
            fieldPanel.add(l, FieldLayout.LABEL);

	    fileLabel = new JLabel();
	    fileLabel.setForeground(Color.black);
	    fieldPanel.add(fileLabel, FieldLayout.FIELD);

	    l = new JLabel(
		ResourceStrings.getString("imp_wiz_review_override"));
	    fieldPanel.add(l, FieldLayout.LABEL);
	    l.setToolTipText(
	        ResourceStrings.getString("imp_wiz_review_override"));

	    overrideLabel = new JLabel();
	    l.setLabelFor(overrideLabel);
	    overrideLabel.setForeground(Color.black);
	    fieldPanel.add(overrideLabel, FieldLayout.FIELD);

	    fieldPanel.setAlignmentX(Component.LEFT_ALIGNMENT);
	    stepBox.add(fieldPanel);

	    stepBox.add(Box.createVerticalStrut(5));

	    infoLabel = new JLabel();
	    infoLabel.setAlignmentX(Component.LEFT_ALIGNMENT);
	    stepBox.add(infoLabel);

	    l = new JLabel(
		ResourceStrings.getString("imp_wiz_review_src"));
	    fieldPanel = new JPanel(new FieldLayout());
	    fieldPanel.add(l, FieldLayout.LABEL);
	    l.setToolTipText(ResourceStrings.getString("imp_wiz_review_src"));

	    srcLabel = new JLabel();
	    l.setLabelFor(srcLabel);
	    fieldPanel.add(srcLabel, FieldLayout.FIELD);
	   
	    l = new JLabel(
		ResourceStrings.getString("imp_wiz_review_user"));
	    fieldPanel.add(l, FieldLayout.LABEL);
	    l.setToolTipText(ResourceStrings.getString("imp_wiz_review_user"));

	    userLabel = new JLabel();
	    l.setLabelFor(userLabel);
	    fieldPanel.add(userLabel, FieldLayout.FIELD);

	    l = new JLabel(
		ResourceStrings.getString("imp_wiz_review_date"));
	    fieldPanel.add(l, FieldLayout.LABEL);
	    l.setToolTipText(ResourceStrings.getString("imp_wiz_review_date"));

	    dateLabel = new JLabel(dateFormat.format(new Date()));
	    l.setLabelFor(dateLabel);
	    fieldPanel.add(dateLabel, FieldLayout.FIELD);

	    fieldPanel.setAlignmentX(Component.LEFT_ALIGNMENT);
	    stepBox.add(fieldPanel);

	    stepBox.add(Box.createVerticalGlue());
	}

	public String getDescription() {
	    return ResourceStrings.getString("imp_wiz_review_desc");
	}

	public Component getComponent() {
	    return stepBox;
	}

	public void setActive(int direction) {
	    fileLabel.setText(importPath);
	    if (conflictImport) {
		overrideLabel.setText(ResourceStrings.getString("yes"));
	    } else {
		overrideLabel.setText(ResourceStrings.getString("no"));
	    }
	    Object [] objs = new Object [] { importPath };
	    infoLabel.setText(infoFormat.format(objs));
	    // Set values from file header
	    srcLabel.setText(header.getServer());
	    userLabel.setText(header.getUser());
	    dateLabel.setText(dateFormat.format(header.getDate()));
	    
	    setFinishEnabled(true);
	}

	public boolean setInactive(int direction) {
	    return true;
	}
    }

    /*
     * Display an error message inside a separate thread so that background
     * threads may interact with the user via SwingUtilities.invoke*
     */
    class ErrorDisplay implements Runnable {
	Object [] objs;

	public ErrorDisplay(Object [] objs) {
	    this.objs = objs;
	}

	public void run() {
	    JOptionPane.showMessageDialog(ImportWizard.this, objs,
		ResourceStrings.getString("server_error_title"),
		JOptionPane.ERROR_MESSAGE);
	}
    }

    private String importPath = "";
    private boolean conflictImport = false;
    private ImportController importController;
    private ExportHeader header;
    /*
     * The Importer allows the ImportController, which contains all of the
     * actual import logic, to interact with the user as the import proceeds.
     * Since we run the import in a background thread to keep the GUI live,
     * the interactions must use SwingUtilities.invoke* to control the GUI.
     * Progress updates via ProgressManager don't need special logic here as
     * ProgressManager already handles the threading work for us.
     */
    private Importer importer = new Importer() {
	ProgressManager progress;
	String [] errObjs = new String [] {
	    ResourceStrings.getString("imp_error"), ""
	};

	// Create progress display
	public void initializeProgress(int length) {
	    progress = new ProgressManager(ImportWizard.this,
		ResourceStrings.getString("imp_progress_title"), "", 0,
		length);
	}

	// Update progress display with current completion level and message
	public void updateProgress(int done, String message)
	    	throws InterruptedException {
	    progress.update(done, message);
	}

	// Display a single error message
	public void displayError(String message) {
	    errObjs[1] = message;
	    displayError(errObjs);
	}

	// Display a group of error messages using a table.
	public void displayErrors(String msg, String label,
		ActionError [] errors) {
	    ErrorTable errTable = new ErrorTable(label);
	    errTable.setErrors(errors);
	    JScrollPane scrollPane = new JScrollPane(errTable);
	    Object [] errObjs = new Object [] { msg, scrollPane };
	    displayError(errObjs);
	}

	// Display an error in the GUI
	private void displayError(Object [] errObjs) {
	    // If we're on the event dispatch thread already then display now
	    ErrorDisplay ed = new ErrorDisplay(errObjs);
	    if (SwingUtilities.isEventDispatchThread()) {
		ed.run();
	    } else {
		try {
		    SwingUtilities.invokeAndWait(ed);
		} catch (Exception e) {
		    // Errors here are fairly serious; dump the stack
		    e.printStackTrace();
		}
	    }
	}
    };

    public ImportWizard(Frame owner) {
	super(owner, "");
	setTitle(ResourceStrings.getString("import_wiz_title"));

	addStep(new LocationStep());
	addStep(new ReviewStep());

	importController = new ImportController(importer,
	    DataManager.get().getServer());
	showFirstStep();
    }

    public void doFinish() {
	/*
	 * Runnable which the importThread can call to tear down the display
	 * when it's completed.
	 */
	final Runnable finisher = new Runnable() {
	    public void run() {
		reallyFinish();
	    }
	};

	// Create the thread in which to execute the import
	Thread importThread = new Thread() {
	    public void run() {	    
		if (importController.importData(conflictImport)) {
		    // Only exit if import successful
		    SwingUtilities.invokeLater(finisher);
		}
	    }
	};
	// Run the import thread
	importThread.start();
    }

    public void doCancel() {
	// Close file if there is one open
	importController.closeFile();
	super.doCancel();
    }

    protected void reallyFinish() {
	super.doFinish();
    }

    public void doHelp() {
	DhcpmgrApplet.showHelp("import_wizard");
    }
}
