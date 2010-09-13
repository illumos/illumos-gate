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
import java.text.MessageFormat;
import java.lang.reflect.InvocationTargetException;

import com.sun.dhcpmgr.server.DhcpMgr;
import com.sun.dhcpmgr.ui.*;
import com.sun.dhcpmgr.data.*;
import com.sun.dhcpmgr.common.*;
import com.sun.dhcpmgr.bridge.ExistsException;

/**
 * ExportWizard provides an easy-to-use interface for exporting the data
 * from one DHCP server to be later imported by another DHCP server, typically
 * because the administrator wishes to repartition the workload among DHCP
 * servers.
 */
public class ExportWizard extends Wizard {

    // Step to collect the networks to be exported
    class NetworkStep implements WizardStep {
	Box stepBox;
	ListPair networkLists;

	public NetworkStep() {
	    stepBox = Box.createVerticalBox();
	    stepBox.add(Wizard.createTextArea(
		ResourceStrings.getString("exp_wiz_net_explain"), 9, 45));
	    stepBox.add(Box.createVerticalStrut(10));
	    // XXX This try/catch goes away at Snakebite integration
	    try {
	    networkLists = new ListPair(
		ResourceStrings.getString("exp_wiz_dont_export"),
		DataManager.get().getNetworks(false),
		ResourceStrings.getString("exp_wiz_export"), networks);
	    } catch (Throwable t) {
		t.printStackTrace();
	    }
	    stepBox.add(networkLists);
	    stepBox.add(Box.createVerticalGlue());
	}

	public String getDescription() {
	    return ResourceStrings.getString("exp_wiz_net_desc");
	}

	public Component getComponent() {
	    return stepBox;
	}

	public void setActive(int direction) {
	    setForwardEnabled(true);
	}

	public boolean setInactive(int direction) {
	    networks =
		(Network [])networkLists.getRightContents(new Network[0]);
	    return true;
	}
    }

    // Step to collect the macros to be exported
    class MacroStep implements WizardStep {
	Box stepBox;
	ListPair macroLists;

	public MacroStep() {
	    stepBox = Box.createVerticalBox();
	    stepBox.add(Wizard.createTextArea(
		ResourceStrings.getString("exp_wiz_macros_explain"), 4, 45));
	    stepBox.add(Box.createVerticalStrut(10));
	    // XXX This try/catch will go away at Snakebite integration
	    try {
	    Macro [] macros = DataManager.get().getMacros(false);
	    macroNames = new String[macros.length];
	    for (int i = 0; i < macros.length; ++i) {
		macroNames[i] = macros[i].getKey();
	    }
	    macroLists = new ListPair(
	    	ResourceStrings.getString("exp_wiz_dont_export"), macroNames, 
		ResourceStrings.getString("exp_wiz_export"), null);
	    } catch (Throwable t) {
		t.printStackTrace();
	    }
	    stepBox.add(macroLists);
	    stepBox.add(Box.createVerticalGlue());
	}

	public String getDescription() {
    	    return ResourceStrings.getString("exp_wiz_macro_desc");
	}

	public Component getComponent() {
    	    return stepBox;
	}

	public void setActive(int direction) {
	    setForwardEnabled(true);
	}

	public boolean setInactive(int direction) {
	    macroNames = (String [])macroLists.getRightContents(new String[0]);
	    return true;
	}
    }

    // Step to collect the options to be exported
    class OptionStep implements WizardStep {
	Box stepBox;
	ListPair optionLists;

	public OptionStep() {
	    stepBox = Box.createVerticalBox();
	    stepBox.add(Wizard.createTextArea(
		ResourceStrings.getString("exp_wiz_options_explain"), 4, 45));
	    stepBox.add(Box.createVerticalStrut(10));
	    // XXX This try/catch will go away at Snakebite integration
	    try {
	    Option[] options = DataManager.get().getOptions(false);
	    optionNames = new String[options.length];
	    for (int i = 0; i < options.length; ++i) {
    		optionNames[i] = options[i].getKey();
	    }
	    optionLists = new ListPair(
		ResourceStrings.getString("exp_wiz_dont_export"), optionNames, 
		ResourceStrings.getString("exp_wiz_export"), null);
	    } catch (Throwable t) {
		t.printStackTrace();
	    }
	    stepBox.add(optionLists);
	    stepBox.add(Box.createVerticalGlue());
	}

	public String getDescription() {
    	    return ResourceStrings.getString("exp_wiz_option_desc");
	}

	public Component getComponent() {
    	    return stepBox;
	}

	public void setActive(int direction) {
	    setForwardEnabled(true);
	}

	public boolean setInactive(int direction) {
	    optionNames =
		(String [])optionLists.getRightContents(new String[0]);
	    return true;
	}
    }

    // Step to collect the name of the file to which data is exported
    class FileStep implements WizardStep {
	JPanel stepPanel;
	NoSpaceField pathField;
	JCheckBox deleteBox;

	public FileStep() {
	    GridBagLayout bag = new GridBagLayout();
	    GridBagConstraints con = new GridBagConstraints();
	    con.insets = new Insets(2, 2, 2, 2);
	    con.gridx = con.gridy = 0;
	    con.gridwidth = 2;
	    con.gridheight = 1;
	    con.weightx = 0;
	    con.weighty = 0.5;
	    con.fill = GridBagConstraints.BOTH;
	    con.anchor = GridBagConstraints.NORTHWEST;
	    stepPanel = new JPanel(bag);
	    Component c = Wizard.createTextArea(
		ResourceStrings.getString("exp_wiz_file_explain"), 4, 45);
	    bag.setConstraints(c, con);
	    stepPanel.add(c);

	    Mnemonic mnFile =
                new Mnemonic(ResourceStrings.getString("exp_wiz_file_label"));
            JLabel l = new JLabel(mnFile.getString());
            l.setLabelFor(stepPanel);
            l.setToolTipText(mnFile.getString());
	    l.setDisplayedMnemonic(mnFile.getMnemonic());

	    con.gridwidth = con.gridheight = 1;
	    con.fill = GridBagConstraints.NONE;
	    con.weighty = 0;
	    ++con.gridy;
	    bag.setConstraints(l, con);
	    stepPanel.add(l);

	    pathField = new NoSpaceField(exportPath);
	    l.setLabelFor(pathField);
	    ++con.gridx;
	    con.weightx = 1.0;
	    con.fill = GridBagConstraints.HORIZONTAL;
	    bag.setConstraints(pathField, con);
	    stepPanel.add(pathField);

	    c = Box.createVerticalStrut(10);
	    ++con.gridy;
	    con.gridx = 0;
	    con.weightx = 0;
	    bag.setConstraints(c, con);
	    stepPanel.add(c);

	    c = Wizard.createTextArea(
		    ResourceStrings.getString("exp_wiz_delete_explain"), 4, 45);
	    ++con.gridy;
	    con.gridx = 0;
	    con.weightx = 1.0;
	    con.weighty = 0.5;
	    con.gridwidth = 2;
	    con.fill = GridBagConstraints.BOTH;
	    bag.setConstraints(c, con);
	    stepPanel.add(c);

	    deleteBox = new JCheckBox(
		ResourceStrings.getString("exp_wiz_delete_exported"), false);
	    deleteBox.setToolTipText(
	        ResourceStrings.getString("exp_wiz_delete_exported"));
	    con.gridx = 0;
	    ++con.gridy;
	    con.fill = GridBagConstraints.HORIZONTAL;
	    bag.setConstraints(deleteBox, con);
	    stepPanel.add(deleteBox);

	    c = Box.createVerticalGlue();
	    ++con.gridy;
	    con.weighty = 1.0;
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
	    return ResourceStrings.getString("exp_wiz_file_desc");
	}

	public Component getComponent() {
	    return stepPanel;
	}

	public void setActive(int direction) {
	    pathField.setText(exportPath);
	    deleteBox.setSelected(deleteData);
	}

	public boolean setInactive(int direction) {
	    exportPath = pathField.getText();
	    deleteData = deleteBox.isSelected();
	    return true;
	}
    }

    // Review everything before doing it
    class ReviewStep implements WizardStep {
	JPanel mainPanel;
	JList networkList, macroList, optionList;
	JLabel exportLabel, deleteLabel;

	public ReviewStep() {
	    mainPanel = new JPanel(new BorderLayout());
	    mainPanel.add(Wizard.createTextArea(
		ResourceStrings.getString("exp_wiz_review_explain"), 6, 45),
		BorderLayout.NORTH);
	    JPanel fieldPanel = new JPanel(new FieldLayout());

	    Mnemonic mnNets =
                new Mnemonic(ResourceStrings.getString("exp_wiz_review_nets"));
            JLabel revNetsLbl = new JLabel(mnNets.getString());
            revNetsLbl.setToolTipText(mnNets.getString());
            fieldPanel.add(revNetsLbl, FieldLayout.LABELTOP);
            networkList = new JList();
            revNetsLbl.setLabelFor(networkList);
            JScrollPane scrollPane = new JScrollPane(networkList);
            fieldPanel.add(scrollPane, FieldLayout.FIELD);
	    revNetsLbl.setDisplayedMnemonic(mnNets.getMnemonic());

	    Mnemonic mnMacros =
                new Mnemonic(ResourceStrings.getString(
		"exp_wiz_review_macros"));
  	    JLabel revMacLbl = new JLabel(mnMacros.getString());
            revMacLbl.setToolTipText(mnMacros.getString());
            fieldPanel.add(revMacLbl, FieldLayout.LABELTOP);
            macroList = new JList();
            revMacLbl.setLabelFor(macroList);
            scrollPane = new JScrollPane(macroList);
            fieldPanel.add(scrollPane, FieldLayout.FIELD);
	    revMacLbl.setDisplayedMnemonic(mnMacros.getMnemonic());

	    Mnemonic mnOpt =
                new Mnemonic(ResourceStrings.getString(
		"exp_wiz_review_options"));
 	    JLabel optLbl = new JLabel(mnOpt.getString());
            fieldPanel.add(optLbl, FieldLayout.LABELTOP);
            optLbl.setToolTipText(mnOpt.getString());
            optionList = new JList();
            optLbl.setLabelFor(optionList);
            scrollPane = new JScrollPane(optionList);
            fieldPanel.add(scrollPane, FieldLayout.FIELD);
	    optLbl.setDisplayedMnemonic(mnOpt.getMnemonic());

	    Mnemonic mnFileRvw =
                new Mnemonic(ResourceStrings.getString("exp_wiz_file_label"));
            JLabel fileLbl =
                new JLabel(mnFileRvw.getString());
            fileLbl.setLabelFor(fieldPanel);
            fileLbl.setToolTipText(mnFileRvw.getString());
            fieldPanel.add(fileLbl, FieldLayout.LABEL);
            exportLabel = new JLabel();
            exportLabel.setForeground(Color.black);
            fieldPanel.add(exportLabel, FieldLayout.FIELD);

	    JLabel delLbl = 
	        new JLabel(ResourceStrings.getString("exp_wiz_delete_label"));
	    delLbl.setLabelFor(fieldPanel);  
	    delLbl.setToolTipText(ResourceStrings.getString(
		"exp_wiz_delete_label"));
	    fieldPanel.add(delLbl, FieldLayout.LABEL);

	    deleteLabel = new JLabel();
	    deleteLabel.setForeground(Color.black);
	    fieldPanel.add(deleteLabel, FieldLayout.FIELD);

	    mainPanel.add(fieldPanel, BorderLayout.CENTER);
	}

	public String getDescription() {
	    return ResourceStrings.getString("exp_wiz_review_desc");
	}

	public Component getComponent() {
	    return mainPanel;
	}

	public void setActive(int direction) {
	    networkList.setListData(networks);
	    macroList.setListData(macroNames);
	    optionList.setListData(optionNames);
	    exportLabel.setText(exportPath);
	    if (deleteData) {
	    	deleteLabel.setText(ResourceStrings.getString("yes"));
	    } else {
		deleteLabel.setText(ResourceStrings.getString("no"));
	    }
	    setFinishEnabled(true);
	}

	public boolean setInactive(int direction) {
	    // Nothing to do here
	    return true;
	}
    }

    /*
     * Display an error message in its own thread.  This allows a task running
     * in a non-GUI thread to get the message displayed by the toolkit.
     */
    class ErrorDisplay implements Runnable {
	Object [] objs;

	public ErrorDisplay(Object [] objs) {
	    this.objs = objs;
	}

	public void run() {
	    JOptionPane.showMessageDialog(ExportWizard.this, objs,
		ResourceStrings.getString("server_error_title"),
		JOptionPane.ERROR_MESSAGE);
	}
    }

    /*
     * Display a warning message in its own thread.  This allows a task running
     * in a non-GUI thread to get the message displayed by the toolkit.
     */
    class WarningDisplay implements Runnable {
	Object [] objs;

	public WarningDisplay(Object [] objs) {
	    this.objs = objs;
	}

	public void run() {
	    JOptionPane.showMessageDialog(ExportWizard.this, objs,
		ResourceStrings.getString("server_warning_title"),
		JOptionPane.WARNING_MESSAGE);
	}
    }

    /*
     * Class to ask the user whether the export file should be forcibly
     * overwritten if it already exists.  We default to not overwriting
     * export files.  This is a Runnable in order to allow it to be displayed
     * by the export thread, which is a non-GUI thread.
     */
    class OverwritePrompter implements Runnable {
	/*
	 * overwrite member is public so we can access it directly since run()
	 * can't return the user's input.
	 */
	public boolean overwrite;

	public OverwritePrompter() {
	    overwrite = false;
	}

	public void run() {
	    int ret = JOptionPane.showConfirmDialog(
		ExportWizard.this,
		ResourceStrings.getString("exp_overwrite"),
		ResourceStrings.getString("exp_overwrite_title"),
		JOptionPane.YES_NO_OPTION,
		JOptionPane.QUESTION_MESSAGE);
	    // Return true if the user clicked Yes
	    overwrite = (ret == JOptionPane.YES_OPTION);
	}
    }

    private Network [] networks = new Network[0];
    private String [] macroNames = new String[0];
    private String [] optionNames = new String[0];
    private boolean deleteData = false;
    private String exportPath = "";

    public ExportWizard(Frame owner) {
	super(owner, "");
	setTitle(ResourceStrings.getString("export_wiz_title"));

	// Insert steps in order of execution
	addStep(new NetworkStep());
	addStep(new MacroStep());
	addStep(new OptionStep());
	addStep(new FileStep());
	addStep(new ReviewStep());

	showFirstStep();
    }

    /*
     * Execute the export.  This is relatively complicated because we want to
     * run the actual export in a background thread so that the whole GUI isn't
     * tied up during the export.  Also, the actual export logic is implemented
     * by the ExportController, and we provide an Exporter implementation
     * which allows it to interact with the user.  So, the ExportController is
     * executed in a background thread, and the callbacks implemented in the
     * Exporter must each use SwingUtilities.invoke* methods to ask for the
     * UI updates to happen.  In the case of the progress display, the
     * ProgressManager class already implements that logic so it's simpler
     * than the rest of the interactions.
     */
    public void doFinish() {
	/*
	 * This runnable serves merely to allow the background thread used for
	 * export to tell the GUI that it's done.
	 */
	final Runnable finisher = new Runnable() {
	    public void run() {
		reallyFinish();
	    }
	};

	/*
	 * Create callback interface used by ExportController to interact with
	 * the user.
	 */
	Exporter exporter = new Exporter() {
	    ProgressManager progress;
	    String [] errObjs = new String[] {
	    	ResourceStrings.getString("exp_error_occurred"),
		""
	    };

	    // Set up the progress display
	    public void initializeProgress(int length) {
		progress = new ProgressManager(ExportWizard.this,
		    ResourceStrings.getString("exp_progress_title"), "", 0,
		    length);
	    }

	    // Update progress to current point, updating message
	    public void updateProgress(int done, String message)
		    throws InterruptedException {
		progress.update(done, message);
	    }

	    // Display an error message
	    public void displayError(String message) {
		errObjs[1] = message;
		try {
		    SwingUtilities.invokeAndWait(new ErrorDisplay(errObjs));
		} catch (InvocationTargetException ex2) {
		    // ErrorDisplay threw an exception; give up!
		    ex2.printStackTrace();
		} catch (InterruptedException ex2) {
		    // ErrorDisplay was interrupted; give up!
		    ex2.printStackTrace();
		}
	    }

	    // Display a bunch of error messages in a table
	    public void displayErrors(String msg, String label,
		    ActionError [] errs) {
		ErrorTable errTable = new ErrorTable(label);
		errTable.setErrors(errs);
		JScrollPane scrollPane = new JScrollPane(errTable);
		Object [] warnObjs = new Object [] { msg, scrollPane };
		try {
		    SwingUtilities.invokeAndWait(new WarningDisplay(warnObjs));
		} catch (InvocationTargetException e) {
		    // WarningDisplay threw an exception; just dump it
		    e.printStackTrace();
		} catch (InterruptedException e) {
		    // WarningDisplay was interrupted; just dump it
		    e.printStackTrace();
		}
	    }
	};

	/*
	 * Create the export controller and set parameters.  Use final so
	 * that the exportThread can reference it.
	 */
	final ExportController exportController = new ExportController(exporter,
	    DataManager.get().getServer());
	exportController.setUser(System.getProperty("user.name"));
	exportController.setFile(exportPath);
	exportController.setOptions(optionNames);
	exportController.setMacros(macroNames);
	exportController.setNetworks(networks);

	// Now create the thread that does the exporting
	Thread exportThread = new Thread() {
	    public void run() {
		OverwritePrompter prompter = new OverwritePrompter();
		while (true) {
		    try {
			/*
			 * Controller will return true if it completed
			 * successfully, in which case we want to exit the
			 * wizard; if it returns false, just exit this
			 * thread but leave the wizard up.
			 */
			if (exportController.exportData(deleteData,
			    	prompter.overwrite)) {
			    SwingUtilities.invokeLater(finisher);
			}
			return;
		    } catch (ExistsException e) {
		    	// Export file already existed and overwrite was false
			try {
			    SwingUtilities.invokeAndWait(prompter);
			    /*
			     * If user said not to overwrite, then exit
			     * this thread but leave wizard up.  Otherwise just
			     * let the while loop try the export again.
			     */
			    if (!prompter.overwrite) {
				return;
			    }
			} catch (Throwable t) {
			    /*
			     * We can get an interrupt or prompter could
			     * throw an exception; the only reasonable
			     * thing to do at this point is just display
			     * the stack and return.
			     */
			    t.printStackTrace();
			    return;
			}
		    }
		}
	    }
	};
		
	// Now run the export thread	
	exportThread.start();
    }

    protected void reallyFinish() {
	super.doFinish();
    }

    public void doHelp() {
	DhcpmgrApplet.showHelp("export_wizard");
    }
}
