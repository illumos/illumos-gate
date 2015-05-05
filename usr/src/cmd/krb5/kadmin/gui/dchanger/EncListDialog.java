/*
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

import java.awt.*;
import java.awt.event.*;
import java.text.*;
import java.util.*;

/*
 * This class creates a dialog box that helps the user select encryption types
 * with some mouse clicks.  The dialog box need only be created
 * once. The Ok and Cancel buttons merely call setVisible with an
 * argument of false.
 */

// The layout will consist of 2 panels:
// topPanel contains the dynamic list of encryption type check boxes.
// bottomPanel contains the buttons ok, clear, cancel, and help.
// The two panels are separated by a LineSeparator.

public class EncListDialog extends Dialog {

	private boolean save;

	private int i;

	private Frame parent;

	private Button ok;
	private Button clear;
	private Button cancel;
	private Button help;

	private HelpDialog hd = null;

	private Panel topPanel;
	private Panel bottomPanel;

	private static Toolkit toolkit = Toolkit.getDefaultToolkit();

	private Kadmin kadmin;
	private Checkbox cb[];
	private Integer grp_num[];
	private String encList = "";

	// For I18N
	private static ResourceBundle rb =
	    ResourceBundle.getBundle("GuiResource" /* NOI18N */);
	private static ResourceBundle hrb =
	    ResourceBundle.getBundle("HelpData" /* NOI18N */);

	/*
	 * Constructor that lays out the components and sets the different
	 * event handlers.
	 */
	public EncListDialog(Frame parent, Color background, Color foreground,
	    Kadmin session) {
		super(parent, getString("SEAM Encryption Type List Helper"),
		    true);

		this.parent = parent;

		this.kadmin = session;

		setLayout(new GridBagLayout());
		addCheckboxes();

		addButtons();
		setSize(250, 300);
		setResizable(true);

		addWindowListener(new DCWindowListener());
	}

	/*
	 * Adds the check boxes only
	 */
	private void addCheckboxes() {

		GridBagConstraints gbc = new GridBagConstraints();

		gbc.weighty = 1;

		topPanel = new Panel();
		topPanel.setLayout(new GridBagLayout());
		gbc.gridwidth = GridBagConstraints.REMAINDER;
		gbc.fill = GridBagConstraints.BOTH;
		gbc.anchor = GridBagConstraints.CENTER;
		gbc.gridx = 0;
		gbc.gridy = 0;
		add(topPanel, gbc);

		gbc.fill = GridBagConstraints.NONE;
		gbc.anchor = GridBagConstraints.WEST;
		gbc.gridx = 0;
		gbc.gridwidth = 1;

		String et[] = kadmin.getEncList();

		cb = new Checkbox[et.length];
		grp_num = new Integer[et.length];

		for (int i = 0; i < et.length; i++) {
			String[] grp_enc = et[i].split(" ");
			cb[i] = new Checkbox(grp_enc[1]);
			CBListener cbl = new CBListener();
			cb[i].addItemListener(cbl);
			grp_num[i] = new Integer(grp_enc[0]);
			gbc.gridy = i;
			topPanel.add(cb[i], gbc);
		}
	}

	// Adds all the buttons
	private void addButtons() {

		GridBagConstraints gbc = new GridBagConstraints();
		gbc.weighty = 1;

		gbc.gridwidth = GridBagConstraints.REMAINDER;
		gbc.gridheight = 1;
		gbc.fill = GridBagConstraints.BOTH;
		gbc.gridx = 0;
		gbc.gridy = 2;
		add(new LineSeparator(), gbc);

		bottomPanel = new Panel();
		ok = new Button(getString("OK"));
		clear = new Button(getString("Clear"));
		cancel = new Button(getString("Cancel"));
		help = new Button(getString("Help"));
		bottomPanel.add(ok);
		bottomPanel.add(clear);
		bottomPanel.add(cancel);
		bottomPanel.add(help);
		gbc.fill = GridBagConstraints.HORIZONTAL;
		gbc.gridwidth = GridBagConstraints.REMAINDER;
		gbc.gridx = 0;
		gbc.gridy = 3;
		add(bottomPanel, gbc);

		DCButtonListener bl = new DCButtonListener();
		ok.addActionListener(bl);
		clear.addActionListener(bl);
		cancel.addActionListener(bl);
		help.addActionListener(bl);
	}

	/*
	 * Closes (hides) the dialog box when the user is done
	 * @param save true if the box is being dismissed by clicking on
	 * "ok" and the user wants to retain the modified value, false
	 * otherwise.
	 */
	private void encListDialogClose(boolean save) {
		this.save = save;
		setVisible(false);
	}

	/*
	 * Checks if the user requested that the value in this
	 * EncListDialog be used e.g., by clicking on "Ok" instead of
	 * "Cancel."
	 * @return true if the user wants to save the value in the
	 * EncListDialog, false otherwise.
	 */

	public boolean isSaved() {
		return save;
	}
	/*
	 * Sets the current enc list for the principal during modification.
	 * @param enc types of current principal.
	 */
	public void setEncTypes(String e_str) {

		if (e_str.compareTo("") == 0)
			return;

		String[] e_list = e_str.split(" ");

		for (int i = 0; i < e_list.length; i++) {
			for (int j = 0; j < cb.length; j++) {
				if (cb[j].getLabel().compareTo(e_list[i])
				    == 0) {
					cb[j].setState(true);
					break;
				}
			}
		}
	}

	// ***********************************************
	//	 I N N E R    C L A S S E S   F O L L O W
	// ***********************************************

	/*
	 * Listener for an annoying work around in deselection of a check box
	 * in case the user doesn't want any items in a grouped list.
	 */
	private class CBListener implements ItemListener {

		public void itemStateChanged(ItemEvent e) {
			Checkbox c = (Checkbox) e.getItemSelectable();

			if (e.getStateChange() == e.DESELECTED) {
				c.setState(false);
			} else if (e.getStateChange() == e.SELECTED) {
				for (int i = 0; i < cb.length; i++) {
				    if (c == cb[i]) {
					for (int j = 0; j < cb.length; j++) {
					    if (grp_num[j].equals(grp_num[i])
						== true) {
						cb[j].setState(false);
					    }
					}
					break;
				    }
				}
				c.setState(true);
			// else what else is there
			}
		}
	}

	/*
	 * Listener for closing the dialog box through the window close
	 * menu.
	 */
	private class DCWindowListener extends WindowAdapter {

		public void windowClosing(WindowEvent e) {
			encListDialogClose(false);
		}
	}

	/*
	 * Listener for all the buttons. The listener is shared for the sake
	 * of reducing the number of overall listeners.
	 * TBD: I18N the help
	 */
	private class DCButtonListener implements ActionListener {

		public void actionPerformed(ActionEvent e) {
			if (e.getSource() == ok) {
				EncListDialog.this.encListDialogClose(true);
			} else if (e.getSource() == cancel) {
				EncListDialog.this.encListDialogClose(false);
			} else if (e.getSource() == clear) {
				for (int i = 0; i < cb.length; i++) {
					cb[i].setState(false);
				}
			} else if (e.getSource() == help) {
				if (hd != null)
					hd.setVisible(true);
				else {
					hd = new HelpDialog(
					    EncListDialog.this.parent,
					    getString(
					    "Help for Encryption Type Dialog"),
					    false);
					hd.setVisible(true);
					hd.setText(getString(hrb,
					    "EncryptionTypeDialogHelp"));
				}
			}
		} // actionPerformed
	}

	/*
	 * The string representation of the dialog box.
	 * @return a String which contians the encryption type list
	 */
	public String toString() {

		for (int i = 0; i < cb.length; i++) {
			if (cb[i].getState() == true)
				encList = encList.concat(cb[i].getLabel() +
				    " ");
		}
		return encList;
	}

	/*
	 * Call rb.getString(), but catch exception and return English
	 * key so that small spelling errors don't cripple the GUI
	 */
	private static final String getString(String key) {
		return (getString(rb, key));
	}

	private static final String getString(ResourceBundle rb, String key) {
		try {
			String res = rb.getString(key);
			return res;
		} catch (MissingResourceException e) {
			System.out.println("Missing resource "+key+
			    ", using English.");
			return key;
		}
	}
}
