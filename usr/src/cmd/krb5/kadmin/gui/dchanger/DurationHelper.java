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
 * Copyright (c) 1999-2000 by Sun Microsystems, Inc.
 * All rights reserved.
 */

    import java.awt.*;
    import java.awt.event.*;
    import java.text.NumberFormat;
    import java.util.ResourceBundle;
    import java.util.MissingResourceException;

    /**
     * This creates a modal dialog box that lets the user enter a duration of
     * time in seconds/minutes/hours/days/weeks/months/years.
     */
    public class DurationHelper extends Dialog {

	private boolean save;

	private Frame parent;

	private Choice unit;
	private TextField value;
	private Label  total;

	private Button ok;
	private Button cancel;
	private Button help;
	private Button compute;

	private HelpDialog hd = null;

	// For I18N
	    private static ResourceBundle rb =
	    ResourceBundle.getBundle("GuiResource" /* NOI18N */);
	    private static ResourceBundle hrb =
	    ResourceBundle.getBundle("HelpData" /* NOI18N */);

	private static String[] units = { getString("Seconds"),
					getString("Minutes"),
					getString("Hours"),
					getString("Days"),
					getString("Weeks"),
					getString("Months"),
					getString("Years")	};
	private static int[] unitMultipliers = {1, 60, 60*60, 60*60*24,
						60*60*24*7, 60*60*24*30,
						60*60*24*365	};
	private static NumberFormat nf = NumberFormat.getInstance();
	private static Toolkit toolkit = Toolkit.getDefaultToolkit();

	/**
	 * Constructor for DurationHelper.
	 * @param parent the parent Frame to whom input will be blocked
	 * while this dialog box is begin shown(modal behaviour).
	 */
    public DurationHelper(Frame parent,	 Color background, Color foreground) {
		super(parent, getString("SEAM Duration Helper"), true);

		this.parent = parent;

		setLayout(new GridBagLayout());
		addLabels();
		addFields(background, foreground);
		addButtons();
		setSize(350, 150);
		setResizable(false);
		addWindowListener(new DHWindowListener());
    }

    /**
     * Adds all the labels.
     */
    private void addLabels() {
	GridBagConstraints gbc = new GridBagConstraints();
	gbc.weightx = gbc.weighty = 1;
	add(new Label(getString("Unit")), gbc);
	add(new Label(getString("Value")), gbc);

	gbc.gridx = 3;
	gbc.gridy = 0;
	add(new Label(getString("Seconds")), gbc);
    }

    /**
     * Initializes the strings for the units.
     */
    private void initUnits() {
	unit = new Choice();
	for (int i = 0; i < units.length; i++)
	    unit.add(units[i]);
	unit.select(getString("Hours"));
	unit.addItemListener(new ItemListener() {
		public void itemStateChanged(ItemEvent e) {
			DurationHelper.this.checkErrorAndSetTotal();
		}
	});
    }

    /**
     * Adds all the fields
     */
    private void addFields(Color background, Color foreground) {
	GridBagConstraints gbc = new GridBagConstraints();
	gbc.weightx =  gbc.weighty = 1;
	initUnits();
	value = new TextField();
	value.setBackground(background);
	value.setForeground(foreground);
	value.setColumns(10);

	// TBD: make total large enough to hold the largest int
	total = new Label("		" /* NO18N */,
			    Label.RIGHT);
	gbc.gridx = 0;
	gbc.gridy = 1;
	add(unit, gbc);
	gbc.gridx = 1;
	add(value, gbc);
	gbc.gridx = 3;
	add(total, gbc);

	value.addActionListener(new ActionListener() {
		public void actionPerformed(ActionEvent e) {
			DurationHelper.this.durationHelperClose(true);
		}
	});
    }

    /**
     * Adds all the buttons.
     */
    private void addButtons() {

	GridBagConstraints gbc = new GridBagConstraints();
	gbc.weightx =  gbc.weighty = 1;

	gbc.gridwidth = GridBagConstraints.REMAINDER;
	gbc.fill = GridBagConstraints.BOTH;
	gbc.gridx = 0;
	gbc.gridy = 2;
	gbc.insets = new Insets(0, 10, 0, 10);
	add(new LineSeparator(), gbc);
	gbc.insets = new Insets(0, 0, 0, 0);

	Panel p = new Panel();
	p.setLayout(new GridBagLayout());
	ok = new Button(getString("OK"));
	cancel =  new Button(getString("Cancel"));
	help = new Button(getString("Help"));
	gbc = new GridBagConstraints();
	gbc.weightx =  gbc.weighty = 1;
	p.add(ok, gbc);
	p.add(cancel, gbc);
	p.add(help, gbc);

	ActionListener bl = new ButtonListener();
	ok.addActionListener(bl);
	cancel.addActionListener(bl);
	help.addActionListener(bl);

	gbc.gridy = 3;
	gbc.gridwidth = GridBagConstraints.REMAINDER;
	gbc.fill = GridBagConstraints.HORIZONTAL;
	add(p, gbc);

	gbc = new GridBagConstraints();
	gbc.gridx = 2;
	gbc.gridy = 1;
	compute = new Button(getString("="));
	add(compute, gbc);
	compute.addActionListener(bl);

    }

    /**
     * Updates the label called total.
     * @return false if the text entry in the value
     * field is not parseable, true otherwise.
     */
    private boolean checkErrorAndSetTotal() {
	try {
	    String noSpaces = value.getText().trim();
	    value.setText(noSpaces);
	    Long l = Long.valueOf(noSpaces);
	    total.setText(nf.format(l.longValue() *
		unitMultipliers[unit.getSelectedIndex()]));
	} catch (NumberFormatException e) {
	  value.requestFocus();
	  value.selectAll();
	  toolkit.beep();
	  return false;
	}

	return true;
    }

    /**
     * Hides the duration helper.
     * @param save true if the user wants to save the current value in
     * the dialog box, false if it is to be discarded. This is decided
     * based on whether the user clicked on the "Ok" button or the
     * "Cancel" button. Choosing the window close menu is equivalent to
     *	clicking on "Cancel."
     */
    private void durationHelperClose(boolean save) {
	if (save == true) {
	    if (!checkErrorAndSetTotal())
		return;
	}
	this.save = save;
	setVisible(false);
    }

    /**
     * Determine whether or not the user wanted to save the value in
     * this Dialog box. The user indicates this by clicking on the Ok
     * button to save it and on the Cancel button to discard it. Using the
     * window close menu responds the same way as cancel.
     * @return true if the user wanted to use this value,
     * false if it is to be discarded.
     */
    public boolean isSaved() {
	return save;
    }

    /**
     * The string representation of the contents of this dialog box.
     * @return a String with the total number of seconds entered.
     */
    public String toString() {
	return total.getText();
    }

    // * **********************************************
    //	 I N N E R    C L A S S E S   F O L L O W
    // * **********************************************

    /**
     * Listener for closing the dialog box through the window close
     * menu.
     */
    private class DHWindowListener extends WindowAdapter {
	public	void windowClosing(WindowEvent e) {
		durationHelperClose(false);
	}
    }

    /**
     * Listener for all the buttons.
     * The listener is shared for the sake
     * of reducing the number of overall listeners.
     */
    private class ButtonListener implements ActionListener {
	public void actionPerformed(ActionEvent e) {
	    if (e.getSource() == ok) {
		DurationHelper.this.durationHelperClose(true);
	    } else if (e.getSource() == cancel) {
		DurationHelper.this.durationHelperClose(false);
	    } else if (e.getSource() == help) {
		if (hd != null)
		    hd.setVisible(true);
		else {
		    hd = new HelpDialog(DurationHelper. this.parent,
			getString("Help for entering time duration"),
				    false, 5, 45);
		    hd.setVisible(true);
		    hd.setText(getString(hrb, "DurationHelperHelp"));
		}
	    } else if (e.getSource() == compute) {
		checkErrorAndSetTotal();
	    }
	}
    }

    /**
     * Call rb.getString(), but catch exception
     * and return English
     * key so that small spelling errors don't cripple the GUI
     *
     */
    private static final String getString(String key) {
	return (getString(rb, key));
    }

    private static final String getString(ResourceBundle rb, String key) {
	try {
	    String res = rb.getString(key);
	    return res;
	} catch (MissingResourceException e) {
		System.out.println("Missing resource "+key+", using English.");
		return key;
	}
    }

    /*
     * A main method to test this class.
     */
    /* BEGIN JSTYLED */
    /*
    public static void main(String args[]) {
	Frame f = new Frame("Test DurationHelper");
	f.setVisible(true); // for help dialog to use this as parent
	DurationHelper dh = new DurationHelper(f, Color.white, Color.black);
	dh.setVisible(true);
	System.out.println("Save is " + dh.save);
    }
	  */
    /* END JSTYLED */
}
