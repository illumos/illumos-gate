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
import java.text.*;
import java.util.*;

/**
 * This class creates a dialog box that helps the user enter date and
 * time with mouse clicks.  The dialog box need only be created
 * once. The Ok and Cancel buttons merely call setVisible with an
 *  argument of false.
 */

// The layout will consist of 3 panels: topPanel contains the
// different labels and fields. middlePanel contains the buttons
// midnight and now. bottomPanel contains the buttons ok, cancel and
// help. The last two panels are separated by a LineSeparator.

public class DateTimeDialog extends Dialog {

    private boolean save;

    private Frame parent;

    private DCPanel dateDCPanel;
    private DCPanel yearDCPanel;
    private DCPanel hourDCPanel;
    private DCPanel minuteDCPanel;
    private DCPanel secondDCPanel;

    private Choice month;

    private DCCircularTextField date;
    private DCCircularTextField hour;
    private DCCircularTextField second;
    private DCCircularTextField minute;
    private DCTextField year;

    private Button ok;
    private Button cancel;
    private Button help;
    private Button now;
    private Button midnight;

    private HelpDialog hd = null;

    private Panel topPanel;
    private Panel middlePanel;
    private Panel bottomPanel;

    private GregorianCalendar calendar = null;
    private static int MONTH_LEN[] = {31, 28, 31, 30, 31, 30, 31,
				    31, 30, 31, 30, 31};
    private static DateFormat df =
    DateFormat.getDateTimeInstance(DateFormat.MEDIUM,
				 DateFormat.MEDIUM);
    private static Toolkit toolkit = Toolkit.getDefaultToolkit();

  // For I18N
    private static ResourceBundle rb =
    ResourceBundle.getBundle("GuiResource" /* NOI18N */);
    private static ResourceBundle hrb =
    ResourceBundle.getBundle("HelpData" /* NOI18N */);

    /**
     * Constructor that lays out the componeents and sets the different
     * event handlers.
     */
    public DateTimeDialog(Frame parent, Color background, Color foreground) {
    super(parent, getString("SEAM Date/Time Helper"), true);

    this.parent = parent;

    setLayout(new GridBagLayout());
    addLabels();
    addFields(background, foreground);
    addDCPanels();
    addButtons();
    addFocusListeners();
    setCurrentTime();
    setSize(250, 300);
    setResizable(false);

    addWindowListener(new DCWindowListener());
    //	    initializeFocusOnTextField();
    }

    /**
     * Adds the labels only
     */
    private void addLabels() {

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
    gbc.anchor = GridBagConstraints.EAST;
    gbc.gridx = 0;
    gbc.gridwidth = 1;

    gbc.gridy = 0;
    topPanel.add(new Label(getString("Month")), gbc);

    gbc.gridy = 1;
    topPanel.add(new Label(getString("Date")), gbc);

    gbc.gridy = 2;
    topPanel.add(new Label(getString("Year")), gbc);

    gbc.gridy = 3;
    topPanel.add(new Label(getString("Hour")), gbc);

    gbc.gridy = 4;
    topPanel.add(new Label(getString("Minute")), gbc);

    gbc.gridy = 5;
    topPanel.add(new Label(getString("Second")), gbc);
    }

    /**
     * Adds the fields that will store the month, year, date, hour,
     * minute and second.
     */
    private void addFields(Color background, Color foreground) {

    GridBagConstraints gbc = new GridBagConstraints();
    gbc.weighty = 1;

    month = new Choice();
    initializeMonth();

    date = new DCCircularTextField("1", 2);
    date.setMinimum(1);
    date.setBackground(background);
    date.setForeground(foreground);

    hour = new DCCircularTextField("00", 2);
    hour.setMaximum(23);
    hour.setBackground(background);
    hour.setForeground(foreground);
    minute = new DCCircularTextField("00", 2);
    minute.setBackground(background);
    minute.setForeground(foreground);
    second = new DCCircularTextField("00", 2);
    second.setBackground(background);
    second.setForeground(foreground);

    year  = new DCTextField("2000", 4);
    year.setBackground(background);
    year.setForeground(foreground);

    Panel tempPanel = new Panel();
    tempPanel.add(month);
    gbc.gridwidth = GridBagConstraints.REMAINDER;
    gbc.fill = GridBagConstraints.HORIZONTAL;
    gbc.anchor = GridBagConstraints.WEST;
    gbc.gridx = 1;
    gbc.gridy = 0;
    topPanel.add(tempPanel, gbc);


    // Remaining fields are in topPanel
    gbc.gridwidth = 1;
    gbc.fill = GridBagConstraints.NONE;
    gbc.gridx = 1;

    gbc.gridy = 1;
    topPanel.add(date, gbc);

    gbc.gridy = 2;
    topPanel.add(year, gbc);

    gbc.gridy = 3;
    topPanel.add(hour, gbc);

    gbc.gridy = 4;
    topPanel.add(minute, gbc);

    gbc.gridy = 5;
    topPanel.add(second, gbc);

    }

  // Adds the panels with the +/- buttons for each DCField
    private void addDCPanels() {

    GridBagConstraints gbc = new GridBagConstraints();
    gbc.weighty = 1;

    gbc.gridx = 2;
    gbc.gridwidth = GridBagConstraints.REMAINDER;
    gbc.gridheight = 1;
    gbc.fill = GridBagConstraints.NONE;

    dateDCPanel = new DCPanel();
    yearDCPanel = new DCPanel();
    hourDCPanel = new DCPanel();
    minuteDCPanel = new DCPanel();
    secondDCPanel = new DCPanel();

    gbc.gridy = 1;
    topPanel.add(dateDCPanel, gbc);

    gbc.gridy = GridBagConstraints.RELATIVE;
    topPanel.add(yearDCPanel, gbc);
    topPanel.add(hourDCPanel, gbc);
    topPanel.add(minuteDCPanel, gbc);
    topPanel.add(secondDCPanel, gbc);

    dateDCPanel.setListener(date);
    yearDCPanel.setListener(year);
    hourDCPanel.setListener(hour);
    minuteDCPanel.setListener(minute);
    secondDCPanel.setListener(second);

    }


    /**
     * Sets the strings in the month pull-down menu. Also adds a listener
     * that will modify the maximum date allowed depending on the month.
     */
    private void initializeMonth() {
    DateFormatSymbols dfSymbols = new DateFormatSymbols();
    String[] monthStrings = dfSymbols.getMonths();

	month.removeAll();

	for (int i = 0; i < monthStrings.length; i++) {
	month.add(monthStrings[i]);
	}

	month.addItemListener(new DCMonthChangeListener());
    }

  // Adds all the buttons
    private void addButtons() {

	GridBagConstraints gbc = new GridBagConstraints();
	gbc.weighty = 1;


	middlePanel = new Panel();
	now  = new Button(getString("Now"));
	midnight	= new Button(getString("Midnight"));
	middlePanel.add(midnight);
	middlePanel.add(now);
	gbc.fill = GridBagConstraints.HORIZONTAL;
	gbc.gridwidth = GridBagConstraints.REMAINDER;
	gbc.gridx = 0;
	gbc.gridy = 1;
	add(middlePanel, gbc);

	gbc.gridwidth = GridBagConstraints.REMAINDER;
	gbc.gridheight = 1;
	gbc.fill = GridBagConstraints.BOTH;
	gbc.gridx = 0;
	gbc.gridy = 2;
	add(new LineSeparator(), gbc);

	bottomPanel = new Panel();
	ok = new Button(getString("OK"));
	cancel =	new Button(getString("Cancel"));
	help = new Button(getString("Help"));
	bottomPanel.add(ok);
	bottomPanel.add(cancel);
	bottomPanel.add(help);
	gbc.fill = GridBagConstraints.HORIZONTAL;
	gbc.gridwidth = GridBagConstraints.REMAINDER;
	gbc.gridx = 0;
	gbc.gridy = 3;
	add(bottomPanel, gbc);

	DCButtonListener bl = new DCButtonListener();
	ok.addActionListener(bl);
	cancel.addActionListener(bl);
	help.addActionListener(bl);
	now.addActionListener(bl);
	midnight.addActionListener(bl);

    }

    /**
     * Adds a listener to all the text fields so that when they go out
     * of focus (by tab or clicking), their values are checked for
     * errors.
     */
    private void addFocusListeners() {
    FocusListener fl = new DCFocusListener();
    date.addFocusListener(fl);
    year.addFocusListener(fl);
    hour.addFocusListener(fl);
    minute.addFocusListener(fl);
    second.addFocusListener(fl);
    }

    /**
     * Closes (hides) the dialog box when the user is done
     * @param save true if the box is being dismissed by clicking on
     * "ok" and the user wants to retain the modified value, false
     * otherwise.
     */
    private void dateTimeDialogClose(boolean save) {
	if (save == true) {
	if (!updateFromGui())
	   return;
    }
    this.save = save;
    setVisible(false);
    }

    /**
     * Checks to see is all text fields contain valid values.
     * @return true if all are valid, false otherwise.
     */
    private boolean updateFromGui() {
	return (checkErrorAndSet(date) && checkErrorAndSet(year) &&
		checkErrorAndSet(hour) && checkErrorAndSet(minute) &&
		checkErrorAndSet(second));
    }

    /**
     * Checks the value stored as text in the field and sets its numeric
     * value to that if it is legitimate.
     * @return true if the value was legitimate and got set, false
     * otherwise.
     */
    private boolean checkErrorAndSet(DCTextField tf) {
	int i = 0;
	boolean errorState = false;
	try {
	i = new Integer(tf.getText().trim()).intValue();
	errorState = !tf.checkValue(i);
	} catch (NumberFormatException e2) {
	errorState =  true;
	}
	if (errorState) {
	tf.selectAll();
	toolkit.beep();
	}
	else
	tf.setValue(i);
	return !errorState;
    }

    /**
     * Checks if the user requested that the value in this
     * DateTimeDialog be used e.g., by clicking on "Ok" instead of
     * "Cancel."
     * @return true if the user wants to save the value in the
     * DateTimeDialog, false otherwise.
     */

    public boolean isSaved() {
	return save;
    }

    /**
     * Sets the date and time in fields to the current date and time.
     */
    public void setCurrentTime() {
	setDate(new Date());
    }

    /**
     * Sets the current date of the DateTimeDialog and updates the gui
     *	 components to reflect that.
     * @param date the Date to set it to.
     */
    public void setDate(Date newDate) {
	calendar = new GregorianCalendar();
	calendar.setTime(newDate);

    // update gui components now

    year.setValue(calendar.get(Calendar.YEAR));
    month.select(calendar.get(Calendar.MONTH));
    date.setValue(calendar.get(Calendar.DATE));

    // Make sure the date is in the valid range for the given month
    fixDateField();

    hour.setValue(calendar.get(Calendar.HOUR_OF_DAY));
    minute.setValue(calendar.get(Calendar.MINUTE));
    second.setValue(calendar.get(Calendar.SECOND));

    }

    /**
     * Set the time fields to midnight, i.e., clears them.
     */
    private void setMidnight() {
	    hour.setValue(0);
	    minute.setValue(0);
	    second.setValue(0);
    }

    /**
     * Make sure the date does not exceed the maximum allowable value
     * for the currently selected month.
     */
    private void fixDateField() {
	int monthIndex = month.getSelectedIndex();
	int max = MONTH_LEN[monthIndex];
	date.setMaximum(calendar.isLeapYear(year.getValue()) &&
		monthIndex == 1 ? max + 1 : max);
    }

  // * **********************************************
  //	 I N N E R    C L A S S E S   F O L L O W
  // ***********************************************

    /**
     * Listener for closing the dialog box through the window close
     * menu.
     */
    private class DCWindowListener extends WindowAdapter {
    public  void windowClosing(WindowEvent e) {
	dateTimeDialogClose(false);
	}
    }

    /**
     * Listener for any change in the month selected through the
     * pull down menu
     */
    private class DCMonthChangeListener implements ItemListener {
    public void itemStateChanged(ItemEvent e) {
	fixDateField();
    }
    }

    /**
     * Listener for all the buttons. The listener is shared for the sake
     * of reducing the number of overall listeners.
     * TBD: I18N the help
     */
    private class DCButtonListener implements ActionListener {
    public void actionPerformed(ActionEvent e) {
	if (e.getSource() == ok) {
	DateTimeDialog.this.dateTimeDialogClose(true);
	}
	else
	if (e.getSource() == cancel) {
	  DateTimeDialog.this.dateTimeDialogClose(false);
	}
	else
	  if (e.getSource() == now) {
	    DateTimeDialog.this.setCurrentTime();
	  }
	  else
	    if (e.getSource() == midnight) {
		DateTimeDialog.this.setMidnight();
	    }
	    else
		if (e.getSource() == help) {
		    if (hd != null)
			hd.setVisible(true);
		else {
		    hd = new
		    HelpDialog(DateTimeDialog.this.parent,
			getString("Help for Date and Time Dialog"), false);
		    hd.setVisible(true);
		    hd.setText(getString(hrb, "DateTimeDialogHelp"));
		}
	    }
	} // actionPerformed
    }

    /**
     * Listener for any change in focus with respect to the text
     * fields. When a text field is going out of focus, it detemines if the
     * text value in it is valid. If not, it returns focus to that text
     * field.
     */
    private class DCFocusListener extends FocusAdapter {

	public void focusLost(FocusEvent e) {
	if (!checkErrorAndSet((DCTextField)e.getSource()))
	  ((DCTextField)e.getSource()).requestFocus();
	}
    }

    /**
     * The string representation of the dialog box.
     * @return a String which contians the date and time in locale
     * default format, but to MEDIUM length formatting style.
     */
    public String toString() {
	calendar = new GregorianCalendar(year.getValue(),
					month.getSelectedIndex(),
					date.getValue(),
					hour.getValue(),
					minute.getValue(),
					second.getValue());
	return df.format(calendar.getTime());
    }

    /**
     * Call rb.getString(), but catch exception and return English
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

    /* BEGIN JSTYLED */
    /*
    public static final void main(String args[]) {
    Frame f = new Frame();
    //	while (true){
	DateTimeDialog d = new DateTimeDialog(f, Color.white, Color.black);
	d.setVisible(true);
	System.out.println(d.toString());
      //    }
    }
    */
    /* END JSTYLED */
}
