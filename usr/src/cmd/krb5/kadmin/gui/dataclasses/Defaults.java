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
 * Copyright (c) 1999-2000 by Sun Microsystems, Inc.
 * All rights reserved.
 */

import java.awt.*;
import java.awt.event.*;
import java.util.*;
import java.text.*;
import java.io.*;

/**
 * Defaults class stores all defaults that are recorded locally on the
 * client side.  It is also resonsible for showing the DefaultsFrame
 * which allows the user to see and change these values.
 */
public class Defaults {
  
  // These gui components are the actual components that go on the editing frame
  // that  allows the user to change the defaults. The reason they are public is
  // that they  need to be accessible to KdcGui so that it can set up the
  // listeners for them in  setupDefaultsNormalListeners() and
  // setupDefaultsHelpListeners().
    public Checkbox disableAccount;
    public Checkbox forcePasswordChange;
    public Checkbox allowPostdatedTix;
    public Checkbox allowForwardableTix;
    public Checkbox allowRenewableTix;
    public Checkbox allowProxiableTix;
    public Checkbox allowServiceTix;
    public Checkbox allowTGTAuth;
    public Checkbox allowDupAuth;
    public Checkbox requirePreauth;
    public Checkbox requireHWAuth;

    public Checkbox serverSide;
    public TextField maxTicketLife;
    public TextField maxTicketRenewableLife;
    public TextField accountExpiryDate;

    public Label maxTicketLifeLabel;
    public Label maxTicketRenewableLifeLabel;
    public Label accountExpiryDateLabel;

    public Checkbox showLists;
    public Checkbox staticLists;
    public TextField cacheTime;

    public Label cacheTimeLabel;

    public Button lifeMoreButton;
    public Button renewalMoreButton;
    public Button dateMoreButton;
    public Button cacheMoreButton;

    public Button saveButton;
    public Button applyButton;
    public Button cancelButton;

    public MenuItem csHelp;
  
  // These data items correspond to fields in struct struct
  // _kadm5_config_params
    private Flags flags;

    private boolean serverSideValue;
    private int maxTicketLifeValue;
    private int maxTicketRenewableLifeValue;
    private Date accountExpiryDateValue;

    private boolean showListsValue;
    private boolean staticListsValue;
    private long cacheTimeValue;

    private String defaultsFile;
    private Color background;

    private EditingFrame frame = null;

    private boolean helpMode = false;

  // For I18N
    private static DateFormat df; 
    private static NumberFormat nf; 
    private static ResourceBundle rb; 
  // no help data since help is handled by KdcGui class

    private static String neverString;

  // For debugging the window arrangement

    Color SEPERATOR_COLOR = Color.blue;
    Color CHECKBOX_COLOR = Color.orange;
    Color LABEL_COLOR = Color.pink;
    Color PANEL_COLOR1 = Color.lightGray;
    Color PANEL_COLOR2 = Color.darkGray;
  
    /**
     * Constructor for Defaults.
     * @param defaultsFile the file from which to read the defaults.
     */
    Defaults(String defaultsFile, Color background) {
        this.defaultsFile = defaultsFile;
        this.background = background;
        flags = new Flags();
        serverSideValue = true;
        maxTicketLifeValue = 144000;
        maxTicketRenewableLifeValue = 144000;
        // set expiry to now + one year
        Calendar c = Calendar.getInstance();
        c.roll(Calendar.YEAR, true);
        accountExpiryDateValue = c.getTime();
        showListsValue = true;
        staticListsValue = false;
        cacheTimeValue = 300;
        readFromFile();
    }

    /**
     * Constructor for Defaults.
     * @param old an existing defaults object to clone
     */
    Defaults(Defaults old) {
        defaultsFile = old.defaultsFile;
        background = old.background;
        flags = new Flags(old.flags.getBits());
    
        maxTicketLifeValue = old.maxTicketLifeValue;
        maxTicketRenewableLifeValue = old.maxTicketRenewableLifeValue;
        accountExpiryDateValue = old.accountExpiryDateValue;
        showListsValue = old.showListsValue;
        staticListsValue = old.staticListsValue;
        cacheTimeValue = old.cacheTimeValue;
    }

    public void restoreValues(Defaults old) {
        flags = new Flags(old.flags.getBits());
        maxTicketLifeValue = old.maxTicketLifeValue;
        maxTicketRenewableLifeValue = old.maxTicketRenewableLifeValue;
        accountExpiryDateValue = old.accountExpiryDateValue;
        showListsValue = old.showListsValue;
        staticListsValue = old.staticListsValue;
        cacheTimeValue = old.cacheTimeValue;
        updateGuiComponents();
    }

    /**
     * Returns a gui Frame with the defaults on it for editing.
     */
    public Frame getEditingFrame() {
        if (frame == null) {
       	    frame = new EditingFrame();
	    updateGuiComponents();
       	    frame.setSize(500, 680);
	    frame.setResizable(true);
	    frame.setBackground(background);
        }
        return frame;
    }

    /**
     * Reread the defaults file in case it has changed, and refresh view
     */
    public void refreshDefaults() {
        readFromFile();
        updateGuiComponents();
    }


    /**
     * Update the duration and date text fields from gui.
     * Check to see if any one of them had a parse error.
     * @return true if all is ok, false if an error occurs
     */
    // Quits as soon as the first error is detected. The method that
    // detects the error also shows a dialog box with a message.
    public final boolean updateFromGui() {
        return (setMaxTicketLife() && setMaxTicketRenewableLife() 
	      && setAccountExpiryDate()	&& setCacheTime());
    }
  
    boolean setServerSide() {
        serverSideValue = serverSide.getState();
        enableTicketLifeFields(serverSideValue);
        return true;
    }

    private void enableTicketLifeFields(boolean fromServer) {
        maxTicketLifeLabel.setEnabled(!fromServer);
        maxTicketLife.setEnabled(!fromServer);
        maxTicketRenewableLifeLabel.setEnabled(!fromServer);
        maxTicketRenewableLife.setEnabled(!fromServer);
        lifeMoreButton.setEnabled(!fromServer);
        renewalMoreButton.setEnabled(!fromServer);
    }
    
    boolean setMaxTicketLife() {
        try {
            maxTicketLifeValue = 
                nf.parse(maxTicketLife.getText().trim()).intValue();
        } catch (ParseException e) {
            KdcGui.showDataFormatError(maxTicketLife, KdcGui.DURATION_DATA);
            return false;
        }

        return true;
    }

    /**
     * Sets the maxTicketRenewable field value from the corresponding text 
     * field.
     */
    boolean setMaxTicketRenewableLife() {
        try {
            maxTicketRenewableLifeValue = 
                nf.parse(maxTicketRenewableLife.getText().trim()).intValue();
        } catch (ParseException e) {
            KdcGui.showDataFormatError(maxTicketRenewableLife, 
                                       KdcGui.DURATION_DATA);
            return false;
        }

        return true;
    }

    /**
     * Sets the accountExpiryDate field value from the corresponding text field.
     */
    boolean setAccountExpiryDate() {
        String value = accountExpiryDate.getText().trim();
        if (value.equalsIgnoreCase(neverString))
            accountExpiryDateValue = new Date(0);
        else {    
            try {
        	accountExpiryDateValue = df.parse(value);
            } catch (ParseException e) {
        	KdcGui.showDataFormatError(accountExpiryDate, KdcGui.DATE_DATA);
        	return false;
            } catch (NullPointerException e) {
        	// gets thrown when parse string begins with text
        	// probable JDK bug
        	KdcGui.showDataFormatError(accountExpiryDate, KdcGui.DATE_DATA);
        	return false;
            } catch (IndexOutOfBoundsException e) {
        	// gets thrown when parse string contains only one number
        	// probable JDK bug
        	KdcGui.showDataFormatError(accountExpiryDate, KdcGui.DATE_DATA);
        	return false;
            }
        }
        return true;
    }

    /**
     * Sets the cacheTime field value from the corresponding text field.
     */
    boolean setCacheTime() {
        try {
            cacheTimeValue = nf.parse(cacheTime.getText().trim()).intValue();
        } catch (ParseException e) {
            KdcGui.showDataFormatError(cacheTime, KdcGui.DURATION_DATA);
            return false;
        }
        return true;
    }

    boolean setShowLists() {
        showListsValue = showLists.getState();
        return true;
    }

    boolean setStaticLists() {
        staticListsValue = staticLists.getState();
        enableCacheTimeFields(staticListsValue);
        return true;
    }

    private void enableCacheTimeFields(boolean staticLists) {
        cacheTime.setEnabled(!staticLists);
        cacheTimeLabel.setEnabled(!staticLists);
        cacheMoreButton.setEnabled(!staticLists);
    }

    public boolean getServerSide() {
        return serverSideValue;
    }

    public Integer getMaxTicketLife() {
        return new Integer(maxTicketLifeValue);
    }

    public Integer getMaxTicketRenewableLife() {
        return new Integer(maxTicketRenewableLifeValue);
    }

    public Date getAccountExpiryDate() {
        return new Date(accountExpiryDateValue.getTime());
    }

    public boolean getShowLists() {
        return showListsValue;
    }

    public boolean getStaticLists() {
        return staticListsValue;
    }

    public boolean getCacheLists() {
        return staticListsValue;
    }

    public long getCacheTime() {
        return cacheTimeValue;
    }

    public Flags getFlags() {
        return flags;
    }
   
    /**
     * Toggles the value of the  bit specified.
     */
    public void toggleFlag(int bitmask) {
        flags.toggleFlags(bitmask);
    }

    public void close(boolean save) {
        if (frame != null)
            frame.close(save);
    }
      
  
    /**
     * Saves the fields onto a file.
     */    
    private void saveToFile() {
        try {
            PrintWriter outFile = null;
            outFile = new PrintWriter(
                      new BufferedWriter(new FileWriter(defaultsFile)));
            outFile.println(flags.getBits());
            outFile.println(maxTicketRenewableLifeValue);
            outFile.println(df.format(accountExpiryDateValue));
            outFile.println((new Boolean(showListsValue)).toString());
            outFile.println((new Boolean(staticListsValue)).toString());
            outFile.println((new Long(cacheTimeValue)).toString());
            outFile.println(serverSideValue);
            outFile.println(maxTicketLifeValue);
            outFile.flush();
            outFile.close();
        } catch (IOException e) { /* xxx: warn user */ }
    }

    /**
     * Reads the fields from a file.
     */
    private void readFromFile() {
        try {
            BufferedReader inFile = null;
            inFile = new BufferedReader(new FileReader(defaultsFile));
            flags = new Flags(new Integer(inFile.readLine()).intValue());
            maxTicketRenewableLifeValue = 
                new Integer(inFile.readLine()).intValue();
            accountExpiryDateValue = df.parse(inFile.readLine());
            String s;
            s = inFile.readLine();
            if (s == null)
        	showListsValue = true;
            else
        	showListsValue = (new Boolean(s)).booleanValue();
            s = inFile.readLine();
            if (s == null)
        	staticListsValue = false;
            else
        	staticListsValue = (new Boolean(s)).booleanValue();
            s = inFile.readLine();
            if (s == null)
        	cacheTimeValue = 300;
            else try {
        	cacheTimeValue = nf.parse(s).longValue();
            } catch (ParseException e) {
        	cacheTimeValue = 300;
            }
            serverSideValue = new Boolean(inFile.readLine()).booleanValue();
            maxTicketLifeValue = new Integer(inFile.readLine()).intValue();
        } catch (FileNotFoundException e) { 
            /* default values. new file will be created automatically. */}
        catch (IOException e) { /* will create new one */}
        catch (ParseException e) { /* leave default values in */}
        catch (NumberFormatException e) { /* leave default values in */}
        catch (NullPointerException e) { /* leave default values in */}
        catch (StringIndexOutOfBoundsException e) { 
            /* leave default values in */}
    }

    /**
     * Sets the value of the gui components from the instance variables
     * that get filled from the defaultsFile.
     */
    public void updateGuiComponents() {
        if (frame == null) 
            getEditingFrame();
        else {
            updateFlags();
            serverSide.setState(serverSideValue);
            enableTicketLifeFields(serverSideValue);
            maxTicketLife.setText(nf.format(maxTicketLifeValue));
            maxTicketRenewableLife.setText(
                nf.format(maxTicketRenewableLifeValue));
            String text = (accountExpiryDateValue.getTime() == 0 ? neverString
		     : df.format(accountExpiryDateValue));
            accountExpiryDate.setText(text);
            showLists.setState(showListsValue);
            staticLists.setState(staticListsValue);
            enableCacheTimeFields(staticListsValue);
            cacheTime.setText((new Long(cacheTimeValue)).toString());
        }
    }

    private void updateFlags() {
        disableAccount.setState(flags.getFlag(Flags.DISALLOW_ALL_TIX));
        forcePasswordChange.setState(flags.getFlag(Flags.REQUIRES_PWCHANGE));
        allowPostdatedTix.setState(!flags.getFlag(Flags.DISALLOW_POSTDATED));
        allowForwardableTix.setState(!flags.getFlag(
            Flags.DISALLOW_FORWARDABLE));
        allowRenewableTix.setState(!flags.getFlag(Flags.DISALLOW_RENEWABLE));
        allowProxiableTix.setState(!flags.getFlag(Flags.DISALLOW_PROXIABLE));
        allowServiceTix.setState(!flags.getFlag(Flags.DISALLOW_SVR));
        allowTGTAuth.setState(!flags.getFlag(Flags.DISALLOW_TGT_BASED));
        allowDupAuth.setState(!flags.getFlag(Flags.DISALLOW_DUP_SKEY));
        requirePreauth.setState(flags.getFlag(Flags.REQUIRE_PRE_AUTH));
        requireHWAuth.setState(flags.getFlag(Flags.REQUIRE_HW_AUTH)); 
    }

    /**
     * Call rb.getString(), but catch exception and return English
     * key so that small spelling errors don't cripple the GUI
     *
     */
    private static final String getString(String key) {
        try {
            String res = rb.getString(key);
	    return res;
        } catch (MissingResourceException e) {
	    System.out.println("Missing resource "+key+", using English.");
	    return key;
        }
    }

    /*
     **********************************************
     *         I N N E R   C L A S S E S
     **********************************************
     */

    private class EditingFrame extends Frame {
        public EditingFrame() {
            super(getString("Properties"));
            setLayout(new GridBagLayout());
            GridBagConstraints gbc = new GridBagConstraints();
            gbc.weightx = gbc.weighty = 1;
            gbc.fill = GridBagConstraints.BOTH;
            gbc.gridwidth = GridBagConstraints.REMAINDER;
            Label l;
            l = new Label(getString("Defaults for New Principals"), 
                                    Label.CENTER);
            l.setFont(new Font("Dialog", Font.PLAIN, 16));
            //            l.setBackground(LABEL_COLOR);
            gbc.insets = new Insets(10, 10, 0, 10);
            add(l, gbc);
            addFlags();
            gbc.insets = new Insets(10, 10, 10, 10);
            add(new LineSeparator(), gbc);
            addTextFields(); 
            add(new LineSeparator(), gbc);
          
            gbc.insets = new Insets(0, 10, 10, 10);
            l = new Label(getString("List Controls"), Label.CENTER);
            l.setFont(new Font("Dialog", Font.PLAIN, 16));
      
            add(l, gbc);
            gbc.insets = new Insets(0, 10, 10, 10); 
            add(new LineSeparator(), gbc);
            addListFields();
            addButtons();
            addWindowListener(new WindowCloseListener());
            addHelpMenu();
        }

        /**
         * Helper method for constructor to add checkboxes and labels for
         * flags.
         */
        private void addFlags() {
            Panel p = new Panel();
            GridBagConstraints gbc = new GridBagConstraints();
            gbc.weightx = gbc.weighty = 1;
            gbc.fill = GridBagConstraints.BOTH;
            gbc.gridwidth = GridBagConstraints.REMAINDER;
            gbc.insets = new Insets(0, 10, 0, 10);
            p.setLayout(new GridBagLayout());
            add(p, gbc);

            disableAccount = new Checkbox();
            forcePasswordChange = new Checkbox();
            allowPostdatedTix = new Checkbox();
            allowForwardableTix = new Checkbox();
            allowRenewableTix = new Checkbox();
            allowProxiableTix = new Checkbox();
            allowServiceTix = new Checkbox();
            allowTGTAuth = new Checkbox();
            allowDupAuth = new Checkbox();
            requirePreauth = new Checkbox();
            requireHWAuth = new Checkbox();

            addSeperatorPanel(getString("Security"), p);

            gbc = new GridBagConstraints();
            gbc.anchor  = GridBagConstraints.WEST;

            addFlag(disableAccount,
    		    Flags.DISALLOW_ALL_TIX, p, gbc, false);
            addFlag(forcePasswordChange,
		    Flags.REQUIRES_PWCHANGE,  p, gbc, true); 

            addSeperatorPanel(getString("Ticket"), p);
            addFlag(allowPostdatedTix,
		    Flags.DISALLOW_POSTDATED,  p, gbc, false);
            addFlag(allowForwardableTix,
		    Flags.DISALLOW_FORWARDABLE,  p, gbc, true);
            addFlag(allowRenewableTix,
		    Flags.DISALLOW_RENEWABLE,  p, gbc, false);
            addFlag(allowProxiableTix,
		    Flags.DISALLOW_PROXIABLE,  p, gbc, true);
            addFlag(allowServiceTix,
      		    Flags.DISALLOW_SVR,  p, gbc, true);

            addSeperatorPanel(getString("Miscellaneous"), p);
            addFlag(allowTGTAuth,
		    Flags.DISALLOW_TGT_BASED,  p, gbc, false);
            addFlag(allowDupAuth,
		    Flags.DISALLOW_DUP_SKEY,  p, gbc, true);
            addFlag(requirePreauth,
		    Flags.REQUIRE_PRE_AUTH,  p, gbc, false);
            addFlag(requireHWAuth,
		    Flags.REQUIRE_HW_AUTH,  p, gbc, true);
        }

    /**
     * Helper method for addFlags. It adds a line seperator with text
     * inside it.
     * @param text the text to put in the line seperator
     * @p the panel to which this line seperator must be added
     */
    private void addSeperatorPanel(String text, Panel p) {
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.weightx = gbc.weighty = 1;
        gbc.fill = GridBagConstraints.BOTH;
        gbc.gridwidth = GridBagConstraints.REMAINDER;
        gbc.insets = new Insets(7, 0, 7, 0);
      
        Panel subP = new Panel();
        //            subP.setBackground(SEPERATOR_COLOR);
        subP.setLayout(new GridBagLayout());
        p.add(subP, gbc);

        gbc = new GridBagConstraints();
        gbc.fill = GridBagConstraints.BOTH;
        gbc.weightx = gbc.weighty = .02;
        subP.add(new LineSeparator(), gbc);

        gbc.weightx = gbc.weighty = .001;
        gbc.fill = GridBagConstraints.NONE;
        gbc.anchor = GridBagConstraints.EAST;
        Label l = new Label(text);
        l.setFont(new Font("Dialog", Font.ITALIC, 12));
        subP.add(l, gbc);

        gbc.gridwidth = GridBagConstraints.REMAINDER;
        gbc.weightx = gbc.weighty = 1;
        gbc.fill = GridBagConstraints.BOTH;
        gbc.anchor = GridBagConstraints.WEST;
        subP.add(new LineSeparator(), gbc);
    }

    /**
     * Helper method for addFlags. It adds the label and the checkbox
     * corresponding to the flag specified by the single bit that is set
     * in mask.
     * @param cb the Checkbox which has to be added corresponding to
     *     this flag
     * @param mask the flag
     * @param p the panel to add this to
     */
    private void addFlag(Checkbox cb, int mask, Panel p, 
			    GridBagConstraints gbc, boolean eol) {
      //      cb.setBackground(CHECKBOX_COLOR);
        cb.setState(flags.getFlag(mask));
        cb.setLabel(Flags.getLabel(mask));
        if (eol)
            gbc.gridwidth = GridBagConstraints.REMAINDER;
        else
            gbc.gridwidth = 1;
        p.add(cb, gbc);
    }

    /**
     * Helper method for constructor - adds Max ticket time, max renewal and def
     * account expiry.
     */
    private void addTextFields() {
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.weightx = gbc.weighty = 1;

        Panel p = new Panel();
        //      p.setBackground(PANEL_COLOR1);
        p.setLayout(new GridBagLayout());
        gbc.fill = GridBagConstraints.VERTICAL;
        gbc.gridwidth = GridBagConstraints.REMAINDER;
        gbc.anchor = GridBagConstraints.WEST;
        gbc.insets = new Insets(0, 10, 0, 10);
        add(p, gbc);

        gbc = new GridBagConstraints();
        gbc.weightx = gbc.weighty = 1;

        gbc.anchor = GridBagConstraints.EAST;
        gbc.weightx = 0;
        gbc.gridx = 0;
        gbc.gridy = 0;
        accountExpiryDateLabel = new Label(getString("Account Expiry:"));
        //      accountExpiryDateLabel.setBackground(LABEL_COLOR);
        p.add(accountExpiryDateLabel, gbc);
        gbc.gridy = 2;
        maxTicketLifeLabel =
		new Label(getString("Maximum Ticket Lifetime (seconds):"));
        //      maxTicketLifeLabel.setBackground(LABEL_COLOR);
        p.add(maxTicketLifeLabel, gbc);
        gbc.gridy = 3;
        maxTicketRenewableLifeLabel =
		new Label(getString("Maximum Ticket Renewal (seconds):"));
        //      maxTicketRenewableLifeLabel.setBackground(LABEL_COLOR);
        p.add(maxTicketRenewableLifeLabel, gbc);

        gbc.gridx = 1;
        gbc.gridy = 0;
        gbc.fill = GridBagConstraints.NONE;
        gbc.anchor = GridBagConstraints.WEST;
        accountExpiryDate = new TextField("1-Jan-70 00:00:00 PM");
        accountExpiryDate.setColumns(22);
        p.add(accountExpiryDate, gbc);
        gbc.gridy = 2;
        maxTicketLife = new TextField("144000");
        maxTicketLife.setColumns(22);
        p.add(maxTicketLife, gbc);
        gbc.gridy = 3;
        maxTicketRenewableLife = new TextField("144000");
        maxTicketRenewableLife.setColumns(22);
        p.add(maxTicketRenewableLife, gbc);

        gbc = new GridBagConstraints();
        gbc.weightx = gbc.weighty = 0;
        gbc.gridwidth = GridBagConstraints.REMAINDER;
        gbc.anchor = GridBagConstraints.WEST;
        gbc.gridx = 2;
        gbc.gridy = 0;
        dateMoreButton = new Button("...");
        p.add(dateMoreButton, gbc);
        gbc.gridy = 2;
        lifeMoreButton = new Button("...");
        p.add(lifeMoreButton, gbc);
        gbc.gridy = 3;
        renewalMoreButton = new Button("...");
        p.add(renewalMoreButton, gbc);

        serverSide = new Checkbox();
        //      serverSide.setBackground(CHECKBOX_COLOR);
        serverSide.setLabel(getString(
            "Let the KDC control the ticket lifetime values"));

        gbc = new GridBagConstraints();
        gbc.anchor = GridBagConstraints.WEST;
        gbc.gridwidth = GridBagConstraints.REMAINDER;
        gbc.gridx = 0;
        gbc.gridy = 1;
        p.add(serverSide, gbc);

    }

    private void addListFields() {
        Panel p = new Panel();
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.weightx = gbc.weighty = 1;
        gbc.fill = GridBagConstraints.VERTICAL;
        gbc.anchor = GridBagConstraints.WEST;
        gbc.gridwidth = GridBagConstraints.REMAINDER;
        //      p.setBackground(PANEL_COLOR1);
        gbc.insets = new Insets(0, 10, 0, 10);
        p.setLayout(new GridBagLayout());
        add(p, gbc);

        gbc = new GridBagConstraints();
        gbc.anchor = GridBagConstraints.WEST;
        gbc.gridwidth = GridBagConstraints.REMAINDER;
        showLists = new Checkbox();
        //      showLists.setBackground(CHECKBOX_COLOR);
        showLists.setLabel(getString("Show Lists"));
        p.add(showLists, gbc);

        gbc.gridwidth = 1;
        gbc.anchor = GridBagConstraints.EAST;
        staticLists = new Checkbox();
        //      staticLists.setBackground(CHECKBOX_COLOR);
        staticLists.setLabel(getString("Cache Lists Forever"));
        p.add(staticLists, gbc);

        gbc.anchor = GridBagConstraints.EAST;
        cacheTimeLabel = new Label(getString("List Cache Timeout (seconds):"));
        //      cacheTimeLabel.setBackground(Color.green);
        p.add(cacheTimeLabel, gbc);

        gbc.anchor = GridBagConstraints.WEST;
        cacheTime = new TextField("300", 8);
        //      cacheTime.setBackground(Color.cyan);
        p.add(cacheTime, gbc);

        gbc.gridwidth = GridBagConstraints.REMAINDER;
        gbc.weightx = gbc.weighty = 0;
        cacheMoreButton = new Button("...");
        p.add(cacheMoreButton, gbc);
    }


    /**
     * Helper method for constructor - adds Save and Cancel
     * buttons.
     */
    private void addButtons() {
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.weightx = gbc.weighty = 1;

        Panel p = new Panel();
        p.setLayout(new GridBagLayout());
        gbc.fill = GridBagConstraints.BOTH;
        gbc.gridwidth = GridBagConstraints.REMAINDER;
        gbc.insets = new Insets(10, 10, 10, 10);
        add(new LineSeparator(), gbc);
        gbc.insets = new Insets(0, 0, 10, 0);
        add(p, gbc);

        gbc = new GridBagConstraints();
        gbc.weightx = gbc.weighty = 1;

        saveButton = new Button(getString("Save"));
        p.add(saveButton, gbc);
        applyButton = new Button(getString("Apply"));
        p.add(applyButton, gbc);
        cancelButton = new Button(getString("Cancel"));
        p.add(cancelButton, gbc);
    }

    private void addHelpMenu() {
        MenuBar mb = new MenuBar();
        setMenuBar(mb);

        Menu m = new Menu(getString("Help"));
        mb.setHelpMenu(m);
  
        csHelp = new MenuItem(getString("Context-Sensitive Help"));
        m.add(csHelp);
    }

        /**
         * Decides whether to save/discard edits and then closes
         * window. If errors exist in the values entered in the fields, then
         * it will not exit.
         */
        public void close(boolean save) {
            if (save) {
      	        if (!Defaults.this.updateFromGui())
	            return;
    	        else
	            Defaults.this.saveToFile();
            }
            setVisible(false);
        }

        // Listeners for the gui components:
        private  class WindowCloseListener extends  WindowAdapter {
            public void windowClosing(WindowEvent e) {
    	        close(false);
            }
        }   
    
    } // class EditingFrame

    public static void main(String argv[]) {
        Defaults d = new Defaults("SomeFile", Color.white);
        Frame f = d.getEditingFrame();
        d.showLists.setSize(new Dimension(18, 22));
        d.staticLists.setSize(new Dimension(18, 22));
        f.setVisible(true);
        System.out.println(d.disableAccount.getSize().toString()); // XXX
        System.out.println(d.showLists.getSize().toString()); // XXX
    }

    static {
        df = DateFormat.getDateTimeInstance(DateFormat.MEDIUM, 
                                            DateFormat.MEDIUM);
        nf = NumberFormat.getInstance();
        rb = ResourceBundle.getBundle("GuiResource" /* NOI18N */); 
        neverString = getString("Never");
    }
  
}
