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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * pmLogin.java
 * Login dialog
 */

package com.sun.admin.pm.client;

import java.awt.*;
import java.awt.event.*;
import javax.swing.JPanel;
import javax.swing.*;
import com.sun.admin.pm.server.*;



/*
 * a panel dialog which captures a username and password.
 */

public class pmLogin extends pmDialog {
    private pmTop theTop = null;
    private String theTag = null;
    private JFrame theFrame = null;

    protected pmButton okButton = null;
    protected pmButton cancelButton = null;
    protected pmButton helpButton = null;

    public pmLogin(JFrame f, String title, String msg) {
        this(f, title, msg, null, null);
    }

    public pmLogin(JFrame f, String title, String msg, pmTop t, String h) {

        super(f, title, true);	// modal

        theTop = t;
        theTag = h;
	theFrame = f;

        JLabel l;
        JPanel p;

        // initialize constraints
        GridBagConstraints c = new GridBagConstraints();
        c.gridx = 0;
        c.gridy = GridBagConstraints.RELATIVE;
        c.gridwidth = 1;
        c.gridheight = 1;
        c.insets = new Insets(10, 10, 10, 10);
        c.anchor = GridBagConstraints.EAST;

        // top panel contains the desired message
        p = new JPanel();
        p.setLayout(new GridBagLayout());

        l = new JLabel(msg, SwingConstants.CENTER);
        p.add(l, c);
        this.getContentPane().add(p, "North");

	// NIS middle panel
	// contains username and password
	if (t.ns.getNameService().equals("nis")) {

        p = new JPanel();
        p.setLayout(new GridBagLayout());

        l = new JLabel(pmUtility.getResource("Hostname:"),
                        SwingConstants.RIGHT);
        p.add(l, c);

        l = new JLabel(pmUtility.getResource("Username:"),
                        SwingConstants.RIGHT);
        p.add(l, c);

        l = new JLabel(pmUtility.getResource("Password:"),
                        SwingConstants.RIGHT);
        p.add(l, c);

        passwordField = new JPasswordField(12);
        passwordField.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                okPressed();
            }
        });
        l.setLabelFor(passwordField);
        // for consistency, don't implement this until all are...
        // l.setDisplayedMnemonic(
	// 	pmUtility.getIntResource("Password.mnemonic"));

        c.gridx = 1;
        c.weightx = 1.0;

        String nisMaster;
        try {
            nisMaster = theTop.host.getNisMaster();
        } catch (Exception e) {
            nisMaster = new String("Unknown");
            Debug.warning("pmLogin: getNisMaster() returns exception: " + e);
        }

        c.anchor = GridBagConstraints.WEST;

        l = new JLabel(nisMaster, SwingConstants.LEFT);
        p.add(l, c);

        l = new JLabel(("root"), SwingConstants.LEFT);
        p.add(l, c);


        c.fill = GridBagConstraints.HORIZONTAL;
        c.anchor = GridBagConstraints.CENTER;
        c.gridy = GridBagConstraints.RELATIVE;

        p.add(passwordField, c);
        passwordField.setEchoChar('*');

        this.getContentPane().add(p, "Center");

	} else if (t.ns.getNameService().equals("ldap")) {

            // middle panel contains LDAP server name, distinguished name,
            // and password
            p = new JPanel();
            p.setLayout(new GridBagLayout());

            // LDAP Server Name
            l = new JLabel(pmUtility.getResource("LDAP.Server:"),
                        SwingConstants.RIGHT);
            p.add(l, c);

            serverField = new pmTextField(25);
            serverField.addActionListener(new ActionListener() {
                public void actionPerformed(ActionEvent e) {
                    okPressed();
                }
            });

            String ldapMaster;
            try {
                ldapMaster = theTop.host.getLDAPMaster();
            } catch (Exception e) {
                ldapMaster = new String("");
                Debug.warning(
		    "pmLdap: getLDAPMaster() returns exception: " + e);
            }

            serverField.setText(ldapMaster);
            c.gridx = 1;
            p.add(serverField, c);


            // Distinguished Name
            c.gridx = 0;
            l = new JLabel(pmUtility.getResource("Distinguished.Name:"),
                            SwingConstants.RIGHT);
            p.add(l, c);

            dnField = new pmTextField(25);
            dnField.addActionListener(new ActionListener() {
                public void actionPerformed(ActionEvent e) {
                    okPressed();
                }
            });

            String defaultDN;
            try {
                defaultDN = theTop.host.getDefaultAdminDN();
            } catch (Exception e) {
                defaultDN = new String("");
                Debug.warning(
		    "pmLdap: getDefaultAdminDN() returns exception: " + e);
            }

            dnField.setText(defaultDN);
            c.gridx = 1;
            p.add(dnField, c);

        // Password
        c.gridx = 0;
        l = new JLabel(pmUtility.getResource("Password:"),
                            SwingConstants.RIGHT);
        p.add(l, c);

        passwordField = new JPasswordField(12);
        passwordField.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                okPressed();
           }
        });
        l.setLabelFor(passwordField);
        // for consistency, don't implement this until all are...
        // l.setDisplayedMnemonic(
	//	pmUtility.getIntResource("Password.mnemonic"));

        c.gridx = 1;
        c.weightx = 1.0;

        c.fill = GridBagConstraints.HORIZONTAL;
        c.anchor = GridBagConstraints.CENTER;
        c.gridy = GridBagConstraints.RELATIVE;

        p.add(passwordField, c);
        passwordField.setEchoChar('*');

        this.getContentPane().add(p, "Center");

	}


        // bottom panel contains buttons
        c.gridx = 0;
        c.weightx = 1.0;
        c.weighty = 0.0;
        c.gridwidth = GridBagConstraints.REMAINDER;
        c.fill = GridBagConstraints.HORIZONTAL;
        c.anchor = GridBagConstraints.CENTER;

        JPanel thePanel = new JPanel();

        okButton = new pmButton(
            pmUtility.getResource("OK"));
        okButton.setMnemonic(
            pmUtility.getIntResource("OK.mnemonic"));
        okButton.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent evt) {
                okPressed();
            }
        });
        thePanel.add(okButton, c);

        cancelButton = new pmButton(
            pmUtility.getResource("Cancel"));
        cancelButton.setMnemonic(
            pmUtility.getIntResource("Cancel.mnemonic"));
        cancelButton.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent evt) {
                cancelPressed();
            }
        });
        thePanel.add(cancelButton, c);

        if (theTag != null && theTop != null) {

            helpButton = new pmButton(
                pmUtility.getResource("Help"));
            helpButton.setMnemonic(
                pmUtility.getIntResource("Help.mnemonic"));
            p.add(helpButton);
            helpButton.addActionListener(new ActionListener() {
                public void actionPerformed(ActionEvent evt) {
					helpPressed();
                }
            });
            thePanel.add(helpButton, c);
        }

        this.getContentPane().add(thePanel, "South");

        addWindowListener(new WindowAdapter() {
            public void windowClosing(WindowEvent e) {
                returnValue = JOptionPane.CLOSED_OPTION;
                pmLogin.this.setVisible(false);
            }
        });

        // handle Esc as cancel in any case
        this.getRootPane().registerKeyboardAction(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                Debug.message("CLNT:  default cancel action");
                cancelPressed();
            }},
            KeyStroke.getKeyStroke(KeyEvent.VK_ESCAPE, 0, false),
            JComponent.WHEN_IN_FOCUSED_WINDOW);

        // lay out the dialog
        this.pack();

        // set focus and defaults after packing...
        // this.getRootPane().setDefaultButton(okButton);
        okButton.setAsDefaultButton();

        passwordField.requestFocus();
    }

    public int getValue() {
        return returnValue;
    }

    public void getLDAPServer() throws pmIncompleteFormException {
    // LDAP Server name is required
	String LDAPserver = null;
	LDAPserver = serverField.getText();
	if (LDAPserver.equals("")) {
	    serverField.requestFocus();
	    throw new pmIncompleteFormException(
		pmUtility.getResource("LDAP.server.name.required."));
	}
    }

    public void getLDAPDN() throws pmIncompleteFormException {
    // LDAP Distinguished name is required
	String LDAPdn = null;
	LDAPdn = dnField.getText();
	if (LDAPdn.equals("")) {
		dnField.requestFocus();
		throw new pmIncompleteFormException(
		    pmUtility.getResource("LDAP.Distinguished.name.required."));
	}
    }

    public void getLDAPPassword() throws pmIncompleteFormException {

    // LDAP password is required

	String tmpp = new String(passwordField.getPassword());
	String LDAPpass = new String(tmpp.trim());

	if (LDAPpass.equals("")) {
		passwordField.requestFocus();
		throw new pmIncompleteFormException(
			pmUtility.getResource("LDAP.Password.required."));
	}
    }

    public void okPressed() {

	// For LDAP, Check Server, Distinguished Name and Password
	boolean complete = true;

	if (theTop.ns.getNameService().equals("ldap")) {
		complete = false;
		try {
			getLDAPServer();
			getLDAPDN();
			getLDAPPassword();
			complete = true;
		} catch (pmIncompleteFormException fe) {
                    pmMessageDialog m = new pmMessageDialog(
                        theFrame,
                        pmUtility.getResource("Error"),
                        fe.getMessage());   // "FormError"
                    m.setVisible(true);
		}
	}

	if (complete) {
            returnValue = JOptionPane.OK_OPTION;
            pmLogin.this.setVisible(false);
	}
    }



    public void cancelPressed() {
       	returnValue = JOptionPane.CANCEL_OPTION;
       	pmLogin.this.setVisible(false);
    }


    public void clearPressed() {

        passwordField.setText("");
    }

    public void helpPressed() {
        theTop.showHelpItem(theTag);
    }

    public static void main(String[] args) {
        JFrame f = new JFrame("Password test");

        f.setSize(300, 100);
        f.addWindowListener(new WindowAdapter() {
            public void windowClosing(WindowEvent e) {
                System.exit(0);
            }
        });
        f.setVisible(true);

	while (true) {
	    pmLogin d = new pmLogin(f, "Test Login",
			"NIS/LDAP Authentication.");
        d.setVisible(true);


    }
     // System.exit(0);
    }

    public JPasswordField passwordField = null;
    public pmTextField serverField = null;
    public pmTextField dnField = null;

    protected int returnValue = JOptionPane.CLOSED_OPTION;

}
