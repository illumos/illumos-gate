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
 * pmAuthOptions.java
 * Prompt for root password from printmgr.
 * This a helper for printmgr which echoes YES, NO, or CANCEL to stdout.
 */

package com.sun.admin.pm.client;

import java.awt.*;
import java.awt.event.*;
import java.util.*;
import javax.swing.*;
import com.sun.admin.pm.server.*;


public class pmAuthOptions {

    public static void main(String[] args) {

	boolean done = false;
	String rv = "CANCEL";

	    pmAuthMessage o = new pmAuthMessage(null,
		pmUtility.getResource("Authentication.required"),
		pmUtility.getResource("Root.access.is.required"));
	    o.setVisible(true);
	    switch (o.getValue()) {
		case JOptionPane.YES_OPTION:
			break;

		case JOptionPane.NO_OPTION:
			System.out.println("NO");
			System.exit(0);
			break;

		case JOptionPane.CANCEL_OPTION:
		default:
			System.out.println("CANCEL");
			System.exit(0);
			break;
	    }

	while (!done) {
	    pmAuthLogin d = new pmAuthLogin(null,
			    pmUtility.getResource("Root.authentication"),
			    pmUtility.getResource("Enter.root.password"));
	    d.setVisible(true);
	    if (d.getValue() != JOptionPane.OK_OPTION)
		done = true;
	    else {
		boolean ok = false;
		String pw = new String(d.getPassword());
		try {
		    PrinterUtil.checkRootPasswd(pw);
		    ok = true;
		} catch (Exception x) {

		}
		if (!ok) {
		    pmOKCancelDialog m = new pmOKCancelDialog(null,
				    pmUtility.getResource("Error"),
				    pmUtility.getResource("Invalid.password"));
		    m.setVisible(true);
		    if (m.getValue() != JOptionPane.OK_OPTION)
			done = true;
		} else {
		    done = true;
		    rv = "YES";
		}
	    }
	}

	System.out.println(rv);
	System.exit(0);
    }


}


/*
 */

class pmAuthLogin extends pmDialog {
    private String theTag = null;

    protected pmButton okButton = null;
    protected pmButton cancelButton = null;

    public pmAuthLogin(JFrame f, String title, String msg) {

	super(f, title, true);		// modal

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


        // middle panel contains username and password
        p = new JPanel();
        p.setLayout(new GridBagLayout());

        l = new JLabel(pmUtility.getResource("Hostname:"),
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

        c.anchor = GridBagConstraints.WEST;

	String hostname = null;
	try {
		hostname = (java.net.InetAddress.getLocalHost()).getHostName();
	} catch (java.net.UnknownHostException uhx) {
		System.out.println(uhx);
	}

        l = new JLabel(hostname, SwingConstants.LEFT);
        p.add(l, c);


        c.fill = GridBagConstraints.HORIZONTAL;
        c.anchor = GridBagConstraints.CENTER;
        c.gridy = GridBagConstraints.RELATIVE;

        p.add(passwordField, c);
        passwordField.setEchoChar('*');

        this.getContentPane().add(p, "Center");

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

        this.getContentPane().add(thePanel, "South");

        addWindowListener(new WindowAdapter() {
            public void windowClosing(WindowEvent e) {
                returnValue = JOptionPane.CANCEL_OPTION;
                setVisible(false);
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


    public void okPressed() {
        returnValue = JOptionPane.OK_OPTION;
        setVisible(false);
    }

    public void cancelPressed() {
       	returnValue = JOptionPane.CANCEL_OPTION;
       	setVisible(false);
    }


    public void clearPressed() {
        passwordField.setText("");
    }

    public char[] getPassword() {
	return passwordField.getPassword();
    }


    public JPasswordField passwordField = null;

    protected int returnValue = JOptionPane.CANCEL_OPTION;

}


class pmAuthMessage extends pmDialog {
    private String theTag = null;

    protected pmButton authButton = null;
    protected pmButton cancelButton = null;
    protected pmButton contButton = null;

    public pmAuthMessage(JFrame f, String title, String msg) {

	super(f, title, true);		// modal

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


        JList l = new JList() {
            public boolean isFocusable() {
                return false;
            }
        };
	// pathetic hacks to make the list look the same as a label
	JLabel tmp = new JLabel();
        l.setBackground(tmp.getBackground());
        l.setForeground(tmp.getForeground());
	l.setFont(tmp.getFont());
	tmp = null;
	Vector v = new Vector();
        if (msg != null) {
            StringTokenizer st = new StringTokenizer(msg, "\n", false);
            try {
                while (st.hasMoreTokens())
                    v.addElement(st.nextToken());
            } catch (Exception x) {
            }
            l.setListData(v);
        }


        p.add(l, c);
        this.getContentPane().add(p, "North");


        // bottom panel contains buttons
        c.gridx = 0;
        c.weightx = 1.0;
        c.weighty = 0.0;
        c.gridwidth = GridBagConstraints.REMAINDER;
        c.fill = GridBagConstraints.HORIZONTAL;
        c.anchor = GridBagConstraints.CENTER;

        JPanel thePanel = new JPanel();

        authButton = new pmButton(pmUtility.getResource("Authenticate"));
        authButton.setMnemonic(
			pmUtility.getIntResource("Authenticate.mnemonic"));
        authButton.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent evt) {
                authPressed();
            }
        });
        thePanel.add(authButton, c);

        contButton = new pmButton(pmUtility.getResource("Continue"));
        contButton.setMnemonic(pmUtility.getIntResource("Continue.mnemonic"));
        contButton.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent evt) {
                contPressed();
            }
        });
        thePanel.add(contButton, c);

        cancelButton = new pmButton(pmUtility.getResource("Cancel"));
        cancelButton.setMnemonic(pmUtility.getIntResource("Cancel.mnemonic"));
        cancelButton.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent evt) {
                cancelPressed();
            }
        });
        thePanel.add(cancelButton, c);

        this.getContentPane().add(thePanel, "South");

        addWindowListener(new WindowAdapter() {
            public void windowClosing(WindowEvent e) {
                returnValue = JOptionPane.CANCEL_OPTION;
                setVisible(false);
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
        authButton.setAsDefaultButton();

    }

    public int getValue() {
        return returnValue;
    }


    public void authPressed() {
        returnValue = JOptionPane.YES_OPTION;
        setVisible(false);
    }

    public void cancelPressed() {
       	returnValue = JOptionPane.CANCEL_OPTION;
       	setVisible(false);
    }


    public void contPressed() {
       	returnValue = JOptionPane.NO_OPTION;
       	setVisible(false);
    }

    protected int returnValue = JOptionPane.CANCEL_OPTION;

}
