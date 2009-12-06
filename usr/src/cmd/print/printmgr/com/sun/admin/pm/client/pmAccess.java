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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Comment which describes the contents of this file.
 *
 * pmAccess.java
 * Add Access To Printer handling
 */

package com.sun.admin.pm.client;

import java.awt.*;
import java.awt.event.*;
import java.util.*;
import java.util.Vector;
import javax.swing.JPanel;
import javax.swing.*;

import com.sun.admin.pm.server.*;


/*
 * Window for Edit -> Add Access to a Printer
 */

public class pmAccess extends pmButtonScreen {
    JComboBox portCombo;
    pmFrame frame = new pmFrame(
	pmUtility.getResource("SPM:Add.Access.To.Printer"));
    pmTextField pnameText;
    pmTextField snameText;
    pmTextField descText;
    Boolean makedefault;
    JCheckBox defaultp;
    Printer newpr = null;
    pmTop mytop;
    String printer = null;
    String server = null;

    String cmdLog = null;
    String errorLog = null;
    String warnLog = null;


    final static int OK =  1;
    final static int APPLY =  2;
    final static int RESET =  3;
    final static int CANCEL =  4;
    final static int HELP =  5;

    public pmAccess(pmTop mytop) {

        // ensure that pmButton hashtable gets cleaned up
        frame.setClearButtonsOnClose(true);

        setLayout(new BorderLayout());

	this.mytop = mytop;

	// Build the Frame
	centerPanel();
	southPanel();

	/*
	 * let's try doing this in Show...
	 *
	 * // default button is always OK, for now...
	 * frame.getRootPane().setDefaultButton(okButton);
	 *
	 * okButton.setAsDefaultButton();
	 */

        // handle Esc as cancel
	this.registerKeyboardAction(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                Debug.message("CLNT:  default cancel action");
                actioncancelButton();
            }},
            KeyStroke.getKeyStroke(KeyEvent.VK_ESCAPE, 0, false),
            JComponent.WHEN_IN_FOCUSED_WINDOW);

        // enable the pmFrame to set focus to our default comp on activation
	frame.setDefaultComponent(pnameText);


	// following is test code, I think...
	Component glass = frame.getGlassPane();

	glass.addKeyListener(new KeyAdapter() {
            public void keyPressed(KeyEvent k) {
                Debug.info("Glass: " + k);
            }
            public void keyReleased(KeyEvent k) {
                Debug.info("Glass: " + k);
            }
            public void keyTyped(KeyEvent k) {
                Debug.info("Glass: " + k);
            }
	});

    }

    public void centerPanel() {
	// Build center panel
	JPanel center = new JPanel();
	center.setLayout(new GridBagLayout());
	GridBagConstraints c = new GridBagConstraints();

	// define center constraints
	c.insets = new Insets(8, 5, 5, 5);
	c.gridheight = 1;
	c.gridwidth = 1;

	// build center components
	// Create
	c.gridx = 0;
	c.weightx = c.weighty = 0.0;
	c.fill = GridBagConstraints.NONE;
	c.anchor = GridBagConstraints.WEST;

	// Build the labels
	c.gridy = 0;
	center.add(new JLabel
		(pmUtility.getResource("Printer.Name:")), c);
	c.gridy = 1;
	center.add(new JLabel
		(pmUtility.getResource("Printer.Server:")), c);
	c.gridy = 2;
	center.add(new JLabel
		(pmUtility.getResource("Description:")), c);
	c.gridy = 3;
	center.add(new JLabel
		(pmUtility.getResource("Option:")), c);

	// Build the text fields
	// Common constraints
	c.gridx = 1;
	c.ipadx = 15;
	c.fill = GridBagConstraints.HORIZONTAL;
	c.anchor = GridBagConstraints.WEST;
	c.weightx = c.weighty = 1.0;

	c.gridy = 0;
	pnameText = new pmTextField(14);

	center.add(pnameText, c);

	c.gridy = 1;
	snameText = new pmTextField(25);
	center.add(snameText, c);

	c.gridy = 2;
	descText = new pmTextField(25);
	center.add(descText, c);

	// Add Choice Menus - ComboBox
	c.weightx = c.weighty = 0.0;
	c.gridy = 3;

	defaultp = new JCheckBox(
		pmUtility.getResource("Default.Printer"));
	center.add(defaultp, c);

	add("Center", center);
    }

    public void createAccess() throws pmGuiException {
	boolean getHostOk = true;
	String description = "";

	newpr = new Printer(mytop.ns);
	Debug.message("CLNT: createAccess()");
	pmCalls.debugShowPrinter(newpr);
	printer = pnameText.getText().trim();
	server = snameText.getText().trim();
	description = descText.getText();

	if (printer.equals("")) {
		pnameText.requestFocus();
		Debug.message("CLNT:pmAccess:Printer name required.");
		throw new pmIncompleteFormException(
			pmUtility.getResource("Printer.name.required."));
	}

	if (!Valid.remotePrinterName(printer)) {
		pnameText.requestFocus();
		Debug.message("CLNT:pmAccess:Printer name invalid: " + printer);
		throw new pmIncompleteFormException(
			pmUtility.getResource("Printer.name.invalid."));
	}

	if (server.equals("")) {
		snameText.requestFocus();
		Debug.message("CLNT:pmAccess:Server name required.");
		throw new pmIncompleteFormException(
			pmUtility.getResource("Server.name.required."));
	}

	if (!Valid.serverName(server)) {
		snameText.requestFocus();
		Debug.message("CLNT:pmAccess:Server name invalid.");
		throw new pmIncompleteFormException(
			pmUtility.getResource("Server.name.invalid."));
	}

	try {
	    if (server.equals(mytop.host.getLocalHostName()) ||
		server.equals("localhost")) {
		snameText.requestFocus();
		getHostOk = false;
	    }
	} catch (Exception e) {
		Debug.warning(
		"CLNT: pmAccess:createAccess:getLocalHostName exception");
		throw new pmGuiException(
			pmUtility.getResource(
			"Could.not.get.local.hostname " + e));
	}

	if (!getHostOk) {
		Debug.warning(
		"CLNT: pmAccess:createAccess:Server name required.");
		throw new pmMustBeRemoteServerException(
			pmUtility.getResource("Server.name.required."));
	}

	boolean exist;
	try {
		exist = PrinterUtil.exists(printer, mytop.ns);
	} catch (Exception e) {
		throw new pmGuiException(e.toString());
	}

	if (exist) {
		throw new pmPrinterExistsException();
	}

	if (mytop.ns.getNameService().equals("nis") == true ||
		mytop.ns.getNameService().equals("ldap") == true) {
		try {
			if (!mytop.ns.isAuth()) {
				pmUtility.doLogin(mytop, frame);
			}
		} catch (pmUserCancelledException e) {
			Debug.message("CLNT:pmAccess:user cancelled login");
			throw new pmUserCancelledException(
				pmUtility.getResource(
				"User.cancelled.login."));
		} catch (pmGuiException e) {
			Debug.message(
			    "CLNT:pmAccess:login nis/ldap failed: " + e);
               		throw new pmLoginFailedException();
		} catch (Exception e) {
			Debug.message(
			    "CLNT:pmAccess:login nis/ldap failed: " + e);
               		throw new pmLoginFailedException();
		}
	}

	Debug.message("CLNT:pmAccess:checkbox: " + defaultp.isSelected());

	// Check for confirmation option
	if (((mytop.getConfirmOption() == true) && (confirmAction() == true))
              	|| (mytop.getConfirmOption() == false)) {

		// Set the printer attributes
		newpr.setPrinterName(printer);
		newpr.setPrintServer(server);
		newpr.setComment(description);
		if (defaultp.isSelected())
			newpr.setIsDefaultPrinter(true);

		frame.setCursor(Cursor.getPredefinedCursor(Cursor.WAIT_CURSOR));

		boolean failed = false;
		try {
			newpr.addRemotePrinter();
		} catch (Exception e) {
			failed = true;
			Debug.warning(
				"CLNT:pmAccess:addRemotePrinter caught:" + e);
		}

		frame.setCursor(Cursor.getDefaultCursor());

		gatherLogs();
		dumpLogs("CLNT:pmAccess:createAccess()");

		pmCalls.debugShowPrinter(newpr);

		mytop.setLogData(cmdLog, errorLog, warnLog);
		mytop.showLogData(
		    pmUtility.getResource("Add.Access.To.Printer"));

		mytop.pmsetPrinterList();
		mytop.clearSelected();
		mytop.listTable.clearSelection();

		if (failed)
			throw new pmAddAccessFailedException(errorLog);

        }
    }

    public void clearAccessInput()  {
	try {
		pnameText.setText("");
		snameText.setText("");
		descText.setText("");
		if (defaultp.isSelected())
			defaultp.doClick();
	} catch (Exception  e) {
	// ignore???
        // throw new pmGuiException("pmAccess: Error clearAccessInput: " + e);
            	Debug.warning("CLNT:pmAccess: Error clearAccessInput: " + e);
	}
    }



    public boolean confirmAction() {
	if (mytop.getConfirmOption() == true) {
		pmOKCancelDialog d = new pmOKCancelDialog(frame,
			pmUtility.getResource("Action.Confirmation"),
			pmUtility.getResource(
				"Continue.creating.access.for.this.printer?"));
		d.setVisible(true);
		if (d.getValue() != JOptionPane.OK_OPTION) {
		    pmMessageDialog m = new pmMessageDialog(frame,
			    pmUtility.getResource("Warning"),
			    pmUtility.getResource("Operation.Cancelled"));
		    m.setVisible(true);
		    return false;
		}
	}
	return true;
    }

    void gatherLogs() {
        cmdLog = newpr.getCmdLog();
        errorLog = newpr.getErrorLog();
        warnLog = newpr.getWarnLog();
    }


    void dumpLogs(String who) {
        Debug.message(who);
        Debug.message(who + " command: " + cmdLog);
        Debug.message(who + " warnings: " + warnLog);
        Debug.message(who + " errors: " + errorLog);
    }

    // returns true if success, false otherwise
    boolean doAction() {
        boolean rv = false;

        try {
            createAccess();
	    rv = true;	// only if it didn't throw!
        } catch (pmIncompleteFormException ix) {
		Debug.warning(
			"CLNT:pmAccess:incomplete form " + ix.getMessage());
            	pmMessageDialog m = new pmMessageDialog(
                	frame,
                	pmUtility.getResource("Error"),
                	ix.getMessage(),
                	mytop,
                	"AddAccessFailed");
            m.setVisible(true);
        } catch (pmPrinterExistsException ex) {
		Debug.warning("CLNT:pmAccess:printer exists");
            pmMessageDialog m = new pmMessageDialog(
                frame,
                pmUtility.getResource("Error"),
                pmUtility.getResource("The.specified.printer.already.exists."));
            m.setVisible(true);
        } catch (pmMustBeRemoteServerException rx) {
		Debug.warning("CLNT:pmAccess:server must be remove.");
            	pmMessageDialog m = new pmMessageDialog(
                	frame,
                	pmUtility.getResource("Error"),
                	pmUtility.getResource(
				"The.server.must.be.a.remote.server."),
                	mytop,
                	"RemoteServer");
		m.setVisible(true);

        } catch (pmLoginFailedException lx) {
		Debug.warning("CLNT:pmAccess:Required login failed");
		pmMessageDialog m = new pmMessageDialog(
			frame,
			pmUtility.getResource("Error"),
			pmUtility.getResource("Required.login.failed."),
			mytop,
			"LoginFailed");
            	m.setVisible(true);

        } catch (pmAddAccessFailedException ax) {
		Debug.warning(
			"CLNT:pmAccess:add access failed " + ax.getMessage());
		pmMessageDialog m = new pmMessageDialog(
			frame,
			pmUtility.getResource("Error"),
			ax.getMessage(),
			mytop,
			"AddAccessFailed");
            m.setVisible(true);

        } catch (pmUserCancelledException cx) {
		Debug.message(
		"CLNT:pmAccess:createAccess: User cancelled namespace login");
        } catch (pmGuiException gx) {
		Debug.warning(
			"CLNT:pmAccess:Application Error" + gx.getMessage());
		pmMessageDialog m = new pmMessageDialog(
			frame,
			pmUtility.getResource("Application.Error"),
			gx.getMessage());
		m.setVisible(true);

        } finally {
            // clearAccessInput();
        }
        return rv;
    }


    public void pmScreendispose() {
        frame.dispose();
    }

    public void actionokButton() {
        Debug.message("CLNT:pmAccess:actionokButton()");

        if (doAction() == true) {
            clearAccessInput();
	    mytop.pmsetdefaultpLabel();
            frame.setVisible(false);
            frame.repaint();
            // frame.dispose();
            mytop.scrollPane.revalidate();
            mytop.scrollPane.repaint();
        } else {
                Debug.message("CLNT: pmAccess: doAction is false");
        }

    }

    public void actionapplyButton() {
        Debug.message("CLNT:pmAccess:actionapplyButton()");

        if (doAction() == true) {
			mytop.pmsetdefaultpLabel();
			mytop.scrollPane.revalidate();
			mytop.scrollPane.repaint();

		}
    }


    public void actionresetButton() {
        Debug.message("CLNT:pmAccess:actionresetButton()");
        clearAccessInput();
		pnameText.requestFocus();
    }

    public void actioncancelButton() {
        Debug.message("CLNT:pmAccess:actioncancelButton()");
        clearAccessInput();
        frame.setVisible(false);
        frame.repaint();
        // frame.dispose();
    }

    public void actionhelpButton() {
	Debug.message("CLNT:pmAccess:actionhelpButton()");
	mytop.showHelpItem("AddAccess");
    }


    public void Show() {

	frame.getContentPane().add("North", this);
	frame.pack();
	frame.setVisible(true);
	frame.repaint();

	frame.toFront();
	frame.requestFocus();

	okButton.setAsDefaultButton();
	pnameText.requestFocus();
	Debug.message("CLNT:pmAccess:Show()");

    }
}
