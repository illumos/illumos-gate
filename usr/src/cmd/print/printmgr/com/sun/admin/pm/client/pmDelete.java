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
 * pmDelete.java
 * Delete Printer implementation
 */

package com.sun.admin.pm.client;

import java.awt.*;
import java.awt.event.*;
import javax.swing.JPanel;
import javax.swing.*;

import com.sun.admin.pm.server.*;


/*
 * Window for Edit -> Delete
 */

// public class pmDelete extends JPanel {
public class pmDelete {

    Printer newpr = null;
    pmTop mytop = null;

    public pmDelete(pmTop mytop)
    {
        this.mytop = mytop;
        newpr = new Printer(mytop.ns);

        Debug.message("CLNT:  pmDelete");

        if (mytop.selectedPrinter.equals("")) {
            Debug.warning("CLNT:  pmDelete:error: selectedPrinter empty");
            // Display error window
            actioncancelButton();
         }

        pmOKCancelDialog d = new pmOKCancelDialog(
            mytop.parentFrame,
            pmUtility.getResource("SPM:Delete.Printer"),
            pmUtility.getResource("Please.confirm.deletion.of.printer") +
		mytop.selectedPrinter, false);
        d.setVisible(true);

        if (d.getValue() != JOptionPane.OK_OPTION)
            actioncancelButton();
        else {
            try {
                actionokButton();
            } catch (pmUserCancelledException ce) {
                Debug.message("CLNT:  pmDelete:okButton: Login cancelled");
            } catch (pmLoginFailedException de) {
                pmMessageDialog m = new pmMessageDialog(
                    mytop.parentFrame,
                    pmUtility.getResource("Error"),
                    pmUtility.getResource("Required.login.failed."),
                    mytop,
                    "LoginFailed");
                m.setVisible(true);
            } catch (pmGuiException ge) {
                pmMessageDialog m = new pmMessageDialog(
                    mytop.parentFrame,
                    pmUtility.getResource("Application.Error"),
                    ge.toString());
                m.setVisible(true);
            }
        }

    }

    public void actionokButton() throws pmGuiException {
	int ret;
        String cmd = null;
        String warn = null;
        String err = null;

	Debug.message("CLNT:  pmDelete actionokButton()");

	// handle authentication if needed
	if (mytop.ns.getNameService().equals("nis") == true ||
		mytop.ns.getNameService().equals("ldap") == true) {
	    try {
		if (!mytop.ns.isAuth()) {
			pmUtility.doLogin(mytop, mytop.parentFrame);
		}
	    } catch (pmUserCancelledException e) {
		Debug.message("CLNT:  pmDelete:User cancelled login");
		throw new pmUserCancelledException(
				pmUtility.getResource("User.Cancelled.Login"));
	    } catch (pmGuiException e) {
		Debug.warning("CLNT:  pmDelete:login for nis/ldap failed");
		throw new pmLoginFailedException(
			pmUtility.getResource("Login.Authorization.Failed"));
	    } catch (Exception e) {
		Debug.warning("CLNT:  pmDelete:login for nis/ldap failed");
		throw new pmLoginFailedException(
                  pmUtility.getResource("Login.Authorization.Failed"));
	    }
	}

	newpr.setPrinterName(mytop.selectedPrinter);

	// delete the printer
	boolean failed = false;
	try {
		newpr.deletePrinter();
        } catch (Exception e) {
		Debug.warning("CLNT:  pmDelete:deletePrinter exception " + e);
		failed = true;
	}

	cmd = newpr.getCmdLog();
	warn = newpr.getWarnLog();
	err = newpr.getErrorLog();

	Debug.message("CLNT:  pmDelete: delete cmd = " + cmd);
	Debug.message("CLNT:  pmDelete: delete err = " + err);
	Debug.message("CLNT:  pmDelete: delete warn = " + warn);

	if (failed) {
		pmMessageDialog m = new pmMessageDialog(
			mytop.parentFrame,
			pmUtility.getResource("Error"),
			((err == null) ?
			   pmUtility.getResource(
				"Printer.delete.operation.failed.") :
			err),
			mytop,
			"DeletePrinterFailed");
		m.setVisible(true);

        } else {
		Debug.message("CLNT: pmDelete return from deletePrinter ok");

		// Deletion successful, change the table
		if (mytop.selectedRow >= 0) {
			// update table
			mytop.pmsetPrinterList();
			mytop.clearSelected();
			mytop.listTable.clearSelection();
			mytop.pmsetdefaultpLabel();
		} else {
			Debug.warning("CLNT:  pmDelete:selectedRow invalid: " +
				   mytop.selectedRow);
		}
	}
	mytop.setLogData(cmd, err, warn);
	mytop.showLogData(pmUtility.getResource("Delete.Printer"));
    }


    public void actioncancelButton() {
	Debug.message("CLNT:  pmDelete: actioncancelButton()");
    }

}
