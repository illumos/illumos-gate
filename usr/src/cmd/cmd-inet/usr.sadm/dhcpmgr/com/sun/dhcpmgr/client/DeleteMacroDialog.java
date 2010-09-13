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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
package com.sun.dhcpmgr.client;

import java.awt.*;
import java.awt.event.*;
import java.text.MessageFormat;
import java.util.*;
import javax.swing.*;

import com.sun.dhcpmgr.server.*;
import com.sun.dhcpmgr.data.*;
import com.sun.dhcpmgr.ui.*;
import com.sun.dhcpmgr.bridge.NotRunningException;

/**
 * This dialog allows the user to delete a macro.
 */
public class DeleteMacroDialog extends DhcpmgrDialog {
    private JCheckBox signalBox;
    private Macro macro;
    private JLabel message;
    
    public DeleteMacroDialog(Frame f, Macro m) {
	super(f, false);
	setTitle(ResourceStrings.getString("delete_macro_title"));
	macro = m;
	message.setText(MessageFormat.format(
	    ResourceStrings.getString("delete_macro_confirm"), macro.getKey()));
	message.setToolTipText(MessageFormat.format(
            ResourceStrings.getString("delete_macro_confirm"), macro.getKey()));
    }

    public JPanel getMainPanel() {
	JPanel mainPanel = new JPanel(new BorderLayout());

	JPanel flowPanel = new JPanel();
	
	message = new JLabel();
	flowPanel.add(message);
	mainPanel.add(flowPanel, BorderLayout.NORTH);
	
	flowPanel = new JPanel();
	signalBox = new JCheckBox(ResourceStrings.getString("signal_server"),
	    true);
	signalBox.setToolTipText(
	    ResourceStrings.getString("signal_server"));
	flowPanel.add(signalBox);
	mainPanel.add(flowPanel, BorderLayout.CENTER);
	
	buttonPanel.setOkEnabled(true);
        return mainPanel;
    }

    protected void doOk() {
	try {
	    DhcptabMgr server = DataManager.get().getDhcptabMgr();
	    server.deleteRecord(macro, signalBox.isSelected());
	    fireActionPerformed();
	    setVisible(false);
	    dispose();
	} catch (NotRunningException e) {
	    // Server not running, put up a warning
	    JOptionPane.showMessageDialog(this,
		ResourceStrings.getString("server_not_running"),
		ResourceStrings.getString("warning"),
		JOptionPane.WARNING_MESSAGE);
	    fireActionPerformed();
	    setVisible(false);
	    dispose();
	} catch (Exception e) {
	    MessageFormat form = null;
	    Object [] args = new Object[2];
	    form = new MessageFormat(
		ResourceStrings.getString("delete_macro_error"));
	    args[0] = macro.getKey();
	    args[1] = e.getMessage();
	    JOptionPane.showMessageDialog(this, form.format(args),
		ResourceStrings.getString("server_error_title"),
		JOptionPane.ERROR_MESSAGE);
	}
    }

    protected String getHelpKey() {
	return "delete_macro";
    }
    
    protected void fireActionPerformed() {
	fireActionPerformed(this, DialogActions.DELETE);
    }
}
