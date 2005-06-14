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

/**
 *  This dialog handles enabling and disabling the service, with user
 * confirmation
 */
public class DisableServiceDialog extends DhcpmgrDialog {
    private boolean disable;
    private JLabel message;
    
    public DisableServiceDialog(Frame f, boolean disable) {
	super(f, false);
	
	this.disable = disable;
	
	String name = DataManager.get().getShortServerName();
	if (disable) {
	    setTitle(ResourceStrings.getString("disable_service_title"));
	    if (DhcpmgrApplet.modeIsRelay) {
		message.setText(MessageFormat.format(
		    ResourceStrings.getString("disable_relay_confirm"), name));
		message.setToolTipText(MessageFormat.format(
		    ResourceStrings.getString("disable_relay_confirm"), name));
	    } else {
		message.setText(MessageFormat.format(
		    ResourceStrings.getString("disable_service_confirm"),
		    name));
		message.setToolTipText(MessageFormat.format(
		    ResourceStrings.getString("disable_service_confirm"),
		    name));
	    }
	} else {
	    setTitle(ResourceStrings.getString("enable_service_title"));
	    if (DhcpmgrApplet.modeIsRelay) {
		message.setText(MessageFormat.format(
		    ResourceStrings.getString("enable_relay_confirm"), name));
		message.setToolTipText(MessageFormat.format(
		    ResourceStrings.getString("enable_relay_confirm"), name));
	    } else {
		message.setText(MessageFormat.format(
		    ResourceStrings.getString("enable_service_confirm"), name));
		message.setToolTipText(MessageFormat.format(
		    ResourceStrings.getString("enable_service_confirm"), name));
	    }
	}
    }

    protected JPanel getMainPanel() {
	JPanel panel = new JPanel();
	panel.setBorder(BorderFactory.createEmptyBorder(20, 10, 20, 10));
	message = new JLabel();
	panel.add(message);

	buttonPanel.setOkEnabled(true);
	return panel;
    }

    protected void doOk() {
	try {
	    DhcpServiceMgr server = DataManager.get().getDhcpServiceMgr();
	    DhcpdOptions opts =
		DataManager.get().getDhcpServiceMgr().readDefaults();
	    if (disable) {
		// Shutdown the server and disable the daemon.
		server.shutdown();
		opts.setDaemonEnabled(false);
		DataManager.get().getDhcpServiceMgr().writeDefaults(opts);
	    } else {
		// Enable = reverse the process
		opts.setDaemonEnabled(true);
		DataManager.get().getDhcpServiceMgr().writeDefaults(opts);
		server.startup();
	    }
	    fireActionPerformed();
	    setVisible(false);
	    dispose();
	} catch (Exception e) {
	    e.printStackTrace();
	    MessageFormat form = null;
	    Object [] args = new Object[1];
	    if (disable) {
		form = new MessageFormat(
		    ResourceStrings.getString("disable_service_error"));
	    } else {
		form = new MessageFormat(
		    ResourceStrings.getString("enable_service_error"));
	    }
	    args[0] = e.getMessage();
	    JOptionPane.showMessageDialog(this, form.format(args),
		ResourceStrings.getString("server_error_title"),
		JOptionPane.ERROR_MESSAGE);
	}
    }

    protected String getHelpKey() {
	if (disable) {
	    return "disable_service";
	} else {
	    return "enable_service";
	}
    }
    
    /**
     * Notify listeners that enable or disable has been done.
     */
    protected void fireActionPerformed() {
	String cmd;
	if (disable) {
	    cmd = DialogActions.DISABLE;
	} else {
	    cmd = DialogActions.ENABLE;
	}
	fireActionPerformed(this, cmd);
    }
}
