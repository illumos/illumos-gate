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
 * Copyright (c) 1999 by Sun Microsystems, Inc.
 * All rights reserved.
 */
package com.sun.dhcpmgr.client;

import java.awt.Component;
import java.util.Enumeration;
import javax.swing.*;

import com.sun.dhcpmgr.ui.*;

/**
 * The view displayed when we're in relay mode.
 */
public class RelayView implements View {
    private Component display;
    
    public RelayView() {
	display = Wizard.createTextArea(
	    ResourceStrings.getString("relay_view_text"), 4, 45);
    }
    
    public String getName() {
	return ResourceStrings.getString("relay_view_name");
    }
    
    public Enumeration menus() {
	return null;
    }
    
    public Enumeration menuItems(int menu) {
	return null;
    }
    
    public Component getDisplay() {
	return display;
    }
    
    public void find(String s) {
	// nothing to search
    }
    
    public void setActive(boolean state) {
	// Nothing to do
    }
    
    public void handleCreate() {
	// Nothing to do
    }
    
    public void handleDelete() {
	// Nothing to do
    }
    
    public void handleDuplicate() {
	// Nothing to do
    }
    
    public void handleProperties() {
	// Nothing to do
    }
    
    public void handleUpdate() {
	// Nothing to do
    }
    
    public void addSelectionListener(SelectionListener listener) {
	// Nothing to do
    }
    
    public void removeSelectionListener(SelectionListener listener) {
	// Nothing to do
    }
    
    public boolean isSelectionEmpty() {
	return true; // Nothing to select
    }
    
    public boolean isSelectionMultiple() {
	return false; // Nothing to select
    }
}
