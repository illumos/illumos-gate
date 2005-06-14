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
 * Copyright (c) 1998-1999 by Sun Microsystems, Inc.
 * All rights reserved.
 */
package com.sun.dhcpmgr.ui;

import java.util.Enumeration;
import java.awt.Component;

/**
 * View is the interface implemented by objects which wish to appear as tabs in
 * the main window.  Each View is given a tab in the tabbed display managed by
 * MainFrame.
 * @see MainFrame
 */
public interface View {
    /**
     * Supply the view's display name, which will be the tab's title.
     * @return a short name to describe the view
     */
    public String getName();
    /**
     * the menus the view wishes to add to the interface.
     * @return an enumeration of JMenus
     */
    public Enumeration menus();
    /**
     * the menu items to be added to a specific menu
     * @return an enumeration of JMenuItems
     */
    public Enumeration menuItems(int menu);
    /**
     * the display to be shown for this view.  It will occupy the entire tab.
     * @return a component to display
     */
    public Component getDisplay();
    /**
     * view is to search for the next occurrence of the supplied string and
     * update its display accordingly.
     * @param s the string to search for
     */
    public void find(String s);
    /**
     * notification to view that it has been activated or deactivated.
     * Views may wish to update their display state at this time.
     * @param state true if view is now active, false if now inactive
     */
    public void setActive(boolean state);
    /**
     * user has selected Edit->Create menu item.  View should provide an
     * interface to create an instance of its primary object type.
     */
    public void handleCreate();
    /**
     * user has selected Edit->Delete menu item.  View should attempt to delete
     * any selected objects, probably with a confirmation notice.
     */
    public void handleDelete();
    /**
     * user has selected Edit->Duplicate menu item.  View should provide an
     * interface which creates a new object with attributes similar to the
     * currently selected object.
     */
    public void handleDuplicate();
    /**
     * user has selected Edit->Properties menu item.  View should provide an
     * interface to modify the properties of the selected item.
     */
    public void handleProperties();
    /**
     * user has selected View->Refresh menu item.  View should make its display
     * current.
     */
    public void handleUpdate();
    /**
     * add a listener for selection events.
     * @param listener a SelectionListener
     */
    public void addSelectionListener(SelectionListener listener);
    /**
     * remove a listener for selection events.
     * @param listener a SelectionListener
     */
    public void removeSelectionListener(SelectionListener listener);
    /**
     * listeners query to ascertain whether selection state is empty.
     * @return true if no objects are selected
     */
    public boolean isSelectionEmpty();
    /**
     * listeners query to ascertain whether selection state is multiple.
     * @return true if multiple objects selected
     */
    public boolean isSelectionMultiple();
}
