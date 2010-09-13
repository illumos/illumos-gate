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
 * Copyright (c) 2000 by Sun Microsystems, Inc.
 * All rights reserved.
 */

/*
 *        Copyright (C) 1996  Active Software, Inc.
 *                  All rights reserved.
 *
 * @(#) DesignerAccess.java 1.25 - last change made 08/07/97
 */

package sunsoft.jws.visual.rt.base;

import sunsoft.jws.visual.rt.shadow.java.awt.*;
import java.util.Hashtable;
import java.awt.Insets;

/**
 * Accessor class for use by Visual Java.  Gives
 * access to specific methods in the rt package that are package
 * private.  The methods in this class should not be used by any other
 * application; they are for use by Visual Java only and are subject
 * to change.
 *
 * @version 08/07/97, 1.25
 */
public class DesignerAccess {
    //
    // Constants
    //
    public static final int STATUS_BAR = 2002;
    
    //
    // Internal "Group" methods
    //
    public static ContainerShadow getContainer(Group group) {
        return group.getContainer();
    }
    
    public static PanelShadow getPanel(Group group) {
        return group.getPanel();
    }
    
    public static WindowShadow getWindow(Group group) {
        return group.getWindow();
    }
    
    public static void internalShowGroup(Group group) {
        group.internalShowGroup();
    }
    
    public static void internalHideGroup(Group group) {
        group.internalHideGroup();
    }
    
    public static boolean doingShow(Group group) {
        return group.doingShow();
    }
    
    public static void preValidate(Group group) {
        group.preValidate();
    }
    
    //
    // Internal "AttributeManager" methods
    //
    public static AttributeManager replicate(AttributeManager mgr) {
        return mgr.replicate();
    }
    
    //
    // Internal "Root" methods
    //
    public static void setMainChild(Root root, AttributeManager
				    container, boolean isPanel) {
        root.setMainChild(container, isPanel);
    }
    
    public static void addRootObserver(Root root, RootObserver observer)
    
    {
        root.addRootObserver(observer);
    }
    
    public static void removeRootObserver(Root root, RootObserver
					  observer) {
        root.removeRootObserver(observer);
    }
    
    public static void disableEventForwarding(Root root) {
        root.disableEventForwarding();
    }
    
    public static void enableEventForwarding(Root root) {
        root.enableEventForwarding();
    }
    
    public static void clearUniqueNameTable(Root root) {
        root.clearUniqueNameTable();
    }
    
    public static boolean isValidName(String name) {
        return Root.isValidName(name);
    }
    
    public static boolean isUniqueName(Root root, String name) {
        return root.isUniqueName(name);
    }
    
    public static boolean isUniqueName(Root root, String name,
				       AttributeManager skip) {
        return root.isUniqueName(name, skip);
    }
    
    public static boolean isUniqueName(Root root, String name,
				       AttributeManager skip,
				       AttributeManager prune) {
        return root.isUniqueName(name, skip, prune);
    }
    
    public static String getUniqueName(Root root, AttributeManager
				       child) {
        return root.getUniqueName(child);
    }
    
    public static String getUniqueName(Root root, AttributeManager
				       child, Root otherTree) {
        return root.getUniqueName(child, otherTree);
    }
    
    public static String getProblemWithName(Root root, String name) {
        return root.getProblemWithName(name);
    }
    
    public static void setCursor(Root root, int cursor) {
        root.setCursor(cursor);
    }
    
    //
    // LOADED ROOT
    //
    
    /*
     * Sets the loaded root flag.
     */
    public static void setLoadedRoot(Root root, boolean flag) {
        root.setLoadedRoot(flag);
    }
    
    //
    // Designer classes used by FrameShadow, DialogShadow,
    // GBPanel, RootFrame
    // and RootDialog.
    //
    
    private static Class frameClass;
    private static Class dialogClass;
    private static Class gbPanelClass;
    private static Class rootWindowHelperClass;
    
    public static void setFrameClass(Class fc) {
        frameClass = fc;
    }
    
    public static Class getFrameClass() {
        return frameClass;
    }
    
    public static void setDialogClass(Class dc) {
        dialogClass = dc;
    }
    
    public static Class getDialogClass() {
        return dialogClass;
    }
    
    public static void setGBPanelClass(Class gbc) {
        gbPanelClass = gbc;
    }
    
    public static Class getGBPanelClass() {
        return gbPanelClass;
    }
    
    public static void setRootWindowHelperClass(Class c) {
        rootWindowHelperClass = c;
    }
    
    public static Class getRootWindowHelperClass() {
        return rootWindowHelperClass;
    }
    
    //
    // The current working directory for the designer
    //
    private static String cwd;
    
    public static void setCWD(String cwd) {
        DesignerAccess.cwd = cwd;
    }
    
    public static String getCWD() {
        return cwd;
    }
    
    //
    // UNSAVED EDITS REGISTRY
    //
    
    /**
     * Is true when there are unsaved changes.  Isn't going to get used
     * unless the visual designer is running.
     */
    private static boolean changesMade = false;
    
    /*
     * Returns whether there have been any changes made
     * since the last save.
     */
    public static boolean getChangesMade() {
        return (changesMade);
    }
    
    /*
     * Sets the changes made flag.  Set to true when a change is made.
     * This needs to set to false at the top-level of the designer's GUI
     * whenever a file is opened, a "New" is done, a file is saved, etc.
     * This doesn't work all the time, so we might replace it with
     * something else in the future.
     */
    public static void setChangesMade(boolean b) {
        // if (b != changesMade) {
        //   Error e = new Error("DesignerAccess.changesMade
        // switched to " + b);
        //   e.printStackTrace();
        // }
        changesMade = b;
    }
    
    //
    // COMPONENT -> SHADOW HASHTABLE
    //
    
    /*
     * Storage to map components (keys) to their shadow objects (values)
     */
    private static Hashtable shadowTable = new Hashtable();
    
    /*
     * Returns the shadow table, which contains components (as keys) and
     * their associated shadow objects (as the values.)  This one table
     * is shared by all of runtime and the visual designer.
     *  It is used to
     * find the Group that should handle the event for a particular
     * component
     * and to find the shadow object for components in the designer.
     */
    public static Hashtable getShadowTable() {
        return (shadowTable);
    }
    
    /**
     * Global lock (for paint workaround.)
     */
    public static Object mutex = new Object();
    
    /*
     *
     */
    
    private static DesignerErrorInterface designerError = null;
    
    static public void
	setDesignerErrorInterface(DesignerErrorInterface obj) {
        designerError = obj;
    }
    
    static public void reportInstantiationError(String msg) {
        if (!java.beans.Beans.isDesignTime())
            return;
        
        if (designerError != null) {
            designerError.reportInstantiationError(msg);
        }
        else
	    {
		System.out.println(msg);
	    }
    }
}
