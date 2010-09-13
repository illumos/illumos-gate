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
 * @(#) Root.java 1.88 - last change made 07/25/97
 */

package sunsoft.jws.visual.rt.base;

import sunsoft.jws.visual.rt.shadow.java.awt.*;

import java.awt.Event;
import java.awt.Frame;
import java.util.*;

/*
 * NOTE: Whenever a new public or protected variable is added to this
 * class the name of the variable must be added to the reservedWords
 * list, so that the user doesn't use it in one of the generated Root
 * sub-classes.
 */

/**
 * Instances of the Root class are used for the root of the group's
 * shadow tree.  The direct child shadows of an instantiation of this
 * object will typically be top-level windows or the top panel of an
 * applet.
 *
 * @version 1.88, 07/25/97
 */
public class Root extends AttributeManager implements AMContainer {
    
    private AMContainerHelper containerHelper = new AMContainerHelper(this);
    
    /**
     * This flag is set to true if this is the loaded root.
     */
    private boolean isLoadedRoot = false;
    
    /**
     * The constructor defines the Root's attributes.
     */
    public Root() {
        attributes.add(/* NOI18N */"generateClass",
		    /* NOI18N */"java.lang.String", null, 0);
        attributes.add(/* NOI18N */"generateDirectory",
		    /* NOI18N */"java.lang.String", null, 0);
        attributes.add(/* NOI18N */"generatePackage",
		    /* NOI18N */"java.lang.String", null, 0);
        attributes.add(/* NOI18N */"willGenerateGUI",
		    /* NOI18N */"java.lang.Boolean", Boolean.TRUE, 0);
        attributes.add(/* NOI18N */"willGenerateMain",
		    /* NOI18N */"java.lang.Boolean", Boolean.TRUE, 0);
        attributes.add(/* NOI18N */"willGenerateGroup",
		    /* NOI18N */"java.lang.Boolean", Boolean.FALSE, 0);
        attributes.add(/* NOI18N */"willGenerateHTML",
		    /* NOI18N */"java.lang.Boolean", Boolean.FALSE, 0);
        attributes.add(/* NOI18N */"suffixForGUIClass",
		    /* NOI18N */"java.lang.String", /* NOI18N */"Root", 0);
        attributes.add(/* NOI18N */"suffixForMainClass",
		    /* NOI18N */"java.lang.String", /* NOI18N */"Main", 0);
        attributes.add(/* NOI18N */"suffixForOpsClass",
		    /* NOI18N */"java.lang.String", /* NOI18N */"Ops", 0);
        attributes.add(/* NOI18N */"suffixForGroupClass",
		    /* NOI18N */"java.lang.String", /* NOI18N */"", 0);
        attributes.add(/* NOI18N */"showGenerateConsole",
		    /* NOI18N */"java.lang.Boolean", Boolean.TRUE, 0);
        
        attributes.add(/* NOI18N */"groupType",
		    /* NOI18N */"java.lang.String", null, 0);
        attributes.add(/* NOI18N */"appletSize",
		    /* NOI18N */"java.awt.Dimension", null, 0);
        
        /**
         * When autoNaming is true, new shadows added somewhere
         * under the
         * root will automatically be assigned unique names if their
         * name
         * attribute is null (see AMContainerHelper.)
         */
        attributes.add(/* NOI18N */"autoNaming",
		    /* NOI18N */"java.lang.Boolean", Boolean.TRUE,
		       HIDDEN | TRANSIENT);
        
        set(/* NOI18N */"name", getUniqueName(this));
    }
    
    protected String getUserTypeName() {
        return (/* NOI18N */"root");
    }
    
    /**
     * Sets the loaded root flag for this root.
     */
    void setLoadedRoot(boolean flag) {
        isLoadedRoot = flag;
    }
    
    /**
     * Returns the value of the loaded root flag.
     */
    public boolean isLoadedRoot() {
        return isLoadedRoot;
    }
    
    /**
     * The first child in the children vector is the main container.
     * To set the main child, we simply move the item to be selected
     * to the top of the list.
     *
     * This method should only called by the builder because this method
     * assumes that panels are wrapped with a window shadow.
     */
    void setMainChild(AttributeManager container, boolean isPanel) {
        AttributeManager prev = getMainChild();
        
        // menubar should be removed from a frame about to become the
        // surrounder for a main panel
        if ((container instanceof FrameShadow) &&
	    !((FrameShadow)container).isPanel() &&
	    isPanel && container.get(/* NOI18N */"menubar") != null) {
            container.set(/* NOI18N */"menubar", null);
        }
        
        WindowShadow win = null;
        WindowShadow prevwin = null;
        
        if (container instanceof WindowShadow)
            win = (WindowShadow)container;
        if (prev instanceof WindowShadow)
            prevwin = (WindowShadow)prev;
        
        if (prev == container) {
            if (win != null) {
                win.isPanel(isPanel);
                win.show();
            }
        } else {
            if (prevwin != null)
                prevwin.isPanel(false);
            
            // Select the prev so that the NameEditor will
            // load prev's "title"
            // attribute.  This way, when we switch off of prev,
            // prev's title won't
            // be wiped out by the name editor.
            observerSelect(prev);
            
            if (win != null) {
                win.isPanel(isPanel);
                win.show();
            }
            
            Vector children = containerHelper.getChildren();
            if (!children.removeElement(container))
                throw new Error(Global.fmtMsg(
			"sunsoft.jws.visual.rt.base.Root.RootMissingContainer",
					      getName(), container.getName()));
            children.insertElementAt(container, 0);
        }
        
        observerReload();
        observerSelect(container);
    }
    
    /**
     * Returns the main child of the root.  This will typically be
     * either a window or a panel.
     */
    public AttributeManager getMainChild() {
        Vector children = containerHelper.getChildren();
        if (children.size() > 0)
            return (AttributeManager)children.elementAt(0);
        else
            return null;
    }
    
    // List of root observers
    private Hashtable observers = new Hashtable();
    
    /**
     * Registers an observer for this root object.
     * The observer will receive
     * updates concerning groups or window shadows that are
     * added or removed
     * from this root.
     */
    void addRootObserver(RootObserver observer) {
        if (observer == null)
            return;
        
        if (observers.put(observer, observer) != null)
            return;
        
        observer.clear();
        Enumeration e = getChildList();
        while (e.hasMoreElements()) {
            AttributeManager mgr = (AttributeManager)e.nextElement();
            observer.add(mgr);
        }
    }
    
    /**
     * Unregisters an observer for this root object.
     */
    void removeRootObserver(RootObserver observer) {
        if (observer == null)
            return;
        
        observers.remove(observer);
    }
    
    private void observerAdd(AttributeManager mgr) {
        if (!(mgr instanceof WindowShadow) && !(mgr instanceof Group) &&
	    !(mgr instanceof BeanShadow))
	    return;
        
        Enumeration e = observers.elements();
        while (e.hasMoreElements())
            ((RootObserver)e.nextElement()).add(mgr);
    }
    
    private void observerRemove(AttributeManager mgr) {
        if (!(mgr instanceof WindowShadow) && !(mgr instanceof Group) &&
	    !(mgr instanceof BeanShadow))
	    return;
        
        Enumeration e = observers.elements();
        while (e.hasMoreElements())
            ((RootObserver)e.nextElement()).remove(mgr);
    }
    
    private void observerSelect(AttributeManager mgr) {
        Enumeration e = observers.elements();
        
        while (e.hasMoreElements())
            ((RootObserver)e.nextElement()).select(mgr);
    }
    
    private void observerReload() {
        Enumeration e1 = observers.elements();
        
        while (e1.hasMoreElements()) {
            RootObserver observer = (RootObserver)e1.nextElement();
            
            observer.clear();
            Enumeration e2 = containerHelper.getChildren().elements();
            while (e2.hasMoreElements())
                observer.add((AttributeManager)e2.nextElement());
        }
    }
    
    // Naming children validly and uniquely
    
    /**
     * A table containing ever-increasing counters for unique new names.
     * Isn't needed in runtime mode, only when the designer is running.
     */
    private Hashtable uniqueNameTable = null;
    
    /**
     * Clears the hashtable of unique name counters.
     * Should only be used when
     * restarting (user selects "File->New").
     */
    void clearUniqueNameTable() {
        uniqueNameTable = null;
    }
    
    /**
     * Returns true if the name chosen is unique and has not already
     * been used by one of the descendants of this root object.
     */
    boolean isUniqueName(String name) {
        return isUniqueName(this, name, null, null);
    }
    
    /**
     * Returns true if the name chosen is unique and has not already
     * been used by something under this root.  When encountered, the
     * "self" object is not compared, so you can also use this function
     * to test whether the name of an object that is within the tree is
     * unique unto itself.
     */
    boolean isUniqueName(String name, AttributeManager skip) {
        return isUniqueName(this, name, skip, null);
    }
    
    boolean isUniqueName(String name,
			 AttributeManager skip, AttributeManager prune) {
        return isUniqueName(this, name, skip, prune);
    }
    
    /**
     * Returns true if the name chosen is unique and has not already
     * been used by one of the descendants of the given AMContainer
     * object.  When encountered, the "self" object is not compared,
     * so you can also use this function to test whether the name of an
     * object that is within the tree is unique unto itself.
     */
    private boolean isUniqueName(AttributeManager mgr,
				 String name,
				 AttributeManager skip,
				 AttributeManager prune)
    {
        if (mgr == prune)
            return true;
        
        if ((mgr != skip) && name.equals(mgr.get(/* NOI18N */"name")))
            return false;
        
        if (mgr instanceof AMContainer) {
            AMContainer cntr = (AMContainer)mgr;
            Enumeration e = cntr.getChildList();
            while (e.hasMoreElements()) {
                mgr = (AttributeManager)e.nextElement();
                if (!isUniqueName(mgr, name, skip, prune))
                    return false;
            }
        }
        
        return true;
    }
    
    /**
     * The list of reserved words.  The java language reserved words and
     * also instance variable names already taken in the
     * AttributeManager or Root classes that cannot be used in names of
     * objects in the designer.
     */
    private static final String reservedWords[] = {
        /* NOI18N */"abstract", /* NOI18N */"boolean",
		    /* NOI18N */"break", /* NOI18N */"byte",
		    /* NOI18N */"byvalue",
		    /* NOI18N */"case", /* NOI18N */"cast",
	    /* NOI18N */"catch", /* NOI18N */"char", /* NOI18N */"class",
		    /* NOI18N */"const", /* NOI18N */"continue",
		    /* NOI18N */"default", /* NOI18N */"do",
		    /* NOI18N */"double", /* NOI18N */"else",
		    /* NOI18N */"extends",
		    /* NOI18N */"false", /* NOI18N */"final",
		    /* NOI18N */"finally", /* NOI18N */"float",
		    /* NOI18N */"for", /* NOI18N */"future",
		    /* NOI18N */"generic", /* NOI18N */"goto",
		    /* NOI18N */"if",
		    /* NOI18N */"implements", /* NOI18N */"import",
		    /* NOI18N */"inner", /* NOI18N */"instanceof",
		    /* NOI18N */"int",
		    /* NOI18N */"interface", /* NOI18N */"long",
		    /* NOI18N */"native",
		    /* NOI18N */"new", /* NOI18N */"null",
		    /* NOI18N */"operator", /* NOI18N */"outer",
		    /* NOI18N */"package",
		    /* NOI18N */"private",
		    /* NOI18N */"protected", /* NOI18N */"public",
		    /* NOI18N */"rest", /* NOI18N */"return",
		    /* NOI18N */"short", /* NOI18N */"static",
		    /* NOI18N */"super", /* NOI18N */"switch",
		    /* NOI18N */"synchronized", /* NOI18N */"this",
		    /* NOI18N */"throw",
		    /* NOI18N */"throws",
	    /* NOI18N */"transient", /* NOI18N */"true", /* NOI18N */"try",
	    /* NOI18N */"var", /* NOI18N */"void", /* NOI18N */"volatile",
		    /* NOI18N */"while",
		    /* NOI18N */"containerHelper", /* NOI18N */"READONLY",
		    /* NOI18N */"HIDDEN", /* NOI18N */"TRANSIENT",
		    /* NOI18N */"CONTAINER", /* NOI18N */"attributes",
		    /* NOI18N */"parent", /* NOI18N */"isCreated",
		    /* NOI18N */"GROUP", /* NOI18N */"ROOT" };
        
    // valid characters in variable names
    // I18N bug
    //  private static final String
    // validNameStarters="$abcdefghijklmnopqrstuvwxyz";
    // private static final String
    // validNameAnys=validNameStarters + "_0123456789";
        
    /**
     * Returns true if the given name could be legally
     * placed in generated
     * code where it would be compiled as a variable name.
     */
    static boolean isValidName(String name) {
	// check that the name isn't blank
	if (name == null || name.length() == 0)
	    return (false);
            
	// check that the name is not a reserved word (case counts!)
	for (int i = 0; i < reservedWords.length; i++)
	    if (name.equals(reservedWords[i]))
                return (false);
	/* JSTYLED */
	/*  I18n BUG
            // check that the name starts with a valid start
            // character (not a number)
            String s = name.toLowerCase();
            if (validNameStarters.indexOf(s.substring(0, 1)) == -1)
	    return (false);
            
            // check that the rest of the characters in the name
            // are valid
            for (int i = 1; i < name.length(); i++)
	    if (validNameAnys.indexOf(s.substring(i, i+1)) == -1)
	    return (false);
	*/
            
	for (int i = 0; i < name.length(); i++) {
	    if ((i == 0) &&
                (!Character.isJavaIdentifierStart(name.charAt(i))))
                return false;
	    else
		if (!Character.isJavaIdentifierPart(name.charAt(i)))
                    return false;
	}
	return (true);
    }
        
    /**
     * Returns a unique name that can be used for a new
     * shadow object.
     * The names are guaranteed to be valid variable names for a
     * generated Root sub-class later on.
     */
    String getUniqueName(AttributeManager child) {
	// delayed creation of the table (this routine never
	// called in runtime)
	if (uniqueNameTable == null)
	    uniqueNameTable = new Hashtable();
            
	String type = child.getUserTypeName();
	String retval = null;
            
	while (retval == null || !isUniqueName(retval) ||
	        !isValidName(retval)) {
	    if (uniqueNameTable.containsKey(type)) {
		int count = ((Integer)
			     uniqueNameTable.get(type)).intValue();
		uniqueNameTable.put(type, new Integer(count + 1));
		retval = type + Integer.toString(count);
	    } else {
		uniqueNameTable.put(type, new Integer(2));
		retval = type + /* NOI18N */"1";
	    }
	}
	return (retval);
    }
        
    /**
     * Returns a name that is unique not only within this root,
     * but within
     * another as well.  This is useful when merging two roots.
     */
    String getUniqueName(AttributeManager child, Root otherTree) {
	// because of the unique name counters, we can repeatedly call
	// getUniqueName without getting the same name over again
	String newName = getUniqueName(child);
	while (!otherTree.isUniqueName(newName))
	    newName = getUniqueName(child);
	return (newName);
    }
        
    /**
     * Returns a string describing what is wrong with given
     * name choice.
     * The string can be used in an error popup or status bar line.
     * Null is returned when there is no problem with the name.
     */
    String getProblemWithName(String name) {
	String errorMsg = null;
            
	if (name == null || name.length() == 0)
	    errorMsg = Global.getMsg(
		    "sunsoft.jws.visual.rt.base.Root.NeedName");
	else if (!isUniqueName(name))
	    errorMsg = Global.fmtMsg(
		    "sunsoft.jws.visual.rt.base.Root.NotUniqueName", name);
	else if (!isValidName(name))
	    errorMsg = Global.fmtMsg(
		    "sunsoft.jws.visual.rt.base.Root.NotValidName", name);
            
	return (errorMsg);
    }
        
    //
    // Overridden to deal with the special "GROUP" and "ROOT" names.
    //
    public AttributeManager resolve(String name) {
	if (name == null)
	    return null;
	else if (name.equals(/* NOI18N */"GROUP"))
	    return group;
	else if (name.equals(/* NOI18N */"ROOT"))
	    return this;
	else
	    return super.resolve(name);
    }
        
    // AMContainer interfaces
        
    public void add(AttributeManager child) {
	containerHelper.add(child);
	observerAdd(child);
    }
        
    public void remove(AttributeManager child) {
	containerHelper.remove(child);
	observerRemove(child);
    }
        
    //
    // The root's "addChildBody" and "removeChildBody"
    // methods are only
    // called when the root has a panel as a child.
    //  In this case, it should
    // add the panel as a child of the group's parent.
    //
        
    public void addChildBody(Shadow child) {
	// Don't add frames and dialogs to the group's parent
	if (child instanceof WindowShadow)
	    return;
            
	if (group == null)
	    return;
            
	AMContainer parent = group.getParent();
	if (parent == null)
	    return;
            
	if (child != null && child.getBody() != null)
	    parent.addChildBody(child);
    }
        
    public void updateContainerAttribute(AttributeManager child,
					 String key, Object value) {
	if (group == null)
	    return;
            
	AMContainer parent = (AMContainer)group.getParent();
	if (parent == null)
	    return;
            
	parent.updateContainerAttribute(child, key, value);
    }
        
    public void removeChildBody(Shadow child) {
	// Don't need to remove frames and dialogs from
	// the group's parent
	if (child instanceof WindowShadow)
	    return;
            
	if (group == null)
	    return;
            
	AMContainer parent = group.getParent();
	if (parent == null)
	    return;
            
	if (child != null && child.getBody() != null)
	    parent.removeChildBody(child);
    }
        
    public void createChildren() {
	containerHelper.createChildren();
    }
        
    public void reparentChildren() {
	containerHelper.reparentChildren();
    }
        
    public void destroyChildren() {
	containerHelper.destroyChildren();
    }
        
    public AttributeManager getChild(String name) {
	return (containerHelper.getChild(name));
    }
        
    public Enumeration getChildList() {
	return (containerHelper.getChildList());
    }
        
    public int getChildCount() {
	return (containerHelper.getChildCount());
    }
        
    /**
     * Groups
     */
        
    private Group group;
        
    public void setGroup(Group group) {
	if (this.group != null)
	    this.group.removeRootChildren(this);
            
	this.group = group;
            
	if (this.group != null)
	    this.group.addRootChildren(this);
    }
        
    public Group getGroup() {
	return group;
    }
        
    /**
     * Sets the cursor for all of the root's frames.  This method is
     * declared package private so that it won't be
     * confused with the
     * group's setCursor method.
     */
    void setCursor(int cursor) {
	Enumeration e = getChildList();
	while (e.hasMoreElements()) {
	    AttributeManager mgr = (AttributeManager)e.nextElement();
	    if (mgr instanceof FrameShadow) {
		FrameShadow fs = (FrameShadow)mgr;
		Frame f = (Frame)fs.getBody();
                    
		if (f != null) {
		    int prevCursor = f.getCursorType();
		    if (cursor == prevCursor) {
			JAShadowAccess.incrCursor(fs);
		    } else if (cursor == Group.RESTORE_CURSOR) {
			if (JAShadowAccess.decrCursor(fs) == 0) {
			    f.setCursor(
					JAShadowAccess.getPrevCursor(fs));
			    JAShadowAccess.setPrevCursor(fs,
							 Frame.DEFAULT_CURSOR);
			}
		    } else {
			JAShadowAccess.setPrevCursor(fs, prevCursor);
			f.setCursor(cursor);
			f.getToolkit().sync();
		    }
		}
	    }
	}
    }
        
    /**
     * Maps all the visible children of the root.  Do not call this
     * method directly.  It is called from the Group class when the
     * group is shown.
     */
    public void showRoot() {
	AttributeManager mgr;
	Enumeration e = getChildList();
            
	while (e.hasMoreElements()) {
	    mgr = (AttributeManager)e.nextElement();
	    if (mgr instanceof ComponentShadow) {
		ComponentShadow comp = (ComponentShadow)mgr;
		Boolean v = (Boolean)comp.get(/* NOI18N */"visible");
		if (v.booleanValue())
		    comp.showComponent();
	    } else if (mgr instanceof Group) {
		Group group = (Group)mgr;
		Boolean v = (Boolean)group.get(/* NOI18N */"visible");
		if (v.booleanValue())
		    group.internalShowGroup();
	    }
	}
    }
        
    /**
     * Unmaps all the children of the root.  Do not call this
     * method directly.  It is called from the Group class when the
     * group is hidden.
     */
    public void hideRoot() {
	AttributeManager mgr;
	Enumeration e = getChildList();
            
	while (e.hasMoreElements()) {
	    mgr = (AttributeManager)e.nextElement();
	    if (mgr instanceof ComponentShadow)
		((ComponentShadow)mgr).hideComponent();
	    else if (mgr instanceof Group)
		((Group)mgr).internalHideGroup();
	}
    }
        
    /**
     * Events
     */
        
    private boolean eventForwardingDisabled;
        
    public void postMessageToParent(Message msg) {
	if (group != null && !eventForwardingDisabled)
	    group.postMessage(msg);
    }
        
    public void postMessage(Message msg) {
	if (!handleMessage(msg) && group != null &&
            !eventForwardingDisabled)
            group.postMessage(msg);
    }
        
    public void postEvent(Message msg) {
	if (handleMessage(msg))
	    return;
            
	if (group != null && !eventForwardingDisabled)
	    group.postMessage(msg);
    }
        
    void disableEventForwarding() {
	eventForwardingDisabled = true;
    }
        
    void enableEventForwarding() {
	eventForwardingDisabled = false;
    }
        
    public void layoutMode() {
	super.layoutMode();
	containerHelper.layoutMode();
    }
        
    public void previewMode() {
	super.previewMode();
	containerHelper.previewMode();
    }
}
