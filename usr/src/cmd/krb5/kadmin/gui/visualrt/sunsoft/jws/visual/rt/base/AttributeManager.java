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
 * @(#) AttributeManager.java 1.83 - last change made 07/29/97
 */

package sunsoft.jws.visual.rt.base;

import sunsoft.jws.visual.rt.type.Op;

import java.awt.Event;
import java.util.*;

/*
 * NOTE: Whenever a new public or protected variable is added to this
 * class
 * the name of the variable must be added to the reserved words list
 * in the
 * Root class so that the user doesn't use it in one of the
 * generated Root
 * sub-classes.
 */

/**
 * The AttributeManager class is a base class for objects that
 * have attributes.  The Shadow and Group classes are sub-classed
 * from AttributeManager.
 * <p>
 * The attributes available for this
 * class are listed below.  In the type column, type names beginning
 * with "sunsoft.jws.visual.rt" have been abbreviated to begin
 * with "rt".
 *
 * <pre>
 * name            type                      default value
 * -----------------------------------------------------------------------
 * name            java.lang.String          null
*  < /pre>
*
* @version 1.83, 07/29/97
*/
public class AttributeManager {
    /**
     * Flags
     */
    
    /**
     * Indicates a readonly attribute.  An attempt
     * to set the attribute will result in an error.
     */
    public static final int READONLY = 0x1;
    
    /**
     * Flags attributes that will not be shown in the Visual Java
     * attribute editor.
     */
    public static final int HIDDEN = 0x2;
    
    /**
     * Flags attributes that will not be stored in the
     * save file.
     */
    public static final int TRANSIENT = 0x4;
    
    /**
     * The parent will be notified by calling updateContainerAttribute
     * on the parent whenever a CONTAINER attribute is changed.
     */
    public static final int CONTAINER = 0x8;
    
    /**
     * This flag indicates that the default value for the attribute
     * matches the default value for the AWT body.  If this flag is
     * set, the setOnBody method will not be called during
     * creation unless the value is actually changed.
     * <p>
     * Similarly for groups, if the DEFAULT flag is set, then
     * setOnGroup will only be called during initialization if the
     * attribute has actually changed.  Otherwise setOnGroup will
     * be called regardless of whether the attribute has changed.
     * <p>
     * Note: This flag should only be used where performance is a
     * concern, since resetting the default value on the AWT body
     * should not change its behavior.
     * <p>
     */
    public static final int DEFAULT = 0x10;
    
    /**
     * This flag tells the attribute manager to not refetch the value
     * of the attribute list during the refetchAttributes call.  This
     * is useful for the AWT component fonts and colors that are
     * inherited from their parent when set to null.
     * If this flag were not set for those attributes, then they
     * would end up everywhere in the save file.
     */
    public static final int DONTFETCH = 0x20;
    
    /**
     * This flag tells the attribute editor's slot that it should
     * not use
     * a type editor for this attribute, even if there is one
     * registered.
     */
    public static final int NOEDITOR = 0x400;
    
    /**
     * The table where attributes are stored.
     * Attributes may be added to this list during construction, but
     * should not be added at any other time.
     */
    protected AttributeList attributes;
    
    /**
     * The parent of this object.
     */
    AMContainer parent;
    
    /**
     * A flag that is true once create() has been performed on a shadow
     * object and remains so until destroy() is called.
     */
    boolean isCreated = false;
    
    /**
     * Flag for storing the return value of inDesignerRoot while we
     * are created.  This speeds up the check in sendToOps.
     */
    private Boolean inDesignerRoot = null;
    
    /**
     * Creates the attributes list and assigns a unique name to this
     * attribute manager.  Attributes may be added to the list of
     * attributes
     * in sub-class constructors, but should not be added at any
     * other time.
     */
    public AttributeManager() {
        attributes = new AttributeList();
        
        // name will be set around the time this object is added
        // to a container
        attributes.add(/* NOI18N */"name",
		       /* NOI18N */"java.lang.String", null,
		       Shadow.NONBODY | NOEDITOR);
        
        // operations for defining callbacks
        attributes.add(/* NOI18N */"operations",
		       /* NOI18N */"[Lsunsoft.jws.visual.rt.type.Op;", null,
		       Shadow.NONBODY);
    }
    
    /**
     * Returns the parent for this attribute manager.
     */
    public AMContainer getParent() {
        return parent;
    }
    
    /**
     * Sets the parent for this attribute manager.
     */
    public void setParent(AMContainer parent) {
        this.parent = parent;
    }
    
    /**
     * Returns true if we are not running inside the designer.
     */
    public boolean isLive() {
        Root r = getRoot();
        while (r != null) {
            if (r.isLoadedRoot())
                return false;
            
            Group group = r.getGroup();
            if (group == null)
                break;
            
            r = group.getRoot();
        }
        
        return true;
    }
    
    /**
     * Returns true if this instance is a direct descendant
     * of the designer root.  Being a direct descendant means
     * that there are no intermediate groups between this
     * attribute manager and the root.
     * The designer root is the root that is built inside
     * Visual Java.
     */
    public boolean inDesignerRoot() {
        if (inDesignerRoot != null)
            return inDesignerRoot.booleanValue();
        else
            return checkDesignerRoot();
    }
    
    private boolean checkDesignerRoot() {
        Root myRoot = getRoot();
        return (myRoot != null && myRoot.isLoadedRoot());
    }
    
    /**
     * Returns a type name suitable for use in making unique names for
     * instances of this class (or one of its sub-classes).  This should
     * be overridden in sub-classes to give more useful names.
     */
    protected String getUserTypeName() {
        return (/* NOI18N */"manager");
    }
    
    /**
     * Puts an attribute's value directly into the attribute table.
     */
    protected final void putInTable(String key, Object value) {
        Attribute a = attributes.get(key);
        if (a == null)
            throw new Error(Global.fmtMsg(
"sunsoft.jws.visual.rt.base.AttributeManager.SetInvalidAttribute", key));
        if (a.flagged(READONLY))
            throw new Error(Global.fmtMsg(
"sunsoft.jws.visual.rt.base.AttributeManager.ReadonlyAttribute", key));
        
        a.setValue(value);
    }
    
    /**
     * Gets an attribute's value directly from the attribute table.
     */
    protected final Object getFromTable(String key) {
        Attribute a = attributes.get(key);
        if (a == null)
            throw new Error(Global.fmtMsg(
"sunsoft.jws.visual.rt.base.AttributeManager.GetInvalidAttribute", key));
        
        return (a.getValue());
    }
    
    /**
     * Sets an attribute in this object's attribute list.  This may be
     * overridden in sub-classes to introduce special behavior for the
     * setting of some attributes.
     */
    public void set(String key, Object value) {
        putInTable(key, value);
        
        // update the the global register for unsaved changes
        if (inDesignerRoot())
            DesignerAccess.setChangesMade(true);
    }
    
    /**
     * Gets an attribute from this shadow object's attribute list.  This
     * may be overridden in sub-classes to introduce special behavior
     * for the getting of some attributes.
     */
    public Object get(String key) {
        return (getFromTable(key));
    }
    
    /**
     * Returns the type string for the attribute,
     * or null if the attribute does not exist.
     */
    public String getType(String key) {
        Attribute attr = attributes.get(key);
        if (attr != null)
            return attr.getType();
        else
            return null;
    }
    
    /**
     * Returns true if the attribute has the flag set, otherwise false.
     */
    public int getFlags(String key) {
        Attribute attr = attributes.get(key);
        if (attr != null)
            return attr.getFlags();
        else
            return 0;
    }
    
    /**
     * Returns true if the attribute exists, otherwise return false.
     */
    public boolean hasAttribute(String key) {
        return (attributes.get(key) != null);
    }
    
    /**
     * Return true if the attribute exists and the type matches,
     * otherwise return false.
     */
    public boolean hasAttribute(String key, String type) {
        Attribute attr = attributes.get(key);
        if (attr != null)
            return attr.getType().equals(type);
        else
            return false;
    }
    
    /**
     * Apply all the CONTAINER attributes in the child to the
     * given parent.
     */
    public void updateContainerAttributes(AMContainer parent,
					  AttributeManager child)
    {
        Enumeration e = child.attributes.elements();
        while (e.hasMoreElements()) {
            Attribute a = (Attribute)e.nextElement();
            if (a.flagged(CONTAINER))
                parent.updateContainerAttribute(child, a.getName(),
						a.getValue());
        }
    }
    
    /**
     * Return a reference to the entire table of attributes.
     */
    public AttributeList getAttributeList() {
        refetchAttributeList();
        
        // Perhaps the attribute list should be cloned here.
        // But this would
        // cause a performance loss.  Anyone using getAttributeList
        // should NOT modify the values of any of the attributes,
        // especially those
        // that have the DONTFETCH flag set.
        return attributes;
    }
    
    Attribute getAttribute(String name) {
        return (Attribute)attributes.get(name);
    }
    
    /**
     * Calls get for all the attributes, and then stores the values
     * directly in the attribute hash table.  This ensures that the
     * list of attributes is up to date.
     */
    public void refetchAttributeList() {
        Enumeration e = attributes.elements();
        while (e.hasMoreElements()) {
            Attribute attr = (Attribute)e.nextElement();
            if (!attr.flagged(DONTFETCH | READONLY)) {
                String name = attr.getName();
                putInTable(name, get(name));
            }
        }
    }
    
    /*
     * Finds a component recursively by name.
     */
    public AttributeManager resolve(String name) {
        if (name == null)
            return null;
        
        if (name.equals(getFromTable(/* NOI18N */"name")))
            return this;
        
        if (this instanceof AMContainer) {
            for (Enumeration e = ((AMContainer) this).getChildList();
		 /* JSTYLED */
		 e.hasMoreElements(); ) {
		AttributeManager child = (AttributeManager)
		    e.nextElement();
		AttributeManager s = child.resolve(name);
		if (s != null)
		    return s;
	    }
	}
    
	return null;
    }

    /**
     * Finds a component from its full path name.
     */
    public AttributeManager resolveFullName(String name) {
	Group group = getGroup();
	if (group != null)
	    return group.resolveFullName(name);
	else
	    return null;
    }

    /**
     * Returns the body for a shadow after resolving it.
     */
    public Object resolveBody(String name) {
	AttributeManager obj = resolve(name);
	if (obj == null)
	    return null;
	if (!(obj instanceof Shadow))
	    return null;
    
	return ((Shadow)obj).getBody();
    }

    /**
     * Returns the name for this attribute manager.
     */
    public String getName() {
	return (String)get(/* NOI18N */"name");
    }

    /**
     * Returns a hierarchy name based on the group tree.
     */
    public String getFullName() {
	String name = getName();
    
	Group group = getGroup();
	if (group != null) {
	    String groupName = group.getFullName();
	    if (groupName != null)
		name = groupName + /* NOI18N */"." + name;
	}
    
	return name;
    }

    /**
     * Initialize the object.  Only useful for groups.
     */
    public void initialize() {
    }

    /**
     * Create the object.  The AWT components are constructed
     * during creation.
     */
    public void create() {
	isCreated = true;
	inDesignerRoot = new Boolean(checkDesignerRoot());
    
	// if this is a container create its children
	if (this instanceof AMContainer)
	    ((AMContainer) this).createChildren();
    }

    /**
     * Returns true if the attribute manager is created.
     */
    public boolean isCreated() {
	return isCreated;
    }

    /**
     * Recreates this object after a CONSTRUCTOR attribute has been set
     * (overridden in Shadow).
     */
    public void recreate() {
    }

    /**
     * This method is overridden in most sub-classes.  It should be the
     * opposite of create() and should have the same ability to be
     * called safely multiple times.
     */
    public void destroy() {
	isCreated = false;
	inDesignerRoot = null;
    
	// destroy all the children of this shadow object
	if (this instanceof AMContainer)
	    ((AMContainer) this).destroyChildren();
    }

    /**
     * Returns a string that shows the hierarchy of shadow objects.
     * Starts first one (the caller) off as the top level.
     */
    public String hierarchy() {
	return (hierarchy(0));
    }

    /**
     * Returns a string that shows the hierarchy of shadow objects.
     */
    private String hierarchy(int level) {
	String indent = /* NOI18N */"";
	for (int i = 0; i < level; i++)
	    indent = indent + /* NOI18N */"    ";
    
	String kids = /* NOI18N */"";
	if (this instanceof AMContainer) {
	    for (Enumeration e = ((AMContainer) this).getChildList();
		 /* JSTYLED */
		 e.hasMoreElements(); )
		kids = kids + ((AttributeManager)
			       e.nextElement()).hierarchy(level + 1);
	}
    
	return (indent + getFromTable(/* NOI18N */"name")
		+ Global.newline() + kids);
    }

    /**
     * Returns a String that represents the value of this Object.
     */
    public String toString() {
	return (super.toString() + /* NOI18N */"["
		+ ((this instanceof AMContainer) ?
		   /* NOI18N */"container" : /* NOI18N */"nonContainer")
		+ /* NOI18N */"]");
    }

    /**
     * Returns the root for this object, or null if these is no root.
     */
    public Root getRoot() {
	AttributeManager mgr = this;
    
	while (mgr != null && !(mgr instanceof Root))
	    mgr = (AttributeManager)mgr.getParent();
    
	return (Root)mgr;
    }

    /**
     * Returns the group for this object, or null if there is none.
     */
    public Group getGroup() {
	Root root = getRoot();
	if (root != null)
	    return root.getGroup();
	else
	    return null;
    }

    /**
     * Returns the group that is forwarding the specified attribute
     * to this attribute manager.  Return null if the attribute is not
     * being forwarded from any group.
     */
    protected Group getForwardingGroup(String attributeName) {
	Root root = getRoot();
	Group group = root.getGroup();
	Group parent;
    
	if (group != null) {
	    if (group.hasAttributeForward(this, attributeName)) {
		parent = group.getParentGroup();
		while (parent != null &&
		       parent.hasAttributeForward(group, attributeName)) {
		    group = parent;
		    parent = group.getParentGroup();
		}
		return group;
	    }
	}
    
	return null;
    }

    /**
     * replicate is used by Visual Java for cut and paste.
     */
    public AttributeManager replicate() {
	// Create a new instance of the AttributeManager
	AttributeManager newMgr = null;
	try {
	    newMgr = (AttributeManager)getClass().newInstance();
	}
	catch (InstantiationException ex) {
	    // Perhaps this should be an Exception?
	    System.out.println(ex.getMessage()
			       + /* NOI18N */" " + this);
	}
	catch (IllegalAccessException ex) {
	    // Perhaps this should be an Exception?
	    System.out.println(ex.getMessage()
			       + /* NOI18N */" " + this);
	}
	if (newMgr == null)
	    return null;
    
	// Copy the attribute list
	AttributeList list = getAttributeList();
	Enumeration e = list.elements();
	while (e.hasMoreElements()) {
	    Attribute attr = (Attribute)e.nextElement();
	    if (!attr.flagged(TRANSIENT | READONLY))
		newMgr.set(attr.getName(), attr.getValue());
	}
    
	// Replicate the children
	if (this instanceof AMContainer) {
	    AMContainer newCntr = (AMContainer)newMgr;
	    e = ((AMContainer)this).getChildList();
        
	    while (e.hasMoreElements()) {
		AttributeManager child = (AttributeManager)
		    e.nextElement();
		newCntr.add(child.replicate());
	    }
	}
    
	return newMgr;
    }

    //
    // Events
    //

    /**
     * Posts a message to this object's parent.
     */
    public void postMessageToParent(Message msg) {
	if (parent != null)
	    ((AttributeManager)parent).postMessage(msg);
    }

    /**
     * Posts a message to this object.
     */
    public void postMessage(Message msg) {
	if (inDesignerRoot())
	    sendToOps(msg);
    
	if (!handleMessage(msg) && parent != null)
	    ((AttributeManager)parent).postMessage(msg);
    }

    private void sendToOps(Message msg) {
	Op ops[] = (Op[])get(/* NOI18N */"operations");
	if (ops != null) {
	    for (int i = 0; i < ops.length; i++) {
		ops[i].filter.target = this;
            
		if (ops[i].scope == null)
		    ops[i].scope = getRoot();
            
		// Don't handle GROUP actions
		if (ops[i].action != null &&
		    ops[i].action.target != null &&
		    ops[i].action.target.getName() != null &&
		    ops[i].action.target.getName().equals(/* NOI18N */"GROUP"))
		    continue;
            
		ops[i].handleMessage(msg);
	    }
	}
    }

    /**
     * May be overridden by subclasses that want to act
     * on messages that are sent to this object.
     */
    public boolean handleMessage(Message msg) {
	if (msg.isAWT)
	    return handleEvent(msg, (Event)msg.arg);
	else
	    return false;
    }

    /**
     * May be overridden by subclasses that want to act
     * on AWT events that are sent to this object.
     */
    public boolean handleEvent(Message msg, Event evt) {
	switch (evt.id) {
        case Event.MOUSE_ENTER:
	    return mouseEnter(msg, evt, evt.x, evt.y);
        case Event.MOUSE_EXIT:
	    return mouseExit(msg, evt, evt.x, evt.y);
        case Event.MOUSE_MOVE:
	    return mouseMove(msg, evt, evt.x, evt.y);
        case Event.MOUSE_DOWN:
	    return mouseDown(msg, evt, evt.x, evt.y);
        case Event.MOUSE_DRAG:
	    return mouseDrag(msg, evt, evt.x, evt.y);
        case Event.MOUSE_UP:
	    return mouseUp(msg, evt, evt.x, evt.y);
        
        case Event.KEY_PRESS:
        case Event.KEY_ACTION:
	    return keyDown(msg, evt, evt.key);
        case Event.KEY_RELEASE:
        case Event.KEY_ACTION_RELEASE:
	    return keyUp(msg, evt, evt.key);
        
        case Event.ACTION_EVENT:
	    return action(msg, evt, evt.arg);
        case Event.GOT_FOCUS:
	    return gotFocus(msg, evt, evt.arg);
        case Event.LOST_FOCUS:
	    return lostFocus(msg, evt, evt.arg);
        
        default:
	    return false;
	}
    }

    public boolean mouseDown(Message msg, Event evt, int x, int y) {
	return false;
    }

    public boolean mouseDrag(Message msg, Event evt, int x, int y) {
	return false;
    }

    public boolean mouseUp(Message msg, Event evt, int x, int y) {
	return false;
    }

    public boolean mouseMove(Message msg, Event evt, int x, int y) {
	return false;
    }

    public boolean mouseEnter(Message msg, Event evt, int x, int y) {
	return false;
    }

    public boolean mouseExit(Message msg, Event evt, int x, int y) {
	return false;
    }

    public boolean keyDown(Message msg, Event evt, int key) {
	return false;
    }

    public boolean keyUp(Message msg, Event evt, int key) {
	return false;
    }

    public boolean action(Message msg, Event evt, Object what) {
	return false;
    }

    public boolean gotFocus(Message msg, Event evt, Object what) {
	return false;
    }

    public boolean lostFocus(Message msg, Event evt, Object what) {
	return false;
    }

    /**
     * isLayoutMode - Are we in layout mode?
     */
    private boolean layoutMode = false;

    /**
     * Returns a boolean indicating if this object is in layout mode.
     */
    public boolean isLayoutMode() {
	return layoutMode;
    }

    /**
     * Called when Visual Java switches to layout mode.
     */
    public void layoutMode() {
	layoutMode = true;
    }

    /**
     * Called when Visual Java switches to preview mode.
     */
    public void previewMode() {
	layoutMode = false;
    }

    /**
     * Called after addNotify and before the window is reshaped.
     */
    protected void preValidate() {
    }
}
