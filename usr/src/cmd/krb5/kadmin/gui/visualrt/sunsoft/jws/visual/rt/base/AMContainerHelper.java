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
 * @(#) AMContainerHelper.java 1.41 - last change made 06/17/97
 */

package sunsoft.jws.visual.rt.base;

import sunsoft.jws.visual.rt.base.Global;

import sunsoft.jws.visual.rt.shadow.java.awt.ComponentShadow;

import java.util.Vector;
import java.util.Enumeration;

/**
 * This is a helper class for shadow containers.  Shadow containers are
 * nodes in the shadow tree.  A shadow container should implement the
 * AMContainer interface.
 *
 * @version 	1.41, 06/17/97
 */
public class AMContainerHelper {
    /**
     * The container that is being assisted by this helper class.
     */
    private AMContainer container;
    
    /**
     * A list of any shadow children a particular shadow instance
     * might have.
     * This is used to describe the hierarchical relationship of
     *  graphical
     * objects in the interface.
     */
    private Vector children;
    
    /**
     * Constructor.
     */
    public AMContainerHelper(AMContainer container) {
        this.container = container;
        children = new Vector();
    }
    
    /**
     * Returns the list of children this helper is keeping track
     * of for the
     * container.
     */
    public Vector getChildren() {
        return children;
    }
    
    /**
     * Returns a list of the children that the caller can use
     * only for reading
     * and cannot alter.  The list is cloned because the caller
     * might use it
     * for removing children from the container.
     */
    public Enumeration getChildList() {
        return ((Vector) children.clone()).elements();
    }
    
    /**
     * Returns the number of children in the container.
     */
    public int getChildCount() {
        return children.size();
    }
    
    /**
     * Adds a child.
     */
    public void add(AttributeManager child) {
        if (child != null && !children.contains(child)) {
            // check to see that child isn't one of this container's parents
            if (child instanceof AMContainer) {
                for (AMContainer cn = container; cn != null;
		     cn = ((AttributeManager)cn).getParent()) {
                    if (cn == child) {
                        throw new IllegalArgumentException(Global.getMsg(
"sunsoft.jws.visual.rt.base.AMContainerHelper.adding__container's__p.0"));
                    }
                }
            }
            
            if (child.getParent() != null) {
                child.getParent().remove(child);
            }
            
            child.setParent(container);
            children.addElement(child);
            
            // Update the group tree
            recurseCheckAdd(child);
            
            // Update the AWT tree
            if ((child instanceof Shadow) && ((Shadow)child).getBody()
                != null) {
                container.addChildBody((Shadow) child);
            }
            
            // Update the mode
            AttributeManager mgr = (AttributeManager)container;
            if (mgr.isLayoutMode() != child.isLayoutMode()) {
                if (mgr.isLayoutMode())
                    child.layoutMode();
                else
                    child.previewMode();
            }
        }
    }
    
    private void recurseCheckAdd(AttributeManager child) {
        /**
         * AttributeManager instances are created with the "name"
         * attribute set to null.  This is fine when the new instances
         * are being created by generated code (runtime mode) or
         * are being
         * loaded from a file.  In both these cases the name has
         * just been
         * or is about to be set to something unique.
         *
         * The case we are watching for here is when the top-level
         * root in
         * the designer (build mode) tries to to create and add a new
         * AtttributeManager object.  In this case a unique default name
         * must be created here (so that every object in a new 
         * application
         * has a unique name.)
         */
        Root root = child.getRoot();
        if (root != null && child.get(/* NOI18N */"name") == null
	    && ((Boolean)
		root.get(/* NOI18N */"autoNaming")).booleanValue())
	    child.set(/* NOI18N */"name", root.getUniqueName(child));
        
        if (child instanceof Group) {
            if (child.getRoot() != null) {
                Group group = child.getRoot().getGroup();
                if (group != null)
                    group.add((Group)child);
                
                ((Group)child).setParentBody();
            }
        } else if (child instanceof AMContainer) {
            AMContainer cntr = (AMContainer)child;
            Enumeration e = cntr.getChildList();
            while (e.hasMoreElements())
                recurseCheckAdd((AttributeManager)e.nextElement());
        }
    }
    
    /**
     * Removes a child.
     */
    public void remove(AttributeManager child) {
        if (child != null) {
            if (child.getParent() != container)
                return;
            
            // update the the global register for unsaved changes
            Root theRoot = child.getRoot();
            if (theRoot != null && theRoot.isLoadedRoot())
                DesignerAccess.setChangesMade(true);
            
            // Update the AWT tree
            if ((child instanceof Shadow) && ((Shadow)child).getBody()
                != null) {
                container.removeChildBody((Shadow) child);
            }
            
            // Update the group tree
            recurseCheckRemove(child);
            
            // Remove the child from the tree
            child.setParent(null);
            children.removeElement(child);
        }
    }
    
    private void recurseCheckRemove(AttributeManager child) {
        if (child instanceof Group) {
            if (child.getRoot() != null) {
                Group group = child.getRoot().getGroup();
                if (group != null)
                    group.remove((Group)child);
                
                ((Group)child).unsetParentBody();
            }
        } else if (child instanceof AMContainer) {
            AMContainer cntr = (AMContainer)child;
            Enumeration e = cntr.getChildList();
            while (e.hasMoreElements())
                recurseCheckRemove((AttributeManager)e.nextElement());
        }
    }
    
    /**
     * Finds a child (by name.)
     */
    public AttributeManager getChild(String name) {
        if (name != null) {
            for (Enumeration e = children.elements();
		 /* JSTYLED */
		 e.hasMoreElements(); ) {
		AttributeManager child = (AttributeManager)
		    e.nextElement();
		if (name.equals(child.get(/* NOI18N */"name")))
		    return (child);
	    }
	}
	return (null);
    }

    /**
     * Create the container's children.
     */
    public void createChildren() {
	for (Enumeration e = children.elements(); e.hasMoreElements(); )
        
	    {
		AttributeManager mgr = (AttributeManager) e.nextElement();
        
		// Don't create the child if it isn't visible
		if (mgr.hasAttribute(/* NOI18N */"visible")) {
		    Boolean v = (Boolean)mgr.get(/* NOI18N */"visible");
		    if (v.booleanValue())
			mgr.create();
		}
		else
		    {
			mgr.create();
		    }
	    }
    }

    /**
     * Destroy all the children of the container.
     */
    public void destroyChildren() {
	for (Enumeration e = children.elements(); e.hasMoreElements(); )
	    ((AttributeManager) e.nextElement()).destroy();
    }

    /**
     * Reparent the children of the container.  This is called when the
     * container is being recreated.
     */
    public void reparentChildren() {
	for (Enumeration e = children.elements(); e.hasMoreElements(); )
        
	    {
		AttributeManager child = (AttributeManager)e.nextElement();
		if ((child instanceof Shadow) && ((Shadow)child).getBody()
		    != null) {
		    container.addChildBody((Shadow) child);
		}
	    }
    }

    //
    // Layout and Preview mode
    //

    public void layoutMode() {
	for (Enumeration e = children.elements(); e.hasMoreElements(); )
        
	    {
		AttributeManager child = (AttributeManager)e.nextElement();
		child.layoutMode();
	    }
    }

    public void previewMode() {
	for (Enumeration e = children.elements(); e.hasMoreElements(); )
        
	    {
		AttributeManager child = (AttributeManager)e.nextElement();
		child.previewMode();
	    }
    }

    public void preValidate() {
	for (Enumeration e = children.elements(); e.hasMoreElements(); )
        
	    {
		AttributeManager child = (AttributeManager)e.nextElement();
		child.preValidate();
	    }
    }
}
