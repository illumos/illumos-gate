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
 * @(#) ContainerShadow.java 1.48 - last change made 08/05/97
 */

package sunsoft.jws.visual.rt.shadow.java.awt;

import sunsoft.jws.visual.rt.base.*;
import sunsoft.jws.visual.rt.awt.GBLayout;
import java.util.Enumeration;
import java.awt.Container;
import java.awt.Component;
import java.awt.SystemColor;

/**
 * Wraps an AWT widget.  The attributes available for this
 * class are listed below.  In the type column, type names beginning
 * with "sunsoft.jws.visual.rt" have been abbreviated to begin with "rt".
 *
 * <pre>
name            type                      default value
-----------------------------------------------------------------------
none
*  < /pre>
*
* Check the super class for additional attributes.
*
* @see Container
* @version 	1.48, 08/05/97
*/
public class ContainerShadow
    extends ComponentShadow implements AMContainer
{
    private AMContainerHelper helper = new AMContainerHelper(this);
    
    ContainerShadow() {
        attributes.add("enabled", "java.lang.Boolean", Boolean.TRUE, HIDDEN);
        
        if (Global.isMotif()) {
            // Set the Container colors to use the system colors.  In
            // Motif Components inherit colors from the Container.
            // ComponentShadow, the bg and fg were set to null so all
            // components will use these colors.
            attributes.add(/* NOI18N */"foreground",
			   /* NOI18N */"java.awt.Color",
			   SystemColor.controlText, DONTFETCH);
            attributes.add(/* NOI18N */"background",
			   /* NOI18N */"java.awt.Color",
			   SystemColor.control, DONTFETCH);
        }
    }
    
    public void createBody() {};
    
    void showGroups() {
        AttributeManager mgr;
        Enumeration e = getChildList();
        
        while (e.hasMoreElements()) {
            mgr = (AttributeManager)e.nextElement();
            if (mgr instanceof Group) {
                if (((Boolean)mgr.get("visible")).booleanValue())
		    DesignerAccess.internalShowGroup((Group)mgr);
            } else if (mgr instanceof ContainerShadow) {
                if (((Boolean)mgr.get("visible")).booleanValue())
		    ((ContainerShadow)mgr).showGroups();
            }
        }
    }
    
    void hideGroups() {
        AttributeManager mgr;
        Enumeration e = getChildList();
        
        while (e.hasMoreElements()) {
            mgr = (AttributeManager)e.nextElement();
            if (mgr instanceof Group) {
                DesignerAccess.internalHideGroup((Group)mgr);
            } else if (mgr instanceof ContainerShadow) {
                ((ContainerShadow)mgr).hideGroups();
            }
        }
    }
    
    // AMContainer interfaces
    
    public void add(AttributeManager child) {
        helper.add(child);
    }
    
    public void remove(AttributeManager child) {
        helper.remove(child);
    }
    
    public void addChildBody(Shadow child) {
        if (body != null) {
            Container cntr = (Container)body;
            Component comp = (Component)child.getBody();
            
            if (comp.getParent() != cntr) {
                cntr.add(comp);
                updateContainerAttributes((AMContainer)this, child);
            }
        }
    }
    
    public void updateContainerAttribute(AttributeManager child,
					 String key, Object value) {
        // Do nothing.  Sub-classes should override this method to deal with
        // specific layout managers.
    }
    
    public void removeChildBody(Shadow child) {
        if (body != null) {
            ((Container) body).remove((Component) child.getBody());
        }
    }
    
    public void createChildren() {
        helper.createChildren();
    }
    
    public void reparentChildren() {
        helper.reparentChildren();
    }
    
    public void destroyChildren() {
        helper.destroyChildren();
    }
    
    public AttributeManager getChild(String name) {
        return (helper.getChild(name));
    }
    
    public Enumeration getChildList() {
        return (helper.getChildList());
    }
    
    public int getChildCount() {
        return (helper.getChildCount());
    }
    
    public void layoutMode() {
        super.layoutMode();
        helper.layoutMode();
    }
    
    public void previewMode() {
        super.previewMode();
        helper.previewMode();
    }
    
    public void preValidate() {
        helper.preValidate();
    }
}
