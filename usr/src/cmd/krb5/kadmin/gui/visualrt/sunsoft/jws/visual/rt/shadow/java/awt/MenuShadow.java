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
 * @(#) MenuShadow.java 1.40 - last change made 07/28/97
 */

package sunsoft.jws.visual.rt.shadow.java.awt;

import sunsoft.jws.visual.rt.base.*;
import java.util.Enumeration;
import java.awt.*;
import sunsoft.jws.visual.rt.base.Global;

/**
 * Wraps an AWT widget.  The attributes available for this
 * class are listed below.  In the type column, type names beginning
 * with "sunsoft.jws.visual.rt" have been abbreviated to begin with "rt".
 *
 * <pre>
name            type                      default value
-----------------------------------------------------------------------
canTearOff      java.lang.Boolean         true
+ text            java.lang.String          menu
*  < /pre>
*
* + = this attribute overrides one inherited from an ancestor class.
*  < p>
* Check the super class for additional attributes.
*
* @see Menu
* @version 	1.40, 07/28/97
*/
public class MenuShadow extends MenuItemShadow implements AMContainer {
    private AMContainerHelper helper = new AMContainerHelper(this);
    
    public MenuShadow() {
        attributes.add(/* NOI18N */"canTearOff",
		       /* NOI18N */"java.lang.Boolean", Boolean.TRUE,
		       CONSTRUCTOR | NONBODY);
        attributes.add(/* NOI18N */"text",
		       /* NOI18N */"java.lang.String", /* NOI18N */"menu",
		       CONSTRUCTOR | NONBODY);
        
        if (Global.isIrix())
	    attributes.add(/* NOI18N */"font", /* NOI18N */"java.awt.Font",
			   new Font(/* NOI18N */"Sansserif",
				    Font.PLAIN, 12), DONTFETCH);
        else if (Global.isMotif())
            attributes.add(/* NOI18N */"font", /* NOI18N */"java.awt.Font",
			   new Font(/* NOI18N */"Dialog",
				    Font.PLAIN, 12), DONTFETCH);
    }
    
    public void createBody() {
        Boolean canTearOff = (Boolean) getFromTable(/* NOI18N */"canTearOff");
        if (canTearOff != null)
            body = new Menu((String) getFromTable(/* NOI18N */"text"),
			    canTearOff.booleanValue());
        else
            body = new Menu((String) getFromTable(/* NOI18N */"text"));
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
            Menu menu = (Menu)body;
            MenuItem menuitem = (MenuItem)child.getBody();
            
            if (menuitem.getParent() != menu) {
                menu.add(menuitem);
                updateContainerAttributes((AMContainer)this, child);
            }
        }
    }
    
    public void updateContainerAttribute(AttributeManager child,
					 String key, Object value) {
        if (key.equals(/* NOI18N */"separator")) {
            Menu menu = (Menu)body;
            MenuItemShadow menuItemShadow = (MenuItemShadow)child;
            MenuItem menuItem = (MenuItem)menuItemShadow.getBody();
            
            if (menu == null || menuItem == null)
                return;
            
            int count = menu.countItems();
            boolean val = ((Boolean)value).booleanValue();
            if (val == menuItemShadow.hasSeparator)
                return;
            
            if (val) {
                if (menu.getItem(count-1) == menuItem) {
                    menuItemShadow.hasSeparator = true;
                    ((Menu)body).addSeparator();
                } else {
                    menuItemShadow.hasSeparator = false;
                    MenuBarShadow menubar = (MenuBarShadow)getParent();
                    if (menubar != null) {
                        menubar.destroy();
                        menubar.create();
                    }
                }
            } else {
                menuItemShadow.hasSeparator = false;
                MenuBarShadow menubar = (MenuBarShadow)getParent();
                if (menubar != null) {
                    menubar.destroy();
                    menubar.create();
                }
            }
        }
    }
    
    public void removeChildBody(Shadow child) {
        if (body != null) {
            ((Menu) body).remove((MenuComponent) child.getBody());
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
}
