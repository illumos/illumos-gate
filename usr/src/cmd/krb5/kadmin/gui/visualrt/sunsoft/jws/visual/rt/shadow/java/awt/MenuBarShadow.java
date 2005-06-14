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
 * @(#) MenuBarShadow.java 1.43 - last change made 07/28/97
 */

package sunsoft.jws.visual.rt.shadow.java.awt;

import sunsoft.jws.visual.rt.base.*;
import sunsoft.jws.visual.rt.type.AMRef;
import sunsoft.jws.visual.rt.base.Global;

import java.util.Enumeration;
import java.awt.MenuBar;
import java.awt.MenuComponent;
import java.awt.Menu;

/**
 * Wraps an AWT widget.  The attributes available for this
 * class are listed below.  In the type column, type names beginning
 * with "sunsoft.jws.visual.rt" have been abbreviated to begin with "rt".
 *
 * <pre>
name            type                      default value
-----------------------------------------------------------------------
helpMenu        rt.type.AMRef             null
*  < /pre>
*
* Check the super class for additional attributes.
*
* @see MenuBar
*/
public class MenuBarShadow extends MenuComponentShadow implements AMContainer {
    private AMContainerHelper helper = new AMContainerHelper(this);
    private boolean fHelpMenu = false;
    private boolean fCreate = false;
    private Menu helpMenu = null;
    
    public MenuBarShadow() {
        attributes.add(/* NOI18N */"helpMenu",
		       /* NOI18N */"sunsoft.jws.visual.rt.type.AMRef",
		       null, 0);
    }
    
    protected Object getOnBody(String key) {
        if (key.equals(/* NOI18N */"helpMenu"))
	    // a menu shadow ref is returned
	    return (getFromTable(/* NOI18N */"helpMenu"));
        else
            return (super.getOnBody(key));
    }
    
    public void create()
    {
        fCreate = true;
        super.create();
        fCreate = false;
    }
    protected void setOnBody(String key, Object value) {
        if (key.equals(/* NOI18N */"helpMenu")) {
            // Check to make sure value is set yet
            if (value != null) {
                // a reference to the help menu shadow is what is
                // stored as attribute
                MenuShadow ms = (MenuShadow)((AMRef)value).getRef(this);
                // Create the body if it does not yet exist
                if (ms != null && ms.getBody() == null)
		    ms.createBody();
                
                if (ms != null && ms.getBody() != null)
		    {
                    
                    
			if (Global.isWindows())
			    {
				if (fCreate) // from create Menubar
				    {
					fHelpMenu = true;
					helpMenu = (Menu) ms.getBody();
				// no create just setting the help menu...
				    } else
					    /* JSTYLED */
					((MenuBar) body).setHelpMenu((Menu) ms.getBody());
			    }
			else
			    {
				    /* JSTYLED */
				((MenuBar) body).setHelpMenu((Menu) ms.getBody());
			    }
		    }
                else
			/* JSTYLED */
                    System.out.println(Global.fmtMsg("sunsoft.jws.visual.rt.awt.java.awt.MenuBarShadow.CantResolveHelpMenu",
						    getName(),
						    ((AMRef)value).getName()));
            }
        }
        else
            super.setOnBody(key, value);
    }
    
    public void createBody() {
        body = new MenuBar();
    }
    
    
    
    protected void postCreate() {
        
        /*
         * note that the sethelpMenu call in the jdk creates and adds 
         * it if the menu does not exists.
         * so during the setOnBody the help menu is created first.
         * and since on windows the menu appear as they are added we 
         * see the help menu first. I believe it is 
         * a bug in the windows peer. This is a workaround for that..
         * we remove and add the help menu again..
         * after all the menus are created.. bug id 4033014....-kp
         */
        
        Menu m;
        MenuBar menubar;
        menubar = (MenuBar)body;
        int i;
        
        if (Global.isWindows())
	    {
		if (fHelpMenu)  // help menu present so add it..
		    {
			if (helpMenu != null)
			    menubar.setHelpMenu(helpMenu);
		    }
	    }
        super.postCreate();
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
            MenuBar menubar = (MenuBar)body;
            Menu menu = (Menu)child.getBody();
            
            if (menu.getParent() != menubar) {
                menubar.add(menu);
                updateContainerAttributes((AMContainer)this, child);
            }
        }
    }
    
    public void updateContainerAttribute(AttributeManager child,
					 String key, Object value) {
        // Menus could have a layout constraint specifying their position
        // in the menubar.  This is not yet implemented.
    }
    
    public void removeChildBody(Shadow child) {
        if (body != null) {
            ((MenuBar) body).remove((MenuComponent) child.getBody());
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
    
    /**
     * replicate is used by Visual Java for cut and paste.
     */
    //
    // Normally this method resides in AttributeManager (super-duper class).
    // We override it here to put in special handling for the helpMenu --
    // fix for Sun Bug # 4043169: help menu getting duplicated on
    // copy/paste frame with help menu.  -- Simran 5/16/97
    //
    public AttributeManager replicate() {
        
        // System.out.println("MenuBarShadow.replicate: ");
        // System.out.println("       this: "+this);
        
        // Create a new instance of the AttributeManager
        AttributeManager newMgr = null;
        try {
            newMgr = (AttributeManager)getClass().newInstance();
        }
        catch (InstantiationException ex) {
            System.out.println(ex.getMessage() + /* NOI18N */" " + this);
        }
        catch (IllegalAccessException ex) {
            System.out.println(ex.getMessage() + /* NOI18N */" " + this);
        }
        if (newMgr == null)
            return null;
        
        // Copy the attribute list
        AttributeList list = getAttributeList();
        // System.out.println(" ----- attribute list: ");
        // printAttList(list);
        Enumeration e = list.elements();
        String helpMenuName = null;
        AttributeManager helpMenuMgr = null;
        while (e.hasMoreElements()) {
            Attribute attr = (Attribute)e.nextElement();
            String aName = attr.getName();
            
            //
            // Find the name of the helpMenu, don't set it until
            // we replicate the help menu. Then set it to the name of the
            // newly replicated helpMenu.
            // Fix for Sun Bug # 4043169: help menu getting duplicated on
            // copy/paste frame with help menu.  -- Simran 5/16/97
            //
            if (aName.equals(/* NOI18N */"helpMenu")) {
                Object gv = attr.getValue();
                AMRef helpMenuRef = (AMRef)gv;
                if (helpMenuRef != null) {
                    helpMenuMgr =  helpMenuRef.getRef(this);
                    helpMenuName = helpMenuRef.getName();
                }
                
                // System.out.println("FOund help menu
                // attribute. *NOT* setting it in new mgr. (yet)");
                
            } else  if (!attr.flagged(TRANSIENT | READONLY)) {
                newMgr.set(aName, attr.getValue());
            }
        }
        
        // Replicate the children
        if (this instanceof AMContainer) {
            AMContainer newCntr = (AMContainer)newMgr;
            e = ((AMContainer)this).getChildList();
            
            // System.out.print("       childList: (isMenuBar: "+isMenuBar+")");
            // printChildList(this);
            while (e.hasMoreElements()) {
                AttributeManager child = (AttributeManager)e.nextElement();
                
                // Check for helpmenu
                //
                
                // System.out.println(); System.out.println("IS
                // MENUBAR: child name="+child.getName());
                // System.out.println(" looking for: "+helpMenuName);
                
                // Is the name test going to be sufficient for finding
                // the help menu?  It seems that if we're restricted
                // to doing the test only if isMenuBar, then we're
                // OK. How unique do names have to be?
                if (child.getName().equals(helpMenuName)) {
                    // System.out.println(" replicating
                    // (helpMenu)child: "+child);
                    AttributeManager replicantChild = child.replicate();
                    newMgr.set(/* NOI18N */"helpMenu",
			       new AMRef(replicantChild));
                    newCntr.add(replicantChild);
                } else {
                    // System.out.println(" replicating (normal) child
                    // of MenuBar: "+child);
                    newCntr.add(child.replicate());
                }
            }
        }
        
        return newMgr;
    }
    
    void printAttList(AttributeList list) {
        Enumeration e = list.elements();
        while (e.hasMoreElements()) {
            Attribute attr = (Attribute)e.nextElement();
            // System.out.println(" name: "+attr.getName()+"; value:
            // "+(String)attr.getValue());
            System.out.print(/* NOI18N */" name: "
			     + attr.getName()+ /* NOI18N */"; ");
            Object gv = attr.getValue();
            System.out.println(/* NOI18N */"  value.toString(): "
			       + ((gv != null) ? gv.toString()
				  : /* NOI18N */"<null value>"));
            if (attr.getName().equals(/* NOI18N */"helpMenu")) {
                System.out.println();
                System.out.println(/* NOI18N */"  found help menu att: "
				   + ((gv != null) ? gv.toString()
				      : /* NOI18N */"<null value>"));
                System.out.println();
            }
        }
    }
    
    void printChildList(AttributeManager mgr) {
        int i = 0;
        for (Enumeration e = ((AMContainer) this).getChildList();
	     /* JSTYLED */
	     e.hasMoreElements();) {
            
            System.out.print(/* NOI18N */"     child["+i+ /* NOI18N */"] ");
            System.out.println(((AttributeManager)e.nextElement())
			       + /* NOI18N */"");
            i++;
        }
        System.out.println(/* NOI18N */"==============");
        System.out.println();
    }
}
