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
 * @(#) ComponentShadow.java 1.82 - last change made 08/05/97
 */

package sunsoft.jws.visual.rt.shadow.java.awt;

import sunsoft.jws.visual.rt.base.*;
import sunsoft.jws.visual.rt.awt.GBLayout;
import sunsoft.jws.visual.rt.awt.GBConstraints;
import sunsoft.jws.visual.rt.type.AnchorEnum;
import sunsoft.jws.visual.rt.base.Global;

import java.awt.Component;
import java.awt.Container;
import java.awt.Window;
import java.awt.LayoutManager;
import java.awt.SystemColor;
import java.awt.Color;
import java.awt.Font;
import java.awt.Frame;
import java.awt.Panel;

/**
 * Shadow class that wraps the AWT Component class.  The attributes
 * available for this class are listed below.  Check the super class
 * for additional attributes.
 *
 * <pre>
name            type                      default value
-----------------------------------------------------------------------
anchor          rt.type.AnchorEnum        center
background      java.awt.Color            null
enabled         java.lang.Boolean         true
font            java.awt.Font             null
foreground      java.awt.Color            null
GBConstraints   rt.awt.GBConstraints      new GBConstraints()
insets          java.awt.Insets           null
visible         java.lang.Boolean         true
*  < /pre>
*
* All shadow classes(except for the menu-related ones) include the
* attributes from the ComponentShadow class in addition to their own,
* and they do so by subclassing it.  This class is a super class and
* isn't available directly from the palette.
*
* @see Component
* @version 1.75, 05/02/97
*/
public class ComponentShadow extends Shadow {
    
    // Set to true while a show operation is in progress
    protected boolean doingShow = false;
    
    ComponentShadow() {
        GBConstraints c = new GBConstraints();
        c.gridx = 0;
        c.gridy = 0;
        attributes.add(/* NOI18N */"GBConstraints",
		       /* NOI18N */"sunsoft.jws.visual.rt.awt.GBConstraints",
		       c, HIDDEN | NONBODY | CONTAINER);
        
        attributes.add(/* NOI18N */"layoutName",
		       /* NOI18N */"java.lang.String", null,
		       HIDDEN | NONBODY | CONTAINER);
        attributes.add(/* NOI18N */"anchor",
		       /* NOI18N */"sunsoft.jws.visual.rt.type.AnchorEnum",
		       new AnchorEnum(GBConstraints.CENTER),
		    NONBODY | CONTAINER);
        attributes.add(/* NOI18N */"insets",
		       /* NOI18N */"java.awt.Insets",
		    null, NONBODY | CONTAINER);
        
        attributes.add(/* NOI18N */"visible",
		       /* NOI18N */"java.lang.Boolean", Boolean.TRUE,
		       HIDDEN | DEFAULT);
        attributes.add(/* NOI18N */"enabled",
		       /* NOI18N */"java.lang.Boolean", Boolean.TRUE, DEFAULT);
        
        if (Global.isMotif()) {
            // Default colors should be null for motif since they inherit the
            // colors from the Containers.
            attributes.add(/* NOI18N */"foreground",
			   /* NOI18N */"java.awt.Color",
			   null, DEFAULT | DONTFETCH);
            attributes.add(/* NOI18N */"background",
			   /* NOI18N */"java.awt.Color",
			   null, DEFAULT | DONTFETCH);
        } else {
            // Component bg and fg must be explicitly set for
            // Windows. Unfortunately, JDK implements setBackground
            // and setForground the Motif way. That is, if the default
            // color is null then retrieve the parent's color. This is
            // not how the peer is implemented. For Windows, the
            // container's colors are not inherited by the container.
            attributes.add(/* NOI18N */"foreground",
			   /* NOI18N */"java.awt.Color",
			   SystemColor.controlText, DONTFETCH);
            attributes.add(/* NOI18N */"background",
			   /* NOI18N */"java.awt.Color",
			   SystemColor.control, DONTFETCH);
        }
        attributes.add(/* NOI18N */"font",
		       /* NOI18N */"java.awt.Font", null,
		       DEFAULT | DONTFETCH);
    }
    
    protected Object getOnBody(String key) {
        Component comp = (Component)body;
        
        if (key.equals(/* NOI18N */"visible"))
	    return (getFromTable(/* NOI18N */"visible"));
        else if (key.equals(/* NOI18N */"enabled"))
            return (new Boolean(comp.isEnabled()));
        else if (key.equals(/* NOI18N */"foreground"))
            return (comp.getForeground());
        else if (key.equals(/* NOI18N */"background"))
            return (comp.getBackground());
        else if (key.equals(/* NOI18N */"font"))
            return (comp.getFont());
        else
            return (super.getOnBody(key));
    }
    
    public void set(String key, Object value) {
        if (key.equals(/* NOI18N */"visible")) {
            boolean oldValue =
		((Boolean)getFromTable(/* NOI18N */"visible")).booleanValue();
            boolean newValue = ((Boolean)value).booleanValue();
            
            if (newValue != oldValue) {
                if (newValue) {
                    if (!isCreated()) {
                        doingShow = true;
                        create();
                        doingShow = false;
                    }
                    
                    super.set(key, value);
                    
                    if (this instanceof ContainerShadow)
                        ((ContainerShadow)this).showGroups();
                } else {
                    super.set(key, value);
                    
                    if (this instanceof ContainerShadow)
                        ((ContainerShadow)this).hideGroups();
                }
                
                return;
            }
        }
        
        super.set(key, value);
    }
    
    protected void setOnBody(String key, Object value) {
        Component comp = (Component)body;
        
        if (key.equals(/* NOI18N */"visible")) {
            // Don't let visible be set to false if we are the main container
            // and we are running inside vjava.
            if (inDesignerRoot() && isMainContainer() &&
		!((Boolean)value).booleanValue()) {
		    /* JSTYLED */
                throw new VJException(Global.getMsg("sunsoft.jws.visual.rt.awt.java.awt.ComponentShadow.IllegalSetVisible"));
            }
            
            // We don't need to use the doingShow() method, because
            // the "visible" attribute has the DEFAULT flag set,
            // therefore setOnBody will be called during creation for
            // the "visible" attribute only if the "visible" attribute
            // is false.
            if (!doingShow)
                showComponent(((Boolean) value).booleanValue());
        } else if (key.equals(/* NOI18N */"enabled"))
            comp.setEnabled(((Boolean) value).booleanValue());
        else if (key.equals(/* NOI18N */"foreground")) {
            comp.setForeground((Color) value);
        } else if (key.equals(/* NOI18N */"background")) {
            comp.setBackground((Color) value);
        } else if (key.equals(/* NOI18N */"font"))
            comp.setFont((Font) value);
        else
            super.setOnBody(key, value);
    }
    
    protected boolean isMainContainer() {
        Root r = getRoot();
        if (r == null)
            return false;
        
        AttributeManager mgr = r.getMainChild();
        if (mgr instanceof WindowShadow) {
            WindowShadow win = (WindowShadow)mgr;
            if (win.isPanel())
		mgr = win.getPanel();
        }
        
        return (mgr == this);
    }
    
    public void createBody() {};
    
    /**
     * Overrides destroyBody() in Shadow so that removeNotify() gets called on
     * AWT components when there will be no more references to them.
     */
    protected void destroyBody() {
        if (body != null) {
            ((Component)body).removeNotify();
            body = null;
        }
    }
    
    /**
     * Calls show or hide, depending on the value of cond.
     */
    public void show(boolean cond) {
        if (cond)
            show();
        else
            hide();
    }
    
    /**
     * Sets the visible attribute to true.
     */
    public void show() {
        set(/* NOI18N */"visible", Boolean.TRUE);
    }
    
    /**
     * Sets the visible attribute to false.
     */
    public void hide() {
        set(/* NOI18N */"visible", Boolean.FALSE);
    }
    
    /**
     * Calls showComponent or hideComponent, depending on the value of cond.
     */
    public void showComponent(boolean cond) {
        if (cond)
            showComponent();
        else
            hideComponent();
    }
    
    /**
     * Shows the component.  Calling showComponent does not affect the
     * value of the visible attrbute.  You should use "show" instead of
     * "showComponent".  The only reason this method exists is that
     * Visual Java needs to use it in certain situations.
     */
    public void showComponent() {
        // Call create if it hasn't already been called.
        if (!isCreated()) {
            doingShow = true;
            create();
            doingShow = false;
        }
        
        ((Component)body).show();
        validateMain();
    }
    
    /**
     * Hides the component.  Calling hideComponent does not affect the
     * value of the visible attrbute.  You should use "hide" instead of
     * "hideComponent".  The only reason this method exists is that
     * Visual Java needs to use it in certain situations.
     */
    public void hideComponent() {
        if (body != null)
	    {
		((Component)body).hide();
		validateMain();
	    }
    }
    
    /**
     * Returns true if we are doing a create operation in the
     * middle of a show operation.  Create likes to call show if the
     * visible attribute is set to true, but create shouldn't call
     * show if show caused create to be called if the first place.
     */
    protected boolean doingShow() {
        if (doingShow) {
            return true;
        } else {
            Group g = getGroup();
            if (g != null)
                return DesignerAccess.doingShow(g);
            else
                return false;
        }
    }
    
    /**
     * Call validate to lay out the component and its children if they
     * are not valid.
     */
    public void validate() {
        if (body != null)
            ((Component)body).validate();
    }
    
    /**
     * Call invalidate to force the component to not be valid, so that
     * it will be layed out again when validate is called.
     */
    public void invalidate() {
        if (body != null)
            ((Component)body).invalidate();
    }
    
    /**
     * Returns the result from calling isShowing on the body.
     */
    public boolean isShowing() {
        if (body != null)
            return ((Component)body).isShowing();
        else
            return false;
    }
    
    public void validateMain()
    {
        Root root = getRoot();
        if (root == null)
            return;
        // Try the main container
        AttributeManager mgr = root.getMainChild();
        if (mgr instanceof Group)
            mgr = DesignerAccess.getContainer((Group)mgr);
        
        if (mgr instanceof ContainerShadow)
	    {
		ContainerShadow fs = ((ContainerShadow)mgr);
		Container f = (Container)fs.getBody();
		f.validate();
	    }
    }
}
