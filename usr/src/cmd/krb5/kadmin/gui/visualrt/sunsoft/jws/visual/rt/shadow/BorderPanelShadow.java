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
 * @(#) BorderPanelShadow.java 1.19 - last change made 06/12/97
 */

package sunsoft.jws.visual.rt.shadow;

import sunsoft.jws.visual.rt.awt.VJPanel;
import sunsoft.jws.visual.rt.base.*;
import sunsoft.jws.visual.rt.shadow.GBPanelShadow;
import java.awt.*;
import java.util.Enumeration;

/**
 * Wraps an AWT widget.  The attributes available for this
 * class are listed below.  In the type column, type names beginning
 * with "sunsoft.jws.visual.rt" have been abbreviated to begin with
 * "rt".
 *
 * < pre >
name            type                      default value
-----------------------------------------------------------------------
useCenter       java.lang.Boolean         true
useEast         java.lang.Boolean         true
useNorth        java.lang.Boolean         true
useSouth        java.lang.Boolean         true
useWest         java.lang.Boolean         true
*  < /pre>
*
* The attributes for this class allow you to select which of the five
* border panel cells are going to be used.  When you set them to
* false, whatever was in that cell is deleted and the cell will no
* longer appear in the border layout for use in arranging components.
*  < p>
* Check the super class for additional attributes.
*
* @see BorderLayout
* @version 1.19, 06/12/97
*/
public class BorderPanelShadow extends VJPanelShadow {
    public BorderPanelShadow() {
        attributes.add(/* NOI18N */"useCenter",
		       /* NOI18N */"java.lang.Boolean", Boolean.TRUE, 0);
        attributes.add(/* NOI18N */"useNorth",
		       /* NOI18N */"java.lang.Boolean", Boolean.TRUE, 0);
        attributes.add(/* NOI18N */"useSouth",
		       /* NOI18N */"java.lang.Boolean", Boolean.TRUE, 0);
        attributes.add(/* NOI18N */"useEast",
		       /* NOI18N */"java.lang.Boolean", Boolean.TRUE, 0);
        attributes.add(/* NOI18N */"useWest",
		       /* NOI18N */"java.lang.Boolean", Boolean.TRUE, 0);
    }
    
    protected Object getOnBody(String key) {
        Panel panel = (Panel)body;
        
        if (key.equals(/* NOI18N */"useCenter") ||
	    key.equals(/* NOI18N */"useNorth") ||
	    key.equals(/* NOI18N */"useSouth") ||
	    key.equals(/* NOI18N */"useEast") ||
	    key.equals(/* NOI18N */"useWest")) {
            return getFromTable(key);
        } else {
            return super.getOnBody(key);
        }
    }
    
    protected void setOnBody(String key, Object value) {
        Panel panel = (Panel)body;
        
        if (key.equals(/* NOI18N */"useCenter") ||
	    key.equals(/* NOI18N */"useNorth") ||
	    key.equals(/* NOI18N */"useSouth") ||
	    key.equals(/* NOI18N */"useEast") ||
	    key.equals(/* NOI18N */"useWest")) {
            // border names differ from the keys "useWest" -> "West"
            adjustChild(key.substring(3),
			((Boolean)value).booleanValue());
        } else {
            super.setOnBody(key, value);
        }
    }
    
    private void adjustChild(String borderName, boolean create) {
        AttributeManager mgr = lookupChild(borderName);
        
        if (create) {
            if (mgr != null)
                return;
            
            double wx[] = {1};
            double wy[] = {1};
            
            GBPanelShadow panel = new GBPanelShadow();
            panel.set(/* NOI18N */"layoutName", borderName);
            panel.set(/* NOI18N */"columnWeights", wx);
            panel.set(/* NOI18N */"rowWeights", wy);
            
            add(panel);
            panel.create();
        } else {
            if (mgr == null)
                return;
            
            GBPanelShadow panel = (GBPanelShadow)mgr;
            panel.destroy();
            remove(panel);
        }
    }
    
    private AttributeManager lookupChild(String borderName) {
        Enumeration e = getChildList();
        while (e.hasMoreElements()) {
            AttributeManager mgr = (AttributeManager)e.nextElement();
            String name = (String)mgr.get(/* NOI18N */"layoutName");
            
            if (name == null)
                continue;
            
            if (name.equals(borderName))
                return mgr;
        }
        
        return null;
    }
    
    public void updateContainerAttribute(AttributeManager child,
					 String key, Object value) {
        if (!key.equals(/* NOI18N */"layoutName"))
            return;
        
        Shadow s = (Shadow)child;
        Component comp = (Component)s.getBody();
        if (comp == null)
            return;
        
        String borderName = (String)value;
        if (borderName == null)
            borderName = /* NOI18N */"Center";
        
        Panel panel = (Panel)body;
        BorderLayout bd = (BorderLayout)panel.getLayout();
        
        bd.addLayoutComponent(borderName, comp);
    }
    
    public void createBody() {
        Panel panel = new VJPanel();
        panel.setLayout(new BorderLayout());
        body = panel;
    }
    
    protected void postCreate() {
        Enumeration e = getChildList();
        while (e.hasMoreElements()) {
            AttributeManager mgr = (AttributeManager)e.nextElement();
            String borderName =
		(String)mgr.get(/* NOI18N */"layoutName");
            
            if (borderName == null)
                continue;
            
            if (borderName.equals(/* NOI18N */"Center"))
                set(/* NOI18N */"useCenter", Boolean.TRUE);
            else if (borderName.equals(/* NOI18N */"North"))
                set(/* NOI18N */"useNorth", Boolean.TRUE);
            else if (borderName.equals(/* NOI18N */"South"))
                set(/* NOI18N */"useSouth", Boolean.TRUE);
            else if (borderName.equals(/* NOI18N */"East"))
                set(/* NOI18N */"useEast", Boolean.TRUE);
            else if (borderName.equals(/* NOI18N */"West"))
                set(/* NOI18N */"useWest", Boolean.TRUE);
        }
        
        super.postCreate();
    }
}
