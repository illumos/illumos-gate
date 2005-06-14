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
 * @(#) ScrollPanelShadow.java 1.7 - last change made 07/25/97
 */
        
package sunsoft.jws.visual.rt.shadow;
        
import sunsoft.jws.visual.rt.awt.ScrollPanel;
import sunsoft.jws.visual.rt.base.Util;
import sunsoft.jws.visual.rt.type.ReliefEnum;
        
import java.awt.Insets;
import java.util.Enumeration;
        
/*
 * Wraps an AWT widget.  The attributes available for this
 * class are listed below.  In the type column, type names beginning
 * with "sunsoft.jws.visual.rt" have been abbreviated to begin with "rt".
 *
 * < pre>
 * name                type                  default value
 * -----------------------------------------------------------------------
 *    + borderRelief        rt.type.ReliefEnum    win95 field border
 *    scrollAreaInsets    java.awt.Insets       null
 *    scrollAreaWidth     java.awt.Integer      null
 *    scrollAreaHeight    java.awt.Integer      null
 *  < /pre>
 *
 * + = this attribute overrides one inherited from an ancestor class.
 *  < p>
 * borderRelief: There are a number of different border drawing styles
 * available for panels, and the user can see what they look like by
 * trying them out: "flat", "raised", "sunken", "ridge", "groove",
 * "win95 raised", "win95 sunken", "win95 field border", "win95 window
 * border"
 *  < p>
 * Check the super class for additional attributes.
 *
 * @see ScrollPanel
 * @see ScrollableAreaShadow
 * @version 1.7, 07/25/97
 */
public class ScrollPanelShadow extends VJPanelShadow {
    public ScrollPanelShadow() {
	attributes.add(/* NOI18N */"borderRelief",
		       /* NOI18N */"sunsoft.jws.visual.rt.type.ReliefEnum",
		       new ReliefEnum(Util.WIN95_FIELD_BORDER), 0);
	attributes.add(/* NOI18N */"scrollAreaInsets",
		       /* NOI18N */"java.awt.Insets", null, 0);
	attributes.add(/* NOI18N */"scrollAreaWidth",
		       /* NOI18N */"java.lang.Integer", null, 0);
	attributes.add(/* NOI18N */"scrollAreaHeight",
		       /* NOI18N */"java.lang.Integer", null, 0);
    }
            
    public Object getOnBody(String key) {
	ScrollPanel scrollPanel = (ScrollPanel)body;
                
	if (key.equals(/* NOI18N */"scrollAreaInsets"))
	    return scrollPanel.getScrollAreaInsets();
	else if (key.equals(/* NOI18N */"scrollAreaWidth"))
	    return new Integer(scrollPanel.getScrollAreaWidth());
	else if (key.equals(/* NOI18N */"scrollAreaHeight"))
	    return new Integer(scrollPanel.getScrollAreaHeight());
	else
	    return super.getOnBody(key);
    }
            
    public void setOnBody(String key, Object value) {
	ScrollPanel scrollPanel = (ScrollPanel)body;
                
	if (key.equals(/* NOI18N */"scrollAreaInsets")) {
	    scrollPanel.setScrollAreaInsets((Insets)value);
	} else if (key.equals(/* NOI18N */"scrollAreaWidth")) {
	    int val = 0;
	    if (value != null)
		val = ((Integer)value).intValue();
	    scrollPanel.setScrollAreaWidth(val);
	} else if (key.equals(/* NOI18N */"scrollAreaHeight")) {
	    int val = 0;
	    if (value != null)
		val = ((Integer)value).intValue();
	    scrollPanel.setScrollAreaHeight(val);
	} else {
	    super.setOnBody(key, value);
	}
    }
            
    public void create() {
	// Add a ScrollableAreaShadow child if there isn't one already.
	if (inDesignerRoot()) {
	    boolean found = false;
                    
	    Enumeration e = getChildList();
	    while (e.hasMoreElements()) {
		if (e.nextElement()
		    instanceof ScrollableAreaShadow)
		    found = true;
	    }
                    
	    if (!found) {
		add(new ScrollableAreaShadow());
	    }
	}
                
	super.create();
    }
            
    public void createBody() {
	body = new ScrollPanel();
    }
}
