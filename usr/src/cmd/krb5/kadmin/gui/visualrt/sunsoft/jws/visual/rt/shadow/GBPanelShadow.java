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
 * @(#) GBPanelShadow.java 1.49 - last change made 07/25/97
 */

package sunsoft.jws.visual.rt.shadow;

import sunsoft.jws.visual.rt.shadow.java.awt.PanelShadow;
import sunsoft.jws.visual.rt.base.AttributeManager;
import sunsoft.jws.visual.rt.base.Group;
import sunsoft.jws.visual.rt.base.Shadow;
import sunsoft.jws.visual.rt.awt.GBPanel;
import sunsoft.jws.visual.rt.awt.GBLayout;
import sunsoft.jws.visual.rt.awt.GBConstraints;
import sunsoft.jws.visual.rt.type.AnchorEnum;

import java.awt.*;

/**
 * Wraps an AWT widget.  The attributes available for this
 * class are listed below.  In the type column, type names beginning
 * with "sunsoft.jws.visual.rt" have been abbreviated to begin with
 * "rt".
 *
 * < pre>
name            type                      default value
-----------------------------------------------------------------------
none
*  < /pre>
*
* Check the super class for additional attributes.
*
* @see GBConstraints
* @see VJPanelShadow
* @see PanelShadow
* @version 	1.49, 07/25/97
*/
public class GBPanelShadow extends VJPanelShadow {
    public GBPanelShadow() {
        attributes.add(/* NOI18N */"columnWidths",
		       /* NOI18N */"[I", null, HIDDEN);
        attributes.add(/* NOI18N */"rowHeights",
		       /* NOI18N */"[I", null, HIDDEN);
        attributes.add(/* NOI18N */"columnWeights",
		       /* NOI18N */"[D", null, HIDDEN);
        attributes.add(/* NOI18N */"rowWeights",
		       /* NOI18N */"[D", null, HIDDEN);
    }
    
    protected Object getOnBody(String key) {
        GBPanel panel = (GBPanel)body;
        
        if (key.equals(/* NOI18N */"columnWidths"))
            return panel.getColumnWidths();
        else if (key.equals(/* NOI18N */"rowHeights"))
            return panel.getRowHeights();
        else if (key.equals(/* NOI18N */"columnWeights"))
            return panel.getColumnWeights();
        else if (key.equals(/* NOI18N */"rowWeights"))
            return panel.getRowWeights();
        else
            return super.getOnBody(key);
    }
    
    protected void setOnBody(String key, Object value) {
        GBPanel panel = (GBPanel)body;
        
        if (key.equals(/* NOI18N */"columnWidths"))
            panel.setColumnWidths((int[])value);
        else if (key.equals(/* NOI18N */"rowHeights"))
            panel.setRowHeights((int[])value);
        else if (key.equals(/* NOI18N */"columnWeights"))
            panel.setColumnWeights((double[])value);
        else if (key.equals(/* NOI18N */"rowWeights"))
            panel.setRowWeights((double[])value);
        else
            super.setOnBody(key, value);
    }
    
    public void updateContainerAttribute(AttributeManager child,
					 String key, Object value) {
        if (key.equals(/* NOI18N */"anchor")) {
            GBConstraints c =
		(GBConstraints)child.get(/* NOI18N */"GBConstraints");
            if (c == null)
                return;
            
            int anchor = ((AnchorEnum)value).intValue();
            if (anchor != c.anchor) {
                c.anchor = anchor;
                child.set(/* NOI18N */"GBConstraints", c);
            }
        } else if (key.equals(/* NOI18N */"insets")) {
            GBConstraints c =
		(GBConstraints)child.get(/* NOI18N */"GBConstraints");
            if (c == null)
                return;
            
            Insets insets = (Insets)value;
            if (c.insets != insets) {
                c.insets = insets;
                child.set(/* NOI18N */"GBConstraints", c);
            }
        } else if (key.equals(/* NOI18N */"GBConstraints")) {
            GBConstraints c = (GBConstraints)value;
            if (c == null)
                c = new GBConstraints();
            
            Shadow s = (Shadow)child;
            Component comp = (Component)s.getBody();
            if (comp == null)
                return;
            
            int anchor =
		((AnchorEnum)child.get(/* NOI18N */"anchor")).intValue();
            c.anchor = anchor;
            c.insets = (Insets)child.get(/* NOI18N */"insets");
            
            ((GBPanel)body).setConstraints(comp, c);
        }
    }
    
    public void createBody() {
        body = new GBPanel();
    }
    
    protected void postCreate() {
        super.postCreate();
        if (isLayoutMode())
            ((GBPanel)body).layoutMode();
        else
            ((GBPanel)body).previewMode();
    }
    
    /**
     * Set the runtime flag in registerBody so that subclasses of
     * GBPanelShadow will work properly.
     */
    protected void registerBody() {
        ((GBPanel)body).setRuntime(!inDesignerRoot());
        super.registerBody();
    }
    
    public void layoutMode() {
        super.layoutMode();
        if (body != null)
            ((GBPanel)body).layoutMode();
    }
    
    public void previewMode() {
        super.previewMode();
        if (body != null)
            ((GBPanel)body).previewMode();
    }
}
