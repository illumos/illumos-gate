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
 * @(#) VJPanelShadow.java 1.7 - last change made 07/25/97
 */

package sunsoft.jws.visual.rt.shadow;

import sunsoft.jws.visual.rt.awt.VJPanel;
import sunsoft.jws.visual.rt.base.AttributeManager;
import sunsoft.jws.visual.rt.type.AlignmentEnum;
import sunsoft.jws.visual.rt.type.ReliefEnum;
import sunsoft.jws.visual.rt.shadow.java.awt.PanelShadow;

import java.awt.FlowLayout;

/**
 * Wraps an AWT widget.  The attributes available for this
 * class are listed below.  In the type column, type names beginning
 * with "sunsoft.jws.visual.rt" have been abbreviated to begin with
 * "rt".
 *
 * < pre>
name            type                       default value
-----------------------------------------------------------------------
borderLabel     java.lang.String           null
borderLabelAlignment rt.type.AlignmentEnum left
borderRelief    rt.type.ReliefEnum         flat
borderWidth     java.lang.Integer          2
*  < /pre>
*
* borderLabel: a recently added new feature: panels can have bevelled
* borders and a labelin the top line somewhere, borderLabel is the
* text of the label.  When null, there is no label.
*  < p>
* borderLabelAlignment: either "left", "center", or "right",
* determines where
* on the top bevel line the label goes.
*  < p>
* borderRelief: There are a number of different border drawing styles
* available for panels, and the user can see what they look like by
* trying them out: "flat", "raised", "sunken", "ridge", "groove",
* "win95 raised", "win95 sunken", "win95 field border", "win95 window
* border"
*  < p>
* borderWidth: the number of pixels wide the border will be drawn
*  < p>
*
* Check the super class for additional attributes.
*
* @see VJPanel
* @version 1.7, 07/25/97
*/
public class VJPanelShadow extends PanelShadow {
    public VJPanelShadow() {
        attributes.add(/* NOI18N */"borderLabel",
		       /* NOI18N */"java.lang.String", null, NOEDITOR);
        attributes.add(/* NOI18N */"borderRelief",
		       /* NOI18N */"sunsoft.jws.visual.rt.type.ReliefEnum",
		       new ReliefEnum(), 0);
        attributes.add(/* NOI18N */"borderWidth",
		       /* NOI18N */"java.lang.Integer", new Integer(2), 0);
        attributes.add(/* NOI18N */"borderLabelAlignment",
		       /* NOI18N */"sunsoft.jws.visual.rt.type.AlignmentEnum",
		       new AlignmentEnum(), 0);
        
        // These attributes are needed for top level panels
        // that are loaded in the designer.  A frame is placed
        // around the panel, and the frame needs to know what
        // size to be.  The panel can ignore the settings for
        // these attributes.
        attributes.add(/* NOI18N */"layoutLocation",
		       /* NOI18N */"java.awt.Point",
		       null, HIDDEN | NONBODY);
        attributes.add(/* NOI18N */"layoutSize",
		       /* NOI18N */"java.awt.Dimension",
		       null, HIDDEN | NONBODY);
    }
    
    public void createBody() {
        VJPanel panel = new VJPanel();
        panel.setLayout(new FlowLayout());
        body = panel;
    }
    
    protected Object getOnBody(String key) {
        VJPanel panel = (VJPanel)body;
        
        if (key.equals(/* NOI18N */"borderRelief")) {
            return new ReliefEnum(panel.getRelief()); }
	else if (key.equals(/* NOI18N */"borderWidth")) {
	    return new Integer(panel.getBorderWidth());
	} else if (key.equals(/* NOI18N */"borderLabel")) {
	    return panel.getBorderLabel();
	} else if (key.equals(/* NOI18N */"borderLabelAlignment")) {
	    return new AlignmentEnum(panel.getLabelAlignment());
	} else {
	    return super.getOnBody(key);
	}
    }
        
    protected void setOnBody(String key, Object value) {
	VJPanel panel = (VJPanel)body;
            
	if (key.equals(/* NOI18N */"borderRelief")) {
	    panel.setRelief(((ReliefEnum)value).intValue());
	} else if (key.equals(/* NOI18N */"borderWidth")) {
	    panel.setBorderWidth(((Integer)value).intValue());
	} else if (key.equals(/* NOI18N */"borderLabel")) {
	    panel.setBorderLabel((String)value);
	} else if (key.equals(/* NOI18N */"borderLabelAlignment")) {
	    panel.setLabelAlignment(((AlignmentEnum)value).intValue());
	} else {
	    super.setOnBody(key, value);
	}
    }
}
