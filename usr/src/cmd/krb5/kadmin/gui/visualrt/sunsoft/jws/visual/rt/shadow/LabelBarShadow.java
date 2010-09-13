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
 * @(#) LabelBarShadow.java 1.27 - last change made 07/25/97
 */
        
package sunsoft.jws.visual.rt.shadow;
        
import sunsoft.jws.visual.rt.awt.GBConstraints;
import sunsoft.jws.visual.rt.awt.LabelBar;
import sunsoft.jws.visual.rt.shadow.java.awt.CanvasShadow;
import sunsoft.jws.visual.rt.type.AlignmentEnum;
        
/**
 * Wraps an AWT widget.  The attributes available for this
 * class are listed below.  In the type column, type names beginning
 * with "sunsoft.jws.visual.rt" have been abbreviated to begin with "rt".
 *
 * < pre>
 * name            type                      default value
 *  -----------------------------------------------------------------------
 * alignment       rt.type.AlignmentEnum     left
 * text            java.lang.String          ""
 * textOffsetFromEdge java.lang.Integer      10
 *  < /pre>
 *
 * alignment: label bars can have a text label, if can be either
 * "left", "center", or "right"
 *  < p>
 * textOffsetFromEdge: if alignment is "left" or "right", this
 * attribute controls how many pixels from the edge the label will be
 *  < p>
 * Check the super class for additional attributes.
 *
 * @see LabelBar
 * @version 1.27, 07/25/97
 */
public class LabelBarShadow extends CanvasShadow {
    public LabelBarShadow() {
	attributes.add(/* NOI18N */"text",
		       /* NOI18N */"java.lang.String",
		       /* NOI18N */"", NOEDITOR);
	attributes.add(/* NOI18N */"alignment",
		       /* NOI18N */"sunsoft.jws.visual.rt.type.AlignmentEnum",
		       new AlignmentEnum(LabelBar.LEFT), 0);
	attributes.add(/* NOI18N */"textOffsetFromEdge",
		       /* NOI18N */"java.lang.Integer", new Integer(10),
		       0);
                
	GBConstraints c =
	    (GBConstraints)get(/* NOI18N */"GBConstraints");
	c.fill = GBConstraints.HORIZONTAL;
	attributes.add(/* NOI18N */"GBConstraints",
		       /* NOI18N */"sunsoft.jws.visual.rt.awt.GBConstraints",
		       c);
    }
            
    protected Object getOnBody(String key) {
	if (key.equals(/* NOI18N */"text"))
	    return (((LabelBar) body).getLabel());
	else if (key.equals(/* NOI18N */"alignment"))
	    return (new AlignmentEnum(
		((LabelBar) body).getAlignment()));
	else if (key.equals(/* NOI18N */"textOffsetFromEdge"))
	    return (new Integer(
		((LabelBar) body).getLabelOffsetFromEdge()));
	else
	    return (super.getOnBody(key));
    }
            
    protected void setOnBody(String key, Object value) {
	if (key.equals(/* NOI18N */"text"))
	    ((LabelBar) body).setLabel((String) value);
	else if (key.equals(/* NOI18N */"alignment"))
/* JSTYLED */
	    ((LabelBar) body).setAlignment(((AlignmentEnum) value).intValue());
	else if (key.equals(/* NOI18N */"textOffsetFromEdge"))
/* JSTYLED */
	    ((LabelBar) body).setLabelOffsetFromEdge(((Integer) value).intValue());
	else
	    super.setOnBody(key, value);
    }
            
    public void createBody() {
	body = new LabelBar(
	    (String) (getFromTable(/* NOI18N */"text")));
    }
}
