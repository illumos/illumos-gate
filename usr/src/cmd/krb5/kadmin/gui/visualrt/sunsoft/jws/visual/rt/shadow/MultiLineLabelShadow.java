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
 * @(#) MultiLineLabelShadow.java 1.7 - last change made 08/04/97
 */
        
package sunsoft.jws.visual.rt.shadow;
        
import sunsoft.jws.visual.rt.shadow.java.awt.CanvasShadow;
import sunsoft.jws.visual.rt.awt.MultiLineLabel;
import sunsoft.jws.visual.rt.type.AlignmentEnum;
import sunsoft.jws.visual.rt.base.Global;
        
import java.util.*;
import java.awt.*;
        
/*
 * Wraps an AWT widget.  The attributes available for this
 * class are listed below.  In the type column, type names beginning
 * with "sunsoft.jws.visual.rt" have been abbreviated to begin with "rt".
 *
 * < pre>
 * name            type                      default value
 * -----------------------------------------------------------------------
 * + text            java.lang.String          "MultiLineLabel"
 * alignment       rt.type.AlignmentEnum     left
 * maxColumns      java.lang.Integer         -1
 * < /pre>
 *
 * maxColumns: the maximum number of columns allowed in a single line.
 * If a line has more than this number it will be wrapped.  Set this to -1
 * do deactivate automatic line wrapping.
 *
 * Check the super class for additional attributes.
 *
 * @see MultiLineLabel
 * @version 	1.7, 08/04/97
 */
public class MultiLineLabelShadow extends CanvasShadow {
    public MultiLineLabelShadow() {
	attributes.add(/* NOI18N */"text",
		       /* NOI18N */"java.lang.String",
/* JSTYLED */
		       Global.getMsg("sunsoft.jws.visual.rt.shadow.MultiLineLabelShadow.DefaultText"),
		       0);
	attributes.add(/* NOI18N */"alignment",
		       /* NOI18N */"sunsoft.jws.visual.rt.type.AlignmentEnum",
		       new AlignmentEnum(Label.LEFT), 0);
	attributes.add(/* NOI18N */"maxColumns",
		       /* NOI18N */"java.lang.Integer",
		       new Integer(-1), 0);
    }
            
    protected Object getOnBody(String key) {
	MultiLineLabel label = (MultiLineLabel)body;
                
	if (key.equals(/* NOI18N */"text")) {
	    return label.getLabel();
	} else if (key.equals(/* NOI18N */"alignment")) {
	    return new AlignmentEnum(label.getAlignment());
	} else if (key.equals(/* NOI18N */"maxColumns")) {
	    return new Integer(label.getMaxColumns());
	} else
	    return (super.getOnBody(key));
    }
            
    protected void setOnBody(String key, Object value) {
	MultiLineLabel label = (MultiLineLabel)body;
                
	if (key.equals(/* NOI18N */"text")) {
	    label.setLabel((String)value);
	} else if (key.equals(/* NOI18N */"alignment")) {
	    label.setAlignment(((AlignmentEnum)value).intValue());
	} else if (key.equals(/* NOI18N */"maxColumns")) {
	    label.setMaxColumns(((Integer) value).intValue());
	} else {
	    super.setOnBody(key, value);
	}
    }
            
    public void createBody() {
	body = new MultiLineLabel();
    }
}
