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
 * @(#) @(#) ScrollbarShadow.java 1.32 - last change made 07/28/97 
 */

package sunsoft.jws.visual.rt.shadow.java.awt;

import sunsoft.jws.visual.rt.awt.GBConstraints;
import sunsoft.jws.visual.rt.awt.VJScrollbar;
import sunsoft.jws.visual.rt.type.OrientationEnum;
import sunsoft.jws.visual.rt.base.Global;

/**
 * Wraps an AWT widget.  The attributes available for this
 * class are listed below.  In the type column, type names beginning
 * with "sunsoft.jws.visual.rt" have been abbreviated to begin with "rt".
 *
 * <pre>
name            type                      default value
-----------------------------------------------------------------------
lineIncrement   java.lang.Integer         10
maximum         java.lang.Integer         100
minimum         java.lang.Integer         0
orientation     rt.type.OrientationEnum   vertical
pageIncrement   java.lang.Integer         10
value           java.lang.Integer         0
visiblePageSize java.lang.Integer         50
*  < /pre>
*
* Check the super class for additional attributes.
*
* @see VJScrollbar
* @see Scrollbar
* @version 	1.32, 07/28/97
*/
public class ScrollbarShadow extends ComponentShadow {
    
    public ScrollbarShadow() {
        attributes.add(/* NOI18N */"orientation",
		       /* NOI18N */"sunsoft.jws.visual.rt.type.OrientationEnum",
		       new OrientationEnum(VJScrollbar.VERTICAL),
		       CONSTRUCTOR);
        attributes.add(/* NOI18N */"lineIncrement",
		       /* NOI18N */"java.lang.Integer", new Integer(10), 0);
        attributes.add(/* NOI18N */"maximum",
		       /* NOI18N */"java.lang.Integer", new Integer(100), 0);
        attributes.add(/* NOI18N */"minimum",
		       /* NOI18N */"java.lang.Integer", new Integer(0), 0);
        attributes.add(/* NOI18N */"pageIncrement",
		       /* NOI18N */"java.lang.Integer", new Integer(10), 0);
        attributes.add(/* NOI18N */"value",
		       /* NOI18N */"java.lang.Integer", new Integer(0), 0);
        attributes.add(/* NOI18N */"visiblePageSize",
		       /* NOI18N */"java.lang.Integer", new Integer(50), 0);
        
        GBConstraints c = (GBConstraints)get(/* NOI18N */"GBConstraints");
        c.fill = GBConstraints.VERTICAL;
        attributes.add(/* NOI18N */"GBConstraints",
		       /* NOI18N */"sunsoft.jws.visual.rt.awt.GBConstraints",
		    c);
    }
    
    /**
     * A change in the orientation of a scrollbar should also result
     * in a change of the fill mode in its GBConstraints.
     */
    private void setProperFill(int orientation) {
        GBConstraints c = (GBConstraints)get(/* NOI18N */"GBConstraints");
        
        if (c == null)
		/* JSTYLED */
            throw new Error(Global.getMsg("sunsoft.jws.visual.rt.awt.java.awt.ScrollbarShadow.NoLayoutConstraints"));
        else if ((c.fill == GBConstraints.VERTICAL
		  && orientation == VJScrollbar.HORIZONTAL) ||
		 (c.fill == GBConstraints.HORIZONTAL
		  && orientation == VJScrollbar.VERTICAL)) {
            c = (GBConstraints) c.clone();
            if (orientation == VJScrollbar.VERTICAL)
                c.fill = GBConstraints.VERTICAL;
            else
                c.fill = GBConstraints.HORIZONTAL;
            set(/* NOI18N */"GBConstraints", c);
        }
    }
    
    protected Object getOnBody(String key) {
        VJScrollbar sbar = (VJScrollbar)body;
        
        if (key.equals(/* NOI18N */"orientation"))
	    return (new OrientationEnum(sbar.getOrientation()));
        else if (key.equals(/* NOI18N */"lineIncrement"))
            return (new Integer(sbar.getLineIncrement()));
        else if (key.equals(/* NOI18N */"maximum"))
            return (new Integer(sbar.getMaximum()));
        else if (key.equals(/* NOI18N */"minimum"))
            return (new Integer(sbar.getMinimum()));
        else if (key.equals(/* NOI18N */"pageIncrement"))
            return (new Integer(sbar.getPageIncrement()));
        else if (key.equals(/* NOI18N */"value"))
            return (new Integer(sbar.getValue()));
        else if (key.equals(/* NOI18N */"visiblePageSize"))
            return (new Integer(sbar.getVisible()));
        else
            return (super.getOnBody(key));
    }
    
    protected void setOnBody(String key, Object value) {
        VJScrollbar sbar = (VJScrollbar)body;
        
        if (key.equals(/* NOI18N */"lineIncrement")) {
            sbar.setLineIncrement(((Integer) value).intValue());
        } else if (key.equals(/* NOI18N */"maximum")) {
            sbar.setValues(sbar.getValue(), sbar.getVisible(),
			   sbar.getMinimum(), ((Integer) value).intValue());
        } else if (key.equals(/* NOI18N */"minimum")) {
            sbar.setValues(sbar.getValue(), sbar.getVisible(),
			   ((Integer) value).intValue(), sbar.getMaximum());
        } else if (key.equals(/* NOI18N */"pageIncrement")) {
            sbar.setPageIncrement(((Integer) value).intValue());
        } else if (key.equals(/* NOI18N */"value")) {
            sbar.setValue(((Integer) value).intValue());
        } else if (key.equals(/* NOI18N */"visiblePageSize")) {
            sbar.setValues(sbar.getValue(),
			   ((Integer) value).intValue(),
			   sbar.getMinimum(), sbar.getMaximum());
        } else if (key.equals(/* NOI18N */"orientation")) {
            setProperFill(((OrientationEnum) value).intValue());
        } else {
            super.setOnBody(key, value);
        }
    }
    
    public void createBody() {
	    /* JSTYLED */
        int orientation = ((OrientationEnum) getFromTable(/* NOI18N */"orientation")).intValue();
        
        // Use the VJScrollbar because it has workarounds for the broken
        // scrollbars on Windows.
        body = new VJScrollbar(orientation);
    }
}
