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
 * @(#) VJCanvasShadow.java 1.8 - last change made 07/25/97
 */
        
package sunsoft.jws.visual.rt.shadow;
        
import sunsoft.jws.visual.rt.shadow.java.awt.CanvasShadow;
import sunsoft.jws.visual.rt.awt.VJCanvas;
        
/*
 * Wraps an AWT widget.  The attributes available for this
 * class are listed below.  In the type column, type names beginning
 * with "sunsoft.jws.visual.rt" have been abbreviated to begin with "rt".
 *
 * < pre>
 *    name            type                      default value
 *    -----------------------------------------------------------------------
 *    minHeight       java.lang.Integer         100
 *    minWidth        java.lang.Integer         100
 *  < /pre>
 *
 * Check the super class for additional attributes.
 *
 * @see VJCanvas
 * @version 	1.8, 07/25/97
 */
public class VJCanvasShadow extends CanvasShadow {
            
    public VJCanvasShadow() {
	attributes.add(/* NOI18N */"minWidth",
		       /* NOI18N */"java.lang.Integer",
		       new Integer(100), 0);
	attributes.add(/* NOI18N */"minHeight",
		       /* NOI18N */"java.lang.Integer",
		       new Integer(100), 0);
    }
            
    protected Object getOnBody(String key) {
	if (key.equals(/* NOI18N */"minWidth"))
	    return (new Integer(((VJCanvas) body).getMinWidth()));
	else if (key.equals(/* NOI18N */"minHeight"))
	    return (new Integer(((VJCanvas) body).getMinHeight()));
	else
	    return (super.getOnBody(key));
    }
            
    protected void setOnBody(String key, Object value) {
	VJCanvas canvas = (VJCanvas)body;
                
	if (key.equals(/* NOI18N */"minWidth")) {
	    canvas.setMinWidth(((Integer)value).intValue());
	} else if (key.equals(/* NOI18N */"minHeight")) {
	    canvas.setMinHeight(((Integer)value).intValue());
	} else {
	    super.setOnBody(key, value);
	}
    }
            
    public void createBody() {
	body = new VJCanvas();
    }
}
