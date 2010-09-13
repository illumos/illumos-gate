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
 * @(#) ImageButtonShadow.java 1.28 - last change made 07/25/97
 */

package sunsoft.jws.visual.rt.shadow;

import sunsoft.jws.visual.rt.type.ImageRef;
import sunsoft.jws.visual.rt.awt.ImageButton;

/**
 * Wraps an AWT widget.  The attributes available for this
 * class are listed below.  In the type column, type names beginning
 * with "sunsoft.jws.visual.rt" have been abbreviated to begin with
 * "rt".
 *
 * < pre>
name            type                      default value
-----------------------------------------------------------------------
lineWidth       java.lang.Integer         2
+ padWidth        java.lang.Integer         2
pressMovement   java.lang.Integer         1
*  < /pre>
*
* + = this attribute overrides one inherited from an ancestor class.
*  < p>
* Check the super class for additional attributes.
*
* @see ImageButton
* @version 	1.28, 07/25/97
*/
public class ImageButtonShadow extends ImageLabelShadow {
    public ImageButtonShadow() {
        attributes.add(/* NOI18N */"padWidth",
		       /* NOI18N */"java.lang.Integer",
		       new Integer(2), 0);
        attributes.add(/* NOI18N */"lineWidth",
		       /* NOI18N */"java.lang.Integer", new Integer(2), 0);
        attributes.add(/* NOI18N */"pressMovement",
		       /* NOI18N */"java.lang.Integer", new Integer(1), 0);
    }
    
    protected Object getOnBody(String key) {
        ImageButton button = (ImageButton)body;
        
        if (key.equals(/* NOI18N */"lineWidth"))
            return (new Integer(button.getLineWidth()));
        else if (key.equals(/* NOI18N */"pressMovement"))
            return (new Integer(button.getPressMovement()));
        else
            return (super.getOnBody(key));
    }
    
    protected void setOnBody(String key, Object value) {
        ImageButton button = (ImageButton)body;
        
        if (key.equals(/* NOI18N */"lineWidth"))
            button.setLineWidth(((Integer) value).intValue());
        else if (key.equals(/* NOI18N */"pressMovement"))
            button.setPressMovement(((Integer) value).intValue());
        else
            super.setOnBody(key, value);
    }
    
    public void createBody() {
        body = new ImageButton(null);
    }
}
