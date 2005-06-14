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
 * @(#) ButtonShadow.java 1.26 - last change made 06/17/97
 */

package sunsoft.jws.visual.rt.shadow.java.awt;

import sunsoft.jws.visual.rt.base.Global;
import sunsoft.jws.visual.rt.awt.*;

import java.awt.Button;
import java.awt.Insets;

/**
 * Wraps an AWT widget.  The attributes available for this
 * class are listed below.  In the type column, type names beginning
 * with "sunsoft.jws.visual.rt" have been abbreviated to begin with "rt".
 *
 * <pre>
name            type                      default value
-----------------------------------------------------------------------
standard        java.lang.Boolean         true
text            java.lang.String          button
*  < /pre>
*
* Check the super class for additional attributes.
*
* @see Button
* @version 	1.26, 06/17/97
*/
public class ButtonShadow extends ComponentShadow {
    public ButtonShadow() {
        attributes.add(/* NOI18N */"text",
		       /* NOI18N */"java.lang.String",
		    /* JSTYLED */
		       Global.getMsg("sunsoft.jws.visual.rt.shadow.java.awt.ButtonShadow.button"),
		       NOEDITOR);
        attributes.add(/* NOI18N */"standard",
		       /* NOI18N */"java.lang.Boolean", Boolean.TRUE, 0);
        
        if (Global.isWindows()) {
            attributes.add(/* NOI18N */"insets", /* NOI18N */"java.awt.Insets",
			   new Insets(2, 2, 2, 2), NONBODY | CONTAINER);
        }
    }
    
    protected Object getOnBody(String key) {
        Button button = (Button)body;
        
        if (key.equals(/* NOI18N */"text")) {
            return button.getLabel();
        } else if (key.equals(/* NOI18N */"standard")) {
            if (button instanceof VJButton)
                return new Boolean(((VJButton)button).isStandard());
            else
                return Boolean.FALSE;
        } else {
            return super.getOnBody(key);
        }
    }
    
    protected void setOnBody(String key, Object value) {
        Button button = (Button)body;
        
        if (key.equals(/* NOI18N */"text")) {
            String text = button.getLabel();
            if ((value == null && text != null)
                || (value != null && !value.equals(text)))
		button.setLabel((String) value);
        } else if (key.equals(/* NOI18N */"standard")) {
            if (button instanceof VJButton)
                ((VJButton)button).setStandard(((Boolean)value).booleanValue());
        } else {
            super.setOnBody(key, value);
        }
    }
    
    public void createBody() {
        body = new VJButton();
    }
}
