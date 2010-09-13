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
 * @(#) CheckboxShadow.java 1.22 - last change made 08/04/97
 */

package sunsoft.jws.visual.rt.shadow.java.awt;

import java.awt.Checkbox;
import sunsoft.jws.visual.rt.base.Global;

/**
 * Wraps an AWT widget.  The attributes available for this
 * class are listed below.  In the type column, type names beginning
 * with "sunsoft.jws.visual.rt" have been abbreviated to begin with "rt".
 *
 * <pre>
name            type                      default value
-----------------------------------------------------------------------
state           java.lang.Boolean         false
text            java.lang.String          checkbox
*  < /pre>
*
* Check the super class for additional attributes.
*
* @see Checkbox
* @version 	1.22, 08/04/97
*/
public class CheckboxShadow extends ComponentShadow {
    public CheckboxShadow() {
        // A bug in AWT keeps us from changing the label in a checkbox
        // (the setLabel() method doesn't work.)  For now the "text" attribute
        // is given the CONSTRUCTOR flag to work around this bug.
        attributes.add(/* NOI18N */"text", /* NOI18N */"java.lang.String",
		    /* JSTYLED */
		       Global.getMsg("sunsoft.jws.visual.rt.shadow.java.awt.CheckboxShadow.text"),
		       CONSTRUCTOR | NOEDITOR);
        attributes.add(/* NOI18N */"state",
		       /* NOI18N */"java.lang.Boolean", Boolean.FALSE, 0);
    }
    
    protected Object getOnBody(String key) {
        if (key.equals(/* NOI18N */"text"))
	    return (((Checkbox) body).getLabel());
        else if (key.equals(/* NOI18N */"state"))
            return (new Boolean((((Checkbox) body).getState())));
        else
            return (super.getOnBody(key));
    }
    
    protected void setOnBody(String key, Object value) {
        if (key.equals(/* NOI18N */"text")) {
            // WORK-AROUND: this is a constructor attribute because the
            // call below doesn't actually work (it causes a Motif error)
            // ((Checkbox) body).setLabel((String) value);
        } else if (key.equals(/* NOI18N */"state")) {
            if (((Checkbox) body).getState()
		!= ((Boolean) value).booleanValue())
		((Checkbox) body).setState(((Boolean) value).booleanValue());
        } else
            super.setOnBody(key, value);
    }
    
    public void createBody() {
        String text = (String) get(/* NOI18N */"text");
        if (text != null)
            body = new Checkbox(text);
        else
            body = new Checkbox();
    }
}
