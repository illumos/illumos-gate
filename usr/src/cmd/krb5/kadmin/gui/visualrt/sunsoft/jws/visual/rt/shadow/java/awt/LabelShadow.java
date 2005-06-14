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
 * @(#) LabelShadow.java 1.26 - last change made 08/04/97
 */

package sunsoft.jws.visual.rt.shadow.java.awt;

import sunsoft.jws.visual.rt.type.AlignmentEnum;
import java.awt.Label;
import sunsoft.jws.visual.rt.base.Global;

/**
 * Wraps an AWT widget.  The attributes available for this
 * class are listed below.  In the type column, type names beginning
 * with "sunsoft.jws.visual.rt" have been abbreviated to begin with "rt".
 *
 * <pre>
name            type                      default value
-----------------------------------------------------------------------
alignment       rt.type.AlignmentEnum     center
text            java.lang.String          label
*  < /pre>
*
* Check the super class for additional attributes.
*
* @see Label
* @version 	1.26, 08/04/97
*/
public class LabelShadow extends ComponentShadow {
    public LabelShadow() {
        attributes.add(/* NOI18N */"text", /* NOI18N */"java.lang.String",
		    /* JSTYLED */
		       Global.getMsg("sunsoft.jws.visual.rt.shadow.java.awt.LabelShadow.text"),
		       NOEDITOR);
        attributes.add(/* NOI18N */"alignment",
		       /* NOI18N */"sunsoft.jws.visual.rt.type.AlignmentEnum",
		       new AlignmentEnum(Label.CENTER), 0);
    }
    
    protected Object getOnBody(String key) {
        if (key.equals(/* NOI18N */"text"))
	    return (((Label) body).getText());
        else if (key.equals(/* NOI18N */"alignment"))
            return (new AlignmentEnum(((Label) body).getAlignment()));
        else
            return (super.getOnBody(key));
    }
    
    protected void setOnBody(String key, Object value) {
        Label label = (Label) body;
        
        if (key.equals(/* NOI18N */"text")) {
            String text = label.getText();
            if ((value == null && text != null)
                || (value != null && !value.equals(text)))
		label.setText((String) value);
        } else if (key.equals(/* NOI18N */"alignment"))
            label.setAlignment(((AlignmentEnum) value).intValue());
        else
            super.setOnBody(key, value);
    }
    
    public void createBody() {
        body = new Label();
    }
}
