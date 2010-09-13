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
 * @(#) MenuItemShadow.java 1.28 - last change made 07/28/97
 */

package sunsoft.jws.visual.rt.shadow.java.awt;

import sunsoft.jws.visual.rt.base.Global;
import java.awt.Font;
import java.awt.MenuItem;

/**
 * Wraps an AWT widget.  The attributes available for this
 * class are listed below.  In the type column, type names beginning
 * with "sunsoft.jws.visual.rt" have been abbreviated to begin with "rt".
 *
 * <pre>
name            type                      default value
-----------------------------------------------------------------------
enabled         java.lang.Boolean         true
separator       java.lang.Boolean         false
text            java.lang.String          menuitem
*  < /pre>
*
* Check the super class for additional attributes.
*
* @see MenuItem
* @version 	1.28, 07/28/97
*/
public class MenuItemShadow extends MenuComponentShadow {
    boolean hasSeparator = false;
    
    public MenuItemShadow() {
        attributes.add(/* NOI18N */"enabled",
		       /* NOI18N */"java.lang.Boolean",
		       Boolean.TRUE, 0);
        attributes.add(/* NOI18N */"text",
		       /* NOI18N */"java.lang.String",
		       /* NOI18N */"menuitem", NOEDITOR);
        attributes.add(/* NOI18N */"separator",
		       /* NOI18N */"java.lang.Boolean", Boolean.FALSE,
		       NONBODY | CONTAINER);
        
        if (Global.isIrix())
	    attributes.add(/* NOI18N */"font", /* NOI18N */"java.awt.Font",
			   new Font(/* NOI18N */"Sansserif",
				    Font.PLAIN, 12), DONTFETCH);
        else if (Global.isMotif())
            attributes.add(/* NOI18N */"font", /* NOI18N */"java.awt.Font",
			   new Font(/* NOI18N */"Dialog",
				    Font.PLAIN, 12), DONTFETCH);
    }
    
    protected Object getOnBody(String key) {
        if (key.equals(/* NOI18N */"enabled"))
	    return (new Boolean(((MenuItem) body).isEnabled()));
        else if (key.equals(/* NOI18N */"text"))
            return (((MenuItem) body).getLabel());
        else
            return (super.getOnBody(key));
    }
    
    protected void setOnBody(String key, Object value) {
        if (key.equals(/* NOI18N */"enabled"))
	    ((MenuItem) body).enable(((Boolean) value).booleanValue());
        else if (key.equals(/* NOI18N */"text"))
            ((MenuItem) body).setLabel((String) value);
        else
            super.setOnBody(key, value);
    }
    
    public void createBody() {
        body = new MenuItem((String) getFromTable(/* NOI18N */"text"));
    }
}
