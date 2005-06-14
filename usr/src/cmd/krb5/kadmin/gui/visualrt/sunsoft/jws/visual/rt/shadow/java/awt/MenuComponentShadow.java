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
 * @(#) MenuComponentShadow.java 1.22 - last change made 07/28/97
 */

package sunsoft.jws.visual.rt.shadow.java.awt;

import sunsoft.jws.visual.rt.base.Shadow;
import java.awt.MenuComponent;
import java.awt.Font;
import sunsoft.jws.visual.rt.base.Global;

/**
 * Wraps an AWT widget.  The attributes available for this
 * class are listed below.  In the type column, type names beginning
 * with "sunsoft.jws.visual.rt" have been abbreviated to begin with "rt".
 *
 * <pre>
name            type                      default value
-----------------------------------------------------------------------
font            java.awt.Font             null
*  < /pre>
*
* Check the super class for additional attributes.
*
* @see MenuComponent
* @version 	1.22, 07/28/97
*/
public class MenuComponentShadow extends Shadow {
    public MenuComponentShadow() {
        attributes.add(/* NOI18N */"font",
		       /* NOI18N */"java.awt.Font",
		       null, DONTFETCH | CONSTRUCTOR);
    }
    
    protected Object getOnBody(String key) {
        if (key.equals(/* NOI18N */"font"))
	    return (((MenuComponent) body).getFont());
        else
            return (super.getOnBody(key));
    }
    
    protected void setOnBody(String key, Object value) {
        if (key.equals(/* NOI18N */"font"))
	    ((MenuComponent) body).setFont((Font) value);
        else
            super.setOnBody(key, value);
    }
    
    public void createBody() {};
}
