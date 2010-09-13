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
 * @(#) ImageLabelShadow.java 1.30 - last change made 07/25/97
 */

package sunsoft.jws.visual.rt.shadow;

import sunsoft.jws.visual.rt.base.VJException;
import sunsoft.jws.visual.rt.type.ImageRef;
import sunsoft.jws.visual.rt.shadow.java.awt.CanvasShadow;
import sunsoft.jws.visual.rt.awt.ImageLabel;
import sunsoft.jws.visual.rt.base.Global;

import java.applet.Applet;
import java.awt.Color;

/**
 * Wraps an AWT widget.  The attributes available for this
 * class are listed below.  In the type column, type names beginning
 * with "sunsoft.jws.visual.rt" have been abbreviated to begin with
 * "rt".
 *
 * < pre>
name            type                      default value
-----------------------------------------------------------------------
image           rt.type.ImageRef          null
padWidth        java.lang.Integer         0
*  < /pre>
*
* Check the super class for additional attributes.
*
* @see ImageLabel
* @version 	1.30, 07/25/97
*/
public class ImageLabelShadow extends CanvasShadow {
    public ImageLabelShadow() {
        attributes.add(/* NOI18N */"image",
		       /* NOI18N */"sunsoft.jws.visual.rt.type.ImageRef",
		       null, 0);
        attributes.add(/* NOI18N */"padWidth",
		       /* NOI18N */"java.lang.Integer",
		       new Integer(0), 0);
        
        // foreground color is meaningless to an image label or button
        // so don't let it be user editable
        attributes.add(/* NOI18N */"foreground",
		       /* NOI18N */"java.awt.Color", Color.black, HIDDEN);
    }
    
    protected Object getOnBody(String key) {
        if (key.equals(/* NOI18N */"padWidth"))
            return (new Integer(((ImageLabel) body).getPadWidth()));
        else if (key.equals(/* NOI18N */"image"))
            // no value available from body
	    return (getFromTable(/* NOI18N */"image"));
        else
            return (super.getOnBody(key));
    }
    
    protected void setOnBody(String key, Object value) {
        ImageLabel label = (ImageLabel)body;
        
        if (key.equals(/* NOI18N */"padWidth"))
            label.setPadWidth(((Integer) value).intValue());
        else if (key.equals(/* NOI18N */"image")) {
            ImageRef ref = (ImageRef)value;
            if (ref == null)
                label.setImage(null);
            else {
                Applet applet = getGroup().getApplet();
                try {
                    label.setImage(ref.getImage(label, applet));
                    label.setDefaultWidth(ref.getWidth(label, applet));
                    label.setDefaultHeight(
			ref.getHeight(label, applet));
                }
                catch (VJException ex) {
                    // XXX If the image file is not found
                    // while loading the root, then
                    //     isLive() will return false even
                    //     though it should return true.
                    //     Throwing an exception can cause the
                    //     whole root not to load, which is
                    //     too drastic.  The layout windows
                    //     has to come up so that the user can
                    //     fix the problem.
                    // if (isLive())
		    System.out.println(
			Global.fmtMsg("sunsoft.jws.visual.rt.shadow.Error",
				      ex.getMessage()));
                    // else
		    //  throw ex;
                }
            }
        }
        else
            super.setOnBody(key, value);
    }
    
    public void createBody() {
        body = new ImageLabel(null);
    }
}
