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
 * @(#) @(#) TextAreaShadow.java 1.19 - last change made 08/12/97 
 */

package sunsoft.jws.visual.rt.shadow.java.awt;

import sunsoft.jws.visual.rt.awt.GBConstraints;
import java.awt.TextArea;
import java.awt.SystemColor;
import sunsoft.jws.visual.rt.base.Global;

/**
 * Wraps an AWT widget.  The attributes available for this
 * class are listed below.  In the type column, type names beginning
 * with "sunsoft.jws.visual.rt" have been abbreviated to begin with "rt".
 *
 * <pre>
name            type                      default value
-----------------------------------------------------------------------
numColumns      java.lang.Integer         10
numRows         java.lang.Integer         10
*  < /pre>
*
* Check the super class for additional attributes.
*
* @see TextArea
* @version 	1.19, 08/12/97
*/
public class TextAreaShadow extends TextComponentShadow {
    public TextAreaShadow() {
        attributes.add(/* NOI18N */"numColumns",
		       /* NOI18N */"java.lang.Integer", new Integer(10),
		       CONSTRUCTOR);
        attributes.add(/* NOI18N */"numRows",
		       /* NOI18N */"java.lang.Integer", new Integer(10),
		       CONSTRUCTOR);
        
        GBConstraints c = (GBConstraints)get(/* NOI18N */"GBConstraints");
        c.fill = GBConstraints.BOTH;
        attributes.add(/* NOI18N */"GBConstraints",
		       /* NOI18N */"sunsoft.jws.visual.rt.awt.GBConstraints",
		    c);
        
        // This is a work around for JDK color bug. The defaults are
        // not correctly set
        if (Global.isWindows())  {
            attributes.add(/* NOI18N */"background",
			   /* NOI18N */"java.awt.Color",
			   SystemColor.window, DONTFETCH);
        }
        if (Global.isMotif())  {
            attributes.add(/* NOI18N */"background",
			   /* NOI18N */"java.awt.Color",
			   SystemColor.text, DONTFETCH);
            attributes.add(/* NOI18N */"foreground",
			   /* NOI18N */"java.awt.Color",
			   SystemColor.textText, DONTFETCH);
        }
    }
    
    protected Object getOnBody(String key) {
        TextArea textarea = (TextArea)body;
        
        if (key.equals(/* NOI18N */"text")) {
            return textarea.getText();
        } else if (key.equals(/* NOI18N */"numColumns")) {
            return new Integer(textarea.getColumns());
        } else if (key.equals(/* NOI18N */"numRows")) {
            return new Integer(textarea.getRows());
        } else {
            return super.getOnBody(key);
        }
    }
    
    protected void setOnBody(String key, Object value) {
        TextArea textarea = (TextArea)body;
        
        if (key.equals(/* NOI18N */"text")) {
            String text = (String)value;
            String text2 = textarea.getText();
            if (text == null)
                text = /* NOI18N */"";
            if (!text.equals(text2))
		textarea.setText(text);
        } else if (key.equals(/* NOI18N */"numColumns")) {
            return;	// can't set this attribute dynamically
        } else if (key.equals(/* NOI18N */"numRows")) {
            return;	// can't set this attribute dynamically
        } else {
            super.setOnBody(key, value);
        }
    }
    
    public void createBody() {
        boolean initText, initColumns, initRows;
        String initTextValue;
        Integer initColumnsValue, initRowsValue;
        
        initTextValue = (String)getFromTable(/* NOI18N */"text");
        initText = (initTextValue != null);
        
        initColumnsValue = (Integer) (getFromTable(/* NOI18N */"numColumns"));
        initColumns = (initColumnsValue != null);
        
        initRowsValue = (Integer) (getFromTable(/* NOI18N */"numRows"));
        initRows = (initRowsValue != null);
        
        if (initText & initColumns & initRows) {
            body = new TextArea(initTextValue, initRowsValue.intValue(),
				initColumnsValue.intValue());
        } else if (initColumns & initRows) {
            body = new TextArea(initRowsValue.intValue(),
				initColumnsValue.intValue());
        } else if (initText) {
            body = new TextArea(initTextValue);
        } else {
            body = new TextArea();
        }
    }
}
