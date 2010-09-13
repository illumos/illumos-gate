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
 * @(#) @(#) TextFieldShadow.java 1.34 - last change made 08/12/97 
 */

package sunsoft.jws.visual.rt.shadow.java.awt;

import sunsoft.jws.visual.rt.base.Global;
import sunsoft.jws.visual.rt.awt.GBConstraints;
import java.awt.TextField;
import java.awt.Insets;
import java.awt.SystemColor;

/**
 * Wraps an AWT widget.  The attributes available for this
 * class are listed below.  In the type column, type names beginning
 * with "sunsoft.jws.visual.rt" have been abbreviated to begin with "rt".
 *
 * <pre>
name            type                      default value
-----------------------------------------------------------------------
numColumns      java.lang.Integer         10
echoCharacter   java.lang.Character       new Character((char) 0)
*  < /pre>
*
* Check the super class for additional attributes.
*
* @see TextField
* @version 	1.34, 08/12/97
*/
public class TextFieldShadow extends TextComponentShadow {
    
    public TextFieldShadow() {
        attributes.add(/* NOI18N */"text",
		       /* NOI18N */"java.lang.String",
		       /* NOI18N */"", NOEDITOR);
        attributes.add(/* NOI18N */"numColumns",
		       /* NOI18N */"java.lang.Integer", new Integer(10),
		       CONSTRUCTOR);
        
        // This is a constructor attribute because the "setEchoCharater"
        // method does not actually update the text on Windows.  Also,
        // the workaround which is to set the text again does not
        // work on Motif!
        attributes.add(/* NOI18N */"echoCharacter",
		       /* NOI18N */"java.lang.Character",
		       new Character((char)0), CONSTRUCTOR);
        GBConstraints c = (GBConstraints)get(/* NOI18N */"GBConstraints");
        c.fill = GBConstraints.HORIZONTAL;
        attributes.add(/* NOI18N */"GBConstraints",
		       /* NOI18N */"sunsoft.jws.visual.rt.awt.GBConstraints",
		    c);
        
        // Workaround for layout problems caused by the fact that
        // textfields on all platforms except WindowsNT have gaps around
        // the border of the textfield.
        if (Global.isWindowsNT()) {
            attributes.add(/* NOI18N */"insets",
			   /* NOI18N */"java.awt.Insets",
			   new Insets(2, 2, 2, 2));
        }
        
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
        if (key.equals(/* NOI18N */"numColumns"))
	    return (new Integer((((TextField) body).getColumns())));
        if (key.equals(/* NOI18N */"echoCharacter")) {
            return (new Character((((TextField) body).getEchoChar())));
        } else
            return (super.getOnBody(key));
    }
    
    protected void setOnBody(String key, Object value) {
        if (key.equals(/* NOI18N */"numColumns")) {
            return;	// can't set this attribute dynamically
        } else if (key.equals(/* NOI18N */"echoCharacter")) {
            if (value != null) {
		    /* JSTYLED */
                ((TextField) body).setEchoCharacter(((Character)value).charValue());
            }
        }
        else
            super.setOnBody(key, value);
    }
    
    public void createBody() {
        boolean initText, initColumns;
        String initTextValue;
        Integer initColumnsValue;
        Character echoChar;
        
        initTextValue = (String) (getFromTable(/* NOI18N */"text"));
        initText = (initTextValue != null);
        
        initColumnsValue = (Integer) (getFromTable(/* NOI18N */"numColumns"));
        initColumns = (initColumnsValue != null);
        
        if (initText & initColumns)
            body = new TextField(initTextValue, initColumnsValue.intValue());
        else if (initColumns)
            body = new TextField(initColumnsValue.intValue());
        else if (initText)
            body = new TextField(initTextValue);
        else
            body = new TextField();
        
        echoChar = (Character) get(/* NOI18N */"echoCharacter");
        if (echoChar != null) {
            ((TextField) body).setEchoCharacter(echoChar.charValue());
        }
    }
}
