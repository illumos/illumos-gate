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
 * @(#) GenericWindowShadow.java 1.13 - last change made 05/02/97
 */

package sunsoft.jws.visual.rt.shadow;

import sunsoft.jws.visual.rt.shadow.java.awt.WindowShadow;
import sunsoft.jws.visual.rt.awt.RootFrame;
import sunsoft.jws.visual.rt.awt.RootDialog;
import sunsoft.jws.visual.rt.base.Global;
import sunsoft.jws.visual.rt.base.VJException;
import sunsoft.jws.visual.rt.base.Message;


import java.awt.*;

/**
 * Wraps an AWT widget.  The attributes available for this
 * class are listed below.  In the type column, type names beginning
 * with "sunsoft.jws.visual.rt" have been abbreviated to begin with
 * "rt".
 *
 * < pre>
name            type                      default value
-----------------------------------------------------------------------
class           java.lang.String          rt.awt.RootFrame
title           java.lang.String          "Generic Window"
*  < /pre>
*
* class: the java class(that must be a sub-class of
* sunsoft.jws.visual.rt.awt.RootFrame and have a null constructor) of
* a user-written window class.  The GenericWindowShadow class can be
* used for quickly incorporating user's existing windows into a
* Visual Java GUI.
*  < p>
* Check the super class for additional attributes.
*
* @see RootFrame
* @see RootDialog
* @see GenericComponentShadow
* @version 1.13, 05/02/97
*/
public class GenericWindowShadow extends WindowShadow {
    private String className;
    private Class genericClass;
    
    public GenericWindowShadow() {
        attributes.add(/* NOI18N */"class",
		       /* NOI18N */"java.lang.String",
		       /* NOI18N */"sunsoft.jws.visual.rt.awt.RootFrame",
		       NOEDITOR);
        attributes.add(/* NOI18N */"title",
		       /* NOI18N */"java.lang.String",
		       /* NOI18N */"Generic Window", NOEDITOR);
        attributes.alias(/* NOI18N */"text", /* NOI18N */"title");
        
        if (Global.isIrix())
            attributes.add(/* NOI18N */"font", /* NOI18N */"java.awt.Font",
			   new Font(/* NOI18N */"Sansserif", Font.PLAIN, 12),
			   DONTFETCH);
        
        if (Global.isWindows()) {
            attributes.add(/* NOI18N */"background",
			   /* NOI18N */"java.awt.Color",
			   Color.lightGray, DONTFETCH);
            attributes.add(/* NOI18N */"font",
			   /* NOI18N */"java.awt.Font",
			   new Font(/* NOI18N */"Dialog", Font.PLAIN, 12),
			   DONTFETCH);
        }
    }
    
    protected boolean useLayoutSize() {
        return false;
    }
    
    protected Object getOnBody(String key) {
        if (key.equals(/* NOI18N */"class"))
            return getFromTable(/* NOI18N */"class");
        else if (key.equals(/* NOI18N */"title")) {
            if (body instanceof RootFrame)
                return ((RootFrame)body).getTitle();
            else
                return ((RootDialog)body).getTitle();
        }
        else
            return super.getOnBody(key);
    }
    
    protected void setOnBody(String key, Object value) {
        if (key.equals(/* NOI18N */"class")) {
            // Don't create a new instance unless
            // the class name has changed
            if (className.equals((String)value))
                return;
            
            Object obj = loadClass((String)value);
            destroy();
            body = obj;
            create();
        } else if (key.equals(/* NOI18N */"title")) {
            if (body instanceof RootFrame)
                ((RootFrame)body).setTitle((String)value);
            else
                ((RootDialog)body).setTitle((String)value);
        }
        else
            super.setOnBody(key, value);
    }
    
    public void createBody() {
        body = loadClass((String)get(/* NOI18N */"class"));
    }
    
    protected void registerBody() {
        super.registerBody();
        
        Window win = (Window)body;
        if (win.countComponents() == 0)
            win.add(new Label(/* NOI18N */"Generic Window"));
    }
    
    private Object loadClass(String name) {
        Class c;
        Object obj;
        
        // Load the class if the name doesn't match the previous name
        if (!name.equals(className)) {
            try {
                c = Class.forName(name);
            }
            catch (ClassNotFoundException ex) {
                throw new VJException(
		    /* JSTYLED */
		    Global.fmtMsg("sunsoft.jws.visual.rt.shadow.GenericWindowShadow.Class__not__found", name));
            }
        } else {
            c = genericClass;
        }
        
        // Create a new instance from the class
        try {
            obj = c.newInstance();
            if (!(obj instanceof RootFrame)
                && !(obj instanceof RootDialog)) {
                throw new VJException(
		    /* JSTYLED */
		    Global.fmtMsg("sunsoft.jws.visual.rt.shadow.GenericWindowShadow.NotARootSubclass", name));
            }
        }
        catch (IllegalAccessException ex) {
            throw new VJException(
		/* JSTYLED */
		Global.fmtMsg("sunsoft.jws.visual.rt.shadow.GenericWindowShadow.IllegalAccess", name));
        }
        catch (InstantiationException ex) {
            throw new VJException(
		/* JSTYLED */
		Global.fmtMsg("sunsoft.jws.visual.rt.shadow.GenericWindowShadow.InstantiationException", name));
        }
        catch (NoSuchMethodError ex) {
            throw new VJException(
		/* JSTYLED */
		Global.fmtMsg("sunsoft.jws.visual.rt.shadow.GenericWindowShadow.Noconstructor", name));
        }
        
        // No errors occurred, so update the name and class variables.
        genericClass = c;
        className = name;
        
        return obj;
    }
    
    public boolean handleEvent(Message msg, Event evt)
	{
	    if (msg.target == this && evt.id == Event.WINDOW_DESTROY)
	    {
		Window win = (Window)body;
		win.hide();
		return true;
	    } else
		return super.handleEvent(msg, evt);
	}
}
