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
 * @(#) @(#) FrameShadow.java 1.65 - last change made 08/11/97
 */

package sunsoft.jws.visual.rt.shadow.java.awt;

import sunsoft.jws.visual.rt.base.Global;
import sunsoft.jws.visual.rt.base.DesignerAccess;
import sunsoft.jws.visual.rt.base.*;
import sunsoft.jws.visual.rt.type.ImageRef;
import sunsoft.jws.visual.rt.awt.RootFrame;

import java.awt.*;

/**
 * Wraps an AWT widget.  The attributes available for this
 * class are listed below.  In the type column, type names beginning
 * with "sunsoft.jws.visual.rt" have been abbreviated to begin with "rt".
 *
 * <pre>
name            type                      default value
-----------------------------------------------------------------------
+ background      java.awt.Color            #c0c0c0
icon            rt.type.ImageRef          null
menubar         rt.type.MenuBarRef        null
resizable       java.lang.Boolean         true
title           java.lang.String          "Unnamed Frame"
*  < /pre>
*
* + = this attribute overrides one inherited from an ancestor class.
*  < p>
* Check the super class for additional attributes.
*
* @see Frame
* @version 	1.65, 08/11/97
*/
public class FrameShadow extends WindowShadow {
    
    private int cursorCount = 0;
    private int prevCursor = Frame.DEFAULT_CURSOR;
    
    public FrameShadow() {
        attributes.add(/* NOI18N */"title", /* NOI18N */"java.lang.String",
		    /* JSTYLED */
		       Global.getMsg("sunsoft.jws.visual.rt.shadow.java.awt.FrameShadow.title"),
		       NOEDITOR);
        attributes.alias(/* NOI18N */"text", /* NOI18N */"title");
        attributes.add(/* NOI18N */"resizable",
		       /* NOI18N */"java.lang.Boolean", Boolean.TRUE, 0);
        attributes.add(/* NOI18N */"icon",
		       /* NOI18N */"sunsoft.jws.visual.rt.type.ImageRef",
		       null, 0);
        attributes.add(/* NOI18N */"menubar",
		    /* JSTYLED */
		       /* NOI18N */"sunsoft.jws.visual.rt.shadow.java.awt.MenuBarShadow",
		       null, DEFAULT | TRANSIENT);
        
        if (Global.isIrix())
	    attributes.add(/* NOI18N */"font", /* NOI18N */"java.awt.Font",
			   new Font(/* NOI18N */"Sansserif",
				    Font.PLAIN, 12), DONTFETCH);
        
        if (Global.isWindows()) {
            attributes.add(/* NOI18N */"font", /* NOI18N */"java.awt.Font",
			   new Font(/* NOI18N */"Dialog",
				    Font.PLAIN, 12), DONTFETCH);
        }
    }
    
    protected Object getOnBody(String key) {
        Frame frame = (Frame)body;
        
        if (key.equals(/* NOI18N */"title"))
	    return frame.getTitle();
        else if (key.equals(/* NOI18N */"resizable"))
            return new Boolean(frame.isResizable());
        else if (key.equals(/* NOI18N */"icon"))
            return getFromTable(/* NOI18N */"icon");
        else if (key.equals(/* NOI18N */"menubar")) {
            MenuBar menuBar = frame.getMenuBar();
            if (menuBar == null)
                return null;
            else
                return DesignerAccess.getShadowTable().get(menuBar);
        } else
            return (super.getOnBody(key));
    }
    
    protected void setOnBody(String key, Object value) {
        Frame frame = (Frame)body;
        
        if (key.equals(/* NOI18N */"title")) {
            frame.setTitle((String) value);
        } else if (key.equals(/* NOI18N */"resizable")) {
            frame.setResizable(((Boolean) value).booleanValue());
        } else if (key.equals(/* NOI18N */"menubar")) {
            MenuBarShadow s = (MenuBarShadow)getOnBody(/* NOI18N */"menubar");
            if (s != null) {
                remove(s);
                s.destroy();
            }
            
            if (value != null) {
                s = (MenuBarShadow)value;
                add(s);
                s.create();
            }
        } else if (key.equals(/* NOI18N */"icon")) {
            if (value != null) {
                try {
                    frame.setIconImage(((ImageRef) value).
				    getImage(frame, getGroup().getApplet()));
                }
                catch (VJException ex) {
                    if (isLive())
			    /* JSTYLED */
			    System.out.println(/* NOI18N */"Error: " + ex.getMessage());
                    else
                        throw ex;
                }
            } else if (frame.getPeer() == null)
                frame.setIconImage(null);
        }
        else
            super.setOnBody(key, value);
    }
    
    protected String getUserTypeName() {
        return (/* NOI18N */"frame");
    }
    
    public void createBody() {
        if (!inDesignerRoot())
	    body = new RootFrame();
        else {
            try {
                body = DesignerAccess.getFrameClass().newInstance();
            } catch (InstantiationException ex) {
                throw new Error(ex.toString());
            } catch (IllegalAccessException ex) {
                throw new Error(ex.toString());
            }
        }
    }
    
    // Overridden AMContainer interfaces
    
    public void addChildBody(Shadow child) {
        // frames will have a single central child and maybe a menubar
        if (body != null) {
            Frame frame = (Frame)body;
            
            if (child instanceof MenuBarShadow) {
                // add the menubar
                MenuBar currentMenuBar = frame.getMenuBar();
                if (currentMenuBar != null
		    && currentMenuBar != child.getBody()) {
			/* JSTYLED */
                    throw new Error(Global.fmtMsg("sunsoft.jws.visual.rt.awt.java.awt.FrameShadow.AlreadyHasMenubar", child.get(/* NOI18N */"name")));
                } else {
                    frame.setMenuBar((MenuBar) child.getBody());
                }
            } else {
                // add a component
                if (frame.getLayout() instanceof BorderLayout) {
                    frame.add(/* NOI18N */"Center",
			      (Component) child.getBody());
                } else {
                    super.addChildBody(child);
                }
            }
        }
    }
    
    public void removeChildBody(Shadow child) {
        if (body != null) {
            if ((child instanceof MenuBarShadow)) {
		/* JSTYLED */
                if (!((Frame) body).getMenuBar().equals((MenuBar) child.getBody())) {
			/* JSTYLED */
                    throw new Error(Global.fmtMsg("sunsoft.jws.visual.rt.awt.java.awt.FrameShadow.MenubarNotInstalled", child.get(/* NOI18N */"name")));
                } else {
                    // remove the  menubar
                    ((Frame) body).remove((MenuComponent) child.getBody());
                }
            } else {
                // remove a component
                ((Frame) body).remove((Component) child.getBody());
            }
        }
    }
    
    int incrCursor() {
        cursorCount++;
        return cursorCount;
    }
    
    int decrCursor() {
        cursorCount--;
        if (cursorCount < 0)
            cursorCount = 0;
        return cursorCount;
    }
    
    void setPrevCursor(int cursor) {
        prevCursor = cursor;
    }
    
    int getPrevCursor() {
        return prevCursor;
    }
}
