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
 * @(#) @(#) DialogShadow.java 1.60 - last change made 08/11/97
 */

package sunsoft.jws.visual.rt.shadow.java.awt;

import sunsoft.jws.visual.rt.base.DesignerAccess;
import sunsoft.jws.visual.rt.base.*;
import sunsoft.jws.visual.rt.type.AMRef;
import sunsoft.jws.visual.rt.awt.RootDialog;
import sunsoft.jws.visual.rt.base.Global;

import java.awt.*;
import java.util.Enumeration;

// This class makes the assumption that dialogClass is either null or a
// subclass of Frame.  No error checking is done here to enforce this.

/**
 * Wraps an AWT widget.  The attributes available for this
 * class are listed below.  In the type column, type names beginning
 * with "sunsoft.jws.visual.rt" have been abbreviated to begin with "rt".
 *
 * <pre>
name            type                      default value
-----------------------------------------------------------------------
frame           rt.type.AMRef             null
modal           java.lang.Boolean         false
resizable       java.lang.Boolean         true
title           java.lang.String          "Unnamed Dialog"
*  < /pre>
*
* modal: when set to true, the dialog's presence(its being visible)
* keeps the user from doing anything else in the generated application
    * until the dialog is popped down.
*  < p>
* Check the super class for additional attributes.
*
* @see Dialog
* @version 	1.60, 08/11/97
*/
public class DialogShadow extends WindowShadow {
    
    protected Frame dialogFrame;
    
    public DialogShadow() {
        attributes.add(/* NOI18N */"frame",
		       /* NOI18N */"sunsoft.jws.visual.rt.type.AMRef",
		       null, CONSTRUCTOR | NONBODY | HIDDEN);
        attributes.alias(/* NOI18N */"text", /* NOI18N */"title");
        attributes.add(/* NOI18N */"title", /* NOI18N */"java.lang.String",
		    /* JSTYLED */
		       Global.getMsg("sunsoft.jws.visual.rt.shadow.java.awt.DialogShadow.title"),
		       NOEDITOR);
        attributes.add(/* NOI18N */"modal",
		       /* NOI18N */"java.lang.Boolean",
		       Boolean.FALSE, CONSTRUCTOR);
        attributes.add(/* NOI18N */"resizable",
		       /* NOI18N */"java.lang.Boolean", Boolean.TRUE, 0);
    }
    
    //
    // getOnBody
    //
    protected Object getOnBody(String key) {
        if (body instanceof Dialog)
            return getOnDialogBody(key);
        else
            return getOnFrameBody(key);
    }
    
    private Object getOnDialogBody(String key) {
        Dialog dialog = (Dialog)body;
        
        if (key.equals(/* NOI18N */"modal")) {
            if (isLive())
		return new Boolean(dialog.isModal());
            else
                return getFromTable(/* NOI18N */"modal");
        } else if (key.equals(/* NOI18N */"resizable"))
            return (new Boolean(dialog.isResizable()));
        else if (key.equals(/* NOI18N */"title"))
            return (dialog.getTitle());
        else
            return (super.getOnBody(key));
    }
    
    private Object getOnFrameBody(String key) {
        Frame frame = (Frame)body;
        
        if (key.equals(/* NOI18N */"modal"))
	    return (getFromTable(/* NOI18N */"modal"));
        else if (key.equals(/* NOI18N */"resizable"))
            return (new Boolean(frame.isResizable()));
        else if (key.equals(/* NOI18N */"title"))
            return (frame.getTitle());
        else
            return (super.getOnBody(key));
    }
    
    //
    // setOnBody
    //
    protected void setOnBody(String key, Object value) {
        if (body instanceof Dialog)
            setOnDialogBody(key, value);
        else
            setOnFrameBody(key, value);
    }
    
    private void setOnDialogBody(String key, Object value) {
        Dialog dialog = (Dialog)body;
        
        if (key.equals(/* NOI18N */"modal"))
	    return; // cannot set modal once dialog is created
        else if (key.equals(/* NOI18N */"resizable"))
            dialog.setResizable(((Boolean)value).booleanValue());
        else if (key.equals(/* NOI18N */"title"))
            dialog.setTitle((String)value);
        else
            super.setOnBody(key, value);
    }
    
    private void setOnFrameBody(String key, Object value) {
        Frame frame = (Frame)body;
        
        if (key.equals(/* NOI18N */"modal"))
	    return; // cannot set modal once dialog is created
        else if (key.equals(/* NOI18N */"resizable"))
            frame.setResizable(((Boolean)value).booleanValue());
        else if (key.equals(/* NOI18N */"title"))
            frame.setTitle((String)value);
        else
            super.setOnBody(key, value);
    }
    
    public void create() {
        if (!isCreated() && Global.isWindows()) {
            createBody();
            if (!(body instanceof Dialog)) {
                if (attributes.get(/* NOI18N */"font").flagged(DEFAULT)) {
                    attributes.add(/* NOI18N */"font",
				/* NOI18N */"java.awt.Font",
				   new Font(/* NOI18N */"Dialog",
					    Font.PLAIN, 12), DONTFETCH);
                }
            }
        }
        
        super.create();
    }
    
    public void createBody() {
        dialogFrame = getFrame();
        
        // Create the dialog
        if (!inDesignerRoot()) {
            boolean modal;
            if (isLive())
	        /* JSTYLED */
	        modal = ((Boolean) getFromTable(/* NOI18N */"modal")).booleanValue();
            else
                modal = false;
            
            String title = (String) getFromTable(/* NOI18N */"title");
            
            Dialog dialog = new RootDialog(dialogFrame, title, modal);
            body = dialog;
        } else {
            try {
                body = DesignerAccess.getDialogClass().newInstance();
            } catch (InstantiationException ex) {
                throw new Error(ex.toString());
            } catch (IllegalAccessException ex) {
                throw new Error(ex.toString());
            }
        }
    }
    
    public void showComponent() {
        // Call addNotify on our frame if necessary.  Need to check for
        // null because we might not be created yet.
        if (dialogFrame != null && dialogFrame.getPeer() == null)
	    dialogFrame.addNotify();
        
        super.showComponent();
    }
    
    protected Frame getFrame() {
        AMRef ref;
        FrameShadow frameShadow;
        Frame frame;
        
        // Determine the frame that this dialog hangs off of
        ref = (AMRef) getFromTable(/* NOI18N */"frame");
        if (ref != null) {
            AttributeManager scope = getForwardingGroup(/* NOI18N */"frame");
            if (scope == null)
                scope = this;
            
            frameShadow = (FrameShadow)ref.getRef(scope);
            
            if (frameShadow == null)
		    /* JSTYLED */
                throw new Error(Global.getMsg("sunsoft.jws.visual.rt.awt.java.awt.DialogShadow.NullFrameShadow"));
            
            frame = getFrameBody(frameShadow);
        } else {
            frame = lookupFrame();
        }
        
        if (frame == null)
		/* JSTYLED */
            throw new Error(Global.getMsg("sunsoft.jws.visual.rt.awt.java.awt.DialogShadow.NullFrame"));
        
        return frame;
    }
    
    private Frame lookupFrame() {
        Root root = getRoot();
        
        // Try the main container
        AttributeManager mgr = root.getMainChild();
        if (mgr instanceof Group)
            mgr = DesignerAccess.getContainer((Group)mgr);
        
        if (mgr instanceof FrameShadow)
            return getFrameBody((FrameShadow)mgr);
        
        // Try any other child of the root if we aren't the main container
        if (mgr != this) {
            Enumeration e = root.getChildList();
            while (e.hasMoreElements()) {
                mgr = (AttributeManager)e.nextElement();
                if (mgr instanceof FrameShadow) {
                    Boolean v = (Boolean)mgr.get(/* NOI18N */"visible");
                    if (v.booleanValue())
			return getFrameBody((FrameShadow)mgr);
                }
            }
        }
        
        // Try for a shadow parent of the root
        FrameShadow frameShadow = lookupGroupFrame(root.getGroup());
        if (frameShadow != null) {
            Boolean v = (Boolean)mgr.get(/* NOI18N */"visible");
            if (v.booleanValue())
		return getFrameBody(frameShadow);
        }
        
        // Try the toplevel
        return getGroup().getTopLevel();
    }
    
    private Frame getFrameBody(FrameShadow frameShadow) {
        Frame frame = (Frame)frameShadow.getBody();
        
        if (frame == null) {
            frameShadow.createBody();
            frame = (Frame)frameShadow.getBody();
        }
        
        return frame;
    }
    
    private FrameShadow lookupGroupFrame(Group group) {
        if (group == null)
            return null;
        
        AttributeManager mgr = DesignerAccess.getContainer(group);
        if (mgr instanceof FrameShadow)
            return (FrameShadow)mgr;
        else
            return lookupGroupFrame(group.getParentGroup());
    }
    
    // Overridden AMContainer interfaces
    
    public void addChildBody(Shadow child) {
        if (body != null) {
            Container cntr = (Container)body;
            if ((cntr.getLayout() instanceof BorderLayout)
		&& getChildCount() == 1)
		cntr.add(/* NOI18N */"Center", (Component) child.getBody());
            else
                super.addChildBody(child);
        }
    }
}
