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
 * @(#) FileDialogShadow.java 1.15 - last change made 08/09/97
 */

package sunsoft.jws.visual.rt.shadow.java.awt;

import sunsoft.jws.visual.rt.type.ModeEnum;
import sunsoft.jws.visual.rt.base.Global;

import java.awt.FileDialog;
import java.io.FilenameFilter;

/**
 * Wraps an AWT widget.  The attributes available for this
 * class are listed below.  In the type column, type names beginning
 * with "sunsoft.jws.visual.rt" have been abbreviated to begin with "rt".
 *
 * <pre>
name            type                      default value
-----------------------------------------------------------------------
directory       java.lang.String          null
file            java.lang.String          null
+ modal           java.lang.Boolean         true
mode            rt.type.ModeEnum	      load
+ title           java.lang.String          "Unnamed File Dialog"
+ visible         java.lang.Boolean         false
*  < /pre>
*
* + = this attribute overrides one inherited from an ancestor class.
*  < p>
* mode: can be "load" or "save", and determines whether the file dialog
* is to be used for opening or saving a file, repectively(the text in
* the lower left button of the file dialog will read either "Open" or
* "Save" depending on the mode.)
*  < p>
* Check the super class for additional attributes.
*
* @see FileFialog
* @version 	1.15, 08/09/97
*/
public class FileDialogShadow extends DialogShadow {
    
    public FileDialogShadow() {
        attributes.add(/* NOI18N */"title", /* NOI18N */"java.lang.String",
		    /* JSTYLED */
		       Global.getMsg("sunsoft.jws.visual.rt.shadow.java.awt.FileDialogShadow.title"),
		       NOEDITOR);
        attributes.add(/* NOI18N */"directory",
		       /* NOI18N */"java.lang.String", null, NOEDITOR);
        attributes.add(/* NOI18N */"file",
		       /* NOI18N */"java.lang.String", null, NOEDITOR);
        
        // REMIND: This is commented out because Java WorkShop's version of
        // the JDK does not implement the FileDialog.setFilenameFilter()
        // method.
        // attributes.add(/* NOI18N */"filenameFilter",
	//  /* NOI18N */"java.io.FilenameFilter",
        //		      null, HIDDEN);
        
        // which mode, load or save?
        attributes.add(/* NOI18N */"mode",
		       /* NOI18N */"sunsoft.jws.visual.rt.type.ModeEnum",
		       new ModeEnum(FileDialog.LOAD), CONSTRUCTOR);
        
        // Always modal
        attributes.add(/* NOI18N */"modal",
		       /* NOI18N */"java.lang.Boolean", Boolean.TRUE, HIDDEN);
        
        // Always resizeable
        attributes.add(/* NOI18N */"resizable",
		       /* NOI18N */"java.lang.Boolean", Boolean.TRUE, HIDDEN);
        
        // Not visible by default
        attributes.add(/* NOI18N */"visible",
		       /* NOI18N */"java.lang.Boolean", Boolean.FALSE,
		       HIDDEN | NONBODY);
    }
    
    public void showComponent() {
        checkCreate();
        ((FileDialog)body).show();
        set(/* NOI18N */"visible", Boolean.FALSE);
    }
    
    protected Object getOnBody(String key) {
        FileDialog fd = (FileDialog)body;
        
        if (key.equals(/* NOI18N */"directory")) {
            return fd.getDirectory();
        } else if (key.equals(/* NOI18N */"file")) {
            String file = fd.getFile();
            
            // WORK-AROUND: remove the .*.* that Win95 puts on filename
            if (file != null && file.endsWith(/* NOI18N */".*.*"))
		file = file.substring(0, file.length() - 4);
            
            return file;
        }
        
        // REMIND: This is commented out because Java WorkShop's version of
        // the JDK does not implement the FileDialog.setFilenameFilter()
        // method.
        // else if (key.equals(/* NOI18N */"filenameFilter"))
	//   return fd.getFilenameFilter();
        
        else if (key.equals(/* NOI18N */"mode"))
            return (new ModeEnum(fd.getMode()));
        else
            return (super.getOnBody(key));
    }
    
    protected void setOnBody(String key, Object value) {
        FileDialog fd = (FileDialog)body;
        
        if (key.equals(/* NOI18N */"directory"))
	    fd.setDirectory((String)value);
        else if (key.equals(/* NOI18N */"file"))
            fd.setFile((String)value);
        
        // REMIND: This is commented out because Java WorkShop's version of
        // the JDK does not implement the FileDialog.setFilenameFilter()
        // method.
        // else if (key.equals(/* NOI18N */"filenameFilter"))
	//   fd.setFilenameFilter((FilenameFilter)value);
        
        else if (key.equals(/* NOI18N */"mode")) {
            // Do nothing ; constructor attribute
        }
        else
            super.setOnBody(key, value);
    }
    
    public void createBody() {
        dialogFrame = getFrame();
        String title = (String) getFromTable(/* NOI18N */"title");
        int mode = ((ModeEnum) getFromTable(/* NOI18N */"mode")).intValue();
        
        body = new FileDialog(dialogFrame, title, mode);
    }
    
    /**
     * Disposes of the AWT top-level window so that window system
     * resources are reclaimed.
     */
    protected void destroyBody() {
        //
        // Workaround for Motif bug during removeNotify
        //
        // java.lang.NullPointerException
        //     at sun.awt.motif.MComponentPeer.dispose(MComponentPeer.java:175)
        //        at sun.awt.motif.MDialogPeer.dispose(MDialogPeer.java:73)
        //        at java.awt.Component.removeNotify(Component.java:1037)
        //        at java.awt.Container.removeNotify(Container.java:385)
        //        at java.awt.Window.dispose(Window.java:127)
        //        at sunsoft.jws.visual.rt.shadow.java.awt.
        //           FileDialogShadow.destroyBody(FileDialogShadow.java:103)
        //
        if (!Global.isMotif())
	    ((FileDialog)body).dispose();
        
        body = null;
    }
}
