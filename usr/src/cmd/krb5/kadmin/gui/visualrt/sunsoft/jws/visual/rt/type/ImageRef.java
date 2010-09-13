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
 * @(#) ImageRef.java 1.17 - last change made 08/07/96
 */

package sunsoft.jws.visual.rt.type;

import sunsoft.jws.visual.rt.base.Global;
import sunsoft.jws.visual.rt.base.VJException;

import java.awt.Component;
import java.awt.Image;
import java.awt.MediaTracker;
import java.awt.image.ImageObserver;
import java.applet.Applet;
import java.net.URL;
import java.net.MalformedURLException;

/**
 * Stores an image and the URL or filename that it came from.  This
 * class is capable of converting a filename to a URL and will do so
 * in order to load the image using a "file:" URL.  The creation of
 * the image is delayed until the image is requested.
 *
 * @see Image
 * @version 1.17, 08/07/96
 */
public class ImageRef implements ImageObserver {
    private Image img;
    private String filename;
    private URL url;
    private int imgWidth, imgHeight;
    private boolean gotWidth, gotHeight;
    private boolean errorFlagged = false;	// set in imageUpdate
    /* JSTYLED */
    private boolean disableErrorPrint = false;	// allow println in imageUpdate
    
    /**
     * Constructs a new instance of ImageRef that use a
     * URL to find the image when it is requested.  
     * The size of the image
     * cannot be appended to the URL.
     */
    public ImageRef(URL url) {
        init(null, url, -1, -1);
    }
    
    /**
     * Constructs a new instance of ImageRef given the name of a file
     * for the image.  The filename may be relative to the codebase or
     * any of the directories in the classpath.  The size of the image
     * may be appended to the filename to help with initial layout of
     * widgets containing images, like this: "imagefile.gif;24x48".
     */
    public ImageRef(String filename) {
        int index = filename.indexOf(/* NOI18N */ ';');
        if (index != -1) {
            String dims = filename.substring(index+1);
            filename = filename.substring(0, index);
            
            index = dims.indexOf(/* NOI18N */ 'x');
            
            try {
                int w, h;
                
                w = Integer.parseInt(dims.substring(0, index));
                h = Integer.parseInt(dims.substring(index+1));
                
                init(filename, null, w, h);
            } catch (Exception e) {
                init(filename, null, -1, -1);
            }
        } else {
            init(filename, null, -1, -1);
        }
    }
    
    private void init(String filename, URL url, int imgWidth,
		      int imgHeight) {
        this.img = null;
        this.filename = filename;
        this.url = url;
        this.imgWidth = imgWidth;
        this.imgHeight = imgHeight;
    }
    
    /**
     * Gets the image stored here (or referenced by the URL).  */
    public Image getImage(Component comp, Applet applet) {
        try {
            cacheImage(comp, applet);
        }
        catch (VJException vje) {
            return null;
        }
        return img;
    }
    
    /**
     * Returns the width of the image.  If the image is not yet loaded,
     * then returns the expected width of the image.
     */
    public int getWidth(Component comp, Applet applet) {
        try {
            cacheImage(comp, applet);
        }
        catch (VJException vje) {
            return 0;
        }
        return imgWidth;
    }
    
    /**
     * Returns the height of the image.  If the image is not 
     * yet loaded,
     * then returns the expected height of the image.
     */
    public int getHeight(Component comp, Applet applet) {
        try {
            cacheImage(comp, applet);
        }
        catch (VJException vje) {
            return 0;
        }
        return imgHeight;
    }
    
    /**
     * Returns the URL stored here.
     */
    public URL getURL() {
        return (url);
    }
    
    /**
     * Returns the file name of the image.
     */
    public String getFileName() {
        String name;
        
        if (filename != null)
            name = filename;
        else
            name = getURL().toExternalForm();
        
        return name;
    }
    
    /**
     * Returns the preferred string representation of this 
     * image reference.
    */
    public String toString() {
        String s = getFileName();
        
        if (imgWidth != -1 && imgHeight != -1)
            s = s + /* NOI18N */";" + imgWidth + /* NOI18N */"x"
		+ imgHeight;
        
        return s;
    }
    
    /**
     * Start loading the image if we haven't already.  
     * Attempt to cache the
     * width and height of the image.
     */
    private void cacheImage(Component comp, Applet applet)
	throws VJException {
        if (img != null)
            return;
        
        if (url == null) {
            url = Global.util.pathToURL(filename, applet);
            if (url == null)
		/* BEGIN JSTYLED */ 
		throw new VJException(Global.fmtMsg(
						    "sunsoft.jws.visual.rt.type.ImageRef.FMT.32",
						    Global.getMsg("sunsoft.jws.visual.rt.type.ImageRef.could__not__find__file__.32"),
						    filename,
						    Global.getMsg("sunsoft.jws.visual.rt.type.ImageRef.-ba--qu-__relative__to__class.33")));
	    /* END JSTYLED */
	}
        
        img = comp.getToolkit().getImage(url);
        if (img == null)
            return;
        
        int w = img.getWidth(this);
        if (w != -1)
            imgWidth = w;
        
        int h = img.getHeight(this);
        if (h != -1)
            imgHeight = h;
    }
    
    /**
     * Verifies that the image for this image ref loaded successfully,
     * returns true if it does.  Warning: will wait until image is
     * loaded before returning, so you shouldn't make this call unless
     * you are really interested in reporting an error message when
     * images can't be loaded.
     */
    public boolean verifyImage(Component comp, Applet applet) {
        disableErrorPrint = true;
        
        if (img != null) {
            // image has already been set up
            if (errorFlagged)
                return false;
            if (gotWidth && gotHeight)
                return true;
        } else {
            // set up the image
            try {
                cacheImage(comp, applet);
            }
            catch (VJException vje) {
                return false;
            }
            return true;
        }
        
        // start loading the image and wait for it to finish
        MediaTracker tracker = new MediaTracker(comp);
        tracker.addImage(img, 0);
        try {
            tracker.waitForID(0);
        }
        catch (InterruptedException e) {
            return false;
        }
        return ((tracker.statusID(0, false)
		 & MediaTracker.ERRORED) == 0);
    }
    
    /**
     * Gets called when an update of the image's width 
     * and height are available.
    */
    public boolean imageUpdate(Image img, int infoflags,
			       int x, int y, int width, int height) {
        if (((infoflags & ERROR) != 0) && !errorFlagged) {
            if (!disableErrorPrint)
                /* JSTYLED */
		System.out.println(Global.getMsg("sunsoft.jws.visual.rt.type.ImageRef.Error-co-__could__not__loa.34")
				   + getFileName() + /* NOI18N */"\"");
            errorFlagged = true;
        }
        
        if ((infoflags & WIDTH) != 0) {
            gotWidth = true;
            imgWidth = width;
        }
        
        if ((infoflags & HEIGHT) != 0) {
            gotHeight = true;
            imgHeight = height;
        }
        
        return (gotWidth && gotHeight);
    }
}
