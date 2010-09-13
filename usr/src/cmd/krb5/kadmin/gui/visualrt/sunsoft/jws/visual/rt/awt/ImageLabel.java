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
 * @(#) ImageLabel.java 1.30 - last change made 07/25/97
 */

package sunsoft.jws.visual.rt.awt;

import sunsoft.jws.visual.rt.base.Global;
import sunsoft.jws.visual.rt.base.DesignerAccess;
import java.awt.*;
import java.awt.image.RGBImageFilter;
import java.awt.image.FilteredImageSource;

/**
 * An image label.  It greys itself out when disabled.
 *
 * @(#) @(#) ImageLabel.java 1.30 - last change made 07/25/97
 */
public class ImageLabel extends Canvas {
    /**
     * The original image set in the constructor or in setImage().
     */
    protected Image origImg;
    
    /**
     * The massaged image (after the win95 work-around.)
     */
    protected Image upImg;
    
    /* BEGIN JSTYLED */
    /**
     * The image to use when the component is disabled.  
     * This is the upImg
     * stippled with the background color.
     */
    /* END JSTYLED */
    protected Image disImg;
    
    protected int padWidth = 0;
    protected int defaultWidth;
    protected int defaultHeight;
    protected int imgWidth = -1;
    protected int imgHeight = -1;
    
    public ImageLabel(Image img) {
        this(img, 20, 20);
    }
    
    public ImageLabel(Image img, int w, int h) {
        origImg = img;
        upImg = null;
        disImg = null;
        defaultWidth = w;
        defaultHeight = h;
    }
    
    public void setPadWidth(int w) {
        padWidth = w;
        repaint();
    }
    
    public int getPadWidth() {
        return (padWidth);
    }
    
    public void setDefaultWidth(int w) {
        if (w <= 0)
            return;
        defaultWidth = w;
    }
    
    public int getDefaultWidth() {
        return defaultWidth;
    }
    
    public void setDefaultHeight(int h) {
        if (h <= 0)
            return;
        defaultHeight = h;
    }
    
    public int getDefaultHeight() {
        return defaultHeight;
    }
    
    private void setUpImages() {
        if (origImg != null && upImg == null) {
            disImg = null;
            imgWidth = -1;
            imgHeight = -1;
            
            if (getBackground() != null) {
                upImg = origImg;
                
                // WORK-AROUND: create an image filter
                // for transparent gifs on Win95
                if (Global.isWindows95() && Global.javaVersion() ==
		    1.0) {
                    RGBImageFilter wfilter = new TransWorkAroundFilter(
						       getBackground());
                    upImg = createImage(new FilteredImageSource(
							upImg.getSource(),
								wfilter));
                }
                
                // start the loading of the main image
                prepareImage(upImg, this);
                
                // width and height might be immediately
                // available if already loaded
                imgWidth = upImg.getWidth(this);
                imgHeight = upImg.getHeight(this);
            }
        } else {
            imgWidth = defaultWidth;
            imgHeight = defaultHeight;
        }
        
        if (origImg != null && disImg == null &&
	    getBackground() != null) {
            // create a checkerboard image for disabled
            // version of the button
            RGBImageFilter filter = new CheckerboardFilter(
							   getBackground());
            disImg = createImage(new FilteredImageSource(
					 origImg.getSource(), filter));
        }
    }
    
    public void setImage(Image img) {
        origImg = img;
        upImg = null;
        disImg = null;
        setUpImages();
        repaint();
    }
    
    public Image getImage() {
        return (origImg);
    }
    
    public Dimension minimumSize() {
        if (upImg != null) {
            if (imgWidth == -1 || imgHeight == -1) {
                imgWidth = upImg.getWidth(this);
                imgHeight = upImg.getHeight(this);
            }
            
            if (imgWidth == -1 || imgHeight == -1)
                return (new Dimension(defaultWidth + padWidth * 2,
				      defaultHeight + padWidth * 2));
            else
                return (new Dimension(imgWidth + padWidth * 2,
				      imgHeight + padWidth * 2));
        } else {
            // return(new Dimension(0, 0));
            return (new Dimension(20, 20));
        }
    }
    
    public Dimension preferredSize() {
        return minimumSize();
    }
    
    /**
     * Overrides Component setBackground in order to redo the images,
     * because of the transparent gif workaround and also because the
     * disabled image relies on the background color.
     */
    public void setBackground(Color bg) {
        super.setBackground(bg);
        if (upImg != null) {
            // this isn't just a work-around for Win95,
            // but on ALL platforms
            // the disabled image must be redone when
            // the background color changes
            upImg = null;
            disImg = null;
            setUpImages();
        }
    }
    /* BEGIN JSTYLED */
    /* Invalidate all of a component's containers and then validate the
     * Window at the top.  Call this when the size of a component
     * changes and you wish to make the window that contains it resize
     * to accomodate the new size.
     */
    /* END JSTYLED */
    protected void updateWindow(Component c) {
        while (c != null) {
            c.invalidate();
            if (c instanceof Window) {
                c.validate();
                break;
            }
            c = c.getParent();
        }
    }
    
    /**
     * Figures out if this component needs to be resized.
     */
    protected void updateSize(int w, int h) {
        if (w >= 0 && h >= 0) {
            Dimension d = size();
            if (d.width != w + padWidth * 2 || d.height != h +
		padWidth * 2) {
                resize(w + padWidth * 2, h + padWidth * 2);
                updateWindow(this);
            }
        }
    }
    
    /**
     * By overriding update we insure that this component won't be
     * completely cleared with the background color each time it's
     * updated (while loading.)  We'd like less flickering than that.
     */
    public void update(Graphics g) {
        if (Global.isWindows())
            g = getGraphics();
        synchronized (DesignerAccess.mutex) {
            g.setColor(getBackground());
            Dimension d = size();
            if (upImg != null && (imgWidth >= 0 && imgHeight >= 0)) {
                // clear only the areas around the image (to
                // avoid having the image
                // flicker as it is loaded scanline-by-scanline)
                int x = (d.width - imgWidth) / 2;
                int y = (d.height - imgHeight) / 2;
                if (x > 0)
                    g.fillRect(0, 0, x, d.height);
                if (y > 0)
                    g.fillRect(0, 0, d.width, y);
                if (d.width > imgWidth)
                    g.fillRect(x + imgWidth, 0, d.width - (x
						   + imgWidth), d.height);
                if (d.height > imgHeight)
                    g.fillRect(0, y + imgHeight, d.width,
			       d.height - (y + imgHeight));
            } else {
                // there is no image, so clear the whole area
                g.fillRect(0, 0, d.width, d.height);
            }
            g.setColor(getForeground());
        }
        paint(g);
    }
    
    /* BEGIN JSTYLED */
    /**
     * Draw the image in the center of the available area.  
     * No background
     * clearing is done here (that job belongs to update().)
     */
    /* END JSTYLED */
    public void paint(Graphics g) {
        if (Global.isWindows())
            g = getGraphics();
        synchronized (DesignerAccess.mutex) {
            Dimension d = size();
            if (upImg != null && (imgWidth >= 0 && imgHeight >= 0)) {
                Image img = isEnabled() ? upImg : disImg;
                int x = (d.width - imgWidth) / 2;
                int y = (d.height - imgHeight) / 2;
                g.drawImage(img, x, y, getBackground(), this);
            } else {
                g.setColor(getForeground());
                g.drawRect(0, 0, d.width-1, d.height-1);
            }
        }
    }
    
    public boolean imageUpdate(Image img, int flags,
			       int x, int y, int w, int h) {
        
        if (img == upImg && (flags & ERROR) == 0) {
            boolean updateSize = false;
            
            if ((flags & WIDTH) != 0) {
                imgWidth = w;
                updateSize = true;
            }
            if ((flags & HEIGHT) != 0) {
                imgHeight = h;
                updateSize = true;
            }
            
            if (updateSize && imgWidth >= 0 && imgHeight >= 0) {
                // As soon as the size is known this
                // component needs to resize itself.
                updateSize(imgWidth, imgHeight);
                
                // This repaint is needed for images
                // that are already loaded, and
                // are being loaded a second time.
                // In this situation, the
                // update for the width and height comes
                // in after all the other
                // updates.  The call to super.imageUpdate
                // does not do a repaint
                // when the size changes, so we need to do one here.
                repaint();
            }
        }
        
        return super.imageUpdate(img, flags, x, y, w, h);
    }
    
    public void enable() {
        if (!isEnabled()) {
            super.enable();
            repaint();
        }
    }
    
    public void disable() {
        if (isEnabled()) {
            super.disable();
            repaint();
        }
    }
    
    public void addNotify() {
        super.addNotify();
        setUpImages();
    }
}


/**
 * A Work-around filter.
 *
 * Transparent gifs don't display properly on Windows 95.  
 * The work-around
 * is to replace transparent pixels with the background color of the
 * component they're being displayed in before drawing them.
 */
class TransWorkAroundFilter extends RGBImageFilter {
    private Color bg;
    
    TransWorkAroundFilter(Color bg) {
        if (bg != null) {
            this.bg = bg;
            canFilterIndexColorModel = false;
        } else {
            throw new Error(
			    /* JSTYLED */
			    Global.fmtMsg("sunsoft.jws.visual.rt.awt.ImageLabel.nullColor", "TransWorkAroundFilter"));
        }
    }
    
    public int filterRGB(int x, int y, int rgb) {
        if ((rgb & 0xff000000) == 0)
            return (bg.getRGB());
        else
            return (rgb);
    }
}


/**
 * Checkerboard color filter.
 *
 * Use for creating a greyed-out version of another image.  Supply the
 * color for the checkerboard spaces.  Every other pixel will still be
 * in the original color of the image.
 */
class CheckerboardFilter extends RGBImageFilter {
    private Color checked;
    
    CheckerboardFilter(Color checked) {
        if (checked != null) {
            this.checked = checked;
            canFilterIndexColorModel = false;
        } else {
            throw new Error(
			    /* JSTYLED */
			    Global.fmtMsg("sunsoft.jws.visual.rt.awt.ImageLabel.nullColor", "CheckerboardFilter"));
        }
    }
    
    public int filterRGB(int x, int y, int rgb) {
        if (y % 2 == x % 2)
            return (rgb);
        else
            return (checked.getRGB());
    }
}
