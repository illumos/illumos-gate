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
 * @(#) ImageButton.java 1.16 - last change made 07/23/97
 */

package sunsoft.jws.visual.rt.awt;

import sunsoft.jws.visual.rt.base.DesignerAccess;
import sunsoft.jws.visual.rt.base.Global;
import java.awt.*;

/**
 * An image button (a 3D rect around an image.)  It greys itself out
 * when disabled and inverts the 3D rect and 
 * moves its image when depressed.
 *
 * @(#) @(#) ImageButton.java 1.16 - last change made 07/23/97
 */
public class ImageButton extends ImageLabel {
    private int lineWidth = 2;	  // thickness of 3D line around button
    private int pressMovement = 1;  // distance image moves
    // when button pressed
    protected boolean depressed;
    
    public ImageButton(Image img) {
        this(img, 20, 20);
    }
    
    public ImageButton(Image img, int w, int h) {
        super(img, w, h);
        depressed = false;
        padWidth = lineWidth + 2;
    }
    
    public void setPadWidth(int w) {
        super.setPadWidth(w + lineWidth);
    }
    
    public int getPadWidth() {
        return (super.getPadWidth() - lineWidth);
    }
    
    public void setLineWidth(int w) {
        int oldPadWidth = getPadWidth();
        lineWidth = w;
        setPadWidth(oldPadWidth);
    }
    
    public int getLineWidth() {
        return (lineWidth);
    }
    
    public void setPressMovement(int p) {
        if (p != pressMovement) {
            pressMovement = p;
            if (depressed) {
                Graphics g = getGraphics();
                if (g != null) {
                    Dimension d = size();
                    g.setColor(getBackground());
                    g.fillRect(0, 0, d.width, d.height);
                    repaint();
                }
            }
        }
    }
    
    public int getPressMovement() {
        return (pressMovement);
    }
    
    /**
     * Paint the image button with a 3D border
     */
    public void paint(Graphics g) {
        Color bg = getBackground();
        
        if (imgWidth >= 0 && imgHeight >= 0) {
            synchronized (DesignerAccess.mutex) {
                Dimension d = size();
                Image img = isEnabled() ? upImg : disImg;
                int x = (d.width - imgWidth) / 2;
                int y = (d.height - imgHeight) / 2;
                int offset = (depressed ? pressMovement : 0);
                
                if (pressMovement != 0) {
                    // clear the area needed to accomodate press movement
                    g.setColor(bg);
                    int m = (pressMovement < 0 ? -1 : 1);
                    for (int i = 0; i < pressMovement * m; i++)
                        g.drawRect(x + i * m + (m < 0 ? -1 : 0),
				   y + i * m + (m < 0 ? -1 : 0),
				imgWidth, imgHeight);
                }
                
                // draw the image and the 3D border
                if (upImg != null) {
                    // Bug workaround: If a SystemColor
                    // is used as the background color
                    // then Win32 JDK code loses the reference
                    // and the bg of a
                    // transparent gif will be black.
                    if (bg instanceof SystemColor)
                        bg = new Color(bg.getRGB());
                    g.drawImage(img, x + offset, y + offset, bg, this);
                }
                g.setColor(bg);
                for (int i = 0; i < lineWidth; i++) {
                    g.draw3DRect(i, i,
				 d.width - i*2 - 1,
				 d.height - i*2 - 1,
				 !depressed);
                }
            }
        }
    }
    
    public boolean mouseDown(Event e, int x, int y) {
        depressed = true;
        repaint();
        return true;
    }
    
    public boolean mouseDrag(Event e, int x, int y) {
        if (depressed != inside(x, y)) {
            depressed = !depressed;
            repaint();
        }
        return true;
    }
    
    public boolean mouseUp(Event evt, int x, int y) {
        if (depressed) {
            action();
            depressed = false;
            repaint();
        }
        return true;
    }
    
    public void action() {
        postEvent(new Event(this, Event.ACTION_EVENT, null));
    }
}
