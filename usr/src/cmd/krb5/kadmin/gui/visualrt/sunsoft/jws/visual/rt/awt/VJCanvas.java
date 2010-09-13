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
 * @(#) VJCanvas.java 1.5 - last change made 12/10/96
 */

package sunsoft.jws.visual.rt.awt;

import sunsoft.jws.visual.rt.base.Global;
import java.awt.*;

public class VJCanvas extends Canvas {
    
    public static final int PAINT_EVENT = 2567;
    public static final int UPDATE_EVENT = 2568;
    
    /**
     * This Canvas doesn't keep growing like the regular Canvas does.
     **/
    
    int minWidth = 100, minHeight = 100;
    
    public void setMinWidth(int minWidth) {
        this.minWidth = minWidth;
    }
    
    public void setMinHeight(int minHeight) {
        this.minHeight = minHeight;
    }
    
    public int getMinWidth() {
        return minWidth;
    }
    
    public int getMinHeight() {
        return minHeight;
    }
    
    public Dimension minimumSize() {
        return new Dimension(minWidth, minHeight);
    }
    
    public Dimension preferredSize() {
        return minimumSize();
    }
    
    public void update(Graphics g) {
        if (Global.isWindows())
            g = getGraphics();
        postEvent(new Event(this, UPDATE_EVENT, g));
        paint(g);
    }
    
    public void paint(Graphics g) {
        if (Global.isWindows())
            g = getGraphics();
        super.paint(g);
        postEvent(new Event(this, PAINT_EVENT, g));
    }
    
    //
    // Workaround for Windows95 AWT bug:  If
    // you call request focus while
    // the mouse is pressed, you get spurious
    // mouse down events.  Not only
    // that, but the spurious events have
    // clickCount set to 2, so you end
    // up with spurious double clicks.
    // On Windows95 the component
    // automatically gets the focus when
    // you press the mouse inside it.
    // Therefore, it isn't necessary to
    // call requestFocus at all if running
    // on Windows and the mouse is down (and this avoids the bug).
    //
    public boolean postEvent(Event e) {
        // Fix the click count
        VJPanel.fixClickCount(e);
        
        if (e.id == Event.MOUSE_DOWN)
            VJPanel.isMouseDown = true;
        else if (e.id == Event.MOUSE_UP)
            VJPanel.isMouseDown = false;
        return super.postEvent(e);
    }
    
    public void requestFocus() {
        if (!Global.isWindows() || !VJPanel.isMouseDown)
            super.requestFocus();
    }
}
