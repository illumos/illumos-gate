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
 * @(#) VJScrollbar.java 1.9 - last change made 07/25/97
 */

package sunsoft.jws.visual.rt.awt;

import sunsoft.jws.visual.rt.base.Global;
import java.awt.*;


public class VJScrollbar extends Panel {
    
    /**
     * The horizontal Scrollbar variable.
     */
    public static final int	HORIZONTAL = Scrollbar.HORIZONTAL;
    
    /**
     * The vertical Scrollbar variable.
     */
    public static final int	VERTICAL   = Scrollbar.VERTICAL;
    
    /**
     * Are we running on Windows
     */
    private boolean win;
    
    /**
     * Workaround scrollbar if we are running on Windows
     */
    private WinScrollbar winScrollbar;
    
    /**
     * Normal scrollbar if we are not running on Windows
     */
    private Scrollbar scrollbar;
    
    /**
     * Constructs a new vertical Scrollbar.
     */
    public VJScrollbar() {
        this(VERTICAL);
    }
    
    /**
     * Constructs a new Scrollbar with the specified orientation.
     */
    public VJScrollbar(int orientation) {
        win = Global.isWindows();
        
        GBLayout gridbag = new GBLayout();
        setLayout(gridbag);
        
        GBConstraints c = new GBConstraints();
        c.gridx = 0;
        c.gridy = 0;
        c.weightx = 1;
        c.weighty = 1;
        c.fill = GBConstraints.BOTH;
        
        if (win) {
            winScrollbar = new WinScrollbar(orientation);
            
            // #ifdef JDK1.1
            super.addImpl(winScrollbar, null, -1);
            // #else
	    // super.add(winScrollbar, -1);
            // #endif
            
            gridbag.setConstraints(winScrollbar, c);
        } else {
            scrollbar = new Scrollbar(orientation);
            
            // #ifdef JDK1.1
            super.addImpl(scrollbar, null, -1);
            // #else
	    // super.add(scrollbar, -1);
            // #endif
            
            gridbag.setConstraints(scrollbar, c);
        }
    }
    
    /**
     * Constructs a new Scrollbar with the specified orientation,
     * value, page size,  and minumum and maximum values.
     */
    public VJScrollbar(int orientation, int value, int visible,
		       int minimum, int maximum) {
        this(orientation);
        setValues(value, visible, minimum, maximum);
    }
    
    // #ifdef JDK1.1
    protected void addImpl(Component comp, Object constraints,
			   int index) {
        throw new Error(Global.getMsg(
		"sunsoft.jws.visual.rt.awt.VJScrollbar.CantAdd"));
    }
    // #else
    // public Component add(Component comp, int pos) {
    //   throw new Error("Cannot add components to a VJScrollbar");
    // }
    // #endif
    
    /**
     * Don't allow any components to be removed
     */
    public void remove(Component comp) {
        throw new Error(Global.getMsg(
		"sunsoft.jws.visual.rt.awt.VJScrollbar.CantRemove"));
    }
    
    /**
     * Returns the orientation for this Scrollbar.
     */
    public int getOrientation() {
        if (win)
            return winScrollbar.getOrientation();
        else
            return scrollbar.getOrientation();
    }
    
    /**
     * Returns the current value of this Scrollbar.
     */
    public int getValue() {
        if (win)
            return winScrollbar.getValue();
        else
            return scrollbar.getValue();
    }
    
    /**
     * Returns the current value of this Scrollbar.
     */
    public void setValue(int value) {
        if (win)
            winScrollbar.setValue(value);
        else
            scrollbar.setValue(value);
    }
    
    /**
     * Returns the minimum value of this Scrollbar.
     */
    public int getMinimum() {
        if (win)
            return winScrollbar.getMinimum();
        else
            return scrollbar.getMinimum();
    }
    
    /**
     * Returns the maximum value of this Scrollbar.
     */
    public int getMaximum() {
        if (win)
            return winScrollbar.getMaximum();
        else
            return scrollbar.getMaximum();
    }
    
    /**
     * Returns the visible amount of the Scrollbar.
     */
    public int getVisible() {
        if (win)
            return winScrollbar.getVisible();
        else
            return scrollbar.getVisible();
    }
    
    /**
     * Sets the line increment for this scrollbar. This is the value
     * that will be added (subtracted) when the user hits the line down
     * (up) gadgets.
     */
    public void setLineIncrement(int l) {
        // Workaround for Motif increment warning
        if (l < 1)
            l = 1;
        
        if (win)
            winScrollbar.setLineIncrement(l);
        else
            scrollbar.setLineIncrement(l);
    }
    
    /**
     * Gets the line increment for this scrollbar.
     */
    public int getLineIncrement() {
        if (win)
            return winScrollbar.getLineIncrement();
        else
            return scrollbar.getLineIncrement();
    }
    
    /**
     * Sets the page increment for this scrollbar. This is the value
     * that will be added (subtracted) when the user hits the page down
     * (up) gadgets.
     */
    public void setPageIncrement(int l) {
        // Workaround for Motif page increment warning
        if (l < 1)
            l = 1;
        
        if (win)
            winScrollbar.setPageIncrement(l);
        else
            scrollbar.setPageIncrement(l);
    }
    
    /**
     * Gets the page increment for this scrollbar.
     */
    public int getPageIncrement() {
        if (win)
            return winScrollbar.getPageIncrement();
        else
            return scrollbar.getPageIncrement();
    }
    
    /**
     * Sets the values for this Scrollbar.
     */
    public void setValues(int value, int visible, int minimum,
			  int maximum) {
        if (win)
            winScrollbar.setValues(value, visible, minimum, maximum);
        else
            scrollbar.setValues(value, visible, minimum, maximum);
    }
    
    /**
     * Returns the String parameters for this Scrollbar.
     */
    protected String paramString() {
        return super.paramString();
    }
    
    /**
     * Need to set the target of any scrollbar events to ourselves.
     */
    public boolean handleEvent(Event evt) {
        switch (evt.id) {
	case Event.SCROLL_LINE_UP:
	case Event.SCROLL_LINE_DOWN:
	case Event.SCROLL_PAGE_UP:
	case Event.SCROLL_PAGE_DOWN:
	case Event.SCROLL_ABSOLUTE:
            if (win) {
                if (evt.target == winScrollbar)
                    evt.target = this;
            } else {
                if (evt.target == scrollbar)
                    evt.target = this;
            }
            break;
	default: return true;
        }
        
        return super.handleEvent(evt);
    }
}
