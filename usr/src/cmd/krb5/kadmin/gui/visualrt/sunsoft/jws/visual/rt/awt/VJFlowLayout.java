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
 * @(#)FlowLayout.java	1.18 95/12/14 Arthur van Hoff
 *
 * Copyright (c) 1994, 2001 by Sun Microsystems, Inc. 
 * All rights reserved.
 *
 * Permission to use, copy, modify, and distribute this software
 * and its documentation for NON-COMMERCIAL purposes and without
 * fee is hereby granted provided that this copyright notice
 * appears in all copies. Please refer to the file "copyright.html"
 * for further important copyright and licensing information.
 *
 * SUN MAKES NO REPRESENTATIONS OR WARRANTIES ABOUT THE SUITABILITY OF
 * THE SOFTWARE, EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED
 * TO THE IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
 * PARTICULAR PURPOSE, OR NON-INFRINGEMENT. SUN SHALL NOT BE LIABLE FOR
 * ANY DAMAGES SUFFERED BY LICENSEE AS A RESULT OF USING, MODIFYING OR
 * DISTRIBUTING THIS SOFTWARE OR ITS DERIVATIVES.
 */
package sunsoft.jws.visual.rt.awt;

import java.awt.*;

/**
 * Flow layout is used to layout buttons in a panel. It will arrange
 * buttons left to right until no more buttons fit on the same line.
 * Each line is centered.
 *
 * @version 	1.18, 14 Dec 1995
 * @author 	Arthur van Hoff
 * @author 	Sami Shaio
 */
public class VJFlowLayout implements LayoutManager {
    
    /**
     * The left alignment variable. 
     */
    public static final int LEFT 	= 0;
    
    /**
     * The right alignment variable. 
     */
    public static final int CENTER 	= 1;
    
    /**
     * The right alignment variable.
     */
    public static final int RIGHT 	= 2;
    
    // Private variables
    private static final int PREFERREDSIZE = 0;
    private static final int MINIMUMSIZE = 1;
    
    private int align;
    private int hgap;
    private int vgap;
    
    private int minimumWidth;
    
    /**
     * Constructs a new Flow Layout with a centered alignment.
     */
    public VJFlowLayout() {
        this.align = LEFT;
        this.hgap = 5;
        this.vgap = 5;
        this.minimumWidth = 0;
    }
    
    public void setAlignment(int align) {
        this.align = align;
    }
    
    public int getAlignment() {
        return align;
    }
    
    public void setHGap(int hgap) {
        this.hgap = hgap;
    }
    
    public int getHGap() {
        return hgap;
    }
    
    public void setVGap(int vgap) {
        this.vgap = vgap;
    }
    
    public int getVGap() {
        return vgap;
    }
    
    public void setMinimumWidth(int width) {
        this.minimumWidth = width;
    }
    
    public int getMinimumWidth() {
        return minimumWidth;
    }
    
    /**
     * Adds the specified component to the layout. 
     * Not used by this class.
     * @param name the name of the component
     * @param comp the the component to be added
     */
    public void addLayoutComponent(String name, Component comp) {
    }
    
    /**
     * Removes the specified component from the layout. Not used by
     * this class.  
     * @param comp the component to remove
     */
    public void removeLayoutComponent(Component comp) {
    }
    
    /**
     * Returns the preferred dimensions for 
     * this layout given the components
     * in the specified target container.
     * @param target the component which needs to be laid out
     * @see Container
     * @see #minimumLayoutSize
     */
    public Dimension preferredLayoutSize(Container target) {
        return calcLayoutSize(target, PREFERREDSIZE);
    }
    
    /**
     * Returns the minimum dimensions needed to layout the components
     * contained in the specified target container.
     * @param target the component which needs to be laid out 
     * @see #preferredLayoutSize
     */
    public Dimension minimumLayoutSize(Container target) {
        return calcLayoutSize(target, MINIMUMSIZE);
    }
    
    private Dimension calcLayoutSize(Container target, int which) {
        Insets insets = target.insets();
        Dimension r = new Dimension(0, vgap + insets.top +
				    insets.bottom);
        int nmembers = target.countComponents();
        int rowCount = 0;
        int rowWidth = insets.left + insets.right + hgap;
        int rowHeight = 0;
        
        for (int i = 0; i < nmembers; i++) {
            Component m = target.getComponent(i);
            
            if (m.isVisible()) {
                Dimension d;
                if (which == PREFERREDSIZE)
                    d = m.preferredSize();
                else
                    d = m.minimumSize();
                
                if (minimumWidth > 0 && rowCount != 0 &&
		    rowWidth + d.width + hgap > minimumWidth) {
                    
                    r.width = Math.max(rowWidth, r.width);
                    r.height += (rowHeight + vgap);
                    
                    rowCount = 0;
                    rowWidth = insets.left + insets.right + hgap;
                    rowHeight = 0;
                }
                
                rowWidth += (d.width + hgap);
                rowHeight = Math.max(rowHeight, d.height);
                rowCount++;
            }
        }
        
        if (rowCount > 0) {
            r.width = Math.max(rowWidth, r.width);
            r.height += (rowHeight + vgap);
        }
        
        return r;
    }
    
    /**
     * Centers the elements in the specified row, if there is any slack.
     * @param target the component which needs to be moved
     * @param x the x coordinate
     * @param y the y coordinate
     * @param width the width dimensions
     * @param height the height dimensions
     * @param rowStart the beginning of the row
     * @param rowEnd the the ending of the row
     */
    private void moveComponents(Container target, int x, int y,
			int width, int height, int rowStart, int rowEnd) {
        switch (align) {
	case LEFT:
            break;
	case CENTER:
            x += width / 2;
            break;
	case RIGHT:
            x += width;
            break;
        }
        for (int i = rowStart; i < rowEnd; i++) {
            Component m = target.getComponent(i);
            if (m.isVisible()) {
                Dimension size = m.size();
                m.move(x, y + (height - size.height) / 2);
                x += hgap + size.width;
            }
        }
    }
    
    /**
     * Lays out the container. This method will actually reshape the
     * components in the target in order to satisfy the constraints of
     * the BorderLayout object. 
     * @param target the specified component being laid out.
     * @see Container
     */
    public void layoutContainer(Container target) {
        Insets insets = target.insets();
        Dimension size = target.size();
        int maxwidth = size.width - (insets.left + insets.right +
				     hgap*2);
        int nmembers = target.countComponents();
        int x = 0, y = insets.top + vgap;
        int rowh = 0, start = 0;
        
        for (int i = 0; i < nmembers; i++) {
            Component m = target.getComponent(i);
            if (m.isVisible()) {
                Dimension d = m.preferredSize();
                m.resize(d.width, d.height);
                
                if ((x == 0) || ((x + d.width) <= maxwidth)) {
                    if (x > 0) {
                        x += hgap;
                    }
                    x += d.width;
                    rowh = Math.max(rowh, d.height);
                } else {
                    moveComponents(target, insets.left + hgap,
				   y, maxwidth - x, rowh, start, i);
                    x = d.width;
                    y += vgap + rowh;
                    rowh = d.height;
                    start = i;
                }
            }
        }
        moveComponents(target, insets.left + hgap, y,
		       maxwidth - x, rowh, start, nmembers);
    }
    
    /**
     * Returns the String representation of this FlowLayout's values.
     */
    public String toString() {
        String str = /* NOI18N */"";
        switch (align) {
	case LEFT:    str = /* NOI18N */",align=left"; break;
	case CENTER:  str = /* NOI18N */",align=center"; break;
	case RIGHT:   str = /* NOI18N */",align=right"; break;
        }
        return getClass().getName() + /* NOI18N */"[hgap=" +
	    hgap + /* NOI18N */",vgap=" + vgap + str + /* NOI18N */"]";
    }
}
