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
 * Copyright (c) 1996-1999 by Sun Microsystems, Inc.
 * All rights reserved.
 */
package com.sun.dhcpmgr.ui;

import java.awt.*;

/**
 * <CODE>VerticalButtonLayout</CODE> is used to layout buttons in a
 * <CODE>Panel</CODE>. It will arrange buttons top to bottom
 * until no more buttons fit in the same column.  Each column is
 * centered vertically. All buttons are set to an equal size.<P>
 *
 * While <CODE>VerticalButtonLayout</CODE> was designed for
 * <CODE>Buttons</CODE>, any component can be added to the layout. All
 * components are set to an equal size.<P>
 */
public class VerticalButtonLayout implements LayoutManager {

    ALIGNMENT align;
    int hgap;
    int vgap;

    /**
     * Constructs a new <CODE>VerticalButtonLayout</CODE> with a centered
     * alignment.
     */
    public VerticalButtonLayout() {
	this(ALIGNMENT.CENTER, 5, 5);
    }

    /**
     * Constructs a new <CODE>VerticalButtonLayout</CODE> with the specified
     * alignment.
     * @param <VAR>align</VAR> The alignment value.
     * @see ALIGNMENT
     */
    public VerticalButtonLayout(ALIGNMENT align) {
	this(align, 5, 5);
    }

    /**
     * Constructs a new <CODE>VerticalButtonLayout</CODE> with the specified
     * alignment and gap values.
     * @param <VAR>align</VAR> The alignment value.
     * @param <VAR>hgap</VAR> The horizontal gap variable.
     * @param <VAR>vgap</VAR> The vertical gap variable.
     * @see ALIGNMENT
     */
    public VerticalButtonLayout(ALIGNMENT align, int hgap, int vgap) {
	this.align = align;
	this.hgap = hgap;
	this.vgap = vgap;
    }

    /**
     * Adds the specified component to the layout. This is not
     * used by this class.
     * @param <VAR>name</VAR>	The name of the component.
     * @param <VAR>comp</VAR>	The component to be added.
     */
    public void addLayoutComponent(String name, Component comp) {
    }

    /**
     * Removes the specified component from the layout. This
     * is not used by this class.  
     * @param <VAR>comp</VAR>	The component to remove.
     */
    public void removeLayoutComponent(Component comp) {
    }

    /**
     * Returns the preferred dimensions for this layout given
     * the components in the specified target container.
     * @param <VAR>target</VAR>	The component that needs to be laid out.
     * @see java.awt.Container
     * @see #minimumLayoutSize
     */
    public Dimension preferredLayoutSize(Container target) {
	Dimension dim = new Dimension(0, 0);
	int nmembers = target.getComponentCount();

	for (int i = 0; i < nmembers; i++) {
	    Component m = target.getComponent(i);
	    if (m.isVisible()) {
		Dimension d = m.getPreferredSize();
		dim.height = Math.max(dim.height, d.height);
		dim.width = Math.max(dim.width, d.width);
	    }
	}
	dim.height = (dim.height*nmembers) + (vgap*nmembers-1);
	Insets insets = target.getInsets();
	dim.width += insets.left + insets.right + hgap*2;
	dim.height += insets.top + insets.bottom + vgap*2;
	return dim;
    }

    /**
     * Returns the minimum dimensions needed to layout the components
     * contained in the specified target container.
     * @param <VAR>target</VAR>	The component that needs to be laid out 
     * @see #preferredLayoutSize
     */
    public Dimension minimumLayoutSize(Container target) {
	Dimension dim = new Dimension(0, 0);
	int nmembers = target.getComponentCount();

	for (int i = 0; i < nmembers; i++) {
	    Component m = target.getComponent(i);
	    if (m.isVisible()) {
		Dimension d = m.getMinimumSize();
		dim.height = Math.max(dim.height, d.height);
		dim.width = Math.max(dim.width, d.width);
	    }
	}
	dim.height = (dim.height*nmembers) + (vgap*nmembers-1);
	Insets insets = target.getInsets();
	dim.width += insets.left + insets.right + hgap*2;
	dim.height += insets.top + insets.bottom + vgap*2;
	return dim;
    }

    /** 
     * Centers the elements in the specified column, if there is any slack.
     * @param <VAR>target</VAR>	The component which needs to be moved.
     * @param <VAR>x</VAR>	The x coordinate.
     * @param <VAR>y</VAR>	The y coordinate.
     * @param <VAR>width</VAR>	The width dimensions.
     * @param <VAR>height</VAR>	The height dimensions.
     */
    private void moveComponents(Container target, int x, int y, int width,
	    int height) {
	Dimension dim;

	if (align == ALIGNMENT.LEFT) {
	    // do nothing
	} else if (align == ALIGNMENT.CENTER) {
	    y += height / 2;
	} else if (align == ALIGNMENT.RIGHT) {
	    y += height;
	}
	for (int i = 0; i < target.getComponentCount(); i++) {
	    Component m = target.getComponent(i);
	    if (m.isVisible()) {
		dim = m.getSize();
		m.setLocation(x + (width - dim.width) / 2, y);
		y += vgap + dim.height;
	    }
	}
    }

    /**
     * Lays out the container. This method will actually reshape the
     * components in the target in order to satisfy the constraints of
     * the <CODE>BorderLayout</CODE> object. 
     * @param <VAR>target</VAR>	The specified component being laid out.
     * @see java.awt.Container
     */
    public void layoutContainer(Container target) {
	Insets insets = target.getInsets();
	Dimension tdim = target.getSize();
	int maxheight = tdim.height - (insets.top + insets.bottom + vgap*2);
	int maxwidth = tdim.width - insets.left - insets.right;
	int nmembers = target.getComponentCount();
	Dimension dim = new Dimension(0, 0);
	int y = 0;

	for (int i = 0; i < nmembers; i++) {
	    Component m = target.getComponent(i);
	    if (m.isVisible()) {
		Dimension d = m.getMinimumSize();
		dim.height = Math.max(dim.height, d.height);
		dim.width = Math.max(dim.width, d.width);
	    }
	}
	for (int i = 0; i < nmembers; i++) {
	    Component m = target.getComponent(i);
	    if (m.isVisible()) {
		m.setSize(dim.width, dim.height);
		y += dim.height;
	    }
	}
	moveComponents(target, insets.left, 0, maxwidth, maxheight - y);
    }
    
    /**
     * Returns the <CODE>String</CODE> representation of this
     * <CODE>VerticalButtonLayout</CODE>'s values.
     */
    public String toString() {
	String str = "";
	if (align == ALIGNMENT.LEFT) {
	    str = ",align=left";
	} else if (align == ALIGNMENT.RIGHT) {
	    str = ",align=right";
	} else if (align == ALIGNMENT.CENTER) {
	    str = ",align=center";
	}
	return getClass().getName()
	    + "[hgap=" + hgap + ",vgap=" + vgap + str + "]";
    }
}
