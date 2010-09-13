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
 * Copyright (c) 1996-2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */
package com.sun.dhcpmgr.ui;

import java.awt.*;
import java.util.*;

/**
 * <CODE>FieldLayout</CODE> treats components as a list of
 * labeled fields, where each label is placed on the left
 * edge of the container with its associated field to its
 * right.<P>
 *
 * Two kinds of components may be added: "Label" and "Field."
 * Labels and Fields must be added in pairs, because there is
 * a one-to-one correspondence between them.<P>
 *
 * When a <CODE>Field</CODE> is added, it is associated with the
 * last <CODE>Label</CODE> added.<P>
 */
public class FieldLayout implements LayoutManager {
    public static final String LABEL = "Label";
    public static final String LABELTOP = "LabelTop";
    public static final String FIELD = "Field";
    
    class Row {
	Component label;
	Component field;
	double yRatio;
	boolean center;
	
	public Row() {
	    label = null;
	    field = null;
	    yRatio = 1;
	    center = true;
	}
    }
    
    Vector rows;
    int hgap;
    int vgap;

    /**
     * Constructs a new <CODE>FieldLayout</CODE> with a centered alignment.
     */
    public FieldLayout() {
	this(5, 5);
    }

    /**
     * Constructs a new <CODE>FieldLayout</CODE> with the specified gap values.
     * @param <VAR>hgap</VAR> The horizontal gap variable.
     * @param <VAR>vgap</VAR> The vertical gap variable.
     */
    public FieldLayout(int hgap, int vgap) {
	this.hgap = hgap;
	this.vgap = vgap;
	rows = new Vector();
    }

    /**
     * Adds the specified component to the layout.
     * @param <VAR>name</VAR> The name of the component.
     * @param <VAR>comp</VAR> The component to be added.
     */
    public void addLayoutComponent(String name, Component comp) {
	if (LABEL.equals(name)) {
	    Row r = new Row();
	    r.label = comp;
	    r.center = true;
	    rows.addElement(r);
	} else if (LABELTOP.equals(name)) {
	    Row r = new Row();
	    r.label = comp;
	    r.center = false;
	    rows.addElement(r);
	} else if (FIELD.equals(name)) {
	    ((Row)rows.lastElement()).field = comp;
	}
    }

    /**
     * Removes the specified component from the layout.
     * @param <VAR>comp</VAR> The component to remove.
     */
    public void removeLayoutComponent(Component comp) {
	Enumeration en = rows.elements();
	while (en.hasMoreElements()) {
	    Row r = (Row)en.nextElement();
	    if (comp == r.label || comp == r.field) {
		rows.removeElement(r);
		return;
	    }
	}
    }

    /**
     * Returns the preferred dimensions for this layout given the components
     * in the specified target container.
     * @param <VAR>target</VAR> The component that needs to be laid out.
     * @see java.awt.Container
     * @see #minimumLayoutSize
     */
    public Dimension preferredLayoutSize(Container target) {
	Dimension dim = new Dimension(0, 0);
	int widestLabel = 0, widestField = 0;

	Enumeration en = rows.elements();
	while (en.hasMoreElements()) {
	    Row r = (Row)en.nextElement();
	    if (!r.label.isVisible() || !r.field.isVisible()) {
		continue;
	    }
	    Dimension ld = r.label.getPreferredSize();
	    widestLabel = Math.max(widestLabel, ld.width);
	    Dimension fd = r.field.getPreferredSize();
	    widestField = Math.max(widestField, fd.width);
	    dim.height += Math.max(ld.height, fd.height) + vgap;
	}
	dim.width = widestLabel + hgap + widestField;
	Insets insets = target.getInsets();
	dim.width  += insets.left + insets.right + hgap*2;
	dim.height += insets.top + insets.bottom + vgap;
	return dim;
    }

    /**
     * Returns the minimum dimensions needed to layout the components
     * contained in the specified target container.
     * @param <VAR>target</VAR> The component that needs to be laid out.
     * @see #preferredLayoutSize
     */
    public Dimension minimumLayoutSize(Container target) {
	Dimension dim = new Dimension(0, 0);
	int widestLabel = 0, widestField = 0;

	Enumeration en = rows.elements();
	while (en.hasMoreElements()) {
	    Row r = (Row)en.nextElement();
	    if (!r.label.isVisible() || !r.field.isVisible()) {
		continue;
	    }
	    Dimension ld = r.label.getMinimumSize();
	    widestLabel = Math.max(widestLabel, ld.width);
	    Dimension fd = r.field.getMinimumSize();
	    widestField = Math.max(widestField, fd.width);
	    dim.height += Math.max(ld.height, fd.height) + vgap;
	}
	dim.width = widestLabel + hgap + widestField;
	Insets insets = target.getInsets();
	dim.width  += insets.left + insets.right + hgap*2;
	dim.height += insets.top + insets.bottom + vgap;
	return dim;
    }

    /**
     * Performs the layout of the container.  Components are treated
     * either as labels or fields. Labels go on the left (right-aligned),
     * with their associated fields placed immediately to their right.
     * @param <VAR>target</VAR> The specified component being laid out.
     * @see java.awt.Container
     */
    public void layoutContainer(Container target) {
	Insets insets = target.getInsets();
	Dimension dim = target.getSize();
	int x = 0, y = insets.top, offset = 0;
	int widestLabel = 0;
	int ySlop = 0;

	// Compute whether preferred sizes will fit
	Dimension pDim = preferredLayoutSize(target);
	boolean usingPreferred = true;
	if ((pDim.height > (dim.height - insets.top - insets.bottom)) ||
	    (pDim.width > (dim.width - insets.left - insets.right))) {
	    usingPreferred = false;
	    // Compute leftover vertical space
	    pDim = minimumLayoutSize(target);
	    ySlop = dim.height - insets.top - insets.bottom - pDim.height;
	    if (ySlop < 0) {
		ySlop = 0;
	    }
	}

	/*
	 * Find widest label.  Our policy on horizontal space is that labels
	 * are fully satisfied and fields get whatever's left.
	 * For vertical space, if there's any leftovers then allocate it
	 * in proportion to demand, which we'll define as the ratio between
	 * preferred size and minimum size.
	 */
	double sumRatios = 0;
	Enumeration en = rows.elements();
	while (en.hasMoreElements()) {
	    Row r = (Row)en.nextElement();
	    if (r.label.isVisible() && r.field.isVisible()) {
		Dimension d = usingPreferred ? r.label.getPreferredSize() :
		    r.label.getMinimumSize();
		widestLabel = Math.max(widestLabel, d.width);
		if (!usingPreferred) {
		    double lRatio = r.label.getPreferredSize().getHeight() /
			r.label.getMinimumSize().getHeight();
		    double fRatio = r.field.getPreferredSize().getHeight() /
			r.field.getMinimumSize().getHeight();
		    r.yRatio = Math.max(lRatio, fRatio);
		}
		// If there is no demand, then adjust ratio to zero
		if (r.yRatio == 1.0) {
		    r.yRatio = 0;
		}
		sumRatios += r.yRatio;
	    }
	}

	// lay out rows, right-aligning labels
	en = rows.elements();
	while (en.hasMoreElements()) {
	    Row r = (Row)en.nextElement();
	    Component l = r.label;
	    Component f = r.field;
	    // Skip the row if both aren't visible
	    if (!l.isVisible() || !f.isVisible())
		continue;
	    Dimension ld = usingPreferred ? l.getPreferredSize() :
		l.getMinimumSize();
	    Dimension fd = usingPreferred ? f.getPreferredSize() :
		f.getMinimumSize();

	    int rowHeight = Math.max(ld.height, fd.height) +
		(int)(ySlop * r.yRatio / sumRatios);

	    x = insets.left;
	    /*
	     * If the field is visible, move it right to line up with
	     * the widest line.
	     */
	    x += Math.max(widestLabel - ld.width, 0);
	    offset = 0;
	    if (r.center) {
		// center label on field
		offset = Math.max(0, (rowHeight-ld.height)/2);
	    }
	    int labelHeight = rowHeight;
	    /*
	     * If label doesn't look like it wants extra space, don't give it;
	     * otherwise, JLabels will get drawn centered even if user
	     * specified it as a top alignment when doing the layout.
	     */
	    if (l.getPreferredSize().height == l.getMinimumSize().height) {
		labelHeight = ld.height;
	    }
	    l.setBounds(x, y+offset, ld.width, labelHeight);
	    x = insets.left + widestLabel + hgap;
	    int w = dim.width-x-hgap;
	    f.setBounds(x, y, w, rowHeight);
	    y += rowHeight + vgap;
	}

    }

    /**
     * Returns the <CODE>String</CODE> representation of this
     * <CODE>FieldLayout</CODE>'s values.
     */
    public String toString() {
	return getClass().getName() + "[hgap=" + hgap + ",vgap=" + vgap + "]";
    }
}
