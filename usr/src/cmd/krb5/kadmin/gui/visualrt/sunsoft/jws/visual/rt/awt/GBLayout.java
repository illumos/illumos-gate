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
 * @(#)GBLayout.java	1.23 97/09/03 Doug Stein
 *
 * Copyright (c) 1996, 2001 by Sun Microsystems, Inc. 
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

import sunsoft.jws.visual.rt.base.Global;

import java.awt.*;
import java.util.Hashtable;

class GBLayoutInfo {
    int width, height;	/* number of cells horizontally, vertically */
    int startx, starty;		/* starting point for layout */
    int minWidth[];		/* largest minWidth in each column */
    int minHeight[];		/* largest minHeight in each row */
    double weightX[];		/* largest weight in each column */
    double weightY[];		/* largest weight in each row */
    
    GBLayoutInfo(int w, int h) {
        width = w;
        height = h;
        minWidth = new int[w];
        minHeight = new int[h];
        weightX = new double[w];
        weightY = new double[h];
    }
}

/* BEGIN JSTYLED */
/**
   GBLayout is a flexible layout manager
   that aligns components vertically and horizontally,
   without requiring that the components be the same size.
   Each GBLayout uses a rectangular grid of cells,
   with each component occupying one or more cells
   (called its  < em >display area</em>).
   Each component managed by a GBLayout
   is associated with a
   < a href = java.awt.GBConstraints.html >GBConstraints</a>  instance
   that specifies how the component is laid out
   within its display area.
   How a GBLayout places a set of components
   depends on each component's GBConstraints and minimum size,
   as well as the preferred size of the components' container.
   < p>
        
   To use a GBLayout effectively,
   you must customize one or more of its components' GBConstraints.
   You customize a GBConstraints object by setting one or more
   of its instance variables:
   < dl>
   < dt > <a href = java.awt.GBConstraints.html#gridx> gridx</a>,
   < a href = java.awt.GBConstraints.html#gridy> gridy</a>
   < dd>  Specifies the cell at the upper left of the component's display area,
   where the upper-left-most cell has address gridx  =  0, gridy=0.
   Use GBConstraints.RELATIVE(the default value)
   to specify that the component be just placed
   just to the right of(for gridx)
   or just below(for gridy)
   the component that was added to the container
   just before this component was added.
   < dt > <a href = java.awt.GBConstraints.html#gridwidth> gridwidth</a>,
   < a href = java.awt.GBConstraints.html#gridheight> gridheight</a>
   < dd>  Specifies the number of cells in a row(for gridwidth)
   or column(for gridheight)
   in the component's display area.
   The default value is 1.
   Use GBConstraints.REMAINDER to specify
   that the component be the last one in its row(for gridwidth)
   or column(for gridheight).
   Use GBConstraints.RELATIVE to specify
   that the component be the next to last one
   in its row(for gridwidth) or column (for gridheight).
   < dt>  <a href = java.awt.GBConstraints.html#fill>fill</a>
   < dd>  Used when the component's display area
   is larger than the component's requested size
   to determine whether(and how) to resize the component.
   Valid values are
   GBConstraints.NONE
   (the default),
   GBConstraints.HORIZONTAL
   (make the component wide enough to fill its display area
   horizontally, but don't change its height),
   GBConstraints.VERTICAL
   (make the component tall enough to fill its display area
   vertically, but don't change its width),
   and
   GBConstraints.BOTH
   (make the component fill its display area entirely).
   < dt > <a href = java.awt.GBConstraints.html#ipadx> ipadx</a>,
   < a href = java.awt.GBConstraints.html#ipady> ipady</a>
   < dd>  Specifies the internal padding:
   how much to add to the minimum size of the component.
   The width of the component will be at least
   its minimum width plus ipadx*2 pixels
   (since the padding applies to both sides of the component).
   Similarly, the height of the component will be at least
   the minimum height plus ipady*2 pixels.
   < dt>  <a href = java.awt.GBConstraints.html#insets>insets</a>
   < dd>  Specifies the external padding of the component --
   the minimum amount of space between the component
   and the edges of its display area.
   < dt>  <a href = java.awt.GBConstraints.html#anchor>anchor</a>
   < dd>  Used when the component is smaller than its display area
   to determine where(within the area) to place the component.
   Valid values are
   GBConstraints.CENTER(the default),
   GBConstraints.NORTH,
   GBConstraints.NORTHEAST,
   GBConstraints.EAST,
   GBConstraints.SOUTHEAST,
   GBConstraints.SOUTH,
   GBConstraints.SOUTHWEST,
   GBConstraints.WEST, and
   GBConstraints.NORTHWEST.
   < dt > <a href = java.awt.GBConstraints.html#weightx> weightx</a>,
   < a href = java.awt.GBConstraints.html#weighty> weighty</a>
   < dd>  Used to determine how to distribute space;
   this is important for specifying resizing behavior.
   Unless you specify a weight
   for at least one component in a row(weightx)
   and column(weighty),
   all the components clump together in the center of
   their container.
   This is because when the weight is zero(the default),
   the GBLayout puts any extra space
   between its grid of cells and the edges of the container.
   < /dl>
        
   The following figure shows ten components(all buttons)
   managed by a GBLayout:
   < blockquote>
   < img src  =  images/java.awt/GridBagEx.gif width=262 height=155>
   < /blockquote>
        
   All the components have fill = GBConstraints.BOTH.
   In addition, the components have the following non-default constraints:
   < ul>
   < li >Button1, Button2, Button3:
   weightx = 1.0
   < li >Button4:
   weightx = 1.0,
   gridwidth = GBConstraints.REMAINDER
   < li >Button5:
   gridwidth = GBConstraints.REMAINDER
   < li >Button6:
   gridwidth = GBConstraints.RELATIVE
   < li >Button7:
   gridwidth = GBConstraints.REMAINDER
   < li >Button8:
   gridheight  =  2, weighty=1.0,
   < li >Button9, Button 10:
   gridwidth = GBConstraints.REMAINDER
   < /ul>
        
   Here is the code that implements the example shown above:
   < blockquote>
   < pre>
   import java.awt.*;
   import java.util.*;
   import java.applet.Applet;
        
   public class GridBagEx1 extends Applet {
            
   protected void makebutton(String name,
   GBLayout gridbag,
   GBConstraints c) {
   Button button = new Button(name);
   gridbag.setConstraints(button, c);
   add(button);
   }
            
   public void init() {
   GBLayout gridbag = new GBLayout();
   GBConstraints c = new GBConstraints();
                
   setFont(new Font("Sansserif", Font.PLAIN, 14));
   setLayout(gridbag);
                
   c.fill = GBConstraints.BOTH;
   c.weightx = 1.0;
   makebutton("Button1", gridbag, c);
   makebutton("Button2", gridbag, c);
   makebutton("Button3", gridbag, c);
                
   c.gridwidth = GBConstraints.REMAINDER; // end row
   makebutton("Button4", gridbag, c);
                
   c.weightx = 0.0;		   // reset to the default
   makebutton("Button5", gridbag, c); // another row
                
   c.gridwidth = GBConstraints.RELATIVE; // next-to-last in row
   makebutton("Button6", gridbag, c);
                
   c.gridwidth = GBConstraints.REMAINDER; // end row
   makebutton("Button7", gridbag, c);
                
   c.gridwidth = 1;	   	   // reset to the default
   c.gridheight = 2;
   c.weighty = 1.0;
   makebutton("Button8", gridbag, c);
                
   c.weighty = 0.0;		   // reset to the default
   c.gridwidth = GBConstraints.REMAINDER; // end row
   c.gridheight = 1;		   // reset to the default
   makebutton("Button9", gridbag, c);
   makebutton("Button10", gridbag, c);
                
   resize(300, 100);
   }
            
   public static void main(String args[]) {
   Frame f = new Frame("GridBag Layout Example");
   GridBagEx1 ex1 = new GridBagEx1();
                
   ex1.init();
                
   f.add("Center", ex1);
   f.pack();
   f.resize(f.getPreferredSize());
   f.show();
   }
   }
   < /pre>
   < /blockquote>
   *
   * @version 1.23, 08/06/97
   * @author Doug Stein
   */
/* END JSTYLED */
public class GBLayout implements LayoutManager {
    
    /**
     * Determines the minimum widths for the grid columns.
     */
    public int columnWidths[];
    
    /**
     * Determines the minimum heights for the grid rows.
     */
    public int rowHeights[];
    
    /**
     * Determines the minimum weights for the grid columns.
     */
    public double columnWeights[];
    
    /**
     * Determines the minimum weights for the grid rows.
     */
    public double rowWeights[];
    
    protected static final int INITGRIDSIZE = 16;
    protected static final int MINSIZE = 1;
    protected static final int PREFERREDSIZE = 2;
    protected static final int TINYSIZE = 3;
    
    protected Hashtable comptable;
    protected GBConstraints defaultConstraints;
    protected GBLayoutInfo layoutInfo;
    
    protected int anchor;
    protected int clipAnchor;
    
    private static boolean layoutDisabled = false;
    private static int disableCount = 0;
    private static Insets windowInsets = new Insets(0, 0, 0, 0);
    
    /**
     * Globally enable gridbag layout.  The 
     * default is for gridbag layout to
     * be enabled.
     */
    public synchronized static void enable() {
        disableCount--;
        if (disableCount <= 0)
            layoutDisabled = false;
    }
    
    /**
     * Globally disable gridbag layout.  This can be used to improve
     * performance by temporarily disabling layout during
     * spurious calls to validate.
     */
    public synchronized static void disable() {
        disableCount++;
        if (disableCount > 0)
            layoutDisabled = true;
    }
    
    /**
     * Set the window insets.  The window insets default to (0,0,0,0).
     */
    public synchronized static void setWindowInsets(Insets insets) {
        if (insets == null)
            windowInsets = new Insets(0, 0, 0, 0);
        else
            windowInsets = (Insets)insets.clone();
    }
    
    /**
     * Get the window insets.
     */
    public synchronized static Insets getWindowInsets() {
        return (Insets)windowInsets.clone();
    }
    
    /**
     * Creates a gridbag layout.
     */
    public GBLayout() {
        comptable = new Hashtable();
        defaultConstraints = new GBConstraints();
        
        anchor = GBConstraints.CENTER;
        clipAnchor = GBConstraints.NORTHWEST;
    }
    
    /**
     * Sets the constraints for the specified component.
     * @param comp the component to be modified
     * @param constraints the constraints to be applied
     */
    public void setConstraints(Component comp,
			       GBConstraints constraints) {
        GBConstraints c = (GBConstraints)constraints.clone();
        if (c.insets == null)
            c.insets = new Insets(0, 0, 0, 0);
        if (c.hardinsets == null)
            c.hardinsets = new Insets(0, 0, 0, 0);
        
        comptable.put(comp, c);
    }
    
    /**
     * Sets the constraints from an option string.
     * Each option has the form key=value. Options are separated by
     * semicolons (;).
     * @param comp the component to be modified
     * @param constraints the constraints string
     */
    public void setConstraints(Component comp, String constraints) {
        if (constraints == null)
            return;
        
        comptable.put(comp, new GBConstraints(constraints));
    }
    
    /**
     * Retrieves the constraints for the specified component.  A copy of
     * the constraints is returned.
     * @param comp the component to be queried
     */
    public GBConstraints getConstraints(Component comp) {
        GBConstraints constraints = (GBConstraints)comptable.get(comp);
        if (constraints == null) {
            setConstraints(comp, defaultConstraints);
            constraints = (GBConstraints)comptable.get(comp);
        }
        return (GBConstraints)constraints.clone();
    }
    
    /**
     * Retrieves the constraints for the specified 
     * component.  The return
     * value is not a copy, but is the actual constraints
     * class used by the
     * layout mechanism.
     * @param comp the component to be queried
     */
    protected GBConstraints lookupConstraints(Component comp) {
        GBConstraints constraints = (GBConstraints)comptable.get(comp);
        if (constraints == null) {
            setConstraints(comp, defaultConstraints);
            constraints = (GBConstraints)comptable.get(comp);
        }
        return constraints;
    }
    
    /**
     * Returns the coordinates of the upper-left corner of the grid.
     * The coordinates are based on the current layout of the grid.
     */
    public Point getLayoutOrigin() {
        Point origin = new Point(0, 0);
        if (layoutInfo != null) {
            origin.x = layoutInfo.startx;
            origin.y = layoutInfo.starty;
        }
        return origin;
    }
    
    /**
     * Returns the widths and heights of the grid columns and rows.
     * The dimensions are based on the current layout of the grid.
     */
    public int [][] getLayoutDimensions() {
        if (layoutInfo == null)
            return new int[2][0];
        
        int dim[][] = new int [2][];
        dim[0] = new int[layoutInfo.width];
        dim[1] = new int[layoutInfo.height];
        
        System.arraycopy(layoutInfo.minWidth, 0, dim[0], 0,
			 layoutInfo.width);
        System.arraycopy(layoutInfo.minHeight, 0, dim[1], 0,
			 layoutInfo.height);
        
        return dim;
    }
    
    /**
     * Returns the minimum widths and heights of the 
     * grid columns and rows.
     * This is how the grid would be arranged if the parent were
     * to be reshaped to its minimum size.
     */
    public int [][] getMinimumLayoutDimensions(Container parent) {
        GBLayoutInfo info = GetLayoutInfo(parent, MINSIZE);
        int dim[][] = new int[2][];
        dim[0] = new int[info.width];
        dim[1] = new int[info.height];
        
        System.arraycopy(info.minWidth, 0, dim[0], 0, info.width);
        System.arraycopy(info.minHeight, 0, dim[1], 0, info.height);
        
        return dim;
    }
    
    /**
     * Returns the preferred widths and heights of the 
     * grid columns and rows.
     * This is how the grid would be arranged if the parent were
     * to be reshaped to its preferred size.
     */
    public int [][] getPreferredLayoutDimensions(Container parent) {
        GBLayoutInfo info = GetLayoutInfo(parent, PREFERREDSIZE);
        int dim[][] = new int[2][];
        dim[0] = new int[info.width];
        dim[1] = new int[info.height];
        
        System.arraycopy(info.minWidth, 0, dim[0], 0, info.width);
        System.arraycopy(info.minHeight, 0, dim[1], 0, info.height);
        
        return dim;
    }
    /* BEGIN JSTYLED */            
    /**
     * Returns the current set of weights for the grid 
     * columns and rows.
     * The return value reflects the effective weights for the columns
     * and rows after taking into account the weight constraints that
     * are set on the child components.
     */
    /* END JSTYLED */
    public double [][] getLayoutWeights() {
        if (layoutInfo == null)
            return new double[2][0];
        
        double weights[][] = new double [2][];
        weights[0] = new double[layoutInfo.width];
        weights[1] = new double[layoutInfo.height];
        
        System.arraycopy(layoutInfo.weightX, 0, weights[0], 0,
			 layoutInfo.width);
        System.arraycopy(layoutInfo.weightY, 0, weights[1], 0,
			 layoutInfo.height);
        
        return weights;
    }
    
    /**
     * Returns the coordinates of the grid cell corresponding 
     * to the given
     * pixel coordinates.
     */
    public Point location(int x, int y) {
        Point loc = new Point(0, 0);
        int i, d;
        
        if (layoutInfo == null)
            return loc;
        
        d = layoutInfo.startx;
        for (i = 0; i < layoutInfo.width; i++) {
            d += layoutInfo.minWidth[i];
            if (d > x)
                break;
        }
        loc.x = i;
        
        d = layoutInfo.starty;
        for (i = 0; i < layoutInfo.height; i++) {
            d += layoutInfo.minHeight[i];
            if (d > y)
                break;
        }
        loc.y = i;
        
        return loc;
    }
    
    /**
     * Sets the anchor for the gridbag.  The anchor determines 
     * the placement
     * for the child components when the container
     * has extra space and none
     * of the children have weights.  The default anchor is CENTER.
     */
    public void setAnchor(int anchor) {
        this.anchor = anchor;
    }
    
    /**
     * Returns the current anchor.
     */
    public int getAnchor() {
        return anchor;
    }
    
    /**
     * Sets the clip anchor.  The clip anchor determines 
     * which edge(s) of
     * the container get clipped when there is not enough space.  The
     * default clip anchor is NORTHWEST.  A clip anchor
     * of NORTHWEST means
     * that northwest corner is anchored, so the south
     * and east edges will
     * be clipped if there is not enough space.
     */
    public void setClipAnchor(int clipAnchor) {
        this.clipAnchor = clipAnchor;
    }
    
    /**
     * Returns the current clip anchor.
     */
    public int getClipAnchor() {
        return clipAnchor;
    }
    
    /**
     * If the parent is a Window, then adjust the insets according to
     * the window insets.
     */
    private Insets getInsets(Container parent) {
        Insets parentInsets = parent.insets();
        Insets insets = null;
        if (parentInsets != null) {
            insets = (Insets) parentInsets.clone();
        } else {
            insets = new Insets(0, 0, 0, 0);
        }
        if (parent instanceof Window) {
            insets.top += windowInsets.top;
            insets.bottom += windowInsets.bottom;
            insets.left += windowInsets.left;
            insets.right += windowInsets.right;
        }
        return insets;
    }
    
    /**
     * Adds the specified component with the specified 
     * name to the layout.
     * The name is converted to a set of GBConstraints.
     * @param name the constraints string
     * @param comp the component to be added
     */
    public void addLayoutComponent(String name, Component comp) {
        setConstraints(comp, name);
    }
    
    /**
     * Removes the specified component from the layout. Does not apply.
     * @param comp the component to be removed
     */
    public void removeLayoutComponent(Component comp) {
    }
    
    /**
     * Returns the preferred dimensions for this layout 
     * given the components
     * in the specified panel.
     * @param parent the component which needs to be laid out
     * @see #minimumLayoutSize
     */
    public Dimension preferredLayoutSize(Container parent) {
        GBLayoutInfo info = GetLayoutInfo(parent, PREFERREDSIZE);
        return GetMinSize(parent, info);
    }
    
    /**
     * Returns the minimum dimensions needed to layout the components 
     * contained in the specified panel.
     * @param parent the component which needs to be laid out 
     * @see #preferredLayoutSize
     */
    public Dimension minimumLayoutSize(Container parent) {
        GBLayoutInfo info = GetLayoutInfo(parent, MINSIZE);
        return GetMinSize(parent, info);
    }
    
    /**
     * Returns the smallest allowable size for the specified panel.
     * This can be smaller than getMinimumSize if there are insets and
     * pads set on any of the panel's children.
     * @param parent the component which needs to be laid out 
     * @see #preferredLayoutSize
     */
    public Dimension tinyLayoutSize(Container parent) {
        GBLayoutInfo info = GetLayoutInfo(parent, TINYSIZE);
        return GetMinSize(parent, info);
    }
    
    /**
     * Lays out the container in the specified panel.  
     * @param parent the specified component being laid out
     * @see Container
     */
    public void layoutContainer(Container parent) {
        if (!layoutDisabled)
            ArrangeGrid(parent, true);
    }
    
    /**
     * Does everything that layout normally does, except the components
     * aren't actually reshaped.  This has the useful side effect of
     * setting the location and size variables in the constraints
     * for each component.
     * @param parent the specified component being laid out
     * @see Container
     */
    public void layoutContainerNoReshape(Container parent) {
        if (!layoutDisabled)
            ArrangeGrid(parent, false);
    }
    
    /**
     * Returns the String representation of this GBLayout's values.
     */
    public String toString() {
        return getClass().getName();
    }
    /* BEGIN JSTYLED */
    /**
     * Print the layout information.  Useful for debugging.
     */
            
    /* DEBUG
     *
     *  protected void DumpLayoutInfo(GBLayoutInfo s) {
     *    int x;
     *
     *    System.out.println("Col\tWidth\tWeight");
     *    for (x=0; x<s.width; x++) {
     *      System.out.println(x + "\t" +
     *			 s.minWidth[x] + "\t" +
     *			 s.weightX[x]);
     *    }
     *    System.out.println("Row\tHeight\tWeight");
     *    for (x=0; x<s.height; x++) {
     *      System.out.println(x + "\t" +
     *			 s.minHeight[x] + "\t" +
     *			 s.weightY[x]);
     *    }
     *  }
     */
            
    /**
     * Print the layout constraints.  Useful for debugging.
     */
            
    /* DEBUG
     *
     *  protected void DumpConstraints(GBConstraints constraints) {
     *    System.out.println(
     *		       "wt " +
     *		       constraints.weightx +
     *		       " " +
     *		       constraints.weighty +
     *		       ", " +
     *
     *		       "box " +
     *		       constraints.gridx +
     *		       " " +
     *		       constraints.gridy +
     *		       " " +
     *		       constraints.gridwidth +
     *		       " " +
     *		       constraints.gridheight +
     *		       ", " +
     *
     *		       "min " +
     *		       constraints.minWidth +
     *		       " " +
     *		       constraints.minHeight +
     *		       ", " +
     *
     *		       "pad " +
     *		       constraints.insets.bottom +
     *		       " " +
     *		       constraints.insets.left +
     *		       " " +
     *		       constraints.insets.right +
     *		       " " +
     *		       constraints.insets.top +
     *		       " " +
     *		       constraints.ipadx +
     *		       " " +
     *		       constraints.ipady);
     *  }
     */
            
    /**
     * Fill in an instance of the GBLayoutInfo structure for the
     * current set of managed children.  This requires four passes
     * through the child components:
     *<pre>
     * 1) Figure out the dimensions of the layout grid.
     * 2) Determine which cells the components occupy.
     * 3) Distribute the weights among the rows/columns.
     * 4) Distribute the minimum sizes among the rows/columns.
     *</pre>
     * This also caches the minsizes for all the children when they are
     * first encountered (so subsequent loops don't need to ask again).
     */

    /* END JSTYLED */
    protected GBLayoutInfo GetLayoutInfo(Container parent,
					 int sizeflag) {
        Component comp;
        GBConstraints constraints;
        Dimension d;
        Component components[] = parent.getComponents();
        
        int compindex, width, height, i, j, k, px, py;
        int limit, pixels_diff, nextSize;
        int curX, curY, curWidth, curHeight, curRow, curCol;
        double weight_diff, weight, start, size;
        int xMax[], yMax[];
        
	/* BEGIN JSTYLED */
	/*
	 * Pass #1
	 *
	 * Figure out the dimensions of the layout 
	 * grid (use a value of 1 for
	 * zero or negative widths and heights).
	 */
	/* END JSTYLED */
        
        width = height = 0;
        curRow = curCol = -1;
        xMax = new int[INITGRIDSIZE];
        yMax = new int[INITGRIDSIZE];
        
        for (compindex = 0; compindex < components.length; compindex++) {
            comp = components[compindex];
            if (!comp.isVisible())
                continue;
            constraints = lookupConstraints(comp);
            
            curX = constraints.gridx;
            curY = constraints.gridy;
            curWidth = constraints.gridwidth;
            if (curWidth <= 0)
                curWidth = 1;
            curHeight = constraints.gridheight;
            if (curHeight <= 0)
                curHeight = 1;
            
            /* If x or y is negative, then use relative positioning: */
            if (curX < 0 && curY < 0) {
                if (curRow >= 0)
                    curY = curRow;
                else if (curCol >= 0)
                    curX = curCol;
                else
                    curY = 0;
            }
            if (curX < 0) {
                px = 0;
                limit = curY + curHeight;
                xMax = ensureCapacity(xMax, limit);
                for (i = curY; i < limit; i++)
                    px = Math.max(px, xMax[i]);
                
                curX = px - curX - 1;
                if (curX < 0)
                    curX = 0;
            } else if (curY < 0) {
                py = 0;
                limit = curX + curWidth;
                yMax = ensureCapacity(yMax, limit);
                for (i = curX; i < limit; i++)
                    py = Math.max(py, yMax[i]);
                
                curY = py - curY - 1;
                if (curY < 0)
                    curY = 0;
            }
            
            /* Adjust the grid width and height */
            for (px = curX + curWidth; width < px; width++);
            for (py = curY + curHeight; height < py; height++);
            
            /* Adjust the xMax and yMax arrays */
            yMax = ensureCapacity(yMax, px);
            xMax = ensureCapacity(xMax, py);
            for (i = curX; i < px; i++) { yMax[i] = py; }
            for (i = curY; i < py; i++) { xMax[i] = px; }
            
            /* Cache the current slave's size. */
            if (sizeflag == TINYSIZE) {
                if (comp instanceof Container) {
                    Container cntr = (Container)comp;
                    if (cntr.getLayout() instanceof GBLayout)
                        d = ((GBLayout)cntr.getLayout()).tinyLayoutSize(cntr);
                    else
                        d = comp.getMinimumSize();
                }
                else
                    d = comp.getMinimumSize();
                
                constraints.tinyWidth = d.width;
                constraints.tinyHeight = d.height;
                
                if (constraints.shrinkx)
                    constraints.tinyWidth = 0;
                if (constraints.shrinky)
                    constraints.tinyHeight = 0;
                
                if (constraints.minsize == null) {
                    d = comp.getMinimumSize();
                    constraints.minsize = new Dimension(d.width,
							d.height);
                }
            } else {
                if (sizeflag == PREFERREDSIZE) {
                    d = comp.getPreferredSize();
                    if (d.width <= 1 && d.height <= 1) {
                        // If the preferred size is not reasonable
                        // then try the minumum size
                        d = comp.getMinimumSize();
                        if (d.width <= 1 && d.height <= 1) {
                            // Both preferred and minimun size
                            // are small so use the actual size
                            // that was set for the component.
                            d = comp.getSize();
                        }
                    }
                    constraints.minsize = new Dimension(d.width,
							d.height);
                } else {
                    d = comp.getMinimumSize();
                    // If the component is less than 1,1 minumum
                    // size then
                    // use getPreferredSize instead. This is
                    // a workaround for
                    // Beans that do not have getMinimumSize
                    // implemented.
                    if (d.width <= 1 && d.height <= 1) {
                        d = comp.getPreferredSize();
                        if (d.width <= 1 && d.height <= 1) {
                            d = comp.getSize();
                        }
                    }
                    constraints.minsize = new Dimension(d.width,
							d.height);
                }
            }
	    /* BEGIN JSTYLED */
	    /*
	     * Zero width and height must mean that this is 
	     * the last item (or
	     * else something is wrong).
	     */
	    if (constraints.gridheight == 0 && 
		constraints.gridwidth == 0)
		curRow = curCol = -1;
                    
	    /* Zero width starts a new row */
	    if (constraints.gridheight == 0 && curRow < 0)
		curCol = curX + curWidth;
                    
	    /* Zero height starts a new column */
	    else if (constraints.gridwidth == 0 && curCol < 0)
		curRow = curY + curHeight;
	}
                
	/*
	 * Apply minimum row/column dimensions
	 */
	/* END JSTYLED */
	if (columnWidths != null && width < columnWidths.length)
	    width = columnWidths.length;
	if (rowHeights != null && height < rowHeights.length)
	    height = rowHeights.length;
            
	GBLayoutInfo r = new GBLayoutInfo(width, height);
            
	/*
	 * Pass #2
	 *
	 * Negative values for gridX are filled in with 
	 * the current x value.
	 * Negative values for gridY are filled in with
	 * the current y value.
	 * Negative or zero values for gridWidth and
	 * gridHeight end the current
	 * row or column, respectively.
	 *
	 * Pass #1 figures out the grid dimensions.
	 * Pass #2 replaces the
	 * negative and zero values for gridWidth and gridHeight with
	 * real values that are based on the grid dimensions determined
	 * in pass #1.
	 */
            
	curRow = curCol = -1;
	xMax = new int[height];
	yMax = new int[width];
            
	for (compindex = 0; compindex < components.length;
	    compindex++) {
	    comp = components[compindex];
	    if (!comp.isVisible())
		continue;
	    constraints = lookupConstraints(comp);
                
	    curX = constraints.gridx;
	    curY = constraints.gridy;
	    curWidth = constraints.gridwidth;
	    curHeight = constraints.gridheight;
                
	    /* If x or y is negative, then use relative positioning: */
	    if (curX < 0 && curY < 0) {
		if (curRow >= 0)
		    curY = curRow;
		else if (curCol >= 0)
		    curX = curCol;
		else
		    curY = 0;
	    }
                
	    if (curX < 0) {
		if (curHeight <= 0) {
		    curHeight += r.height - curY;
		    if (curHeight < 1)
			curHeight = 1;
		}
                    
		px = 0;
		for (i = curY; i < (curY + curHeight); i++)
		    px = Math.max(px, xMax[i]);
                    
		curX = px - curX - 1;
		if (curX < 0)
		    curX = 0;
	    } else if (curY < 0) {
		if (curWidth <= 0) {
		    curWidth += r.width - curX;
		    if (curWidth < 1)
			curWidth = 1;
		}
                    
		py = 0;
		for (i = curX; i < (curX + curWidth); i++)
		    py = Math.max(py, yMax[i]);
                    
		curY = py - curY - 1;
		if (curY < 0)
		    curY = 0;
	    }
                
	    if (curWidth <= 0) {
		curWidth += r.width - curX;
		if (curWidth < 1)
		    curWidth = 1;
	    }
                
	    if (curHeight <= 0) {
		curHeight += r.height - curY;
		if (curHeight < 1)
		    curHeight = 1;
	    }
                
	    px = curX + curWidth;
	    py = curY + curHeight;
                
	    for (i = curX; i < px; i++) { yMax[i] = py; }
	    for (i = curY; i < py; i++) { xMax[i] = px; }
                
	    /* Make negative sizes start a new row/column */
	    if (constraints.gridheight == 0 &&
                constraints.gridwidth == 0)
                curRow = curCol = -1;
	    if (constraints.gridheight == 0 && curRow < 0)
		curCol = curX + curWidth;
	    else if (constraints.gridwidth == 0 && curCol < 0)
		curRow = curY + curHeight;
                
	    /* Assign the new values to the gridbag slave */
	    constraints.tempX = curX;
	    constraints.tempY = curY;
	    constraints.tempWidth = curWidth;
	    constraints.tempHeight = curHeight;
	}
            
	/*
	 * Apply row/column weights.
	 */
            
	if (columnWeights != null)
	    System.arraycopy(columnWeights, 0, r.weightX, 0,
			     Math.min(columnWeights.length, r.weightX.length));
	if (rowWeights != null)
	    System.arraycopy(rowWeights, 0, r.weightY, 0,
			     Math.min(rowWeights.length, r.weightY.length));
            
	/*
	 * Pass #3
	 *
	 * Distribute the weights.
	 */
            
	nextSize = Integer.MAX_VALUE;
            
	for (i = 1;
	    i != Integer.MAX_VALUE;
	    i = nextSize, nextSize = Integer.MAX_VALUE) {
	    for (compindex = 0; compindex < components.length;
		 compindex++) {
		comp = components[compindex];
		if (!comp.isVisible())
		    continue;
		constraints = lookupConstraints(comp);
                    
		if (constraints.tempWidth == i) {
		    px = constraints.tempX + constraints.tempWidth;
		    /* right column */
                        
		    /*
		     * Figure out if we should use this slave\'s 
		     * weight.  If the weight
		     * is less than the total weight spanned
		     * by the width of the cell,
		     * then discard the weight.  Otherwise
		     * split the difference
		     * according to the existing weights.
		     */
                        
		    weight_diff = constraints.weightx;
		    for (k = constraints.tempX; k < px; k++)
			weight_diff -= r.weightX[k];
		    if (weight_diff > 0.0) {
			weight = 0.0;
			for (k = constraints.tempX; k < px; k++)
			    weight += r.weightX[k];
			for (k = constraints.tempX; weight > 0.0
				 && k < px; k++) {
			    double wt = r.weightX[k];
			    double dx = (wt * weight_diff) / weight;
			    r.weightX[k] += dx;
			    weight_diff -= dx;
			    weight -= wt;
			}
				/* BEGIN JSTYLED */
                                /* Assign the remainder to the 
				 * rightmost cell */
				/* END JSTYLED */
			r.weightX[px-1] += weight_diff;
		    }
		} else if (constraints.tempWidth > i &&
			   constraints.tempWidth < nextSize)
                    nextSize = constraints.tempWidth;
                    
                    
		if (constraints.tempHeight == i) {
		    py = constraints.tempY + constraints.tempHeight;
		    /* bottom row */
                        
		    /*
		     * Figure out if we should use this slave\'s 
		     * weight.  If the weight
		     * is less than the total weight spanned by
		     * the height of the cell,
		     * then discard the weight.  Otherwise split
		     * it the difference
		     * according to the existing weights.
		     */
                        
		    weight_diff = constraints.weighty;
		    for (k = constraints.tempY; k < py; k++)
			weight_diff -= r.weightY[k];
		    if (weight_diff > 0.0) {
			weight = 0.0;
			for (k = constraints.tempY; k < py; k++)
			    weight += r.weightY[k];
			for (k = constraints.tempY; weight > 0.0
				 && k < py; k++) {
			    double wt = r.weightY[k];
			    double dy = (wt * weight_diff) / weight;
			    r.weightY[k] += dy;
			    weight_diff -= dy;
			    weight -= wt;
			}
			/* Assign the remainder to the bottom cell */
			r.weightY[py-1] += weight_diff;
		    }
		} else if (constraints.tempHeight > i &&
			   constraints.tempHeight < nextSize)
                    nextSize = constraints.tempHeight;
	    }
	}
            
	/*
	 * Apply minimum row/column widths.
	 */
            
	if (sizeflag == TINYSIZE) {
	    if (columnWidths != null) {
		for (i = 0; i < columnWidths.length; i++) {
		    if (r.weightX[i] == 0)
			r.minWidth[i] = columnWidths[i];
		}
	    }
	    if (rowHeights != null) {
		for (i = 0; i < rowHeights.length; i++) {
		    if (r.weightY[i] == 0)
			r.minHeight[i] = rowHeights[i];
		}
	    }
	} else {
	    if (columnWidths != null)
		System.arraycopy(columnWidths, 0, r.minWidth, 0,
				 columnWidths.length);
	    if (rowHeights != null)
		System.arraycopy(rowHeights, 0, r.minHeight, 0,
				 rowHeights.length);
	}
            
	/*
	 * Pass #4
	 *
	 * Distribute the minimum widths.
	 */
            
	nextSize = Integer.MAX_VALUE;
            
	for (i = 1;
	    i != Integer.MAX_VALUE;
	    i = nextSize, nextSize = Integer.MAX_VALUE) {
	    for (compindex = 0; compindex < components.length;
		 compindex++) {
		comp = components[compindex];
		if (!comp.isVisible())
		    continue;
		constraints = lookupConstraints(comp);
                    
		if (constraints.tempWidth == i) {
		    px = constraints.tempX + constraints.tempWidth;
		    /* right column */
                        
		    /*
		     * Calculate the minWidth array values.
		     * First, figure out how wide the current 
		     * slave needs to be.
		     * Then, see if it will fit within the
		     * current minWidth values.
		     * If it will not fit, add the difference
		     * according to the
		     * weightX array.
		     */
                        
		    if (sizeflag == TINYSIZE && hasWeightX(r,
							   constraints)) {
			pixels_diff = constraints.tinyWidth
                            + constraints.hardipadx +
                            constraints.hardinsets.left +
                            constraints.hardinsets.right;
		    } else {
			pixels_diff = constraints.minsize.width +
                            constraints.ipadx + constraints.hardipadx +
                            constraints.insets.left +
                            constraints.insets.right +
                            constraints.hardinsets.left +
                            constraints.hardinsets.right;
		    }
                        
		    for (k = constraints.tempX; k < px; k++)
			pixels_diff -= r.minWidth[k];
		    if (pixels_diff > 0) {
			weight = 0.0;
			for (k = constraints.tempX; k < px; k++)
			    weight += r.weightX[k];
			for (k = constraints.tempX; weight > 0.0 &&
				 k < px; k++) {
			    double wt = r.weightX[k];
			    int dx = (int)((wt * ((double)
						  pixels_diff)) / weight);
			    r.minWidth[k] += dx;
			    pixels_diff -= dx;
			    weight -= wt;
			}
                            
			/* Any leftovers are evenly distributed */
			int dx = pixels_diff/(px-constraints.tempX);
			for (k = constraints.tempX; k < (px-1); k++) {
			    r.minWidth[k] += dx;
			    pixels_diff -= dx;
			}
			r.minWidth[px-1] += pixels_diff;
		    }
		} else if (constraints.tempWidth > i &&
			   constraints.tempWidth < nextSize)
                    nextSize = constraints.tempWidth;
                    
                    
		if (constraints.tempHeight == i) {
		    py = constraints.tempY + constraints.tempHeight;
		    /* bottom row */
                        
		    /*
		     * Calculate the minHeight array values.
		     * First, figure out how tall the current 
		     * slave needs to be.
		     * Then, see if it will fit within the
		     * current minHeight values.
		     * If it will not fit, add the difference
		     * according to the
		     * weightY array.
		     */
                        
		    if (sizeflag == TINYSIZE && hasWeightY(r,
							   constraints)) {
			pixels_diff = constraints.tinyHeight +
                            constraints.hardipady +
                            constraints.hardinsets.top +
                            constraints.hardinsets.bottom;
		    } else {
			pixels_diff = constraints.minsize.height +
                            constraints.ipady + constraints.hardipady +
                            constraints.insets.top +
                            constraints.insets.bottom +
                            constraints.hardinsets.top +
                            constraints.hardinsets.bottom;
		    }
                        
		    for (k = constraints.tempY; k < py; k++)
			pixels_diff -= r.minHeight[k];
		    if (pixels_diff > 0) {
			weight = 0.0;
			for (k = constraints.tempY; k < py; k++)
			    weight += r.weightY[k];
			for (k = constraints.tempY; weight > 0.0 &&
				 k < py; k++) {
			    double wt = r.weightY[k];
			    int dy = (int)((wt * ((double)pixels_diff))
					   / weight);
			    r.minHeight[k] += dy;
			    pixels_diff -= dy;
			    weight -= wt;
			}
                            
			/* Any leftovers are evenly distributed */
			int dy = pixels_diff/(py-constraints.tempY);
			for (k = constraints.tempY; k < (py-1); k++) {
			    r.minHeight[k] += dy;
			    pixels_diff -= dy;
			}
			r.minHeight[py-1] += pixels_diff;
		    }
		} else if (constraints.tempHeight > i &&
			   constraints.tempHeight < nextSize)
                    nextSize = constraints.tempHeight;
	    }
	}
            
	return r;
    }
        
    private int[] ensureCapacity(int arr[], int size) {
	if (arr.length < size) {
	    int newSize = arr.length * 2;
	    if (newSize == 0)
		newSize = 1;
	    while (newSize < size)
		newSize = newSize * 2;
                
	    int newArr[] = new int[newSize];
	    System.arraycopy(arr, 0, newArr, 0, arr.length);
	    arr = newArr;
	}
            
	return arr;
    }
        
    private boolean hasWeightX(GBLayoutInfo r, GBConstraints c) {
	int gx = c.tempX + c.tempWidth;
	for (int i = c.tempX; i < gx; i++) {
	    if (r.weightX[i] != 0)
		return true;
	}
	return false;
    }
        
    private boolean hasWeightY(GBLayoutInfo r, GBConstraints c) {
	int gy = c.tempY + c.tempHeight;
	for (int i = c.tempY; i < gy; i++) {
	    if (r.weightY[i] != 0)
		return true;
	}
	return false;
    }
        
    /**
     * Adjusts the x, y, width, and height fields to the correct
     * values according to the constraint geometry and pads.
     */
    protected void AdjustForGravity(GBConstraints c, Rectangle r) {
	int diffx, diffy, w, h;
	Insets insets = (Insets)c.insets.clone();
            
	w = r.width -
            (insets.left + insets.right + c.hardinsets.left +
	    c.hardinsets.right);
	h = r.height -
            (insets.top + insets.bottom + c.hardinsets.top +
	    c.hardinsets.bottom);
            
	if (w < c.tinyWidth) {
	    if (c.fill == GBConstraints.HORIZONTAL ||
                c.fill == GBConstraints.BOTH) {
		diffx = c.tinyWidth - w;
		insets.left -= diffx/2;
		insets.right -= diffx/2;
		if (insets.left < 0) {
		    insets.right += insets.left;
		    insets.left = 0;
		}
		if (insets.right < 0) {
		    insets.left += insets.right;
		    insets.right = 0;
		}
	    } else {
		switch (c.anchor) {
		case GBConstraints.NORTH:
		case GBConstraints.SOUTH:
		case GBConstraints.CENTER:
		    diffx = c.tinyWidth - w;
		    insets.left -= diffx/2;
		    insets.right -= diffx/2;
		    if (insets.left < 0) {
			insets.right += insets.left;
			insets.left = 0;
		    }
		    if (insets.right < 0) {
			insets.left += insets.right;
			insets.right = 0;
		    }
		    break;
                        
		case GBConstraints.NORTHWEST:
		case GBConstraints.SOUTHWEST:
		case GBConstraints.WEST:
		    diffx = c.tinyWidth - w;
		    insets.right -= diffx;
		    if (insets.right < 0) {
			insets.left += insets.right;
			insets.right = 0;
		    }
		    break;
                        
		case GBConstraints.NORTHEAST:
		case GBConstraints.SOUTHEAST:
		case GBConstraints.EAST:
		    diffx = c.tinyWidth - w;
		    insets.left -= diffx;
		    if (insets.left < 0) {
			insets.right += insets.left;
			insets.left = 0;
		    }
		    break;
		default:
		    /* JSTYLED */
		    throw new IllegalArgumentException(Global.getMsg("sunsoft.jws.visual.rt.awt.GBLayout.illegal__anchor__value.4"));
		}
	    }
	}
            
	if (h < c.tinyHeight) {
	    if (c.fill == GBConstraints.VERTICAL ||
                c.fill == GBConstraints.BOTH) {
		diffy = c.tinyHeight - h;
		insets.top -= diffy/2;
		insets.bottom -= diffy/2;
		if (insets.top < 0) {
		    insets.bottom += insets.top;
		    insets.top = 0;
		}
		if (insets.bottom < 0) {
		    insets.top += insets.bottom;
		    insets.bottom = 0;
		}
	    } else {
		switch (c.anchor) {
		case GBConstraints.WEST:
		case GBConstraints.EAST:
		case GBConstraints.CENTER:
		    diffy = c.tinyHeight - h;
		    insets.top -= diffy/2;
		    insets.bottom -= diffy/2;
		    if (insets.top < 0) {
			insets.bottom += insets.top;
			insets.top = 0;
		    }
		    if (insets.bottom < 0) {
			insets.top += insets.bottom;
			insets.bottom = 0;
		    }
		    break;
                        
		case GBConstraints.NORTHWEST:
		case GBConstraints.NORTHEAST:
		case GBConstraints.NORTH:
		    diffy = c.tinyHeight - h;
		    insets.bottom -= diffy;
		    if (insets.bottom < 0) {
			insets.top += insets.bottom;
			insets.bottom = 0;
		    }
		    break;
                        
		case GBConstraints.SOUTHWEST:
		case GBConstraints.SOUTHEAST:
		case GBConstraints.SOUTH:
		    diffy = c.tinyHeight - h;
		    insets.top -= diffy;
		    if (insets.top < 0) {
			insets.bottom += insets.top;
			insets.top = 0;
		    }
		    break;
		default:
		    /* JSTYLED */
		    throw new IllegalArgumentException(Global.getMsg("sunsoft.jws.visual.rt.awt.GBLayout.illegal__anchor__value.4"));
		}
	    }
	}
            
	r.x += insets.left + c.hardinsets.left;
	r.width -= (insets.left + insets.right +
		    c.hardinsets.left + c.hardinsets.right);
	r.y += insets.top + c.hardinsets.top;
	r.height -= (insets.top + insets.bottom +
		     c.hardinsets.top + c.hardinsets.bottom);
            
	diffx = 0;
	if ((c.fill != GBConstraints.HORIZONTAL &&
	    c.fill != GBConstraints.BOTH)
            && (r.width > (c.minsize.width + c.ipadx + c.hardipadx))) {
	    diffx = r.width - (c.minsize.width + c.ipadx +
			       c.hardipadx);
	    r.width = c.minsize.width + c.ipadx + c.hardipadx;
	}
            
	diffy = 0;
	if ((c.fill != GBConstraints.VERTICAL &&
	    c.fill != GBConstraints.BOTH)
            && (r.height > (c.minsize.height + c.ipady + c.hardipady))) {
	    diffy = r.height - (c.minsize.height + c.ipady +
				c.hardipady);
	    r.height = c.minsize.height + c.ipady + c.hardipady;
	}
            
	switch (c.anchor) {
	case GBConstraints.CENTER:
	    r.x += diffx/2;
	    r.y += diffy/2;
	    break;
	case GBConstraints.NORTH:
	    r.x += diffx/2;
	    break;
	case GBConstraints.NORTHEAST:
	    r.x += diffx;
	    break;
	case GBConstraints.EAST:
	    r.x += diffx;
	    r.y += diffy/2;
	    break;
	case GBConstraints.SOUTHEAST:
	    r.x += diffx;
	    r.y += diffy;
	    break;
	case GBConstraints.SOUTH:
	    r.x += diffx/2;
	    r.y += diffy;
	    break;
	case GBConstraints.SOUTHWEST:
	    r.y += diffy;
	    break;
	case GBConstraints.WEST:
	    r.y += diffy/2;
	    break;
	case GBConstraints.NORTHWEST:
	    break;
	default:
	    /* JSTYLED */
	    throw new IllegalArgumentException(Global.getMsg("sunsoft.jws.visual.rt.awt.GBLayout.illegal__anchor__value.5"));
	}
    }
        
    /**
     * Figure out the minimum size of the
     * parent based on the information retrieved from GetLayoutInfo.
     */
    protected Dimension GetMinSize(Container parent,
				   GBLayoutInfo info) {
	Dimension d = new Dimension();
	int i, t;
	Insets insets = getInsets(parent);
            
	t = 0;
	for (i = 0; i < info.width; i++)
	    t += info.minWidth[i];
	d.width = t + insets.left + insets.right;
            
	t = 0;
	for (i = 0; i < info.height; i++)
	    t += info.minHeight[i];
	d.height = t + insets.top + insets.bottom;
            
	return d;
    }
        
    /**
     * Lays out the grid.  Called directly from layoutContainer.
     */
    protected void ArrangeGrid(Container parent) {
	ArrangeGrid(parent, true);
    }
        
    /**
     * Lays out the grid, conditionally reshaping the children.
     * The doReshape flag indicates whether or not
     * the children should be reshaped.
     *
     * @see layoutContainerNoReshape
     */
    protected void ArrangeGrid(Container parent, boolean doReshape) {
	Component comp;
	int compindex;
	GBConstraints constraints;
	Insets insets = getInsets(parent);
	Component components[] = parent.getComponents();
	Dimension d;
	Rectangle r = new Rectangle();
	int i, diffw, diffh;
	double weight;
	GBLayoutInfo info, tinyinfo;
            
	/*
	 * If the parent has no slaves anymore, then don't do anything
	 * at all:  just leave the parent's size as-is.
	 */
	if (components.length == 0 &&
            (columnWidths == null || columnWidths.length == 0) &&
            (rowHeights == null || rowHeights.length == 0)) {
	    return;
	}
            
	/*
	 * Pass #1: scan all the slaves to figure out the total amount
	 * of space needed.
	 */
            
	info = GetLayoutInfo(parent, PREFERREDSIZE);
	d = GetMinSize(parent, info);
            
	Dimension parentSize = parent.getSize();
            
	if (d.width > parentSize.width || d.height >
            parentSize.height) {
	    info = GetLayoutInfo(parent, MINSIZE);
	    d = GetMinSize(parent, info);
	}
            
	tinyinfo = GetLayoutInfo(parent, TINYSIZE);
            
	layoutInfo = info;
	r.width = d.width;
	r.height = d.height;
            
	/* BEGIN JSTYLED */
	/*
	 * DEBUG
	 *
	 * DumpLayoutInfo(info);
	 * for (compindex = 0 ; compindex < components.length ; compindex++) {
	 * comp = components[compindex];
	 * if (!comp.isVisible())
	 *	continue;
	 * constraints = lookupConstraints(comp);
	 * DumpConstraints(constraints);
	 * }
	 * System.out.println("minSize " + r.width + " " + r.height);
	 */
                
	/*
	 * If the current dimensions of the window don't match the desired
	 * dimensions, then adjust the minWidth and minHeight arrays
	 * according to the weights.
	 */

	/* END JSTYLED */
            
	diffw = parentSize.width - r.width;
	if (diffw != 0) {
	    weight = 0.0;
	    for (i = 0; i < info.width; i++)
		weight += info.weightX[i];
	    if (weight > 0.0) {
		for (i = 0; i < info.width; i++) {
		    int dx = (int)((((double)diffw) *
				    info.weightX[i]) / weight);
		    info.minWidth[i] += dx;
		    r.width += dx;
		    if (info.minWidth[i] < tinyinfo.minWidth[i]) {
			r.width += tinyinfo.minWidth[i] -
                            info.minWidth[i];
			info.minWidth[i] = tinyinfo.minWidth[i];
		    }
		}
	    }
	    diffw = parentSize.width - r.width;
	} else {
	    diffw = 0;
	}
            
	diffh = parentSize.height - r.height;
	if (diffh != 0) {
	    weight = 0.0;
	    for (i = 0; i < info.height; i++)
		weight += info.weightY[i];
	    if (weight > 0.0) {
		for (i = 0; i < info.height; i++) {
		    int dy = (int)((((double)diffh) *
				    info.weightY[i]) / weight);
		    info.minHeight[i] += dy;
		    r.height += dy;
		    if (info.minHeight[i] < tinyinfo.minHeight[i]) {
			r.height += tinyinfo.minHeight[i] -
                            info.minHeight[i];
			info.minHeight[i] = tinyinfo.minHeight[i];
		    }
		}
	    }
	    diffh = parentSize.height - r.height;
	} else {
	    diffh = 0;
	}
            
	/*
	 * DEBUG
	 *
	 * System.out.println("Re-adjusted:");
	 * DumpLayoutInfo(info);
	 */
            
	/*
	 * Now do the actual layout of the slaves 
	 * using the layout information
	 * that has been collected.
	 */
            
	int anchorx = anchor;
	int anchory = anchor;
            
	if (diffw < 0)
	    anchorx = clipAnchor;
	if (diffh < 0)
	    anchory = clipAnchor;
            
	switch (anchorx) {
	case GBConstraints.CENTER:
	case GBConstraints.NORTH:
	case GBConstraints.SOUTH:
	    info.startx = diffw/2;
	    break;
                
	case GBConstraints.WEST:
	case GBConstraints.NORTHWEST:
	case GBConstraints.SOUTHWEST:
	    info.startx = 0;
	    break;
                
	case GBConstraints.EAST:
	case GBConstraints.NORTHEAST:
	case GBConstraints.SOUTHEAST:
	    info.startx = diffw;
	    break;
                
	default:
	    /* JSTYLED */
	    throw new IllegalArgumentException(Global.getMsg("sunsoft.jws.visual.rt.awt.GBLayout.illegal__anchor__value.6"));
	}
            
	switch (anchory) {
	case GBConstraints.CENTER:
	case GBConstraints.WEST:
	case GBConstraints.EAST:
	    info.starty = diffh/2;
	    break;
                
	case GBConstraints.NORTH:
	case GBConstraints.NORTHWEST:
	case GBConstraints.NORTHEAST:
	    info.starty = 0;
	    break;
                
	case GBConstraints.SOUTH:
	case GBConstraints.SOUTHWEST:
	case GBConstraints.SOUTHEAST:
	    info.starty = diffh;
	    break;
                
	default:
	    /* JSTYLED */
	    throw new IllegalArgumentException(Global.getMsg("sunsoft.jws.visual.rt.awt.GBLayout.illegal__anchor__value.7"));
	}
            
	info.startx += insets.left;
	info.starty += insets.top;
            
	for (compindex = 0; compindex < components.length;
	    compindex++) {
	    comp = components[compindex];
	    if (!comp.isVisible())
		continue;
	    constraints = lookupConstraints(comp);
                
	    r.x = info.startx;
	    for (i = 0; i < constraints.tempX; i++)
		r.x += info.minWidth[i];
                
	    r.y = info.starty;
	    for (i = 0; i < constraints.tempY; i++)
		r.y += info.minHeight[i];
                
	    r.width = 0;
	    for (i = constraints.tempX;
		 i < (constraints.tempX + constraints.tempWidth);
		 i++) {
		r.width += info.minWidth[i];
	    }
                
	    r.height = 0;
	    for (i = constraints.tempY;
		 i < (constraints.tempY + constraints.tempHeight);
		 i++) {
		r.height += info.minHeight[i];
	    }
                
	    AdjustForGravity(constraints, r);
                
	    /*
	     * If the window is too small to be interesting then
	     * unmap it.  Otherwise configure it and then make sure
	     * it's mapped.
	     */
                
	    if ((r.width <= 0) || (r.height <= 0)) {
		if (doReshape)
		    comp.reshape(-1, -1, 0, 0);
		constraints.location = new Point(-1, -1);
		constraints.size = new Dimension(0, 0);
	    } else {
		Point loc = comp.getLocation();
		Dimension size = comp.getSize();
                    
		if (loc.x != r.x || loc.y != r.y ||
                    size.width != r.width || size.height != r.height) {
		    if (doReshape)
			comp.reshape(r.x, r.y, r.width, r.height);
		    constraints.location = new Point(r.x, r.y);
		    constraints.size = new Dimension(r.width, r.height);
		}
	    }
	}
    }
}
