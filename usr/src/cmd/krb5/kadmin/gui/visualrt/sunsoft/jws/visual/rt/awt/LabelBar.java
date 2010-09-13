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
 * @(#) LabelBar.java 1.25 - last change made 07/25/97
 */

package sunsoft.jws.visual.rt.awt;

import java.awt.*;
import sunsoft.jws.visual.rt.base.DesignerAccess;
import sunsoft.jws.visual.rt.base.Global;

            /* BEGIN JSTYLED */
        /**
         * Displays a 3D bar with text within it.  Useful as a divider between
         * different parts of a panel.  Uses the java.awt.Label contants for
         * its alignment settings (LEFT, CENTER, RIGHT.) <P>
         *
         * When the alignment is set to LEFT, the label 
	 * looks something like this:
         *
         * <pre>
         *    ----label---------------------------
         * </pre>
         *
         * Set the edge offset attribute to control how far from the edge the
         * text in the label rests.  When the alignment is CENTER, the offset
         * is the distance on both sides on the label.  You may set
         * the label text to null to get a label bar that acts merely as a
         * separator.
         *
         * @version 1.25, 07/25/97
         */
            /* END JSTYLED */
public class LabelBar extends Canvas {
    /**
     * The left alignment.
     */
    public static final int LEFT = Label.LEFT;
    
    /**
     * The center alignment.
     */
    public static final int CENTER = Label.CENTER;
    
    /**
     * The right alignment.
     */
    public static final int RIGHT = Label.RIGHT;
    
    /**
     * The number of pixels (both sides) between bar and label.
     */
    private static final int barAndLabelPad = 2;
    
    /**
     * The number of pixels (both sides) between bar edge
     */
    private static final int barAndEdgePad = 1;
    
    /**
     * The number of pixels in the bar's thickness.
     */
    private static final int barThickness = 2;
    
    private int alignment = Label.LEFT;
    private int labelOffsetFromEdge = 10;
    private String label;
    
    public LabelBar() {
        this.label = null;
    }
    
    public LabelBar(String label) {
        this.label = label;
    }
    
    public void setLabel(String label) {
        this.label = label;
        repaint();
    }
    
    public String getLabel() {
        return (label);
    }
    
    public void setLabelOffsetFromEdge(int offset) {
        if (offset != labelOffsetFromEdge) {
            labelOffsetFromEdge = offset;
            repaint();
        }
    }
    
    public int getLabelOffsetFromEdge() {
        return (labelOffsetFromEdge);
    }
    
    public void setAlignment(int alignment) {
        switch (alignment) {
	case LEFT:
	case CENTER:
	case RIGHT:
            this.alignment = alignment;
            repaint();
            break;
	default:
            throw new IllegalArgumentException(
					       /* JSTYLED */
					       Global.getMsg("sunsoft.jws.visual.rt.awt.ImageLabel.ImproperAlignment"));
        }
    }
    
    public int getAlignment() {
        return (alignment);
    }
    
    public Dimension preferredSize() {
        return (minimumSize());
    }
    
    public Dimension minimumSize() {
        Font font = getFont();
        if (label != null && label.length() > 0 && font != null) {
            FontMetrics fm = getFontMetrics(font);
            return (new Dimension(fm.stringWidth(label) +
				  labelOffsetFromEdge * 2,
				  fm.getHeight()));
        } else {
            return (new Dimension(labelOffsetFromEdge * 2, 6));
        }
    }
    
    /**
     * Sets the foreground color (the label bar text.)  This overrides
     * the setForeground call in Component in order to get an immediate
     * repaint when the foreground color setting is changed.
     */
    public void setForeground(Color c) {
        super.setForeground(c);
        repaint();
    }
    
    /**
     * Disables this component. This overrides the same call in
     * Component in order to get an immediate repaint when it is
     * called.
     */
    public void disable() {
        super.disable();
        repaint();
    }
    
    /**
     * Enables this component. This overrides the same call in
     * Component in order to get an immediate repaint when it is
     * called.
     */
    public void enable() {
        super.enable();
        repaint();
    }
    
    /**
     * Stipples the given area in a checkerboard fashion using the given
     * color.  It could be called, for example, after regular painting
     * is complete whenever this component is disabled by using the
     * background color as the stipple color.
     */
    private void checkerStipple(Graphics g, Color c,
				int x1, int y1, int w, int h) {
        Color oldColor = g.getColor();
        g.setColor(c);
        for (int y = y1; y < y1 + h; y++)
            for (int x = x1; x < x1 + w; x++)
		if (y % 2 == x % 2)
		    g.drawLine(x, y, x, y);
        g.setColor(oldColor);
    }
    
    /**
     * Paints LabelBar contents.
     */
    public void paint(Graphics g) {
        if (Global.isWindows())
            g = getGraphics();
        synchronized (DesignerAccess.mutex) {
            
            super.paint(g);
            int midy = size().height / 2 - 1;
            if (label != null && label.length() > 0) {
                // set up and draw the label location
                // according to the alignment
                Font font = getFont();
                FontMetrics fm = getFontMetrics(font);
                int labelWidth = fm.stringWidth(label);
                int labelBegin;
                switch (alignment) {
		case LEFT:
                    labelBegin = labelOffsetFromEdge;
                    break;
		case CENTER:
                    labelBegin = (size().width - labelWidth) / 2;
                    break;
		case RIGHT:
                    labelBegin = size().width - (labelOffsetFromEdge +
						 labelWidth);
                    break;
		default:
                    throw new IllegalArgumentException(
						       /* JSTYLED */
						       Global.getMsg("sunsoft.jws.visual.rt.awt.ImageLabel.ImproperAlignment"));
                }
                g.setColor(getForeground());
                g.setFont(getFont());
                g.drawString(label, labelBegin,
		     size().height - (((size().height - fm.getHeight()) / 2)
					      + fm.getMaxDescent() + 1));
                
                // set up and draw the bars according
                // to the location of the label
                int leftBarBegin = barAndEdgePad;
                int leftBarWidth = labelBegin - (barAndLabelPad +
						 leftBarBegin);
                int rightBarBegin = labelBegin + (labelWidth +
						  barAndLabelPad);
                int rightBarWidth = size().width - (rightBarBegin +
						    barAndEdgePad);
                g.setColor(getBackground());
                if (leftBarWidth > 0)
                    g.fill3DRect(leftBarBegin, midy, leftBarWidth,
				 barThickness, false);
                if (rightBarWidth > 0)
                    g.fill3DRect(rightBarBegin, midy, rightBarWidth,
				 barThickness, false);
            } else {
                // no label, just draw a single bar
                int barBegin = barAndEdgePad;
                int barWidth = size().width - (barAndEdgePad * 2);
                g.setColor(getBackground());
                g.fill3DRect(barBegin, midy, barWidth, barThickness,
			     false);
            }
            
            // if disabled, stipple everything just
            // painted with the background color
            if (!isEnabled())
                checkerStipple(g, getBackground(), 0, 0, size().width,
			       size().height);
        }
    }
}
