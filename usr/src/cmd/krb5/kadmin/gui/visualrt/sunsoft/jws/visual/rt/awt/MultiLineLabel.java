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

/* BEGIN JSTYLED */
        /**
         * MultiLineLabel.java
         *
         * This example is from the book _Java in a 
	 * Nutshell_ by David Flanagan.
         * Written by David Flanagan.  
	 * Copyright (c) 1996 O'Reilly & Associates.
         * You may study, use, modify, and distribute 
	 * this example for any purpose.
         * This example is provided WITHOUT WARRANTY either 
	 * expressed or implied.
         *
         * Tilman 05/07/96: added a maxChars parameter to 
	 * specify a maximum line
         * length. If any of the lines is longer, it will be cut
         * at the last space character before maxChars, until it fits
         * into maxChars. Set maxChars to -1 if you don't care.
         *
         * Van 07/30/96: added the removal of backslash-r 
	 * from the multi-line string
         * that might have been added by strings in Windows (which
         * expect newlines to be indicated by backslash-r backslash-n)
         *
         * Van 10/18/96: changed the way lines are tokenized so that multiple
         * consequetive newline characters create a blank line(s).
         *
         * Van 10/21/96: added interfaces to the maxChars variable
         *
         * @version @(#)MultiLineLabel.java 1.15 97/07/25
         */
/* END JSTYLED */        

package sunsoft.jws.visual.rt.awt;

import sunsoft.jws.visual.rt.base.Global;
import java.awt.*;
import java.util.*;

public class MultiLineLabel extends Canvas {
    public static final int LEFT = Label.LEFT; // Alignment constants
    public static final int CENTER = Label.CENTER;
    public static final int RIGHT = Label.RIGHT;
    
    protected String label;
    protected Vector lines;         // The lines of text to display
    protected int num_lines;          // The number of lines
    protected int maxChars;           // maximum width of lines
    protected int margin_width;       // Left and right margins
    protected int margin_height;      // Top and bottom margins
    protected int line_height;        // Total height of the font
    protected int line_ascent;        // Font height above baseline
    protected int[] line_widths;      // How wide each line is
    protected int max_width;          // The width of the widest line
    protected int alignment = LEFT;   // The alignment of the text.
    
    /**
     * This method breaks a specified label up into an array of lines.
     * It uses the StringTokenizer utility class.
     */
    protected void newLabel(String label) {
        if (label == null)
            label = /* NOI18N */"";
        this.label = label;
        
        lines = new Vector();
        int len = label.length();
        int startFrom = 0;
        while (startFrom != -1 && startFrom < len) {
            // determine next line
            String line;
            int index = label.indexOf(/* NOI18N */"\n", startFrom);
            if (index == -1) {
                line = label.substring(startFrom);
                startFrom = -1;
            } else {
                line = label.substring(startFrom, index);
                startFrom = index + 1;
            }
            
            // wrap the words in the line
            if ((maxChars == -1) || (line.length() <= maxChars))
                lines.addElement(line);
            else {
                while (line.length() > maxChars) {
                    int offset = line.lastIndexOf(/* NOI18N */ ' ',
						  maxChars);
                    if (offset == -1) {
                        // didn't get one within maxChars!
                        offset = line.indexOf(/* NOI18N */ ' ');
                        if (offset == -1)
                            break;
                    }
                    lines.addElement(line.substring(0, offset));
                    line = line.substring(offset + 1);
                }
                lines.addElement(line);
            }
        }
        num_lines = lines.size();
        line_widths = new int[num_lines];
    }
    
    /**
     * This method figures out how the font is, and how wide each
     * line of the label is, and how wide the widest line is.
     */
    protected void measure() {
        /* JSTYLED */
	if (this.getFont() == null) return;
        FontMetrics fm = this.getFontMetrics(this.getFont());
        // If we don't have font metrics yet, just return.
        /* JSTYLED */
	if (fm == null) return;
        
        line_height = fm.getHeight();
        line_ascent = fm.getAscent();
        max_width = 0;
        for (int i = 0; i < num_lines; i++) {
            line_widths[i] = fm.stringWidth(
					    (String) lines.elementAt(i));
            if (line_widths[i] > max_width) max_width = line_widths[i];
        }
        Dimension d = preferredSize();
        setSize(d);
    }
    
    // Here are four versions of the constructor.
    
    /**
     * Break the label up into separate lines, and save the other info.
     */
    public MultiLineLabel(String label, int maxChars,
			  int margin_width, int margin_height,
			  int alignment) {
        this.maxChars = maxChars;
        newLabel(label);
        this.margin_width = margin_width;
        this.margin_height = margin_height;
        this.alignment = alignment;
    }
    public MultiLineLabel(String label, int maxChars,
			  int margin_width, int margin_height) {
        this(label, maxChars, margin_width, margin_height, LEFT);
    }
    public MultiLineLabel(String label, int maxChars,
			  int alignment) {
        this(label, maxChars, 10, 10, alignment);
    }
    public MultiLineLabel(String label, int maxChars) {
        this(label, maxChars, 10, 10, LEFT);
    }
    
    public MultiLineLabel(String label) {
        this(label, -1, 10, 10, LEFT);
    }
    
    public MultiLineLabel() {
        this(/* NOI18N */"MultiLineLabel");
    }
    
    // Methods to set the various attributes of the component
    public void setLabel(String label) {
        newLabel(label);
        measure();
        repaint();
    }
    
    public String getLabel() {
        return label;
    }
    
    public void setMaxColumns(int w) {
        if (w < 0)
            w = -1;
        maxChars = w;
        newLabel(label);
        measure();
        repaint();
    }
    
    public int getMaxColumns() {
        return (maxChars);
    }
    
    public void setFont(Font f) {
        super.setFont(f);
        measure();
        repaint();
    }
    
    public void setForeground(Color c) {
        super.setForeground(c);
        repaint();
    }
    
    public void setAlignment(int a) { alignment = a; repaint(); }
    public void setMarginWidth(int mw) { margin_width = mw; repaint(); }
    public void setMarginHeight(int mh) { margin_height = mh;
    repaint(); }
    public int getAlignment() { return alignment; }
    public int getMarginWidth() { return margin_width; }
    public int getMarginHeight() { return margin_height; }
    
    /**
     * This method is invoked after our Canvas is first created
     * but before it can actually be displayed.  After we've
     * invoked our superclass's addNotify() method, we have font
     * metrics and can successfully call measure() to figure out
     * how big the label is.
     */
    public void addNotify() { super.addNotify(); measure(); }
    
    /**
     * This method is called by a layout manager when it wants to
     * know how big we'd like to be.
     */
    public Dimension preferredSize() {
        return new Dimension(max_width + 2*margin_width,
			     num_lines * line_height + 2*margin_height);
    }
    
    /**
     * This method is called when the layout manager wants to know
     * the bare minimum amount of space we need to get by.
     */
    public Dimension minimumSize() {
        return new Dimension(max_width, num_lines * line_height);
    }
    
    /**
     * This method draws the label (applets use the same method).
     * Note that it handles the margins and the alignment, but that
     * it doesn't have to worry about the color or font--the superclass
     * takes care of setting those in the Graphics object we're passed.
     */
    public void paint(Graphics g) {
        if (Global.isWindows())
            g = getGraphics();
        int x, y;
        Dimension d = this.size();
        
        int mw = Math.max((d.width - max_width)/2, 0);
        g.setColor(getForeground());
        
        y = line_ascent + (d.height - num_lines * line_height)/2;
        for (int i = 0; i < num_lines; i++, y += line_height) {
            switch (alignment) {
	    case LEFT:
                x = mw;
                break;
	    case CENTER:
	    default:
                x = (d.width - line_widths[i])/2;
                break;
	    case RIGHT:
                x = d.width - mw - line_widths[i];
                break;
            }
            g.drawString(((String) lines.elementAt(i)).trim(), x, y);
        }
    }
}
