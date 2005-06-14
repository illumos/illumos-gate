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

/**
 * CLCheckbox.java
 *
 * Copyright 1995-1996 Active Software Inc.
 *
 * @version @(#)CLCheckbox.java 1.9 96/12/11
 * @author  Tilman Sporkert
 */


package sunsoft.jws.visual.rt.awt;

import java.awt.*;
/* BEGIN JSTYLED */

/**
         * A CLCheckbox is a special Object that the ColumnList 
	 * draws like a flat
         * checkbox. This has two advantages over putting 
	 * java.awt.Checkboxes into
         * the ColumnList:
         * - under Motif, the java.awt.Checkbox has some 
	 * extra space around it, 
         *   making the rows very high.
         * - highlighting a row with a java.awt.Checkbox in it looks ugly
         * - significant performance improvements (measured 10x 
	 * in one application)
         * - the Checkbox is always drawn flat, not in 3D look. 
	 * Flat is the correct
         *   look in a scrollable area with a white background.
         *
         * Notes on usage:
         * - if the state of a CLCheckbox gets changed, 
	 * needsRepaint() should be
         *   called on the ColumnList to make the change visible
         * - If a CLCheckbox is in a column list, clicking 
	 * on the box changes the
         *   state and sends out an ACTION_EVENT. The row 
	 * will not get selected.
         *   Unlike AWT Checkboxes, clicking on the label does not change the
         *   status. It just selects the row in the 
	 * ColumnList (which triggers a
         *   LIST_EVENT).
         *
         * @author  Tilman Sporkert
         */
            /* END JSTYLED */
public class CLCheckbox extends CLComponent
{
    private boolean state = false;
    
    public CLCheckbox(String text, boolean state) {
        super(text);
        this.state = state;
    }
    
    public boolean getState() {
        return state;
    }
    
    public void setState(boolean state) {
        this.state = state;
    }
    
    public void paint(Graphics g, int x, int y, int colWidth,
		      int rowHeight, int ascent, int alignment)
    {
        if (canvas == null)
            return;
        
        if (colWidth >= (rowHeight+4)) {
            g.drawRect(x + 5, y + 2, rowHeight - 6, rowHeight - 6);
            if (state) {
                g.drawLine(x + 8, y + rowHeight / 2 - 1,
			   x + rowHeight / 2 + 2, y + rowHeight - 7);
                g.drawLine(x + rowHeight / 2 + 2, y + rowHeight - 7,
			   x + rowHeight - 3, y + 4);
                g.drawLine(x + 7, y + rowHeight / 2 - 1,
			   x + rowHeight / 2 + 2, y + rowHeight - 6);
                g.drawLine(x + rowHeight / 2 + 2, y + rowHeight - 6,
			   x + rowHeight - 3, y + 5);
            }
        }
        if (text != null) {
            canvas.drawString(g, text, x + rowHeight + 4, y + ascent,
			      colWidth - rowHeight - 8, alignment);
        }
    }
    
    public int textX() {
        if (canvas == null)
            return -1;
        else
            return canvas.rowHeight + 4;
    }
    
    public int textY() {
        if (canvas == null)
            return -1;
        else
            return canvas.rowAscent;
    }
    
    public Dimension size() {
        if (canvas == null)
            return null;
        
        FontMetrics metrics = canvas.getFontMetrics();
        Dimension size = new Dimension(0, 0);
        
        if (text != null)
            size.width += metrics.stringWidth(text) + 8;
        size.width += canvas.rowHeight;
        size.height = canvas.rowHeight;
        
        return size;
    }
    
    public boolean mouseDown(Event evt) {
        if (canvas == null)
            return false;
        
        if (evt.x <= canvas.rowHeight) {
            state = !state;
            canvas.postEvent(new Event(this, Event.ACTION_EVENT,
				       new Boolean(state)));
            canvas.repaint();
            return true;
        }
        
        return false;
    }
}
