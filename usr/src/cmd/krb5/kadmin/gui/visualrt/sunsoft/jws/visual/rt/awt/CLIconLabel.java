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
 * Copyright 1996 Active Software Inc.
 *
 * @version @(#)CLIconLabel.java 1.8 96/11/14
 */

package sunsoft.jws.visual.rt.awt;

import sunsoft.jws.visual.rt.type.IntHolder;
import java.awt.*;

public class CLIconLabel extends CLComponent
{
    private static final int ICON_XPAD = 2;
    private static final int ICON_WIDTH = 16;
    private static final int TOTAL_ICON_WIDTH = ICON_WIDTH +
	(2*ICON_XPAD);
    
    private static final int ICON_YPAD = 0;
    private static final int ICON_HEIGHT = 16;
    private static final int TOTAL_ICON_HEIGHT = ICON_HEIGHT +
	(2*ICON_YPAD);
    
    private static final int TEXT_PAD = 4;
    
    private Image icon;
    private boolean editable = true;
    
    /**
     * Construct a new CLIconLabel.
     */
    public CLIconLabel(String text, Image icon) {
        super(text);
        this.icon = icon;
    }
    
    public Image getIcon() {
        return icon;
    }
    
    public void setIcon(Image icon) {
        setIcon(icon, true);
    }
    
    public void setIcon(Image icon, boolean update) {
        this.icon = icon;
        if (canvas != null && update)
            canvas.updateView();
    }
    
    public void paint(Graphics g,
		      int x, int y, int w, int h, int ascent, int alignment)
    {
        if (canvas == null)
            return;
        
        IntHolder xoff = new IntHolder();
        String s = getOffsetAndText(w, alignment, xoff);
        
        if (icon != null && w >= TOTAL_ICON_WIDTH) {
            g.drawImage(icon, x + xoff.value + ICON_XPAD,
			y + ICON_YPAD, canvas);
            xoff.value += TOTAL_ICON_WIDTH;
        } else {
            xoff.value += TEXT_PAD;
        }
        
        if (s != null) {
            g.drawString(s, x + xoff.value, y + ascent);
        }
    }
    
    private String getOffsetAndText(int width, int alignment,
				    IntHolder xoff) {
        FontMetrics fm = canvas.getFontMetrics();
        int iconWidth = 0;
        int iconPad = 0;
        int textWidth = 0;
        int rTextPad = 0;
        String s = null;
        
        if (icon != null) {
            iconWidth = TOTAL_ICON_WIDTH;
            iconPad = ICON_XPAD;
        } else if (text != null) {
            iconWidth = TEXT_PAD;
        }
        
        if (text != null) {
            rTextPad = TEXT_PAD;
            int availTextW = width - iconWidth - rTextPad;
            s = canvas.chopText(text, availTextW);
            textWidth = fm.stringWidth(s);
        }
        
        int totalWidth = iconWidth + textWidth + rTextPad;
        
        switch (alignment) {
	case Label.LEFT:
            xoff.value = 0;
            break;
	case Label.CENTER:
            xoff.value = (width - totalWidth)/2;
            break;
	case Label.RIGHT:
            xoff.value = width - totalWidth;
            break;
        }
        
        if (xoff.value < 0)
            xoff.value = 0;
        
        return s;
    }
    
    public int textX() {
        if (canvas == null)
            return -1;
        
        IntHolder xoff = new IntHolder();
        getOffsetAndText(canvas.columnWidth(column),
			 canvas.getFormat(column),
			 xoff);
        
        if (icon != null)
            xoff.value += TOTAL_ICON_WIDTH;
        else if (text != null)
            xoff.value += TEXT_PAD;
        
        return xoff.value;
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
        
        if (icon != null)
            size.width += TOTAL_ICON_WIDTH;
        else if (text != null)
            size.width += TEXT_PAD;
        
        if (text != null)
            size.width += metrics.stringWidth(text) + TEXT_PAD;
        size.height = canvas.rowHeight;
        
        return size;
    }
}
