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
 * @version @(#)CLComponent.java 1.6 96/11/08
 */

package sunsoft.jws.visual.rt.awt;

import java.awt.*;

public abstract class CLComponent {
    protected ColumnListCanvas canvas;
    protected int row, column;
    protected String text;
    private boolean editable;
    
    public CLComponent(String text) {
        setText(text);
        this.editable = true;
    }
    
    void setCanvas(ColumnListCanvas canvas, int row, int column) {
        this.canvas = canvas;
        this.row = row;
        this.column = column;
    }
    
    public void setText(String text) {
        setText(text, true);
    }
    
    public void setText(String text, boolean update) {
        this.text = text;
        if (canvas != null) {
            canvas.adjustColumnWidths(this, column);
            if (update)
                canvas.updateView();
        }
    }
    
    public String getText() {
        return text;
    }
    
    public void setEditable(boolean value) {
        this.editable = value;
    }
    
    public boolean getEditable() {
        return editable;
    }
    
    public String toString() {
        return text;
    }
    
    public abstract int textX();
    public abstract int textY();
    public abstract Dimension size();
    public abstract void paint(Graphics g, int x, int y, int width,
			       int height, int ascent, int alignment);
    
    public boolean mouseDown(Event evt) {
        return false;
    }
}
