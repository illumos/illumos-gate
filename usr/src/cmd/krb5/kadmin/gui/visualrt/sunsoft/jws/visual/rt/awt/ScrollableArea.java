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
 * @(#) ScrollableArea.java 1.6 - last change made 02/09/97
 */

package sunsoft.jws.visual.rt.awt;

import sunsoft.jws.visual.rt.awt.*;

import java.awt.*;

public class ScrollableArea extends VJPanel implements Scrollable {
    private Component comp;
    private int curx, cury;
    private int lineHeight = 4;
    
    public void layout() {
        if (comp == null)
            return;
        
        Dimension d = comp.preferredSize();
        d = new Dimension(d.width, d.height);
        Dimension size = size();
        d.width = Math.max(d.width, size.width);
        d.height = Math.max(d.height, size.height);
        
        comp.reshape(curx, cury, d.width, d.height);
    }
    
    // #ifdef JDK1.1
    protected void addImpl(Component comp, Object constraints,
			   int index) {
        doAdd(comp);
        super.addImpl(comp, constraints, index);
    }
    // #else
    // public Component add(Component comp, int pos) {
    //   doAdd(comp);
    //   return super.add(comp, pos);
    // }
    // #endif
    
    private void doAdd(Component comp) {
        if (this.comp != null)
            remove(this.comp);
        this.comp = comp;
    }
    
    public void remove(Component comp) {
        super.remove(comp);
        if (this.comp == comp)
            this.comp = null;
    }
    
    public Dimension minimumSize() {
        if (comp != null)
            return comp.preferredSize();
        else
            return new Dimension(0, 0);
    }
    
    public Dimension preferredSize() {
        return minimumSize();
    }
    
    public void scrollX(int x) {
        curx = -x;
        if (comp != null)
            comp.move(curx, cury);
    }
    
    public void scrollY(int y) {
        cury = -y;
        if (comp != null)
            comp.move(curx, cury);
    }
    
    public Dimension scrollSize() {
        return minimumSize();
    }
    
    public Dimension viewSize(Dimension size) {
        return size;
    }
    
    public void setLineHeight(int lineHeight) {
        this.lineHeight = lineHeight;
    }
    
    public int lineHeight() {
        return lineHeight;
    }
}
