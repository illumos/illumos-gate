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

package sunsoft.jws.visual.rt.awt;

import java.awt.*;

public interface GBContainer {
    
    //
    // Initialization
    //
    
    public void setGBPanel(GBPanel panel);
    
    //
    // Container methods
    //
    
    public void setLayout(LayoutManager mgr);
    public void layout();
    
    public Component add(Component comp);
    public void remove(Component comp);
    public void removeAll();
    
    public void update(Graphics g);
    public void paint(Graphics g);
    public boolean handleEvent(Event e);
    public void reshape(int x, int y, int w, int h);
    
    //
    // Constraints
    //
    
    public void setConstraints(Component comp, GBConstraints c);
    public GBConstraints getConstraints(Component comp);
    
    //
    // Layout and Preview modes
    //
    
    public void layoutMode();
    public void previewMode();
    
    //
    // GBLayout attributes
    //
    
    public void setColumnWeights(double w[]);
    public void setRowWeights(double w[]);
    public double [] getColumnWeights();
    public double [] getRowWeights();
    
    public void setColumnWidths(int w[]);
    public void setRowHeights(int h[]);
    public int[] getColumnWidths();
    public int[] getRowHeights();
    
    public void addRow(int index);
    public void addColumn(int index);
}
