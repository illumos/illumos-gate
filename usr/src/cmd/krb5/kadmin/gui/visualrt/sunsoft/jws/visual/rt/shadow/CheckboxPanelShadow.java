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
 * @(#) CheckboxPanelShadow.java 1.7 - last change made 06/03/97
 */

package sunsoft.jws.visual.rt.shadow;

import sunsoft.jws.visual.rt.awt.CheckboxPanel;
import sunsoft.jws.visual.rt.shadow.GBPanelShadow;

/**
 * Wraps an AWT widget.  The attributes available for this
 * class are listed below.  In the type column, type names beginning
 * with "sunsoft.jws.visual.rt" have been abbreviated to begin with
 * "rt".
 *
 * < pre>
name            type                      default value
-----------------------------------------------------------------------
none
*  < /pre>
*
* Check the super class for additional attributes.
*
* @see CheckboxPanel
* @version 	1.7, 06/03/97
*/
public class CheckboxPanelShadow extends GBPanelShadow {
    
    /* added -kp bug id */
    static final int minColumnWidth = 14;
    static final int minRowHeight = 14;
    static final int columns = 2;
    static final int rows = 2;
    /* end added -kp */
    
    
    public void createBody() {
        body = new CheckboxPanel();
    }
    /* added -kp */
    protected void postCreate() {
        super.postCreate();
        if (inDesignerRoot())
        {
            CheckboxPanel c = (CheckboxPanel)body;
            int gw[] = c.getColumnWidths();
            int gh[] = c.getRowHeights();
            int w[] = new int[columns];
            int h[] = new int[rows];
            double ww[] = new double[columns];
            double hh[] = new double[rows];
            for (int x = 0; x < columns; x++)
            {
                w[x] = minColumnWidth;
                ww[x] = 0.0;
            }
            for (int y = 0; y < rows; y++)
            {
                h[y] = minRowHeight;
                hh[y] = 0.0;
            }
            if ((gw ==  null) || (gw.length <= 1))
            {
                if (c.getComponentCount() <= 0)
                {
                    c.setColumnWidths(w);
                    c.setColumnWeights(ww);
                }
            }
            if ((gh ==  null) || (gh.length <= 1))
            {
                if (c.getComponentCount() <= 0)
                {
                    c.setRowHeights(h);
                    c.setRowWeights(hh);
                }
            }
        }
    }
    /* end added -kp */
}
