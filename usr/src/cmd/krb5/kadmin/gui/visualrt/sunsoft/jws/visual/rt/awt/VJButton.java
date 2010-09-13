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
 * @(#) VJButton.java 1.3 - last change made 01/08/97
 */

package sunsoft.jws.visual.rt.awt;

import sunsoft.jws.visual.rt.base.Global;
import java.awt.*;

public class VJButton extends Button {
    private boolean isStandard = true;
    
    public VJButton() {
        super();
    }
    
    public VJButton(String label) {
        super(label);
    }
    
    public Dimension minimumSize() {
        Dimension d = super.minimumSize();
        d = new Dimension(d.width, d.height);
        if (isStandard) {
            d.width = Math.max(d.width, 75);
            if (!Global.isWindows())
                d.height += 6;
        }
        return d;
    }
    
    public Dimension preferredSize() {
        Dimension d = super.preferredSize();
        d = new Dimension(d.width, d.height);
        if (isStandard) {
            d.width = Math.max(d.width, 75);
            if (!Global.isWindows())
                d.height += 6;
        }
        return d;
    }
    
    public boolean isStandard() {
        return isStandard;
    }
    
    public void setStandard(boolean value) {
        isStandard = value;
    }
}
