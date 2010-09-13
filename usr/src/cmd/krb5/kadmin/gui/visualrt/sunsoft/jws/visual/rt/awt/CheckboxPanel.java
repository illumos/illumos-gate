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

public class CheckboxPanel extends GBPanel {
    
    private CheckboxGroup group;
    
    public CheckboxPanel() {
        super();
        group = new CheckboxGroup();
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
        if (comp instanceof Checkbox) {
            Checkbox box = (Checkbox)comp;
            box.setCheckboxGroup(group);
            
            if (box.getState()) {
                if (group.getCurrent() == null)
                    group.setCurrent(box);
                else
                    box.setState(false);
            }
        }
    }
    
    public void remove(Component comp) {
        if (comp instanceof Checkbox)
            ((Checkbox)comp).setCheckboxGroup(null);
        super.remove(comp);
    }
    
    public void removeAll() {
        int count = countComponents();
        for (int i = 0; i < count; i++) {
            Component comp = getComponent(i);
            if (comp instanceof Checkbox)
                ((Checkbox)comp).setCheckboxGroup(null);
        }
        
        super.removeAll();
    }
}
