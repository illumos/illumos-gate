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
 * @(#) CheckboxList.java 1.7 - last change made 07/25/97
 */

package sunsoft.jws.visual.rt.awt;

import sunsoft.jws.visual.rt.awt.*;
import java.awt.*;
import java.util.Vector;

public class CheckboxList extends ScrollPanel {
    private CheckboxView view;
    
    public CheckboxList() {
        view = new CheckboxView();
        add(view);
        
        Vector items = view.items;
        for (int i = 0; i < 100; i++)
            items.addElement(/* NOI18N */"item" + i);
        
        view.updateCheckboxes();
    }
}

class CheckboxView extends Panel implements Scrollable {
    Vector items;
    
    private int curx, cury;
    private GBLayout gridbag;
    private Panel panel;
    
    public CheckboxView() {
        items = new Vector();
        
        setLayout(null);
        gridbag = new GBLayout();
        
        panel = new Panel();
        panel.setLayout(gridbag);
        
        add(panel);
    }
    
    public void updateCheckboxes() {
        panel.removeAll();
        GBConstraints c = new GBConstraints();
        
        c.gridx = 0;
        c.gridy = 0;
        c.fill = GBConstraints.BOTH;
        
        int size = items.size();
        for (int i = 0; i < items.size(); i++) {
            Checkbox box = new Checkbox((String)items.elementAt(i));
            gridbag.setConstraints(panel.add(box), c);
            
            c.gridx++;
            if (c.gridx == 3) {
                c.gridx = 0;
                c.gridy++;
            }
        }
        
        if (panel.getPeer() != null) {
            Dimension d = panel.minimumSize();
            panel.reshape(0, 0, d.width, d.height);
        }
    }
    
    public void addNotify() {
        super.addNotify();
        Dimension d = panel.minimumSize();
        panel.reshape(0, 0, d.width, d.height);
    }
    
    public Dimension minimumSize() {
        return new Dimension(150, 300);
    }
    
    public Dimension preferredSize() {
        return minimumSize();
    }
    
    public void scrollX(int x) {
        curx = -x;
        panel.move(curx, cury);
    }
    
    public void scrollY(int y) {
        cury = -y;
        panel.move(curx, cury);
    }
    
    public Dimension scrollSize() {
        return panel.minimumSize();
    }
    
    public Dimension viewSize(Dimension size) {
        return size;
    }
    
    public int lineHeight() {
        if (panel.countComponents() == 0)
            return 1;
        
        Component comp = panel.getComponent(0);
        Dimension min = comp.minimumSize();
        return min.height;
    }
}
