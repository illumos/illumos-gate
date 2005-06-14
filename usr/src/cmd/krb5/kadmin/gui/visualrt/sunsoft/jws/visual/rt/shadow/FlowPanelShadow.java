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
 * @(#) FlowPanelShadow.java 1.21 - last change made 07/29/97
 */

package sunsoft.jws.visual.rt.shadow;

import sunsoft.jws.visual.rt.awt.*;
import sunsoft.jws.visual.rt.base.*;
import sunsoft.jws.visual.rt.shadow.java.awt.*;
import sunsoft.jws.visual.rt.type.AlignmentEnum;
import sunsoft.jws.visual.rt.base.Global;

import java.awt.*;
import java.util.*;

/**
 * Wraps an AWT widget.  The attributes available for this
 * class are listed below.  In the type column, type names beginning
 * with "sunsoft.jws.visual.rt" have been abbreviated to begin with
 * "rt".
 *
 * < pre>
name            type                      default value
-----------------------------------------------------------------------
alignment       rt.type.AlignmentEnum     left
hgap            java.lang.Integer         5
items           [Lrt.shadow.GBPanelShadow initial label
vgap            java.lang.Integer         5
*  < /pre>
* alignment: left, center, or right; determines how each row will be
* aligned if it doesn't require all of the horizontal space
* available.
*  < p>
* Check the super class for additional attributes.
*
* @see FlowLayout
* @version 1.21, 07/29/97
*/
public class FlowPanelShadow extends VJPanelShadow {
    
    private GBPanelShadow items[];
    
    public FlowPanelShadow() {
        GBConstraints c =
	    (GBConstraints)get(/* NOI18N */"GBConstraints");
        c.fill = GBConstraints.BOTH;
        c.shrinkx = true;
        c.shrinky = false;
        attributes.add(/* NOI18N */"GBConstraints",
	       /* NOI18N */"sunsoft.jws.visual.rt.awt.GBConstraints", c);
        
        attributes.add(/* NOI18N */"items",
	       /* NOI18N */"[Lsunsoft.jws.visual.rt.shadow.GBPanelShadow;",
		       null, DEFAULT | TRANSIENT);
        attributes.add(/* NOI18N */"alignment",
		       /* NOI18N */"sunsoft.jws.visual.rt.type.AlignmentEnum",
		       new AlignmentEnum(VJFlowLayout.LEFT), 0);
        attributes.add(/* NOI18N */"hgap",
		       /* NOI18N */"java.lang.Integer", new Integer(5), 0);
        attributes.add(/* NOI18N */"vgap",
		       /* NOI18N */"java.lang.Integer", new Integer(5), 0);
    }
    
    protected Object getOnBody(String key) {
        Panel panel = (Panel)body;
        VJFlowLayout flow = (VJFlowLayout)panel.getLayout();
        
        if (key.equals(/* NOI18N */"items")) {
            return getItems();
        } else if (key.equals(/* NOI18N */"alignment")) {
            return new AlignmentEnum(flow.getAlignment());
        } else if (key.equals(/* NOI18N */"hgap")) {
            return new Integer(flow.getHGap());
        } else if (key.equals(/* NOI18N */"vgap")) {
            return new Integer(flow.getVGap());
        } else {
            return super.getOnBody(key);
        }
    }
    
    protected void setOnBody(String key, Object value) {
        Panel panel = (Panel)body;
        Component parent = panel.getParent();
        VJFlowLayout flow = (VJFlowLayout)panel.getLayout();
        
        if (key.equals(/* NOI18N */"items")) {
            setItems((GBPanelShadow[])value);
        } else if (key.equals(/* NOI18N */"alignment")) {
            flow.setAlignment(((AlignmentEnum)value).intValue());
        } else if (key.equals(/* NOI18N */"hgap")) {
            flow.setHGap(((Integer)value).intValue());
        } else if (key.equals(/* NOI18N */"vgap")) {
            flow.setVGap(((Integer)value).intValue());
        } else {
            super.setOnBody(key, value);
        }
    }
    
    public void add(AttributeManager child) {
        super.add(child);
        items = null;
    }
    
    public void remove(AttributeManager child) {
        super.remove(child);
        items = null;
    }
    
    private synchronized GBPanelShadow[] getItems() {
        if (items == null) {
            int i = 0;
            Enumeration e = getChildList();
            while (e.hasMoreElements()) {
                if (e.nextElement() instanceof GBPanelShadow)
                    i++;
            }
            
            items = new GBPanelShadow[i];
            
            i = 0;
            e = getChildList();
            while (e.hasMoreElements()) {
                ComponentShadow s = (ComponentShadow)e.nextElement();
                if (s instanceof GBPanelShadow)
                    items[i++] = (GBPanelShadow)s;
            }
        }
        
        return items;
    }
    
    private void setItems(GBPanelShadow items[]) {
        Enumeration e = getChildList();
        while (e.hasMoreElements()) {
            ComponentShadow s = (ComponentShadow)e.nextElement();
            remove(s);
            
            // Destroy items that are no longer used
            if (items == null) {
                s.destroy();
            } else {
                int i;
                for (i = 0; i < items.length; i++) {
                    if (items[i] == s)
                        break;
                }
                if (i == items.length)
                    s.destroy();
            }
        }
        
        if (items == null || items.length == 0) {
            addLabel();
        } else {
            for (int i = 0; i < items.length; i++) {
                add(items[i]);
                
                // Make sure the item is created
                items[i].create();
            }
        }
        
        this.items = items;
    }
    
    public void createBody() {
        Panel panel = new VJPanel();
        panel.setLayout(new VJFlowLayout());
        body = panel;
    }
    
    protected void postCreate() {
        super.postCreate();
        
        if (getChildCount() == 0)
            addLabel();
    }
    
    private void addLabel() {
        LabelShadow s = new LabelShadow();
        s.set(/* NOI18N */"layoutName", /* NOI18N */"");
        s.set(/* NOI18N */"text",
	      /* JSTYLED */
	      Global.getMsg("sunsoft.jws.visual.rt.shadow.FlowPanelShadow.DefaultText"));
        add(s);
        s.create();
        s.show();
    }
}
