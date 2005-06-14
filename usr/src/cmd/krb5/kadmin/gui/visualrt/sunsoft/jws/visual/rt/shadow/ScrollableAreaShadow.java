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
 * @(#) ScrollableAreaShadow.java 1.5 - last change made 07/25/97
 */
        
package sunsoft.jws.visual.rt.shadow;
        
import sunsoft.jws.visual.rt.awt.ScrollableArea;
import sunsoft.jws.visual.rt.shadow.java.awt.PanelShadow;
        
import java.util.Enumeration;
        
/*
 * Wraps an AWT widget.  The attributes available for this
 * class are listed below.  In the type column, type names beginning
 * with "sunsoft.jws.visual.rt" have been abbreviated to begin with "rt".
 *
 * < pre>
 *        name            type                      default value
 *    -----------------------------------------------------------------------
 *    lineHeight      java.lang.Integer         4
 *  < /pre>
 *
 * Check the super class for additional attributes.
 *
 * @see ScrollableArea
 * @see ScrollPanelShadow
 * @version 1.5, 07/25/97
 */
public class ScrollableAreaShadow extends PanelShadow {
            
	public ScrollableAreaShadow() {
                attributes.add(/* NOI18N */"lineHeight",
			    /* NOI18N */"java.lang.Integer",
			    new Integer(4), 0);
	}
            
	protected Object getOnBody(String key) {
                if (key.equals(/* NOI18N */"lineHeight"))
			return new Integer(
				((ScrollableArea)body).lineHeight());
                else
			return super.getOnBody(key);
	}
            
	protected void setOnBody(String key, Object value) {
                if (key.equals(/* NOI18N */"lineHeight"))
			((ScrollableArea)body).setLineHeight(
				((Integer)value).intValue());
                else
			super.setOnBody(key, value);
	}
            
	public void create() {
                // Add a GBPanelShadow child if there isn't one already.
                if (inDesignerRoot()) {
			boolean found = false;
                    
			Enumeration e = getChildList();
			while (e.hasMoreElements()) {
				if (e.nextElement() instanceof GBPanelShadow)
					found = true;
			}
                    
			if (!found) {
				GBPanelShadow s = new GBPanelShadow();
				int w[] = {14, 14};
				s.set(/* NOI18N */"columnWidths", w);
				int h[] = {14, 14};
				s.set(/* NOI18N */"rowHeights", h);
				add(s);
			}
                }
                
                super.create();
	}
            
	public void createBody() {
                body = new ScrollableArea();
	}
}
