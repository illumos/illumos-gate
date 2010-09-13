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
 * @(#) PanelShadow.java 1.15 - last change made 07/28/97
 */

package sunsoft.jws.visual.rt.shadow.java.awt;

import sunsoft.jws.visual.rt.awt.GBConstraints;
import java.awt.Panel;
import java.awt.FlowLayout;
import sunsoft.jws.visual.rt.base.Global;

/* BEGIN JSTYLED */
/**
 * Wraps an AWT widget.  The attributes available for this
 * class are listed below.  In the type column, type names beginning
 * with "sunsoft.jws.visual.rt" have been abbreviated to begin with "rt".
 *
 * <pre>
    name            type                      default value
    -----------------------------------------------------------------------
    none
 * </pre>
 *
 * Check the super class for additional attributes.
 *
 * @see Panel
 * @see sunsoft.jws.visual.rt.shadow.VJPanelShadow
 * @version 	1.15, 07/28/97
 */
/* END JSTYLED */
public class PanelShadow extends ContainerShadow {
    public PanelShadow() {
	GBConstraints c = (GBConstraints)get(/* NOI18N */"GBConstraints");
	c.fill = GBConstraints.BOTH;
	attributes.add(/* NOI18N */"GBConstraints",
		       /* NOI18N */"sunsoft.jws.visual.rt.awt.GBConstraints",
		    c);
    }

    public void createBody() {
	Panel panel = new Panel();
	panel.setLayout(new FlowLayout());
	body = panel;
    }

    protected Object getOnBody(String key) {
	return super.getOnBody(key);
    }

    protected void setOnBody(String key, Object value) {
	super.setOnBody(key, value);
    }
}
