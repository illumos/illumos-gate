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
 * @(#) VJErrorDialog.java 1.4 - last change made 07/25/97
 */

package sunsoft.jws.visual.rt.awt;

import sunsoft.jws.visual.rt.base.Global;
import java.awt.*;

public class VJErrorDialog extends RootDialog {
    
    private MultiLineLabel errorLabel;
    private VJButton okButton;
    
    public VJErrorDialog(Frame frame, boolean modal) {
        super(frame, modal);
        init();
    }
    
    public VJErrorDialog(Frame frame, String title, boolean modal) {
        super(frame, title, modal);
        init();
    }
    
    public void setLabel(String label) {
        errorLabel.setLabel(label);
    }
    
    public String getLabel() {
        return errorLabel.getLabel();
    }
    
    private void init() {
        GBLayout gb = new GBLayout();
        GBConstraints c = new GBConstraints();
        setLayout(gb);
        
        c.weightx = 1;
        c.weighty = 1;
        c.gridwidth = 0;
        
        errorLabel = new MultiLineLabel();
        c.fill = GBConstraints.BOTH;
        c.insets = new Insets(2, 2, 2, 2);
        gb.setConstraints(add(errorLabel), c);
        
        c.weightx = 0;
        c.weighty = 0;
        c.fill = GBConstraints.HORIZONTAL;
        c.insets = new Insets(0, 0, 0, 0);
        gb.setConstraints(add(new LabelBar()), c);
        
        okButton = new VJButton(Global.getMsg(
		"sunsoft.jws.visual.rt.awt.VJErrorDialog.OK"));
        c.fill = GBConstraints.NONE;
        c.insets = new Insets(2, 2, 2, 2);
        gb.setConstraints(add(okButton), c);
    }
    
    public boolean action(Event evt, Object what) {
        if (evt.target == okButton) {
            hide();
            return true;
        }
        
        return false;
    }
}
