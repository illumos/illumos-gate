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
 * Copyright (c) 1998-1999 by Sun Microsystems, Inc.
 * All rights reserved.
 */
package com.sun.dhcpmgr.ui;

import java.awt.Component;

/**
 * The interface implemented by a step in a wizard.
 *
 * @see	Wizard
 */
public interface WizardStep {
    /**
     * Constant for traversing forward.
     */
    public static final int FORWARD = 1;
    /**
     * Constant for traversing backward.
     */
    public static final int BACKWARD = -1;
    /**
     * Returns the descriptive text which will be displayed for this step in the
     * contents pane (i.e. the left side of the wizard).  The description must
     * be unique for each step used in a wizard.
     * @return a <code>String</code> describing the step
     */
    public String getDescription();
    /**
     * Returns the component to be displayed when the step is active.  Usually
     * this will be some form of a panel.  This is displayed in the right half
     * of the wizard's display area.
     * @return a <code>Component</code> to display
     */
    public Component getComponent();
    /**
     * Called when the step transitions from the inactive to active state.
     * Use the direction to determine which direction user is traversing to
     * possibly differentiate the initialization actions needed.
     * @param direction either <code>FORWARD</code> or <code>BACKWARD</code> to
     *			indicate direction of traversal.
     */ 
    public void setActive(int direction);
    /**
     * Called when the step transitions from the active to inactive state.
     * Use the direction to determine which direction user is traversing to 
     * differentiate the input processing needed.  Return false if there is a
     * problem the user needs to correct before being allowed to proceed to the
     * next step.
     * @param direction either <code>FORWARD</code> or <code>BACKWARD</code> to
     *			indicate direction of traversal.
     * @return	<code>true</code> if traversal should proceed,
     * 		<code>false</code> if not.
     */
    public boolean setInactive(int direction);     
}
