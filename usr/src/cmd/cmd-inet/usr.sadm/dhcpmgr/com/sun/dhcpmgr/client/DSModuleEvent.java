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
 * Copyright (c) 2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */
package com.sun.dhcpmgr.client;

import java.util.*;

/**
 * This class defines a DSModule event. These events are the means by which
 * a DSModule communicates with the DHCP configuration wizard.
 */
public class DSModuleEvent extends EventObject {

    /**
     * Signifies that the DSModule configuration data is valid.
     */
    public static final int DATA_VALID = 0;

    /**
     * Signifies that the DSModule configuration data is not valid.
     */
    public static final int DATA_INVALID = 1;

    /**
     * Set to DATA_VALID or DATA_INVALID.
     */
    private int state;

    /**
     * Constructs a DSModuleEvent from a source and state.
     * @param source module that is source of the event.
     * @param state DATA_VALID or DATA_INVALID.
     */
    public DSModuleEvent(Object source, int state) {
	super(source);
	this.state = state;
    } // constructor

    /**
     * Returns the state of the event.
     * @return the state of the event.
     */
    public int getState() {
	return state;
    }// getState

} // DSModuleEvent
