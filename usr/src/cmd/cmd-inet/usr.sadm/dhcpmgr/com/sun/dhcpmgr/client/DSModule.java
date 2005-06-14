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

import java.awt.*;
import java.util.*;
import javax.swing.event.EventListenerList;

/**
 * This class provides a skeletal implementation of the data store module
 * management interface to minimize the effort required to implement a
 * data store management class.
 */
public abstract class DSModule {

    /**
     * Listeners registered with the DSModule.
     */
    private EventListenerList DSMListeners = new EventListenerList();

    /**
     * Attribute that signifies whether or not the data store  has been
     * configured well enough to allow the data store to be managed.
     */
    private boolean forwardEnabled = false;

    /**
     * Returns the path that is used by the data store (i.e., the PATH value
     * in the DHCP config file).
     * @return the path that is used by the data store (i.e., the PATH value
     * in the DHCP config file) or null if not set.
     */
    public abstract String getPath();

    /**
     * Returns additional datastore specific information (i.e., the
     * RESOURCE_CONFIG value in the DHCP config file).
     * @return additional datastore specific information (i.e., the
     * RESOURCE_CONFIG value in the DHCP config file) or null if not set.
     */
    public abstract String getAdditionalInfo();

    /**
     * Returns the description that will be used by the DHCP configuration
     * wizard when adding the data store to the list of data store radio
     * buttons.
     * @return the description that will be used by the DHCP configuration
     * wizard when adding the data store to the list of data store radio
     * buttons.
     */
    public abstract String getDescription();

    /**
     * Returns the component that will be used by the DHCP configuration
     * wizard to manage obtaining the data store parameters.
     * @return the component that will be used by the DHCP configuration
     * wizard to manage obtaining the data store parameters.
     */
    public abstract Component getComponent();

    /**
     * Adds a listener to the DSModule listener list.
     * @param l the listener.
     */
    public void addDSMListener(DSModuleListener l) {
	DSMListeners.add(DSModuleListener.class, l);
    } // addDSMListener

    /**
     * Removes a listener from the DSModule listener list.
     * @param l the listener.
     */
    public void removeDSMListener(DSModuleListener l) {
	DSMListeners.remove(DSModuleListener.class, l);
    } // removeDSMListener

    /**
     * Fires a DSModuleEvent to all DSModule listeners on the listener list.
     * @param e the DSModuleEvent to be fired.
     */
    private void fireDSMEvent(DSModuleEvent e) {
	// Guaranteed to return a non-null array
	Object[] listeners = DSMListeners.getListenerList();

	// Process the listeners last to first, notifying
	// those that are interested in this event
	for (int i = listeners.length - 2; i >= 0; i -= 2) {
	    if (listeners[i] == DSModuleListener.class) {
		((DSModuleListener)listeners[i + 1]).stateChanged(e);
	    }              
	}
    } // fireDSMEvent

    /**
     * Returns the modules readiness state (i.e., can the DHCP config wizard
     * continue forward if the user wishes).
     * @return the modules readiness state
     */
    public final boolean getForwardEnabled() {
	return forwardEnabled;
    } // getForwardEnabled

    /**
     * Sets the forwardEnabled attribute and fires a DSModuleEvent to the DHCP
     * configuration wizard to let it know that the module's state has changed.
     * @param enable value to which forwardEnabled should be set.
     */
    public final void setForwardEnabled(boolean enable) {

	forwardEnabled = enable;

	int state = DSModuleEvent.DATA_VALID;
	if (!enable) {
	    state = DSModuleEvent.DATA_INVALID;
	}
	
	fireDSMEvent(new DSModuleEvent(this, state));
    } // setForwardEnabled

} // DSModule
