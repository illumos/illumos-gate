/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
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
 * Copyright (c) 2001 by Sun Microsystems, Inc.
 * All rights reserved.
 *
 * SystemDataModel.java
 */


package com.sun.wbem.solarisprovider.srm;

import javax.wbem.cim.*;

import java.util.*;

/**
 * The global system properties, osname and csname, are handled by this
 * class. The data fields are defined as static in the superclass, since they
 * should be accessible by all provider data models.
 * @author Sun Microsystems, Inc.
 */
public class SystemDataModel extends SRMProviderDataModel
	implements SRMProviderProperties {

    protected void setCIMInstance(boolean newInstance) {
	return;
    }

    protected void setOpPropertiesVector() {
	return;
    }

    protected void initKeyValTable() {
    	return;
    }

    void setProperty(String key, String val) {

	PropertyAccessInterface ac;

	if (!key.equals(CSNAME_KEY)) {
	    csName = val;
	} else if (!key.equals(OSNAME_KEY)) {
	    osName = val;
	}
    }

} // end class SystemDataModel
