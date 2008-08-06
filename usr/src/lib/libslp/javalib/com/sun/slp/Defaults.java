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
 */

// Defaults.java : Defaults for SLP Locator, Advertiser and slpd.
// Author:   Erik Guttman
//

package com.sun.slp;

import java.util.*;
import java.net.*;

/**
 * This class gathers all constants used in the package into one place.
 *
 * @author James Kempf
 */

class Defaults {

    // Default header class name for server.

    static final String DEFAULT_SERVER_HEADER_CLASS =
	"com.sun.slp.SLPServerHeaderV2";

    // Default DA table implementation.

    static final String SUN_DATABLE = "com.sun.slp.SunDATable";

    // Character set.

    static final String UTF8 = "UTF8";

    // Service prefix.

    final static String SERVICE_PREFIX = "service";

    // Restricted type for DA table information.

    static final ServiceType SUN_DA_SERVICE_TYPE =
	new ServiceType("service:directory-agent.sun");

    // Restricted type for SA table information.

    static final ServiceType SUN_SA_SERVICE_TYPE =
	new ServiceType("service:service-agent.sun");

    // Directory agent URL type.

    static final ServiceType DA_SERVICE_TYPE =
	new ServiceType("service:directory-agent");

    // Service agent URL type.

    static final ServiceType SA_SERVICE_TYPE =
	new ServiceType("service:service-agent");

    // Service type attribute tag.

    static final String SERVICE_TYPE_ATTR_ID = "service-type";

    // Minimum refresh interval attribute tag.

    static final String MIN_REFRESH_INTERVAL_ATTR_ID = "min-refresh-interval";

    // These constants are involved in refreshing URLs or aging them out.

    final static long lMaxSleepTime = 64800000L;  // 18 hrs in milliseconds
    final static float fRefreshGranularity = (float)0.1;

    // Special naming authority names.

    protected static final String ALL_AUTHORITIES = "*";

    // Default scope name.

    static final String DEFAULT_SCOPE = "default";

    // Default DA attributes.

    static final Vector defaultDAAttributes = new Vector();

    // Default SA attributes.

    static final Vector defaultSAAttributes = new Vector();

    // DA attribute names.

    static final String minDALifetime = "min-lifetime";
    static final String maxDALifetime = "max-lifetime";

    // Loopback address and name.

    static final String LOOPBACK_ADDRESS = "127.0.0.1";
    static final String LOOPBACK_NAME = "localhost";

    // Solaris default config file
    static final String SOLARIS_CONF = "file:/etc/inet/slp.conf";

    static final int         version = 2;
    static final int	   iSocketQueueLength = 10;
    static final int         iMulticastRadius = 255;
    static final int         iHeartbeat = 10800;
    static final int	   iActiveDiscoveryInterval = 900;
    static final int	   iActiveDiscoveryGranularity = 900;
    static final int	   iRandomWaitBound = 1000;
    static final int         iMulticastMaxWait = 15000;
    static final int         iMaximumResults = Integer.MAX_VALUE;
    static final Locale      locale = new Locale("en", "");
    static final int         iMTU = 1400;
    static final int         iReadMaxMTU = 8192;
    static final int         iSLPPort = 427;
    static final String      sGeneralSLPMCAddress = "239.255.255.253";
    static final String      sBroadcast           = "255.255.255.255";
    static final int         iTCPTimeout          = 20000;
    static final int[]       a_iDatagramTimeout = {1000, 2000, 3000};
    static final int[]       a_iConvergeTimeout =
					{3000, 3000, 3000, 3000, 3000};
    static final int[]	   a_iDADiscoveryTimeout =
					{2000, 2000, 2000, 2000, 3000, 4000};

    static Vector restrictedTypes;

    static {

	InetAddress iaLocal = null;

	// Get local host. Note that we just use this for the scope
	//  name, so it doesn't matter if that interface isn't
	//  taking any requests.

	try {
	    iaLocal =  InetAddress.getLocalHost();

	}  catch (UnknownHostException ex) {
	    Assert.slpassert(false,
			  "resolve_failed",
			  new Object[] {"localhost"});
	}

	// Normalize the hostname into just the nodename (as
	//  opposed to the fully-qualified host name).
	String localHostName = iaLocal.getHostName();
	int dot = localHostName.indexOf('.');
	if (dot != -1) {
	    localHostName = localHostName.substring(0, dot);
	}

	// Set default DA table and SA only scopes. On Solaris,
	//  the SA only scopes consist of the local machine
	//  name, and the default DA table is SolarisDATable.
	//  If this were C, there would be an #ifdef SOLARIS
	//  around this code.

	Properties props = System.getProperties();
	props.put(DATable.SA_ONLY_SCOPES_PROP, localHostName);
	props.put(DATable.DA_TABLE_CLASS_PROP, SUN_DATABLE);
	System.setProperties(props);

	// Set up the vector of restricted types. Restricted types
	//  are only allowed to be added or deleted through the
	//  slpd process. They also have no authentication information,
	//  even if the network is authenticated. This is because
	//  slpd is running as root and so unless root is compromised
	//  the information can be trusted.

	restrictedTypes = new Vector();
	restrictedTypes.addElement(SUN_DA_SERVICE_TYPE);

    }

}
