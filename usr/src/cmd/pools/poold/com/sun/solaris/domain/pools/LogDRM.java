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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 *ident	"%Z%%M%	%I%	%E% SMI"
 *
 */

package com.sun.solaris.domain.pools;

import java.util.*;
import java.util.logging.*;

import com.sun.solaris.service.logging.Severity;
import com.sun.solaris.service.pools.*;

/**
 * The <code>LogDRM</code> class implements the Distributed Resource
 * Management (DRM) protocol as a logger.
 *
 * All actions are logged using the logging facilities offered by
 * <code>Poold</code>.
 */
class LogDRM implements DRM
{
	/**
	 * Supported protocol version.
	 */
	private final int version = 1;

	/**
	 * Location of higher level resource manager.
	 */
	private String url;

	/**
	 * Connect to a higher level partitioning agent.
	 *
	 * @param requested The requested version of the protocol.
	 * @param url The location of the agent.
	 * @throws Exception If the connect fails.
	 */
	public void connect(int requested, String url) throws Exception
	{
		if (requested > version) {
			Poold.CONF_LOG.log(Severity.NOTICE,
			    "Requested protocol version (" + requested +
			    ") not supported");
			return;
		}
		this.url = url;
		Poold.CONF_LOG.log(Severity.INFO, "DRM protocol version:" +
		    version + ", server: " + url);
	}


	/**
	 * Disconnect from a higher level partitioning agent.
	 *
	 * @throws Exception If the client is not connected.
	 */
	public void disconnect() throws Exception
	{
		Poold.CONF_LOG.log(Severity.INFO, "Disconnected from " + url);
	}


	/**
	 * Request resources via a higher level partitioning agent.
	 *
	 * TODO: Define request parameters.
	 *
	 * @throws Exception If the request fails.
	 */
	public void request() throws Exception
	{
		Poold.MON_LOG.log(Severity.INFO, "Requesting additional " +
		    "resources ");
	}


	/**
	 * Offer resources via a higher level partitioning agent.
	 *
	 * TODO: Define offer parameters.
	 *
	 * @throws Exception If the offer fails.
	 */
	public void offer() throws Exception
	{
		Poold.MON_LOG.log(Severity.INFO, "Requesting additional " +
		    "resources ");
	}

	/**
	 * Canel a previous offer or request.
	 *
	 * TODO: Define cancel parameters.
	 *
	 * @throws Exception If the cancel fails.
	 */
	public void cancel() throws Exception
	{
		Poold.MON_LOG.log(Severity.INFO, "Requesting additional " +
		    "resources ");
	}
}
