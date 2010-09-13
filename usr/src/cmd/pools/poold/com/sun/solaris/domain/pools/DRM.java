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

/**
 * The <code>DRM</code> interface specifies the contract between
 * poold and higher level partitioning agents.
 *
 * <code>Poold</code> is designed to operate indepedently or as a
 * member of a hierarchy of co-operating resource managers. In order
 * to promote interaction and minimise implementation dependencies,
 * the use of a common protocol which may be implemented in multiple
 * languages is advocated. The protocol is provisionally named the
 * "Distributed Resource Management" (DRM) protocol.
 *
 * This interface specifies how an implementation of the protocol
 * would be implemented in Java.
 *
 * @see LogDRM
 */

interface DRM {
	/**
	 * Connect to a higher level partitioning agent.
	 *
	 * @param version The version of the protocol.
	 * @param url The location of the agent.
	 * @throws Exception If the connect fails.
	 */
	public void connect(int version, String url) throws Exception;

	/**
	 * Disconnect from a higher level partitioning agent.
	 *
	 * @throws Exception If the client is not connected.
	 */
	public void disconnect() throws Exception;

	/**
	 * Request resources via a higher level partitioning agent.
	 *
	 * @throws Exception If the request fails.
	 */
	public void request() throws Exception;

	/**
	 * Offer resources via a higher level partitioning agent.
	 *
	 * @throws Exception If the offer fails.
	 */
	public void offer() throws Exception;

	/**
	 * Cancel a previous offer or request.
	 *
	 * @throws Exception If the cancel fails.
	 */
	public void cancel() throws Exception;
}
