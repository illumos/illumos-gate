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
 * Copyright (c) 1998-2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */
package com.sun.dhcpmgr.server;

import com.sun.dhcpmgr.bridge.*;
import com.sun.dhcpmgr.data.*;

/**
 * This class defines the methods available to manage the DHCP network
 * tables and hosts table.
 */
public interface DhcpNetMgr {
    public Network getNetwork(String networkName)
	throws BridgeException;
    public Network [] getNetworks(DhcpDatastore datastore)
	throws BridgeException;
    public Network [] getNetworks()
	throws BridgeException;
    public DhcpClientRecord [] loadNetwork(String network,
	DhcpDatastore datastore) throws BridgeException;
    public DhcpClientRecord [] loadNetwork(String network)
	throws BridgeException;
    public DhcpClientRecord [] loadNetworkCompletely(String network)
	throws BridgeException;
    public void modifyClient(DhcpClientRecord oldClient,
	DhcpClientRecord newClient, String table)
	throws BridgeException;
    public void modifyClient(DhcpClientRecord oldClient,
	DhcpClientRecord newClient, String table,
	DhcpDatastore datastore) throws BridgeException;
    public void addClient(DhcpClientRecord client, String table,
	DhcpDatastore datastore) throws BridgeException;
    public void addClient(DhcpClientRecord client, String table)
	throws BridgeException;
    public void deleteClient(DhcpClientRecord client, String table,
	DhcpDatastore datastore)
	throws BridgeException;
    public void deleteClient(DhcpClientRecord client, String table)
        throws BridgeException;
    public DhcpClientRecord getClient(DhcpClientRecord client, String table,
	DhcpDatastore datastore) throws BridgeException;
    public void cvtNetwork(String network,
	DhcpDatastore datastore) throws BridgeException;
    public void createNetwork(String network,
	DhcpDatastore datastore) throws BridgeException;
    public void createNetwork(String network)
	throws BridgeException;
    public void deleteNetwork(String network, boolean deleteMacro,
	DhcpDatastore datastore)
	throws BridgeException;
    public void deleteNetwork(String network, boolean deleteMacro)
        throws BridgeException;
}
