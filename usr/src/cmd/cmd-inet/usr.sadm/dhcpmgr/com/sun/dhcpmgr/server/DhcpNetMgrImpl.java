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

import java.net.InetAddress;
import java.net.UnknownHostException;

/**
 * This class provides the functionality to manage the DHCP network tables and
 * the hosts table.
 */
public class DhcpNetMgrImpl implements DhcpNetMgr {
    private Bridge bridge;

    public DhcpNetMgrImpl(Bridge bridge) {
	this.bridge = bridge;
    }

    /**
     * Return the Network corresponding to the network string
     * @return a Network
     */
    public Network getNetwork(String network)
	throws BridgeException {

	return bridge.getNetwork(network);
    }

    /**
     * Return the list of networks currently known to DHCP
     * @return an array of Networks
     */
    public Network [] getNetworks() throws BridgeException {
	return getNetworks(null);
    }

    public Network [] getNetworks(DhcpDatastore datastore)
	throws BridgeException {
	return bridge.getNetworks(datastore);
    }

    /**
     * Return the list of addresses managed by DHCP on a given network
     * @param network the dotted-decimal representation of the network address
     * @return an array of records for the addresses defined on that network
     */
    public DhcpClientRecord [] loadNetwork(String network)
	throws BridgeException {
	return loadNetwork(network, null);
    }

    /**
     * Return the list of addresses managed by DHCP on a given network
     * @param network the dotted-decimal representation of the network address
     * @param datastore user-supplied datastore attributes
     * @return an array of records for the addresses defined on that network
     */
    public DhcpClientRecord [] loadNetwork(String network,
	DhcpDatastore datastore) throws BridgeException {
	return bridge.loadNetwork(network, datastore);
    }

    /**
     * Return the list of addresses managed by DHCP on a given network, with
     * the hostnames for each client looked up, too.
     * @param network the dotted-decimal representation of the network address
     * @return an array of records for the addresses defined on that network
     */
    public DhcpClientRecord [] loadNetworkCompletely(String network)
	    throws BridgeException {
	DhcpClientRecord [] clients = loadNetwork(network);
	// Force loading of client name for each client
	for (int i = 0; i < clients.length; ++i) {
	    clients[i].getClientName();
	}
	return clients;
    }

    /**
     * Modify an existing client record, and update the associated hosts
     * record if needed.
     * @param oldClient the existing record
     * @param newClient the new record
     * @param table the network on which the record is defined
     */
    public void modifyClient(DhcpClientRecord oldClient,
	DhcpClientRecord newClient, String table) throws BridgeException {

	modifyClient(oldClient, newClient, table, null);
    }

    /**
     * Modify an existing client record, and update the associated hosts
     * record if needed.
     * @param oldClient	the existing record
     * @param newClient	the new record
     * @param table the network on which the record is defined
     * @param datastore user-supplied datastore attributes
     */
    public void modifyClient(DhcpClientRecord oldClient,
	DhcpClientRecord newClient, String table, DhcpDatastore datastore)
	throws BridgeException {

	// Update the network table record
	bridge.modifyDhcpClientRecord(oldClient, newClient,
	    table, datastore);
    }

    /**
     * Create a new record in the given table, and create a hosts record.
     * @param client the client to create
     * @param table the network on which to create the client
     */
    public void addClient(DhcpClientRecord client, String table)
	throws BridgeException {

	addClient(client, table, null);
    }

    /**
     * Create a new record in the given table, and create a hosts record.
     * @param client the client to create
     * @param table the network on which to create the client
     * @param datastore user-supplied datastore attributes
     */
    public void addClient(DhcpClientRecord client, String table,
	DhcpDatastore datastore) throws BridgeException {

	// Create the record in the per-network table
	bridge.createDhcpClientRecord(client, table, datastore);

    }

    /**
     * Delete a record from the given table, and delete the associated hosts
     * record if requested.
     * @param client the client to delete
     * @param table the network to delete the client from
     */
    public void deleteClient(DhcpClientRecord client, String table)
        throws BridgeException {

		deleteClient(client, table, null);
	}

    /**
     * Delete a record from the given table, and delete the associated hosts
     * record if requested.
     * @param client the client to delete
     * @param table the network to delete the client from
     * @param datastore user-supplied datastore attributes
     */
    public void deleteClient(DhcpClientRecord client, String table,
	DhcpDatastore datastore)
	throws BridgeException {

	// Delete the client record from the per-network table
	bridge.deleteDhcpClientRecord(client, table, datastore);
    }


    /**
     * Retrieve a client record from the given table.
     * @param client the client to delete
     * @param table the network to delete the client from
     * @param datastore user-supplied datastore attributes
     */
    public DhcpClientRecord getClient(DhcpClientRecord client,
	String table, DhcpDatastore datastore) throws BridgeException {

	// Retrieve the client record from the per-network table
	DhcpClientRecord clientRecord =
	    bridge.getDhcpClientRecord(client, table, datastore);

	return clientRecord;
    }

    /**
     * Create a new per-network table for the given network by converting the
     * one from the server's data store into a new data store.
     * @param network the network number in dotted-decimal form.
     * @param datastore user-supplied datastore attributes
     */
    public void cvtNetwork(String network,
	DhcpDatastore datastore) throws BridgeException {
	bridge.cvtNetwork(network, datastore);
    }

    /**
     * Create a new per-network table for the given network.
     * @param network the network number in dotted-decimal form.
     */
    public void createNetwork(String network)
	throws BridgeException {

	createNetwork(network, null);
    }

    /**
     * Create a new per-network table for the given network.
     * @param network the network number in dotted-decimal form.
     * @param datastore user-supplied datastore attributes
     */
    public void createNetwork(String network,
	DhcpDatastore datastore) throws BridgeException {
	bridge.createDhcpNetwork(network, datastore);
    }

    /**
     * Delete a per-network table, the macro associated with the network number,
     * and optionally deleting the associated hosts records.
     * @param network the network number in dotted-decimal form.
     * @param deleteMacro true if the network macro should be deleted
     */
    public void deleteNetwork(String network, boolean deleteMacro)
        throws BridgeException {
	deleteNetwork(network, deleteMacro, null);
    }

    /**
     * Delete a per-network table, the macro associated with the network number,
     * and optionally deleting the associated hosts records.
     * @param network the network number in dotted-decimal form.
     * @param deleteMacro true if the network macro should be deleted
     * @param datastore user-supplied datastore attributes
     */
    public void deleteNetwork(String network, boolean deleteMacro,
	DhcpDatastore datastore)
	throws BridgeException {

	// Delete network table, then the macro for the network
	bridge.deleteDhcpNetwork(network, datastore);
	try {
	    if (deleteMacro) {
		bridge.deleteDhcptabRecord(new Macro(network),
		    datastore);
	    }
	} catch (Throwable e) {
	    // All the errors here are ignorable
	}
    }
}
