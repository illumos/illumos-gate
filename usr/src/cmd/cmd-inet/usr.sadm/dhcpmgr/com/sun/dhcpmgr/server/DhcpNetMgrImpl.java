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
 * Copyright (c) 1998-2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */
package com.sun.dhcpmgr.server;

import com.sun.dhcpmgr.bridge.*;
import com.sun.dhcpmgr.data.*;

import com.sun.wbem.utility.directorytable.*;

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

	boolean nameChanged = !oldClient.getClientName().equals(
	    newClient.getClientName());
	boolean commentChanged = !oldClient.getComment().equals(
	    newClient.getComment());
	/*
	 * If the name changed, need to update hosts.  If comment changed,
	 * hosts is only updated if there was already a hosts record.
	 */
	if (nameChanged) {
	    /*
	     * If new name is empty, delete the hosts entry.  Otherwise
	     * try to modify it.
	     */
	    if (newClient.getClientName().length() == 0) {
		try {
		    deleteHostsRecord(newClient.getClientIPAddress());
		} catch (Throwable e) {
		    throw new NoHostsEntryException(
			newClient.getClientIPAddress());
		}
	    } else {
		try {
		    modifyHostsRecord(oldClient.getClientIPAddress(),
			newClient.getClientIPAddress(),
			newClient.getClientName(), newClient.getComment());
		} catch (NoHostsEntryException e) {
		    // Must not be one, so create it instead
		    createHostsRecord(newClient.getClientIPAddress(),
		   	newClient.getClientName(), newClient.getComment());
		}
	    }
	} else if (commentChanged) {
	    // Try to modify, but toss all exceptions as this isn't a big deal
	    try {
		modifyHostsRecord(oldClient.getClientIPAddress(),
		    newClient.getClientIPAddress(), newClient.getClientName(),
		    newClient.getComment());
	    } catch (Throwable e) {
		// Ignore
	    }
	}

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

	/*
	 * If a name was supplied and we can't resolve it to this address,
	 * create a hosts record.
	 */
	if (client.getClientName().length() != 0
	    && !client.getClientName().equals(client.getClientIPAddress())) {
	    createHostsRecord(client.getClientIPAddress(),
		client.getClientName(), client.getComment());
	}

	// Create the record in the per-network table
	bridge.createDhcpClientRecord(client, table, datastore);

    }
    
    /**
     * Delete a record from the given table, and delete the associated hosts
     * record if requested.
     * @param client the client to delete
     * @param table the network to delete the client from
     * @param deleteHosts true if the hosts record should be removed as well
     */
    public void deleteClient(DhcpClientRecord client, String table,
	boolean deleteHosts) throws BridgeException {

		deleteClient(client, table, deleteHosts, null);
	}

    /**
     * Delete a record from the given table, and delete the associated hosts
     * record if requested.
     * @param client the client to delete
     * @param table the network to delete the client from
     * @param deleteHosts true if the hosts record should be removed as well
     * @param datastore user-supplied datastore attributes
     */
    public void deleteClient(DhcpClientRecord client, String table,
	boolean deleteHosts, DhcpDatastore datastore)
	throws BridgeException {

	// Delete the client record from the per-network table
	bridge.deleteDhcpClientRecord(client, table, datastore);

	// Delete hosts if requested
	if (deleteHosts) {
	    try {
		deleteHostsRecord(client.getClientIPAddress());
	    } catch (NoEntryException e) {
		throw new NoEntryException("hosts");
	    }
	}
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
     * @param deleteHosts true if the associated hosts records should be deleted
     */
    public void deleteNetwork(String network, boolean deleteMacro,
	boolean deleteHosts) throws BridgeException {
	deleteNetwork(network, deleteMacro, deleteHosts, null);
    }

    /**
     * Delete a per-network table, the macro associated with the network number,
     * and optionally deleting the associated hosts records.
     * @param network the network number in dotted-decimal form.
     * @param deleteMacro true if the network macro should be deleted
     * @param deleteHosts true if the associated hosts records should be deleted
     * @param datastore user-supplied datastore attributes
     */
    public void deleteNetwork(String network, boolean deleteMacro,
	boolean deleteHosts, DhcpDatastore datastore)
	throws BridgeException {

	// If we're supposed to clean up hosts, do so
	if (deleteHosts) {
	    DhcpClientRecord [] recs =
		bridge.loadNetwork(network, datastore);
	    if (recs != null) {
		for (int i = 0; i < recs.length; ++i) {
		    try {
			deleteHostsRecord(recs[i].getClientIPAddress());
		    } catch (Throwable e) {
			// Ignore errors here; they're not important
		    }
		}
	    }
	}

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

    /**
     * Add a record to the hosts table.
     * @param addr address of entry to add to the hosts table
     * @param name alias for the entry
     * @param comment comment for the entry
     */
    private void createHostsRecord(String addr, String name,
	String comment)	throws BridgeException {

	DhcpHostsTable hostsTable = null;
	try {
	    hostsTable = DhcpHostsTable.getCfgHostsTable(bridge);
	    if (hostsTable != null) {
		hostsTable.openTable();
		hostsTable.createHostsRecord(addr, name, comment);
	    }
	} finally {
	    if (hostsTable != null) {
		hostsTable.closeTable();
	    }
	}

    } // createHostsRecord

    /**
     * Delete a record from the hosts table.
     * @param addr address of entry to remove from the hosts table
     */
    private void deleteHostsRecord(String addr)
	throws BridgeException {

	DhcpHostsTable hostsTable = null;
	try {
	    hostsTable = DhcpHostsTable.getCfgHostsTable(bridge);
	    if (hostsTable != null) {
		hostsTable.openTable();
		hostsTable.deleteHostsRecord(addr);
	    }
	} finally {
	    if (hostsTable != null) {
		hostsTable.closeTable();
	    }
	}

    } // deleteHostsRecord

    /**
     * Modify a record in the hosts table.
     * @param oldAddr address of entry to modify in the hosts table
     * @param newAddr new address of entry
     * @param name alias for the entry
     * @param comment comment for the entry
     */
    private void modifyHostsRecord(String oldAddr,
	String newAddr, String name, String comment) throws BridgeException {

	DhcpHostsTable hostsTable = null;
	try {
	    hostsTable = DhcpHostsTable.getCfgHostsTable(bridge);
	    if (hostsTable != null) {
		hostsTable.openTable();
		hostsTable.modifyHostsRecord(oldAddr, newAddr, name, comment);
	    }
	} finally {
	    if (hostsTable != null) {
		hostsTable.closeTable();
	    }
	}

    } // modifyHostsRecord
}
