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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
package com.sun.dhcpmgr.server;

import java.util.*;
import java.net.InetAddress;

import com.sun.dhcpmgr.bridge.*;
import com.sun.dhcpmgr.data.*;

/**
 * This interface defines the methods available for managing the dhcptab.
 */
public interface DhcptabMgr {
    public Option createOption(String name, String value)
	throws BridgeException;
    public Option [] getOptions(DhcpDatastore datastore)
	throws BridgeException;
    public Option [] getOptions()
	throws BridgeException;
    public Macro [] getMacros(DhcpDatastore datastore)
	throws BridgeException;
    public Macro [] getMacros()
	throws BridgeException;
    public Macro getMacro(String key, DhcpDatastore datastore)
	throws BridgeException;
    public Macro getMacro(String key)
	throws BridgeException;
    public Option getOption(String key, DhcpDatastore datastore)
	throws BridgeException;
    public Option getOption(String key)
	throws BridgeException;
    public void createRecord(DhcptabRecord rec, boolean signalServer,
	DhcpDatastore datastore) throws BridgeException;
    public void createRecord(DhcptabRecord rec, boolean signalServer)
	throws BridgeException;
    public void modifyRecord(DhcptabRecord oldRec, DhcptabRecord newRec,
	boolean signalServer, DhcpDatastore datastore)
	throws BridgeException;
    public void modifyRecord(DhcptabRecord oldRec, DhcptabRecord newRec,
	boolean signalServer) throws BridgeException;
    public void deleteRecord(DhcptabRecord rec, boolean signalServer,
	DhcpDatastore datastore) throws BridgeException;
    public void deleteRecord(DhcptabRecord rec, boolean signalServer)
	throws BridgeException;
    public ActionError [] deleteAllMacros() throws BridgeException;
    public ActionError [] deleteAllOptions() throws BridgeException;
    public ActionError [] deleteMacros(String [] macroNames);
    public ActionError [] deleteOptions(String [] optionNames);
    public void cvtDhcptab(DhcpDatastore datastore)
	throws BridgeException;
    public void createDhcptab(DhcpDatastore datastore)
	throws BridgeException;
    public void createDhcptab()
	throws BridgeException;
    public void deleteDhcptab(DhcpDatastore datastore)
	throws BridgeException;
    public void deleteDhcptab()
	throws BridgeException;
    public void createLocaleMacro()
	throws BridgeException, ValidationException;
    public void createLocaleMacro(DhcpDatastore datastore)
	throws BridgeException, ValidationException;
    public void createServerMacro(String svrName, InetAddress svrAddress,
	int leaseLength, boolean leaseNegotiable, String dnsDomain,
	Vector dnsServs) throws BridgeException, ValidationException;
    public void createServerMacro(String svrName, InetAddress svrAddress,
	int leaseLength, boolean leaseNegotiable, String dnsDomain,
	Vector dnsServs, DhcpDatastore datastore)
	throws BridgeException, ValidationException;
    public void createNetworkMacro(Network network, IPAddress [] routers,
	boolean isLan, String nisDomain, Vector nisServs)
	throws BridgeException, ValidationException;
    public void createNetworkMacro(Network network, IPAddress [] routers,
	boolean isLan, String nisDomain, Vector nisServs,
	DhcpDatastore datastore)
	throws BridgeException, ValidationException;
}
