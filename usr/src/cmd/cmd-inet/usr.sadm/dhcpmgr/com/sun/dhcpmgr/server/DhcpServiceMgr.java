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

import java.util.*;
import java.net.InetAddress;

import com.sun.dhcpmgr.bridge.*;
import com.sun.dhcpmgr.data.*;

/**
 * This interface defines the methods available for managing the basic
 * service parameters which are not stored in the dhcptab or network tables.
 */
public interface DhcpServiceMgr {
    public String getServerName();
    public String getShortServerName();
    public InetAddress getServerAddress();
    public void makeLocation(DhcpDatastore datastore)
	throws BridgeException;
    public DhcpDatastore getDataStore(String resource) throws BridgeException;
    public DhcpDatastore [] getDataStores() throws BridgeException;
    public Option [] getInittabOptions(byte context) throws BridgeException;
    public String getDataStoreClassname(String dataStoreName)
	throws BridgeException;
    public DhcpdOptions readDefaults() throws BridgeException;
    public void writeDefaults(DhcpdOptions defs) throws BridgeException;
    public void removeDefaults() throws BridgeException;
    public void startup() throws BridgeException;
    public void shutdown() throws BridgeException;
    public void reload() throws BridgeException;
    public IPInterface [] getInterfaces() throws BridgeException;
    public String [] getArguments(String line) throws BridgeException;
    public String getStringOption(String optionName, String arg)
	throws BridgeException;
    public IPAddress [] getIPOption(String optionName, String arg)
	throws BridgeException;
    public long [] getNumberOption(String optionName, String arg)
	throws BridgeException;
    public boolean isServerRunning() throws BridgeException;
    public boolean isVersionCurrent() throws BridgeException;
}
