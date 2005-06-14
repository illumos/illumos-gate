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

import java.io.IOException;
import java.io.OptionalDataException;

import com.sun.dhcpmgr.data.*;
import com.sun.dhcpmgr.bridge.*;

public interface DhcpMgr {
    public DhcpNetMgr getNetMgr();
    public DhcptabMgr getDhcptabMgr();
    public DhcpServiceMgr getDhcpServiceMgr();
    public String getLockPath();
    public Object openExportFile(String name, String user, int recCount,
	Network [] nets, boolean overWrite)
	throws ExistsException, IOException;
    public Object openImportFile(String name)
	throws IOException;
    public ExportHeader getExportHeader(Object ref)
	throws IOException, ClassNotFoundException;
    public void exportMacros(Object ref, boolean allMacros, String [] names)
	throws BridgeException, IOException;
    public void exportOptions(Object ref, boolean allOptions, String [] names)
	throws BridgeException, IOException;
    public void exportNetwork(Object ref, Network net)
	throws BridgeException, IOException;
    public ActionError [] importOptions(Object ref, boolean overwrite)
	throws IOException, OptionalDataException, ClassNotFoundException;
    public ActionError [] importMacros(Object ref, boolean overwrite)
	throws IOException, OptionalDataException, ClassNotFoundException;
    public ActionError [] importNetwork(Network net, Object ref,
	boolean overwrite)
	throws IOException, OptionalDataException, ClassNotFoundException,
    	BridgeException;
    public void closeExportFile(Object ref, boolean deleteFile)
	throws IOException;
    public void closeImportFile(Object ref, boolean deleteFile)
	throws IOException;
}
