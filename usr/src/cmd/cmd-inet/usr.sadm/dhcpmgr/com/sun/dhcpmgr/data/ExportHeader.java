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
 * Copyright 2001-2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

package com.sun.dhcpmgr.data;

import java.io.Serializable;
import java.util.Date;

/**
 * This class defines the header for the export file.
 */
public class ExportHeader implements Serializable {

    /**
     * The name of the server from which the data originated.
     */
    private String server;
    /**
     * Date of export
     */
    private Date date;
    /**
     * User who requested export
     */
    private String user;
    /**
     * Number of records in this file.
     */
    private int recCount;
    /**
     * Networks exported in this file
     */
    private Network [] networks;

    // Serialization id for this class
    static final long serialVersionUID = -3581829760827739278L;

    /**
     * Simple constructor.
     * @param server name of the server from which the server was exported
     * @param user name of the user who performed the export
     * @param recCount number of records which will be exported
     * @param networks list of networks exported
     */
    public ExportHeader(String server, String user, int recCount,
	    Network [] networks) {

	this.server = server;
	this.user = user;
	this.recCount = recCount;
	this.networks = networks;
	date = new Date();

    } // constructor

    /**
     * Get the server value.
     * @return returns the server name
     */
    public String getServer() {

	return server;

    } // getServer

    /**
     * Retrieve exporting user name
     * @return name of user
     */
    public String getUser() {
	return user;
    }

    /**
     * Retrieve date of export
     * @return date & time of export
     */
    public Date getDate() {
	return date;
    }

    /**
     * Retrieve the number of records in the file.
     * @return the number of records contained.
     */
    public int getRecCount() {
	return recCount;
    }

    /**
     * Retrieve the list of networks which are exported in this file.
     * @return An array of networks
     */
    public Network [] getNetworks() {
	return networks;
    }
} // ExportHeader
