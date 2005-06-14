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

package com.sun.dhcpmgr.data;

import java.io.Serializable;

public class DhcpDatastore implements Serializable {
    
    private String resource;
    private String location;
    private String config;
    private int version;
    private boolean enabled;
    
    /**
     * Simplest constructor.
     */
    public DhcpDatastore() {
	this(null, null, null, -1, true);
    } // constructor
    
    /**
     * Constructor.
     * @param r the data store 'resource' value
     * @param v the data store 'version' value
     * @param e the data store 'enabled' value
     */
    public DhcpDatastore(String r, int v, boolean e) {
	this(r, null, null, v, e);
    } // constructor
    
    /**
     * Constructor.
     * @param r the data store 'resource' value
     * @param l the data store 'location' value
     * @param a the data store 'config' value
     */
    public DhcpDatastore(String r, String l, String a) {
	this(r, l, a, -1, true);
    } // constructor

    /**
     * Constructor.
     * @param r the data store 'resource' value
     * @param l the data store 'location' value
     * @param a the data store 'config' value
     * @param v the data store 'version' value
     */
    public DhcpDatastore(String r, String l, String a, int v) {
	this(r, l, a, v, true);
    } // constructor

    /**
     * Constructor.
     * @param r the data store 'resource' value
     * @param l the data store 'location' value
     * @param a the data store 'config' value
     * @param v the data store 'version' value
     * @param e the data store 'enabled' value
     */
    public DhcpDatastore(String r, String l, String a, int v, boolean e) {
	setResource(r);
	setLocation(l);
	setConfig(a);
	setVersion(v);
	setEnabled(e);
    } // constructor
    
    /**
     * Returns the data store 'resource' value.
     * @returns the data store 'resource' value.
     */
    public String getResource() {
	return resource;
    } // getResource
    
    /**
     * Sets the data store 'resource' value.
     * @param s the data store 'resource' value.
     */
    public void setResource(String s) {
	resource = s;
    } // setResource

    /**
     * Returns the data store 'location' value.
     * @returns the data store 'location' value.
     */
    public String getLocation() {
	return location;
    } // getLocation
    
    /**
     * Sets the data store 'location' value.
     * @param s the data store 'location' value.
     */
    public void setLocation(String s) {
	location = s;
    } // setLocation

    /**
     * Returns the data store 'config' value.
     * @returns the data store 'config' value.
     */
    public String getConfig() {
	return config;
    } // getConfig
    
    /**
     * Sets the data store 'config' value.
     * @param s the data store 'config' value.
     */
    public void setConfig(String s) {
	config = s;
    } // setConfig

    /**
     * Returns the data store 'version' value.
     * @returns the data store 'version' value.
     */
    public int getVersion() {
	return version;
    } // getVersion
    
    /**
     * Sets the data store 'version' value.
     * @param v the data store 'version' value.
     */
    public void setVersion(int v) {
	version = v;
    } // setVersion

    /**
     * Returns the data store 'enabled' value.
     * @returns the data store 'enabled' value.
     */
    public boolean isEnabled() {
	return enabled;
    } // isEnables
    
    /**
     * Sets the data store 'enabled' value.
     * @param e the data store 'enabled' value.
     */
    public void setEnabled(boolean e) {
	enabled = e;
    } // setEnabled

    /**
     * Indicates whether some other object "is equal" to this one.
     * @param o the object with which to compare.
     * @returns true if the objects are equal, false otherwise.
     */
    public boolean equals(Object o) {
	if (o instanceof DhcpDatastore) {
            DhcpDatastore d = (DhcpDatastore)o;

            return (version == d.getVersion() &&
		stringsEqual(resource, d.getResource()) &&
		stringsEqual(location, d.getLocation()) &&
		stringsEqual(config, d.getConfig()));

        } else {
            return false;
        }

    } // equals

    /**
     * Compares two strings for equality.
     * @param s1 one of the strings to compare.
     * @param s2 the other string to compare against.
     * @returns true if the strings are equal, false otherwise.
     */
    private boolean stringsEqual(String s1, String s2) {
	if (s1 == s2) {
	    return true;
	} else if (s1 == null || s2 == null) {
	    return false;
	} else {
	    return s1.equals(s2);
	}
    } // stringsEqual

} // DhcpDatastore
