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
 * Copyright (c) 1998-1999 Sun Microsystems, Inc.
 * All rights reserved.
 */

package com.sun.dhcpmgr.data;

import java.io.Serializable;

/**
 * DhcpResource represents a record in the /etc/defaults/dhcp file.  Each
 * record is either an option setting for the DHCP daemon or a comment.
 */
public class DhcpResource implements Serializable {
    private String key;
    private String value;
    private boolean comment;

    public DhcpResource() {
    	this("", "", false);
    }

    public DhcpResource(String key, String value) {
	this(key, value, false);
    }

    public DhcpResource(String key, String value, boolean comment) {
    	this.key = key;
	this.value = value;
	this.comment = comment;
    }
    
    public boolean isComment() {
    	return comment;
    }

    public void setComment(boolean comment) {
    	this.comment = comment;
    }

    public String getKey() {
	return key;
    }
    
    public void setKey(String key) {
	this.key = key;
    }
    
    public String getValue() {
	return value;
    }
    
    public void setValue(String value) {
	this.value = value;
    }
    
    /**
     * Compare for equality against another object.
     * @return true if the object is another DhcpResource instance and
     * they are both comments or normal resources and the key value is
     * identical.  The value of 'value' is irrelevant.  This is primarily
     * used by the indexOf method of the ArrayList used to store the options
     * in DhcpdOptions.
     */
    public boolean equals(Object o) {
    	if (o instanceof DhcpResource) {
	    DhcpResource r = (DhcpResource)o;
    	    return (comment == r.isComment()) && key.equals(r.getKey());
	} else {
	    return false;
	}
    }

    public String toString() {
	if (comment) {
	    return "#" + key;
	} else {
	    return key + "=" + value;
	}
    }
}
