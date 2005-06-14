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
 * Copyright 1998-2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

package com.sun.dhcpmgr.data;

import java.io.Serializable;

public abstract class DhcptabRecord implements Serializable, Cloneable {
    public static final String MACRO = "m";
    public static final String OPTION = "s";

    public static final String DEFAULT_SIGNATURE = "0";

    protected String key;
    protected String flag;
    protected String value;
    protected String signature = DEFAULT_SIGNATURE;

    // Serialization id for this class
    static final long serialVersionUID = -1734667901914072052L;
    
    public DhcptabRecord() {
	key = flag = value = "";
	signature = DEFAULT_SIGNATURE;
    }
    
    public DhcptabRecord(String k, String f, String v) {
	this(k, f, v, DEFAULT_SIGNATURE);
    }
    
    public DhcptabRecord(String k, String f, String v, String sig) {
	key = k;
	flag = f;
	value = v;
	signature = sig;
    }
    
    public void setKey(String k) throws ValidationException {
	key = k;
    }
    
    public String getKey() {
	return key;
    }
    
    public void setFlag(String f) throws ValidationException {
	flag = f;
    }
    
    public String getFlag() {
	return flag;
    }
    
    public void setValue(String v) throws ValidationException {
	value = v;
    }
    
    public String getValue() {
	return value;
    }
    
    public void setSignature(String sig) {
	signature = sig;
    }
    
    public String getSignature() {
	return signature;
    }
    
    public String toString() {
	return new String(key + " " + flag + " " + signature + " " + value);
    }
}
