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
 * Copyright 2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

package com.sun.dhcpmgr.data.qualifier;

import java.util.Map;
import java.util.HashMap;

/**
 * Super class for qualifier. Provides common methods and fields.
 */
public class QualifierImpl implements Qualifier {

    /**
     * Map of qualifier attributes to values.
     */
    protected Map attributes;

    /**
     * Construct an empty qualifier.
     */
    public QualifierImpl() {
    }

    /**
     * Construct a qualifier, assigning all the required fields.
     *
     * @param keyword
     *   The name of the parameter that the qualifier is associated with.
     * @param readOnly
     *   Inidicate whether the parameter is to be treated as read only.
     * @param hidden
     *   Inidicate whether the parameter is hidden.
     * @param type
     *   The parameter value type.
     */
    public QualifierImpl(String keyword,
			 boolean readOnly,
			 boolean hidden,
			 QualifierType type) {

	attributes = new HashMap();
	attributes.put(KEYWORD, keyword);
	attributes.put(READONLY, new Boolean(readOnly));
	attributes.put(HIDDEN, new Boolean(hidden));
	attributes.put(TYPE, type);
    }

    public synchronized Object getAttribute(String attribute) {
	return attributes.get(attribute);
    }

    public synchronized void setAttribute(String attribute, Object value) {
	if (value == null) {
	    if (attributes.containsKey(attribute)) {
		attributes.remove(attribute);
	    }
	} else {
	    attributes.put(attribute, value);
	}
    }

    public String getKeyword() {
	return (String)attributes.get(KEYWORD);
    }

    public boolean isReadOnly() {
	return ((Boolean)attributes.get(READONLY)).booleanValue();
    }

    public boolean isHidden() {
	return ((Boolean)attributes.get(HIDDEN)).booleanValue();
    }

    public QualifierType getType() {
	return (QualifierType)attributes.get(TYPE);
    }

    public String toString() {
	return attributes.toString();
    }
}
