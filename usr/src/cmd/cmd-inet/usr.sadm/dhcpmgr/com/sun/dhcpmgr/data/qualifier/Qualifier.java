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

/**
 * Common interface that all concrete qualifiers can implement. A qualifier
 * contains information about a given parameter. This information includes the
 * parameter type and whether the parameter is read only.
 */
public interface Qualifier {

    /**
     * Attribute that indicates the name of the parameter the qualifier is
     * associated with.
     */
    public final static String KEYWORD = "keyword";

    /**
     * Attribute that indicates the Java type that can store a legal value for
     * the parameter.
     */
    public final static String TYPE = "type";

    /**
     * Attribute that indicates whether the parameter is designated as read
     * only.
     */
    public final static String READONLY = "readOnly";

    /**
     * Attribute that indicates whether the parameter is hidden.
     */
    public final static String HIDDEN = "hidden";

    /**
     * Get the named qualifier attribute.
     *
     * @param attribute
     *   Attribute to get.
     * @return
     *   The value of the attribute, or null if the attribute is not set.
     */
    public Object getAttribute(String attribute);
    
    /**
     * Set the named qualifier attributes value.
     *
     * @param attribute
     *   Attribute to set.
     * @param value
     *   The value to set the attribute to, or null if the attribute is to
     *   be removed.
     */
    public void setAttribute(String attribute, Object value);

    /**
     * Get the name of the parameter this qualifier is connected to.
     * Convenience method for obtaining the KEYWORD attribute.
     *
     * @return
     *   String containing the name of the parameter.
     */
    public String getKeyword();

    /**
     * Indicates whether the parameter is designated as read only.
     * Convenience method for obtaining the READONLY attribute.
     *
     * @return
     *   True if the parameter is read only, otherwise false.
     */
    public boolean isReadOnly();

    /**
     * Indicates whether the parameter is hidden.
     * Convenience method for obtaining the HIDDEN attribute.
     *
     * @return
     *   True if the parameter is hidden, otherwise false.
     */
    public boolean isHidden();

    /**
     * Get the Java type that can store a legal value for the parameter.
     * Primitive Java types have their counterpart wrapper classes returned.
     * For example for an int the Integer class is returned.
     * Convenience method for obtaining the TYPE attribute.
     *
     * @return
     *   A class that can store legal parameter values.
     */
    public QualifierType getType();

}
