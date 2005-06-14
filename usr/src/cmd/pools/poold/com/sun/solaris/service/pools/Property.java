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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 *ident	"%Z%%M%	%I%	%E% SMI"
 *
 */

package com.sun.solaris.service.pools;

/**
 * The <code>Property</code> interface specifies the contract between
 * a pools configuration element and it's properties. This interface
 * must be implemented by all pools configuration elements to ensure that
 * properties can be manipulated.
 */

public interface Property {
	/**
	 * Get a property with the supplied name.
	 *
	 * @param name The name of the property to be retrieved.
	 * @throws PoolsExecption If there is an error accessing the property.
	 */
	public boolean getBoolProperty(String name) throws PoolsException;

	/**
	 * Get a property with the supplied name.
	 *
	 * @param name The name of the property to be retrieved.
	 * @throws PoolsExecption If there is an error accessing the property.
	 */
	public double getDoubleProperty(String name) throws PoolsException;

	/**
	 * Get a property with the supplied name.
	 *
	 * @param name The name of the property to be retrieved.
	 * @throws PoolsExecption If there is an error accessing the property.
	 */
	public long getLongProperty(String name) throws PoolsException;

	/**
	 * Get a property with the supplied name.
	 *
	 * @param name The name of the property to be retrieved.
	 * @throws PoolsExecption If there is an error accessing the property.
	 */
	public String getStringProperty(String name) throws PoolsException;

	/**
	 * Put the supplied value as a property with the supplied name.
	 *
	 * @param name The name of the property to be updated.
	 * @param value The value of the property to be updated.
	 * @throws PoolsExecption If there is an error accessing the property.
	 */
	public void putProperty(String name, Value value) throws PoolsException;

	/**
	 * Remove the property with the supplied name.
	 *
	 * @param name The name of the property to be removed.
	 * @throws PoolsExecption If there is an error removing the property.
	 */
	public void rmProperty(String name) throws PoolsException;
}
