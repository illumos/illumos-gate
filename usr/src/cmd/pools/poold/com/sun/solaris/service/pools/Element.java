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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 */

package com.sun.solaris.service.pools;

import java.util.List;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Arrays;

/**
 * The <code>Element</code> class represents a pools configuration
 * element.  The class is an abstract, base class for concrete
 * implementation elements, such as pool and resource.
 */
public abstract class Element implements Property, PropertyWalk
{
	/**
	 * The configuration to which this element belongs.
	 */
	protected Configuration _conf;

        /**
         * Returns a string representation of this element.
         *
         * @return  a string representation of this element.
         */
	public String toString()
	{
		try {
			return (getInformation(1));
		} catch (PoolsException pe) {
			return (pe.toString());
		}
	}

	/**
	 * Returns a descriptive string which describes the element.
	 *
	 * @param deep Whether the information should contain information about
	 * all contained elements.
	 * @throws PoolsException If the element cannot be located.
	 * @return a descriptive string which describes the element.
	 */
	public abstract String getInformation(int deep) throws PoolsException;

	/**
	 * A list of properties that are chosen to be cached.
	 */
	private static final List cachedProperties
			= Arrays.asList(new String[] {"cpu.sys_id",
			"pool.default", "pool.sys_id", "pset.default",
			"pset.sys_id", "pset.type", "pset.units"});

        /**
         * hashmap of property values that are determined readonly
         */
        private HashMap readOnlyValues = new HashMap();

	/**
	 * Get the property with the supplied name.
	 *
	 * @param name The name of the property to be retrieved.
	 * @throws PoolsExecption If there is an error accessing the property.
	 * @return a value containing the property details.
	 */
        private Value getProperty(String name) throws PoolsException
	{
            if (readOnlyValues.containsKey(name)) {
                Value value = (Value) readOnlyValues.get(name);
                return (value);
            } else {
                Value value = new Value(name);
                if (PoolInternal.pool_get_property(_conf.getConf(), getElem(),
                        name, value.getValue()) == PoolInternal.POC_INVAL) {
                    throw new PoolsException();
                } else {
                    if (cachedProperties.contains(name)) {
                        value.lock();
                        readOnlyValues.put(name, value);
                    }
                    return (value);
                }
            }
        }

	/**
	 * Get the property with the supplied name using the supplied
	 * proxy.
	 *
	 * @param name The name of the property to be retrieved.
	 * @param proxy The proxy item used to retrieve the property.
	 * @throws PoolsExecption If there is an error accessing the property.
	 * @return a value containing the property details.
	 */
        protected Value getProperty(String name, long proxy)
	    throws PoolsException
	{
            if (readOnlyValues.containsKey(name)) {
                Value value = (Value) readOnlyValues.get(name);
                return (value);
            } else {
                Value value = new Value(name);
                if (PoolInternal.pool_get_property(_conf.getConf(), proxy, name,
                        value.getValue()) == PoolInternal.POC_INVAL) {
                    throw new PoolsException();
                } else {
                    if (cachedProperties.contains(name)) {
                        value.lock();
                        readOnlyValues.put(name, value);
                    }
                    return (value);
                }
            }
        }

	/**
	 * Put the supplied value as an element property with the supplied
	 * name.
	 *
	 * @param name The name of the property to be updated.
	 * @param value The value of the property to be updated.
	 * @throws PoolsExecption If there is an error accessing the property.
	 */
        public void putProperty(String name, Value value) throws PoolsException
	{
		if (PoolInternal.pool_put_property(_conf.getConf(), getElem(),
			name, value.getValue()) != PoolInternal.PO_SUCCESS)
			throw new PoolsException();
	}

	/**
	 * Remove the element property with the supplied name.
	 *
	 * @param name The name of the property to be removed.
	 * @throws PoolsExecption If there is an error removing the property.
	 */
        public void rmProperty(String name) throws PoolsException
	{
		if (PoolInternal.pool_rm_property(_conf.getConf(), getElem(),
			name) != PoolInternal.PO_SUCCESS)
			throw new PoolsException();
	}

	/**
	 * Get a String property.
	 *
	 * If the type of the property does not match, i.e. it's not a
	 * String, or the element does not have such a property then a
	 * PoolsException is thrown.
	 *
	 * @param name The name of the property to be retrieved.
	 * @throws PoolsException If getting the String property fails.
	 */
	public String getStringProperty(String name) throws PoolsException
	{
		Value val = getProperty(name);

		if (val != null) {
			String ret = val.getString();
			val.close();
			return (ret);
		}
		throw new PoolsException();
	}

	/**
	 * Get a long property.
	 *
	 * If the type of the property does not match, i.e. it's not a
	 * long, or the element does not have such a property then a
	 * PoolsException is thrown.
	 *
	 * @param name The name of the property to be retrieved.
	 * @throws PoolsException If getting the long property fails.
	 */
	public long getLongProperty(String name) throws PoolsException
	{
		Value val = getProperty(name);

		if (val != null) {
			long ret = val.getLong();
			val.close();
			return (ret);
		}
		throw new PoolsException();
	}

	/**
	 * Get a double property.
	 *
	 * If the type of the property does not match, i.e. it's not a
	 * double, or the element does not have such a property then a
	 * PoolsException is thrown.
	 *
	 * @param name The name of the property to be retrieved.
	 * @throws PoolsException If getting the double property fails.
	 */
	public double getDoubleProperty(String name) throws PoolsException
	{
		Value val = getProperty(name);

		if (val != null) {
			double ret = val.getDouble();
			val.close();
			return (ret);
		}
		throw new PoolsException();
	}

	/**
	 * Get a boolean property.
	 *
	 * If the type of the property does not match, i.e. it's not a
	 * boolean, or the element does not have such a property then
	 * a PoolsException is thrown.
	 *
	 * @param name The name of the property to be retrieved.
	 * @throws PoolsException If getting the boolean property fails.
	 */
	public boolean getBoolProperty(String name) throws PoolsException
	{
		Value val = getProperty(name);

		if (val != null) {
			boolean ret = val.getBool();
			val.close();
			return (ret);
		}
		throw new PoolsException();
	}

	/**
	 * Walk all properties of the invoking object.
	 *
	 * @param elem The element to whom the property belongs.
	 * @param val The value representing the current element.
	 * @param user User supplied data, provided when the walk is invoked.
	 * @throws PoolsExecption If there is an error walking the property.
	 * @return 0 to continue the walk, anything else to terminate it.
	 */
	public int walk(Element elem, Value val, Object user)
	    throws PoolsException
	{
		System.out.println("Property name: " + val.getName() +
		    ", value: "+val.toString());
		val.close();
		return (0);
	}

	/**
	 * Return the pointer to this subtype as an element.
	 *
	 * @return The pointer to the native subtype which this object wraps.
	 * @throws PoolsExecption If there is an error converting the native
	 * subtype pointer to a native elem pointer.
	 */
	protected abstract long getElem() throws PoolsException;

	/**
	 * Walk all the properties of this element.
	 *
	 * @param handler The object which will receive the callbacks.
	 * @param user Data supplied by the user for use in the callback.
	 * @return 0 for a successful walk, else 1.
	 * @throws PoolsExecption If there is an error during the walk.
	 */
	public int walkProperties(PropertyWalk handler, Object user)
	    throws PoolsException
	{
		return (walkProps(_conf.getConf(), getElem(), handler, user));
	}

	/**
	 * Walk the properties of the supplied element using the
	 * supplied handler.
	 *
	 * @param conf native reference to the configuration in which
	 * the element belongs.
	 * @param elem native reference to the element whose
	 * properties are to be walked.
	 * @param handler a method to be invoked with each property of
	 * the elem.
	 * @param user a user parameter which is passed to handler on
	 * each invocation.
	 * @throws PoolsException if there is an error accessing the
	 * element properties.
	 */
	private native int walkProps(long conf, long elem,
	    PropertyWalk handler, Object user) throws PoolsException;

	/**
	 * Return the key of the element.
	 */
	abstract String getKey();
}
