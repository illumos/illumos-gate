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
 * The <code>Component</code> class represents a configuration
 * resource component.
 */
public class Component extends Element
{
	/**
	 * The type of the component.
	 */
	private final String type;

	/**
	 * The system id of the component.
	 */
	private final long sys_id;

	/**
	 * The key of the component.
	 */
	private final String key;

	/**
	 * Constructor
	 *
	 * @param conf The configuration to which this component belongs
	 * @param comp The pointer to the native component
	 * @throws PoolsException If accessing the proxy fails.
	 */
	Component(Configuration conf, long comp) throws PoolsException
	{
		_conf = conf;
		Value val = getProperty("type", comp);
		type = val.getString();
		val.close();
		val = getProperty(type + ".sys_id", comp);
		sys_id = val.getLong();
		val.close();
		key = type + "." + sys_id;
	}

	/**
	 * Return the pointer to the component represented by this object.
	 *
	 * @return conf the pointer to the component represented by this object
	 * @throws PoolsException If the component cannot be located.
	 */
	long getComponent() throws PoolsException
	{
		return (_conf.checkComponent(type, sys_id));
	}

	/**
	 * Returns a descriptive string which describes the component.
	 *
	 * @param deep Whether the information should contain information about
	 * all contained elements.
	 * @throws PoolsException If the component cannot be located.
	 * @return a descriptive string which describes the component.
	 */
	public String getInformation(int deep) throws PoolsException
	{
		return (PoolInternal.pool_component_info(_conf.getConf(),
			getComponent(), deep));
	}

        /**
         * Returns a string representation of this component.
         *
         * @return  a string representation of this component.
         */
	public String toString()
	{
		StringBuffer buf = new StringBuffer();

		buf.append(type);
		buf.append(" ");
		buf.append(sys_id);
		return (buf.toString());
	}

	/**
	 * Indicates whether some other Component is "equal to this one.
	 * @param o the reference object with which to compare.
	 * @return <code>true</code> if this object is the same as the
	 * o argument; <code>false</code> otherwise.
	 * @see	#hashCode()
	 */
	public boolean equals(Object o)
	{
		if (o == this)
			return (true);
		if (!(o instanceof Component))
			return (false);
		Component other = (Component) o;
		if (type.compareTo(other.getType()) != 0 ||
		    sys_id != other.getSysId())
			return (false);
		return (true);
	}

	/**
	 * Returns a hash code value for the object. This method is
	 * supported for the benefit of hashtables such as those provided by
	 * <code>java.util.Hashtable</code>.
	 *
	 * @return a hash code value for this object.
	 * @see	#equals(java.lang.Object)
	 * @see	java.util.Hashtable
	 */
	public int hashCode()
	{
		return (type.hashCode() + (int) sys_id);
	}

	/**
	 * Return the pointer to this component as an element.
	 *
	 * @return The pointer to the native component which this object wraps.
	 * @throws PoolsExecption If there is an error converting the native
	 * component pointer to a native elem pointer.
	 */
	protected long getElem() throws PoolsException
	{
		long elem;

		if ((elem = PoolInternal.pool_component_to_elem(_conf.getConf(),
		    getComponent())) == 0)
			throw new PoolsException();
		return (elem);
	}

	/**
	 * Return the type of the component
	 */
	String getType()
	{
		return (type);
	}

	/**
	 * Return the system id of the component.
	 */
	long getSysId()
	{
		return (sys_id);
	}

	/**
	 * Return the key of the component.
	 */
	String getKey()
	{
		return (key);
	}
}
