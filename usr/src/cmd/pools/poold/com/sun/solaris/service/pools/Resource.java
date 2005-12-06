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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 *ident	"%Z%%M%	%I%	%E% SMI"
 */

package com.sun.solaris.service.pools;

import java.util.List;
import java.util.ArrayList;

/**
 * The <code>Resource</code> class represents a resource.
 */
public class Resource extends Element
{
	/**
	 * The type of the resource.
	 */
	private final String type;
	/**
	 * The system id of the resource.
	 */
	private final String name;
	/**
	 * The key of the resource.
	 */
	private final String key;

	/**
	 * Constructor
	 * @param conf The configuration to which this pool belongs.
	 * @param resource The pointer to the native resource which
	 * this object wraps.
	 * @throws PoolsException If accessing the proxy fails.
	 */
	Resource(Configuration conf, long resource) throws PoolsException
	{
		_conf = conf;
		Value val = getProperty("type", resource);
		type = val.getString();
		val.close();
		val = getProperty(type + ".name", resource);
		name = val.getString();
		val.close();
		key = type + "." + name;
	}

        /**
         * Returns a pointer to the native resouce represented by this resource
	 * object.
         *
	 * @throws PoolsException If the pool cannot be located.
         * @return a pointer to the native resource represented by this
	 * resource object.
         */
	long getResource() throws PoolsException
	{
		return (_conf.checkResource(type, name));
	}

        /**
         * Transfer the requested quantity of resource from the donor to this
	 * resource.
         *
         * @param donor A donating resource.
         * @param qty Amount of resource to be donated.
	 * @throws PoolsException If there is an error whilst donating the
	 * resource.
         */
	public void transfer(Resource donor, long qty) throws PoolsException
	{
		if (PoolInternal.pool_resource_transfer(_conf.getConf(),
		    donor.getResource(), getResource(), qty) !=
		    PoolInternal.PO_SUCCESS)
			throw new PoolsException();
	}		

        /**
         * Transfer the specified resource components from the donor to this
	 * resource.
         *
         * @param donor A donating resource.
         * @param components A list of resource components to be donated.
	 * @throws PoolsException If there is an error whilst donating the
	 * resource components.
         */
	public void transfer(Resource donor, List components)
	    throws PoolsException
	{
		if (PoolInternal.pool_resource_xtransfer(_conf.getConf(),
		    donor.getResource(), getResource(), components) !=
		    PoolInternal.PO_SUCCESS)
			throw new PoolsException();
	}		

	/**
	 * Get a list of components which match the supplied selection
	 * criteria in values.  Only components which are controlled by
	 * this resource are searched.
	 *
	 * @param values A list of values to be used to qualify the search.
	 * @throws PoolsExecption If there is an error executing the query.
	 * @return a list of components which match the supplied criteria
	 */
	public List getComponents(List values) throws PoolsException
	{
		List components;

		if ((components = PoolInternal.pool_query_resource_components(
		    _conf.getConf(), getResource(), values)) == null) {
			if (PoolInternal.pool_error() ==
			    PoolInternal.POE_INVALID_SEARCH)
				return new ArrayList();
			else
				throw new PoolsException();
		}
		ArrayList aList = new ArrayList(components.size());
		for (int i = 0; i < components.size(); i++)
			aList.add(new Component(_conf,
			    ((Long)components.get(i)).longValue()));
		return (aList);
	}

	/**
	 * Returns a descriptive string which describes the resource.
	 *
	 * @param deep Whether the information should contain information about
	 * all contained elements.
	 * @throws PoolsException If the resource cannot be located.
	 * @return a descriptive string which describes the resource.
	 */
	public String getInformation(int deep) throws PoolsException
	{
		return (PoolInternal.pool_resource_info(_conf.getConf(),
			getResource(), deep));
	}

        /**
         * Returns a string representation of this resource.
         *
         * @return  a string representation of this resource.
         */
	public String toString()
	{
		StringBuffer buf = new StringBuffer();

		buf.append(type);
		buf.append(" ");
		buf.append(name);
		return (buf.toString());
	}

	/**
	 * Indicates whether some other Resource is "equal to this one.
	 * @param o the reference object with which to compare.
	 * @return <code>true</code> if this object is the same as the
	 * o argument; <code>false</code> otherwise.
	 * @see	#hashCode()
	 */
	public boolean equals(Object o)
	{
		if (o == this)
			return (true);
		if (!(o instanceof Resource))
			return (false);
		Resource other = (Resource) o;
		if (type.compareTo(other.getType()) != 0 ||
		    name.compareTo(other.getName()) != 0)
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
		return (type.hashCode() + name.hashCode());
	}

	/**
	 * Return the pointer to this resource as an element.
	 *
	 * @return The pointer to the native resource which this object wraps.
	 * @throws PoolsExecption If there is an error converting the native
	 * resource pointer to a native elem pointer.
	 */
	protected long getElem() throws PoolsException
	{
		long elem;

		if ((elem = PoolInternal.pool_resource_to_elem(_conf.getConf(),
		    getResource())) == 0)
			throw new PoolsException();
		return (elem);
	}

	/**
	 * Return the type of the resource
	 */
	String getType()
	{
		return (type);
	}

	/**
	 * Return the name of the resource.
	 */
	String getName()
	{
		return (name);
	}

	/**
	 * Return the key of the resource.
	 */
	String getKey()
	{
		return (key);
	}
}
