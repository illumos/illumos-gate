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
 *
 */

package com.sun.solaris.service.pools;

import java.util.List;
import java.util.ArrayList;

/**
 * The <code>Pool</code> class represents a Resource Pool.
 */
public class Pool extends Element {

	/**
	 * The name of this instance.
	 */
	private final String name;
	/**
	 * The key of the pool.
	 */
	private final String key;

	/**
	 * Constructor
	 * @param conf The configuration to which this pool belongs.
	 * @param pool The pointer to the native pool which this object wraps.
	 * @throws PoolsException If accessing the proxy fails.
	 */
	Pool(Configuration conf, long pool) throws PoolsException
	{
		_conf = conf;
		Value val = getProperty("pool.name", pool);
		name = val.getString();
		val.close();
		key = "pool." + name;
	}

        /**
         * Returns a pointer to the native pool represented by this
         * pool object.
	 *
	 * @throws PoolsException If the pool cannot be located.
         * @return a pointer to the native pool represented by this
         * pool object.
	 */
	long getPool() throws PoolsException
	{
		return (_conf.checkPool(name));
	}

        /**
         * Associate this pool with the supplied resource.
         *
         * @param res A resource in the same configuration as this pool.
	 * @throws PoolsException If there is an error whilst associating the
	 * resource with the pool.
         */
	public void associate(Resource res) throws PoolsException
	{
		if (PoolInternal.pool_associate(_conf.getConf(), getPool(),
		    res.getResource()) != PoolInternal.PO_SUCCESS)
			throw new PoolsException();
	}

        /**
         * Dissociate this pool from the supplied resource.
         *
         * @param res A resource in the same configuration as this pool.
	 * @throws PoolsException If there is an error whilst dissociating the
	 * resource from the pool.
         */
	public void dissociate(Resource res) throws PoolsException
	{
		if (PoolInternal.pool_dissociate(_conf.getConf(), getPool(),
		    res.getResource()) != PoolInternal.PO_SUCCESS)
			throw new PoolsException();
	}

	/**
	 * Get a list of resources which match the supplied selection criteria
	 * in values. Only resources which are associated with this pool are
	 * searched.
	 *
	 * @param values A list of values to be used to qualify the search.
	 * @throws PoolsExecption If there is an error executing the query.
	 * @return a list of resources which match the supplied criteria
	 */
	public List getResources(List values) throws PoolsException
	{
		List resources;

		if ((resources = PoolInternal.pool_query_pool_resources(
			 _conf.getConf(), getPool(), values)) == null) {
			if (PoolInternal.pool_error() ==
			    PoolInternal.POE_INVALID_SEARCH)
				return new ArrayList();
			else
				throw new PoolsException();
		}
		ArrayList aList = new ArrayList(resources.size());
		for (int i = 0; i < resources.size(); i++)
			aList.add(new Resource(_conf,
			    ((Long)resources.get(i)).longValue()));
		return (aList);
	}

	/**
	 * Returns a descriptive string which describes the pool.
	 *
	 * @param deep Whether the information should contain information about
	 * all contained elements.
	 * @throws PoolsException If the pool cannot be located.
	 * @return a descriptive string which describes the pool.
	 */
	public String getInformation(int deep) throws PoolsException
	{
		return (PoolInternal.pool_info(_conf.getConf(), getPool(),
			    deep));
	}

        /**
         * Returns a string representation of this pool.
         *
         * @return  a string representation of this pool.
         */
	public String toString()
	{
		StringBuffer buf = new StringBuffer();

		buf.append("pool: ");
		buf.append(name);
		return (buf.toString());
	}

	/**
	 * Indicates whether some other Pool is "equal to this one.
	 * @param o the reference object with which to compare.
	 * @return <code>true</code> if this object is the same as the
	 * o argument; <code>false</code> otherwise.
	 * @see	#hashCode()
	 */
	public boolean equals(Object o)
	{
		if (o == this)
			return (true);
		if (!(o instanceof Pool))
			return (false);
		Pool other = (Pool) o;
		if (name.compareTo(other.getName()) != 0)
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
		return (name.hashCode());
	}

	/**
	 * Return the pointer to this pool as an element.
	 *
	 * @return The pointer to the native pool which this object wraps.
	 * @throws PoolsExecption If there is an error converting the native
	 * pool pointer to a native elem pointer.
	 */
	protected long getElem() throws PoolsException
	{
		long elem;

		if ((elem = PoolInternal.pool_to_elem(_conf.getConf(),
		    getPool())) == 0)
			throw new PoolsException();
		return (elem);
	}

	/**
	 * Return the name of the pool.
	 */
	String getName()
	{
		return (name);
	}

	/**
	 * Return the key of the pool.
	 */
	String getKey()
	{
		return (key);
	}
}
