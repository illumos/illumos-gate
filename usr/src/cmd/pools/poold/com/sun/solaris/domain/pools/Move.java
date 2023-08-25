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
 * ident	"%Z%%M%	%I%	%E% SMI"
 */

package com.sun.solaris.domain.pools;

import java.util.*;

import com.sun.solaris.service.pools.*;

/**
 * This class represents a move of resources between two resource
 * sets. It is designed to be extended by classes which implement
 * different types of moves.
 */
abstract class Move
{
	/**
	 * Source resource set
	 */
	private Resource from;

	/**
	 * Destination resource set
	 */
	private Resource to;

	/**
	 * Sole constructor.  (For invocation by subclass constructors)
	 *
	 * @param from The source of the move
	 * @param to The destination of the move
	 */
	protected Move(Resource from, Resource to)
	{
		this.from = from;
		this.to = to;
	}

	/**
	 * Return the source of this move.
	 */
	Resource getFrom()
	{
		return (from);
	}

	/**
	 * Return the destination of this move.
	 */
	Resource getTo()
	{
		return (to);
	}

	/**
	 * Apply this move to the resources described.
	 *
	 * @throws PoolsException If the move fails for any reason.
	 */
	abstract void apply() throws PoolsException;

	/**
	 * Return the quantity of moved resource.
	 */
	abstract long getQty();
}

/**
 * This class represents a move of component resources between two
 * resource sets. A component of a resource set is a uniquely
 * identifiable component, such as a processor.
 */
final class ComponentMove extends Move
{
	/**
	 * List of components being moved.
	 */
	private List compList;

	/**
	 * Constructor
	 *
	 * @param from The source of the move
	 * @param to The destination of the move
	 * @param comp The component which is to be moved
	 */
	ComponentMove(Resource from, Resource to, Component comp)
	{
		super(from, to);
		compList = new ArrayList();
		compList.add(comp);
	}

	/**
	 * Return a list of the components that comprise this move.
	 *
	 * The members of the list are guaranteed to be Component
	 * objects.
	 */
	List getComponents()
	{
		return ((List) ((ArrayList) compList).clone());
	}

	/**
	 * Apply the move to the configuration to which the resources
	 * belong.
	 *
	 * @throws PoolsException if the transfer of resource fails.
	 */
	void apply() throws PoolsException
	{
		getTo().transfer(getFrom(), compList);
	}

	/**
	 * Return the quantity of resource which is participating in
	 * this move.
	 */
	long getQty()
	{
		return (compList.size());
	}

	/**
	 * Converts the <code>ComponentMove</code> to a
	 * <code>String</code> of the form:
	 */
	public String toString()
	{
		return ("from " + getFrom().toString() + " to " +
		    getTo().toString() + " components " + compList);
	}
}

/**
 * This class represents a move of commodity resources between two
 * resource sets. Such a resource cannot be uniquely identified in the
 * resource abstraction and is thus different to a move consisting of
 * uniquely identifiable resource components.
 */
class QuantityMove extends Move
{
	/**
	 * The resource quantity of the move.
	 */
	private long qty;

	/**
	 * Construct a quantity move using the supplied details.
	 *
	 * @param from The source of the resources.
	 * @param to The destination of the resources.
	 * @param qty The quantity of the resources.
	 *
	 * @throws IllegalArgumentException if the qty is negative.
	 */
	QuantityMove(Resource from, Resource to, long qty)
	{
		super(from, to);
		if (qty < 0)
			throw new IllegalArgumentException(
			    "The resource quantity supplied (" + qty +
			    ") is illegal.");
		this.qty = qty;
	}

	/**
	 * Apply the move to the configuration to which the resources
	 * belong.
	 *
	 * @throws PoolsException if the transfer of resource fails.
	 */
	void apply() throws PoolsException
	{
		getTo().transfer(getFrom(), qty);
	}

	/**
	 * Return the quantity of resource which is participating in
	 * this move.
	 */
	long getQty()
	{
		return (qty);
	}

	/**
	 * Return a string representation of the move.
	 */
	public String toString()
	{
		return ("from " + getFrom().toString() + " to " +
		    getTo().toString() + " quantity " + qty);
	}
}
