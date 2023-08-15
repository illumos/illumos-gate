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
 *
 */

package com.sun.solaris.service.locality;

import java.util.*;

import com.sun.solaris.service.pools.*;

/**
 * A representation of an individual Locality Group. A Locality Group
 * resides within a Locality Domain.
 */
public class LocalityGroup
{
	/**
	 * The locality domain which contains this group.
	 */
	private LocalityDomain domain;

	/**
	 * The C proxy id for this instance.
	 */
	private long id;

	/**
	 * The parent group of this instance.
	 */
	private LocalityGroup parent;

	/**
	 * The array of CPU IDs which are assigned to this instance.
	 */
	private int cpu_ids[];

	/**
	 * The child groups of this instance.
	 */
	private Set children;

	/**
	 * Constructor.
	 *
	 * @param domain is the domain to which this instance belongs.
	 * @param id is the id of this instance.
	 * @param parent is the parent of this instance.
	 */
	public LocalityGroup(LocalityDomain domain, long id,
	    LocalityGroup parent)
	{
		this.domain = domain;
		this.id = id;
		this.parent = parent;
		this.cpu_ids = jl_cpus();
		long nativeChildren[] = jl_children();
		children = new HashSet();
		for (int i = 0; i < nativeChildren.length; i++)
			children.add(new LocalityGroup(domain,
				     nativeChildren[i], this));
	}

	/**
	 * Return a string representation of this instance.
	 */
	public String toString()
	{
		StringBuffer sb = new StringBuffer().append("locality group ")
		    .append(id)
		    .append(" with cpus [");

		String sep = "";
		for (int i = 0; i < cpu_ids.length; i++) {
			sb.append(sep);
			sb.append(cpu_ids[i]);
			sep = " ";
		}
		sb.append("]");

		return (sb.toString());
	}

	/**
	 * Return the set of child locality groups for this instance.
	 */
	public Set getChildren()
	{
		return (children);
	}

	/**
	 * Return the array of CPU IDs which belong to this locality
	 * group.
	 */
	public int[] getCPUIDs()
	{
		return (cpu_ids);
	}

	/**
	 * Return the locality group ID.
	 */
	long getID()
	{
		return (id);
	}

	/**
	 * Return the latency of the supplied group with respect to
	 * this group.
	 *
	 * @param other is another locality group belonging to the
	 * same LocalityDomain.
	 */
	public int getLatency(LocalityGroup other)
	{
		return (jl_latency(id, other.getID()));
	}

	/**
	 * Return the number of Latency Groups to which these cpus
	 * belong which are not part of this group.
	 *
	 * @param cpus List of cpus to be examined.
	 *
	 * @throws PoolsException if there is an error accessing the
	 * cpu details.
	 */
	public int countForeignGroups(List cpus) throws PoolsException
	{
		Set groups = new HashSet();
		Iterator cpuIt = cpus.iterator();

		while (cpuIt.hasNext()) {
			Component comp = (Component) cpuIt.next();
			int id = (int) comp.getLongProperty("cpu.sys_id");
			for (int i = 0; i < cpu_ids.length; i++) {
				if (cpu_ids[i] == id) {
					LocalityGroup other = domain.
					    getGroup(id);
					if (other != this &&
					    groups.contains(other) == false)
						groups.add(other);
				}
			}
		}
		return (groups.size());
	}

	public Set contains(List cpus) throws PoolsException
	{
		Set contained = new HashSet();
		Iterator cpuIt = cpus.iterator();
		int set_cpus[] = getCPUIDs();

		while (cpuIt.hasNext()) {
			Component comp = (Component) cpuIt.next();
			for (int i = 0; i < set_cpus.length; i++) {
				if (set_cpus[i] == (int)comp.getLongProperty(
					"cpu.sys_id")) {
					contained.add(comp);
					break;
				}
			}
		}
		return (contained);
	}

	/**
	 * Return an array containing the child locality group IDs.
	 */
	private native long[] jl_children();

	/**
	 * Return an array of CPU IDs within this locality group.
	 */
	private native int[] jl_cpus();

	/**
	 * Return the latency between the two supplied lgrp IDs.
	 *
	 * @param id1 is the first id.
	 * @param id2 is the second id.
	 */
	private native int jl_latency(long id1, long id2);
}
