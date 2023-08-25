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
 * A representation of the Locality Groups for a single Solaris
 * instance.
 */
public class LocalityDomain
{
	/**
	 * Obtain a Locality Group snapshot based on the view
	 * available to the caller.
	 */
	public static final int LGRP_VIEW_CALLER = 0;

	/**
	 * Obtain a Locality Group snapshot based on the view
	 * of the Operating System.
	 */
	public static final int LGRP_VIEW_OS = 1;

        static
	{
                System.loadLibrary("jlgrp");
        }

	/**
	 * The view used to create this LocalityDomain.
	 */
	private int view;

	/**
	 * The cookie which represents the snapshot of locality
	 * information held by the lgrp library.
	 */
	private long cookie;

	/**
	 * The root LocalityGroup for the LocalityDomain
	 */
	private LocalityGroup root;

	/**
	 * Cached value of maxLatency.
	 */
	private final int maxLatency;

	/**
	 * String representation of often used property.
	 */
	private final static String CPU_SYS_ID = "cpu.sys_id";

	/**
	 * Constructor.
	 *
	 * @param view to use when creating the LocalityDomain.
         * @throws Exception if there is a problem initializing the
         * lgrp snapshot.
	 */
	public LocalityDomain(int view) throws Exception
	{
		this.view = view;
		cookie = jl_init(view);
		root = jl_root();
		/*
		 * The maxLatency calculation is expensive and is used
		 * every time a locality objective is examined. Since
		 * it will never change over the lifetime of a
		 * LocalityDomain, we calculate it once in the
		 * constructor and cache for future use.
		 */
		maxLatency = calcMaxLatency();
	}

        /**
         * Reclaim the resource allocated by the C proxy.
         *
         * @throws Throwable if there is a problem reclaiming the reosurces.
         */
        protected void finalize() throws Throwable
        {
                try
                {
			close();
                }
                finally
                {
                        super.finalize();
                }
        }

	/**
	 * Return the "root" LocalityGroup.
	 */
	public LocalityGroup getRoot()
	{
		return (root);
	}

	/**
	 * Close this LocalityDomain. Resources are reclaimed in the C
	 * proxy and this LocalityDomain should never be used
	 * again. None of the LocalityGroups which are referenced from
	 * this LocalityDomain should be used after this method is
	 * invoked. NB: jl_fini returns a success indicator which is
	 * ignored as we are closing this domain.
	 */
	public void close()
	{
		if (cookie != 0) {
			jl_fini();
			cookie = 0;
			root = null;
		}
	}

	/**
	 * Return a string representation of this instance.
	 */
	public String toString()
	{
		return (root.toString());
	}

	/**
	 * Return the groups in this domain to which the supplied cpus
	 * belong, excluding the supplied set of groups.
	 *
	 * @param exclude Set of groups to be excluded.
	 * @param cpus List of cpus
	 *
	 * @throws PoolsException if there is an error accessing the
	 * cpu details.
	 */
	public Set foreignGroups(Set exclude, List cpus) throws PoolsException
	{
		Iterator cpuIt = cpus.iterator();
		Set result = new HashSet();
		while (cpuIt.hasNext()) {
			Component comp = (Component) cpuIt.next();
			int id = (int) comp.getLongProperty(CPU_SYS_ID);
			LocalityGroup group = getGroup(id);
			if (group != null && exclude.contains(group) == false)
				result.add(group);
		}
		return (result);
	}

	/**
	 * Return the locality group which contains the majority of
	 * the cpus in the supplied list. If more than one group
	 * satisfies this criteria, then the choice of group is
	 * deterministic but unspecified.
	 *
	 * @param cpus List of cpus to be examined.
	 *
	 * @throws PoolsException if there is an error accessing the
	 * cpu details.
	 */
	public LocalityGroup getRepresentativeGroup(List cpus)
	    throws PoolsException
	{
		Iterator cpuIt = cpus.iterator();
		Map grps = new HashMap();
		while (cpuIt.hasNext()) {
			Component comp = (Component) cpuIt.next();
			int id = (int) comp.getLongProperty(CPU_SYS_ID);
			LocalityGroup group = getGroup(id);
			Integer score = (Integer) grps.get(group);
			if (score != null) {
				int iscore = score.intValue() + 1;
				grps.put(group, new Integer(iscore));
			} else {
				grps.put(group, new Integer(1));
			}
		}
		Iterator groupIt = grps.keySet().iterator();
		LocalityGroup centre = null;
		Integer highest = new Integer(0);
		while (groupIt.hasNext()) {
			LocalityGroup cand = (LocalityGroup) groupIt.next();
			Integer value = (Integer) grps.get(cand);
			if (value.intValue() > highest.intValue()) {
				highest = value;
				centre = cand;
			}
		}
		return (centre);
	}

	/**
	 * Return the maximum latency between the groups in this
	 * domain.
	 *
	 */
	private int calcMaxLatency()
	{
		int max = 0;

		Set groups = getGroups();
		Iterator outer = groups.iterator();
		while (outer.hasNext()) {
			Iterator inner = groups.iterator();
			LocalityGroup g1 = (LocalityGroup) outer.next();
			while (inner.hasNext()) {
				LocalityGroup g2 = (LocalityGroup) inner.next();
				int latency = g1.getLatency(g2);
				if (latency > max)
					max = latency;
			}
		}
		return (max);
	}

	/**
	 * Return the maximum possible latency between all locality
	 * groups in this domain.
	 */
	public int getMaxLatency()
	{
		return (maxLatency);
	}

	/**
	 * Return the set of all LocalityGroups for this LocalityDomain.
	 */
	public Set getGroups()
	{
		Set groups = new HashSet();
		groups.add(root);
		getGroups(root, groups);
		return (groups);
	}

	/**
	 * Add all the descendent LocalityGroups for the supplied
	 * group into the supplied set.
	 *
	 * @param group is the group whose descendents are processed.
	 * @param descendents the set to add descendents of group.
	 */
	private void getGroups(LocalityGroup group, Set descendents)
	{
		Set children = group.getChildren();

		if (! children.isEmpty()) {
			Iterator itChild = children.iterator();
			while (itChild.hasNext()) {
				LocalityGroup child = (LocalityGroup) itChild.
				    next();
				getGroups(child, descendents);
			}
			descendents.addAll(children);
		}
	}

	/**
	 * Return the LocalityGroup containing the supplied CPU
	 * id. Search all LocalityGroups starting at the root group.
	 *
	 * @param cpuid is the sys-id of the CPU to search for.
	 */
	public LocalityGroup getGroup(int cpuid)
	{
		LocalityGroup answer = getGroup(root, cpuid);
		return (getGroup(root, cpuid));
	}

	/**
	 * Return the LocalityGroup containing the supplied CPU
	 * id. Search LocalityGroups starting at the supplied group.
	 *
	 * @param group is the group to start searching from.
	 * @param cpuid is the sys-id of the CPU to search for.
	 */
	private LocalityGroup getGroup(LocalityGroup group, int cpuid)
	{
		Set children = group.getChildren();

		if (children.isEmpty()) {
			int cpus[] = group.getCPUIDs();


			for (int i = 0; i < cpus.length; i++)
				if (cpus[i] == cpuid) {
					return (group);
				}
		} else {
			Iterator itGroup = children.iterator();
			while (itGroup.hasNext()) {
				LocalityGroup owner;
				LocalityGroup child = (LocalityGroup) itGroup.
				    next();
				if ((owner = getGroup(child, cpuid)) != null)
					return (owner);
			}
		}
		return (null);
	}

	/**
	 * Initialise the LocalityDomain with an lgrp snapshot.
	 *
	 * @param view is the type of snapshot to obtain.
	 */
	private native long jl_init(int view) throws Exception;

	/**
	 * Release the lgrp snapshot.
	 */
	private native int jl_fini();

	/**
	 * Find the root LocalityGroup.
	 */
	private native LocalityGroup jl_root();

}
