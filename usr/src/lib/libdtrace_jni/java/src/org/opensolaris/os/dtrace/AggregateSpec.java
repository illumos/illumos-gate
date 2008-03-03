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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * ident	"%Z%%M%	%I%	%E% SMI"
 */
package org.opensolaris.os.dtrace;

import java.util.*;

/**
 * Implementation detail used by {@link Consumer#getAggregate()}.
 * Package level access.
 *
 * @author Tom Erickson
 */
class AggregateSpec {
    private Set <String> includedAggregationNames;
    private Set <String> clearedAggregationNames;

    AggregateSpec()
    {
	includedAggregationNames = new HashSet <String> ();
	clearedAggregationNames = new HashSet <String> ();
    }

    public boolean
    isIncludeByDefault()
    {
	return (includedAggregationNames == null);
    }

    public boolean
    isClearByDefault()
    {
	return (clearedAggregationNames == null);
    }

    public void
    setIncludeByDefault(boolean include)
    {
	if (include) {
	    includedAggregationNames = null;
	} else if (includedAggregationNames == null) {
	    includedAggregationNames = new HashSet <String> ();
	}
    }

    public void
    setClearByDefault(boolean clear)
    {
	if (clear) {
	    clearedAggregationNames = null;
	} else if (clearedAggregationNames == null) {
	    clearedAggregationNames = new HashSet <String> ();
	}
    }

    /**
     * Specifies which aggregations to include in an aggregate snapshot.
     * If none are specified, all aggregations are included.  A snapshot
     * is read-consistent across all included aggregations.
     *
     * @see Consumer#getAggregate(AggregateSpec spec)
     */
    public void
    addIncludedAggregationName(String name)
    {
	if (includedAggregationNames == null) {
	    includedAggregationNames = new HashSet <String> ();
	}
	includedAggregationNames.add(name);
    }

    /**
     * Specifies which aggregations to clear after snapping the
     * aggregate.  If none are specified, no aggregations are cleared.
     * <p>
     * Aggregations are cleared immediately after they are snapped
     * before any more data can be accumulated in order to prevent loss
     * of data between snapshots.
     *
     * @see Consumer#getAggregate(AggregateSpec spec)
     */
    public void
    addClearedAggregationName(String name)
    {
	if (clearedAggregationNames == null) {
	    clearedAggregationNames = new HashSet <String> ();
	}
	clearedAggregationNames.add(name);
    }

    public Set <String>
    getIncludedAggregationNames()
    {
	if (includedAggregationNames == null) {
	    return Collections. <String> emptySet();
	}
	return Collections. <String> unmodifiableSet(includedAggregationNames);
    }

    public Set <String>
    getClearedAggregationNames()
    {
	if (clearedAggregationNames == null) {
	    return Collections. <String> emptySet();
	}
	return Collections. <String> unmodifiableSet(clearedAggregationNames);
    }

    public boolean
    isIncluded(String aggregationName)
    {
	return ((includedAggregationNames == null) ||
		includedAggregationNames.contains(aggregationName));
    }

    public boolean
    isCleared(String aggregationName)
    {
	return ((clearedAggregationNames == null) ||
		clearedAggregationNames.contains(aggregationName));
    }

    public String
    toString()
    {
	StringBuilder buf = new StringBuilder();
	buf.append(AggregateSpec.class.getName());
	buf.append("[includedAggregationNames = ");
	buf.append(Arrays.toString(getIncludedAggregationNames().toArray()));
	buf.append(", clearedAggregationNames = ");
	buf.append(Arrays.toString(getClearedAggregationNames().toArray()));
	buf.append(", includeByDefault = ");
	buf.append(isIncludeByDefault());
	buf.append(", clearByDefault = ");
	buf.append(isClearByDefault());
	buf.append(']');
	return buf.toString();
    }
}
