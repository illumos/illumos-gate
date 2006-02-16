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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * ident	"%Z%%M%	%I%	%E% SMI"
 */
package org.opensolaris.os.dtrace;

/**
 * A value accumulated by an aggregating DTrace action such as {@code
 * count()} or {@code sum()}.  Each {@code AggregationValue} is
 * associated with a {@link Tuple} in an {@link AggregationRecord}.  In
 * other words it is a value in a key-value pair (each pair representing
 * an entry in a DTrace aggregation).
 * <p>
 * This value may be a single number or consist of multiple numbers,
 * such as a value distribution.  In the latter case, it still has a
 * single, composite value useful for display and/or comparison.
 *
 * @see AggregationRecord
 *
 * @author Tom Erickson
 */
public interface AggregationValue {
    /**
     * Gets the numeric value of this instance.
     *
     * @return non-null numeric value
     */
    public Number getValue();
}
