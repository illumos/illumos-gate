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
 * ident	"%Z%%M%	%I%	%E% SMI"
 *
 * Copyright (c) 2000 by Sun Microsystems, Inc.
 * All rights reserved.
 */

/*
 *        Copyright (C) 1996  Active Software, Inc.
 *                  All rights reserved.
 *
 * @(#) RootObserver.java 1.4 - last change made 04/25/96
 */

package sunsoft.jws.visual.rt.base;

/**
 * Interface to be provided by those who which to watch
 * the comings and
 * goings of WindowShadows and Groups in a particular Root
 * object.  This
 * is used in the visual designer to keep a list of the
 * top-level windows
 * currently under the main application root.
 * It registers itself as an
 * observer with the root object and then through this
 * interface receives
 * updates.
 *
 * @version 	1.4, 04/25/96
 */
public interface RootObserver {
    public void add(AttributeManager mgr);
    public void remove(AttributeManager mgr);
    public void select(AttributeManager mgr);
    public void clear();
}
