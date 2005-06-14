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
 * @(#) RegistryEntry.java 1.3 - last change made 04/25/96
 */

package sunsoft.jws.visual.rt.base;

/**
 * The Registry publisher entry.
 */
public class RegistryEntry {
    public RegistryEntry(String pub_name,
			 String pub_description,
			 Object pub_object) {
        name = pub_name;
        description = pub_description;
        obj = pub_object;
    }
    
    public RegistryEntry(RegistryEntry re) {
        name = re.name;
        description = re.description;
    }
    
    String name;
    String description;
    Object obj;
}
