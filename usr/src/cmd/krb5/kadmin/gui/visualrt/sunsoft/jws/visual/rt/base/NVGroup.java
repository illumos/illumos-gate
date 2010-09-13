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
 * @(#) NVGroup.java 1.11 - last change made 07/25/97
 */

package sunsoft.jws.visual.rt.base;

public abstract class NVGroup extends Group {
    
    public NVGroup() {
        attributes.add(/* NOI18N */"visible", /* NOI18N */
		       "java.lang.Boolean", Boolean.TRUE, HIDDEN | TRANSIENT);
        attributes.add(/* NOI18N */"initialized",
		    /* NOI18N */"java.lang.Boolean", Boolean.TRUE, 0);
    }
    
    public Object get(String key) {
        if (key.equals(/* NOI18N */"initialized"))
            key = /* NOI18N */"visible";
        
        return super.get(key);
    }
    
    public void set(String key, Object value) {
        if (key.equals(/* NOI18N */"initialized"))
            key = /* NOI18N */"visible";
        
        super.set(key, value);
    }
    
    protected Root initRoot() {
        return null;
    }
    
    public void setParentBody() {
    }
    
    public void unsetParentBody() {
    }
    
    protected void removeForwardedAttributes() {
    }
}
