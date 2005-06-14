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

package sunsoft.jws.visual.rt.shadow.java.awt;

import sunsoft.jws.visual.rt.shadow.java.awt.*;
import sunsoft.jws.visual.rt.base.*;
import sunsoft.jws.visual.rt.awt.*;
import sunsoft.jws.visual.rt.base.Global;

public abstract class BeanComponentShadow extends ComponentShadow
    implements BeanableComponent {
    
    protected boolean bodyCreated = false;
    protected Object beanBody = null;
    
    // boolean needsBeans() is defined in subclasses
    // boolean needsJDK1_1() is defined in subclasses
    
    private boolean hasDeserialized = false;	// should only deserialize once
    
    protected Object getOnBody(String key) {
        if (key.equals(/* NOI18N */"serializationData")) {
            if (!bodyCreated || getBody() == null) {
                return null;
            }
            return BeanSerialization.serializeObject(getBody());
        } else {
            return (super.getOnBody(key));
        }
    }
    
    protected void setOnBody(String key, Object value) {
        if (key.equals(/* NOI18N */"serializationData") && !hasDeserialized) {
            if (!bodyCreated || getBody() == null) {
                return;
            }
            Object newBody = BeanSerialization.deserializeObject(
		    (String)value, getName());
            if (newBody != null) {
                body = beanBody = newBody;
                hasDeserialized = true;
                DesignerAccess.getShadowTable().put(body, this);
            }
        } else {
            super.setOnBody(key, value);
        }
    }
}
