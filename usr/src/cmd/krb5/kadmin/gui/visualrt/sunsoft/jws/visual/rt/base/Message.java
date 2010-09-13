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
 * @(#) Message.java 1.14 - last change made 07/25/97
 */

package sunsoft.jws.visual.rt.base;

/**
 * An event structure that can hold either an AWT event
 * or a specialized
 * event passed between Group objects.
 *
 * @version 	1.7, 23 Apr 1996
 */
public class Message {
    public String name;
    public Object arg;
    public Object target;
    public long when;
    
    public String type;
    public String targetName;
    public boolean isAWT;
    
    public Message() {
        this(null, null, null, /* NOI18N */"", null);
    }
    
    public Message(Object target, String name, Object arg) {
        this(target, null, null, name, arg);
    }
    
    public Message(Object target, String name, Object arg, boolean isAWT) {
        this(target, null, null, name, arg);
        this.isAWT = isAWT;
    }
    
    public Message(Object target, String targetName, String type, String name,
		   Object arg) {
        this.target = target;
        this.name = name;
        this.arg = arg;
        this.when = System.currentTimeMillis();
        this.type = type;
        this.targetName = targetName;
        this.isAWT = false;
    }
    
    public Message(Message msg) {
        this(msg.target, msg.targetName, msg.type, msg.name, msg.arg);
        this.isAWT = msg.isAWT;
        this.when = msg.when;
    }
}
