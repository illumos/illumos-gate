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
 * Copyright 1998-2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
package com.sun.dhcpmgr.data;

import java.io.Serializable;
import java.util.Vector;
import java.text.MessageFormat;

/**
 * OptionValue is an abstract superclass for all the actual types of options
 * which may be stored in a macro.
 */
public abstract class OptionValue implements Serializable, Cloneable {

    // Serialization id for this class
    static final long serialVersionUID = -1346853613202192887L;

    public abstract String getName();
    public abstract String getValue();
    public abstract void setValue(Object value) throws ValidationException;
    public abstract boolean isValid();
    public abstract Object clone();

    protected void throwException(String msgid, Object [] args)
	throws ValidationException {
	MessageFormat form = new MessageFormat(
	    ResourceStrings.getString(msgid));
	String msg = form.format(args);
	throw new ValidationException(msg);
    }
}
