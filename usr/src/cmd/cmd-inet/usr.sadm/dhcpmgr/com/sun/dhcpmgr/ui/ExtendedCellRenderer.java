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
 * Copyright (c) 1998-1999 by Sun Microsystems, Inc.
 * All rights reserved.
 */
package com.sun.dhcpmgr.ui;

import javax.swing.table.DefaultTableCellRenderer;
import java.util.Date;
import java.text.DateFormat;
import java.net.InetAddress;
import com.sun.dhcpmgr.data.IPAddress;

// Renderer for cells containing Dates, InetAddresses or IPAddresses
public class ExtendedCellRenderer extends DefaultTableCellRenderer {
    private DateFormat dateFormat = DateFormat.getInstance();

    protected void setValue(Object value) {
	if (value != null) {
	    if (value instanceof Date) {
		long t = ((Date)value).getTime();
		if (t == 0) {
		    super.setValue(null);
		} else if (t < 0) {
		    super.setValue(ResourceStrings.getString("never"));
		} else {
		    super.setValue(dateFormat.format(value));
		}
	    } else if (value instanceof InetAddress) {
		super.setValue(((InetAddress)value).getHostAddress());
	    } else if (value instanceof IPAddress) {
		super.setValue(((IPAddress)value).getHostAddress());
	    } else {
		super.setValue(value);
	    }
	} else {
	    super.setValue(value);
	}
    }
}
