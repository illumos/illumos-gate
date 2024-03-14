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
 * Copyright (c) 1999 by Sun Microsystems, Inc.
 * All rights reserved.
 *
 */

//  SrvLocMsgImpl.java:  SrvLocMsg implementation.
//  Author:           James Kempf
//  Created On:       Tue Sep 15 10:06:27 1998
//  Last Modified By: James Kempf
//  Last Modified On: Sun Oct 11 17:11:13 1998
//  Update Count:     8
//

package com.sun.slp;

import java.util.*;

/**
 * The SrvLocMsgImpl class is the base class for all SLPv2 side SrvLocMsg
 * implementations.
 *
 * @author James Kempf
 */

abstract class SrvLocMsgImpl extends Object implements SrvLocMsg {

    protected SrvLocHeader hdr = null;

    // For creating outgoing messages.

    SrvLocMsgImpl() {}

    // Check and set the header.

    SrvLocMsgImpl(SrvLocHeader hdr, int functionCode)
	throws ServiceLocationException {

	if (hdr.functionCode != functionCode) {
	    throw
		new ServiceLocationException(
			ServiceLocationException.NETWORK_ERROR,
			"wrong_reply_type",
			new Object[] {Integer.valueOf(hdr.functionCode)});
	}

	this.hdr = hdr;

    }

    // Return the header.

    public SrvLocHeader getHeader() {
	return hdr;
    }

    // Return the error code, via the header.

    public short getErrorCode() {
	return hdr.errCode;
    }

}
