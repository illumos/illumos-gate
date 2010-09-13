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

//  ServiceURLV1.java: SLPv1 Service URL class.
//  Author:           James Kempf
//  Created On:       Fri Oct  9 19:08:53 1998
//  Last Modified By: James Kempf
//  Last Modified On: Wed Oct 14 17:00:08 1998
//  Update Count:     3
//

package com.sun.slp;

import java.util.*;
import java.io.*;

/**
 * ServiceURLV1 enforces no abstract types and no non-service: URL types for
 * SLPv1 queries.
 *
 * @author James Kempf
 */

class ServiceURLV1 extends ServiceURL implements Serializable {

    ServiceURLV1(String URL, int iLifetime) throws IllegalArgumentException {
	super(URL, iLifetime);

	ServiceType serviceType = this.getServiceType();

	// Check for illegal service types.

	if (serviceType.isAbstractType()) {
	    throw
		new IllegalArgumentException(
		SLPConfig.getSLPConfig().formatMessage("v1_abstract_type",
						       new Object[0]));

	}

	if (!serviceType.isServiceURL()) {
	    throw
		new IllegalArgumentException(
			SLPConfig.getSLPConfig().formatMessage("v1_not_surl",
							       new Object[0]));

	}
    }
}
