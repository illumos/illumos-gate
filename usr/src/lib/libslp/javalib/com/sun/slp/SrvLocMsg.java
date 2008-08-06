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

//  SrvLocMsg.java:   Abstract class for all SLP message objects.
//  Author:           James Kempf
//  Created On:       Mon Sep 14 13:03:22 1998
//  Last Modified By: James Kempf
//  Last Modified On: Tue Sep 15 09:51:56 1998
//  Update Count:     4
//

package com.sun.slp;

import java.util.*;
import java.net.*;
import java.io.*;

/**
 * SrvLocMsg is an interface supported by all SLP message objects,
 * regardless of type.
 *
 * @author James Kempf
 */

interface SrvLocMsg {

    // Return the header object.

    abstract SrvLocHeader getHeader();

    // Return the error code.

    abstract short getErrorCode();

}
