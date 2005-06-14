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
 * Copyright (c) 2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */
package com.sun.dhcpmgr.cli.pntadm;

import com.sun.dhcpmgr.cli.dhcpbatch.*;

import java.lang.IllegalArgumentException;

/**
 * The main class for the batch functionality of pntadm.
 */
public class PntAdmBatch extends PntAdmFunction {

    /**
     * The valid options associated with batching.
     */
    static final int supportedOptions[] = {
	PntAdm.VERBOSE
    };

    private String inputSource = null;

    /**
     * Constructs a PntAdmBatch object.
     */
    public PntAdmBatch(String inputSource) {

	this.inputSource = inputSource;
	validOptions = supportedOptions;

    } // constructor

    /**
     * Returns the option flag for this function.
     * @returns the option flag for this function.
     */
    public int getFunctionFlag() {
	return (PntAdm.BATCH_EXECUTION);
    }

    /**
     * Executes the batch functionality.
     * @return one of the PntAdm return codes.
     */
    public int execute()
	throws IllegalArgumentException {

	DhcpBatch batch = new DhcpBatch(inputSource);
	batch.setVerbose(options.isSet(PntAdm.VERBOSE));
	return (batch.execute());

    } // execute

} // PntAdmBatch
