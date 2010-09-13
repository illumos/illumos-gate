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

/**
 * ColumnListThread.java
 *
 * Copyright 1995-1996 Active Software Inc.
 *
 * @version @(#)ColumnListThread.java 1.11 97/06/17
 * @author  Tilman Sporkert
 */

package sunsoft.jws.visual.rt.awt;

import sunsoft.jws.visual.rt.base.Global;


/**
 * A simple class that provides timing for fading colors in highlighted 
 * ColumnList rows
 *
 * @author  Tilman Sporkert
 */
class ColumnListThread extends Thread {
    private ColumnListCanvas parent;
    
    /**
     * ...
     *
     * @param ...    ...
     * @return       ...
     * @exception    ...
     */
    public ColumnListThread(ColumnListCanvas parentIn) {
        parent = parentIn;
    }
    
    /**
     * ...
     *
     * @param ...    ...
     * @return       ...
     * @exception    ...
     */
    public void run() {
        setPriority(Thread.MIN_PRIORITY);
        int i = 0;
        while (true) {
            try {
                // System.out.println("Thread goes to sleep..." + i);
                Thread.currentThread().sleep(3000);
            } catch (Exception e) {
                /* JSTYLED */
		System.out.println(Global.getMsg("sunsoft.jws.visual.rt.awt.ColumnListThread.Exception__in__sleep-co-__.2") + e);
            }
            i++;
            if (!parent.updateRowColors()) {
                // System.out.println("Done changing, stopping thread...");
                Thread.currentThread().suspend();
            }
            
        }
    }
    
    
}
