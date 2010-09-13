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
 * Copyright (c) 1999-2000 by Sun Microsystems, Inc.
 * All rights reserved.
 */

/**
 * Copyright 1996 Active Software Inc. 
 */

package sunsoft.jws.visual.rt.encoding;


public class CRC16
{
    
    public CRC16()
    {
        super();
        value = 0;
    }
    
    public void update(byte aByte)
    {
        int a = aByte;
        for (int count = 7; count >= 0; count--)
	    {
		a <<= 1;
		int b = a >>> 8 & 0x1;
		if ((value & 0x8000) != 0)
		    value = (value << 1) + b ^ 0x1021;
		else
		    value = (value << 1) + b;
	    }
        
        value = value & 0xffff;
    }
    
    public void reset()
    {
        value = 0;
    }
    
    public int value;
}
