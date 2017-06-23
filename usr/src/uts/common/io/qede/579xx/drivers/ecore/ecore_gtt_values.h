/*
* CDDL HEADER START
*
* The contents of this file are subject to the terms of the
* Common Development and Distribution License, v.1,  (the "License").
* You may not use this file except in compliance with the License.
*
* You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
* or http://opensource.org/licenses/CDDL-1.0.
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
* Copyright 2014-2017 Cavium, Inc. 
* The contents of this file are subject to the terms of the Common Development 
* and Distribution License, v.1,  (the "License").

* You may not use this file except in compliance with the License.

* You can obtain a copy of the License at available 
* at http://opensource.org/licenses/CDDL-1.0

* See the License for the specific language governing permissions and 
* limitations under the License.
*/

#ifndef __PREVENT_PXP_GLOBAL_WIN__

static u32 pxp_global_win[] = {
	0,
	0,
	0x1c02, /* win 2: addr=0x1c02000, size=4096 bytes */
	0x1c80, /* win 3: addr=0x1c80000, size=4096 bytes */
	0x1d00, /* win 4: addr=0x1d00000, size=4096 bytes */
	0x1d01, /* win 5: addr=0x1d01000, size=4096 bytes */
	0x1d80, /* win 6: addr=0x1d80000, size=4096 bytes */
	0x1d81, /* win 7: addr=0x1d81000, size=4096 bytes */
	0x1d82, /* win 8: addr=0x1d82000, size=4096 bytes */
	0x1e00, /* win 9: addr=0x1e00000, size=4096 bytes */
	0x1e80, /* win 10: addr=0x1e80000, size=4096 bytes */
	0x1f00, /* win 11: addr=0x1f00000, size=4096 bytes */
	0,
	0,
	0,
	0,
	0,
	0,
	0,
};

#endif /* __PREVENT_PXP_GLOBAL_WIN__ */
