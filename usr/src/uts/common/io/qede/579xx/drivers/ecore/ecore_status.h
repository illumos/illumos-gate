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

#ifndef __ECORE_STATUS_H__
#define __ECORE_STATUS_H__

enum _ecore_status_t {
	ECORE_CONN_REFUSED = -14,
	ECORE_CONN_RESET = -13,
	ECORE_UNKNOWN_ERROR  = -12,
	ECORE_NORESOURCES	 = -11,
	ECORE_NODEV   = -10,
	ECORE_ABORTED = -9,
	ECORE_AGAIN   = -8,
	ECORE_NOTIMPL = -7,
	ECORE_EXISTS  = -6,
	ECORE_IO      = -5,
	ECORE_TIMEOUT = -4,
	ECORE_INVAL   = -3,
	ECORE_BUSY    = -2,
	ECORE_NOMEM   = -1,
	ECORE_SUCCESS = 0,
	/* PENDING is not an error and should be positive */
	ECORE_PENDING = 1,
};

#endif /* __ECORE_STATUS_H__ */

