/*
 * Copyright 2014-2017 Cavium, Inc.
 * The contents of this file are subject to the terms of the Common Development
 * and Distribution License, v.1,  (the "License").
 *
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the License at available
 * at http://opensource.org/licenses/CDDL-1.0
 *
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#ifndef	_MM_H_
#define	_MM_H_

#include "bnx_mm.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Add some preprocessor definitions that
 * should technically be part of the LM.
 */
#define	LM_HC_RX_QUICK_CONS_TRIP_VAL_MAX	256
#define	LM_HC_RX_QUICK_CONS_TRIP_INT_MAX	256

#define	LM_HC_RX_TICKS_VAL_MAX			511
#define	LM_HC_RX_TICKS_INT_MAX			1023


#define	mm_indicate_rx(a, b, c, d)

#ifdef __cplusplus
}
#endif

#endif /* _MM_H_ */
