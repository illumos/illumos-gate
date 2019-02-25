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
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 2019, Joyent, Inc.
 */

#ifndef _BNXINT_H
#define	_BNXINT_H

#include "bnx.h"

#ifdef __cplusplus
extern "C" {
#endif

void bnx_intr_enable(um_device_t *const);
void bnx_intr_disable(um_device_t *const);

int  bnxIntrInit(um_device_t *);
void bnxIntrFini(um_device_t *);

#ifdef __cplusplus
}
#endif

#endif /* _BNXINT_H */
