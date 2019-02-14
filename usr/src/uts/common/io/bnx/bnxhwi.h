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
 */

#ifndef _BNXHWI_H
#define	_BNXHWI_H

#include "bnx.h"

#ifdef __cplusplus
extern "C" {
#endif

int  bnx_hdwr_init(um_device_t * const umdevice);
int  bnx_hdwr_acquire(um_device_t * const umdevice);
void bnx_hdwr_release(um_device_t * const umdevice);
void bnx_hdwr_fini(um_device_t * const umdevice);

#ifdef __cplusplus
}
#endif

#endif /* _BNXHWI_H */
