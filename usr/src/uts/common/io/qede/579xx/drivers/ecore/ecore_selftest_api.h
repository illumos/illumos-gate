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

#ifndef __ECORE_SELFTEST_API_H__
#define __ECORE_SELFTEST_API_H__

#include "ecore_status.h"

/**
 * @brief ecore_selftest_memory - Perform memory test
 *
 * @param p_dev
 *
 * @return enum _ecore_status_t
 */
enum _ecore_status_t ecore_selftest_memory(struct ecore_dev *p_dev);

/**
 * @brief ecore_selftest_interrupt - Perform interrupt test
 *
 * @param p_dev
 *
 * @return enum _ecore_status_t
 */
enum _ecore_status_t ecore_selftest_interrupt(struct ecore_dev *p_dev);

/**
 * @brief ecore_selftest_register - Perform register test
 *
 * @param p_dev
 *
 * @return enum _ecore_status_t
 */
enum _ecore_status_t ecore_selftest_register(struct ecore_dev *p_dev);

/**
 * @brief ecore_selftest_clock - Perform clock test
 *
 * @param p_dev
 *
 * @return enum _ecore_status_t
 */
enum _ecore_status_t ecore_selftest_clock(struct ecore_dev *p_dev);

/**
 * @brief ecore_selftest_nvram - Perform nvram test
 *
 * @param p_dev
 *
 * @return enum _ecore_status_t
 */
enum _ecore_status_t ecore_selftest_nvram(struct ecore_dev *p_dev);
#endif
