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

/****************************************************************************
 * Name:        mfw_sig_meta.h
 *
 ****************************************************************************/

#ifndef MFW_SIG_META_H
#define MFW_SIG_META_H

#define SIGNATURE_MAX_DER_SIZE 128
#define SIG_ID_LIM (0)
#define SIG_ID_TIM (1)
#define SIG_ID_MIM (2)
#define SIG_ID_MAX (3)
#define SIG_ID_NONE (SIG_ID_MAX)

#define MFW_DIGEST_SIZE (32)
#define SIG_META_VERSION (1)
struct sig_meta_group {
	uint32_t signature_offset;
	uint8_t  digest[MFW_DIGEST_SIZE];            

};

struct mfw_sig_meta {
	uint32_t version;
	struct sig_meta_group group[SIG_ID_MAX];
};

#endif				/*MFW_SIG_META_H */
