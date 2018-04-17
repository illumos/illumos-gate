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

#include "bcm_osal.h"
#include "ecore.h"
#include "ecore_sp_commands.h"
#include "ecore_dev_api.h"
#include "ecore_mcp.h"
#include "nvm_map.h"
#include "ecore_selftest_api.h"

enum _ecore_status_t ecore_selftest_memory(struct ecore_dev *p_dev)
{
	enum _ecore_status_t rc = ECORE_SUCCESS;
	int i;

	for_each_hwfn(p_dev, i) {
		rc = ecore_sp_heartbeat_ramrod(&p_dev->hwfns[i]);
		if (rc != ECORE_SUCCESS)
			return rc;
	}

	return rc;
}

enum _ecore_status_t ecore_selftest_interrupt(struct ecore_dev *p_dev)
{
	enum _ecore_status_t rc = ECORE_SUCCESS;
	int i;

	for_each_hwfn(p_dev, i) {
		rc = ecore_sp_heartbeat_ramrod(&p_dev->hwfns[i]);
		if (rc != ECORE_SUCCESS)
			return rc;
	}

	return rc;
}

enum _ecore_status_t ecore_selftest_register(struct ecore_dev *p_dev)
{
	struct ecore_hwfn *p_hwfn;
	struct ecore_ptt *p_ptt;
	enum _ecore_status_t rc = ECORE_SUCCESS;
	int i;


	/* although performed by MCP, this test is per engine */
	for_each_hwfn(p_dev, i) {
		p_hwfn = &p_dev->hwfns[i];
		p_ptt = ecore_ptt_acquire(p_hwfn);
		if (!p_ptt) {
			DP_ERR(p_hwfn, "failed to acquire ptt\n");
			return ECORE_BUSY;
		}
		rc = ecore_mcp_bist_register_test(p_hwfn, p_ptt);
		ecore_ptt_release(p_hwfn, p_ptt);
		if (rc != ECORE_SUCCESS)
			break;
	}

	return rc;
}

enum _ecore_status_t ecore_selftest_clock(struct ecore_dev *p_dev)
{
	struct ecore_hwfn *p_hwfn;
	struct ecore_ptt *p_ptt;
	enum _ecore_status_t rc = ECORE_SUCCESS;
	int i;

	/* although performed by MCP, this test is per engine */
	for_each_hwfn(p_dev, i) {
		p_hwfn = &p_dev->hwfns[i];
		p_ptt = ecore_ptt_acquire(p_hwfn);
		if (!p_ptt) {
			DP_ERR(p_hwfn, "failed to acquire ptt\n");
			return ECORE_BUSY;
		}
		rc = ecore_mcp_bist_clock_test(p_hwfn, p_ptt);
		ecore_ptt_release(p_hwfn, p_ptt);
		if (rc != ECORE_SUCCESS)
			break;
	}

	return rc;
}

enum _ecore_status_t ecore_selftest_nvram(struct ecore_dev *p_dev)
{
	struct ecore_hwfn *p_hwfn = ECORE_LEADING_HWFN(p_dev);
	struct ecore_ptt *p_ptt = ecore_ptt_acquire(p_hwfn);
	u32 num_images, i, j, nvm_crc, calc_crc;
	struct bist_nvm_image_att image_att;
	u8 *buf = OSAL_NULL;
	OSAL_BE32 val;
	enum _ecore_status_t rc;

	if (!p_ptt) {
		DP_ERR(p_hwfn, "failed to acquire ptt\n");
		return ECORE_BUSY;
	}

	/* Acquire from MFW the amount of available images */
	rc = ecore_mcp_bist_nvm_test_get_num_images(p_hwfn, p_ptt, &num_images);
	if ((rc != ECORE_SUCCESS) || (num_images == 0)) {
		DP_ERR(p_hwfn, "Failed getting number of images\n");
		return ECORE_INVAL;
	}

	/* Iterate over images and validate CRC */
	for (i = 0; i < num_images; i++) {
		/* This mailbox returns information about the image required for
		 * reading it.
		 */
		rc = ecore_mcp_bist_nvm_test_get_image_att(p_hwfn, p_ptt,
							   &image_att, i);
		if (rc != ECORE_SUCCESS) {
			DP_ERR(p_hwfn,
			       "Failed getting image index %d attributes\n",
			       i);
			goto err0;
		}

		/* After MFW crash dump is collected - the image's CRC stops
		 * being valid.
		 */
		if (image_att.image_type == NVM_TYPE_MDUMP)
			continue;

		DP_VERBOSE(p_hwfn, ECORE_MSG_SP, "image index %d, size %x\n", i,
			   image_att.len);

		/* Allocate a buffer for holding the nvram image */
		buf = OSAL_ZALLOC(p_hwfn->p_dev, GFP_KERNEL, image_att.len);
		if (!buf) {
			DP_ERR(p_hwfn,
			       "Failed allocating memory for image index %d.\n",
			       i);
			rc = ECORE_NOMEM;
			goto err0;
		}

		/* Read image into buffer */
		rc = ecore_mcp_nvm_read(p_hwfn->p_dev, image_att.nvm_start_addr,
					buf, image_att.len);
		if (rc != ECORE_SUCCESS) {
			DP_ERR(p_hwfn,
			       "Failed reading image index %d from nvm.\n", i);
			goto err1;
		}

		/* Convert the buffer into big-endian format (excluding the
		 * closing 4 bytes of CRC).
		 */
		for (j = 0; j < image_att.len - 4; j += 4) {
			val = OSAL_CPU_TO_BE32(*(u32 *)&buf[j]);
			*(u32 *)&buf[j] = val;
		}

		/* Calc CRC for the "actual" image buffer, i.e. not including
		 * the last 4 CRC bytes.
		 */
		nvm_crc = *(u32 *)(buf + image_att.len - 4);
		calc_crc = OSAL_CRC32(0xffffffff , buf, image_att.len - 4);
		calc_crc = ~OSAL_CPU_TO_BE32(calc_crc);
		DP_VERBOSE(p_hwfn, ECORE_MSG_SP,
			   "nvm crc 0x%x, calc_crc 0x%x\n", nvm_crc, calc_crc);

		if (calc_crc != nvm_crc) {
			rc = ECORE_UNKNOWN_ERROR;
			goto err1;
		}

		/* Done with this image */
		OSAL_FREE(p_hwfn->p_dev, buf);
		buf = OSAL_NULL;
	}

	ecore_ptt_release(p_hwfn, p_ptt);
	return ECORE_SUCCESS;

err1:
	OSAL_FREE(p_hwfn->p_dev, buf);
err0:
	ecore_ptt_release(p_hwfn, p_ptt);
	return rc;
}

