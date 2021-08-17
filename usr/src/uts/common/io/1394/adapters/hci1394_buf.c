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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * hci1394_buf.c
 *   These routines handle IO mapped memory.  They include routines to alloc and
 *   free  IO mapped memory and a routine to get the adapters default dma
 *   attributes. These routines are meant to be called from the base context.
 *   They should not be called from an interrupt handler.
 */

#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/modctl.h>
#include <sys/stat.h>
#include <sys/sunddi.h>
#include <sys/kmem.h>

#include <sys/1394/h1394.h>
#include <sys/1394/adapters/hci1394.h>


/*
 * hci1394_buffer_attr_get()
 *    returns (in dma_attr) the default DMA attributes for this adapter.
 */
void
hci1394_buf_attr_get(ddi_dma_attr_t *dma_attr)
{
	dma_attr->dma_attr_version = DMA_ATTR_V0;
	dma_attr->dma_attr_addr_lo = (uint64_t)0x00000000;
	dma_attr->dma_attr_addr_hi = (uint64_t)0xFFFFFFFF;
	dma_attr->dma_attr_count_max = (uint64_t)0xFFFFFFFF;
	dma_attr->dma_attr_align = 64;
	dma_attr->dma_attr_burstsizes = 0x3FF;
	dma_attr->dma_attr_minxfer = 1;
	dma_attr->dma_attr_maxxfer = (uint64_t)0xFFFFFFFF;
	dma_attr->dma_attr_seg = (uint64_t)0xFFFFFFFF;
	dma_attr->dma_attr_sgllen = 0x7FFFFFFF;
	dma_attr->dma_attr_granular = 4;
	dma_attr->dma_attr_flags = 0;

#if defined(__x86)
	/* XXX - Not sure why x86 wants the dma_attr_seg to be 0x7FFF?? */
	dma_attr->dma_attr_seg = (uint64_t)0x7FFF;
#endif
}


/*
 * hci1394_buf_alloc()
 *    Allocate an IO mapped buffer. drvinfo is passed in and contains generic
 *    driver info, like dip, instance, buf_attr, etc.  Parms is passed in and
 *    contains the input parameters for alloc, ow much memory to alloc, how many
 *    cookies can we handle, and alignment requirements. info is returned with
 *    all the info about the mapped buffer.  handle is returned. It should be
 *    used when calling hci1394_buf_free().
 */
int
hci1394_buf_alloc(hci1394_drvinfo_t *drvinfo, hci1394_buf_parms_t *parms,
    hci1394_buf_info_t *info, hci1394_buf_handle_t *handle)
{
	ddi_dma_attr_t dma_attr;
	hci1394_buf_t *buf;
	int status;


	ASSERT(drvinfo != NULL);
	ASSERT(parms != NULL);
	ASSERT(info != NULL);
	ASSERT(handle != NULL);
	TNF_PROBE_0_DEBUG(hci1394_buf_alloc_enter, HCI1394_TNF_HAL_STACK, "");

	/* alloc the space to keep track of the buffer */
	buf = kmem_alloc(sizeof (hci1394_buf_t), KM_SLEEP);

	/* setup the return parameter */
	*handle = buf;

	/* save away pointer to general info */
	buf->bu_drvinfo = drvinfo;

	/* Get the default DMA attributes and override sgllen and alignment */

	_NOTE(SCHEME_PROTECTS_DATA("unique (on stack)", ddi_dma_attr_t))
	hci1394_buf_attr_get(&dma_attr);
	dma_attr.dma_attr_sgllen = parms->bp_max_cookies;
	dma_attr.dma_attr_align = parms->bp_alignment;

	status = ddi_dma_alloc_handle(drvinfo->di_dip, &dma_attr,
	    DDI_DMA_SLEEP, NULL, &buf->bu_dma_handle);
	if (status != DDI_SUCCESS) {
		kmem_free(buf, sizeof (hci1394_buf_t));
		TNF_PROBE_0(hci1394_buf_alloc_dah_fail, HCI1394_TNF_HAL_ERROR,
		    "");
		TNF_PROBE_0_DEBUG(hci1394_buf_alloc_exit, HCI1394_TNF_HAL_STACK,
		    "");
		return (DDI_FAILURE);
	}

	status = ddi_dma_mem_alloc(buf->bu_dma_handle, parms->bp_length,
	    &drvinfo->di_buf_attr, DDI_DMA_STREAMING, DDI_DMA_SLEEP,
	    NULL, &info->bi_kaddr, &info->bi_real_length, &buf->bu_handle);
	if (status != DDI_SUCCESS) {
		ddi_dma_free_handle(&buf->bu_dma_handle);
		kmem_free(buf, sizeof (hci1394_buf_t));
		TNF_PROBE_0(hci1394_buf_alloc_dam_fail, HCI1394_TNF_HAL_ERROR,
		    "");
		TNF_PROBE_0_DEBUG(hci1394_buf_alloc_exit, HCI1394_TNF_HAL_STACK,
		    "");
		return (DDI_FAILURE);
	}

	status = ddi_dma_addr_bind_handle(buf->bu_dma_handle, NULL,
	    info->bi_kaddr, info->bi_real_length, DDI_DMA_RDWR |
	    DDI_DMA_STREAMING, DDI_DMA_SLEEP, NULL, &info->bi_cookie,
	    &info->bi_cookie_count);
	if (status != DDI_SUCCESS) {
		ddi_dma_mem_free(&buf->bu_handle);
		ddi_dma_free_handle(&buf->bu_dma_handle);
		kmem_free(buf, sizeof (hci1394_buf_t));
		TNF_PROBE_0(hci1394_buf_alloc_dbh_fail, HCI1394_TNF_HAL_ERROR,
		    "");
		TNF_PROBE_0_DEBUG(hci1394_buf_alloc_exit, HCI1394_TNF_HAL_STACK,
		    "");
		return (DDI_FAILURE);
	}

	/* setup rest of buffer info returned to caller */
	info->bi_handle = buf->bu_handle;
	info->bi_dma_handle = buf->bu_dma_handle;
	info->bi_length = parms->bp_length;

	TNF_PROBE_0_DEBUG(hci1394_buf_alloc_exit, HCI1394_TNF_HAL_STACK, "");

	return (DDI_SUCCESS);
}


/*
 * hci1394_buf_free()
 *    Free IO mapped buffer. Notice that a pointer to the handle is used for
 *    the parameter.  free() will set your handle to NULL before returning.
 */
void
hci1394_buf_free(hci1394_buf_handle_t *handle)
{
	hci1394_buf_t *buf;

	ASSERT(handle != NULL);
	TNF_PROBE_0_DEBUG(hci1394_buf_free_enter, HCI1394_TNF_HAL_STACK, "");

	buf = *handle;
	(void) ddi_dma_unbind_handle(buf->bu_dma_handle);
	ddi_dma_mem_free(&buf->bu_handle);
	ddi_dma_free_handle(&buf->bu_dma_handle);

	/* free the space to keep track of the buffer */
	kmem_free(buf, sizeof (hci1394_buf_t));

	/* set the handle to NULL to help catch bugs */
	*handle = NULL;

	TNF_PROBE_0_DEBUG(hci1394_buf_free_exit, HCI1394_TNF_HAL_STACK, "");
}
