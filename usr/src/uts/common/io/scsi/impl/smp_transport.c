/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/byteorder.h>
#include <sys/scsi/scsi.h>

static int
smp_device_prop_update_inqstring(struct smp_device *smp_sd,
    char *name, char *data, size_t len)
{
	int	ilen;
	char	*data_string;
	int	rv;

	/* SMP information follows SCSI INQUIRY rules */
	ilen = scsi_ascii_inquiry_len(data, len);
	ASSERT(ilen <= (int)len);
	if (ilen <= 0)
		return (DDI_PROP_INVAL_ARG);

	/* ensure null termination */
	data_string = kmem_zalloc(ilen + 1, KM_SLEEP);
	bcopy(data, data_string, ilen);
	rv = ndi_prop_update_string(DDI_DEV_T_NONE,
	    smp_sd->smp_sd_dev, name, data_string);
	kmem_free(data_string, ilen + 1);
	return (rv);
}

/*
 * smp_probe: probe device and create inquiry-like properties.
 */
int
smp_probe(struct smp_device *smp_sd)
{
	smp_pkt_t				*smp_pkt;
	smp_pkt_t				smp_pkt_data;
	smp_request_frame_t			*srq;
	smp_response_frame_t			*srs;
	smp_report_manufacturer_info_resp_t	*srmir;
	int					ilen, clen;
	char					*component;
	uint8_t			srq_buf[SMP_REQ_MINLEN];
	uint8_t			srs_buf[SMP_RESP_MINLEN + sizeof (*srmir)];

	srq = (smp_request_frame_t *)srq_buf;
	bzero(srq, sizeof (srq_buf));
	srq->srf_frame_type = SMP_FRAME_TYPE_REQUEST;
	srq->srf_function = SMP_FUNC_REPORT_MANUFACTURER_INFO;

	smp_pkt = &smp_pkt_data;
	bzero(smp_pkt, sizeof (*smp_pkt));
	smp_pkt->smp_pkt_address = &smp_sd->smp_sd_address;
	smp_pkt->smp_pkt_req = (caddr_t)srq;
	smp_pkt->smp_pkt_reqsize = sizeof (srq_buf);
	smp_pkt->smp_pkt_rsp = (caddr_t)srs_buf;
	smp_pkt->smp_pkt_rspsize = sizeof (srs_buf);
	smp_pkt->smp_pkt_timeout = SMP_DEFAULT_TIMEOUT;

	bzero(srs_buf, sizeof (srs_buf));

	if (smp_transport(smp_pkt) != DDI_SUCCESS) {
		/*
		 * The EOVERFLOW should be excluded here, because it indicates
		 * the buffer (defined according to SAS1.1 Spec) to store
		 * response is shorter than transferred message frame.
		 * In this case, the smp device is alive and should be
		 * enumerated.
		 */
		if (smp_pkt->smp_pkt_reason != EOVERFLOW)
			return (DDI_PROBE_FAILURE);
	}

	/*
	 * NOTE: Deal with old drivers (mpt, mpt_sas) that allocate
	 * 'struct smp_device' on the stack.  When these drivers convert to
	 * SCSAv3, the check for a NULL smp_sd_dev can be removed.
	 */
	if (smp_sd->smp_sd_dev == NULL)
		return (DDI_PROBE_SUCCESS);

	/* Save raw response data for devid */
	srs = (smp_response_frame_t *)srs_buf;
	if (srs->srf_result != SMP_RES_FUNCTION_ACCEPTED)
		return (DDI_PROBE_SUCCESS);

	/*
	 * Convert smp_report_manufacturer_info_resp_t data into properties.
	 * NOTE: since things show up in the oposite order in prtconf, we are
	 * going from detailed information to generic here.
	 */
	srmir = (smp_report_manufacturer_info_resp_t *)&srs->srf_data[0];
	if (srmir->srmir_sas_1_1_format) {
		/* Establish 'component' property. */
		ilen = scsi_ascii_inquiry_len(
		    srmir->srmir_component_vendor_identification,
		    sizeof (srmir->srmir_component_vendor_identification));
		if (ilen > 0) {
			/* component value format is '%s.%05d.%03d' */
			clen = ilen + 1 + 5 + 1 + 3 + 1;
			component = kmem_zalloc(clen, KM_SLEEP);
			bcopy(srmir->srmir_component_vendor_identification,
			    component, ilen);
			(void) snprintf(&component[ilen], clen - ilen,
			    ".%05d.%03d", BE_16(srmir->srmir_component_id),
			    srmir->srmir_component_revision_level);
			if (ddi_prop_exists(DDI_DEV_T_NONE, smp_sd->smp_sd_dev,
			    DDI_PROP_DONTPASS | DDI_PROP_NOTPROM,
			    "component") == 0)
				(void) ndi_prop_update_string(DDI_DEV_T_NONE,
				    smp_sd->smp_sd_dev, "component", component);
			kmem_free(component, clen);
		}
	}
	/* First one to define the property wins */
	if (ddi_prop_exists(DDI_DEV_T_NONE, smp_sd->smp_sd_dev,
	    DDI_PROP_DONTPASS | DDI_PROP_NOTPROM, INQUIRY_REVISION_ID) == 0)
		(void) smp_device_prop_update_inqstring(smp_sd,
		    INQUIRY_REVISION_ID, srmir->srmir_product_revision_level,
		    sizeof (srmir->srmir_product_revision_level));

	if (ddi_prop_exists(DDI_DEV_T_NONE, smp_sd->smp_sd_dev,
	    DDI_PROP_DONTPASS | DDI_PROP_NOTPROM, INQUIRY_PRODUCT_ID) == 0)
		(void) smp_device_prop_update_inqstring(smp_sd,
		    INQUIRY_PRODUCT_ID, srmir->srmir_product_identification,
		    sizeof (srmir->srmir_product_identification));

	if (ddi_prop_exists(DDI_DEV_T_NONE, smp_sd->smp_sd_dev,
	    DDI_PROP_DONTPASS | DDI_PROP_NOTPROM, INQUIRY_VENDOR_ID) == 0)
		(void) smp_device_prop_update_inqstring(smp_sd,
		    INQUIRY_VENDOR_ID, srmir->srmir_vendor_identification,
		    sizeof (srmir->srmir_vendor_identification));

	/* NOTE: SMP_PROP_REPORT_MANUFACTURER is deleted after devid created */
	if (ddi_prop_exists(DDI_DEV_T_NONE, smp_sd->smp_sd_dev,
	    DDI_PROP_DONTPASS | DDI_PROP_NOTPROM,
	    SMP_PROP_REPORT_MANUFACTURER) == 0)
		(void) ndi_prop_update_byte_array(DDI_DEV_T_NONE,
		    smp_sd->smp_sd_dev, SMP_PROP_REPORT_MANUFACTURER,
		    (uchar_t *)srs, sizeof (srs_buf));

	return (DDI_PROBE_SUCCESS);
}

int
smp_transport(struct smp_pkt *smp_pkt)
{
	return (smp_pkt->smp_pkt_address->
	    smp_a_hba_tran->smp_tran_start(smp_pkt));
}
