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

#include <sys/scsi/scsi.h>

static void sas_gen_smp_crc(uint32_t *frame, size_t len);

/*
 * Function: query capability from SAS HBA driver
 * Return value: 0, capability supported
 *               EINVAL, unknown capability
 *               ENOTSUP, known capability but unsupported
 */
int
sas_ifgetcap(struct sas_addr *ap, char *cap)
{
	if (ap->a_hba_tran && ap->a_hba_tran->tran_sas_getcap)
		return (ap->a_hba_tran->tran_sas_getcap(ap, cap));
	return (EINVAL);
}

int
sas_smp_transport(struct smp_pkt *pkt)
{
	struct sas_addr *ap = pkt->pkt_address;
	if (sas_ifgetcap(ap, "smp-crc") != 0) {
		sas_gen_smp_crc((uint32_t *)(pkt->pkt_req), pkt->pkt_reqsize);
	}
	return (ap->a_hba_tran->tran_smp_start(pkt));
}

int
sas_hba_probe_smp(struct smp_device *smp_devp)
{
	smp_pkt_t smp_pkt_data, *smp_pkt = &smp_pkt_data;
	uint8_t reqbuf[SMP_REQ_MINLEN];
	uint8_t respbuf[SMP_RESP_MINLEN + sizeof (smp_report_general_resp_t)];
	smp_request_frame_t *qfp = (smp_request_frame_t *)reqbuf;
	smp_report_general_resp_t *sfp = (smp_report_general_resp_t *)respbuf;
	int rval = DDI_PROBE_SUCCESS;

	bzero(reqbuf, sizeof (reqbuf));
	bzero(respbuf, sizeof (respbuf));
	qfp->srf_frame_type = SMP_FRAME_TYPE_REQUEST;
	qfp->srf_function = SMP_FUNC_REPORT_GENERAL;

	bzero(smp_pkt, sizeof (struct smp_pkt));
	smp_pkt->pkt_address = &smp_devp->smp_addr;
	smp_pkt->pkt_reason = 0;
	smp_pkt->pkt_req = (caddr_t)qfp;
	smp_pkt->pkt_reqsize = sizeof (reqbuf);
	smp_pkt->pkt_rsp = (caddr_t)sfp;
	smp_pkt->pkt_rspsize = sizeof (respbuf);
	smp_pkt->pkt_timeout = SMP_DEFAULT_TIMEOUT;

	if (sas_smp_transport(smp_pkt) != DDI_SUCCESS) {
		/*
		 * The EOVERFLOW should be excluded here, because it indicates
		 * the buffer (defined according to SAS1.1 Spec) to store
		 * response is shorter than transferred message frame.
		 * In this case, the smp device is alive and should be
		 * enumerated.
		 */
		if (smp_pkt->pkt_reason != EOVERFLOW) {
			rval = DDI_PROBE_FAILURE;
		}
	}

	return (rval);
}

int
sas_hba_lookup_capstr(char *capstr)
{
	/*
	 * Capability strings, masking the the '-' vs. '_' misery
	 */
	static struct cap_strings {
		char	*cap_string;
		int	cap_index;
	} cap_strings[] = {
		{ "smp-crc",		SAS_CAP_SMP_CRC	},
		{ NULL,			0		}
	};
	struct cap_strings	*cp;

	for (cp = cap_strings; cp->cap_string != NULL; cp++) {
		if (strcmp(cp->cap_string, capstr) == 0) {
			return (cp->cap_index);
		}
	}

	return (-1);
}

/*ARGSUSED*/
static void
sas_gen_smp_crc(uint32_t *frame, size_t len)
{
/*
 * Leave this function here for future use.
 */
}
