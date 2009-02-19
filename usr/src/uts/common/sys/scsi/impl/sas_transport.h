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

#ifndef _SYS_SCSI_IMPL_SAS_TRANSPORT_H
#define	_SYS_SCSI_IMPL_SAS_TRANSPORT_H

#include <sys/types.h>
#include <sys/scsi/impl/usmp.h>

#ifdef	__cplusplus
extern "C" {
#endif

#if defined(_KERNEL)

/*
 * Properties for smp device
 */
#define	SMP_PROP		"smp-device"
#define	SMP_WWN			"smp-wwn"

/*
 * Common Capability Strings Array for SAS
 */
/*
 * SAS_CAP_SMP_CRC represent if the HBA has the
 * capability to generate CRC for SMP frame and
 * check the CRC of the reply frame
 */
#define	SAS_CAP_SMP_CRC		1
#define	SAS_CAP_ASCII		{					\
		"smp-crc", NULL }

typedef struct sas_hba_tran	sas_hba_tran_t;

typedef struct sas_addr {
	uint8_t		a_wwn[SAS_WWN_BYTE_SIZE];	/* expander wwn */
	sas_hba_tran_t	*a_hba_tran;			/* Transport vector */
} sas_addr_t;

typedef struct smp_pkt {
	caddr_t		pkt_req;
	caddr_t		pkt_rsp;
	size_t		pkt_reqsize;
	size_t		pkt_rspsize;
	int		pkt_timeout;
	uchar_t		pkt_reason;	/* code from errno.h */
	sas_addr_t	*pkt_address;
} smp_pkt_t;

typedef struct smp_device {
	dev_info_t	*dip;
	sas_addr_t	smp_addr;
} smp_device_t;


struct sas_hba_tran {
	void		*tran_hba_private;

	int		(*tran_sas_getcap)(
				sas_addr_t		*ap,
				char			*cap);

	int		(*tran_smp_start)(
				struct smp_pkt		*pkt);

};

extern sas_hba_tran_t *sas_hba_tran_alloc(dev_info_t *dip, int flags);
extern int	sas_hba_attach_setup(dev_info_t *dip, sas_hba_tran_t *smp);
extern void	sas_hba_tran_free(sas_hba_tran_t *smp);

extern int	sas_smp_transport(struct smp_pkt *pkt);
extern int	sas_ifgetcap(struct sas_addr *ap, char *cap);

extern int	sas_hba_probe_smp(struct smp_device *smp_devp);
extern int	sas_hba_lookup_capstr(char *capstr);

#endif /* defined(_KERNEL) */


#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_SCSI_IMPL_SAS_TRANSPORT_H */
