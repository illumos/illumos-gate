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

#ifndef _SYS_SCSI_IMPL_SMP_TRANSPORT_H
#define	_SYS_SCSI_IMPL_SMP_TRANSPORT_H

#include <sys/types.h>
#include <sys/scsi/impl/usmp.h>

#ifdef	__cplusplus
extern "C" {
#endif

#if defined(_KERNEL)

/*
 * Properties for smp device
 */
#define	SMP_PROP			"smp-device"
#define	SMP_WWN				"smp-wwn"
#define	SMP_PROP_REPORT_MANUFACTURER	"report-manufacturer"

typedef struct smp_hba_tran	smp_hba_tran_t;

typedef struct smp_address {
	uint8_t		smp_a_wwn[SAS_WWN_BYTE_SIZE];	/* expander wwn */
	smp_hba_tran_t	*smp_a_hba_tran;		/* Transport vector */
} smp_address_t;

typedef struct smp_device {
	smp_address_t	smp_sd_address;
	dev_info_t	*smp_sd_dev;
	void		*smp_sd_hba_private;
	void		*smp_sd_private;
} smp_device_t;

typedef struct smp_pkt {
	smp_address_t	*smp_pkt_address;
	caddr_t		smp_pkt_req;
	caddr_t		smp_pkt_rsp;
	size_t		smp_pkt_reqsize;
	size_t		smp_pkt_rspsize;
	int		smp_pkt_timeout;
	uchar_t		smp_pkt_reason;		/* code from errno.h */
	uchar_t		smp_pkt_will_retry;	/* will retry on EAGAIN */
} smp_pkt_t;

struct smp_hba_tran {
	void		*smp_tran_hba_private;

	int		(*smp_tran_init)(
				dev_info_t		*self,
				dev_info_t		*child,
				smp_hba_tran_t		*tran,
				smp_device_t		*smp);

	void		(*smp_tran_free)(
				dev_info_t		*self,
				dev_info_t		*child,
				smp_hba_tran_t		*tran,
				smp_device_t		*smp);

	int		(*smp_tran_start)(
				struct smp_pkt		*pkt);

};

/* interfaces for hba/iport driver */
extern smp_hba_tran_t	*smp_hba_tran_alloc(dev_info_t *dip);
extern int		smp_hba_attach_setup(dev_info_t *dip,
			    smp_hba_tran_t *smp);
extern int		smp_hba_detach(dev_info_t *self);
extern void		smp_hba_tran_free(smp_hba_tran_t *smp);

/* interfaces target driver (and framework) */
extern int		smp_probe(struct smp_device *smp_devp);
extern int		smp_transport(struct smp_pkt *pkt);

/* ==== The following interfaces are private (currently) ==== */

/*
 * smp_device_prop_*() property interfaces: flags
 *
 *   SMP_DEVICE_PROP_DEVICE: property of device.
 *	The property is always associated with the smp_sd_dev devinfo
 *	node.  Implementation uses ndi_prop_*() interfaces applied
 *	dev_info_t (smp_sd_dev) nodes.
 */
#define	SMP_DEVICE_PROP_DEVICE		0x2	/* type is property-of-device */
#define	SMP_DEVICE_PROP_TYPE_MSK	0xF

int	smp_device_prop_get_int(struct smp_device *smp_sd, char *name,
	    int defvalue);
int64_t	smp_device_prop_get_int64(struct smp_device *, char *name,
	    int64_t defvalue);

int	smp_device_prop_lookup_byte_array(struct smp_device *smp_sd, char *name,
	    uchar_t **, uint_t *);
int	smp_device_prop_lookup_int_array(struct smp_device *smp_sd, char *name,
	    int **, uint_t *);
int	smp_device_prop_lookup_string(struct smp_device *smp_sd, char *name,
	    char **);
int	smp_device_prop_lookup_string_array(struct smp_device *smp_sd,
	    char *name, char ***, uint_t *);

int	smp_device_prop_update_byte_array(struct smp_device *smp_sd, char *name,
	    uchar_t *, uint_t);
int	smp_device_prop_update_int(struct smp_device *smp_sd, char *name, int);
int	smp_device_prop_update_int64(struct smp_device *smp_sd, char *name,
	    int64_t);
int	smp_device_prop_update_int_array(struct smp_device *smp_sd, char *name,
	    int *, uint_t);
int	smp_device_prop_update_string(struct smp_device *smp_sd, char *name,
	    char *);
int	smp_device_prop_update_string_array(struct smp_device *smp_sd,
	    char *name, char **, uint_t);

int	smp_device_prop_remove(struct smp_device *smp_sd, char *name);
void	smp_device_prop_free(struct smp_device *smp_sd, void *data);

#endif /* defined(_KERNEL) */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_SCSI_IMPL_SMP_TRANSPORT_H */
