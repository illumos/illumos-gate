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

#ifndef	_TPM_DDI_H
#define	_TPM_DDI_H

/* Duration index is SHORT, MEDIUM, LONG, UNDEFINED */
#define	TPM_DURATION_MAX_IDX	3

/*
 * IO buffer size: this seems sufficient, but feel free to modify
 * This should be at minimum 765
 */
#define	TPM_IO_BUF_SIZE		4096

#define	TPM_IO_TIMEOUT		10000000

/*
 * Flags to keep track of for the allocated resources
 * so we know what to deallocate later on
 */
enum tpm_ddi_resources_flags {
	TPM_OPENED = 0x001,
	TPM_DIDMINOR = 0x002,
	TPM_DIDREGSMAP = 0x004,
	TPM_DIDINTMUTEX = 0x008,
	TPM_DIDINTCV = 0x010,
	TPM_DID_IO_ALLOC = 0x100,
	TPM_DID_IO_MUTEX = 0x200,
	TPM_DID_IO_CV = 0x400,
	TPM_DID_MUTEX = 0x800,
	TPM_DID_SOFT_STATE = 0x1000,
#ifdef sun4v
	TPM_HSVC_REGISTERED = 0x2000
#endif
};

typedef struct tpm_state tpm_state_t;

/* TPM specific data structure */
struct tpm_state {
	/* TPM specific */
	TPM_CAP_VERSION_INFO vers_info;

	/* OS specific */
	int 		instance;
	dev_info_t 	*dip;
	ddi_acc_handle_t handle;

	kmutex_t	dev_lock;
	uint8_t		dev_held;

	/*
	 * For read/write
	 */
	uint8_t		*iobuf;
	size_t		bufsize;
	uint8_t		iobuf_inuse;
	kmutex_t	iobuf_lock;
	kcondvar_t	iobuf_cv;

	/*
	 * For supporting the interrupt
	 */
	uint8_t			intr_enabled;
	ddi_intr_handle_t	*h_array;
	uint_t			intr_pri;
	unsigned int		state;

	uint8_t		*addr;		/* where TPM is mapped to */
	char		locality;	/* keep track of the locality */

	uint32_t flags;		/* flags to keep track of what is allocated */
	clock_t duration[4];	/* short,medium,long,undefined */
	clock_t timeout_a;
	clock_t timeout_b;
	clock_t timeout_c;
	clock_t timeout_d;
	clock_t timeout_poll;

	ddi_device_acc_attr_t accattr;

	/* For power management. */
	kmutex_t	pm_mutex;
	kcondvar_t	suspend_cv;
	uint32_t	suspended;

	/* For RNG */
	crypto_kcf_provider_handle_t	n_prov;
};

#endif	/* _TPM_DDI_H */
