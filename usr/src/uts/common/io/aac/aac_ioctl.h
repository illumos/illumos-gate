/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright 2005-06 Adaptec, Inc.
 * Copyright (c) 2005-06 Adaptec Inc., Achim Leubner
 * Copyright (c) 2000 Michael Smith
 * Copyright (c) 2000 Scott Long
 * Copyright (c) 2000 BSDi
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *    $FreeBSD: /repoman/r/ncvs/src/sys/sys/aac_ioctl.h,v 1.11 2004/12/09 22:20:25 scottl Exp $
 */

#ifndef	_AAC_IOCTL_H_
#define	_AAC_IOCTL_H_

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * IOCTL Interface
 */

/* Macro definitions for IOCTL function control codes */
#define	CTL_CODE(function, method) \
	((4<< 16) | ((function) << 2) | (method))

/* Method codes for how buffers are passed for I/O and FS controls */
#define	METHOD_BUFFERED		0
#define	METHOD_NEITHER		3

/* IOCTL commands */
#define	FSACTL_SENDFIB			CTL_CODE(2050, METHOD_BUFFERED)
#define	FSACTL_SEND_RAW_SRB		CTL_CODE(2067, METHOD_BUFFERED)
#define	FSACTL_DELETE_DISK		0x163
#define	FSACTL_QUERY_DISK		0x173
#define	FSACTL_OPEN_GET_ADAPTER_FIB	CTL_CODE(2100, METHOD_BUFFERED)
#define	FSACTL_GET_NEXT_ADAPTER_FIB	CTL_CODE(2101, METHOD_BUFFERED)
#define	FSACTL_CLOSE_GET_ADAPTER_FIB	CTL_CODE(2102, METHOD_BUFFERED)
#define	FSACTL_MINIPORT_REV_CHECK	CTL_CODE(2107, METHOD_BUFFERED)
#define	FSACTL_GET_PCI_INFO		CTL_CODE(2119, METHOD_BUFFERED)
#define	FSACTL_FORCE_DELETE_DISK	CTL_CODE(2120, METHOD_NEITHER)
#define	FSACTL_REGISTER_FIB_SEND	CTL_CODE(2136, METHOD_BUFFERED)
#define	FSACTL_GET_CONTAINERS		2131
#define	FSACTL_GET_VERSION_MATCHING	CTL_CODE(2137, METHOD_BUFFERED)
#define	FSACTL_SEND_LARGE_FIB		CTL_CODE(2138, METHOD_BUFFERED)
#define	FSACTL_GET_FEATURES		CTL_CODE(2139, METHOD_BUFFERED)

#pragma pack(1)

struct aac_revision
{
	uint32_t compat;
	uint32_t version;
	uint32_t build;
};

struct aac_get_adapter_fib
{
	uint32_t context;
	int32_t wait;
	uint32_t aif_fib;	/* RAID config app is 32bit */
};

struct aac_pci_info {
	uint32_t bus;
	uint32_t slot;
};

struct aac_query_disk {
	int32_t container_no;
	int32_t bus;
	int32_t target;
	int32_t lun;
	uint32_t valid;
	uint32_t locked;
	uint32_t deleted;
	int32_t instance;
	char disk_device_name[10];
	uint32_t unmapped;
};

struct aac_delete_disk {
	int32_t nt_disk_no;
	int32_t container_no;
};

/*
 * The following definitions come from Adaptec:
 */
typedef union {
	struct {
		uint32_t largeLBA  : 1;	/* disk support greater 2TB */
		uint32_t fReserved : 31;
	} fBits;
	uint32_t fValue;
} featuresState;

struct aac_features {
	featuresState feat;
	uint32_t data[31];
	uint32_t reserved[32];
};

#pragma pack()

/*
 * Aligned structure definitions for variable declarations that require
 * alignment.
 *
 * Normally the packed structures are defined in a way that if the initial
 * member is aligned, then the following members will also be aligned. So
 * we need only to make sure the packed structure, ie. the first member, is
 * aligned to satisfy alignment requirement.
 */
union aac_revision_align {
	struct aac_revision d;
	uint32_t dummy;
};

union aac_get_adapter_fib_align {
	struct aac_get_adapter_fib d;
	uint32_t dummy;
};

union aac_pci_info_align {
	struct aac_pci_info d;
	uint32_t dummy;
};

union aac_query_disk_align {
	struct aac_query_disk d;
	int32_t dummy;
};

union aac_delete_disk_align {
	struct aac_delete_disk d;
	int32_t dummy;
};

union aac_features_align {
	struct aac_features d;
	uint32_t dummy;
};

#ifdef	__cplusplus
}
#endif

#endif /* _AAC_IOCTL_H_ */
