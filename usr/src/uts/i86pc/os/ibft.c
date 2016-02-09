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

/*
 * This is the place to implement ld_ib_props()
 * For x86 it is to load iBFT and costruct the global ib props
 */

#include <sys/types.h>
#include <sys/null.h>
#include <sys/cmn_err.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/mman.h>
#include <sys/bootprops.h>
#include <sys/kmem.h>
#include <sys/psm.h>
#include <sys/bootconf.h>

typedef enum ibft_structure_type {
	Reserved	=	0,
	Control		=	1,
	Initiator	=	2,
	Nic		=	3,
	Target		=	4,
	Extensions	=	5,
	Type_End
}ibft_struct_type;

typedef enum _chap_type {
	NO_CHAP		=	0,
	CHAP		=	1,
	Mutual_CHAP	=	2,
	TYPE_UNKNOWN
}chap_type;

typedef struct ibft_entry {
	int	af;
	int	e_port;
	char	target_name[224];
	char	target_addr[INET6_ADDRSTRLEN];
}ibft_entry_t;

typedef struct iSCSI_ibft_tbl_hdr {
	char	    Signature[4];
	int	    Length;
	char	    Revision;
	char	    Checksum;
	char	    oem_id[6];
	char	    oem_table_id[8];
	char	    Reserved[24];
}iscsi_ibft_tbl_hdr_t;

typedef struct iSCSI_ibft_hdr {
	char	    Structure_id;
	char	    Version;
	ushort_t    Length;
	char	    Index;
	char	    Flags;
}iscsi_ibft_hdr_t;

typedef struct iSCSI_ibft_control {
	iscsi_ibft_hdr_t    header;
	ushort_t	    Extensions;
	ushort_t	    Initiator_offset;
	ushort_t	    Nic0_offset;
	ushort_t	    Target0_offset;
	ushort_t	    Nic1_offset;
	ushort_t	    Target1_offset;
}iscsi_ibft_ctl_t;

typedef struct iSCSI_ibft_initiator {
	iscsi_ibft_hdr_t    header;
	uchar_t		    iSNS_Server[16];
	uchar_t		    SLP_Server[16];
	uchar_t		    Pri_Radius_Server[16];
	uchar_t		    Sec_Radius_Server[16];
	ushort_t	    ini_name_len;
	ushort_t	    ini_name_offset;
}iscsi_ibft_initiator_t;

typedef struct iSCSI_ibft_nic {
	iscsi_ibft_hdr_t    header;
	uchar_t		    ip_addr[16];
	char		    Subnet_Mask_Prefix;
	char		    Origin;
	uchar_t		    Gateway[16];
	uchar_t		    Primary_dns[16];
	uchar_t		    Secondary_dns[16];
	uchar_t		    dhcp[16];
	ushort_t	    vlan;
	char		    mac[6];
	ushort_t	    pci_BDF;
	ushort_t	    Hostname_len;
	ushort_t	    Hostname_offset;
}iscsi_ibft_nic_t;

typedef struct iSCSI_ibft_target {
	iscsi_ibft_hdr_t    header;
	uchar_t		    ip_addr[16];
	ushort_t	    port;
	uchar_t		    boot_lun[8];
	uchar_t		    chap_type;
	uchar_t		    nic_association;
	ushort_t	    target_name_len;
	ushort_t	    target_name_offset;
	ushort_t	    chap_name_len;
	ushort_t	    chap_name_offset;
	ushort_t	    chap_secret_len;
	ushort_t	    chap_secret_offset;
	ushort_t	    rev_chap_name_len;
	ushort_t	    rev_chap_name_offset;
	ushort_t	    rev_chap_secret_len;
	ushort_t	    rev_chap_secret_offset;
}iscsi_ibft_tgt_t;

#define	ISCSI_IBFT_LOWER_ADDR		0x80000	    /* 512K */
#define	ISCSI_IBFT_HIGHER_ADDR		0x100000    /* 1024K */
#define	ISCSI_IBFT_SIGNATRUE		"iBFT"
#define	ISCSI_IBFT_SIGNATURE_LEN	4
#define	ISCSI_IBFT_TBL_BUF_LEN		1024
#define	ISCSI_IBFT_ALIGNED		16
#define	ISCSI_IBFT_CTL_OFFSET		48

#define	IBFT_BLOCK_VALID_YES		0x01	/* bit 0 */
#define	IBFT_FIRMWARE_BOOT_SELECTED	0x02	/* bit 1 */
#define	IBFT_USE_RADIUS_CHAP		0x04	/* bit 2 */
#define	IBFT_USE_GLOBLE			0x04	/* NIC structure */
#define	IBFT_USE_RADIUS_RHCAP		0x08	/* bit 3 */

/*
 * Currently, we only support initiator offset, NIC0 offset, Target0 offset,
 * NIC1 offset and Target1 offset. So the length is 5. If we want to support
 * extensions, we should change this number.
 */
#define	IBFT_OFFSET_BUF_LEN		5
#define	IPV4_OFFSET			12

#define	IBFT_INVALID_MSG		"Invalid iBFT table 0x%x"
#define	IBFT_NOPROBE_MSG		"iSCSI boot is disabled"

typedef enum ibft_status {
	IBFT_STATUS_OK = 0,
	/* General error */
	IBFT_STATUS_ERR,
	/* Bad header */
	IBFT_STATUS_BADHDR,
	/* Bad control ID */
	IBFT_STATUS_BADCID,
	/* Bad ip addr */
	IBFT_STATUS_BADIP,
	/* Bad af */
	IBFT_STATUS_BADAF,
	/* Bad chap name */
	IBFT_STATUS_BADCHAPNAME,
	/* Bad chap secret */
	IBFT_STATUS_BADCHAPSEC,
	/* Bad checksum */
	IBFT_STATUS_BADCHECKSUM,
	/* Low memory */
	IBFT_STATUS_LOWMEM,
	/* No table */
	IBFT_STATUS_NOTABLE
} ibft_status_t;

extern void *memset(void *s, int c, size_t n);
extern int memcmp(const void *s1, const void *s2, size_t n);
extern void bcopy(const void *s1, void *s2, size_t n);
extern void iscsi_print_boot_property();

int ibft_noprobe = 0;
ib_boot_prop_t boot_property;		/* static allocated */
extern ib_boot_prop_t *iscsiboot_prop;	/* to be filled */

static ibft_status_t iscsi_parse_ibft_control(iscsi_ibft_ctl_t *ctl_hdr,
    ushort_t *iscsi_offset_buf);

static ibft_status_t iscsi_parse_ibft_initiator(char *begin_of_ibft,
    iscsi_ibft_initiator_t *initiator);

static ibft_status_t iscsi_parse_ibft_NIC(iscsi_ibft_nic_t *nicp);

static ibft_status_t iscsi_parse_ibft_target(char *begin_of_ibft,
    iscsi_ibft_tgt_t *tgtp);


/*
 * Return value:
 * Success: IBFT_STATUS_OK
 * Fail: IBFT_STATUS_BADCHECKSUM
 */
static ibft_status_t
iscsi_ibft_hdr_checksum(iscsi_ibft_tbl_hdr_t *tbl_hdr)
{
	uchar_t	checksum    =	0;
	uchar_t	*start	    =	NULL;
	int	length	    =	0;
	int	i	    =	0;

	if (tbl_hdr == NULL) {
		return (IBFT_STATUS_BADHDR);
	}

	length = tbl_hdr->Length;
	start = (uchar_t *)tbl_hdr;

	for (i = 0; i < length; i++) {
		checksum = checksum + start[i];
	}

	if (!checksum)
		return (IBFT_STATUS_OK);
	else
		return (IBFT_STATUS_BADCHECKSUM);
}

/*
 * Now we only support one control structure in the IBFT.
 * So there is no Control ID here.
 */
static ibft_status_t
iscsi_parse_ibft_structure(char *begin_of_ibft, char *buf)
{
	iscsi_ibft_hdr_t	*hdr	=   NULL;
	ibft_status_t		ret	=   IBFT_STATUS_OK;

	if (buf == NULL) {
		return (IBFT_STATUS_ERR);
	}

	hdr = (iscsi_ibft_hdr_t *)buf;
	switch (hdr->Structure_id) {
		case Initiator:
			ret = iscsi_parse_ibft_initiator(
			    begin_of_ibft,
			    (iscsi_ibft_initiator_t *)buf);
			break;
		case Nic:
			ret = iscsi_parse_ibft_NIC(
			    (iscsi_ibft_nic_t *)buf);
			break;
		case Target:
			ret = iscsi_parse_ibft_target(
			    begin_of_ibft,
			    (iscsi_ibft_tgt_t *)buf);
			break;
		default:
			ret = IBFT_STATUS_BADHDR;
			break;
	}

	return (ret);
}

/*
 * Parse the iBFT table
 * return IBFT_STATUS_OK upon sucess
 */
static ibft_status_t
iscsi_parse_ibft_tbl(iscsi_ibft_tbl_hdr_t *tbl_hdr)
{
	char		*outbuf	    =	NULL;
	int		i	    =	0;
	ibft_status_t	ret	    =	IBFT_STATUS_OK;
	ushort_t	iscsi_offset_buf[IBFT_OFFSET_BUF_LEN] = {0};

	if (tbl_hdr == NULL) {
		return (IBFT_STATUS_ERR);
	}

	if (iscsi_ibft_hdr_checksum(tbl_hdr) != IBFT_STATUS_OK) {
		return (IBFT_STATUS_BADCHECKSUM);
	}

	outbuf = (char *)tbl_hdr;

	ret = iscsi_parse_ibft_control(
	    (iscsi_ibft_ctl_t *)&outbuf[ISCSI_IBFT_CTL_OFFSET],
	    iscsi_offset_buf);

	if (ret == IBFT_STATUS_OK) {
		ret = IBFT_STATUS_ERR;
		for (i = 0; i < IBFT_OFFSET_BUF_LEN; i++) {
			if (iscsi_offset_buf[i] != 0) {
				ret = iscsi_parse_ibft_structure(
				    (char *)tbl_hdr,
				    (char *)tbl_hdr +
				    iscsi_offset_buf[i]);
				if (ret != IBFT_STATUS_OK) {
					return (ret);
				}
			}
		}
	}

	return (ret);
}

static ibft_status_t
iscsi_parse_ibft_control(iscsi_ibft_ctl_t *ctl_hdr,
    ushort_t	*iscsi_offset_buf)
{
	int	    i		=	0;
	ushort_t    *offsetp	=	NULL;

	if (ctl_hdr == NULL) {
		return (IBFT_STATUS_BADHDR);
	}

	if (ctl_hdr->header.Structure_id != Control) {
		return (IBFT_STATUS_BADCID);
	}

	/*
	 * Copy the offsets to offset buffer.
	 */
	for (offsetp = &(ctl_hdr->Initiator_offset); i < IBFT_OFFSET_BUF_LEN;
	    offsetp++) {
		iscsi_offset_buf[i++] = *offsetp;
	}

	return (IBFT_STATUS_OK);
}

/*
 * We only copy the "Firmare Boot Selseted" and valid initiator
 * to the boot property.
 */
static ibft_status_t
iscsi_parse_ibft_initiator(char *begin_of_ibft,
    iscsi_ibft_initiator_t *initiator)
{
	if (initiator == NULL) {
		return (IBFT_STATUS_ERR);
	}

	if (initiator->header.Structure_id != Initiator) {
		return (IBFT_STATUS_BADHDR);
	}

	if ((initiator->header.Flags & IBFT_FIRMWARE_BOOT_SELECTED) &&
	    (initiator->header.Flags & IBFT_BLOCK_VALID_YES)) {
		/*
		 * If the initiator name exists, we will copy it to our own
		 * property structure
		 */
		if (initiator->ini_name_len != 0) {
			boot_property.boot_init.ini_name =
			    (uchar_t *)kmem_zalloc(
			    initiator->ini_name_len + 1, KM_SLEEP);
			boot_property.boot_init.ini_name_len =
			    initiator->ini_name_len + 1;
			(void) snprintf(
			    (char *)boot_property.boot_init.ini_name,
			    initiator->ini_name_len + 1, "%s",
			    begin_of_ibft + initiator->ini_name_offset);
		}
	}
	return (IBFT_STATUS_OK);
}

static ibft_status_t
iscsi_parse_ipaddr(uchar_t *source, char *dest, int *af)
{
	int i = 0;

	if (source == NULL) {
		return (IBFT_STATUS_ERR);
	}

	if (source[0] == 0x00 && source[1] == 0x00 &&
	    source[2] == 0x00 && source[3] == 0x00 &&
	    source[4] == 0x00 && source[5] == 0x00 &&
	    source[6] == 0x00 && source[7] == 0x00 &&
	    source[8] == 0x00 && source[9] == 0x00 &&
	    (source[10] == 0xff) && (source[11] == 0xff)) {
		/*
		 * IPv4 address
		 */
		if (dest != NULL) {
			(void) sprintf(dest, "%d.%d.%d.%d",
			    source[12], source[13], source[14], source[15]);
		}
		if (af != NULL) {
			*af = AF_INET;
		}
	} else {
		if (dest != NULL) {
			for (i = 0; i < 14; i = i + 2) {
				(void) sprintf(dest, "%02x%02x:", source[i],
				    source[i+1]);
				dest = dest + 5;
			}
			(void) sprintf(dest, "%02x%02x",
			    source[i], source[i+1]);
		}
		if (af != NULL) {
			*af = AF_INET6;
		}
	}

	return (IBFT_STATUS_OK);
}

/*
 * Copy the ip address from ibft. If IPv4 is used, we should copy
 * the address from 12th byte.
 */
static ibft_status_t
iscsi_copy_ibft_ipaddr(uchar_t *source, void *dest, int *af)
{
	ibft_status_t	ret		=	IBFT_STATUS_OK;
	int		sin_family	=	0;

	if (source == NULL || dest == NULL) {
		return (IBFT_STATUS_ERR);
	}
	ret = iscsi_parse_ipaddr(source, NULL, &sin_family);
	if (ret != 0) {
		return (IBFT_STATUS_BADIP);
	}

	if (sin_family == AF_INET) {
		bcopy(source+IPV4_OFFSET, dest, sizeof (struct in_addr));
	} else if (sin_family == AF_INET6) {
		bcopy(source, dest, sizeof (struct in6_addr));
	} else {
		return (IBFT_STATUS_BADAF);
	}

	if (af != NULL) {
		*af = sin_family;
	}
	return (IBFT_STATUS_OK);
}

/*
 * Maybe there are multiply NICs are available. We only copy the
 * "Firmare Boot Selseted" and valid one to the boot property.
 */
static ibft_status_t
iscsi_parse_ibft_NIC(iscsi_ibft_nic_t *nicp)
{
	ibft_status_t	ret	=	IBFT_STATUS_OK;
	int		af	=	0;

	if (nicp == NULL) {
		return (IBFT_STATUS_ERR);
	}

	if (nicp->header.Structure_id != Nic) {
		return (IBFT_STATUS_ERR);
	}

	if ((nicp->header.Flags & IBFT_FIRMWARE_BOOT_SELECTED) &&
	    (nicp->header.Flags & IBFT_BLOCK_VALID_YES)) {
		ret = iscsi_copy_ibft_ipaddr(nicp->ip_addr,
		    &boot_property.boot_nic.nic_ip_u, &af);
		if (ret != IBFT_STATUS_OK) {
			return (ret);
		}

		boot_property.boot_nic.sin_family = af;

		ret = iscsi_copy_ibft_ipaddr(nicp->Gateway,
		    &boot_property.boot_nic.nic_gw_u, NULL);
		if (ret != IBFT_STATUS_OK) {
			return (ret);
		}

		ret = iscsi_copy_ibft_ipaddr(nicp->dhcp,
		    &boot_property.boot_nic.nic_dhcp_u, NULL);
		if (ret != IBFT_STATUS_OK) {
			return (ret);
		}

		bcopy(nicp->mac, boot_property.boot_nic.nic_mac, 6);
		boot_property.boot_nic.sub_mask_prefix =
		    nicp->Subnet_Mask_Prefix;
	}

	return (IBFT_STATUS_OK);
}

/*
 * Maybe there are multiply targets are available. We only copy the
 * "Firmare Boot Selseted" and valid one to the boot property.
 */
static ibft_status_t
iscsi_parse_ibft_target(char *begin_of_ibft, iscsi_ibft_tgt_t *tgtp)
{
	char		*tmp	=   NULL;
	int		af	=   0;
	ibft_status_t	ret	=   IBFT_STATUS_OK;

	if (tgtp == NULL) {
		return (IBFT_STATUS_ERR);
	}

	if (tgtp->header.Structure_id != Target) {
		return (IBFT_STATUS_BADHDR);
	}

	if ((tgtp->header.Flags & IBFT_FIRMWARE_BOOT_SELECTED) &&
	    (tgtp->header.Flags & IBFT_BLOCK_VALID_YES)) {
		/*
		 * Get Target Address
		 */
		ret = iscsi_copy_ibft_ipaddr(tgtp->ip_addr,
		    &boot_property.boot_tgt.tgt_ip_u, &af);
		if (ret != IBFT_STATUS_OK) {
			return (ret);
		}
		boot_property.boot_tgt.sin_family = af;
		/*
		 * Get Target Name
		 */
		if (tgtp->target_name_len != 0) {
			boot_property.boot_tgt.tgt_name =
			    (uchar_t *)kmem_zalloc(tgtp->target_name_len + 1,
			    KM_SLEEP);
			boot_property.boot_tgt.tgt_name_len =
			    tgtp->target_name_len + 1;
			(void) snprintf(
			    (char *)boot_property.boot_tgt.tgt_name,
			    tgtp->target_name_len + 1, "%s",
			    begin_of_ibft + tgtp->target_name_offset);
		} else {
			boot_property.boot_tgt.tgt_name = NULL;
		}

		/* Get Dest Port */
		boot_property.boot_tgt.tgt_port = tgtp->port;

		boot_property.boot_tgt.lun_online = 0;

		/*
		 * Get CHAP secret and name.
		 */
		if (tgtp->chap_type != NO_CHAP) {
			if (tgtp->chap_name_len != 0) {
				boot_property.boot_init.ini_chap_name =
				    (uchar_t *)kmem_zalloc(
				    tgtp->chap_name_len + 1,
				    KM_SLEEP);
				boot_property.boot_init.ini_chap_name_len =
				    tgtp->chap_name_len + 1;
				tmp = (char *)
				    boot_property.boot_init.ini_chap_name;
				(void) snprintf(
				    tmp,
				    tgtp->chap_name_len + 1, "%s",
				    begin_of_ibft + tgtp->chap_name_offset);
			} else {
				/*
				 * Just set NULL, initiator is able to deal
				 * with this
				 */
				boot_property.boot_init.ini_chap_name = NULL;
			}

			if (tgtp->chap_secret_len != 0) {
				boot_property.boot_init.ini_chap_sec =
				    (uchar_t *)kmem_zalloc(
				    tgtp->chap_secret_len + 1,
				    KM_SLEEP);
				boot_property.boot_init.ini_chap_sec_len =
				    tgtp->chap_secret_len + 1;
				bcopy(begin_of_ibft +
				    tgtp->chap_secret_offset,
				    boot_property.boot_init.ini_chap_sec,
				    tgtp->chap_secret_len);
			} else {
				boot_property.boot_init.ini_chap_sec = NULL;
				return (IBFT_STATUS_ERR);
			}

			if (tgtp->chap_type == Mutual_CHAP) {
				if (tgtp->rev_chap_name_len != 0) {
					boot_property.boot_tgt.tgt_chap_name =
					    (uchar_t *)kmem_zalloc(
					    tgtp->rev_chap_name_len + 1,
					    KM_SLEEP);
					boot_property.boot_tgt.tgt_chap_name_len
					    = tgtp->rev_chap_name_len + 1;
#define	TGT_CHAP_NAME	boot_property.boot_tgt.tgt_chap_name
					tmp = (char *)TGT_CHAP_NAME;
#undef	TGT_CHAP_NAME
					(void) snprintf(
					    tmp,
					    tgtp->rev_chap_name_len + 1,
					    "%s",
					    begin_of_ibft +
					    tgtp->rev_chap_name_offset);
				} else {
					/*
					 * Just set NULL, initiator is able
					 * to deal with this
					 */
					boot_property.boot_tgt.tgt_chap_name =
					    NULL;
				}

				if (tgtp->rev_chap_secret_len != 0) {
					boot_property.boot_tgt.tgt_chap_sec =
					    (uchar_t *)kmem_zalloc(
					    tgtp->rev_chap_secret_len + 1,
					    KM_SLEEP);
					boot_property.boot_tgt.tgt_chap_sec_len
					    = tgtp->rev_chap_secret_len + 1;
					tmp = (char *)
					    boot_property.boot_tgt.tgt_chap_sec;
					(void) snprintf(
					    tmp,
					    tgtp->rev_chap_secret_len + 1,
					    "%s",
					    begin_of_ibft +
					    tgtp->chap_secret_offset);
				} else {
					boot_property.boot_tgt.tgt_chap_sec =
					    NULL;
					return (IBFT_STATUS_BADCHAPSEC);
				}
			}
		} else {
			boot_property.boot_init.ini_chap_name = NULL;
			boot_property.boot_init.ini_chap_sec = NULL;
		}

		/*
		 * Get Boot LUN
		 */
		(void) bcopy(tgtp->boot_lun,
		    boot_property.boot_tgt.tgt_boot_lun, 8);
	}

	return (IBFT_STATUS_OK);
}

/*
 * This function is used for scanning iBFT from the physical memory.
 * Return Value:
 * IBFT_STATUS_OK
 * IBFT_STATUS_ERR
 */
static ibft_status_t
iscsi_scan_ibft_tbl(char *ibft_tbl_buf)
{
	int		start;
	void		*va		= NULL;
	int		*len 		= NULL;
	ibft_status_t	ret		= IBFT_STATUS_NOTABLE;

	for (start = ISCSI_IBFT_LOWER_ADDR; start < ISCSI_IBFT_HIGHER_ADDR;
	    start = start + ISCSI_IBFT_ALIGNED) {
		va = (void *)psm_map((paddr_t)(start&0xffffffff),
		    ISCSI_IBFT_SIGNATURE_LEN,
		    PROT_READ);

		if (va == NULL) {
			continue;
		}
		if (memcmp(va, ISCSI_IBFT_SIGNATRUE,
		    ISCSI_IBFT_SIGNATURE_LEN) == 0) {
			ret = IBFT_STATUS_ERR;
			/* Acquire table length */
			len = (int *)psm_map(
			    (paddr_t)((start+\
			    ISCSI_IBFT_SIGNATURE_LEN)&0xffffffff),
			    ISCSI_IBFT_SIGNATURE_LEN, PROT_READ);
			if (len == NULL) {
				psm_unmap((caddr_t)va,
				    ISCSI_IBFT_SIGNATURE_LEN);
				continue;
			}
			if (ISCSI_IBFT_LOWER_ADDR + *len <
			    ISCSI_IBFT_HIGHER_ADDR - 1) {
				psm_unmap(va,
				    ISCSI_IBFT_SIGNATURE_LEN);
				va = psm_map((paddr_t)(start&0xffffffff),
				    *len,
				    PROT_READ);
				if (va != NULL) {
					/*
					 * Copy data to our own buffer
					 */
					bcopy(va, ibft_tbl_buf, *len);
					ret = IBFT_STATUS_OK;
				}
				psm_unmap((caddr_t)va, *len);
				psm_unmap((caddr_t)len,
				    ISCSI_IBFT_SIGNATURE_LEN);
				break;
			} else {
				psm_unmap((caddr_t)va,
				    ISCSI_IBFT_SIGNATURE_LEN);
				psm_unmap((caddr_t)len,
				    ISCSI_IBFT_SIGNATURE_LEN);
			}
		} else {
			psm_unmap((caddr_t)va, ISCSI_IBFT_SIGNATURE_LEN);
		}
	}

	return (ret);
}

/*
 * Scan the ibft table and store the iSCSI boot properties
 * If there is a valid table then set the iscsiboot_prop
 * iBF should be off if the host is not intended
 * to be booted from iSCSI disk
 */
void
ld_ib_prop()
{
	ibft_status_t	ret	=   IBFT_STATUS_OK;
	char		*ibft_tbl_buf;

	if (do_bsys_getproplen(NULL, "ibft-noprobe") > 0)
		ibft_noprobe = 1;

	if (ibft_noprobe != 0) {
		/*
		 * Scanning for iBFT may conflict with devices which use memory
		 * in 640-1024KB of physical address space.  The iBFT
		 * specification suggests use of low RAM method - scanning
		 * physical memory 512-1024 KB for iBFT table.  However, the
		 * Upper Memory Area (UMA) 640-1024 KB may contain device
		 * memory or memory mapped I/O.  Although reading from I/O area
		 * is usually fine, the actual behavior depends on device
		 * implementation.  In some cases, the user may want to disable
		 * low RAM method and prevent reading from device I/O area.
		 *
		 * To disable low RAM method:
		 * 1) pass "-B ibft-noprobe=1" on kernel command line
		 * 2) add line "set ibft_noprobe=1" in /etc/system
		 */
		cmn_err(CE_NOTE, IBFT_NOPROBE_MSG);
		return;
	}

	ibft_tbl_buf = (char *)kmem_zalloc(ISCSI_IBFT_TBL_BUF_LEN,
	    KM_SLEEP);

	if (!ibft_tbl_buf) {
		/* Unlikely to happen */
		cmn_err(CE_NOTE, IBFT_INVALID_MSG,
		    IBFT_STATUS_LOWMEM);
		return;
	}

	(void) memset(&boot_property, 0, sizeof (boot_property));
	if ((ret = iscsi_scan_ibft_tbl(ibft_tbl_buf)) ==
	    IBFT_STATUS_OK) {
		ret = iscsi_parse_ibft_tbl(
		    (iscsi_ibft_tbl_hdr_t *)ibft_tbl_buf);
		if (ret == IBFT_STATUS_OK) {
			iscsiboot_prop = &boot_property;
			iscsi_print_boot_property();
		} else {
			cmn_err(CE_NOTE, IBFT_INVALID_MSG, ret);
		}
	} else if (ret != IBFT_STATUS_NOTABLE) {
		cmn_err(CE_NOTE, IBFT_INVALID_MSG, ret);
	}

	kmem_free(ibft_tbl_buf, ISCSI_IBFT_TBL_BUF_LEN);
}
