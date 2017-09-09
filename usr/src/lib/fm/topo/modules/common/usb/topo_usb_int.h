/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright (c) 2018, Joyent, Inc.
 */

#ifndef	_TOPO_USB_INT_H
#define	_TOPO_USB_INT_H

#include <stdint.h>
#include <sys/types.h>
#include <fm/topo_list.h>
#include <fm/topo_mod.h>
#include <sys/fm/protocol.h>

#include "acpi.h"
#include "accommon.h"
#include "acbuffer.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum topo_usb_path_type {
	TOPO_USB_T_ACPI
} topo_usb_path_type_t;

typedef struct topo_usb_meta_port_path {
	topo_list_t		tmpp_link;
	topo_usb_path_type_t	tmpp_type;
	char			*tmpp_path;
} topo_usb_meta_port_path_t;

typedef enum topo_usb_meta_port_flags {
	TOPO_USB_F_INTERNAL	= 1 << 0,
	TOPO_USB_F_EXTERNAL	= 1 << 1,
	TOPO_USB_F_CHASSIS	= 1 << 2,
} topo_usb_meta_port_flags_t;

typedef struct topo_usb_meta_port {
	topo_list_t			tmp_link;
	topo_usb_meta_port_flags_t	tmp_flags;
	uint_t				tmp_port_type;
	char				*tmp_label;
	topo_list_t			tmp_paths;
} topo_usb_meta_port_t;

typedef enum topo_usb_meta_flags {
	TOPO_USB_M_ACPI_MATCH	= 1 << 0,
	TOPO_USB_M_NO_ACPI	= 1 << 1,
	TOPO_USB_M_METADATA_MATCH = 1 << 2
} topo_usb_meta_flags_t;

extern int topo_usb_load_metadata(topo_mod_t *, tnode_t *, topo_list_t *,
    topo_usb_meta_flags_t *);
extern void topo_usb_free_metadata(topo_mod_t *, topo_list_t *);

typedef ACPI_PLD_INFO	acpi_pld_info_t;
extern boolean_t usbtopo_decode_pld(uint8_t *, size_t, acpi_pld_info_t *);

#ifdef __cplusplus
}
#endif

#endif /* _TOPO_USB_INT_H */
