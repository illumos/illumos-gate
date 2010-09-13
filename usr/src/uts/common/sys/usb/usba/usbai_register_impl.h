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

#ifndef	_SYS_USB_REGISTER_IMPL_H
#define	_SYS_USB_REGISTER_IMPL_H


#ifdef	__cplusplus
extern "C" {
#endif

/* For binary dump function */
#define	BINDUMP_BYTES_PER_LINE	16 /* For binary dump of class/vendor descr */
#define	INDENT_SPACE_STR	"    " /* Spaces for indentation */
#define	SPACES_PER_INDENT	(strlen(INDENT_SPACE_STR) - 1)

#define	USBA_ALL	-1			/* Build all */

/* State of the tree-building process */
typedef struct usba_reg_state {
	dev_info_t	*dip;			/* Dev info pointer */
	usb_cfg_data_t	*st_curr_cfg;	/* Current cfg being init'ed */
	usb_if_data_t	*st_curr_if;		/* Current if being init'ed */
	usb_alt_if_data_t *st_curr_alt;	/* Current alt being init'ed */
	usb_ep_data_t	*st_curr_ep;		/* Current ep being init'ed */
	int		st_last_processed_descr_type; /* Type of last descr */
					    /* processed for placing c/vs */
	int		st_if_to_build;		/* Interface to build */
	int		st_cfg_to_build;	/* Configuration to build */
	int		st_total_cfg_length;	/* Len of all descriptors */
						/* for the current config */
	uchar_t 	*st_curr_raw_descr;	/* Ptr to raw curr descr */
	uchar_t 	st_curr_raw_descr_type;    /* Type of curr descr */
	uchar_t 	st_curr_raw_descr_len;    /* Length of curr descr */
	char		*st_curr_cfg_str;    /* Cfg string from usba_device */
	usb_reg_parse_lvl_t st_dev_parse_level;	/* All, curr cfg, 1 iface */
	usb_cfg_data_t	*st_dev_cfg;		/* Cfg array, root of tree */
	uint_t		st_dev_n_cfg;		/* Number cfgs in tree */
	boolean_t	st_build_ep_comp;	/* for wusb only */
} usba_reg_state_t;

_NOTE(SCHEME_PROTECTS_DATA("chg at attach only", usb_cvs_data))
_NOTE(SCHEME_PROTECTS_DATA("chg at attach only", usb_ep_data))
_NOTE(SCHEME_PROTECTS_DATA("chg at attach only", usb_alt_if_data))
_NOTE(SCHEME_PROTECTS_DATA("chg at attach only", usb_if_data))
_NOTE(SCHEME_PROTECTS_DATA("chg at attach only", usb_cfg_data))
_NOTE(SCHEME_PROTECTS_DATA("chg at attach only", usba_reg_state))


_NOTE(SCHEME_PROTECTS_DATA("chg at attach only",
					usb_client_dev_data::dev_cfg))
_NOTE(SCHEME_PROTECTS_DATA("chg at attach only",
					usb_client_dev_data::dev_curr_cfg))
_NOTE(SCHEME_PROTECTS_DATA("chg at attach only",
					usb_client_dev_data::dev_n_cfg))
_NOTE(SCHEME_PROTECTS_DATA("chg at attach only",
					usb_client_dev_data::dev_parse_level))
_NOTE(SCHEME_PROTECTS_DATA("chg at attach only",
					usb_client_dev_data::dev_curr_if))
_NOTE(SCHEME_PROTECTS_DATA("chg at attach only",
					usb_client_dev_data::dev_default_ph))
_NOTE(SCHEME_PROTECTS_DATA("chg at attach only",
					usb_client_dev_data::dev_descr))
_NOTE(SCHEME_PROTECTS_DATA("chg at attach only",
					usb_client_dev_data::dev_bos))
_NOTE(SCHEME_PROTECTS_DATA("chg at attach only",
					usb_client_dev_data::dev_iblock_cookie))
_NOTE(SCHEME_PROTECTS_DATA("chg at attach only",
					usb_client_dev_data::dev_mfg))
_NOTE(SCHEME_PROTECTS_DATA("chg at attach only",
					usb_client_dev_data::dev_product))
_NOTE(SCHEME_PROTECTS_DATA("chg at attach only",
					usb_client_dev_data::dev_serial))

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_USB_REGISTER_IMPL_H */
