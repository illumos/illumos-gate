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

#ifndef	_CRYPTO_UTIL_H
#define	_CRYPTO_UTIL_H


#ifdef	__cplusplus
extern "C" {
#endif

#include <limits.h>
#include <security/cryptoki.h>
#include <security/pkcs11.h>
#include <kmfapi.h>

#include <sys/usb/usba/wusba_io.h>


#define	WUSB_DEV_MAC_LENGTH		6
#define	WUSB_CC_LABEL_LENGTH		(WUSB_DEV_MAC_LENGTH * 2 + 1)
#define	WUSB_TYPE_LEN			16

/*
 * wusb_cc_info.
 * Record the association information and it is
 * saved at /etc/usb/wusbcc
 */
typedef	struct wusb_cc_info {
	uint8_t			mac[WUSB_DEV_MAC_LENGTH];
	wusb_cc_t		cc;   /* cc info */
	char			type[WUSB_TYPE_LEN]; /* device/host path */
	uint8_t			host; /* Host id */
	uint16_t		dev;  /* Device id */
	char			flag; /* Onetime/Always */
} wusb_cc_info_t;


/* Device state definition */
#define	DEV_STAT_DISCONN	0x00
#define	DEV_STAT_CONNECT	0x01

/* wusbadm list structure */
typedef	struct wusb_cc_list {
	struct wusb_cc_list	*next;
	wusb_cc_info_t		info;   /* cc info */
	uint8_t			stat;	/* host or device state */
} wusb_cc_list_t;

typedef	struct wusb_device_info {
	char			type[WUSB_TYPE_LEN];
	uint8_t			host; /* host id */
	uint16_t		dev;  /* device id */
	uint8_t			stat; /* state */
} wusb_device_info_t;

/* cc generation functions */
int	wusb_crypto_init(KMF_HANDLE_T *, CK_SESSION_HANDLE *,
		const char *, const char *);
void	wusb_crypto_fini(KMF_HANDLE_T);

int	wusb_random(CK_SESSION_HANDLE, CK_BYTE *, size_t, CK_BYTE *, size_t);


void	mac_to_label(uint8_t *, char *);

void	print_array(const char *, CK_BYTE *, size_t);

int	chk_auths(uid_t, const char *);
#ifdef __cplusplus
}
#endif

#endif	/* _CRYPTO_UTIL_H */
