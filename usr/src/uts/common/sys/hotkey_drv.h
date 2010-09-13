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

#ifndef _HOTKEY_DRV_H
#define	_HOTKEY_DRV_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <sys/conf.h>
#include <sys/stat.h>
#include <sys/note.h>
#include <sys/modctl.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/acpi/acpi.h>
#include <sys/acpica.h>
#include <sys/sysevent/eventdefs.h>
#include <sys/acpi_drv.h>


#define	ID_LEN		9

struct acpi_drv_dev {
	ACPI_HANDLE hdl;
	char hid[ID_LEN];	/* ACPI HardwareId */
	char uid[ID_LEN];	/* ACPI UniqueId */
	ACPI_INTEGER adr;	/* Bus device Id */
	int valid;		/* the device state is valid */

	/*
	 * Unlike most other devices, when a battery is inserted or
	 * removed from the system, the device itself(the battery bay)
	 * is still considered to be present in the system.
	 *
	 * Value:
	 *    0 -- Off-line
	 *    1 -- On-line
	 *   -1 -- Unknown
	 */
	int present;
	enum acpi_drv_type type;
	int index;	/* device index */
	int minor;
};

/*
 * hotkey driver soft-state structure
 */
typedef struct hotkey_drv {
	struct acpi_drv_dev	dev;
	dev_info_t		*dip;
	void			*private;	/* Vendor specific structure */
	kmutex_t		*hotkey_lock;
	int			hotkey_method;
	int			modid;
	int			(*vendor_ioctl)(struct hotkey_drv *,
				    int cmd, intptr_t arg, int mode,
				    cred_t *cr, int *rval);
	int			(*vendor_fini)(struct hotkey_drv *);
	boolean_t		check_acpi_video;
	void			*acpi_video;
} hotkey_drv_t;

/*
 * Collection of vendor specific hotkey support
 */
struct vendor_hotkey_drv {
	const char		*vid;
	const char		*module;
	boolean_t		enable;
};

#define	HOTKEY_DRV_OK			0
#define	HOTKEY_DRV_ERR			-1
#define	HOTKEY_DBG_NOTICE		0x8000
#define	HOTKEY_DBG_WARN			0x0001

#define	HOTKEY_METHOD_NONE		0x0
#define	HOTKEY_METHOD_VENDOR		0x1
#define	HOTKEY_METHOD_ACPI_VIDEO	0x2
#define	HOTKEY_METHOD_MISC		(HOTKEY_METHOD_VENDOR | \
					HOTKEY_METHOD_ACPI_VIDEO)
/*
 * Inter-source-file linkage ...
 */
extern struct hotkey_drv acpi_hotkey;
extern int hotkey_drv_debug;
int acpi_drv_set_int(ACPI_HANDLE dev, char *method, uint32_t aint);
void acpi_drv_gen_sysevent(struct acpi_drv_dev *devp, char *ev, uint32_t val);
int acpi_drv_dev_init(struct acpi_drv_dev *p);

int hotkey_init(hotkey_drv_t *htkp);
int hotkey_fini(hotkey_drv_t *htkp);
int acpi_drv_hotkey_ioctl(int cmd, intptr_t arg, int mode, cred_t *cr,
    int *rval);
int acpi_video_ioctl(void *vidp, int cmd, intptr_t arg, int mode, cred_t *cr,
    int *rval);
int hotkey_brightness_inc(hotkey_drv_t *htkp);
int hotkey_brightness_dec(hotkey_drv_t *htkp);
void hotkey_drv_gen_sysevent(dev_info_t *, char *);

#ifdef	__cplusplus
}
#endif

#endif /* _HOTKEY_DRV_H */
