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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_GFX_PRIVATE_H
#define	_GFX_PRIVATE_H

#ifdef __cplusplus
extern "C" {
#endif

/* Memory cache attributes */
#define	GFXP_MEMORY_CACHED		0
#define	GFXP_MEMORY_UNCACHED		1
#define	GFXP_MEMORY_WRITECOMBINED	2

typedef uint64_t gfx_maddr_t;

extern int gfxp_ddi_segmap_setup(dev_t dev, off_t offset, struct as *as,
	caddr_t *addrp, off_t len, uint_t prot, uint_t maxprot, uint_t flags,
	cred_t *cred, ddi_device_acc_attr_t *accattrp, uint_t rnumber);

extern ddi_umem_cookie_t gfxp_umem_cookie_init(caddr_t kva, size_t size);
extern void gfxp_umem_cookie_destroy(ddi_umem_cookie_t cookie);
extern int gfxp_devmap_umem_setup(devmap_cookie_t dhc, dev_info_t *dip,
	struct devmap_callback_ctl *callbackops, ddi_umem_cookie_t cookie,
	offset_t off, size_t len, uint_t maxprot, uint_t flags,
	ddi_device_acc_attr_t *accattrp);
extern void gfxp_map_devmem(devmap_cookie_t dhc, gfx_maddr_t maddr,
	size_t length, ddi_device_acc_attr_t *attrp);


typedef char *gfxp_acc_handle_t;
extern gfxp_acc_handle_t gfxp_pci_init_handle(uint8_t bus, uint8_t slot,
	uint8_t function, uint16_t *vendor, uint16_t *device);
extern uint8_t gfxp_pci_read_byte(gfxp_acc_handle_t handle, uint16_t offset);
extern uint16_t gfxp_pci_read_word(gfxp_acc_handle_t handle, uint16_t offset);
extern uint32_t gfxp_pci_read_dword(gfxp_acc_handle_t handle, uint16_t offset);
extern void gfxp_pci_write_byte(gfxp_acc_handle_t handle, uint16_t offset,
	uint8_t value);
extern void gfxp_pci_write_word(gfxp_acc_handle_t handle, uint16_t offset,
	uint16_t value);
extern void gfxp_pci_write_dword(gfxp_acc_handle_t handle, uint16_t offset,
	uint32_t value);
extern int gfxp_pci_device_present(uint16_t vendor, uint16_t device);

typedef char *gfxp_kva_t;
extern gfxp_kva_t gfxp_map_kernel_space(uint64_t start, size_t size,
	uint32_t mode);
extern void gfxp_unmap_kernel_space(gfxp_kva_t address, size_t size);
extern int gfxp_va2pa(struct as *as, caddr_t addr, uint64_t *pa);
extern void gfxp_fix_mem_cache_attrs(caddr_t kva_start, size_t length,
	int cache_attr);
extern gfx_maddr_t gfxp_convert_addr(paddr_t paddr);

typedef char *gfxp_vgatext_softc_ptr_t;

extern gfxp_vgatext_softc_ptr_t gfxp_vgatext_softc_alloc(void);
extern void gfxp_vgatext_softc_free(gfxp_vgatext_softc_ptr_t ptr);
extern int gfxp_vgatext_attach(dev_info_t *devi, ddi_attach_cmd_t cmd,
	gfxp_vgatext_softc_ptr_t ptr);
extern int gfxp_vgatext_detach(dev_info_t *devi, ddi_detach_cmd_t cmd,
	gfxp_vgatext_softc_ptr_t ptr);
extern int gfxp_vgatext_open(dev_t *devp, int flag, int otyp, cred_t *cred,
	gfxp_vgatext_softc_ptr_t ptr);
extern int gfxp_vgatext_close(dev_t devp, int flag, int otyp, cred_t *cred,
	gfxp_vgatext_softc_ptr_t ptr);
extern int gfxp_vgatext_ioctl(dev_t dev, int cmd, intptr_t data, int mode,
	cred_t *cred, int *rval, gfxp_vgatext_softc_ptr_t ptr);

extern int gfxp_mlock_user_memory(caddr_t address, size_t length);
extern int gfxp_munlock_user_memory(caddr_t address, size_t length);
extern int gfxp_vgatext_devmap(dev_t dev, devmap_cookie_t dhp, offset_t off,
	size_t len, size_t *maplen, uint_t model, void *ptr);

#ifdef __cplusplus
}
#endif

#endif /* _GFX_PRIVATE_H */
