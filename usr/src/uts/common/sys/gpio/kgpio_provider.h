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
 * Copyright 2022 Oxide Computer Company
 */

#ifndef _SYS_GPIO_KGPIO_PROVIDER_H
#define	_SYS_GPIO_KGPIO_PROVIDER_H

/*
 * This header describes the private interface between the kernel GPIO framework
 * and GPIO providers.
 */

#include <sys/nvpair.h>
#include <sys/stdint.h>

#include <sys/gpio/dpio.h>
#include <sys/gpio/kgpio_attr.h>

#ifdef __cplusplus
extern "C" {
#endif


/*
 * The remainder of this header is intended for kernel implementations of the
 * KGPIO framework.
 */
#ifdef _KERNEL

typedef int (*kgpio_name2id_f)(void *, const char *, uint32_t *);
typedef int (*kgpio_attr_get_f)(void *, uint32_t, nvlist_t *);
typedef int (*kgpio_attr_set_f)(void *, uint32_t, nvlist_t *, nvlist_t *);
typedef int (*kgpio_dpio_cap_f)(void *, uint32_t, dpio_caps_t *);
typedef int (*kgpio_dpio_input_f)(void *, uint32_t, dpio_input_t *);
typedef int (*kgpio_dpio_output_get_f)(void *, uint32_t, dpio_output_t *);
typedef int (*kgpio_dpio_output_set_f)(void *, uint32_t, dpio_output_t);

typedef struct kgpio_ops {
	kgpio_name2id_f		kgo_name2id;
	kgpio_attr_get_f	kgo_get;
	kgpio_attr_set_f	kgo_set;
	kgpio_dpio_cap_f	kgo_cap;
	kgpio_dpio_input_f	kgo_input;
	kgpio_dpio_output_get_f	kgo_output_state;
	kgpio_dpio_output_set_f	kgo_output;
} kgpio_ops_t;

extern int kgpio_register(dev_info_t *, const kgpio_ops_t *, void *, uint32_t);
extern int kgpio_unregister(dev_info_t *);

/*
 * These are convenience functions for filling in information about an
 * attribute.
 */
extern void kgpio_nvl_attr_fill_u32(nvlist_t *, nvlist_t *, const char *,
    uint32_t, uint_t, uint32_t *, kgpio_prot_t);
extern void kgpio_nvl_attr_fill_str(nvlist_t *, nvlist_t *, const char *,
    const char *, uint_t, char *const *, kgpio_prot_t);

#endif	/* _KERNEL */

#ifdef __cplusplus
}
#endif

#endif /* _SYS_GPIO_KGPIO_PROVIDER_H */
