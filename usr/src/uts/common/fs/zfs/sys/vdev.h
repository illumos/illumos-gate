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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_VDEV_H
#define	_SYS_VDEV_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/spa.h>
#include <sys/zio.h>
#include <sys/dmu.h>
#include <sys/space_map.h>
#include <sys/fs/zfs.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Vdev knobs.
 */
typedef struct vdev_knob {
	char		*vk_name;		/* knob name		*/
	char		*vk_desc;		/* knob description	*/
	uint64_t	vk_min;			/* minimum legal value	*/
	uint64_t	vk_max;			/* maximum legal value	*/
	uint64_t	vk_default;		/* default value	*/
	size_t		vk_offset;		/* offset into vdev_t	*/
} vdev_knob_t;

/*
 * Fault injection modes.
 */
#define	VDEV_FAULT_NONE		0
#define	VDEV_FAULT_RANDOM	1
#define	VDEV_FAULT_COUNT	2

extern int vdev_open(vdev_t *);
extern void vdev_close(vdev_t *);
extern int vdev_create(vdev_t *, uint64_t txg);
extern void vdev_init(vdev_t *, uint64_t txg);
extern void vdev_reopen(vdev_t *, zio_t **zq);

extern vdev_t *vdev_lookup_top(spa_t *spa, uint64_t vdev);
extern vdev_t *vdev_lookup_by_path(vdev_t *vd, const char *path);
extern vdev_t *vdev_lookup_by_guid(vdev_t *vd, uint64_t guid);
extern void vdev_dtl_dirty(space_map_t *sm, uint64_t txg, uint64_t size);
extern int vdev_dtl_contains(space_map_t *sm, uint64_t txg, uint64_t size);
extern void vdev_dtl_reassess(vdev_t *vd, uint64_t txg, uint64_t scrub_txg,
    int scrub_done);

extern const char *vdev_description(vdev_t *vd);

extern void vdev_metaslab_init(vdev_t *vd, uint64_t txg);
extern void vdev_metaslab_fini(vdev_t *vd);

extern void vdev_get_stats(vdev_t *vd, vdev_stat_t *vs);
extern void vdev_stat_update(zio_t *zio);
extern void vdev_scrub_stat_update(vdev_t *vd, pool_scrub_type_t type,
    boolean_t complete);
extern void vdev_checksum_error(zio_t *zio, vdev_t *vd);
extern int vdev_getspec(spa_t *spa, uint64_t vdev, char **vdev_spec);
extern void vdev_set_state(vdev_t *vd, vdev_state_t state, vdev_aux_t aux);

extern void vdev_space_update(vdev_t *vd, uint64_t space_delta,
    uint64_t alloc_delta);

extern uint64_t vdev_psize_to_asize(vdev_t *vd, uint64_t psize);

extern void vdev_io_start(zio_t *zio);
extern void vdev_io_done(zio_t *zio);

extern int vdev_online(spa_t *spa, const char *path);
extern int vdev_offline(spa_t *spa, const char *path, int istmp);

extern int vdev_error_setup(spa_t *spa, const char *path, int mode, int mask,
    uint64_t arg);
extern int vdev_error_inject(vdev_t *vd, zio_t *zio);
extern int vdev_is_dead(vdev_t *vd);

extern void vdev_cache_init(vdev_t *vd);
extern void vdev_cache_fini(vdev_t *vd);
extern int vdev_cache_read(zio_t *zio);
extern void vdev_cache_write(zio_t *zio);

extern void vdev_queue_init(vdev_t *vd);
extern void vdev_queue_fini(vdev_t *vd);
extern zio_t *vdev_queue_io(zio_t *zio);
extern void vdev_queue_io_done(zio_t *zio);

extern vdev_knob_t *vdev_knob_next(vdev_knob_t *vk);

extern void vdev_config_dirty(vdev_t *vd);
extern void vdev_config_clean(vdev_t *vd);

extern nvlist_t *vdev_config_generate(vdev_t *vd, int getstats);

/*
 * Label routines
 */
struct uberblock;
extern uint64_t vdev_label_offset(uint64_t psize, int l, uint64_t offset);
extern nvlist_t *vdev_label_read_config(vdev_t *vd);
extern void vdev_uberblock_load(zio_t *zio, vdev_t *vd, struct uberblock *ub);
int vdev_label_init(vdev_t *vd, uint64_t create_txg);
extern int spa_sync_labels(spa_t *spa, uint64_t txg);

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_VDEV_H */
