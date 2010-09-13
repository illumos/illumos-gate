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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SD_SAFESTORE_H
#define	_SD_SAFESTORE_H

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/nsc_thread.h>
#ifdef DS_DDICT
#include <sys/nsctl/contract.h>
#endif
#include <sys/nsctl/nsctl.h>
#if defined(_KERNEL) || defined(_KMEMUSER)

/* CSTYLED */
/**$
 * token for a volume directory stream
 */
typedef struct ss_vdir_s {
	intptr_t opaque[6];
} ss_vdir_t;

/* CSTYLED */
/**$
 * token for a cache entry directory stream
 */
typedef struct ss_cdir_s {
	intptr_t opaque[6];
}ss_cdir_t;

/* CSTYLED */
/**$
 * token for a volume
 */
typedef struct ss_vol_s {
	intptr_t opaque;
}ss_vol_t;

/* CSTYLED */
/**$
 * token for cache entry block and dirty bits
 */
typedef struct s_resource_s {
	intptr_t opaque;
} ss_resource_t;

/* CSTYLED */
/**$
 * token for a list of cache safestore resources
 */
typedef struct ss_resourcelist_s {
	intptr_t opaque;
}ss_resourcelist_t;


/* CSTYLED */
/**$
 * cache entry directory stream type specifier
 *
 * @field ck_type specifies all cache entries, cache entries for volume, node
 * @field ck_vol volume token if ck_type is CDIR_VOL
 * @field ck_node node id if ck_type is node CDIR_NODE
 */
typedef struct ss_cdirkey_s {
	uint_t   ck_type; /* discriminator: see type defines below */
	union {
		ss_vol_t *ck_vol;
		uint_t   ck_node;
	} cdk_u;
} ss_cdirkey_t;

/* centry directory stream types */
#define	CDIR_ALL 0
#define	CDIR_VOL 1
#define	CDIR_NODE 2

/* BEGIN CSTYLED */
/**$
 * exported cache entry info
 *
 * @field sc_cd the cache descriptor, associates this entry with a volume
 * @field sc_fpos file position in cache blocks
 * @field sc_dirty dirty bits, one for each fba in the cache block
 * @field sc_flag flags
 * @field sc_res safestore resource token for this cache entry
 * @see ss_voldata_t{}
 */
typedef struct ss_centry_info_s {
	int sc_cd;		/* Cache descriptor */
	nsc_off_t sc_fpos;	/* File position    */
	int sc_dirty;		/* Dirty mask	    */
	int sc_flag;		/* CC_PINNABLE | CC_PINNED */
	ss_resource_t *sc_res;	/* token for this centry */
} ss_centry_info_t;
/* END CSTYLED */


/* CSTYLED */
/**$
 * volume directory stream type specifier
 *
 * @field vk_type specifies all volume entries, entries for volume, node
 * @field vk_vol volume token if vk_type is VDIR_VOL
 * @field vk_node node id if vk_type is node VDIR_NODE
 */
typedef struct ss_vdirkey_s {
	uint_t   vk_type; /* discriminator: see type defines below */
	union {
		ss_vol_t *vk_vol;
		uint_t   vk_node;
	} cdk_u;
} ss_vdirkey_t;

/* volume directory stream types */
#define	VDIR_ALL 0
#define	VDIR_VOL 1
#define	VDIR_NODE 2

/* CSTYLED */
/**$
 * exported volume entry info
 *
 * @field sv_cd the cache descriptor
 * @field sv_vol the safestore volume token for this volume
 * @field sv_pinned volume has pinned blocks, holds node id
 * @field sv_attached node which has attached this volume
 * @field sv_volname path name
 * @field sv_devidsz length of device id, the sv_devid
 * @field sv_devid unique id for physical, i.e. non-volume-managed volumes
 */
typedef struct ss_voldata_s {
	int  sv_cd;			/* NOTE may need dual node map info */
	ss_vol_t *sv_vol;		/* volume token for this vol entry */
	int  sv_pinned;			/* Device has failed/pinned blocks */
	int  sv_attached;		/* Node which has device attached */
	char sv_volname[NSC_MAXPATH];	/* Filename */
	int  sv_devidsz;		/* unique dev id length */
	uchar_t sv_devid[NSC_MAXPATH];	/* wwn id - physical devs only */
} ss_voldata_t;

/* safestore media types */

/* CSTYLED */
/**%
 * safestore in RAM, useful but not very safe
 */
#define	SS_M_RAM 0x00000001

/* CSTYLED */
/**%
 * safestore in NVRAM on a single node
 */
#define	SS_M_NV_SINGLENODE 0x00000002

/* CSTYLED */
/**%
 * safestore in NVRAM on a dual node system. all data is store remotely.
 */
#define	SS_M_NV_DUALNODE_NOMIRROR 0x00000004

/* CSTYLED */
/**%
 * safestore in NVRAM on a dual node system. data is mirrored on both nodes.
 */
#define	SS_M_NV_DUALNODE_MIRROR 0x00000008


/* safestore data and metadata transport types */

/* CSTYLED */
/**%
 * data is transferred using STE connection
 */
#define	SS_T_STE   0x00010000

/* CSTYLED */
/**%
 * data is transferred using RPC
 */
#define	SS_T_RPC 0x00020000

/* CSTYLED */
/**%
 * no transport -- (single node)
 */
#define	SS_T_NONE  0x08000000

#define	SS_MEDIA_MASK 0x0000ffff
#define	SS_TRANSPORT_MASK 0xffff0000

#define	_SD_NO_NET 0
#define	_SD_NO_NETADDR 0
#define	_SD_NO_HOST -1
#define	_SD_NO_CD -1

/* config settings */
#define	SS_UNCONFIGURED 0
#define	SS_INITTED 1
#define	SS_CONFIGURED 2

/* error return for safestore ops */
#define	SS_ERR -1
#define	SS_OK  0
#define	SS_EOF 1

/* config flag */
#define	SS_GENPATTERN 1

/*
 * convenience macros.  should they be implemented in ss_ctl()?
 */

/* is safestore on a single node? */
#define	SAFESTORE_LOCAL(ssp) ((ssp) && (ssp->ssop_type & SS_T_NONE))

/* is safestore really safe or is it just RAM? */
#define	SAFESTORE_SAFE(ssp)  ((ssp) && !(ssp->ssop_type & SS_M_RAM))

/* is recovery needed with this safestore module? */
#define	SAFESTORE_RECOVERY(ssp) ((ssp) && \
				(ssp->ssop_flags & SS_RECOVERY_NEEDED))

/* CSTYLED */
/**$
 * configuration structure provided by safestore client
 *
 * @field ssc_configured set by safestore module to indicate config completed
 * @field ssc_ss_psize safestore internal page size, set by ss module
 * @field ssc_client_psize callers page size
 * @field ssc_wsize cache size in bytes: amount of data that can be safestored
 * @field ssc_maxfiles maximum number of volumes
 * @field ssc_pattern initialization pattern if any
 * @field ssc_flag use ssc_pattern if this is SS_GENPATTERN
 */
typedef struct ss_common_config_s {
	uint_t ssc_configured;
	uint_t ssc_ss_psize;	/* safestore internal page size */
	uint_t ssc_client_psize;	/* client page size */
	uint_t ssc_wsize;	/* Write cache size in bytes */
	int ssc_maxfiles;	/* max files */
	uint_t ssc_pattern;	/* initialization pattern */
	uint_t ssc_flag;
} ss_common_config_t;

/* BEGIN CSTYLED */
/**$
 * safestore operations structure
 *
 * @field ssop_name description of this module.
 * @field ssop_type media type OR'd with transport type
 * @field ssop_flags  SS_RECOVERY_NEEDED
 * @field ssop_configure configure the module
 * @field ssop_deconfigure deconfigure the module
 * @field ssop_getvdir get a volume directory stream according to type
 * @field ssop_getvdirent get next entry in a volume directory stream
 * @field ssop_getvol get the data for a volume
 * @field ssop_setvol set the data for a volume
 * @field ssop_getcdir get cache entry directory stream according to type
 * @field ssop_getcdirent get next cache entry in stream
 * @field ssop_allocresource allocate safestore resources from free list
 * @field ssop_deallocresource deallocate, i.e. free, a safestore resource
 * @field ssop_getresource get next resource in resource list
 * @field ssop_getcentry get metadata for a cache entry
 * @field ssop_setcentry set the metadata for a cache entry
 * @field ssop_read_cblock read the actual data for a cache entry
 * @field ssop_write_cblock write the data for a cache entry
 * @field ssop_ctl module entry point for everything else, e.g. stats
 *
 * @see ss_vdirkey_t{}
 * @see ss_voldata_t{}
 * @see ss_cdirkey_t{}
 * @see ss_resourcelist_t{}
 * @see ss_resource_t{}
 * @see ss_centry_info_t{}
 */
typedef struct safestore_ops_s {
	char *ssop_name;
	uint_t  ssop_type; /* media type OR'd with transport type */
	uint_t ssop_flags; /* recovery needed, etc */
	int (* ssop_configure)(ss_common_config_t *, spcs_s_info_t);
	int (* ssop_deconfigure)(int);
	int (* ssop_getvdir)(const ss_vdirkey_t *, ss_vdir_t *);
	int (* ssop_getvdirent)(const ss_vdir_t *, ss_voldata_t *);
	int (* ssop_getvol)(ss_voldata_t *);
	int (* ssop_setvol)(const ss_voldata_t *);
	int (* ssop_getcdir)(const ss_cdirkey_t *, ss_cdir_t *);
	int (* ssop_getcdirent)(ss_cdir_t *, ss_centry_info_t *);
	int (* ssop_allocresource)(int, int *, ss_resourcelist_t **);
	void (* ssop_deallocresource)(ss_resource_t *);
	int (* ssop_getresource)(ss_resourcelist_t **, ss_resource_t **);
	int (* ssop_getcentry)(ss_centry_info_t *);
	int (* ssop_setcentry)(const ss_centry_info_t *);
	int (* ssop_read_cblock)(const ss_resource_t *, void *, int, int);
	int (* ssop_write_cblock)(const ss_resource_t *,
						const void *, int, int);
	int (* ssop_ctl)(uint_t, uintptr_t);
} safestore_ops_t;
/* END CSTYLED */

/* ssop_flags */
/*
 * no writes permitted when this bit is set in ssop flags field
 * (single node nvram mostly)
 */
#define	SS_RECOVERY_NEEDED 1

/* safestore operations */

/* BEGIN CSTYLED */
/**#
 * SSOP_CONFIGURE() configure a safestore module
 * @param ssp a safestore_ops_t pointer obtained from sst_open()
 * @param cfg a pointer to ss_common_config_t, initialized by caller
 * @param kstatus unistat spcs_s_info_t
 * @return SS_OK successful, errno otherwise
 *
 * @see safestore_ops_t{}
 * @see sst_open()
 * @see ss_common_config_t{}
 */
#define	SSOP_CONFIGURE(ssp, cfg, kstatus) \
	((ssp)->ssop_configure(cfg, kstatus))

/**#
 * SSOP_DECONFIGURE deconfigure a safestore module
 * @param ssp a safestore_ops_t pointer obtained from sst_open()
 * @param dirty integer flag, if set it signifies there is pinned data
 * @return SS_OK success, SS_ERR otherwise
 *
 * @see safestore_ops_t{}
 */
#define	SSOP_DECONFIGURE(ssp, dirty) ((ssp)->ssop_deconfigure(dirty))


/* volume directory functions */

/**#
 * SSOP_GETVDIR   get a volume directory stream according to type
 * @param ssp	a safestore_ops_t pointer obtained from sst_open()
 * @param key	pointer to ss_vdirkey_t initialized by caller
 * @param vdir	pointer to ss_vdir_t owned by caller
 * @return SS_OK success, SS_ERR otherwise
 *
 * @see safestore_ops_t{}
 * @see ss_vdirkey_t{}
 * @see ss_vdir_t{}
 */
#define	SSOP_GETVDIR(ssp, key, vdir) ((ssp)->ssop_getvdir(key, vdir))

/**#
 * SSOP_GETVDIRENT get next volume in a volume directory stream
 * @param ssp	a safestore_ops_t pointer obtained from sst_open()
 * @param vdir	pointer to a properly initialized ss_vdir_t obtained
 *              from a successsful SSOP_GETVDIR() call
 * @param voldata	pointer to ss_voldata_t owned by caller, filled
 *                      in with valid data on successful return
 * @return SS_OK success
 *         SS_EOF if no more elements in stream,
 *         SS_ERR otherwise
 *
 * @see safestore_ops_t{}
 * @see sst_open()
 * @see ss_vdir_t{}
 * @see ss_voldata_t{}
 * @see SSOP_GETVDIR()
 */
#define	SSOP_GETVDIRENT(ssp, vdir, voldata) \
		((ssp)->ssop_getvdirent(vdir, voldata))

/* volume accessor functions */

/**#
 * SSOP_GETVOL get the volume data for a particular volume
 * @param ssp a safestore_ops_t pointer obtained from sst_open()
 * @param voldata pointer to ss_voldata_t owned by caller, field sv_vol
 *                must be initialized with a valid ss_vol_t, normally
 *                obtained from a successful SSOP_GETVDIRENT() call.
 *                the rest of the structure is filled with valid volume data
 *                on successful return
 * @return SS_OK if data read successfully
 *         SS_ERR otherwise
 * @see safestore_ops_t{}
 * @see sst_open()
 * @see ss_voldata_t{}
 * @see ss_vol_t{}
 * @see SSOP_GETVDIRENT()
 */
#define	SSOP_GETVOL(ssp, voldata) ((ssp)->ssop_getvol(voldata))


/**#
 * SSOP_SETVOL set the volume data for a particular volume
 * @param ssp a safestore_ops_t pointer obtained from sst_open()
 * @param voldata   pointer to ss_voldata_t owned by caller, field sv_vol
 *                  must be initialized with a valid ss_vol_t, obtained from
 *                  a successful SSOP_GETVDIRENT() call. the remaining
 *                  fields of the structure are written to safestore
 * @return SS_OK if data saved successfully
 *         SS_ERR otherwise
 * @see safestore_ops_t{}
 * @see sst_open()
 * @see ss_voldata_t{}
 * @see ss_vol_t{}
 * @see SSOP_GETVDIRENT()
 */
#define	SSOP_SETVOL(ssp, voldata) ((ssp)->ssop_setvol(voldata))

/* centry directory functions */

/**#
 * SSOP_GETCDIR	get a cache entry stream accroding to type
 * @param ssp	a safestore_ops_t pointer obtained from sst_open()
 * @param key	pointer to a ss_cdirkey_t initialized by caller
 * @param cdir	pointer to ss_cdir_t owned by caller
 * @return SS_OK success, SS_ERR otherwise
 *
 * @see safestore_ops_t{}
 * @see sst_open()
 * @see ss_cdirkey_t{}
 * @ see ss_cdir_t{}
 */
#define	SSOP_GETCDIR(ssp, key, cdir) \
	((ssp)->ssop_getcdir(key, cdir))

/**#
 * SSOP_GETCDIRENT get next cache entry in a cache entry stream
 * @param ssp	a safestore_ops_t pointer obtained from sst_open()
 * @param cdir	pointer to valid ss_cdirkey_t obtained from a
 *              successsful SSOP_GETCDIR call
 * @param voldata	pointer to ss_voldata_t owned by caller, filled
 *                      in with valid data on successful return
 * @return SS_OK success
 *         SS_EOF if no more elements in stream,
 *         SS_ERR otherwise
 *
 * @see safestore_ops_t{}
 * @see sst_open()
 * @see ss_vdirkey_t{}
 * @see ss_voldata_t{}
 * @see SSOP_GETVDIR()
 */
#define	SSOP_GETCDIRENT(ssp, cdir, centry) \
			((ssp)->ssop_getcdirent(cdir, centry))

/* cache entry alloc functions */

/**#
 * SSOP_ALLOCRESOURCE allocate safestore resources from the free list
 * @param ssp	a safestore_ops_t pointer obtained from sst_open()
 * @param count	number of resources, that is data blocks, needed
 * @param stall	integer pointer to stall count, no blocks available.  used only
 *              when _sd_wblk_sync === 0
 * @param reslist pointer to pointer to ss_resourcelist_t. points to valid
 *                resource list on successful return
 * @return SS_OK success
 *         SS_ERR otherwise
 *
 * @see safestore_ops_t{}
 * @see ss_resourcelist_t{}
 * @see SSOP_DEALLOCRESOURCE()
 * @see SSOP_GETRESOURCE()
 */
#define	SSOP_ALLOCRESOURCE(ssp, count, stall, reslist) \
		((ssp)->ssop_allocresource(count, stall, reslist))

/**#
 * SSOP_DEALLOCRESOURCE deallocate, i.e. release, a single safestore resource
 * @param ssp	a safestore_ops_t pointer obtained from sst_open()
 * @param res   pointer to ss_resource_t to be released
 * @return void
 *
 * @see safestore_ops_t{}
 * @see ss_resource_t{}
 * @see SSOP_ALLOCRESOURCE()
 * @see SSOP_GETRESOURCE()
 */
#define	SSOP_DEALLOCRESOURCE(ssp, res) \
		((ssp)->ssop_deallocresource(res))

/**#
 * SSOP_GETRESOURCE get the next safestore resource in a list
 * @param ssp	a safestore_ops_t pointer obtained from sst_open()
 * @param reslist pointer to pointer to ss_resourcelist_t obtained from
 *                a successful call to SSOP_ALLOCRESOURCE()
 * @param res   pointer to pointer to ss_resource_t.  points to a valid
 *              on successful resource
 * @return SS_OK success
 *         SS_EOF if no more resources in list
 *         SS_ERR otherwise
 *
 * @see safestore_ops_t{}
 * @see ss_resourcelist_t{}
 * @see ss_resource_t{}
 * @see SSOP_ALLOCRESOURCE()
 * @see SSOP_DEALLOCRESOURCE()
 */
#define	SSOP_GETRESOURCE(ssp, reslist, res) \
		((ssp)->ssop_getresource(reslist, res))

/* centry accessor functions */


/**#
 * SSOP_GETCENTRY read cache entry metadata for a particular cache entry
 * @param ssp	a safestore_ops_t pointer obtained from sst_open()
 * @param centry_info  pointer to ss_centry_info_t owned by caller.
 *                     field sc_res must point to a valid ss_resource_t
 *                     obtained from a successful call to SSOP_GETRESOURCE().
 *                     the rest of the structure is filled with valid
 *                     metadata on successful return
 * @return SS_OK if data was read successfully
 *         SS_ERR otherwise
 *
 * @see safestore_ops_t{}
 * @see sst_open()
 * @see ss_centry_info_t
 * @see ss_resource_t{}
 * @see SSOP_GETRESOURCE()
 */
#define	SSOP_GETCENTRY(ssp, centry_info) \
		((ssp)->ssop_getcentry(centry_info))

/**#
 * SSOP_SETCENTRY write cache entry metadata for a particular cache entry
 * @param ssp	a safestore_ops_t pointer obtained from sst_open()
 * @param centry_info  pointer to ss_centry_info_t owned by caller.
 *                     field sc_res must point to a valid ss_resource_t
 *                     obtained from a successful call to SSOP_GETRESOURCE().
 *                     the remaining fields of the structured are written
 *                     to safestore.
 * @return SS_OK if data was written successfully
 *         SS_ERR otherwise
 *
 * @see safestore_ops_t{}
 * @see sst_open()
 * @see ss_centry_info_t{}
 * @see ss_resource_t{}
 * @see SSOP_GETRESOURCE()
 */
#define	SSOP_SETCENTRY(ssp, centry_info) \
		((ssp)->ssop_setcentry(centry_info))

/* cache data block read/write and ctl */


/**#
 * SSOP_READ_CBLOCK read cache data for a particular cache entry
 * @param ssp	a safestore_ops_t pointer obtained from sst_open()
 * @param resource  pointer to ss_resource_t obtained from a successful
 *                  call to SSOP_GETRESOURCE().
 * @param buf       buffer to hold the data
 * @param nbyte     number of bytes to read
 * @param srcoffset    byte location from beginning of the cache block
 *                     represented by resource to read the data from
 *
 * @return SS_OK if data was read successfully
 *         SS_ERR otherwise
 *
 * @see safestore_ops_t{}
 * @see sst_open()
 * @see ss_resource_t{}
 * @see SSOP_GETRESOURCE()
 */
#define	SSOP_READ_CBLOCK(ssp, resource, buf, nbyte, srcoffset) \
		((ssp)->ssop_read_cblock(resource, buf, nbyte, srcoffset))
/**#
 * SSOP_WRITE_CBLOCK write cache data for a particular cache entry
 * @param ssp	a safestore_ops_t pointer obtained from sst_open()
 * @param resource  pointer to ss_resource_t obtained from a successful
 *                  call to SSOP_GETRESOURCE().
 * @param buf       buffer to hold the data
 * @param nbyte     number of bytes to write
 * @param destoffset    byte location from beginning the cache block
 *                      represented by resource to write the data to
 *
 * @return SS_OK if data was read successfully
 *         SS_ERR otherwise
 *
 * @see safestore_ops_t{}
 * @see sst_open()
 * @see ss_resource_t{}
 * @see SSOP_GETRESOURCE()
 */
#define	SSOP_WRITE_CBLOCK(ssp, resource, buf, nbyte, destoffset) \
		((ssp)->ssop_write_cblock(resource, buf, nbyte, destoffset))

/**#
 * SSOP_CTL perform a safestore control function
 * @param cmd  integer specifying the command to execute, e.g. SSIOC_STATS.
 *             some commands may be specific to a safestore module type
 * @param arg  a uintptr_t that has additional information that is
 *             needed by the safestore module to perform the command.  it
 *             may be an int or a pionter to a module specifc structure.
 * @return SS_OK success
 *         errno otherwise
 */
#define	SSOP_CTL(ssp, cmd, arg) ((ssp)->ssop_ctl(cmd, arg))

/* END CSTYLED */

/* general control definitions supported by safestore modules */

#define	SSCTL(x)	(('S'<< 16)|('S'<< 8)|(x))

#define	SSIOC_STATS	SSCTL(1)
#define	SSIOC_SETFLAG	SSCTL(2)

/* structure definitions */

typedef struct ssioc_stats_s {
	int	wq_inq;		/* write queue count */
} ssioc_stats_t;

extern void sst_init();
extern void sst_register_mod(safestore_ops_t *);
extern void sst_unregister_mod(safestore_ops_t *);
extern safestore_ops_t *sst_open(uint_t, ...);
extern int sst_close(safestore_ops_t *);

extern safestore_ops_t *sdbc_safestore;

extern int _sd_centry_shift;

#endif /* _KERNEL */

#ifdef __cplusplus
}
#endif

#endif	/* _SD_SAFESTORE_H */
