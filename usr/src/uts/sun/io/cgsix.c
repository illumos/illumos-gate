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


#pragma	weak	setintrenable
/*
 * Cgsix theory of operation:
 *
 * Most cg6 operations are done by mapping the cg6 components into
 * user process memory.  User processes that share mappings (typically
 * pixrect programs) must cooperate among themselves to prevent damaging
 * the state of the cg6.  User processes may also acquire private
 * mappings (MAP_PRIVATE flag to mmap(2)), in which case the cg6 segment
 * driver will preserve device state for each mapping.
 *
 * Note that the segment driver may go away in the future.
 *
 * cg6_mmap interprets the device offset as follows:
 *
 *	CG6_VBASE	0x70000000
 *	CG6_VADDR_FBC	0x70000000	fbc mapping
 *	CG6_VADDR_TEC	0x70001000	tec mapping
 *	CG6_VADDR_CMAP	0x70002000	colormap dacs
 *	CG6_VADDR_FHC	0x70004000	fhc mapping
 *	CG6_VADDR_THC	0x70005000	thc mapping
 *	CG6_VADDR_ROM	0x70006000	eprom mapping
 *	CG6_VADDR_COLOR	0x70016000	framebuffer mapping
 *	CG6_VADDR_DHC	0x78000000	dac hardware
 *	CG6_VADDR_ALT	0x78002000	alternate registers (?)
 *	CG6_VADDR_UART	0x78004000	uart, if any
 *	CG6_VADDR_VRT	0x78006000	vertical retrace counter page
 *
 * The lengths of these mappings should be:
 *
 *	CG6_CMAP_SZ	0x2000
 *	CG6_FBCTEC_SZ	0x2000
 *	CG6_FHCTHC_SZ	0x2000
 *	CG6_ROM_SZ	0x10000
 *	CG6_FB_SZ	0x100000
 *	CG6_DHC_SZ	0x2000
 *	CG6_ALT_SZ	0x2000
 *
 * Mappings to the fbc and tec registers may be MAP_PRIVATE, in which case
 * the segment driver keeps a per-context copy of the fbc and tec
 * registers in local memory.  Only one context at a time may have valid
 * mappings.  If a process tries to access the registers through an
 * invalid mapping, the segment driver in invoked to swap register state
 * and validate the mappings.
 *
 * In the case of the buggy LSC revision 2. chip, the framebuffer mapping
 * is also considered part of a context.  This is to ensure that the
 * registers are idle before the framebuffer is touched.
 *
 * Mappings to FBC, TEC and framebuffer may be made seperately, in which
 * case the driver uses heuristics to bind seperate mappings into a single
 * context.  These heuristics may break down if mappings are done in a
 * funny order or in a multi-threaded environment, so seperate mappings
 * are not recommended.
 *
 * Finally, processes have the option of mapping the "vertical retrace
 * page".  This is a page in shared memory containing a 32-bit integer
 * that is incremented each time a vertical retrace interrupt occurs.  It
 * is used so that programs may synchronize themselves with vertical
 * retrace.
 */

/*
 * SBus accelerated 8 bit color frame buffer driver
 */

#include <sys/debug.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/time.h>
#include <sys/buf.h>
#include <sys/errno.h>
#include <sys/systm.h>
#include <sys/conf.h>

#include <sys/model.h>

#include <sys/file.h>
#include <sys/uio.h>
#include <sys/ioctl.h>
#include <sys/proc.h>
#include <sys/user.h>
#include <sys/sysmacros.h>
#include <sys/mman.h>
#include <sys/cred.h>
#include <sys/open.h>
#include <sys/stat.h>

#include <sys/visual_io.h>
#include <sys/fbio.h>

#include <sys/cg6reg.h>
#include <sys/kmem.h>
#include <sys/cmn_err.h>
#include <sys/vnode.h>

#include <vm/page.h>
#include <vm/as.h>
#include <vm/hat.h>
#include <vm/seg.h>

#include <sys/pixrect.h>
#include <sys/pr_impl_util.h>
#include <sys/pr_planegroups.h>
#include <sys/memvar.h>
#include <sys/cg3var.h>		/* for CG3_MMAP_OFFSET */
#include <sys/cg6var.h>
#include <sys/kstat.h>

#include <sys/kmem.h>
#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/devops.h>
#include <sys/sunddi.h>
#include <sys/ddi_impldefs.h>
#include <sys/fs/snode.h>

#include <sys/modctl.h>

#include <sys/machsystm.h>

#define	KIOIP		KSTAT_INTR_PTR(softc->intrstats)

#define	CG6DEBUG	0

/* configuration options */
#define	CG6DELAY(c, n)    \
{ \
	register int N = n; \
	while (--N > 0) { \
	    if (c) \
		break; \
	    drv_usecwait(1); \
	} \
}

#if CG6DEBUG >= 2
int	cg6_debug = 0;

#define	DEBUGF(level, args) \
		{ if (cg6_debug >= (level)) cmn_err args; }
#define	DUMP_SEGS(level, s, c) \
		{ if (cg6_debug >= (level)) dump_segs(s, c); }
#else
#define	DEBUGF(level, args)	/* nothing */
#define	DUMP_SEGS(level, s, c)	/* nothing */
#endif

#define	getprop(devi, name, def)	\
		ddi_getprop(DDI_DEV_T_ANY, (devi), \
		DDI_PROP_DONTPASS, (name), (def))

/* config info */

static int	cg6_open(dev_t *, int, int, cred_t *);
static int	cg6_close(dev_t, int, int, cred_t *);
static int	cg6_ioctl(dev_t, int, intptr_t, int, cred_t *, int *);
static int	cg6_mmap(dev_t, off_t, int);
static int	cg6_devmap(dev_t, devmap_cookie_t, offset_t, size_t,
			size_t *, uint_t);
static int	cg6_segmap(dev_t, off_t,
			struct as *, caddr_t *, off_t, uint_t,
			uint_t, uint_t, cred_t *);

static struct vis_identifier cg6_ident = { "SUNWcg6" };

static struct cb_ops cg6_cb_ops = {
	cg6_open,		/* open */
	cg6_close,		/* close */
	nodev,			/* strategy */
	nodev,			/* print */
	nodev,			/* dump */
	nodev,			/* read */
	nodev,			/* write */
	cg6_ioctl,		/* ioctl */
	cg6_devmap,		/* devmap */
	cg6_mmap,		/* mmap */
	cg6_segmap,		/* segmap */
	nochpoll,		/* poll */
	ddi_prop_op,		/* cb_prop_op */
	0,			/* streamtab  */
	D_NEW|D_MP|D_DEVMAP|D_HOTPLUG,	/* Driver compatibility flag */
	CB_REV,			/* rev */
	nodev,			/* int (*cb_aread)() */
	nodev			/* int (*cb_awrite)() */
};

static int cg6_info(dev_info_t *dip, ddi_info_cmd_t infocmd,
		void *arg, void **result);
static int cg6_attach(dev_info_t *, ddi_attach_cmd_t);
static int cg6_detach(dev_info_t *, ddi_detach_cmd_t);
static int cg6_power(dev_info_t *, int, int);

struct dev_ops cgsix_ops = {
	DEVO_REV,		/* devo_rev, */
	0,			/* refcnt  */
	cg6_info,		/* info */
	nulldev,		/* identify */
	nulldev,		/* probe */
	cg6_attach,		/* attach */
	cg6_detach,		/* detach */
	nodev,			/* reset */
	&cg6_cb_ops,		/* driver operations */
	(struct bus_ops *)0,	/* bus operations */
	cg6_power,
	ddi_quiesce_not_supported,	/* devo_quiesce */
};

/*
 * This stucture is used to contain the driver
 * private mapping data (one for each requested
 * device mapping).  A pointer to this data is
 * passed into each mapping callback routine.
 */
struct cg6map_pvt {
	struct	cg6_softc *softc;
	devmap_cookie_t dhp;	/* handle of devmap object	*/
	uint_t	type;			/* mapping type */
	off_t   offset;			/* starting offset of this map	*/
	size_t	len;			/* length of this map		*/
	struct cg6_cntxt *context;	/* associated context		*/
	struct cg6map_pvt *next;	/* List of associated pvt's for */
					/* this context			*/
};

static struct ddi_device_acc_attr endian_attr = {
	DDI_DEVICE_ATTR_V0,
	DDI_NEVERSWAP_ACC,
	DDI_STRICTORDER_ACC
};

/* how much to map */
#define	CG6MAPSIZE	MMAPSIZE(0)

/* vertical retrace counter page */
#ifndef	CG6_VRT_SZ
#define	CG6_VRT_SZ	8192
#endif

/* boardrev bits */
#define	BRDRV_SETRES	0x01	/* board supports set resolution */
#define	BRDRV_TYPE	0x78	/* board type: */
#define	BRDRV_GX	0x00
#define	BRDRV_LSC	0x08
#define	BRDRV_DUPLO	0x10
#define	BRDRV_LEGOHR	0x18
#define	BRDRV_QAUDRO	0x20
#define	BRDRV_HIRES	0x80	/* hires dacs (junior vs. senior) */

#define	CG6_FBC_WAIT	500000	/* .5 seconds */

/* enable/disable interrupt */
#define	TEC_EN_VBLANK_IRQ	0x20
#define	TEC_HCMISC_IRQBIT	0x10

/* position value to use to disable HW cursor */
#define	CG6_CURSOR_OFFPOS	((uint_t)0xffe0ffe0)

/*
 * Per-context info:
 *	many registers in the tec and fbc do
 *	not need to be saved/restored.
 */

struct cg6_cntxt {
	struct cg6_cntxt *link;	/* link to next (private) context if any */
	struct cg6map_pvt *pvt; /* List of associated pvt's for this context */
	pid_t	pid;		/* "owner" of this context */
	int	flag;

	struct {
	    uint_t   mv;
	    uint_t   clip;
	    uint_t   vdc;
	    uint_t   data[64][2];
	}    tec;

	struct {
	    uint_t   status;
	    uint_t   clipcheck;
	    struct l_fbc_misc misc;
	    uint_t   x0, y0, x1, y1, x2, y2, x3, y3;
	    uint_t   rasteroffx, rasteroffy;
	    uint_t   autoincx, autoincy;
	    uint_t   clipminx, clipminy, clipmaxx, clipmaxy;
	    uint_t   fcolor, bcolor;
	    struct l_fbc_rasterop rasterop;
	    uint_t   planemask, pixelmask;
	    union l_fbc_pattalign pattalign;
	    uint_t   pattern0, pattern1, pattern2, pattern3, pattern4, pattern5,
		pattern6, pattern7;
	}    fbc;
};

/* per-unit data */
struct cg6_softc {
	Pixrect pr;			/* kernel pixrect */
	struct mprp_data prd;	/* pixrect private data */
#define	_w		pr.pr_size.x
#define	_h		pr.pr_size.y
#define	_fb		prd.mpr.md_image
#define	_linebytes	prd.mpr.md_linebytes
	size_t size;		/* total size of frame buffer */
	size_t ndvramsz;	/* size of non-display Video RAM */
	caddr_t ndvram;		/* Storage for nd-VRAM, while suspended */
	size_t	dummysize;	/* total size of overlay plane */
	kmutex_t interlock;	/* interrupt locking */
	off_t   addr_rom;	/* varies between p4 & sbus */
	caddr_t fbctec;	/* fbc&tec kernel map addr. */
	caddr_t cmap;		/* colormap kernel map addr. */
	caddr_t fhcthc;	/* fhc&thc kernel map addr. */
	caddr_t rom;		/* rom kernel map addr. */
	caddr_t dhc;		/* dac hardware */
	caddr_t alt;		/* alt registers */
	caddr_t uart;		/* uart registers */
	pfn_t   fbpfnum;	/* pfn of fb for mmap() */

	struct softcur {
	    short   enable;		/* cursor enable */
	    short   pad1;
	    struct fbcurpos pos;	/* cursor position */
	    struct fbcurpos hot;	/* cursor hot spot */
	    struct fbcurpos size;	/* cursor bitmap size */
	    uint32_t  image[32];		/* cursor image bitmap */
	    uint32_t  mask[32];		/* cursor mask bitmap */
	}    cur;

	union {			/* shadow overlay color map */
	    uint32_t	omap_int[2];	/* cheating here to save space */
	    uchar_t  omap_char[3][2];
	}    omap_image;
#define	omap_rgb	omap_image.omap_char[0]
	ushort_t	omap_update;	/* overlay colormap update flag */
	uint32_t	cmap_index;	/*	colormap update index	*/
	uint32_t	cmap_count;	/*	colormap update count	*/
	union {			/* shadow color map */
	uint32_t	cmap_int[CG6_CMAP_ENTRIES * 3 / sizeof (uint32_t)];
	    uchar_t  cmap_char[3][CG6_CMAP_ENTRIES];
	}    cmap_image;
#define	cmap_rgb	cmap_image.cmap_char[0]

#define	CG6VRTIOCTL	1	/* FBIOVERTICAL in effect */
#define	CG6VRTCTR	2	/* OWGX vertical retrace counter */
	size_t	fbmappable;	/* bytes mappable */
	int		*vrtpage;	/* pointer to VRT page */
	ddi_umem_cookie_t	vrtcookie;	/* pointer to VRT allocation */
	int		vrtmaps;	/* number of VRT page maps */
	int		vrtflag;	/* vrt interrupt flag */
	struct cg6_info cg6info;	/* info about this cg6 */
	struct mon_info moninfo;	/* info about this monitor */
	struct cg6_cntxt *curctx;	/* context switching */
	struct cg6_cntxt shared_ctx;	/* shared context */
	struct cg6_cntxt *pvt_ctx;	/* list of non-shared contexts */
	int		chiprev;	/* fbc chip revision # */
	int		emulation;	/* emulation type, normally cgsix */
	dev_info_t	*devi;		/* back pointer */
	ddi_iblock_cookie_t iblock_cookie;	/* block interrupts */
	kmutex_t	mutex;		/* mutex locking */
	kcondvar_t	vrtsleep;	/* for waiting on vertical retrace */
	int		mapped_by_prom;	/* $#!@ SVr4 */
	off_t		mapped_by_driver;
	int		waiting;
	int		cg6_suspended;	/* true if driver is suspended */
	int		vidon;		/* video enable state */
	int		intr_flag;
	kstat_t		*intrstats;	/* interrupt statistics */
};

static int cg6map_map(devmap_cookie_t, dev_t, uint_t, offset_t, size_t,
		void **);
static int cg6map_contextmgt(devmap_cookie_t, void *, offset_t, size_t,
	uint_t, uint_t);
static int cg6map_dup(devmap_cookie_t, void *, devmap_cookie_t, void **);
static void cg6map_unmap(devmap_cookie_t, void *, offset_t, size_t,
			devmap_cookie_t, void **, devmap_cookie_t, void **);
static int cg6map_access(devmap_cookie_t, void *,  offset_t, size_t,
			uint_t, uint_t);
static
struct devmap_callback_ctl cg6map_ops = {
	DEVMAP_OPS_REV,	/* devmap_ops version number	*/
	cg6map_map,	/* devmap_ops map routine */
	cg6map_access,	/* devmap_ops access routine */
	cg6map_dup,		/* devmap_ops dup routine		*/
	cg6map_unmap,	/* devmap_ops unmap routine */
};

static size_t	pagesize;
static void	*cg6_softc_head;
clock_t	cg6_ctxholdval = 1;

/* default structure for FBIOGATTR ioctl */
static struct fbgattr cg6_attr = {
/*	real_type	 owner */
	FBTYPE_SUNFAST_COLOR, 0,
/* fbtype: type		 h  w  depth    cms  size */
	{FBTYPE_SUNFAST_COLOR, 0, 0, CG6_DEPTH, CG6_CMAP_ENTRIES, 0},
/* fbsattr: flags emu_type    dev_specific */
	{0, FBTYPE_SUN4COLOR, {0}},
/*	emu_types */
	{FBTYPE_SUNFAST_COLOR, FBTYPE_SUN3COLOR, FBTYPE_SUN4COLOR, -1}
};


/*
 * handy macros
 */
#define	getsoftc(instance)	\
	((struct cg6_softc *)ddi_get_soft_state(cg6_softc_head, (instance)))

#define	btob(n)		ptob(btopr(n))	/* TODO, change this? */



/* convert softc to data pointers */

#define	S_FBC(softc)	((struct fbc *)(softc)->fbctec)
#define	S_TEC(softc)	((struct tec *)((softc)->fbctec + CG6_TEC_POFF))
#define	S_FHC(softc)	((uint_t *)(softc)->fhcthc)
#define	S_THC(softc)	((struct thc *)((softc)->fhcthc + CG6_TEC_POFF))
#define	S_CMAP(softc)	((struct cg6_cmap *)(softc)->cmap)

#define	cg6_set_video(softc, on)	thc_set_video(S_THC(softc), (on))
#define	cg6_get_video(softc)		thc_get_video(S_THC(softc))

#define	cg6_int_enable(softc) \
	{\
	    thc_int_enable(S_THC(softc)); }

#define	cg6_int_disable_intr(softc) \
	{\
	    thc_int_disable(S_THC(softc)); }

#define	cg6_int_disable(softc) \
	{\
	    mutex_enter(&(softc)->interlock); \
	    softc->intr_flag = 1; \
	    cg6_int_disable_intr(softc);    \
	    mutex_exit(&(softc)->interlock); }

#define	cg6_int_pending(softc)		thc_int_pending(S_THC(softc))

/* check if color map update is pending */
#define	cg6_update_pending(softc) \
	((softc)->cmap_count || (softc)->omap_update)

/*
 * forward references
 */
static uint_t	cg6_intr(caddr_t);
static void	cg6_reset_cmap(volatile uchar_t *, uint_t);
static void	cg6_update_cmap(struct cg6_softc *, uint_t, uint_t);
static void	cg6_cmap_bcopy(uchar_t *, uchar_t *, uint_t);
static void	cg6_restore_prom_cmap(struct cg6_softc *, volatile uchar_t *,
			uint_t);

static void	cg6_setcurpos(struct cg6_softc *);
static void	cg6_setcurshape(struct cg6_softc *);
static void	cg6_reset(struct cg6_softc *);
static int	cg6_cntxsave(volatile struct fbc *, volatile struct tec *,
			struct cg6_cntxt *);
static int	cg6_cntxrestore(volatile struct fbc *, volatile struct tec *,
			struct cg6_cntxt *);
static struct cg6_cntxt *ctx_map_insert(struct cg6_softc *, int);
static pid_t	getpid(void);

/* Loadable Driver stuff */

static struct modldrv modldrv = {
	&mod_driverops,		/* Type of module.  This one is a driver */
	"cgsix driver",	/* Name of the module. */
	&cgsix_ops,		/* driver ops */
};

static struct modlinkage modlinkage = {
	MODREV_1, (void *) &modldrv, NULL
};

int
_init(void)
{
	register int e;

	if ((e = ddi_soft_state_init(&cg6_softc_head,
		    sizeof (struct cg6_softc), 1)) != 0) {
	    DEBUGF(1, (CE_CONT, "done\n"));
	    return (e);
	}

	e = mod_install(&modlinkage);

	if (e) {
		ddi_soft_state_fini(&cg6_softc_head);
		DEBUGF(1, (CE_CONT, "done\n"));
	}
	DEBUGF(1, (CE_CONT, "cgsix: _init done rtn=%d\n", e));
	return (e);
}

int
_fini(void)
{
	register int e;

	DEBUGF(1, (CE_CONT, "cgsix: _fini, mem used=%d\n", total_memory));

	if ((e = mod_remove(&modlinkage)) != 0)
		return (e);

	ddi_soft_state_fini(&cg6_softc_head);

	return (0);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

static int
cg6_attach(dev_info_t *devi, ddi_attach_cmd_t cmd)
{
	register struct cg6_softc *softc;
	caddr_t		reg;
	int		w, h, bytes;
	char		*tmp;
	char		name[16];
	int		unit = ddi_get_instance(devi);
	int		proplen;
	caddr_t		fb_ndvram;

	DEBUGF(1, (CE_CONT, "cg6_attach unit=%d cmd=%d\n", unit, (int)cmd));

	switch (cmd) {
	case DDI_ATTACH:
		break;

	case DDI_RESUME:
		if ((softc = ddi_get_driver_private(devi)) == NULL)
			return (DDI_FAILURE);
		if (!softc->cg6_suspended)
			return (DDI_SUCCESS);
		mutex_enter(&softc->mutex);
		cg6_reset(softc);
		if (softc->curctx) {
		    /* Restore the video state */
			cg6_set_video(softc, softc->vidon);

		    /* Restore non display RAM */
			if (ddi_map_regs(devi, 0, (caddr_t *)&fb_ndvram,
			    CG6_ADDR_COLOR + softc->_w * softc->_h,
			    softc->ndvramsz) == -1) {
				mutex_exit(&softc->mutex);
				return (DDI_FAILURE);
			}
			bcopy(softc->ndvram, fb_ndvram, softc->ndvramsz);
			ddi_unmap_regs(devi, 0, (caddr_t *)&fb_ndvram,
			    CG6_ADDR_COLOR + softc->_w * softc->_h,
			    softc->ndvramsz);
			kmem_free(softc->ndvram, softc->ndvramsz);

		    /* Restore other frame buffer state */
			(void) cg6_cntxrestore(S_FBC(softc), S_TEC(softc),
			    softc->curctx);
			cg6_setcurpos(softc);
			cg6_setcurshape(softc);
			cg6_update_cmap(softc, (uint_t)_ZERO_,
			    CG6_CMAP_ENTRIES);
			cg6_int_enable(softc);	/* Schedule the update */
		}
		softc->cg6_suspended = 0;
		mutex_exit(&softc->mutex);
		return (DDI_SUCCESS);

	default:
		return (DDI_FAILURE);
	}

	DEBUGF(1, (CE_CONT, "cg6_attach unit=%d\n", unit));

	pagesize = (size_t)ddi_ptob(devi, 1);

	/* Allocate softc struct */
	if (ddi_soft_state_zalloc(cg6_softc_head, unit) != 0) {
		return (DDI_FAILURE);
	}

	softc = getsoftc(unit);

	/* link it in */
	softc->devi = devi;
	DEBUGF(1, (CE_CONT, "cg6_attach devi=0x%x unit=%d\n", devi, unit));
	ddi_set_driver_private(devi, softc);

	/* Grab properties from PROM */
	/* TODO don't really want default w, h */
	if (ddi_prop_op(DDI_DEV_T_ANY, devi, PROP_LEN_AND_VAL_ALLOC,
	    DDI_PROP_DONTPASS, "emulation", (caddr_t)&tmp, &proplen) ==
	    DDI_PROP_SUCCESS) {
		if (strcmp(tmp, "cgthree+") == 0)
		softc->emulation = FBTYPE_SUN3COLOR;
		else if (strcmp(tmp, "cgfour+") == 0)
		softc->emulation = FBTYPE_SUN4COLOR;
		else if (strcmp(tmp, "bwtwo+") == 0)
		softc->emulation = FBTYPE_SUN2BW;
		else
		softc->emulation = FBTYPE_SUNFAST_COLOR;
		kmem_free(tmp, proplen);
	} else
		softc->emulation = FBTYPE_SUNFAST_COLOR;

	softc->_w = w = getprop(devi, "width", 1152);
	softc->_h = h = getprop(devi, "height", 900);
	bytes = getprop(devi, "linebytes", mpr_linebytes(w, 8));

	softc->_linebytes = bytes;

	/* Compute size of color frame buffer */
	bytes = btob(bytes * h);
	softc->size = (size_t)ddi_ptob(devi, ddi_btopr(devi, bytes));

	softc->cg6info.vmsize = getprop(devi, "vmsize", 1);
	if (softc->cg6info.vmsize > 1) {
		softc->size = (size_t)ddi_ptob(devi,
		    ddi_btopr(devi, 8 * 1024 * 1024));
		softc->fbmappable = 8 * 1024 * 1024;
	} else
		softc->fbmappable = 1024 * 1024;

	/* Compute size of dummy overlay/enable planes */
	softc->dummysize = btob(mpr_linebytes(w, 1) * h) * 2;

	/*
	 * only use address property if we are console fb NOTE: if the prom has
	 * already mapped the fb *and* it has mapped all of fbmappable, then we
	 * don't need a new mapping
	 */
	if (reg = (caddr_t)(uintptr_t)getprop(devi, "address", 0)) {
		softc->_fb = (MPR_T *) reg;
		softc->mapped_by_prom = 1;
		if (ddi_ptob(devi, ddi_btopr(devi, w * h)) <=
		    getprop(devi, "fbmapped", w * h))
			bytes = 0;
		DEBUGF(2, (CE_CONT, "cg6 mapped by PROM\n"));
	}

	softc->cg6info.line_bytes = softc->_linebytes;
	softc->cg6info.accessible_width = getprop(devi, "awidth", 1152);
	softc->cg6info.accessible_height = (uint_t)
	    (softc->cg6info.vmsize * 1024 * 1024) /
	    softc->cg6info.accessible_width;
	softc->cg6info.hdb_capable = getprop(devi, "dblbuf", 0);
	softc->cg6info.boardrev = getprop(devi, "boardrev", 0);
	softc->vrtpage = NULL;
	softc->vrtmaps = 0;
	softc->vrtflag = 0;

#ifdef DEBUG
	softc->cg6info.pad1 = CG6_VADDR_COLOR + CG6_FB_SZ;
#endif

	/*
	 * get monitor attributes
	 */
	softc->moninfo.mon_type = getprop(devi, "montype", 0);
	softc->moninfo.pixfreq = getprop(devi, "pixfreq", 929405);
	softc->moninfo.hfreq = getprop(devi, "hfreq", 61795);
	softc->moninfo.vfreq = getprop(devi, "vfreq", 66);
	softc->moninfo.hfporch = getprop(devi, "hfporch", 32);
	softc->moninfo.vfporch = getprop(devi, "vfporch", 2);
	softc->moninfo.hbporch = getprop(devi, "hbporch", 192);
	softc->moninfo.vbporch = getprop(devi, "vbporch", 31);
	softc->moninfo.hsync = getprop(devi, "hsync", 128);
	softc->moninfo.vsync = getprop(devi, "vsync", 4);

	/*
	 * map in the registers.  Map fbc&tec together.  Likewise for fhc&thc.
	 */
	softc->addr_rom = CG6_ADDR_ROM_SBUS;

	if (ddi_map_regs(devi, 0, &softc->fbctec, CG6_ADDR_FBC,
	    (off_t)CG6_FBCTEC_SZ) != 0) {
		(void) cg6_detach(devi, DDI_DETACH);
		return (DDI_FAILURE);
	}
	if (ddi_map_regs(devi, 0, &softc->cmap, CG6_ADDR_CMAP,
	    (off_t)CG6_CMAP_SZ) != 0) {
		(void) cg6_detach(devi, DDI_DETACH);
		return (DDI_FAILURE);
	}
	if (ddi_map_regs(devi, 0, &softc->fhcthc, CG6_ADDR_FHC,
	    (off_t)CG6_FHCTHC_SZ) != 0) {
		(void) cg6_detach(devi, DDI_DETACH);
		return (DDI_FAILURE);
	}

	softc->chiprev =
	    *S_FHC(softc) >> FHC_CONFIG_REV_SHIFT & FHC_CONFIG_REV_MASK;

	cg6_reset(softc);

	if (ddi_get_iblock_cookie(devi, 0, &softc->iblock_cookie)
	    != DDI_SUCCESS) {
		DEBUGF(2, (CE_CONT,
		    "cg6_attach%d ddi_get_iblock_cookie failed\n", unit));
		(void) cg6_detach(devi, DDI_DETACH);
		return (DDI_FAILURE);
	}

	mutex_init(&softc->interlock, NULL, MUTEX_DRIVER, softc->iblock_cookie);
	mutex_init(&softc->mutex, NULL, MUTEX_DRIVER, softc->iblock_cookie);
	cv_init(&softc->vrtsleep, NULL, CV_DRIVER, NULL);

	if (ddi_add_intr(devi, 0, &softc->iblock_cookie, 0,
	    cg6_intr, (caddr_t)softc) != DDI_SUCCESS) {
		DEBUGF(2, (CE_CONT,
		"cg6_attach%d add_intr failed\n", unit));
		(void) cg6_detach(devi, DDI_DETACH);
		return (DDI_FAILURE);
	}

	/*
	 * Initialize hardware colormap and software colormap images. It might
	 * make sense to read the hardware colormap here.
	 */
	cg6_reset_cmap(softc->cmap_rgb, CG6_CMAP_ENTRIES);
	cg6_reset_cmap(softc->omap_rgb, 2);
	cg6_update_cmap(softc, (uint_t)_ZERO_, CG6_CMAP_ENTRIES);
	cg6_update_cmap(softc, (uint_t)_ZERO_, (uint_t)_ZERO_);

	DEBUGF(2, (CE_CONT,
	    "cg6_attach%d just before create_minor node\n", unit));
	(void) sprintf(name, "cgsix%d", unit);
	if (ddi_create_minor_node(devi, name, S_IFCHR,
	    unit, DDI_NT_DISPLAY, NULL) == DDI_FAILURE) {
		ddi_remove_minor_node(devi, NULL);
		DEBUGF(2, (CE_CONT,
		    "cg6_attach%d create_minor node failed\n", unit));
		return (DDI_FAILURE);
	}
	ddi_report_dev(devi);

	if (softc->chiprev == 0)
		cmn_err(CE_CONT, "?Revision 0 FBC\n");

	cmn_err(CE_CONT,
	    "?cgsix%d: screen %dx%d, %s buffered, %dM mappable, rev %d\n",
	    unit, w, h, softc->cg6info.hdb_capable ? "double" : "single",
	    softc->cg6info.vmsize, softc->chiprev);

	softc->pvt_ctx = NULL;

	/*
	 * Initialize power management bookkeeping; components are created idle
	 */
	if (pm_create_components(devi, 2) == DDI_SUCCESS) {
		(void) pm_busy_component(devi, 0);
		pm_set_normal_power(devi, 0, 1);
		pm_set_normal_power(devi, 1, 1);

		(void) sprintf(name, "cgsixc%d", unit);
		softc->intrstats = kstat_create("cgsix", unit, name,
		    "controller", KSTAT_TYPE_INTR,
		    1, KSTAT_FLAG_PERSISTENT);
		if (softc->intrstats) {
			kstat_install(softc->intrstats);
		}

		return (DDI_SUCCESS);
	} else {
		return (DDI_FAILURE);
	}
}

static int
cg6_detach(dev_info_t *devi, ddi_detach_cmd_t cmd)
{
	int instance = ddi_get_instance(devi);
	register struct cg6_softc *softc = getsoftc(instance);
	caddr_t fb_ndvram;

	DEBUGF(1, (CE_CONT, "cg6_detach softc=%x, devi=0x%x\n", softc, devi));

	switch (cmd) {
	case DDI_DETACH:
		break;

	case DDI_SUSPEND:
		if (softc == NULL)
			return (DDI_FAILURE);
		if (softc->cg6_suspended)
			return (DDI_FAILURE);

		mutex_enter(&softc->mutex);

		if (softc->curctx) {
		struct fbc *fbc0 = S_FBC(softc);

		/* Save the video state */
		softc->vidon = cg6_get_video(softc);

		/* Save non display RAM */
		softc->ndvramsz = (softc->cg6info.vmsize * 1024 * 1024)
		    - (softc->_w * softc->_h);
		if ((softc->ndvram = kmem_alloc(softc->ndvramsz,
		    KM_NOSLEEP)) == NULL) {
			mutex_exit(&softc->mutex);
			return (DDI_FAILURE);
		}

		/*
		 * If FBC is busy, wait for maximum of 2 seconds for it
		 * to be idle
		 */
		CG6DELAY(!(fbc0->l_fbc_status & L_FBC_BUSY),
		    4*CG6_FBC_WAIT);

		if (fbc0->l_fbc_status & L_FBC_BUSY) {

			/*
			 * if still busy, try another 2 seconds before
			 * giving up
			 */
			CG6DELAY(!(fbc0->l_fbc_status & L_FBC_BUSY),
			    4*CG6_FBC_WAIT);
			if (fbc0->l_fbc_status & L_FBC_BUSY)
				cmn_err(CE_WARN, "cg6_detach: FBC still busy");
			}

			if (ddi_map_regs(devi, 0, &fb_ndvram, CG6_ADDR_COLOR +
			    softc->_w * softc->_h, softc->ndvramsz) == -1) {
				kmem_free(softc->ndvram, softc->ndvramsz);
				mutex_exit(&softc->mutex);
				return (DDI_FAILURE);
			}
			bcopy(fb_ndvram, softc->ndvram, softc->ndvramsz);
			ddi_unmap_regs(devi, 0, &fb_ndvram, CG6_ADDR_COLOR +
			    softc->_w * softc->_h, softc->ndvramsz);

		    /* Save other frame buffer state */
			(void) cg6_cntxsave(S_FBC(softc), S_TEC(softc),
			    softc->curctx);
		}
		softc->cg6_suspended = 1;
		mutex_exit(&softc->mutex);
		return (DDI_SUCCESS);

	default:
		return (DDI_FAILURE);
	}

	/* shut off video if not console */

	if (!softc->mapped_by_prom)
		cg6_set_video(softc, 0);

	mutex_enter(&softc->mutex);
	cg6_int_disable(softc);
	mutex_exit(&softc->mutex);

	ddi_remove_intr(devi, 0, softc->iblock_cookie);

	if (softc->fbctec)
		ddi_unmap_regs(devi, 0,
		    &softc->fbctec, CG6_ADDR_FBC, CG6_FBCTEC_SZ);
	if (softc->cmap)
		ddi_unmap_regs(devi, 0, &softc->cmap, CG6_ADDR_CMAP,
		    CG6_CMAP_SZ);
	if (softc->fhcthc)
		ddi_unmap_regs(devi, 0,
		    &softc->fhcthc, CG6_ADDR_FHC, CG6_FHCTHC_SZ);
	if (softc->intrstats) {
		kstat_delete(softc->intrstats);
	}
	softc->intrstats = NULL;

	if (softc->vrtpage != NULL)
		ddi_umem_free(softc->vrtcookie);

	mutex_destroy(&softc->mutex);

	cv_destroy(&softc->vrtsleep);

	ASSERT(softc->curctx == NULL);

	/* free softc struct */
	(void) ddi_soft_state_free(cg6_softc_head, instance);
	pm_destroy_components(devi);

	return (DDI_SUCCESS);
}

static int
cg6_power(dev_info_t *dip, int cmpt, int level)
{
	struct cg6_softc *softc;

	/*
	 * Framebuffer is represented by cmpt 0.  In cg6, no power
	 * management is done on the framebuffer itself.  Only the
	 * monitor (cmpt 1) is being power managed.
	 */
	if (cmpt == 0)
		return (DDI_SUCCESS);

	if (cmpt != 1 || 0 > level || level > 1 ||
	    (softc = ddi_get_driver_private(dip)) == NULL)
		return (DDI_FAILURE);

	if (level) {
		/* Turn on sync and video. */
		mutex_enter(&softc->mutex);
		S_THC(softc)->l_thc_hcmisc |= THC_HCMISC_RESET;
		drv_usecwait(500);
		S_THC(softc)->l_thc_hcmisc |=
		    (THC_HCMISC_SYNCEN | THC_HCMISC_VIDEO);
		S_THC(softc)->l_thc_hcmisc &= ~THC_HCMISC_RESET;
		cg6_update_cmap(softc, (uint_t)_ZERO_, CG6_CMAP_ENTRIES);
		cg6_int_enable(softc);
		mutex_exit(&softc->mutex);
	} else {
		/* Turn off sync and video. */
		mutex_enter(&softc->mutex);
		S_THC(softc)->l_thc_hcmisc |= THC_HCMISC_RESET;
		drv_usecwait(500);
		S_THC(softc)->l_thc_hcmisc &=
		    ~(THC_HCMISC_VIDEO | THC_HCMISC_SYNCEN);
		S_THC(softc)->l_thc_hcmisc &= ~THC_HCMISC_RESET;
		mutex_exit(&softc->mutex);
	}
	return (DDI_SUCCESS);
}

/* ARGSUSED */
static int
cg6_info(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg, void **result)
{
	int error = DDI_SUCCESS;
	minor_t	instance;
	struct cg6_softc *softc;

	instance = getminor((dev_t)arg);

	switch (infocmd) {
	case DDI_INFO_DEVT2DEVINFO:
		if ((softc = getsoftc(instance)) == NULL) {
		error = DDI_FAILURE;
		} else {
		*result = (void *) softc->devi;
		error = DDI_SUCCESS;
		}
		break;
	case DDI_INFO_DEVT2INSTANCE:
		*result = (void *) (uintptr_t)instance;
		error = DDI_SUCCESS;
		break;
	default:
		error = DDI_FAILURE;
	}
	return (error);
}

/*ARGSUSED*/
static int
cg6_open(dev_t *devp, int flag, int otyp, cred_t *cred)
{
	int	unit = getminor(*devp);
	struct	cg6_softc *softc = getsoftc(unit);
	int	error = 0;

	DEBUGF(2, (CE_CONT, "cg6_open(%d), mem used=%d\n", unit, total_memory));

	/*
	 * is this gorp necessary?
	 */
	if (otyp != OTYP_CHR) {
		error = EINVAL;
	} else
	if (softc == NULL) {
		error = ENXIO;
	}

	return (error);
}

/*ARGSUSED*/
static
int
cg6_close(dev_t dev, int flag, int otyp, cred_t *cred)
{
	int    unit = getminor(dev);
	struct cg6_softc *softc = getsoftc(unit);
	int	error = 0;

	DEBUGF(2, (CE_CONT, "cg6_close(%d, %d, %d), mem used=%d\n",
	    unit, flag, otyp, total_memory));

	if (otyp != OTYP_CHR) {
		error = EINVAL;
	} else if (softc == NULL) {
		error = ENXIO;
	} else {
		mutex_enter(&softc->mutex);
		cg6_reset_cmap(softc->cmap_rgb, CG6_CMAP_ENTRIES);
		cg6_restore_prom_cmap(softc, softc->cmap_rgb, CG6_CMAP_ENTRIES);
		softc->cur.enable = 0;
		softc->curctx = NULL;
		cg6_reset(softc);
		mutex_exit(&softc->mutex);
	}

	return (error);
}

/*ARGSUSED*/
static int
cg6_mmap(dev_t dev, off_t off, int prot)
{
	struct cg6_softc *softc = getsoftc(getminor(dev));
	ssize_t diff;
	caddr_t page;
	intptr_t rval = 0;

	DEBUGF(off ? 5 : 1, (CE_CONT, "cg6_mmap(%d, 0x%x)\n",
	    getminor(dev), (uint_t)off));

	if ((diff = off - CG6_VADDR_COLOR) >= 0 && diff < softc->fbmappable)
		rval = softc->fbpfnum + diff / pagesize;
	else if ((diff = off - CG6_VADDR_FBC) >= 0 && diff < CG6_FBCTEC_SZ)
		page = softc->fbctec + diff;
	else if ((diff = off - CG6_VADDR_CMAP) >= 0 && diff < CG6_CMAP_SZ)
		page = softc->cmap + diff;
	else if ((diff = off - CG6_VADDR_FHC) >= 0 && diff < CG6_FHCTHC_SZ)
		page = softc->fhcthc + diff;
	else if ((diff = off - CG6_VADDR_ROM) >= 0 && diff < CG6_ROM_SZ)
		page = softc->rom + diff;
	else if ((diff = off - CG6_VADDR_DHC) >= 0 && diff < CG6_DHC_SZ)
		page = softc->dhc + diff;
	else if ((diff = off - CG6_VADDR_ALT) >= 0 && diff < CG6_ALT_SZ)
		page = softc->alt + diff;
	else if ((diff = off - CG6_VADDR_VRT) >= 0 && diff < CG6_VRT_SZ)
		page = softc->vrtpage ?
		    (caddr_t)softc->vrtpage + diff : (caddr_t)-1;
	else if ((diff = off - CG3_MMAP_OFFSET) >= 0 &&
	    diff < softc->fbmappable)
		rval = softc->fbpfnum + diff / pagesize;
	else if (off < CG6_VBASE) {

	/*
	 * getting more and more complicated; what we return depends on what
	 * we're emulating
	 */

		if (softc->emulation == FBTYPE_SUN3COLOR) {
		if (off >= 0 && off < softc->fbmappable)
			rval = softc->fbpfnum + diff / pagesize;
		else
			page = (caddr_t)-1;
		} else {	/* softc->emulation == FBTYPE_SUN4COLOR */
		if (off >= 0 && off < softc->dummysize)
			page = softc->rom;
		else if ((diff = off - softc->dummysize) < softc->fbmappable)
			rval = softc->fbpfnum + diff / pagesize;
		}
	    /* TODO: bw2? */
	} else
		page = (caddr_t)-1;

	if (rval == 0)
		if (page != (caddr_t)-1)
		rval = hat_getkpfnum(page);
		else
		rval = -1;

	DEBUGF(5, (CE_CONT, "cg6_mmap returning 0x%x\n", rval));

	return ((int)rval);	/* XXX64 */
}

/*ARGSUSED*/
static int
cg6_ioctl(dev_t dev, int cmd, intptr_t data, int mode, cred_t *cred, int *rval)
{
	struct cg6_softc *softc = getsoftc(getminor(dev));
	int    cursor_cmap;
	int    i;

	uchar_t *iobuf_cmap_red;
	uchar_t *iobuf_cmap_green;
	uchar_t *iobuf_cmap_blue;
	uchar_t *stack_cmap;

	STRUCT_DECL(fbcmap, fbcmap);
	STRUCT_DECL(fbcursor, fbcursor);

	uint_t   index;
	uint_t   count;
	uchar_t *map;
	uint_t   entries;

	DEBUGF(3, (CE_CONT, "cg6_ioctl(%d, 0x%x)\n", getminor(dev), cmd));

	/* default to updating normal colormap */
	cursor_cmap = 0;


	switch (cmd) {

	case VIS_GETIDENTIFIER:

		if (ddi_copyout((caddr_t)&cg6_ident,
		    (caddr_t)data,
		    sizeof (struct vis_identifier),
		    mode))
			return (EFAULT);
		break;

	case FBIOPUTCMAP:
	case FBIOGETCMAP:


	cmap_ioctl:

		if (cursor_cmap == 0) {
			STRUCT_INIT(fbcmap, mode);
			if (ddi_copyin((caddr_t)data,
			    STRUCT_BUF(fbcmap), STRUCT_SIZE(fbcmap), mode))
				return (EFAULT);
		}
		index = STRUCT_FGET(fbcmap, index);
		count = STRUCT_FGET(fbcmap, count);

		if (count == 0) {
			return (0);
		}
		if (cursor_cmap == 0) {
			switch (PIX_ATTRGROUP(index)) {

			case 0:
			case PIXPG_8BIT_COLOR:
				map = softc->cmap_rgb;
				entries = CG6_CMAP_ENTRIES;
				break;
			default:
				return (EINVAL);
			}
		} else {
			map = softc->omap_rgb;
			entries = 2;
		}

		if ((index &= PIX_ALL_PLANES) >= entries ||
		    index + count > entries) {
			return (EINVAL);
		}
		/*
		 * Allocate memory for color map RGB entries.
		 */
		stack_cmap = kmem_alloc((CG6_CMAP_ENTRIES * 3), KM_SLEEP);

		iobuf_cmap_red = stack_cmap;
		iobuf_cmap_green = stack_cmap + CG6_CMAP_ENTRIES;
		iobuf_cmap_blue = stack_cmap + (CG6_CMAP_ENTRIES * 2);

		if (cmd == FBIOPUTCMAP) {
			int error;

			DEBUGF(3, (CE_CONT, "FBIOPUTCMAP\n"));

			if (error = ddi_copyin(
			    STRUCT_FGETP(fbcmap, red),
			    iobuf_cmap_red, count, mode)) {
				kmem_free(stack_cmap, (CG6_CMAP_ENTRIES * 3));
				return (error);
			}

			if (error = ddi_copyin(
			    STRUCT_FGETP(fbcmap, green),
			    iobuf_cmap_green, count, mode)) {
				kmem_free(stack_cmap, (CG6_CMAP_ENTRIES * 3));
				return (error);
			}
			if (error = ddi_copyin(
			    STRUCT_FGETP(fbcmap, blue),
			    iobuf_cmap_blue, count, mode)) {
				kmem_free(stack_cmap, (CG6_CMAP_ENTRIES * 3));
				return (error);
			}

			mutex_enter(&softc->mutex);
			map += index * 3;
			if (cg6_update_pending(softc))
				cg6_int_disable(softc);

			/*
			 * Copy color map entries from stack to the color map
			 * table in the softc area.
			 */

			cg6_cmap_bcopy(iobuf_cmap_red, map++, count);
			cg6_cmap_bcopy(iobuf_cmap_green, map++, count);
			cg6_cmap_bcopy(iobuf_cmap_blue, map, count);

			/* cursor colormap update */
			if (entries < CG6_CMAP_ENTRIES)
				count = 0;
			cg6_update_cmap(softc, index, count);
			cg6_int_enable(softc);
			mutex_exit(&softc->mutex);

		} else {
			/* FBIOGETCMAP */
			DEBUGF(3, (CE_CONT, "FBIOGETCMAP\n"));

			mutex_enter(&softc->mutex);
			map += index * 3;

			/*
			 * Copy color map entries from soft area to
			 * local storage and prepare for a copyout
			 */

			cg6_cmap_bcopy(iobuf_cmap_red, map++, -count);
			cg6_cmap_bcopy(iobuf_cmap_green, map++, -count);
			cg6_cmap_bcopy(iobuf_cmap_blue, map, -count);

			mutex_exit(&softc->mutex);

			if (ddi_copyout(iobuf_cmap_red,
			    STRUCT_FGETP(fbcmap, red), count,
			    mode)) {
				kmem_free(stack_cmap, (CG6_CMAP_ENTRIES * 3));
				return (EFAULT);
			}
			if (ddi_copyout(iobuf_cmap_green,
			    STRUCT_FGETP(fbcmap, green), count,
			    mode)) {
				kmem_free(stack_cmap, (CG6_CMAP_ENTRIES * 3));
				return (EFAULT);
			}
			if (ddi_copyout(iobuf_cmap_blue,
			    STRUCT_FGETP(fbcmap, blue), count,
			    mode)) {
				kmem_free(stack_cmap, (CG6_CMAP_ENTRIES * 3));
				return (EFAULT);
			}
		}
		kmem_free(stack_cmap, (CG6_CMAP_ENTRIES * 3));
		break;

	case FBIOSATTR: {
		struct fbsattr attr;

		if (ddi_copyin((caddr_t)data,
		    (caddr_t)&attr,
		    sizeof (attr),
		    mode))
			return (EFAULT);
		DEBUGF(3, (CE_CONT, "FBIOSATTR, type=%d\n", attr.emu_type));
		if (attr.emu_type != -1)
			switch (attr.emu_type) {

			case FBTYPE_SUN3COLOR:
			case FBTYPE_SUN4COLOR:
			case FBTYPE_SUN2BW:
			case FBTYPE_SUNFAST_COLOR:
					mutex_enter(&softc->mutex);
					softc->emulation = attr.emu_type;
					mutex_exit(&softc->mutex);
					break;
			default:
					return (EINVAL);
		}
		/* ignore device-dependent stuff */
	}
	break;

	case FBIOGATTR: {
		struct fbgattr attr;

		DEBUGF(3, (CE_CONT, "FBIOGATTR, emu_type=%d\n",
		    softc->emulation));
		bcopy((caddr_t)&cg6_attr, (caddr_t)&attr, sizeof (attr));
		mutex_enter(&softc->mutex);
		attr.fbtype.fb_type = softc->emulation;
		attr.fbtype.fb_width = softc->_w;
		attr.fbtype.fb_height = softc->_h;
		/* XXX not quite like a cg4 */
		attr.fbtype.fb_size = (int)softc->size;
		attr.sattr.emu_type = softc->emulation;
		mutex_exit(&softc->mutex);

		if (ddi_copyout((caddr_t)&attr,
		    (caddr_t)data,
		    sizeof (struct fbgattr),
		    mode))
			return (EFAULT);
	}
	break;

	/*
	 * always claim to be a cg4 if they call this ioctl.  This is to
	 * support older software which was staticly-linked before cg6 was
	 * invented, and to support newer software which has come to expect
	 * this behavior.
	 */
	case FBIOGTYPE: {
		struct fbtype fb;

		mutex_enter(&softc->mutex);

		bcopy(&cg6_attr.fbtype, &fb, sizeof (struct fbtype));
		DEBUGF(3, (CE_CONT, "FBIOGTYPE\n"));
		fb.fb_type = FBTYPE_SUN4COLOR;
		fb.fb_width = softc->_w;
		fb.fb_height = softc->_h;
		/* XXX not quite like a cg4 */
		fb.fb_size = (int)softc->size;

		mutex_exit(&softc->mutex);

		if (ddi_copyout((caddr_t)&fb,
		    (caddr_t)data,
		    sizeof (struct fbtype),
		    mode))
			return (EFAULT);
		}
		break;
	case FBIOSVIDEO:

		DEBUGF(3, (CE_CONT, "FBIOSVIDEO\n"));
		if (ddi_copyin((caddr_t)data,
		    (caddr_t)&i,
		    sizeof (int),
		    mode))
			return (EFAULT);
		mutex_enter(&softc->mutex);
		cg6_set_video(softc, i & FBVIDEO_ON);
		mutex_exit(&softc->mutex);
		break;

	case FBIOGVIDEO:

		DEBUGF(3, (CE_CONT, "FBIOGVIDEO\n"));
		mutex_enter(&softc->mutex);
		i = cg6_get_video(softc) ? FBVIDEO_ON : FBVIDEO_OFF;
		mutex_exit(&softc->mutex);

		if (ddi_copyout((caddr_t)&i,
		    (caddr_t)data,
		    sizeof (int),
		    mode))
			return (EFAULT);
		break;

	/* informational ioctls */

	case FBIOGXINFO:
		if (ddi_copyout((caddr_t)&softc->cg6info,
		    (caddr_t)data,
		    sizeof (struct cg6_info),
		    mode))
			return (EFAULT);
		return (0);

	case FBIOMONINFO:
		if (ddi_copyout((caddr_t)&softc->moninfo,
		    (caddr_t)data,
		    sizeof (struct mon_info),
		    mode))
			return (EFAULT);
		return (0);

	/* vertical retrace interrupt */

	case FBIOVERTICAL:

		mutex_enter(&softc->mutex);
		softc->vrtflag |= CG6VRTIOCTL;
		cg6_int_enable(softc);
		cv_wait(&softc->vrtsleep, &softc->mutex);
		mutex_exit(&softc->mutex);
		return (0);

	case FBIOVRTOFFSET:

		i = CG6_VADDR_VRT;

		if (ddi_copyout((caddr_t)&i,
		    (caddr_t)data,
		    sizeof (int),
		    mode))
			return (EFAULT);
		return (0);

	/* HW cursor control */
	case FBIOSCURSOR: {

		int	set;
		ssize_t	cbytes;
		uint32_t	stack_image[32], stack_mask[32];

		STRUCT_INIT(fbcursor, mode);
		if (ddi_copyin((void *)data, STRUCT_BUF(fbcursor),
		    STRUCT_SIZE(fbcursor), mode))
			return (EFAULT);

		set = STRUCT_FGET(fbcursor, set);

		/* Compute cursor bitmap bytes */
		cbytes = STRUCT_FGET(fbcursor, size.y) *
		    sizeof (softc->cur.image[0]);
		if (set & FB_CUR_SETSHAPE) {
			if (STRUCT_FGET(fbcursor, size.x) > 32 ||
			    STRUCT_FGET(fbcursor, size.y) > 32) {
				return (EINVAL);
			}


			/* copy cursor image into softc */
			if (STRUCT_FGETP(fbcursor, image) &&
			    ddi_copyin(STRUCT_FGETP(fbcursor, image),
			    &stack_image, cbytes, mode))
				return (EFAULT);

			if (STRUCT_FGETP(fbcursor, mask) &&
			    ddi_copyin(STRUCT_FGETP(fbcursor, mask),
			    &stack_mask, cbytes, mode))
				return (EFAULT);
		}

		mutex_enter(&softc->mutex);
		if (set & FB_CUR_SETCUR)
			softc->cur.enable = STRUCT_FGET(fbcursor, enable);

		if (set & FB_CUR_SETPOS)
			softc->cur.pos = STRUCT_FGET(fbcursor, pos);

		if (set & FB_CUR_SETHOT)
			softc->cur.hot = STRUCT_FGET(fbcursor, hot);

		/* update hardware */

		cg6_setcurpos(softc);

		if (set & FB_CUR_SETSHAPE) {

			if (STRUCT_FGETP(fbcursor, image)) {
				bzero((caddr_t)softc->cur.image,
				    sizeof (softc->cur.image));
				bcopy((caddr_t)&stack_image,
				    (caddr_t)softc->cur.image,
				    cbytes);
			}
			if (STRUCT_FGETP(fbcursor, mask)) {
				bzero((caddr_t)softc->cur.mask,
				    sizeof (softc->cur.mask));
				bcopy((caddr_t)&stack_mask,
				    (caddr_t)softc->cur.mask,
				    cbytes);
			}
			/* load into hardware */
			softc->cur.size = STRUCT_FGET(fbcursor, size);
			cg6_setcurshape(softc);
		}
		mutex_exit(&softc->mutex);
		/* load colormap */
		if (set & FB_CUR_SETCMAP) {
			cursor_cmap = 1;
			cmd = FBIOPUTCMAP;
			STRUCT_SET_HANDLE(fbcmap, mode,
			    STRUCT_FADDR(fbcursor, cmap));
			goto cmap_ioctl;
		}
	}
	break;

	case FBIOGCURSOR: {
		ssize_t    cbytes;
		uint32_t stack_image[32], stack_mask[32];

		STRUCT_INIT(fbcursor, mode);
		if (ddi_copyin((void *)data, STRUCT_BUF(fbcursor),
		    STRUCT_SIZE(fbcursor), mode))
			return (EFAULT);

		mutex_enter(&softc->mutex);

		STRUCT_FSET(fbcursor, set, 0);
		STRUCT_FSET(fbcursor, enable, softc->cur.enable);
		STRUCT_FSET(fbcursor, pos, softc->cur.pos);
		STRUCT_FSET(fbcursor, hot, softc->cur.hot);
		STRUCT_FSET(fbcursor, size, softc->cur.size);
		STRUCT_FSET(fbcursor, cmap.index, 0);
		STRUCT_FSET(fbcursor, cmap.count, 2);

		/* compute cursor bitmap bytes */
		cbytes = softc->cur.size.y * sizeof (softc->cur.image[0]);

		bcopy(softc->cur.image, &stack_image, cbytes);
		bcopy(softc->cur.mask, &stack_mask, cbytes);

		mutex_exit(&softc->mutex);

		if (ddi_copyout(STRUCT_BUF(fbcursor), (void *)data,
		    STRUCT_SIZE(fbcursor), mode))
			return (EFAULT);

		/* if image pointer is non-null copy both bitmaps */
		if (STRUCT_FGETP(fbcursor, image)) {
			if (ddi_copyout(&stack_image,
			    STRUCT_FGETP(fbcursor, image),
			    cbytes, mode))
				return (EFAULT);

			if (ddi_copyout(&stack_mask,
			    STRUCT_FGETP(fbcursor, mask),
			    cbytes, mode))
				return (EFAULT);
		}

		/* if red pointer is non-null copy colormap */
		if (STRUCT_FGETP(fbcursor, cmap.red)) {
			cursor_cmap = 1;
			cmd = FBIOGETCMAP;
			/*
			 * XX64	The code used to do this:
			 *
			 * data = (int)&((struct fbcursor *)data)->cmap;
			 *
			 * However the cmap_ioctl handler doesn't look
			 * at 'data' so this assignment doesn't do anything.
			 * Instead we made it set the correct field in the
			 * fbcurpos structure we were passed in from
			 * userland.
			 */
			STRUCT_SET_HANDLE(fbcmap, mode,
			    STRUCT_FADDR(fbcursor, cmap));
			goto cmap_ioctl;
		}
	}
	break;

	case FBIOSCURPOS: {

		struct fbcurpos stack_curpos;	/* cursor position */

		if (ddi_copyin((caddr_t)data,
		    (caddr_t)&stack_curpos,
		    sizeof (struct fbcurpos),
		    mode))
			return (EFAULT);

		mutex_enter(&softc->mutex);
		bcopy((caddr_t)&stack_curpos, (caddr_t)&softc->cur.pos,
		    sizeof (struct fbcurpos));
		cg6_setcurpos(softc);
		mutex_exit(&softc->mutex);
	}
	break;

	case FBIOGCURPOS: {
		struct fbcurpos stack_curpos;	/* cursor position */

		mutex_enter(&softc->mutex);
		bcopy((caddr_t)&softc->cur.pos, (caddr_t)&stack_curpos,
		    sizeof (struct fbcurpos));
		mutex_exit(&softc->mutex);

		if (ddi_copyout((caddr_t)&stack_curpos,
		    (caddr_t)data,
		    sizeof (struct fbcurpos),
		    mode))
			return (EFAULT);
	}
	break;

	case FBIOGCURMAX: {
		static struct fbcurpos curmax = {32, 32};

		if (ddi_copyout((caddr_t)&curmax,
		    (caddr_t)data,
		    sizeof (struct fbcurpos),
		    mode))
			return (EFAULT);
	}
	break;

#if	CG6DEBUG >= 3
	case 255:
		cg6_debug = (int)data;
		if (cg6_debug == -1)
			cg6_debug = CG6DEBUG;
		cmn_err(CE_CONT, "cg6_debug is now %d\n", cg6_debug);
		break;
#endif

	default:
		return (ENOTTY);
	}				/* switch(cmd) */

	return (0);
}

static  uint_t
cg6_intr(caddr_t arg)
{
	struct cg6_softc *softc = (struct cg6_softc *)arg;
	volatile uint32_t *in;
	volatile uint32_t *out;
	volatile uint32_t  tmp;

	DEBUGF(7, (CE_CONT,
	    "cg6_intr: softc=%x, vrtflag=%x\n", softc, softc->vrtflag));

	mutex_enter(&softc->mutex);
	mutex_enter(&softc->interlock);

	if (!cg6_int_pending(softc)) {
		if (softc->intr_flag) {
		softc->intr_flag = 0;
		} else {
		if (softc->intrstats) {
			KIOIP->intrs[KSTAT_INTR_SPURIOUS]++;
		}
		mutex_exit(&softc->interlock);
		mutex_exit(&softc->mutex);
		return (DDI_INTR_UNCLAIMED);	/* nope, not mine */
		}
	}

	if (!(cg6_update_pending(softc) || (softc)->vrtflag)) {
	    /* TODO catch stray interrupts? */
		cg6_int_disable_intr(softc);
		if (softc->intrstats) {
		KIOIP->intrs[KSTAT_INTR_HARD]++;
		}
		mutex_exit(&softc->interlock);
		mutex_exit(&softc->mutex);
		return (DDI_INTR_CLAIMED);
	}
	if (softc->vrtflag & CG6VRTCTR) {
		if (softc->vrtmaps == 0) {
		softc->vrtflag &= ~CG6VRTCTR;
		} else
		*softc->vrtpage += 1;
	}
	if (softc->vrtflag & CG6VRTIOCTL) {
		softc->vrtflag &= ~CG6VRTIOCTL;
		cv_broadcast(&softc->vrtsleep);
	}
	if (cg6_update_pending(softc)) {
		volatile struct cg6_cmap *cmap = S_CMAP(softc);
		LOOP_T  count = softc->cmap_count;

		/* load cursor color map */
		if (softc->omap_update) {
			in = &softc->omap_image.omap_int[0];
			out = (uint32_t *)& cmap->omap;

			/* background color */
			cmap->addr = 1 << 24;
			tmp = in[0];
			*out = tmp;
			*out = tmp <<= 8;
			*out = tmp <<= 8;

			/* foreground color */
			cmap->addr = 3 << 24;
			*out = tmp <<= 8;
			tmp = in[1];
			*out = tmp;
			*out = tmp <<= 8;
		}
		/* load main color map */
		if (count) {
			LOOP_T  index = softc->cmap_index;

			in = &softc->cmap_image.cmap_int[0];
			out = (uint32_t *)& cmap->cmap;

			/* count multiples of 4 RGB entries */
			count = (count + (index & 3) + 3) >> 2;

			/* round index to 4 entry boundary */
			index &= ~3;

			cmap->addr = index << 24;
			PTR_INCR(uint32_t *, in, index * 3);

			/* copy 4 bytes (4/3 RGB entries) per loop iteration */
			count *= 3;
			/* CSTYLED */
			PR_LOOPV(count, tmp = *in++;
				*out = tmp;
				*out = tmp <<= 8;
				*out = tmp <<= 8;
				/* CSTYLED */
				*out = tmp <<= 8);

			softc->cmap_count = 0;
		}
		softc->omap_update = 0;
	}
	cg6_int_disable_intr(softc);
	if (softc->vrtflag)
		cg6_int_enable(softc);
	if (softc->intrstats) {
		KIOIP->intrs[KSTAT_INTR_HARD]++;
	}
	mutex_exit(&softc->interlock);
	mutex_exit(&softc->mutex);
	return (DDI_INTR_CLAIMED);
}

/*
 * Initialize a colormap: background = white, all others = black
 */
static void
cg6_reset_cmap(volatile uchar_t *cmap, uint_t entries)
{
	bzero((char *)cmap, entries * 3);
	cmap[0] = 255;
	cmap[1] = 255;
	cmap[2] = 255;
}

/*
 * Compute color map update parameters: starting index and count.
 * If count is already nonzero, adjust values as necessary.
 * Zero count argument indicates cursor color map update desired.
 */
static void
cg6_update_cmap(struct cg6_softc *softc, uint_t index, uint_t count)
{
	uint_t   high, low;

	if (count == 0) {
		softc->omap_update = 1;
		return;
	}

	high = softc->cmap_count;

	if (high != 0) {
		high += (low = softc->cmap_index);

		if (index < low)
		softc->cmap_index = low = index;

		if (index + count > high)
		high = index + count;

		softc->cmap_count = high - low;
	} else {
		softc->cmap_index = index;
		softc->cmap_count = count;
	}
}

/*
 * Copy colormap entries between red, green, or blue array and
 * interspersed rgb array.
 *
 * count > 0 : copy count bytes from buf to rgb
 * count < 0 : copy -count bytes from rgb to buf
 */
static void
cg6_cmap_bcopy(uchar_t *bufp, uchar_t *rgb, uint_t count)
{
	LOOP_T rcount = count;

	if (--rcount >= 0)
		PR_LOOPVP(rcount,
			/* CSTYLED */
			*rgb = *bufp++;
			/* CSTYLED */
			rgb += 3);
	else {
		rcount = -rcount - 2;
		PR_LOOPVP(rcount,
			/* CSTYLED */
			*bufp++ = *rgb;
			/* CSTYLED */
			rgb += 3);
	}
}

/*
 * This routine restores the color map to it's post-attach time values.
 */
static void
cg6_restore_prom_cmap(struct cg6_softc *softc,
	volatile uchar_t *cmap,
	uint_t entries)
{
	volatile struct cg6_cmap *hwcmap = S_CMAP(softc);
	volatile uint32_t *in, *out, tmp;
	LOOP_T count;

	out = (uint32_t *)&hwcmap->cmap;
	in = (uint32_t *)cmap;

	if (entries != 0) {
		hwcmap->addr = 0;

		count = ((entries + 3) >> 2) * 3;
		/* CSTYLED */
		PR_LOOPV(count, tmp = *in++;
			*out = tmp;
			*out = tmp <<= 8;
			*out = tmp <<= 8;
			/* CSTYLED */
			*out = tmp <<= 8);
	}
}

/*
 * enable/disable/update HW cursor
 */
static void
cg6_setcurpos(struct cg6_softc *softc)
{
	volatile struct thc *thc = S_THC(softc);

	thc->l_thc_cursor = softc->cur.enable ?
	    (((softc->cur.pos.x - softc->cur.hot.x) << 16) |
	    ((softc->cur.pos.y - softc->cur.hot.y) & 0xffff)) :
	    CG6_CURSOR_OFFPOS;
}

/*
 * load HW cursor bitmaps
 */
static void
cg6_setcurshape(struct cg6_softc *softc)
{
	uint_t  tmp, edge = 0;
	volatile uint_t *image, *mask, *hw;
	volatile struct thc *thc = S_THC(softc);
	int    i;

	/* compute right edge mask */
	if (softc->cur.size.x)
		edge = (uint_t)~ 0 << (32 - softc->cur.size.x);

	image = softc->cur.image;
	mask = softc->cur.mask;
	hw = (uint_t *)&thc->l_thc_cursora00;

	for (i = 0; i < 32; i++) {
		hw[i] = (tmp = mask[i] & edge);
		hw[i + 32] = tmp & image[i];
	}
}

static void
cg6_reset(struct cg6_softc *softc)
{
	volatile struct thc *thc = S_THC(softc);

	/* disable HW cursor */
	thc->l_thc_cursor = CG6_CURSOR_OFFPOS;

	/* reinitialize TEC */
	{
		volatile struct tec *tec = S_TEC(softc);

		tec->l_tec_mv = 0;
		tec->l_tec_clip = 0;
		tec->l_tec_vdc = 0;
	}

	/* reinitialize FBC config register */
	{
		volatile uint_t  *fhc = S_FHC(softc);
		uint_t rev, conf;

		rev = *fhc >> FHC_CONFIG_REV_SHIFT & FHC_CONFIG_REV_MASK;
		if (rev <= 4) {

		/* PROM knows how to deal with LSC and above */
		/* rev == 0 : FBC 0 (not available to customers) */
		/* rev == 1 : FBC 1 */
		/* rev == 2 : FBC 2 */
		/* rev == 3 : Toshiba (never built) */
		/* rev == 4 : Standard Cell (not built yet) */
		/* rev == 5 : LSC rev 2 (buggy) */
		/* rev == 6 : LSC rev 3 */
		conf = *fhc & FHC_CONFIG_RES_MASK |
		    FHC_CONFIG_CPU_68020;

#if FBC_REV0
		/* FBC0: test window = 0, disable fast rops */
		if (rev == 0)
			conf |= FHC_CONFIG_TEST |
			    FHC_CONFIG_FROP_DISABLE;
		else
#endif	/* FBC_REV0 */

		    /* test window = 1K x 1K */
			conf |= FHC_CONFIG_TEST |
			    (10 + 1) << FHC_CONFIG_TESTX_SHIFT |
			    (10 + 1) << FHC_CONFIG_TESTY_SHIFT;

		/* FBC[01]: disable destination cache */
		if (rev <= 1)
			conf |= FHC_CONFIG_DST_DISABLE;

		*fhc = conf;
		}
	}

	/* reprogram DAC to enable HW cursor use */
	{
		volatile struct cg6_cmap *cmap = S_CMAP(softc);

	    /* command register */
		cmap->addr = 6 << 24;

	    /* turn on CR1:0, overlay enable */
		cmap->ctrl = cmap->ctrl | (0x3 << 24);
	}
}

	/*
	 * This code is no longer used, since OBP proms now do all device
	 * initialization. Nevertheless, it is instructive and I'm going to
	 * keep it in as a comment, should anyone ever want to know how to
	 * do minimal device initialization. Note the c++ style embedded
	 * comments.
	 *
	 * cg6_init(softc)
	 *	struct cg6_softc *softc;
	 * {
	 *	// Initialize DAC
	 *	{
	 *	    register struct cg6_cmap *cmap = S_CMAP(softc);
	 *	    register char *p;
	 *
	 *	    static char dacval[] = {
	 *		4, 0xff,
	 *		5, 0,
	 *		6, 0x73,
	 *		7, 0,
	 *		0
	 *	    };
	 *
	 *	    // initialize DAC
	 *	    for (p = dacval; *p; p += 2) {
	 *		cmap->addr = p[0] << 24;
	 *		cmap->ctrl = p[1] << 24;
	 *	    }
	 *	}
	 *
	 *	// Initialize THC
	 *	{
	 *	    register struct thc *thc = S_THC(softc);
	 *	    int    vidon;
	 *
	 *	    vidon = thc_get_video(thc);
	 *	    thc->l_thc_hcmisc = THC_HCMISC_RESET | THC_HCMISC_INIT;
	 *	    thc->l_thc_hcmisc = THC_HCMISC_INIT;
	 *
	 *	    thc->l_thc_hchs = 0x010009;
	 *	    thc->l_thc_hchsdvs = 0x570000;
	 *	    thc->l_thc_hchd = 0x15005d;
	 *	    thc->l_thc_hcvs = 0x010005;
	 *	    thc->l_thc_hcvd = 0x2403a8;
	 *	    thc->l_thc_hcr = 0x00016b;
	 *
	 *	    thc->l_thc_hcmisc = THC_HCMISC_RESET | THC_HCMISC_INIT;
	 *	    thc->l_thc_hcmisc = THC_HCMISC_INIT;
	 *
	 *	    if (vidon)
	 *		thc_set_video(thc, _ONE_);
	 *
	 *	    DEBUGF(1, (CE_CONT, "TEC rev %d\n",
	 *			thc->l_thc_hcmisc >> THC_HCMISC_REV_SHIFT &
	 *			THC_HCMISC_REV_MASK));
	 *	}
	 *
	 *	//
	 *	// Initialize FHC for 1152 X 900 screen
	 *	//
	 *	{
	 *	    volatile uint_t *fhc = S_FHC(softc), rev;
	 *
	 *	    rev = *fhc >> FHC_CONFIG_REV_SHIFT & FHC_CONFIG_REV_MASK;
	 *	    DEBUGF(1, (CE_CONT, "cg6_init: FBC rev %d\n", rev));
	 *
	 *	//
	 *	// FBC0: disable fast rops FBC[01]: disable destination cache
	 *	//
	 *	    *fhc = FHC_CONFIG_1152 |
	 *		FHC_CONFIG_CPU_68020 |
	 *		FHC_CONFIG_TEST |
	 *
	 * #if FBC_REV0
	 *	    (rev == 0 ? FHC_CONFIG_FROP_DISABLE : 0) |
	 * #endif
	 *
	 *	    (rev <= 1 ? FHC_CONFIG_DST_DISABLE : 0);
	 *	}
	 * }
	 */

/*
 * from here on down, is the lego segment driver.  this virtualizes the
 * lego register file by associating a register save area with each
 * mapping of the lego device (each lego segment).  only one of these
 * mappings is valid at any time; a page fault on one of the invalid
 * mappings saves off the current lego context, invalidates the current
 * valid mapping, restores the former register contents appropriate to
 * the faulting mapping, and then validates it.
 *
 * this implements a graphical context switch that is transparent to the user.
 *
 * the TEC and FBC contain the interesting context registers.
 *
 */

/*
 * Per-segment info:
 *	Some, but not all, segments are part of a context.
 *	Any segment that is a MAP_PRIVATE mapping to the TEC or FBC
 *	will be part of a unique context.  MAP_SHARED mappings are part
 *	of the shared context and all such programs must arbitrate among
 *	themselves to keep from stepping on each other's register settings.
 *	Mappings to the framebuffer may or may not be part of a context,
 *	depending on exact hardware type.
 */

#define	CG6MAP_SHARED	0x02	/* shared context */
#define	CG6MAP_VRT	0x04	/* vrt page */
#define	CG6MAP_FBCTEC	0X08	/* mapping includes fbc and/or tec */
#define	CG6MAP_FB	0X10	/* mapping includes framebuffer */

#define	CG6MAP_CTX	(CG6MAP_FBCTEC | CG6MAP_FB)	/* needs context */

static struct cg6map_pvt *
cg6_pvt_alloc(struct cg6_cntxt *ctx,
		uint_t type,
		offset_t off,
		size_t len,
		struct cg6_softc *softc)
{
	struct cg6map_pvt *pvt;

	/*
	 * create the private data portion of the devmap object
	 */
	pvt = kmem_zalloc(sizeof (struct cg6map_pvt), KM_SLEEP);
	pvt->type = type;
	pvt->offset  = off;
	pvt->len = len;
	pvt->context = ctx;
	pvt->softc = softc;

	/*
	 * Link this pvt into the list of associated pvt's for this
	 * context
	 */
	pvt->next = ctx->pvt;
	ctx->pvt = pvt;

	return (pvt);
}

/*
 * This routine is called through the cb_ops table to handle
 * the creation of lego (cg6) segments.
 */
/*ARGSUSED*/
static int
cg6_segmap(dev_t	dev,
	    off_t	off,
	    struct as	*as,
	    caddr_t	*addrp,
	    off_t	len,
	    uint_t	prot,
	    uint_t	maxprot,
	    uint_t	flags,
	    cred_t	*cred)
{
	struct cg6_softc *softc = getsoftc(getminor(dev));
	int	error;

	DEBUGF(3, (CE_CONT, "segmap: off=%x, len=%x\n", off, len));
	mutex_enter(&softc->mutex);

	/*
	 * check to see if this is a VRT page
	 */
	if (off == CG6_VADDR_VRT) {
		if (len != pagesize) {
			mutex_exit(&softc->mutex);
			DEBUGF(3, (CE_CONT,
			    "rejecting because off=vrt and len=%x\n", len))
			return (EINVAL);
		}
		if (softc->vrtmaps++ == 0) {
			if (softc->vrtpage == NULL) {
				softc->vrtpage = (int *)ddi_umem_alloc(
				    pagesize, KM_SLEEP,
				    (void **)&softc->vrtcookie);
			}
			*softc->vrtpage = 0;
			softc->vrtflag |= CG6VRTCTR;
			cg6_int_enable(softc);
		}
	}

	/*
	 * use the devmap framework for setting up the user mapping.
	 */
	error = devmap_setup(dev, (offset_t)off, as, addrp, (size_t)len, prot,
	    maxprot, flags, cred);

	mutex_exit(&softc->mutex);

	return (error);
}

/* ARGSUSED */
static int
cg6map_map(devmap_cookie_t dhp, dev_t dev, uint_t flags, offset_t off,
	size_t len, void **pvtp)
{
	struct cg6_softc *softc = getsoftc(getminor(dev));
	struct cg6_cntxt *ctx		= (struct cg6_cntxt *)NULL;
	struct cg6_cntxt *shared_ctx	= &softc->shared_ctx;
	struct cg6map_pvt *pvt;
	uint_t	maptype = 0;

	DEBUGF(3, (CE_CONT, "cg6map_map: off = %x, len = %x\n",
	    (uint_t)off, (uint_t)len));

	/*
	 * LSC DFB BUG KLUDGE:  DFB must always be mapped private on the buggy
	 * (chip rev. 5) LSC chip.  This is done to ensure that nobody ever
	 * touches the framebuffer without the segment driver getting involved
	 * to make sure the registers are idle. This involves taking a page
	 * fault, invalidating all other process's mappings to the fb, (and
	 * performing a context switch?)
	 *
	 * Under pixrects, which maps the chips and the FB all at once, the
	 * entire mapping becomes a context. This won't hurt pixrects but
	 * entails unnecessary context switching.  Under other libraries such
	 * as XGL, which maps the chips private and the FB shared, the FB
	 * becomes part of the context. Programs which only map the FB will
	 * also become contexts, but since they don't map the chips, there's
	 * no context to switch.
	 */
	if (off + len > CG6_VADDR_FBC && off < CG6_VADDR_FBC + CG6_FBCTEC_SZ)
		maptype |= CG6MAP_FBCTEC;
	if (off + len > CG6_VADDR_COLOR && off < CG6_VADDR_COLOR + CG6_FB_SZ)
		maptype |= CG6MAP_FB;

	/*
	 * we now support MAP_SHARED and MAP_PRIVATE:
	 *
	 * MAP_SHARED means you get the shared context which is the traditional
	 * mapping method.
	 *
	 * MAP_PRIVATE means you get your very own LEGO context.
	 *
	 * Note that you can't get to here without asking for one or the other,
	 * but not both.
	 */
	if (softc->chiprev == 5 && (maptype & CG6MAP_FB))
		flags = (flags & ~MAP_TYPE) | MAP_PRIVATE;

	if (flags & MAP_SHARED) {	/* shared mapping */
		ctx = shared_ctx;
		ctx->flag = CG6MAP_CTX;
	} else {
		ctx = ctx_map_insert(softc, maptype);
		ctx->flag |= maptype;
		DEBUGF(2, (CE_CONT, "cg6map_map: ** MAP_PRIVATE **. ctx = %x\n",
		    ctx));
	}

	pvt = cg6_pvt_alloc(ctx, maptype, off, len, softc);
	pvt->dhp = dhp;

	*pvtp = pvt;

	devmap_set_ctx_timeout(dhp, cg6_ctxholdval);
	return (DDI_SUCCESS);
}

/*
 * An access has been made to a context other than the current one
 */
/* ARGSUSED */
static int
cg6map_access(devmap_cookie_t dhp, void *pvt, offset_t offset, size_t len,
	uint_t type, uint_t rw)
{
	return (devmap_do_ctxmgt(dhp, pvt, offset, len, type, rw,
	    cg6map_contextmgt));
}

/*
 * called by the devmap framework to perform context switching.
 */
/* ARGSUSED */
static int
cg6map_contextmgt(devmap_cookie_t dhp, void *pvt, offset_t offset,
	size_t len, uint_t type, uint_t rw)
{
	struct cg6map_pvt *p   = (struct cg6map_pvt *)pvt;
	struct cg6map_pvt *pvts;
	struct cg6_softc *softc = p->softc;
	volatile struct fbc *fbc;
	int err = 0;

	ASSERT(pvt);

	mutex_enter(&softc->mutex);

	DEBUGF(6, (CE_CONT, "cg6map_contextmgt: pvt = %x, dhp = %x, \
curctx = %x, context = %x\n",
	    p, dhp, softc->curctx, p->context));
	/*
	 * Do we need to switch contexts?
	 */
	if (softc->curctx != p->context) {

		fbc = S_FBC(softc);

		/*
		 * If there's a current context, save it
		 */
		if (softc->curctx != (struct cg6_cntxt *)NULL) {
			/*
			 * Set segdev for current context and all associated
			 * handles to intercept references to their addresses
			 */
			ASSERT(softc->curctx->pvt);
			for (pvts = softc->curctx->pvt; pvts != NULL;
			    pvts = pvts->next) {
				err = devmap_unload(pvts->dhp, pvts->offset,
				    pvts->len);
				if (err) {
					mutex_exit(&softc->mutex);
					return (err);
				}
			}

			if (cg6_cntxsave(fbc, S_TEC(softc),
			    softc->curctx) == 0) {
				DEBUGF(1, (CE_CONT,
				    "cgsix: context save failed\n"));
				/*
				 * At this point we have no current context.
				 */
				softc->curctx = NULL;
				mutex_exit(&softc->mutex);
				return (-1);
			}
		}

		/*
		 * Idle the chips
		 */
		CG6DELAY(!(fbc->l_fbc_status & L_FBC_BUSY), CG6_FBC_WAIT);
		if (fbc->l_fbc_status & L_FBC_BUSY) {
			DEBUGF(1, (CE_CONT, "cgsix: idle_cg6: status = %x\n",
			    fbc->l_fbc_status));
			/*
			 * At this point we have no current context.
			 */
			softc->curctx = NULL;
			mutex_exit(&softc->mutex);
			return (-1);
		}

		DEBUGF(4, (CE_CONT, "loading context %x\n", p->context));

		if (p->context->flag & CG6MAP_FBCTEC)
			if (cg6_cntxrestore(fbc, S_TEC(softc),
			    p->context) == 0) {
				DEBUGF(1, (CE_CONT,
				    "cgsix: context restore failed\n"));
				/*
				 * At this point we have no current context.
				 */
				softc->curctx = NULL;
				mutex_exit(&softc->mutex);
				return (-1);
			}

		/*
		 * switch software "context"
		 */
		softc->curctx = p->context;
	}

	ASSERT(p->context->pvt);
	if ((type == DEVMAP_LOCK) || (type == DEVMAP_UNLOCK)) {
		if ((err = devmap_load(p->dhp, offset, len, type, rw)) != 0) {
			mutex_exit(&softc->mutex);
			return (err);
		}
	} else {
		if ((err = devmap_load(p->dhp, p->offset, p->len, type,
		    rw)) != 0) {
			mutex_exit(&softc->mutex);
			return (err);
		}
	}

	mutex_exit(&softc->mutex);

	return (err);
}

/* ARGSUSED */
static void
cg6map_unmap(devmap_cookie_t dhp, void *pvtp, offset_t off, size_t len,
	devmap_cookie_t new_dhp1, void **pvtp1,
	devmap_cookie_t new_dhp2, void **pvtp2)
{
	struct cg6map_pvt *p = (struct cg6map_pvt *)pvtp;
	struct cg6_softc *softc = p->softc;
	struct cg6_cntxt *ctx = p->context;
	struct cg6map_pvt *ptmp;
	struct cg6map_pvt *ppvts;
	struct cg6_cntxt *shared_ctx    = &softc->shared_ctx;
	size_t length;

	DEBUGF(3, (CE_CONT, "cg6map_unmap: pvt = %x, dhp = %x, \
off = %x, len = %x, dhp1 = %x, dhp2 = %x\n",
	    pvtp, dhp, (uint_t)off, len, new_dhp1, new_dhp2));

	mutex_enter(&softc->mutex);

	/*
	 * We are unmapping at the end of the mapping, if
	 * new_dhp1 is not NULL.
	 */
	if (new_dhp1 != NULL) {
		ptmp = cg6_pvt_alloc(ctx,  p->type,
		    p->offset,
		    (off - p->offset),
		    softc);
		ptmp->dhp = new_dhp1;
		*pvtp1 = ptmp;
	}

	/*
	 * We are unmapping at the beginning of the mapping, if
	 * new_dhp2 is not NULL.
	 */
	if (new_dhp2 != NULL) {
		length = p->len - len - (off -  p->offset);
		ptmp = cg6_pvt_alloc(ctx, p->type, (off + len), length, softc);
		ptmp->dhp = new_dhp2;

		*pvtp2 = ptmp;
	}

	/*
	 * Remove the original pvt data
	 */
	ppvts = NULL;
	for (ptmp = ctx->pvt; ptmp != NULL; ptmp = ptmp->next) {
		if (ptmp == pvtp) {
			if (ppvts == NULL) {
				ctx->pvt = ptmp->next;
			} else {
				ppvts->next = ptmp->next;
			}
			kmem_free(pvtp, sizeof (struct cg6map_pvt));
			break;
		}
		ppvts = ptmp;
	}

	/*
	 * We want to remove the conext if both new_dhp1 and new_dhp2 are NULL.
	 */
	if (new_dhp1 == NULL && new_dhp2 == NULL) {
		/*
		 * Remove the context if this is not the shared context
		 * xand there are no more associated pvt's
		 */
		if ((ctx != shared_ctx) && (ctx->pvt == NULL)) {
			struct cg6_cntxt *ctxptr;

			if (ctx == softc->curctx)
				softc->curctx = NULL;

			/*
			 * Scan private context list for entry to remove.
			 * Check first to see if it's the head of our list.
			 */
			if (softc->pvt_ctx == ctx) {
				softc->pvt_ctx = ctx->link;
				kmem_free(ctx, sizeof (struct cg6_cntxt));
			} else {
				for (ctxptr = softc->pvt_ctx; ctxptr != NULL;
				    ctxptr = ctxptr->link) {
					if (ctxptr->link == ctx) {
						ctxptr->link = ctx->link;
						kmem_free(ctx,
						    sizeof (struct cg6_cntxt));
					}
				}
			}
		}

		/*
		 * If the curctx is the shared context, and there are no
		 * more pvt's for the shared context, set the curctx to
		 * NULL to force a context switch on the next device access.
		 */
		if ((softc->curctx == shared_ctx) && (softc->curctx->pvt ==
		    NULL)) {
			softc->curctx = NULL;
		}
	}

	mutex_exit(&softc->mutex);
}

/* ARGSUSED */
static int
cg6map_dup(devmap_cookie_t dhp, void *oldpvt, devmap_cookie_t new_dhp,
	void **newpvt)
{
	struct cg6map_pvt *p   = (struct cg6map_pvt *)oldpvt;
	struct cg6_softc *softc = p->softc;
	struct cg6map_pvt *pvt;
	struct cg6_cntxt *ctx;
	uint_t maptype;

	DEBUGF(3, (CE_CONT, "cg6map_dup: pvt=%x, dhp=%x, newdhp=%x\n",
	    oldpvt, dhp, new_dhp));

	mutex_enter(&softc->mutex);
	if (p->context != &softc->shared_ctx) {
		maptype = p->type;
		ctx = ctx_map_insert(softc, maptype);
	} else
		ctx = &softc->shared_ctx;

	pvt = cg6_pvt_alloc(ctx, p->type, p->offset, p->len, softc);

	pvt->dhp = new_dhp;
	*newpvt = pvt;

	if (p->context && (p->context->flag & CG6MAP_VRT)) {
		softc->vrtflag |= CG6VRTCTR;
		if (softc->vrtmaps == 0)
			cg6_int_enable(softc);
		softc->vrtmaps++;
	}

	mutex_exit(&softc->mutex);
	return (0);
}

/*
 * please don't mess with these defines... they may look like
 * a strange place for defines, but the context management code
 * wants them as they are. JMP
 *
 */
#undef	L_TEC_VDC_INTRNL0
#define	L_TEC_VDC_INTRNL0	0x8000
#undef	L_TEC_VDC_INTRNL1
#define	L_TEC_VDC_INTRNL1	0xa000

static int
cg6_cntxsave(fbc, tec, saved)
	volatile struct fbc *fbc;
	volatile struct tec *tec;
	struct cg6_cntxt *saved;
{
	int    dreg;		/* counts through the data registers */
	uint_t  *dp;			/* points to a tec data register */

	DEBUGF(5, (CE_CONT, "saving registers for %d\n", saved->pid));

	CDELAY(!(fbc->l_fbc_status & L_FBC_BUSY), CG6_FBC_WAIT);
	if (fbc->l_fbc_status & L_FBC_BUSY) {
	    DEBUGF(1, (CE_CONT, "cgsix: idle_cg6: status = %x\n",
			fbc->l_fbc_status));
	    return (0);
	}

	/*
	 * start dumping stuff out.
	 */
	saved->fbc.status = fbc->l_fbc_status;
	saved->fbc.clipcheck = fbc->l_fbc_clipcheck;
	saved->fbc.misc = fbc->l_fbc_misc;
	saved->fbc.x0 = fbc->l_fbc_x0;
	saved->fbc.y0 = fbc->l_fbc_y0;
	saved->fbc.x1 = fbc->l_fbc_x1;
	saved->fbc.y1 = fbc->l_fbc_y1;
	saved->fbc.x2 = fbc->l_fbc_x2;
	saved->fbc.y2 = fbc->l_fbc_y2;
	saved->fbc.x3 = fbc->l_fbc_x3;
	saved->fbc.y3 = fbc->l_fbc_y3;
	saved->fbc.rasteroffx = fbc->l_fbc_rasteroffx;
	saved->fbc.rasteroffy = fbc->l_fbc_rasteroffy;
	saved->fbc.autoincx = fbc->l_fbc_autoincx;
	saved->fbc.autoincy = fbc->l_fbc_autoincy;
	saved->fbc.clipminx = fbc->l_fbc_clipminx;
	saved->fbc.clipminy = fbc->l_fbc_clipminy;
	saved->fbc.clipmaxx = fbc->l_fbc_clipmaxx;
	saved->fbc.clipmaxy = fbc->l_fbc_clipmaxy;
	saved->fbc.fcolor = fbc->l_fbc_fcolor;
	saved->fbc.bcolor = fbc->l_fbc_bcolor;
	saved->fbc.rasterop = fbc->l_fbc_rasterop;
	saved->fbc.planemask = fbc->l_fbc_planemask;
	saved->fbc.pixelmask = fbc->l_fbc_pixelmask;
	saved->fbc.pattalign = fbc->l_fbc_pattalign;
	saved->fbc.pattern0 = fbc->l_fbc_pattern0;
	saved->fbc.pattern1 = fbc->l_fbc_pattern1;
	saved->fbc.pattern2 = fbc->l_fbc_pattern2;
	saved->fbc.pattern3 = fbc->l_fbc_pattern3;
	saved->fbc.pattern4 = fbc->l_fbc_pattern4;
	saved->fbc.pattern5 = fbc->l_fbc_pattern5;
	saved->fbc.pattern6 = fbc->l_fbc_pattern6;
	saved->fbc.pattern7 = fbc->l_fbc_pattern7;

	/*
	 * the tec matrix and clipping registers are easy.
	 */
	saved->tec.mv = tec->l_tec_mv;
	saved->tec.clip = tec->l_tec_clip;
	saved->tec.vdc = tec->l_tec_vdc;

	/*
	 * the tec data registers are a little more non-obvious.
	 * internally, they are 36 bits. what we see in the register
	 * file is a 32-bit window onto the underlying data register.
	 * changing the data-type in the VDC gets us either of two parts
	 * of the data register. the internal format is opaque to us.
	 */
	tec->l_tec_vdc = (uint_t)L_TEC_VDC_INTRNL0;
	for (dreg = 0, dp = (uint_t *)&tec->l_tec_data00; dreg < 64;
				dreg++, dp++) {
		saved->tec.data[dreg][0] = *dp;
	}
	tec->l_tec_vdc = (uint_t)L_TEC_VDC_INTRNL1;
	for (dreg = 0, dp = (uint_t *)&tec->l_tec_data00; dreg < 64;
				dreg++, dp++) {
		saved->tec.data[dreg][1] = *dp;
	}

	return (1);
}

static int
cg6_cntxrestore(fbc, tec, saved)
	volatile struct fbc *fbc;
	volatile struct tec *tec;
	struct cg6_cntxt *saved;
{
	int	dreg;
	uint_t  *dp;

	DEBUGF(5, (CE_CONT, "restoring registers for %d\n", saved->pid));

	/*
	 * reload the tec data registers. see above for "how do they get
	 * 36 bits in that itty-bitty int"
	 */
	tec->l_tec_vdc = (uint_t)L_TEC_VDC_INTRNL0;
	for (dreg = 0, dp = (uint_t *)&tec->l_tec_data00;
		dreg < 64; dreg++, dp++) {
		*dp = saved->tec.data[dreg][0];
	}
	tec->l_tec_vdc = (uint_t)L_TEC_VDC_INTRNL1;
	for (dreg = 0, dp = (uint_t *)&tec->l_tec_data00;
		dreg < 64; dreg++, dp++) {
		*dp = saved->tec.data[dreg][1];
	}

	/*
	 * the tec matrix and clipping registers are next.
	 */
	tec->l_tec_mv = saved->tec.mv;
	tec->l_tec_clip = saved->tec.clip;
	tec->l_tec_vdc = saved->tec.vdc;

	/*
	 * now the FBC vertex and address registers
	 */
	fbc->l_fbc_x0 = saved->fbc.x0;
	fbc->l_fbc_y0 = saved->fbc.y0;
	fbc->l_fbc_x1 = saved->fbc.x1;
	fbc->l_fbc_y1 = saved->fbc.y1;
	fbc->l_fbc_x2 = saved->fbc.x2;
	fbc->l_fbc_y2 = saved->fbc.y2;
	fbc->l_fbc_x3 = saved->fbc.x3;
	fbc->l_fbc_y3 = saved->fbc.y3;
	fbc->l_fbc_rasteroffx = saved->fbc.rasteroffx;
	fbc->l_fbc_rasteroffy = saved->fbc.rasteroffy;
	fbc->l_fbc_autoincx = saved->fbc.autoincx;
	fbc->l_fbc_autoincy = saved->fbc.autoincy;
	fbc->l_fbc_clipminx = saved->fbc.clipminx;
	fbc->l_fbc_clipminy = saved->fbc.clipminy;
	fbc->l_fbc_clipmaxx = saved->fbc.clipmaxx;
	fbc->l_fbc_clipmaxy = saved->fbc.clipmaxy;

	/*
	 * restoring the attribute registers
	 */
	fbc->l_fbc_fcolor = saved->fbc.fcolor;
	fbc->l_fbc_bcolor = saved->fbc.bcolor;
	fbc->l_fbc_rasterop = saved->fbc.rasterop;
	fbc->l_fbc_planemask = saved->fbc.planemask;
	fbc->l_fbc_pixelmask = saved->fbc.pixelmask;
	fbc->l_fbc_pattalign = saved->fbc.pattalign;
	fbc->l_fbc_pattern0 = saved->fbc.pattern0;
	fbc->l_fbc_pattern1 = saved->fbc.pattern1;
	fbc->l_fbc_pattern2 = saved->fbc.pattern2;
	fbc->l_fbc_pattern3 = saved->fbc.pattern3;
	fbc->l_fbc_pattern4 = saved->fbc.pattern4;
	fbc->l_fbc_pattern5 = saved->fbc.pattern5;
	fbc->l_fbc_pattern6 = saved->fbc.pattern6;
	fbc->l_fbc_pattern7 = saved->fbc.pattern7;

	fbc->l_fbc_clipcheck = saved->fbc.clipcheck;
	fbc->l_fbc_misc = saved->fbc.misc;

	/*
	 * lastly, let's restore the status
	 */
	fbc->l_fbc_status = saved->fbc.status;

	return (1);
}

/*
 * ctx_map_insert()
 *
 * Insert a mapping into the mapping list of a private context.  First
 * determine if there's an existing context (e.g. one with the same PID
 * as the current  one and that does not already have a mapping of this
 * type yet).  If not, allocate a new one.  Then insert mapping into this
 * context's list.
 *
 * The softc mutex must be held across calls to this routine.
 */
static
struct cg6_cntxt *
ctx_map_insert(struct cg6_softc *softc, int maptype)
{
	struct cg6_cntxt *ctx;
	pid_t curpid = getpid();

	DEBUGF(4, (CE_CONT, "ctx_map_insert: maptype=0x%x curpid=%d\n",
	    maptype, curpid));

	/*
	 * If this is the first time we're here, then alloc space
	 * for new context and depart.
	 */
	if (softc->pvt_ctx == NULL) {
		ctx = (struct cg6_cntxt *)
		    kmem_zalloc(sizeof (struct cg6_cntxt), KM_SLEEP);
		ctx->pid = curpid;
		ctx->link = NULL;
		softc->pvt_ctx = ctx;
		return (ctx);
	}

	/*
	 * Find existing context if one exists.  We have a match if
	 * we're the same process *and* there's not already a
	 * mapping of this type assigned.
	 */
	for (ctx = softc->pvt_ctx; ctx != NULL; ctx = ctx->link) {
		if (ctx->pid == curpid &&
		    (maptype & ctx->flag & (CG6MAP_FBCTEC|CG6MAP_FB)) == 0)
			break;
	}


	/* no match, create a new one and add to softc list */
	if (ctx == NULL) {
		ctx = (struct cg6_cntxt *)
		    kmem_zalloc(sizeof (struct cg6_cntxt), KM_SLEEP);
		ctx->pid = curpid;
		ctx->link = softc->pvt_ctx;
		softc->pvt_ctx = ctx;
	}

	DEBUGF(4, (CE_CONT, "ctx_map_insert: returning ctx=0x%x\n", ctx));

	return (ctx);
}

/*
 * getpid()
 *
 * Simple wrapper around process ID call to drv_getparm(9f).
 */
static pid_t
getpid()
{
	pid_t mypid;

	if (drv_getparm(PPID, &mypid) == -1)
		return (0);
	return (mypid);
}

#define	DEVMEMORY	1
#define	KERNELMEMORY	2

/*ARGSUSED*/
static int
cg6_devmap(dev_t dev, devmap_cookie_t dhp, offset_t off, size_t len,
    size_t *maplen, uint_t model)
{
	struct cg6_softc *softc = getsoftc(getminor(dev));
	dev_info_t *dip = softc->devi;
	ssize_t diff;
	int err = 0;
	caddr_t	kvaddr = NULL;
	ddi_umem_cookie_t cookie = NULL;
	offset_t offset = 0;
	uint_t	rnumber = 0;
	uint_t	type = DEVMEMORY;
	size_t	length = len;
	uint_t	map_type = 0;
	uint_t	ctxmap = 0;
	struct devmap_callback_ctl *callbackops = &cg6map_ops;

	DEBUGF(2, (CE_CONT, "cg6_devmap(%d), off=0x%x, len=%x, dhp=%x\n",
	    getminor(dev), (uint_t)off, len, dhp));

	if ((diff = off - CG6_VADDR_COLOR) >= 0 && diff < softc->fbmappable) {
		if ((len + off) > (CG6_VADDR_COLOR + softc->fbmappable))
			length = CG6_VADDR_COLOR + softc->fbmappable - off;
		offset = CG6_ADDR_COLOR + diff;
		map_type = CG6MAP_FB;
	} else if ((diff = off - CG6_VADDR_FBC) >= 0 && diff < CG6_FBCTEC_SZ) {
		if ((len + off) > (CG6_VADDR_FBC + CG6_FBCTEC_SZ))
			length = (CG6_VADDR_FBC + CG6_FBCTEC_SZ) - off;
		offset = CG6_ADDR_FBC + diff;
		map_type = CG6MAP_FBCTEC;
	} else if ((diff = off - CG6_VADDR_CMAP) >= 0 && diff < CG6_CMAP_SZ) {
		if ((len + off) > (CG6_VADDR_CMAP + CG6_CMAP_SZ))
			length = (CG6_VADDR_CMAP + CG6_CMAP_SZ) - off;
		offset = CG6_ADDR_CMAP + diff;
	} else if ((diff = off - CG6_VADDR_FHC) >= 0 && diff < CG6_FHCTHC_SZ) {
		if ((len + off) > (CG6_VADDR_FHC + CG6_FHCTHC_SZ))
			length = (CG6_VADDR_FHC + CG6_FHCTHC_SZ) - off;
		offset = CG6_ADDR_FHC + diff;
	} else if ((diff = off - CG6_VADDR_ROM) >= 0 && diff < CG6_ROM_SZ) {
		if ((len + off) > (CG6_VADDR_ROM + CG6_ROM_SZ))
			length = (CG6_VADDR_ROM + CG6_ROM_SZ) - off;
		offset = softc->addr_rom + diff;
	} else if ((diff = off - CG6_VADDR_DHC) >= 0 && diff < CG6_DHC_SZ) {
		if ((len + off) > (CG6_VADDR_DHC + CG6_DHC_SZ))
			length = (CG6_VADDR_DHC + CG6_DHC_SZ) - off;
		offset = CG6_ADDR_DHC + diff;
	} else if ((diff = off - CG6_VADDR_ALT) >= 0 && diff < CG6_ALT_SZ) {
		if ((len + off) > (CG6_VADDR_ALT + CG6_ALT_SZ))
			length = (CG6_VADDR_ALT + CG6_ALT_SZ) - off;
		offset = CG6_ADDR_ALT + diff;
	} else if ((diff = off - CG6_VADDR_VRT) >= 0 && diff < CG6_VRT_SZ) {
		if ((len + off) > (CG6_VADDR_VRT + CG6_VRT_SZ))
			length = (CG6_VADDR_VRT + CG6_VRT_SZ) - off;
		type = KERNELMEMORY;
		if (softc->vrtpage != NULL)
			offset = diff;
		else
			kvaddr = (caddr_t)-1;
		cookie = softc->vrtcookie;
	} else if ((diff = off - CG3_MMAP_OFFSET) >= 0 &&
	    diff < softc->fbmappable) {
		if ((len + off) > (CG3_MMAP_OFFSET + softc->fbmappable))
			length = CG3_MMAP_OFFSET + softc->fbmappable - off;
		offset = CG6_ADDR_COLOR + diff;
	} else if (off < CG6_VBASE) {
		if (softc->emulation == FBTYPE_SUN3COLOR) {
			if (off >= 0 && off < softc->fbmappable) {
				if ((len + off) > softc->fbmappable)
					length = softc->fbmappable - off;
				offset = CG6_ADDR_COLOR + diff;
			} else
				kvaddr = (caddr_t)-1;
		} else {	/* softc->emulation == FBTYPE_SUN4COLOR */
			if (off >= 0 && off < softc->dummysize) {
				if ((len + off) > softc->dummysize)
					length = softc->dummysize - off;
				offset = CG6_ADDR_COLOR + diff;
			} else if ((diff = off - softc->dummysize) <
			    softc->fbmappable) {
				if ((len + off) >
				    (softc->dummysize + softc->fbmappable))
					length = softc->fbmappable - off;
				offset = CG6_ADDR_COLOR + diff;
			}
		}
	} else
		kvaddr = (caddr_t)-1;

	if (kvaddr == (caddr_t)-1) {
		DEBUGF(1, (CE_CONT, "cg6_devmap: no mapping off=0x%x, len=%x\n",
		    (uint_t)off, len));
		return (-1);
	}

	DEBUGF(2, (CE_CONT, "cg6_devmap: offset=0x%x, kvaddr=%x, length=%x\n",
	    (uint_t)offset, kvaddr, length));

	/*
	 * LSC DFB BUG KLUDGE:  DFB must always be mapped private on the buggy
	 * (chip rev. 5) LSC chip.  This is done to ensure that nobody ever
	 * touches the framebuffer without the segment driver getting involved
	 * to make sure the registers are idle. This involves taking a page
	 * fault, invalidating all other process's mappings to the fb, (and
	 * performing a context switch?)
	 *
	 * Under pixrects, which maps the chips and the FB all at once, the
	 * entire mapping becomes a context. This won't hurt pixrects but
	 * entails unnecessary context switching.  Under other libraries such
	 * as XGL, which maps the chips private and the FB shared, the FB
	 * becomes part of the context. Programs which only map the FB will
	 * also become contexts, but since they don't map the chips, there's
	 * no context to switch.
	 */
	ctxmap = (softc->chiprev == 5) ?
	    (CG6MAP_FBCTEC|CG6MAP_FB) : CG6MAP_FBCTEC;

	/*
	 * do context switching on the TEC and FBC registers.
	 */
	if (map_type & ctxmap)
		callbackops = &cg6map_ops;
	else
		callbackops = NULL;

	if (type == DEVMEMORY) {
		if ((err = devmap_devmem_setup(dhp, dip, callbackops, rnumber,
		    offset, length, PROT_ALL, DEVMAP_DEFAULTS,
		    &endian_attr)) < 0)
			return (err);
	} else {
		if ((err = devmap_umem_setup(dhp, dip, callbackops, cookie,
		    offset, length, PROT_ALL, DEVMAP_DEFAULTS,
		    &endian_attr)) < 0)
			return (err);
	}

	*maplen = roundup(length, PAGESIZE);
	return (0);
}
