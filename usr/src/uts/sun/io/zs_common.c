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

/*
 *	Serial I/O driver for Z8530 chips
 */


#include	<sys/types.h>
#include	<sys/param.h>
#include	<sys/systm.h>
#include	<sys/sysmacros.h>
#include	<sys/stropts.h>
#include	<sys/stream.h>
#include	<sys/stat.h>
#include	<sys/mkdev.h>
#include	<sys/cmn_err.h>
#include	<sys/errno.h>
#include	<sys/kmem.h>
#include	<sys/zsdev.h>
#include	<sys/debug.h>
#include	<sys/machsystm.h>

#include	<sys/conf.h>
#include	<sys/sunddi.h>
#include	<sys/errno.h>

#define	 ZS_TRACING
#ifdef  ZS_TRACING
#include <sys/vtrace.h>

/*
 * Temp tracepoint definitions
 */
#define	TR_FAC_ZS		51

#define	TR_ZS_H_INT_START	1
#define	TR_ZS_H_INT_END		2
#define	TR_ZS_INT_START		3
#define	TR_ZS_INT_END		4

#define	TR_FAC_ZS_INT		52
#define	TR_READ_START		1
#define	TR_READ_END		2

#endif  /* ZSH_TRACING */

#define	KIOIP		KSTAT_INTR_PTR(zs->intrstats)

#ifndef	MAXZS
#define	MAXZS		4
#endif
int maxzs = MAXZS;

int nzs = 0;

struct zscom *zscom;
struct zscom *zscurr;
struct zscom *zslast;
struct zs_prog *zs_prog;
char  *zssoftCAR;
int	zs_watchdog_count = 10;	/* countdown to determine if tx hung */

int zs_drain_check = 15000000;		/* tunable: exit drain check time */

#ifdef ZS_DEBUG
char zs_h_log[ZS_H_LOG_MAX +10];
int zs_h_log_n = 0;
#define	zs_h_log_add(c) \
	{ \
		if (zs_h_log_n >= ZS_H_LOG_MAX) \
			zs_h_log_n = 0; \
		zs_h_log[zs_h_log_n++] = c; \
		zs_h_log[zs_h_log_n] = '\0'; \
	}

#else /* NO_ZS_DEBUG */
#define	zs_h_log_add(c)
#endif /* ZS_DEBUG */


/*
 * Driver data
 */

#define	GETPROP(dip, str, defval) \
	ddi_getprop(DDI_DEV_T_ANY, (dip), DDI_PROP_DONTPASS, (str), (defval))

int	zs_usec_delay = 1;
int	zssoftpend;
ddi_softintr_t zs_softintr_id;
time_t	default_dtrlow = 3;	/* hold dtr low nearly this long on close */
static ddi_iblock_cookie_t zs_iblock;
static ddi_iblock_cookie_t zs_hi_iblock;
static int zs_addedsoft = 0;


/*
 * Driver information for auto-configuration stuff.
 */

static int zsprobe(dev_info_t *dev);
static int zsattach(dev_info_t *dev, ddi_attach_cmd_t cmd);
static int zsdetach(dev_info_t *dev, ddi_detach_cmd_t cmd);
void	zsopinit(struct zscom *zs, struct zsops *zso);

static void zsnull_intr(struct zscom *zs);
static int zsnull_softint(struct zscom *zs);
static int zsnull_suspend(struct zscom *zs);
static int zsnull_resume(struct zscom *zs);

struct zsops zsops_null = {
			zsnull_intr,
			zsnull_intr,
			zsnull_intr,
			zsnull_intr,
			zsnull_softint,
			zsnull_suspend,
			zsnull_resume
};

extern struct streamtab asynctab;	/* default -- from zs_async.c */

uint_t zs_high_intr(caddr_t argzs);
uint_t zsintr(caddr_t intarg);

extern int zsc_info(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg,
void **result);

extern int ddi_create_internal_pathname(dev_info_t *dip, char *name,
    int spec_type, minor_t minor_num);

extern struct streamtab zsstab;
int		zssoftpend;		/* soft interrupt pending */
kmutex_t	zs_soft_lock;		/* adapt.lock,to use to protect data */
					/* common to sev. streams or ports   */
kmutex_t	zs_curr_lock;		/* lock protecting zscurr */

extern kcondvar_t lbolt_cv;

/*
 * curently the only spin lock level 12 for all ocasions
 */

#define	ZSS_CONF_FLAG   (D_NEW | D_MP)

static  struct cb_ops cb_zs_ops = {
	nulldev,		/* cb_open */
	nulldev,		/* cb_close */
	nodev,			/* cb_strategy */
	nodev,			/* cb_print */
	nodev,			/* cb_dump */
	nodev,			/* cb_read */
	nodev,			/* cb_write */
	nodev,			/* cb_ioctl */
	nodev,			/* cb_devmap */
	nodev,			/* cb_mmap */
	nodev,			/* cb_segmap */
	nochpoll,		/* cb_chpoll */
	ddi_prop_op,		/* cb_prop_op */
	&asynctab,		/* cb_stream */
	(int)(ZSS_CONF_FLAG)	/* cb_flag */
};

struct dev_ops zs_ops = {
	DEVO_REV,		/* devo_rev */
	0,			/* devo_refcnt */
	zsc_info,		/* devo_getinfo */
	nulldev,		/* devo_identify */
	zsprobe,		/* devo_probe */
	zsattach,		/* devo_attach */
	zsdetach,		/* devo_detach */
	nodev,			/* devo_reset */
	&cb_zs_ops,		/* devo_cb_ops */
	(struct bus_ops *)NULL,	/* devo_bus_ops */
	ddi_power,		/* devo_power */
	ddi_quiesce_not_supported,	/* devo_quiesce */
};


/*
 * This is the loadable module wrapper.
 */

#include <sys/modctl.h>

/*
 * Module linkage information for the kernel.
 */

extern struct mod_ops mod_driverops;

static struct modldrv modldrv = {
		&mod_driverops, /* Type of module.  This one is a driver */
		"Z8530 serial driver",
		&zs_ops,	/* driver ops */
};

static struct modlinkage modlinkage = {
			MODREV_1, (void *)&modldrv, NULL
};

int
_init(void)
{
	return (mod_install(&modlinkage));
}

int
_fini(void)
{
	return (EBUSY);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

static int
zsprobe(dev_info_t *dev)
{
	struct zscc_device *zsaddr;
	int	rval;
	auto char	c;

	rval = DDI_PROBE_FAILURE;

	/*
	 * temporarily map in  registers
	 */
	if (ddi_map_regs(dev, 0, (caddr_t *)&zsaddr, 0, 0)) {
		cmn_err(CE_WARN, "zsprobe: unable to map registers");
		return (rval);
	}

	/*
	 * NON-DDI Compliant call
	 */
	mon_clock_stop();

	/*
	 * get in sync with the chip
	 */

	if (ddi_peek8(dev, (char *)&zsaddr->zscc_control, &c) != DDI_SUCCESS) {
		goto out;
	}
	drv_usecwait(2);

	/*
	 * The traditional test for the presence of an 8530 has been to write
	 * a 15 (octal 017) to its control register address, then read it back.
	 * A Z8530 will respond to this with the contents of Read-Register 15.
	 * If this address were memory, or something else, we would expect to
	 * see the 15 again.  Normally, the contents of RR15 will be entirely
	 * different.  A Z8530 does not use the D0 and D2 bits of register 15,
	 * so they should equal zero.  Compatable chips should do the same.
	 * Beware of "enhanced" SCC's that do not guarantee this.
	 */
	if (ddi_poke8(dev, (char *)&zsaddr->zscc_control, '\017')
	    != DDI_SUCCESS) {
		goto out;
	}
	drv_usecwait(2);
	if (ddi_peek8(dev, (char *)&zsaddr->zscc_control, &c) != DDI_SUCCESS) {
		goto out;
	}
	drv_usecwait(2);
	if (c & 5) {
		goto out;
	}

	rval = DDI_PROBE_SUCCESS;

out:
	/*
	 * NON-DDI Compliant call
	 */
	mon_clock_start();

	ddi_unmap_regs(dev, 0, (caddr_t *)&zsaddr, 0, 0);
	return (rval);
}

/*ARGSUSED*/
static int
zsattach(dev_info_t *dev, ddi_attach_cmd_t cmd)
{
	struct zscom	*zs;
	int		loops, i;
	uint_t		s;
	int		rtsdtr_bits = 0;
	char			softcd;
	uchar_t	rr;
	short			speed[2];
	int			current_chip = ddi_get_instance(dev);
	struct zscc_device	*tmpzs;		/* for mapping purposes */
	char name[16];
	int keyboard_prop;

	switch (cmd) {
	case DDI_ATTACH:
		break;

	case DDI_RESUME:
		zs = &zscom[current_chip*2];
		/*
		 * Try to resume first channel
		 */
		if (!zs->zs_resume || (zs->zs_resume)(zs) != DDI_SUCCESS)
			return (DDI_FAILURE);
		/*
		 * And the second channel
		 */
		zs++;
		if (!zs->zs_resume || (zs->zs_resume)(zs) != DDI_SUCCESS) {
			zs--;
			if (!zs->zs_suspend ||
			    (zs->zs_suspend)(zs) != DDI_SUCCESS)
				cmn_err(CE_WARN,
				    "zs: inconsistent suspend/resume state");
			return (DDI_FAILURE);
		}
		return (DDI_SUCCESS);

	default:
		return (DDI_FAILURE);
	}

	if (zscom == NULL) {
		mutex_init(&zs_soft_lock, NULL, MUTEX_DRIVER, (void *)ZS_PL);
		mutex_init(&zs_curr_lock, NULL, MUTEX_DRIVER, (void *)ZS_PL_HI);
		zscom = kmem_zalloc(maxzs * sizeof (struct zscom), KM_SLEEP);
		zs_prog = kmem_zalloc(maxzs * sizeof (struct zs_prog),
		    KM_SLEEP);
		zssoftCAR = kmem_zalloc(maxzs, KM_SLEEP);
		/* don't set nzs until arrays are allocated */
		membar_producer();
		nzs = maxzs;
		zscurr = &zscom[(current_chip*2) + 1];
		zslast = &zscom[current_chip*2];
		i = GETPROP(dev, "zs-usec-delay", 0);
		zs_usec_delay = (i <= 0) ? 1 : i;
	}

	if (2 * current_chip >=  maxzs) {
		cmn_err(CE_WARN,
		    "zs: unable to allocate resources for  chip %d.",
		    current_chip);
		cmn_err(CE_WARN, "Change zs:maxzs in /etc/system");
		return (DDI_FAILURE);
	}
	zs = &zscom[current_chip*2];

	/*
	 * map in the device registers
	 */
	if (ddi_map_regs(dev, 0, (caddr_t *)&zs->zs_addr, 0, 0)) {
		cmn_err(CE_WARN, "zs%d: unable to map registers\n",
		    current_chip);
		return (DDI_FAILURE);
	}

	tmpzs = zs->zs_addr;

	/*
	 * Non-DDI compliant Sun-Ness specfic call(s)
	 */

	/*
	 * Stop the monitor's polling interrupt.
	 *
	 * I know that this is not exactly obvious. On all sunmon PROM
	 * machines, the PROM has can have a high level periodic clock
	 * interrupt going at this time. It uses this periodic interrupt
	 * to poll the console tty or kbd uart to check for things like
	 * BREAK or L1-A (abort). While we're probing this device out we
	 * have to shut that off so the PROM won't get confused by what
	 * we're doing to the zs. This has caused some pretty funny bugs
	 * in its time.
	 *
	 * For OPENPROM machines, the prom  takes level12 interrupts directly,
	 * but we call this routine anyway (I forget why).
	 */
	mon_clock_stop();

	/*
	 * Go critical to keep uart from urking.
	 */
	s = ddi_enter_critical();

	/*
	 * We are about to issue a full reset to this chip.
	 * First, now that interrupts are blocked, we will delay up to a
	 * half-second, checking both channels for any stray activity.
	 * Next we will preserve the time constants from both channels,
	 * so that they can be restored after the reset.  This is especially
	 * important for the console device.  Finally, do the reset and
	 * follow it with an extended recovery while the chip settles down.
	 */
	for (loops = 0; loops++ <= 500; DELAY(1000)) {
		SCC_READA(1, rr);
		if ((rr & ZSRR1_ALL_SENT) == 0) continue;
		SCC_READB(1, rr);
		if ((rr & ZSRR1_ALL_SENT) == 0) continue;
		SCC_READA(0, rr);
		if ((rr & ZSRR0_TX_READY) == 0) continue;
		SCC_READB(0, rr);
		if ((rr & ZSRR0_TX_READY) != 0) break;
	}

	SCC_READA(12, speed[0]);
	SCC_READA(13, rr);
	speed[0] |= rr << 8;
	SCC_READB(12, speed[1]);
	SCC_READB(13, rr);
	speed[1] |= rr << 8;

	SCC_WRITE(9, ZSWR9_RESET_WORLD);
	DELAY(10);

	/*
	 * Set up the other components of the zscom structs for this chip.
	 */
	for (i = 0; i < 2; i++) {
		/*
		 * Property for ignoring DCD.
		 * We switch between 'a' and 'b' ports for this device.
		 */
		static char prop[] = "port-a-ignore-cd";

		/*
		 * For this channel, set the hardware address, allocate the
		 * high-level mutex, and update the zscurr pointer.
		 * The high-level lock is shared by both channels because
		 * 8530 register addressing is non-atomic and asymetrical.
		 * Multiple threads crossing paths during this operation
		 * could trash the chip, and thus, possibly the system console.
		 */
		if (i == 0) {		/* port A */
			zs->zs_addr = (struct zscc_device *)
			    ((uintptr_t)tmpzs | ZSOFF);
			(zs+1)->zs_excl_hi = zs->zs_excl_hi = &zs_curr_lock;
		} else {		/* port B */
			zs++;
			zs->zs_addr = (struct zscc_device *)
			    ((uintptr_t)tmpzs & ~ZSOFF);
			zscurr = zs;
		}
		zs->zs_unit = current_chip * 2 + i;
		zs->zs_dip = dev;
		zs->zs_excl = kmem_zalloc(sizeof (kmutex_t), KM_SLEEP);
		mutex_init(zs->zs_excl, NULL, MUTEX_DRIVER, (void *)ZS_PL);
		zs->zs_ocexcl = kmem_zalloc(sizeof (kmutex_t), KM_SLEEP);
		mutex_init(zs->zs_ocexcl, NULL, MUTEX_DRIVER, (void *)ZS_PL);

		zsopinit(zs, &zsops_null);

		prop[5] = 'a' + i;
		softcd = GETPROP((dev_info_t *)(dev), prop, 0);
		zssoftCAR[zs->zs_unit] = softcd;
		if (softcd)
			rtsdtr_bits = ZSWR5_RTS | ZSWR5_DTR;

		keyboard_prop = GETPROP((dev_info_t *)(zs->zs_dip),
		    "keyboard", 0);

		mutex_enter(&zs_curr_lock);

		/*
		 * Set up the default asynch modes
		 * so the monitor will still work
		 */
		SCC_WRITE(4, ZSWR4_PARITY_EVEN | ZSWR4_1_STOP | ZSWR4_X16_CLK);
		SCC_WRITE(3, ZSWR3_RX_8);
		SCC_WRITE(11, ZSWR11_TXCLK_BAUD | ZSWR11_RXCLK_BAUD);
		SCC_WRITE(12, (speed[i] & 0xff));
		SCC_WRITE(13, (speed[i] >> 8) & 0xff);
		SCC_WRITE(14, ZSWR14_BAUD_FROM_PCLK);
		SCC_WRITE(3, ZSWR3_RX_8 | ZSWR3_RX_ENABLE);
		SCC_WRITE(5, ZSWR5_TX_ENABLE | ZSWR5_TX_8 | rtsdtr_bits);
		SCC_WRITE(14, ZSWR14_BAUD_ENA | ZSWR14_BAUD_FROM_PCLK);

		/*
		 * The SYNC pin on the second SCC (keyboard & mouse) may not
		 * be connected and noise creates transitions on this line.
		 * This floods the system with interrupts, unless the
		 * Sync/Hunt Interrupt Enable is cleared.  So write
		 * register 15 with everything we need but that one.
		 */
		if (keyboard_prop) {
			SCC_WRITE(15, ZSR15_BREAK | ZSR15_TX_UNDER |
			    ZSR15_CTS | ZSR15_CD);
		}

		SCC_WRITE0(ZSWR0_RESET_ERRORS);
		SCC_WRITE0(ZSWR0_RESET_STATUS);
		mutex_exit(&zs_curr_lock);

		zs->zs_dtrlow = gethrestime_sec() - default_dtrlow;
		cv_init(&zs->zs_flags_cv, NULL, CV_DEFAULT, NULL);
		zsa_init(zs);
	}

	mutex_enter(&zs_curr_lock);
	SCC_WRITE(9, ZSWR9_MASTER_IE | ZSWR9_VECTOR_INCL_STAT);
	DELAY(4000);
	mutex_exit(&zs_curr_lock);

	/*
	 * Two levels of interrupt - chip interrupts at a high level (12),
	 * (which is seen below as zs_high_intr), and then as a secondary
	 * stage soft interrupt as seen in zsintr below.
	 *
	 * Because zs_high_intr does a window save, as well as calls to
	 * other functions, we cannot install it as a "fast" interrupt
	 * that would execute right out of the trap window.  Too bad...
	 */
	if (ddi_add_intr(dev, (uint_t)0, &zs_hi_iblock,
	    (ddi_idevice_cookie_t *)0, zs_high_intr,
	    (caddr_t)0) != DDI_SUCCESS) {
		cmn_err(CE_PANIC, "cannot set high level zs interrupt");
		/*NOTREACHED*/
	}

	if (zs_addedsoft == 0) {
		if (ddi_add_softintr(dev, DDI_SOFTINT_HIGH, &zs_softintr_id,
		    &zs_iblock, (ddi_idevice_cookie_t *)0,
		    zsintr, (caddr_t)0) != DDI_SUCCESS) {
			cmn_err(CE_PANIC,
			    "cannot set second stage zs interrupt");
			/*NOTREACHED*/
		}

		zs_addedsoft++;	/* we only need one zsintr! */
	}

	if (zs > zslast)
		zslast = zs;

	(void) ddi_exit_critical(s);

	/*
	 * Non-DDI compliant Sun-Ness specific call
	 */
	mon_clock_start();	/* re-enable monitor's polling interrupt */

	if (!GETPROP(zs->zs_dip, "keyboard", 0)) {
		static char *serial_line = DDI_NT_SERIAL_MB;
		static char *dial_out = DDI_NT_SERIAL_MB_DO;

		/*
		 * Export names for channel a or b consconfig match...
		 * The names exported to the filesystem include the
		 * designated tty'a' type name and may not match the PROM
		 * pathname.
		 * Note the special name "obp-console-name" used in these calls.
		 * This keeps the ports and devlinks programs from seeing these
		 * names. (But allows ddi_pathname_to_dev_t to see them.)
		 * We don't need to do this if the instance number is zero,
		 * because we'll create them below, in this case.
		 */

		if (ddi_get_instance(dev) != 0)  {

			/*
			 * Select a node type unused by ddi/devfs
			 */
			static char *obp_type = "obp-console-name";

			(void) strcpy(name, "a");
			if (ddi_create_minor_node(dev, name, S_IFCHR,
			    ddi_get_instance(dev) * 2,
			    obp_type, NULL) == DDI_FAILURE) {
				ddi_remove_minor_node(dev, NULL);
				return (DDI_FAILURE);
			}
			(void) strcpy(name, "b");
			if (ddi_create_minor_node(dev, name, S_IFCHR,
			    (ddi_get_instance(dev) * 2) + 1,
			    obp_type, NULL) == DDI_FAILURE) {
				ddi_remove_minor_node(dev, NULL);
				return (DDI_FAILURE);
			}
		}

		/*
		 * Export normal device names...
		 */
		(void) sprintf(name, "%c", (ddi_get_instance(dev) + 'a'));
		if (ddi_create_minor_node(dev, name, S_IFCHR,
		    ddi_get_instance(dev) * 2,
		    serial_line, NULL) == DDI_FAILURE) {
			ddi_remove_minor_node(dev, NULL);
			return (DDI_FAILURE);
		}
		(void) sprintf(name, "%c", (ddi_get_instance(dev) + 'b'));
		if (ddi_create_minor_node(dev, name, S_IFCHR,
		    (ddi_get_instance(dev) * 2) + 1,
		    serial_line, NULL) == DDI_FAILURE) {
			ddi_remove_minor_node(dev, NULL);
			return (DDI_FAILURE);
		}
		(void) sprintf(name, "%c,cu", (ddi_get_instance(dev) + 'a'));
		if (ddi_create_minor_node(dev, name, S_IFCHR,
		    (ddi_get_instance(dev) * 2) | OUTLINE,
		    dial_out, NULL) == DDI_FAILURE) {
			ddi_remove_minor_node(dev, NULL);
			return (DDI_FAILURE);
		}
		(void) sprintf(name, "%c,cu", (ddi_get_instance(dev) + 'b'));
		if (ddi_create_minor_node(dev, name, S_IFCHR,
		    ((ddi_get_instance(dev)  * 2) + 1) | OUTLINE,
		    dial_out, NULL) == DDI_FAILURE) {
			ddi_remove_minor_node(dev, NULL);
			return (DDI_FAILURE);
		}
	} else {

		/*
		 * Create keyboard and mouse nodes which devfs doesn't see
		 */

		/*
		 * This set of minor nodes is for use with the consconfig_dacf
		 * module for the sun4u platforms.  (See PSARC/1998/212)
		 */
		if (ddi_create_internal_pathname(dev, "keyboard", S_IFCHR,
		    ddi_get_instance(dev) * 2) == DDI_FAILURE) {
			ddi_remove_minor_node(dev, NULL);
			return (DDI_FAILURE);
		}

		if (ddi_create_internal_pathname(dev, "mouse", S_IFCHR,
		    (ddi_get_instance(dev) * 2) + 1) == DDI_FAILURE) {
			ddi_remove_minor_node(dev, NULL);
			return (DDI_FAILURE);
		}

		/*
		 * These minor nodes are for use with pre-sun4u platforms.
		 * Either one set or the other will be opened by consconfig.
		 */
		(void) strcpy(name, "a");
		if (ddi_create_internal_pathname(dev, name, S_IFCHR,
		    ddi_get_instance(dev) * 2) == DDI_FAILURE) {
			ddi_remove_minor_node(dev, NULL);
			return (DDI_FAILURE);
		}

		(void) strcpy(name, "b");
		if (ddi_create_internal_pathname(dev, name, S_IFCHR,
		    (ddi_get_instance(dev) * 2) + 1) == DDI_FAILURE) {
			ddi_remove_minor_node(dev, NULL);
			return (DDI_FAILURE);
		}

	}

	ddi_report_dev(dev);
	/*
	 * Initialize power management bookkeeping; components are
	 * created idle.
	 */
	if (pm_create_components(dev, 3) == DDI_SUCCESS) {
		(void) pm_busy_component(dev, 0);
		pm_set_normal_power(dev, 0, 1);
		pm_set_normal_power(dev, 1, 1);
		pm_set_normal_power(dev, 2, 1);
	} else {
		return (DDI_FAILURE);
	}

	(void) sprintf(name, "zsc%d", current_chip);
	zs->intrstats = kstat_create("zs", current_chip, name, "controller",
	    KSTAT_TYPE_INTR, 1, KSTAT_FLAG_PERSISTENT);
	if (zs->intrstats) {
		kstat_install(zs->intrstats);
	}

	return (DDI_SUCCESS);
}

static int
zsdetach(dev_info_t *dev, ddi_detach_cmd_t cmd)
{
	struct zscom *zs;
	int	current_chip = ddi_get_instance(dev);

	switch (cmd) {
	case DDI_DETACH:
		return (DDI_FAILURE);

	case DDI_SUSPEND:
		zs = &zscom[current_chip*2];
		/*
		 * Try to suspend first channel
		 */
		if (!zs->zs_suspend || (zs->zs_suspend)(zs) != DDI_SUCCESS)
			return (DDI_FAILURE);
		/*
		 * And the second channel
		 */
		zs++;
		if (!zs->zs_suspend || (zs->zs_suspend)(zs) != DDI_SUCCESS) {
			zs--;
			if (!zs->zs_resume ||
			    (zs->zs_resume)(zs) != DDI_SUCCESS)
				cmn_err(CE_WARN,
				    "zs: inconsistent suspend/resume state");
			return (DDI_FAILURE);
		}
		return (DDI_SUCCESS);

	default:
		return (DDI_FAILURE);
	}
}

/*
 * SCC High Level Interrupt Handler
 *
 * This routine fields the level 12 interrupts generated by the 8530 chips.
 * When the SCC interrupts the conditions that triggered it are available
 * for reference in Read Register 3 of the A channel (RR3A).  We process
 * all the pending interrupts before returning.  The maximum interrupts
 * that will be processed before returning is set to 6, which is twice
 * the size of RX-FIFO.
 * We keep a pointer to the B side of the most recently interrupting chip
 * in zscurr.
 */

/*
 * 'argzs' actually 'struct zscom *argzs'
 */

#define	ZSRR3_INT_PENDING (ZSRR3_IP_B_STAT | ZSRR3_IP_B_TX | ZSRR3_IP_B_RX |\
			ZSRR3_IP_A_STAT | ZSRR3_IP_A_TX | ZSRR3_IP_A_RX)

#define	ZSRR1_ANY_ERRORS (ZSRR1_PE | ZSRR1_DO | ZSRR1_FE | ZSRR1_RXEOF)
#define	ZS_HIGH_INTR_LOOPLIMIT 6

/*ARGSUSED*/
uint_t
zs_high_intr(caddr_t argzs)
{
	struct zscom	*zs;
	uchar_t	stat, isource, count;
	int		unit;

	TRACE_0(TR_FAC_ZS, TR_ZS_H_INT_START, "zs_h_int start");
	mutex_enter(&zs_curr_lock);
	zs = zscurr;				/* Points at Channel B */

	ZSNEXTPOLL(zs, zscurr);

	SCC_READA(3, isource);
start_zs_h:
	count = ZS_HIGH_INTR_LOOPLIMIT;
	while ((isource & ZSRR3_INT_PENDING) && (count--)) {
		if (isource & ZSRR3_IP_B_STAT)
			(zs->zs_xsint)(zs);
		else {
			if (isource & ZSRR3_IP_B_TX)
				(zs->zs_txint)(zs);
			if (isource & ZSRR3_IP_B_RX) {
				SCC_READ(1, stat);
				if (stat & ZSRR1_ANY_ERRORS)
					(zs->zs_srint)(zs);
				else if ((SCC_READ0()) & ZSRR0_RX_READY)
					(zs->zs_rxint)(zs);
			}
		}

		zs -= 1;
		if (isource & ZSRR3_IP_A_STAT)
			(zs->zs_xsint)(zs);
		else {
			if (isource & ZSRR3_IP_A_TX)
				(zs->zs_txint)(zs);
			if (isource & ZSRR3_IP_A_RX) {
				SCC_READ(1, stat);
				if (stat & ZSRR1_ANY_ERRORS)
					(zs->zs_srint)(zs);
				else if ((SCC_READ0()) & ZSRR0_RX_READY)
					(zs->zs_rxint)(zs);
			}
		}

		zs = zscurr;
		SCC_READA(3, isource);
	}

	if (count == ZS_HIGH_INTR_LOOPLIMIT) {
		unit = (nzs >> 1) - 1;
		while (unit--) {
			zs += 2;	/* Always Channel B */
			if (zs > zslast)
				zs = &zscom[1];
			if (!zs->zs_ops)
				continue;
			SCC_READA(3, isource);
			if (isource & ZSRR3_INT_PENDING) {
				zscurr = zs;	/* update zscurr and */
				goto start_zs_h;
			}
		}
		if (zs->intrstats) {
			KIOIP->intrs[KSTAT_INTR_HARD]++;
		}
		mutex_exit(&zs_curr_lock);
		TRACE_0(TR_FAC_ZS, TR_ZS_H_INT_END, "zs_h_int end");
		return (DDI_INTR_UNCLAIMED);	/* Must not be for us. */
	}
	if (zs->intrstats) {
		KIOIP->intrs[KSTAT_INTR_HARD]++;
	}
	mutex_exit(&zs_curr_lock);	/* we're done with zscurr */
	TRACE_0(TR_FAC_ZS, TR_ZS_H_INT_END, "zs_h_int end");
	return (DDI_INTR_CLAIMED);
}

/*
 * Handle a second-stage interrupt.
 */
/*ARGSUSED*/
uint_t
zsintr(caddr_t intarg)
{
	struct zscom *zs;
	int    rv;

	/*
	 * Test and clear soft interrupt.
	 */
	TRACE_0(TR_FAC_ZS, TR_ZS_INT_START,
	    "zs_int start");

	mutex_enter(&zs_curr_lock);
	rv = zssoftpend;
	if (rv != 0) {
		zssoftpend = 0;
	}
	mutex_exit(&zs_curr_lock);

	if (rv) {
		for (zs = &zscom[0]; zs <= zslast; zs++) {
			if (zs->zs_flags & ZS_NEEDSOFT) {
				zs->zs_flags &= ~ZS_NEEDSOFT;
				(*zs->zs_ops->zsop_softint)(zs);
				if (zs->intrstats) {
					KIOIP->intrs[KSTAT_INTR_SOFT]++;
				}
			}
		}
	}
	TRACE_0(TR_FAC_ZS, TR_ZS_INT_END,
	    "zs_int end");
	return (rv);
}

void
setzssoft(void)
{
	ddi_trigger_softintr(zs_softintr_id);
}

/*
 * Install a new ops vector into low level vector routine addresses
 */
void
zsopinit(struct zscom *zs, struct zsops *zso)
{
	zs->zs_txint	= zso->zsop_txint;
	zs->zs_xsint	= zso->zsop_xsint;
	zs->zs_rxint	= zso->zsop_rxint;
	zs->zs_srint	= zso->zsop_srint;
	zs->zs_suspend	= zso->zsop_suspend;
	zs->zs_resume	= zso->zsop_resume;
	zs->zs_ops	= zso;
	zs->zs_flags	= 0;
}

/*
 * Set or get the modem control status.
 *
 * This routine relies on the fact that the bits of interest in RR0 (CD and
 * CTS) do not overlap the bits of interest in WR5 (RTS and DTR).  Thus, they
 * can be combined into a single 'int' without harm.
 */
int
zsmctl(struct zscom *zs, int bits, int how)
{
	int mbits, obits;
	time_t now, held;

	ASSERT(mutex_owned(zs->zs_excl_hi));
	ASSERT(mutex_owned(zs->zs_excl));

again:
	mbits = zs->zs_wreg[5] & (ZSWR5_RTS|ZSWR5_DTR);
	SCC_WRITE0(ZSWR0_RESET_STATUS);
	mbits |= SCC_READ0() & (ZSRR0_CD|ZSRR0_CTS);
	ZSDELAY();
	obits = mbits;

	switch (how) {

	case DMSET:
		mbits = bits;
		break;

	case DMBIS:
		mbits |= bits;
		break;

	case DMBIC:
		mbits &= ~bits;
		break;

	case DMGET:
		return (mbits);
	}

	now = gethrestime_sec();
	held = now - zs->zs_dtrlow;

	/*
	 * if DTR is going low, stash current time away
	 */
	if (~mbits & obits & ZSWR5_DTR)
		zs->zs_dtrlow = now;

	/*
	 * if DTR is going high, sleep until it has been low a bit
	 */
	if ((mbits & ~obits & ZSWR5_DTR) && (held < default_dtrlow)) {
		mutex_exit(zs->zs_excl_hi);
		cv_wait(&lbolt_cv, zs->zs_excl);
		if (zs->zs_suspended)
			(void) ddi_dev_is_needed(zs->zs_dip, 0, 1);
		mutex_enter(zs->zs_excl_hi);
		goto again;
	}

	zs->zs_wreg[5] &= ~(ZSWR5_RTS|ZSWR5_DTR);
	SCC_BIS(5, mbits & (ZSWR5_RTS|ZSWR5_DTR));
	return (mbits);
}

/*
 * Program the Z8530 registers.
 */
void
zs_program(struct zs_prog *zspp)
{
	struct zscom *zs = zspp->zs;
	int	loops;
	uchar_t	c;
	uchar_t wr10 = 0, wr14 = 0;

	ASSERT(mutex_owned(zs->zs_excl));
	ASSERT(mutex_owned(zs->zs_excl_hi));

	/*
	 * There are some special cases to account for before reprogramming.
	 * We might be transmitting, so delay 100,000 usec (worst case at 110
	 * baud) for this to finish, then disable the receiver until later,
	 * reset the External Status Change latches and the error bits, and
	 * drain the receive FIFO.
	 * XXX: Doing any kind of reset (WR9) here causes trouble!
	 */
	if (zspp->flags & ZSP_SYNC) {
		SCC_WRITE(7, SDLCFLAG);
		wr10 = ZSWR10_PRESET_ONES;
		if (zspp->flags & ZSP_NRZI)
			wr10 |= ZSWR10_NRZI;
		SCC_WRITE(10, wr10);
	} else {
		for (loops = 1000; loops > 0; --loops) {
			SCC_READ(1, c);
			if (c & ZSRR1_ALL_SENT)
				break;
			DELAY(100);
		}
		SCC_WRITE(3, 0);
		SCC_WRITE0(ZSWR0_RESET_STATUS);
		SCC_WRITE0(ZSWR0_RESET_ERRORS);
		c = SCC_READDATA();		/* Empty the FIFO */
		c = SCC_READDATA();
		c = SCC_READDATA();
	}

	/*
	 * Programming the SCC is done in three phases.
	 * Phase one sets operating modes:
	 */
	SCC_WRITE(4, zspp->wr4);
	SCC_WRITE(11, zspp->wr11);
	SCC_WRITE(12, zspp->wr12);
	SCC_WRITE(13, zspp->wr13);
	if (zspp->flags & ZSP_PLL) {
		SCC_WRITE(14, ZSWR14_DPLL_SRC_BAUD);
		SCC_WRITE(14, ZSWR14_DPLL_NRZI);
	} else
		SCC_WRITE(14, ZSWR14_DPLL_DISABLE);

	/*
	 * Phase two enables special hardware functions:
	 */
	wr14 = ZSWR14_BAUD_FROM_PCLK | ZSWR14_BAUD_ENA;
	if (zspp->flags & ZSP_LOOP)
		wr14 |= ZSWR14_LOCAL_LOOPBACK;
	if (zspp->flags & ZSP_ECHO)
		wr14 |= ZSWR14_AUTO_ECHO;
	SCC_WRITE(14, wr14);
	SCC_WRITE(3, zspp->wr3);
	SCC_WRITE(5, zspp->wr5);

	SCC_WRITE0(ZSWR0_RESET_TXCRC);

	if (zspp->flags & ZSP_PARITY_SPECIAL) {
		SCC_WRITE(1, ZSWR1_PARITY_SPECIAL);
	} else {
		SCC_WRITE(1, 0);
	}

	/*
	 * Phase three enables interrupt sources:
	 */
	SCC_WRITE(15, zspp->wr15);
	SCC_WRITE0(ZSWR0_RESET_STATUS);
	SCC_WRITE0(ZSWR0_RESET_ERRORS);
	SCC_BIS(1, ZSWR1_INIT);
}

static void
zsnull_intr(struct zscom *zs)
{
	short	c;

	SCC_WRITE0(ZSWR0_RESET_TXINT);
	SCC_WRITE0(ZSWR0_RESET_STATUS);
	c = SCC_READDATA();
	ZSDELAY();
#ifdef lint
	c = c;
#endif /* lint */
	SCC_WRITE0(ZSWR0_RESET_ERRORS);
}

static int
zsnull_softint(struct zscom *zs)
{
	cmn_err(CE_WARN, "zs%d: unexpected soft int\n", zs->zs_unit);
	return (0);
}

/*
 * These will be called on suspend/resume for un-opened zs ports.
 */
static int
zsnull_suspend(struct zscom *zs)
{
	struct zs_prog	*zspp = &zs_prog[zs->zs_unit];

	/*
	 * Get a copy of the current registers
	 */
	mutex_enter(zs->zs_excl);
	mutex_enter(zs->zs_excl_hi);
	zspp->zs = zs;
	zspp->flags = 0;
	zspp->wr3 = zs->zs_wreg[3];
	zspp->wr4 = zs->zs_wreg[4];
	zspp->wr5 = zs->zs_wreg[5];
	zspp->wr11 = zs->zs_wreg[11];
	zspp->wr12 = zs->zs_wreg[12];
	zspp->wr13 = zs->zs_wreg[13];
	zspp->wr15 = zs->zs_wreg[15];
	mutex_exit(zs->zs_excl_hi);
	mutex_exit(zs->zs_excl);

	return (DDI_SUCCESS);
}

static int
zsnull_resume(struct zscom *zs)
{
	struct zs_prog	*zspp = &zs_prog[zs->zs_unit];

	/*
	 * Restore registers
	 */
	mutex_enter(zs->zs_excl);
	mutex_enter(zs->zs_excl_hi);
	zs_program(zspp);
	SCC_WRITE(9, ZSWR9_MASTER_IE);
	DELAY(4000);
	mutex_exit(zs->zs_excl_hi);
	mutex_exit(zs->zs_excl);
	return (DDI_SUCCESS);
}
