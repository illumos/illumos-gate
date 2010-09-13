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
/*
 * Copyright (c) 2009,  Intel Corporation.
 * All Rights Reserved.
 */

#ifndef _SYS_PPMVAR_H
#define	_SYS_PPMVAR_H

#include <sys/epm.h>
#include <sys/sunldi.h>

#ifdef	__cplusplus
extern "C" {
#endif


typedef struct ppm_unit {
	dev_info_t	*dip;		/* node dev info */
	kmutex_t	lock;		/* global driver lock */
	uint_t		states;		/* driver states */
	timeout_id_t	led_tid;	/* timeout id for LED */
} ppm_unit_t;

/*
 * driver states
 */
#define	PPM_STATE_SUSPENDED	0x1	/* driver is suspended */

/*
 * Check for domain operational
 */
#define	PPM_DOMAIN_UP(domp)	(!(domp->dflags & PPMD_OFFLINE))

/*
 * LED constants
 */
#define	PPM_LED_PULSE		(drv_usectohz(250000))	/* 0.25 seconds */
#define	PPM_LEDON_INTERVAL	(1 * PPM_LED_PULSE)
#define	PPM_LEDOFF_INTERVAL	(8 * PPM_LED_PULSE)
#define	PPM_LEDON		1	/* (s10) */
#define	PPM_LEDOFF		0	/* (s10) */

/*
 * internal form of "ppm.conf" data
 */
struct ppm_db {
	struct ppm_db	*next;
	char		*name;		/* device name */
	int		plen;		/* strlen before wildcard(s10) */
	int		wccnt;		/* upto 2 '*' allowed */
	int		wcpos[2];	/* '*' location in pathname */
};
typedef struct ppm_db ppm_db_t;

struct ppm_cdata {
	char *name;			/* property name */
	char **strings;			/* string array */
	uint_t cnt;			/* property count */
};

/*
 * ppm device info
 */
struct ppm_dev {
	struct ppm_dev	*next;
	struct ppm_domain *domp;
	dev_info_t	*dip;
	char		*path;		/* OBP device pathname */
	int		cmpt;		/* component number */
	int		rplvl;		/* last requested power level */
	int		level;		/* actual current power level */
	int		lowest;		/* lowest power level for device */
	int		highest;	/* highest power level for device */
	uint_t		flags;
};
typedef struct ppm_dev ppm_dev_t;

/*
 * ppm_dev.flags field
 */
#define	PPMDEV_PCI66_D2		0x1	/* device support D2 at pci 66mhz */
#define	PPMDEV_PCI_PROP_CLKPM	0x2	/* clock can be power managed */
#define	PPM_PM_POWEROP		0x10	/* power level change, initiated  */
					/* from PM is in progress.	  */
#define	PPM_PHC_WHILE_SET_POWER 0x20	/* power level of a device is	  */
					/* changed through		  */
					/* pm_power_has_changed path	  */
					/* while power level change,	  */
					/* initiated from PM is in	  */
					/* progress.			  */


/*
 * per domain record of device _ever_ managed by ppm
 */
struct ppm_owned {
	struct ppm_owned *next;
	char	*path;		/* device pathname */
	int	initializing;	/* initializing  flag */
};
typedef struct ppm_owned ppm_owned_t;


/*
 * domain control data structure -
 *   when you need to do an op for a domain, look up the op in the
 *   cmd member of the struct, and then perform the method on the
 *   path using iowr cmd with the args specified in val or val and
 *   mask or the speed index.
 */
struct ppm_dc {
	struct ppm_dc	*next;
	ldi_handle_t	lh;	/* layered (ldi) handle			*/
	char	*path;		/* control device prom pathname		*/
	uint_t	cmd;		/* search key: op to be performed	*/
				/* one of: PPMDC_CPU_NEXT		*/
				/* PPMDC_CPU_GO, PPMDC_FET_ON,		*/
				/* PPMDC_FET_OFF, PPMDC_LED_ON,		*/
				/* PPMDC_LED_OFF, PPMDC_PCI_ON,		*/
				/* PPMDC_ENTER_S3, PPMDC_PCI_OFF	*/
				/* PPMDC_EXIT_S3 commands		*/
	uint_t	method;		/* control method / union selector	*/
				/* one of PPMDC_KIO, PPMDC_I2CKIO,	*/
				/* PPMDC_CPUSPEEDKIO			*/

	union {
		/* In each sub struct in union, the first three fields	*/
		/* must be .iord, .iowr and .val and in such order.	*/
		/* The .method field above selects a union sub struct	*/
		/* for a particular .cmd operation.			*/
		/* The association between .method and .cmd is platform	*/
		/* specific, therefore described in ppm.conf file.	*/

		/* PPMDC_KIO: simple KIO 				*/
		struct m_kio {
			uint_t	iord;	/* IOCTL read cmd		*/
			uint_t	iowr;	/* IOCTL write cmd		*/
			uint_t	val;	/* ioctl arg			*/
			uint_t	delay;	/* total delay before this 	*/
					/* operation can be carried out	*/
			uint_t	post_delay; /* post delay, if any	*/
		} kio;

#ifdef sun4u
		/* PPMDC_I2CKIO: KIO requires 'arg' as struct i2c_gpio	*/
		/*    (defined in i2c_client.h)				*/
		struct m_i2ckio {
			uint_t	iord;	/* IOCTL read cmd		*/
			uint_t	iowr;	/* IOCTL write cmd 		*/
			uint_t	val;	/* register content		*/
			uint_t	mask;	/* mask to select relevant bits	*/
					/* of register content		*/
			uint_t	delay;	/* total delay before this 	*/
					/* operation can be carried out	*/
			uint_t	post_delay; /* post delay, if any	*/
		} i2c;
#endif

		/* PPMDC_CPUSPEEDKIO, PPMDC_VCORE: cpu estar related	*/
		/* simple KIO						*/
		struct m_cpu {
			uint_t	iord;	/* IOCTL read cmd 		*/
			uint_t	iowr;	/* IOCTL write cmd 		*/
			int	val;	/* new register value		*/
			uint_t	speeds;	/* number of speeds cpu supports */
			uint_t	delay;	/* microseconds post op delay	*/
		} cpu;
	} m_un;
};
typedef struct ppm_dc ppm_dc_t;

/*
 * ppm_dc.cmd field -
 */
#define	PPMDC_CPU_NEXT		2
#define	PPMDC_PRE_CHNG		3
#define	PPMDC_CPU_GO		4
#define	PPMDC_POST_CHNG		5
#define	PPMDC_FET_ON		6
#define	PPMDC_FET_OFF		7
#define	PPMDC_LED_ON		8
#define	PPMDC_LED_OFF		9
#define	PPMDC_CLK_ON		10
#define	PPMDC_CLK_OFF		11
#define	PPMDC_PRE_PWR_OFF	12
#define	PPMDC_PRE_PWR_ON	13
#define	PPMDC_POST_PWR_ON	14
#define	PPMDC_PWR_OFF		15
#define	PPMDC_PWR_ON		16
#define	PPMDC_RESET_OFF		17
#define	PPMDC_RESET_ON		18
#define	PPMDC_ENTER_S3		19
#define	PPMDC_EXIT_S3		20

/*
 * ppm_dc.method field - select union element
 */
#define	PPMDC_KIO  		1	/* simple ioctl with val as arg	*/
#define	PPMDC_CPUSPEEDKIO	2	/* ioctl with speed index arg	*/
#define	PPMDC_VCORE		3	/* CPU Vcore change operation */
#ifdef sun4u
#define	PPMDC_I2CKIO		4	/* ioctl with i2c_gpio_t as arg	*/
#endif

/*
 * devices that are powered by the same source
 * are grouped by this struct as a "power domain"
 */
struct ppm_domain {
	char		*name;		/* domain name */
	int		dflags;		/* domain flags */
	int		pwr_cnt;	/* number of powered up devices */
	ppm_db_t	*conflist;	/* all devices from ppm.conf file */
	ppm_dev_t	*devlist;	/* current attached devices */
	char		*propname;	/* domain property name */
	kmutex_t	lock;		/* domain lock */
	int		refcnt;		/* domain lock ref count */
	int		model;		/* pm model, CPU, FET or LED	*/
	int		status;		/* domain specific status */
	int		sub_domain;	/* sub-domain */
	ppm_dc_t	*dc;		/* domain control method */
	ppm_owned_t	*owned;		/* list of ever owned devices */
	struct ppm_domain	*next;	/* a linked list */
	clock_t		last_off_time;	/* last time domain was off	*/

};
typedef struct ppm_domain ppm_domain_t;


/*
 * ppm_domain.model field -
 */
#define	PPMD_CPU		1	/* cpu PM model */
#define	PPMD_FET		2	/* power FET pm model */
#define	PPMD_LED		3	/* LED pm model */
#define	PPMD_PCI		4	/* PCI pm model */
#define	PPMD_PCI_PROP		5	/* PCI_PROP pm model */
#define	PPMD_PCIE		6	/* PCI Express pm model */
#define	PPMD_SX			7	/* ACPI Sx pm model */

#define	PPMD_IS_PCI(model) \
	((model) == PPMD_PCI || (model) == PPMD_PCI_PROP)

/*
 * ppm_domain.status field -
 */
#define	PPMD_OFF		0x0	/* FET/LED/PCI clock: off */
#define	PPMD_ON			0x1	/* FET/LED/PCI clock: on */

/*
 * ppm_domain.dflags field -
 */
#define	PPMD_LOCK_ONE		0x1
#define	PPMD_LOCK_ALL		0x4
#define	PPMD_PCI33MHZ		0x1000	/* 33mhz PCI slot */
#define	PPMD_PCI66MHZ		0x2000	/* 66mhz PCI slot */
#define	PPMD_INITCHILD_CLKON	0x4000	/* clk turned on in init_child */
#define	PPMD_OFFLINE		0x10000	/* domain is not functional */
#define	PPMD_CPU_READY		0x20000	/* CPU domain can process power call */

struct ppm_domit {
	char	*name;
	int	model;
	int	dflags;
	int	status;
};
extern struct ppm_domit ppm_domit_data[];

/*
 * XXppm driver-specific routines called from common code (s10)
 */
struct ppm_funcs {
	void	(*dev_init)(ppm_dev_t *);
	void	(*dev_fini)(ppm_dev_t *);
	void	(*iocset)(uint8_t);
	uint8_t	(*iocget)(void);
};

extern ppm_domain_t	*ppm_domain_p;
extern void		*ppm_statep;
extern int		ppm_inst;
extern ppm_domain_t *ppm_domains[];	/* (s10) */
extern struct ppm_funcs ppmf;		/* (s10) */

extern void		ppm_dev_init(ppm_dev_t *);
extern void		ppm_dev_fini(ppm_dev_t *);
extern int		ppm_create_db(dev_info_t *);
extern int		ppm_claim_dev(dev_info_t *);
extern void		ppm_rem_dev(dev_info_t *);
extern ppm_dev_t	*ppm_get_dev(dev_info_t *, ppm_domain_t *);
extern void		ppm_init_cb(dev_info_t *);
extern int		ppm_init_lyr(ppm_dc_t *, dev_info_t *);
extern ppm_domain_t	*ppm_lookup_dev(dev_info_t *);
extern ppm_domain_t	*ppm_lookup_domain(char *);
extern ppm_dc_t		*ppm_lookup_dc(ppm_domain_t *, int);
extern ppm_dc_t		*ppm_lookup_hndl(int, ppm_dc_t *);
extern ppm_domain_t	*ppm_get_domain_by_dev(const char *);
extern boolean_t	ppm_none_else_holds_power(ppm_domain_t *);
extern ppm_owned_t	*ppm_add_owned(dev_info_t *, ppm_domain_t *);
extern void		ppm_lock_one(ppm_dev_t *, power_req_t *, int *);
extern void		ppm_lock_all(ppm_domain_t *, power_req_t *, int *);
extern boolean_t	ppm_manage_early_cpus(dev_info_t *, int, int *);
extern int		ppm_change_cpu_power(ppm_dev_t *, int);
extern int		ppm_revert_cpu_power(ppm_dev_t *, int);
extern ppm_dev_t	*ppm_add_dev(dev_info_t *, ppm_domain_t *);

#define	PPM_GET_PRIVATE(dip) \
    DEVI(dip)->devi_pm_ppm_private
#define	PPM_SET_PRIVATE(dip, datap) \
    DEVI(dip)->devi_pm_ppm_private = datap

#define	PPM_LOCK_DOMAIN(domp) {			\
	if (!MUTEX_HELD(&(domp)->lock))		\
		mutex_enter(&(domp)->lock);	\
	(domp)->refcnt++;			\
}

#define	PPM_UNLOCK_DOMAIN(domp) {		\
	ASSERT(MUTEX_HELD(&(domp)->lock) &&	\
		(domp)->refcnt > 0);		\
	if (--(domp)->refcnt == 0)		\
		mutex_exit(&(domp)->lock);	\
}

/*
 * debug support
 */
#ifdef DEBUG
#include <sys/promif.h>

extern char	*ppm_get_ctlstr(int, uint_t);
extern void	ppm_print_dc(struct ppm_dc *);

extern uint_t ppm_debug;

#define	D_CREATEDB	0x00000001
#define	D_CLAIMDEV	0x00000002
#define	D_ADDDEV	0x00000004
#define	D_REMDEV	0x00000008
#define	D_LOWEST	0x00000010
#define	D_SETLVL	0x00000020
#define	D_GPIO		0x00000040
#define	D_CPU		0x00000080
#define	D_FET		0x00000100
#define	D_PCIUPA	0x00000200
#define	D_1394		0x00000400
#define	D_CTLOPS1	0x00000800
#define	D_CTLOPS2	0x00001000
#define	D_SOME		0x00002000
#define	D_LOCKS		0x00004000
#define	D_IOCTL		0x00008000
#define	D_ATTACH	0x00010000
#define	D_DETACH	0x00020000
#define	D_OPEN		0x00040000
#define	D_CLOSE		0x00080000
#define	D_INIT		0x00100000
#define	D_FINI		0x00200000
#define	D_ERROR		0x00400000
#define	D_SETPWR	0x00800000
#define	D_LED		0x01000000
#define	D_PCI		0x02000000
#define	D_PPMDC		0x04000000
#define	D_CPR		0x08000000

#define	PPMD(level, arglist) {			\
	if (ppm_debug & (level)) {		\
		pm_log arglist;			\
	}					\
}
/* (s10) */
#define	DPRINTF		PPMD

#else	/* DEBUG */
#define	PPMD(level, arglist)
#define	DPRINTF(flag, args)	/* (s10) */
#endif	/* DEBUG */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_PPMVAR_H */
