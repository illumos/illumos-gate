/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * PCMCIA nexus
 */

#ifndef _PCMCIA_H
#define	_PCMCIA_H

#ifdef	__cplusplus
extern "C" {
#endif

#if defined(DEBUG)
#define	PCMCIA_DEBUG
#endif

#include <sys/modctl.h>

#define	PCMCIA_MAX_ADAPTERS	8 /* maximum distinct adapters */
#define	PCMCIA_MAX_SOCKETS	64 /* maximum distinct sockets */
#define	PCMCIA_MAX_WIN_ADAPT	40
#define	PCMCIA_MAX_WINDOWS	(PCMCIA_MAX_ADAPTERS*PCMCIA_MAX_WIN_ADAPT)
#define	PCMCIA_MAX_POWER	16 /* maximum power table entries */

#define	_VERSION(major, minor)	((major)<<16|(minor))

/*
 * DDI/Nexus stuff
 */

#define	PCMCIA_NEXUS_NAME	"pcmcia"
#define	PCMCIA_ADAPTER_NODE	"ddi_pcmcia:adapter"
#define	PCMCIA_SOCKET_NODE	"ddi_pcmcia:socket"
#define	PCMCIA_PCCARD_NODE	"ddi_pcmcia:pccard"

/*
 * private interface between nexus and adapter specific driver
 * This is only an "ops" type structure
 */

typedef struct pcmcia_if {
	uint32_t  pcif_magic;	/* magic number to verify correct scructure */
	uint32_t  pcif_version;
	int	(*pcif_set_callback)();
	int	(*pcif_get_adapter)();
	int	(*pcif_get_page)();
	int	(*pcif_get_socket)();
	int	(*pcif_get_status)();
	int	(*pcif_get_window)();
	int	(*pcif_inquire_adapter)();
	int	(*pcif_inquire_socket)();
	int	(*pcif_inquire_window)();
	int	(*pcif_reset_socket)();
	int	(*pcif_set_page)();
	int	(*pcif_set_window)();
	int	(*pcif_set_socket)();
	int	(*pcif_set_interrupt)();
	int	(*pcif_clr_interrupt)();
	int	(*pcic_init_dev)();
	uint32_t  (*pcic_get_tstamp)();
} pcmcia_if_t;

/*
 * magic number and version information to identify
 * variant of the PCMCIA nexus.
 */
#define	PCIF_MAGIC 0x50434946
#define	PCIF_VERSION	_VERSION(0, 1)
#define	PCIF_MIN_VERSION _VERSION(0, 1)
#define	DEFAULT_CS_NAME	"cs"

/*
 * all adapter drivers use a commonly defined structure for
 * their private data.  This structure must be filled in
 * and set.  The an_private member is for the driver writer's
 * use and is not looked at by the nexus.
 */
struct pcmcia_adapter_nexus_private {
	dev_info_t	*an_dip;
	pcmcia_if_t	*an_if;
	void		*an_private;
	ddi_iblock_cookie_t *an_iblock;	/* high priority handler cookies */
	ddi_idevice_cookie_t *an_idev;
	uint32_t	an_ipl;
};

typedef struct pcmcia_adapter_nexus_private anp_t;

struct pcm_regs {
	uint32_t phys_hi;
	uint32_t phys_lo;
	uint32_t phys_len;
};

/*
 * shared interrupts are handled by the
 * nexus going through the list
 */
typedef struct inthandler {
	struct inthandler	*next;
	struct inthandler	*prev;
	int			flags;
	uint32_t		(*intr)(caddr_t, caddr_t);
	unsigned		handler_id;
	void			*arg1;
	void			*arg2;
	unsigned		socket;
	unsigned		irq;
	unsigned		priority;
	ddi_softintr_t		softid;
	ddi_iblock_cookie_t	iblk_cookie;
	ddi_idevice_cookie_t	idev_cookie;
} inthandler_t;

/*
 * parent private data area
 *	not using the old style but will adapt on request
 *	this allows better framework handling and 1275 compliance
 */

struct pcmcia_parent_private {
	int	ppd_nreg;	/* number of regs */
	struct	pcm_regs *ppd_reg; /* array of regs in parsed form */
	int	ppd_intr;	/* number intrspecs (always 0 or 1) */
	struct	intrspec *ppd_intrspec;
	void	*pcm_dummy[3];	/* fill for prtconf -v */
	struct	pcm_regs *ppd_assigned; /* array of regs in parsed form */
	short	ppd_socket;	/* socket number of this instance */
	short	ppd_function;	/* function number */
	int	ppd_active;	/* is PC Card in a socket and active */
	uint32_t  ppd_flags;
	void	*ppd_handle; /* client handle */
};

#define	PPD_CARD_MULTI		0x0001 /* card is multifunction card */
#define	PPD_CARD_CARDBUS	0x0002 /* card is CardBus type */
#define	PPD_CB_BUSMASTER	0x0004 /* card bus card is busmaster */
#define	PPD_SUSPENDED		0x0008 /* this device was pm suspended */

/*
 * macros to make indirect functions easier
 * and shorter (makes cstyle happier)
 */

#define	GET_SOCKET_STATUS(f, dip, sock, stat)\
			(*(f)->pcif_get_socket_status)(dip, sock, stat)
#define	SET_CALLBACK(f, dip, callback, sock)\
			(*(f)->pcif_set_callback)(dip, callback, sock)

#define	GET_ADAPTER(f, dip, conf) (*(f)->pcif_get_adapter) (dip, conf)
#define	GET_SOCKET(f, dip, sock) (*(f)->pcif_get_socket)(dip, sock)
#define	GET_STATUS(f, dip, status) (*(f)->pcif_get_status)(dip, status)
#define	GET_WINDOW(f, dip, window) (*(f)->pcif_get_window)(dip, window)
#define	INQUIRE_ADAPTER(f, dip, inquire) (*(f)->pcif_inquire_adapter)(dip,\
						inquire)
#define	GET_CONFIG(f, dip, conf) INQUIRE_ADAPTER(f, dip, conf)
#define	INQUIRE_SOCKET(f, dip, sock) (*(f)->pcif_inquire_socket)(dip, \
						sock)
#define	GET_PAGE(f, dip, page) (*(f)->pcif_get_page)(dip, page)
#define	INQUIRE_WINDOW(f, dip, window) (*(f)->pcif_inquire_window)(dip, window)
#define	RESET_SOCKET(f, dip, socket, mode) \
			(*(f)->pcif_reset_socket)(dip, socket, mode)
#define	SET_PAGE(f, dip, page) (*(f)->pcif_set_page)(dip, page)
#define	SET_WINDOW(f, dip, window) (*(f)->pcif_set_window)(dip, window)
#define	SET_SOCKET(f, dip, socket) (*(f)->pcif_set_socket)(dip, socket)
#define	SET_IRQ(f, dip, handler) (*(f)->pcif_set_interrupt)(dip, handler)
#define	CLEAR_IRQ(f, dip, handler) (*(f)->pcif_clr_interrupt)(dip, handler)

typedef struct pcmcia_cs {
	uint32_t   pccs_magic;	/* magic number of verify correct structure */
	uint32_t   pccs_version;
	int   (*pccs_callback)();
	int   (*pccs_getconfig)();
} pcmcia_cs_t;

#define	PCCS_MAGIC	0x50434353
#define	PCCS_VERSION	_VERSION(2, 1)

/* properties used by the nexus for setup */
#define	ADAPT_PROP	"adapters"	/* property used to find adapter list */
#define	CS_PROP		"card-services"	/* property specifying Card Services */
#define	DEF_DRV_PROP	"default-driver" /* default driver to load if no CIS */

/*
 * per adapter structure
 * this structure defines everything necessary for the
 * the nexus to interact with the adapter specific driver
 */

struct pcmcia_adapter {
	int		pca_module;	/* adapter major number */
	int		pca_unit;	/* adapter minor number */
	int		pca_number;	/* canonical adapter number */
	struct dev_ops	*pca_ops;
	dev_info_t	*pca_dip;
	pcmcia_if_t	*pca_if;
	void		*pca_power;
	ddi_iblock_cookie_t *pca_iblock;
	ddi_idevice_cookie_t *pca_idev;
	kmutex_t	*pca_mutex;
	int		pca_numpower;
	int		pca_numsockets;
	int		pca_first_socket;
	uint32_t	pca_flags;
	char		pca_name[MODMAXNAMELEN];
	uint32_t	pca_avail_intr;
	inthandler_t	pca_int_handlers;
};

#define	PCA_RES_NEED_IRQ	0x0001 /* needs IRQ allocation */
#define	PCA_RES_NEED_IO		0x0002 /* needs I/O allocation */
#define	PCA_RES_NEED_MEM	0x0004 /* needs memory allocation */
#define	PCA_RES_CONSTRAINT	0x0008 /* resource constraints defined */
#define	PCA_IRQ_SMI_SHARE	0x0010 /* SMI and child share */
#define	PCA_IRQ_SHAREABLE	0x0020 /* all interrupts sharable */
#define	PCA_IRQ_ISA		0x0040 /* ISA style (host) interrupts */

/* These flags are for open/close -- hot-plug support in future */
#define	PCMCIA_MAX_FUNCTIONS	8
#define	PCS_CARD_PRESENT	0x0001 /* card in socket */
#define	PCS_MULTI_FUNCTION	0x0002 /* indicates dip is multifunction */
#define	PCS_SOCKET_ADDED	0x0004 /* CS knows about the socket */
#define	PCS_COOKIES_VALID	0x0008 /* iblk and idev valid */
#define	PCS_IRQ_ENABLED		0x0010 /* IRQ has been enabled */
#define	PCS_SUSPENDED		0x0020 /* PM SUSPEND was done */

typedef struct pcmcia_logical_window {
	int			lw_window; /* window number */
	int			lw_socket; /* logical socket number assigned */
	struct pcmcia_adapter	*lw_adapter;
	pcmcia_if_t		*lw_if;
	uint32_t		lw_status;
	baseaddr_t		lw_base;
	int			lw_len;
} pcmcia_logical_window_t;

#define	PCS_ENABLED		0x0002 /* window is enabled */

/*
 * management interface hook
 */
#define	EM_EVENTSIZE	4
struct pcmcia_mif {
	struct pcmcia_mif *mif_next;
	void		(*mif_function)();
	uint32_t	  mif_id;
	uchar_t		  mif_events[EM_EVENTSIZE]; /* events registered for */
};

#define	PR_WORDSIZE	8	/* bits in word */
#define	PR_MASK		0x7
#define	PR_GET(map, bit)	(((uchar_t *)(map))[(bit)/PR_WORDSIZE] &\
					(1 << ((bit) & PR_MASK)))
#define	PR_SET(map, bit)	(((uchar_t *)(map))[(bit)/PR_WORDSIZE] |=\
					(1 << ((bit) & PR_MASK)))
#define	PR_CLEAR(map, bit)	(((uchar_t *)(map))[(bit)/PR_WORDSIZE] &=\
					~(1 << ((bit) & PR_MASK)))
#define	PR_ADDR(map, bit)	(((uchar_t *)(map)) + ((bit)/PR_WORDSIZE))
#define	PR_ZERO(map)		\
	bzero((caddr_t)map, PCMCIA_MAX_SOCKETS / PR_WORDSIZE)

/* socket bit map */
typedef uchar_t socket_enum_t[PCMCIA_MAX_SOCKETS/PR_WORDSIZE];

/*
 * Max resoruce limits - all of these have to be power-of-2 aligned
 *	and the PR_MAX_IO_LEN and PR_MAX_MEM_LEN values must be at
 *	least 64 or the allocators will panic.
 */
#define	PR_MAX_IO_LEN		1024	/* bytes of IO space */
#define	PR_MAX_IO_RANGES	4
#define	PR_MAX_MEM_LEN		1024 /* pages or 4M bytes */
#define	PR_MAX_MEM_RANGES	32

#define	PR_MAX_IOADDR		0xffffffff
#define	PR_MAX_MEMADDR		0xffffffff
#define	PR_MAX_INTERRUPTS	0xff


/*
 * structures and definitions used in the private interface
 */

/* general values */
#define	PC_SUCCESS	1
#define	PC_FAILURE	0

/* set_mem() */
#define	PC_MEM_AM	0
#define	PC_MEM_CM	1

/* device classes */
#define	PCC_MULTI	0
#define	PCC_MEMORY	1
#define	PCC_SERIAL	2
#define	PCC_PARALLEL	3
#define	PCC_FIXED_DISK	4
#define	PCC_VIDEO	5
#define	PCC_LAN		6

/*
 * device information structure information
 * this is what is used for initial construction of a device node
 */

struct pcm_device_info {
	int		pd_socket;
	int		pd_function;
	int		pd_type;
	uint32_t	pd_handle;
	uint32_t	pd_tuples;
	uint32_t	pd_flags;
	char		pd_bind_name[MODMAXNAMELEN];
	char		pd_vers1_name[MODMAXNAMELEN*4];
	char		pd_generic_name[MODMAXNAMELEN];
};

#define	PCM_GET_SOCKET(socknum)		((socknum) & 0x1F)
#define	PCM_GET_FUNCTION(socknum)	(((socknum) >> 5) & 0x7)

#define	PCM_DEFAULT_NODEID		(-1)
#define	PCM_DEV_MODEL	"model"
#define	PCM_DEV_ACTIVE	"card-active"
#define	PCM_DEV_SOCKET	"socket"
#define	PCM_DEV_R2TYPE	"16bitcard"
#define	PCM_DEV_CARDBUS	"cardbus"

typedef
struct init_dev {
	int	socket;
} init_dev_t;

/*
 * device descriptions
 * used to determine what driver to associate with a PC Card
 * so that automatic creation of device information trees can
 * be supported.
 */

typedef
struct pcm_device_node {
	struct pcm_device_node *pd_next;
	dev_info_t *pd_dip;	/* proto device info */
	char	pd_name[16];
	int	pd_flags;
	int	pd_devtype;	/* from device tuple */
	int	pd_funcid;
	int	pd_manfid;
	int	pd_manmask;
} pcm_dev_node_t;

#define	PCMD_DEVTYPE	0x0001	/* match device type */
#define	PCMD_FUNCID	0x0002	/* match function ID */
#define	PCMD_MANFID	0x0004	/* match manufacturer ID */
#define	PCMD_FUNCE	0x0008	/* match function extension */
#define	PCMD_VERS1	0x0010	/* match VERSION_1 string(s) */
#define	PCMD_JEDEC	0x0020	/* JEDEC ID */

#define	PCM_NAME_1275		0x0001
#define	PCM_NAME_VERS1		0x0002
#define	PCM_NAME_GENERIC	0x0004
#define	PCM_NO_CONFIG		0x0008
#define	PCM_OTHER_NOCIS		0x0100
#define	PCM_MULTI_FUNCTION	0x0200

#define	PCM_MAX_R2_MEM		0x3ffffff

#define	PCMDEV_PREFIX	"PC,"
#define	PCMDEV_NAMEPREF "pccard"

/* property names */
#define	PCM_PROP_DEVICE	"device"
#define	PCM_PROP_FUNCID "funcid"

/* 1275 specific properties */
#define	PCM_1275_NUMWIN		"#windows"
#define	PCM_1275_NUMSOCK	"#sockets"
#define	PCM_1275_SCIC		"status-change-int_caps"

/* basic device types */

#define	PCM_TYPE_MULTI		0
#define	PCM_TYPE_MEMORY		1
#define	PCM_TYPE_SERIAL		2
#define	PCM_TYPE_PARALLEL	3
#define	PCM_TYPE_FIXED		4
#define	PCM_TYPE_VIDEO		5
#define	PCM_TYPE_LAN		6


typedef
struct string_to_int {
	char *sti_str;
	uint32_t sti_int;
} str_int_t;

/*
 * PCMCIA nexus/adapter specific ioctl commands
 */

#define	PCIOC	('P' << 8)
/* SS is temporary until design done */
#define	PC_SS_CMD(cmd)		(PCIOC|(cmd))

/* stuff that used to be in obpdefs.h but no longer */
#define	PCM_DEVICETYPE	"device_type"

/*
 * new regspec and other 1275 stuff
 */
#define	PC_REG_RELOC(x)		((((uint32_t)x) & 0x1) << 31)
#define	PC_REG_PREFETCH(x)	(((x) & 0x1) << 30)
#define	PC_REG_TYPE(x)		(((x) & 0x1) << 29)
#define	PC_REG_SPACE(x)		(((x) & 0x7) << 24)
#define	PC_REG_SOCKET(x)	(((x) & 0x1f) << 11)
#define	PC_REG_FUNCTION(x)	(((x) & 0x7) << 8)
#define	PC_REG_BASEREG(x)	((x) & 0xff)
/* solaris internal only */
#define	PC_REG_REFCNT(x)	(((x) & 0xFF) << 16)

#define	PC_GET_REG_RELOC(x)	(((x) >> 31) & 1)
#define	PC_GET_REG_PREFETCH(x)	(((x) >> 30) & 1)
#define	PC_GET_REG_TYPE(x)	(((x) >> 29) & 1)
#define	PC_GET_REG_SPACE(x)	(((x) >> 24) & 7)
#define	PC_GET_REG_SOCKET(x)	(((x) >> 11) & 0x1f)
#define	PC_GET_REG_FUNCTION(x)	(((x) >> 8) & 0x7)
#define	PC_GET_REG_BASEREG(x)	((x) & 0xff)
/* solaris internal only */
#define	PC_GET_REG_REFCNT(x)	(((x) >> 16) & 0xFF)
#define	PC_INCR_REFCNT(x)	(((x) & 0xFF00FFFF) | \
				    PC_REG_REFCNT(PC_GET_REG_REFCNT(x) + 1))
#define	PC_DECR_REFCNT(x)	(((x) & 0xFF00FFFF) | \
				    PC_REG_REFCNT(PC_GET_REG_REFCNT(x) - 1))

#define	PC_REG_PHYS_HI(n, p, t, c, s, f, r) (uint32_t)( \
			PC_REG_RELOC(n) | \
			PC_REG_PREFETCH(p) | \
			PC_REG_TYPE(t) | \
			PC_REG_SPACE(c) | \
			PC_REG_SOCKET(s) | \
			PC_REG_FUNCTION(f) | \
			PC_REG_BASEREG(r))

#define	PC_REG_TYPE_CARDBUS	0
#define	PC_REG_TYPE_16BIT	1

#define	PC_REG_SPACE_CONFIG	0x0
#define	PC_REG_SPACE_IO		0x1
#define	PC_REG_SPACE_MEMORY	0x2
#define	PC_REG_SPACE_ATTRIBUTE	0x4

/*
 * internal properties and other prop_op defines
 */

#define	PCMCIA_PROP_UNKNOWN	0x10000	/* pass to DDI decode */
#define	PCMCIA_PROP_CIS		0x20000	/* need to get the tuple */

	/* specific known properties */
#define	PCMCIA_PROP_SOCKET	0 /* "socket" */
#define	PCMCIA_PROP_COMPAT	1 /* "compatible" */
#define	PCMCIA_PROP_DEFAULT_PM	2 /* power managment timestamp */
#define	PCMCIA_PROP_ACTIVE	3 /* card-active property */
#define	PCMCIA_PROP_R2TYPE	4 /* 16 bit card */
#define	PCMCIA_PROP_CARDBUS	5 /* card is cardbus */
#define	PCMCIA_PROP_OLDCS	6 /* old card services property */
#define	PCMCIA_PROP_REG		7 /* standard reg= property */
#define	PCMCIA_PROP_INTR	8 /* interrupts property */

#ifdef	__cplusplus
}
#endif

#endif	/* _PCMCIA_H */
