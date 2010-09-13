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

#ifndef	_SYS_SBBCREG_H
#define	_SYS_SBBCREG_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Register definitions for SBBC, a PCI device.
 */
#define	SBBC_SC_MODE	0x00000020

typedef struct pad12 {
	uint32_t pad[3];
}pad12_t;

/*
 * SBBC registers.
 */
struct sbbc_regs_map {
	uint32_t devid;			/* 0x0.0000 All, device ID */
	pad12_t  pada;
	uint32_t devtemp;		/* 0x0.0010 All */
	pad12_t  padb;
	uint32_t incon_scratch;		/* 0x0.0020 All */
	pad12_t  padc;
	uint32_t incon_tstl1;		/* 0x0.0030 AR and SDC */
	pad12_t  padd;
	uint32_t incon_tsterr;		/* 0x0.0040 AR and SDC */
	pad12_t  pade;
	uint32_t device_conf;		/* 0x0.0050 All, device configuration */
	pad12_t  padf;
	uint32_t device_rstcntl;	/* 0x0.0060 SBBC,AR,dev reset control */
	pad12_t  padg;
	uint32_t device_rststat;	/* 0x0.0070 All, device reset status */
	pad12_t  padh;
	uint32_t device_errstat;	/* 0x0.0080 SBBC, device reset */
	pad12_t  padi;
	uint32_t device_errcntl;	/* 0x0.0090 SBBC,device error control */
	pad12_t  padj;
	uint32_t jtag_cntl;		/* 0x0.00a0 SBBC and SDC,JTAG control */
	pad12_t  padk;
	uint32_t jtag_cmd;		/* 0x0.00b0 SBBC and SDC,JTAG command */
	pad12_t  padl;
	uint32_t i2c_addrcmd;		/* 0x0.00c0 SBBC,I2C addr and command */
	pad12_t  padm;
	uint32_t i2c_data;		/* 0x0.00d0 SBBC, I2C data */
	pad12_t  padn;
	uint32_t pci_errstat;		/* 0x0.00e0 SBBC, PCI error status */
	pad12_t  pad2[45];
	uint32_t consbus_conf;		/* 0x0.0300 All */
	pad12_t  pado;
	uint32_t consbus_erraddr;	/* 0x0.0310 SBBC */
	pad12_t  padp;
	uint32_t consbus_errack;	/* 0x0.0320 SBBC */
	pad12_t  pad4[18];
	uint32_t pad5;
	uint32_t consbus_port0_err;	/* 0x0.0400 All */
	pad12_t  pad6[19];
	uint32_t pad7[2];
	uint32_t consbus_part_dom_err;	/* 0x0.04f0 SBBC and CBH */
	pad12_t  pad8[235];
	uint32_t pad8a[2];
	uint32_t sbbc_synch;		/* 0x0.1000 SBBC */
	pad12_t  padq[20];
	uint32_t padqa[3];
	uint32_t dev_access_tim0;	/* 0x0.1100 SBBC */
	pad12_t  padr;
	uint32_t dev_access_tim1;	/* 0x0.1110 SBBC */
	pad12_t  pads;
	uint32_t dev_access_tim2;	/* 0x0.1120 SBBC */
	pad12_t  padt;
	uint32_t dev_access_tim3;	/* 0x0.1130 SBBC */
	pad12_t  padu;
	uint32_t dev_access_tim4;	/* 0x0.1140 SBBC */
	pad12_t  padv;
	uint32_t dev_access_tim5;	/* 0x0.1150 SBBC */
	pad12_t  pad9[14];
	uint32_t pad9a[1];
	uint32_t spare_in_out;		/* 0x0.1200 SBBC */
	pad12_t  pad10[127];
	uint32_t pad10a[2];
	uint32_t monitor_cntl;		/* 0x0.1800 SBBC */
	pad12_t  pad11[170];
	uint32_t pad11a[1];
	uint32_t port_intr_gen0;	/* 0x0.2000 SBBC */
	pad12_t  padw;
	uint32_t port_intr_gen1;	/* 0x0.2010 SBBC */
	pad12_t  padx;
	uint32_t syscntlr_intr_gen;	/* 0x0.2020 SBBC */
	pad12_t  pad12[61];
	uint32_t sys_intr_status;	/* 0x0.2300 SBBC */
	pad12_t  pady;
	uint32_t sys_intr_enable;	/* 0x0.2310 SBBC */
	pad12_t  padz;
	uint32_t pci_intr_status;	/* 0x0.2320 SBBC */
	pad12_t  padaa;
	uint32_t pci_intr_enable;	/* 0x0.2330 SBBC */
	pad12_t  pad13[614];
	uint32_t pad13a[1];
	uint32_t pci_to_consbus_map;	/* 0x0.4000 SBBC */
	pad12_t  padab;
	uint32_t consbus_to_pci_map;	/* 0x0.4010 SBBC */
	uint32_t pad14[2247];
					/* 0x0.6330 SBBC */
};


/*
 * SSC DEV presence registers
 */
struct ssc_devpresence_regs_map {
	uint8_t devpres_reg0;
	uint8_t devpres_reg1;
	uint8_t devpres_reg2;
	uint8_t devpres_reg3;
	uint8_t devpres_reg4;
	uint8_t devpres_reg5;
	uint8_t devpres_reg6;
	uint8_t devpres_reg7;
	uint8_t devpres_reg8;
	uint8_t devpres_reg9;
	uint8_t devpres_rega;
	uint8_t devpres_regb;
};

/*
 * EChip
 * 0088.0000 - 0089.FFFF
 */
struct ssc_echip_regs {
	uint8_t offset[0x20000];
};

/*
 * Device Presence
 * 008A.0000 - 008B.FFFF
 */
struct ssc_devpresence_regs {
	uint8_t offset[0x20000];
};

/*
 * I2C Mux
 * 008C.0000 - 008D.FFFF
 */
struct ssc_i2cmux_regs {
	uint8_t offset[0x20000];
};

/*
 * Error Interrupts Status and Control
 * 008E.0000 - 008F.FFFF
 */
struct ssc_errintr_statcntl_regs {
	uint8_t offset[0x20000];
};

/*
 * Console Bus Window
 * 0400.0000 - 07FF.FFFF
 */
struct ssc_console_bus {
	uint8_t offset[0x4000000];
};

/*
 * SSC EILD registers
 */
struct ssc_eild_reg_map {
	uint8_t darb_intr;
	uint8_t darb_intr_mask;
	uint8_t sbbc_cons_err;
	uint8_t sbbc_cons_err_mask;
	uint8_t pwr_supply;
};

/*
 * PCI SBBC slave mapping
 */
struct pci_sbbc {
	uint8_t fprom[0x800000];	/* FPROM */
	struct sbbc_regs_map sbbc_internal_regs;	/* sbbc registers */
	uint8_t dontcare[0x79CD0];	/* reserved sbbc registers */
	struct ssc_echip_regs echip_regs;
	struct ssc_devpresence_regs devpres_regs;
	struct ssc_i2cmux_regs i2cmux_regs;
	struct ssc_errintr_statcntl_regs errintr_scntl_regs;
	uint8_t sram[0x100000];
	uint8_t reserved[0x3600000];
	struct ssc_console_bus consbus;
};


/*
 * SBBC registers.
 */
struct sbbc_common_devregs {
	uint32_t devid;			/* All, device ID */
	uint32_t devtemp;		/* All */
	uint32_t incon_scratch;		/* All */
	uint32_t incon_tstl1;		/* AR and SDC */
	uint32_t incon_tsterr;		/* AR and SDC */
	uint32_t device_conf;		/* All, device configuration */
	uint32_t device_rstcntl;	/* SBBC and AR, dev reset control */
	uint32_t device_rststat;	/* All, device reset status */
	uint32_t device_errstat;	/* SBBC, device reset */
	uint32_t device_errcntl;	/* SBBC, device error control */
	uint32_t jtag_cntl;		/* SBBC and SDC, JTAG control */
	uint32_t jtag_cmd;		/* SBBC and SDC, JTAG command */
	uint32_t i2c_addrcmd;		/* SBBC, I2C address and command */
	uint32_t i2c_data;		/* SBBC, I2C data */
	uint32_t pci_errstat;		/* SBBC, PCI error status */
	uint32_t domain_conf;		/* CBH */
	uint32_t safari_port0_conf;	/* AR and SDC */
	uint32_t safari_port1_conf;	/* AR and SDC */
	uint32_t safari_port2_conf;	/* AR and SDC */
	uint32_t safari_port3_conf;	/* AR and SDC */
	uint32_t safari_port4_conf;	/* AR and SDC */
	uint32_t safari_port5_conf;	/* AR and SDC */
	uint32_t safari_port6_conf;	/* AR and SDC */
	uint32_t safari_port7_conf;	/* AR and SDC */
	uint32_t safari_port8_conf;	/* AR and SDC */
	uint32_t safari_port9_conf;	/* AR and SDC */
	uint32_t safari_port0_err;	/* AR and SDC */
	uint32_t safari_port1_err;	/* AR and SDC */
	uint32_t safari_port2_err;	/* AR and SDC */
	uint32_t safari_port3_err;	/* AR and SDC */
	uint32_t safari_port4_err;	/* AR and SDC */
	uint32_t safari_port5_err;	/* AR and SDC */
	uint32_t safari_port6_err;	/* AR and SDC */
	uint32_t safari_port7_err;	/* AR and SDC */
	uint32_t safari_port8_err;	/* AR and SDC */
	uint32_t safari_port9_err;	/* AR and SDC */
	uint32_t consbus_conf;		/* All */
	uint32_t consbus_erraddr;	/* SBBC */
	uint32_t consbus_errack;	/* SBBC */
	uint32_t consbus_errinj0;	/* CBH */
	uint32_t consbus_errinj1;	/* CBH */
	uint32_t consbus_port0_err;	/* All */
	uint32_t consbus_port1_err;	/* SDC and CBH */
	uint32_t consbus_port2_err;	/* SDC and CBH */
	uint32_t consbus_port3_err;	/* SDC and CBH */
	uint32_t consbus_port4_err;	/* SDC and CBH */
	uint32_t consbus_port5_err;	/* CBH */
	uint32_t consbus_port6_err;	/* CBH */
	uint32_t consbus_port7_err;	/* CBH */
	uint32_t consbus_port8_err;	/* CBH */
	uint32_t consbus_port9_err;	/* CBH */
	uint32_t consbus_porta_err;	/* CBH */
	uint32_t consbus_portb_err;	/* CBH */
	uint32_t consbus_portc_err;	/* CBH */
	uint32_t consbus_portd_err;	/* CBH */
	uint32_t consbus_porte_err;	/* CBH */
	uint32_t consbus_part_dom_err;	/* SBBC and CBH */
	uint32_t sbbc_synch;		/* SBBC */
	uint32_t dev_access_tim0;	/* SBBC */
	uint32_t dev_access_tim1;	/* SBBC */
	uint32_t dev_access_tim2;	/* SBBC */
	uint32_t dev_access_tim3;	/* SBBC */
	uint32_t dev_access_tim4;	/* SBBC */
	uint32_t dev_access_tim5;	/* SBBC */
	uint32_t spare_in_out;		/* SBBC */
	uint32_t monitor_cntl;		/* SBBC */
	uint32_t port_intr_gen0;	/* SBBC */
	uint32_t port_intr_gen1;	/* SBBC */
	uint32_t syscntlr_intr_gen;	/* SBBC */
	uint32_t sys_intr_status;	/* SBBC */
	uint32_t sys_intr_enable;	/* SBBC */
	uint32_t pci_intr_status;	/* SBBC */
	uint32_t pci_intr_enable;	/* SBBC */
	uint32_t pci_to_consbus_map;	/* SBBC */
	uint32_t consbus_to_pci_map;	/* SBBC */
	uint32_t scm_consbus_addrmap;	/* CBH */
	uint32_t ar_slot0_trans_cnt;	/* AR */
	uint32_t ar_slot1_trans_cnt;	/* AR */
	uint32_t ar_slot2_trans_cnt;	/* AR */
	uint32_t ar_slot3_trans_cnt;	/* AR */
	uint32_t ar_slot4_trans_cnt;	/* AR */
	uint32_t ar_slot5_trans_cnt;	/* AR */
	uint32_t ar_slot6_trans_cnt;	/* AR */
	uint32_t ar_slot7_trans_cnt;	/* AR */
	uint32_t ar_slot8_trans_cnt;	/* AR */
	uint32_t ar_slot9_trans_cnt;	/* AR */
	uint32_t ar_trans_cnt_oflow;	/* AR */
	uint32_t ar_trans_cnt_uflow;	/* AR */
	uint32_t ar_l1l1_conf;		/* AR */
	uint32_t lock_step_err;		/* AR and SDC */
	uint32_t l2_check_err;		/* AR and SDC */
	uint32_t incon_tstl1_slave;	/* AR */
	uint32_t incon_tstl2_slave;	/* AR and SDC */
	uint32_t ecc_status;		/* SDC */
	uint32_t event_counter0;	/* SDC */
	uint32_t event_counter1;	/* SDC */
	uint32_t event_counter2;	/* SDC */
	uint32_t monitor_counter_cntl;	/* AR and SDC */
	uint32_t ar_transid_match;	/* AR */
};


#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_SBBCREG_H */
