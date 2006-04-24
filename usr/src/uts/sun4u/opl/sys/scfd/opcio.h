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
 * All Rights Reserved, Copyright (c) FUJITSU LIMITED 2006
 */

#ifndef	_SYS_OPCIO_H
#define	_SYS_OPCIO_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/ioccom.h>

/*
 * ioctl
 */
#define	SCFIOC			'p'<<8

/*
 * ioctl
 */
#define	SCFIOCCLEARLCD		(SCFIOC|10|0x80040000)
#define	SCFIOCWRLCD		(SCFIOC|11|0x800c0000)
#define	SCFIOCREPORTSTAT	(SCFIOC|22|0x80040000)
#define	SCFIOCHAC		(SCFIOC|28|0x80810000)
#define	SCFIOCRDCLIST		(SCFIOC|37|0xc00c0000)
#define	SCFIOCHSTADRSINFO	(SCFIOC|41|0x40040000)
#define	SCFIOCAUTOPWRSET	(SCFIOC|42|0x80f40000)
#define	SCFIOCAUTOPWRGET	(SCFIOC|43|0x40f40000)
#define	SCFIOCAUTOPWREXSET	(SCFIOC|44|0x80100000)
#define	SCFIOCAUTOPWREXGET	(SCFIOC|45|0x40100000)
#define	SCFIOCAUTOPWRFPOFF	(SCFIOC|46|0x80f40000)
#define	SCFIOCRCIPWR		(SCFIOC|48|0xc0080000)
#define	SCFIOCGETREPORT		(SCFIOC|49|0x40100000)
#define	SCFIOCRDCLISTMAX	(SCFIOC|50|0x40040000)
#define	SCFIOCRDCLISTX		(SCFIOC|51|0x800c0000)
#define	SCFIOCRDCTRL		(SCFIOC|52|0xc0820000)
#define	SCFIOCPANICREQ		(SCFIOC|53|0x80040000)
#define	SCFIOCSYSAUTOPWRGET	(SCFIOC|60|0x20000000)
#define	SCFIOCOPECALL		(SCFIOC|62|0x20000000)
#define	SCFIOCSYSAUTOPWRCLR	(SCFIOC|66|0x20000000)
#define	SCFIOCPANICCHK		(SCFIOC|67|0x80040000)
#define	SCFIOCDR		(SCFIOC|68|0x80040000)
#define	SCFIOCEVENTLIST		(SCFIOC|70|0x80040000)
#define	SCFIOCGETEVENT		(SCFIOC|71|0x80040000)
#define	SCFIOCOPTIONDISP	(SCFIOC|80|0x80040000)
#define	SCFIOCPARMSET		(SCFIOC|82|0x80040000)
#define	SCFIOCPARMGET		(SCFIOC|83|0x80040000)

#define	SCFIOCGETDISKLED	(SCFIOC|101|0x80040000)
#define	SCFIOCSETDISKLED	(SCFIOC|102|0x80040000)
#define	SCFIOCGETSDOWNREASON	(SCFIOC|103|0x80040000)
#define	SCFIOCGETPCICONFIG	(SCFIOC|104|0x80040000)
#define	SCFIOCSETMADMEVENT	(SCFIOC|105|0x80040000)
#define	SCFIOCREMCSCMD		(SCFIOC|106|0x80040000)
#define	SCFIOCSPARECMD		(SCFIOC|107|0x80040000)
#define	SCFIOCREMCSFILE		(SCFIOC|108|0x80040000)

#define	SCFIOCSETPHPINFO	(SCFIOC|1|0xe0000000)

/* SCFIOCOPECALL */
#define	SUB_OPECALL_DISP	0x10	/* OP call disp */
#define	SUB_OPECALL_ON_SET	0x20	/* OP call ON set */
#define	SUB_OPECALL_OFF_SET	0x31	/* OP call OFF set */

/* SCFIOCCLEARLCD */
#define	SCF_CLRLCD_SEQ		0

/* SCFIOCWRLCD */
typedef struct scfwrlcd {
	int		lcd_type;
	int		length;
	unsigned char	*string;
} scfwrlcd_t;
/* for lcd_type field */
#define	SCF_WRLCD_SEQ		0

#define	SCF_WRLCD_MAX		32

/* SCFIOCREPORTSTAT */
#define	SCF_SHUTDOWN_START	0
#define	SCF_SYSTEM_RUNNING	1
#define	SCF_RE_REPORT		9

/* SCFIOCHAC */
typedef struct scfhac {
	unsigned char	sbuf[64];
	unsigned char	rbuf[64];
	unsigned char	sub_command;
} scfhac_t;
/* for sub_command field */
#define	SUB_HOSTADDR_DISP	0x00	/* Host address disp */
#define	SUB_REMOTE_POWCTL_SET	0x11	/* Remote power control set */
#define	SCF_SUB_REMOTE_POWCTL_SET	0x10
#define	SUB_DEVICE_INFO		0x0c	/* Device information disp */

/* SCFIOCAUTOPWRSET, SCFIOCAUTOPWRGET, SCFIOCAUTOPWRFPOFF */
typedef struct scfautopwrtime {
	int		pon_year;	/* 1970 - 9999 */
	int		pon_month;	/* 1 - 12 */
	int		pon_date;	/* 1 - 31 */
	int		pon_hour;	/* 0 - 23 */
	int		pon_minute;	/* 0 - 59 */
	int		poff_year;	/* 1970 - 9999 */
	int		poff_month;	/* 1 - 12 */
	int		poff_date;	/* 1 - 31 */
	int		poff_hour;	/* 0 - 23 */
	int		poff_minute;	/* 0 - 59 */
	int		flag;
	int		sarea;
} scfautopwrtime_t;

typedef struct scfautopwr {
	int		valid_entries;
	struct		scfautopwrtime	ptime[5];
} scfautopwr_t;

/* SCFIOCAUTOPWREXSET, SCFIOCAUTOPWREXGET */
typedef struct scfautopwrex {
	int		rpwr_mode;
	int		rpwr_time;	/* minutes */
	int		w_time;		/* minutes */
	int		a_time;		/* minutes */
} scfautopwrex_t;
/* for rpwr_mode field */
#define	AUTOPWREX_RESTORE	0x00
#define	AUTOPWREX_NOPON		0x01
#define	AUTOPWREX_AUTOPON	0x80

/* SCFIOCRCIPWR */
typedef struct scfrcipwr {
	int		sub_cmd;
	unsigned int	rci_addr;
} scfrcipwr_t;
/* for sub_cmd field */
#define	RCI_PWR_ON		0x80
#define	RCI_PWR_OFF		0x40
#define	RCI_SYS_RESET		0x20
#define	RCI_PFCTR		0x00
#define	RCI_PWR_NOR_OFF		0x41

/* SCFIOCGETREPORT */
typedef struct scfreport {
	int		flag;
	unsigned int	rci_addr;
	unsigned char	report_sense[4];
	time_t		timestamp;
} scfreport_t;
/* for flag field */
#define	GETREPORT_WAIT			1
#define	GETREPORT_NOWAIT		2
#define	GETREPORT_WAIT_AND_RCIDWN	3

/* SCFIOCRDCLISTX */
typedef struct scfrdclistx {
	unsigned int	rci_addr;
	unsigned char	status;
	unsigned short	dev_class;
	unsigned char	sub_class;
} scfrdclistx_t;

/* SCFIOCRDCTRL */
typedef struct scfrdctrl {
	unsigned char	sub_cmd;
	unsigned char	scount;
	unsigned char	sbuf[64];
	unsigned char	sense[64];
} scfrdctrl_t;
/* for sub_cmd field */
#define	SUB_DEVICE_STATUS_RPT	0x14	/* Device status print */
#define	SCF_SUB_DEVICE_STATUS_RPT	0x71
#define	SCF_RCI_PATH_40		0x50	/* RCI device request */

/* SCFIOCDR */
typedef struct scfdr {
	unsigned char	sbuf[16];
	unsigned char	rbuf[16 * 64];
	unsigned char	sub_command;
} scfdr_t;
/* for sub_command field */
#define	SUB_SB_CONF_CHG		0x11	/* SB configuration change */
#define	SUB_SB_SENSE		0x00	/* SB status disp */
#define	SUB_SB_SENSE_ALL	0x18	/* SB status all disp */
#define	SUB_SB_BUILD_COMP	0x12	/* SB build completion */

/* SCFIOCEVENTLIST */
#define	SCF_EVENTLIST_MAX	128
typedef struct scfeventlist {
	int		listcnt;
	unsigned char	codelist[SCF_EVENTLIST_MAX];
} scfeventlist_t;

/* SCFIOCGETEVENT */
typedef struct scfevent {
	int		flag;
	unsigned int	rci_addr;
	unsigned char	code;
	unsigned char	size;
	unsigned char	rsv[2];
	unsigned char	event_sense[24];
	time_t		timestamp;
} scfevent_t;
/* for flag field */
#define	GETEVENT_WAIT		1
#define	GETEVENT_NOWAIT		2

/* SCFIOCOPTIONDISP */
typedef struct scfoption {
	unsigned char	rbuf[16];
} scfoption_t;

/* SCFIOCPARMSET, SCFIOCPARMGET */
typedef struct scfparam {
	int		parm;
	int		value;
} scfparam_t;
/* for parm field */
#define	SCF_PARM_RDCTRL_TIMER	0x00000001

/* SCFIOCGETDISKLED/SCFIOCSETDISKLED */
#define	SCF_DISK_LED_PATH_MAX	512
typedef struct scfiocgetdiskled {
	unsigned char	path[SCF_DISK_LED_PATH_MAX];
	unsigned char	led;
} scfiocgetdiskled_t;
/* for led field */
#define	SCF_DISK_LED_ON		0x01
#define	SCF_DISK_LED_BLINK	0x02
#define	SCF_DISK_LED_OFF	0x04

/* SCFIOCGETSDOWNREASON */
#define	REASON_NOTHING		0x00000000	/* reason nothing */
#define	REASON_SHUTDOWN_FAN	0x00000001	/* Fan unit failure */
#define	REASON_SHUTDOWN_PSU	0x00000002	/* Power unit failure */
#define	REASON_SHUTDOWN_THERMAL	0x00000006	/* Thermal failure */
#define	REASON_SHUTDOWN_UPS	0x00000007	/* UPS failure */
#define	REASON_RCIPOFF		0x00000100	/* RCI POFF */
#define	REASON_XSCFPOFF		0x00000103	/* XSCF POFF */
#define	REASON_SHUTDOWN_HALT	0xffffffff	/* SCF HALT */

/* SCFIOCGETPCICONFIG */
typedef struct scfiocgetpciconfig {
	unsigned char	sbuf[16];
	unsigned char	rbuf[65536];
} scfiocgetpciconfig_t;

/* SCFIOCSETMADMEVENT */
typedef struct scfiocsetmadmevent {
	unsigned char	buf[65536];
	unsigned int	size;
} scfiocsetmadmevent_t;

/* SCFIOCREMCSCMD */
typedef struct scfiocremcscmd {
	unsigned char	buf[16];
	unsigned int	size;
	unsigned char	sub_command;
} scfiocremcscmd_t;
/* for sub_command field */
#define	SUB_CMD_EX_REMCS	0x01

/* SCFIOCREMCSFILE */
typedef struct scfiocremcsfile {
	unsigned char	buf[65536];
	unsigned int	size;
	unsigned char	sub_command;
} scfiocremcsfile_t;
/* for sub_command field */
#define	SUB_FILEUP_READY	0x10
#define	SUB_FILEUP_SET		0x20
#define	SUB_TRANSFER_STOP	0x40

/* SCFIOCSPARECMD */
typedef struct scfiocsparecmd {
	unsigned char	buf[65536];
	unsigned int	size;
	unsigned char	command;
	unsigned char	sub_command;
	unsigned char	spare_sub_command;
} scfiocsparecmd_t;
/* for sub_command field */
#define	SUB_SPARE_SS		0x00	/* Type SS */
#define	SUB_SPARE_SL		0x11	/* Type SL */
#define	SUB_SPARE_LS		0x12	/* Type LS */

/* SCFIOCSETPHPINFO */
typedef struct scfsetphpinfo {
	unsigned char	buf[65536];
	unsigned int	size;
} scfsetphpinfo_t;

#ifdef	__cplusplus
}
#endif

#endif /* _SYS_OPCIO_H */
