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
 * PHOTON CONFIGURATION MANAGER
 * Common definitions
 */

/*
 * I18N message number ranges
 *  This file: 12500 - 12999
 *  Shared common messages: 1 - 1999
 */

#ifndef	_COMMON_H
#define	_COMMON_H




/*
 * Include any headers you depend on.
 */
#include <sys/types.h>
#include <sys/scsi/adapters/scsi_vhci.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*#ifdef _BIG_ENDIAN
#define	htonll(x)   (x)
#define	ntohll(x)   (x)
#else
#define	htonll(x)   ((((unsigned long long)htonl(x)) << 32) + htonl(x >> 32))
#define	ntohll(x)   ((((unsigned long long)ntohl(x)) << 32) + ntohl(x >> 32))
#endif*/


extern	char	*p_error_msg_ptr;

#ifdef __x86
#include <nl_types.h>
extern nl_catd l_catd;
#define	L_SET1			1   /* catalog set number */
#define	MSGSTR(Num, Str)	catgets(l_catd, L_SET1, Num, Str)
#endif


/* Defines */
#define	USEAGE()	{(void) fprintf(stderr,  MSGSTR(12500, \
			"Usage: %s [-v] subcommand [option...]" \
			" {enclosure[,dev]... | pathname...}\n"), \
			whoami); \
			(void) fflush(stderr); }

#define	E_USEAGE()	{(void) fprintf(stderr,  MSGSTR(12501, \
			"Usage: %s [-v] -e subcommand [option...]" \
			" {enclosure[,dev]... | pathname...}\n"), \
			whoami); \
			(void) fflush(stderr); }

#define	VERBPRINT	 if (Options & PVERBOSE) (void) printf

#define	L_ERR_PRINT	\
			if (p_error_msg_ptr == NULL) {  \
				perror(MSGSTR(12502, "Error"));	 \
			} else {	\
	(void) fprintf(stderr, MSGSTR(12503, "Error: %s"), p_error_msg_ptr); \
			} \
			p_error_msg_ptr = NULL;

#define	P_ERR_PRINT	 if (p_error_msg_ptr == NULL) {  \
					perror(whoami);	 \
			} else {	\
	(void) fprintf(stderr, MSGSTR(12504, "Error: %s"), p_error_msg_ptr); \
			} \
			p_error_msg_ptr = NULL;


/* Display extended mode page information. */
#ifndef	MODEPAGE_CACHING
#undef	MODEPAGE_CACHING
#define	MODEPAGE_CACHING	0x08
#endif


/* Primary commands */
#define	ENCLOSURE_NAMES 100
#define	DISPLAY	 101
#define	DOWNLOAD	102
#define	FAST_WRITE	400	 /* SSA */
#define	FAILOVER	500
#define	FC_UPDATE	401	 /* SSA */
#define	FCAL_UPDATE	103	 /* Update the Fcode on Sbus soc card */
#define	FCODE_UPDATE	117	 /* Update the Fcode on all cards */
#define	QLGC_UPDATE	116	 /* Update the Fcode on PCI card(s) */
#define	INQUIRY		105
#define	LED		107
#define	LED_ON		108
#define	LED_OFF		109
#define	LED_BLINK	110
#define	NVRAM_DATA	402	 /* SSA */
#define	POWER_OFF	403	 /* SSA */
#define	POWER_ON	111
#define	PASSWORD	112
#define	PURGE		404	 /* SSA */
#define	PERF_STATISTICS 405	 /* SSA */
#define	PROBE		113
#define	RELEASE		210
#define	RESERVE		211
#define	START		213
#define	STOP		214
#define	SYNC_CACHE	406	 /* SSA */
#define	SET_BOOT_DEV	115	 /* Set the boot-device variable in nvram */
#define	INSERT_DEVICE	106	/* Hot plug */
#define	REMOVE_DEVICE	114	/* hot plug */

/* Device hotplugging */
#define	REPLACE_DEVICE	150
#define	DEV_ONLINE	155
#define	DEV_OFFLINE	156
#define	DEV_GETSTATE	157
#define	DEV_RESET	158
#define	BUS_QUIESCE	160
#define	BUS_UNQUIESCE	161
#define	BUS_GETSTATE	162
#define	BUS_RESET	163
#define	BUS_RESETALL	164

#define	SKIP		111
#define	QUIT		222

#define	L_LED_STATUS	0x00
#define	L_LED_RQST_IDENTIFY	0x01
#define	L_LED_ON	0x02
#define	L_LED_OFF	0x04


/* Enclosure Specific */
#define	ALARM		407	 /* SSA */
#define	ALARM_OFF	408	 /* SSA */
#define	ALARM_ON	409	 /* SSA */
#define	ALARM_SET	410	 /* SSA */
#define	ENV_DISPLAY	411	 /* SSA */

/* Expert commands */
#define	RDLS		215
#define	P_BYPASS	218
#define	P_ENABLE	219
#define	BYPASS		220
#define	ENABLE		221
#define	FORCELIP	222
#define	LUX_P_OFFLINE	223
#define	LUX_P_ONLINE	224
#define	EXT_LOOPBACK	225
#define	INT_LOOPBACK	226
#define	NO_LOOPBACK	227
#define	CREATE_FAB	228

/* Undocumented commands */
#define	DUMP		300
#define	CHECK_FILE	301	/* Undocumented - Check download file */
#define	DUMP_MAP	302	/* Dump map of loop */
#define	VERSION		303	/* undocumented */
#define	AU		304	/* undocumented */
#define	PORT		305	/* undocumented */

/* Undocumented diagnostic subcommands */
#define	SYSDUMP	 350


/* SSA - for adm_download */
/* #define	SSAFIRMWARE_FILE	"/usr/lib/firmware/ssa/ssafirmware" */

/*	Global variables	*/
extern char	*whoami;
extern int	Options;
extern const	int OPTION_A;
extern const	int OPTION_B;
extern const	int OPTION_C;
extern const	int OPTION_D;
extern const	int OPTION_E;
extern const	int OPTION_F;
extern const	int OPTION_L;
extern const	int OPTION_P;
extern const	int OPTION_R;
extern const	int OPTION_T;
extern const	int OPTION_V;
extern const	int OPTION_Z;
extern const	int OPTION_Y;
extern const	int OPTION_CAPF;
extern const	int PVERBOSE;
extern const	int SAVE;
extern const	int EXPERT;

#define		TARGET_ID(box_id, f_r, slot)	\
		((box_id | ((f_r == 'f' ? 0 : 1) << 4)) | (slot + 2))

#define		NEWER(time1, time2) 	(time1.tv_sec > time2.tv_sec)

/* used to set the behavior of get_slash_devices_from_osDevName. */
#define		STANDARD_DEVNAME_HANDLING	1
#define		NOT_IGNORE_DANGLING_LINK	2

#include <hbaapi.h>
#ifndef __x86
#include <sys/scsi/generic/mode.h>
#include <sys/scsi/generic/sense.h>
#include <sys/scsi/impl/uscsi.h>
#include <g_state.h>
#include <stgcom.h>
#include <l_common.h>
#else
typedef struct l_inquiry_inq_2 {
#if defined(_BIT_FIELDS_HTOL)
	uchar_t inq_2_reladdr	: 1,	/* relative addressing */
		inq_wbus32	: 1,	/* 32 bit wide data xfers */
		inq_wbus16	: 1,	/* 16 bit wide data xfers */
		inq_sync	: 1,	/* synchronous data xfers */
		inq_linked	: 1,	/* linked commands */
		inq_res1	: 1,	/* reserved */
		inq_cmdque	: 1,	/* command queueing */
		inq_sftre	: 1;	/* Soft Reset option */
#else
	uchar_t inq_sftre	: 1,	/* Soft Reset option */
		inq_cmdque	: 1,	/* command queueing */
		inq_res1	: 1,	/* reserved */
		inq_linked	: 1,	/* linked commands */
		inq_sync	: 1,	/* synchronous data xfers */
		inq_wbus16	: 1,	/* 16 bit wide data xfers */
		inq_wbus32	: 1,	/* 32 bit wide data xfers */
		inq_2_reladdr	: 1;	/* relative addressing */
#endif /* _BIT_FIELDS_HTOL */
} L_inq_2;

typedef struct l_inquiry_inq_3 {
#if defined(_BIT_FIELDS_HTOL)
	uchar_t inq_3_reladdr	: 1,	/* relative addressing */
		inq_SIP_2	: 3,	/* Interlocked Protocol */
		inq_3_linked	: 1,	/* linked commands */
		inq_trandis	: 1,	/* Transfer Disable */
		inq_3_cmdque	: 1,	/* command queueing */
		inq_SIP_3	: 1;	/* Interlocked Protocol */
#else
	uchar_t inq_SIP_3	: 1,	/* Interlocked Protocol */
		inq_3_cmdque	: 1,	/* command queueing */
		inq_trandis	: 1,	/* Transfer Disable */
		inq_3_linked	: 1,	/* linked commands */
		inq_SIP_2	: 3,	/* Interlocked Protocol */
		inq_3_reladdr	: 1;	/* relative addressing */
#endif /* _BIT_FIELDS_HTOL */
} L_inq_3;

typedef struct l_inquiry_struct {
	/*
	 * byte 0
	 *
	 * Bits 7-5 are the Peripheral Device Qualifier
	 * Bits 4-0 are the Peripheral Device Type
	 *
	 */
	uchar_t	inq_dtype;
	/* byte 1 */
#if defined(_BIT_FIELDS_HTOL)
	uchar_t	inq_rmb		: 1,	/* removable media */
		inq_qual	: 7;	/* device type qualifier */
#else
	uchar_t	inq_qual	: 7,	/* device type qualifier */
		inq_rmb		: 1; 	/* removable media */
#endif /* _BIT_FIELDS_HTOL */

	/* byte 2 */
#if defined(_BIT_FIELDS_HTOL)
	uchar_t	inq_iso		: 2,	/* ISO version */
		inq_ecma	: 3,	/* ECMA version */
		inq_ansi	: 3;	/* ANSI version */
#else
	uchar_t	inq_ansi	: 3,	/* ANSI version */
		inq_ecma	: 3,	/* ECMA version */
		inq_iso		: 2;	/* ISO version */
#endif /* _BIT_FIELDS_HTOL */

	/* byte 3 */
#define	inq_aerc inq_aenc	/* SCSI-3 */
#if defined(_BIT_FIELDS_HTOL)
	uchar_t	inq_aenc	: 1,	/* async event notification cap. */
		inq_trmiop	: 1,	/* supports TERMINATE I/O PROC msg */
		inq_normaca	: 1,	/* Normal ACA Supported */
				: 1,	/* reserved */
		inq_rdf		: 4;	/* response data format */
#else
	uchar_t	inq_rdf		: 4,	/* response data format */
				: 1,	/* reserved */
		inq_normaca	: 1,	/* Normal ACA Supported */
		inq_trmiop	: 1,	/* supports TERMINATE I/O PROC msg */
		inq_aenc	: 1;	/* async event notification cap. */
#endif /* _BIT_FIELDS_HTOL */

	/* bytes 4-7 */
	uchar_t	inq_len;		/* additional length */
	uchar_t			: 8;	/* reserved */
#if defined(_BIT_FIELDS_HTOL)
	uchar_t			: 2,	/* reserved */
		inq_port	: 1,	/* Only defined when dual_p set */
		inq_dual_p	: 1,	/* Dual Port */
		inq_mchngr	: 1,	/* Medium Changer */
		inq_SIP_1	: 3;	/* Interlocked Protocol */
#else
	uchar_t	inq_SIP_1	: 3,	/* Interlocked Protocol */
		inq_mchngr	: 1,	/* Medium Changer */
		inq_dual_p	: 1,	/* Dual Port */
		inq_port	: 1,	/* Only defined when dual_p set */
				: 2;	/* reserved */
#endif /* _BIT_FIELDS_HTOL */

	union {
		L_inq_2 inq_2;
		L_inq_3 inq_3;
	} ui;


	/* bytes 8-35 */

	uchar_t	inq_vid[8];		/* vendor ID */

	uchar_t	inq_pid[16];		/* product ID */

	uchar_t	inq_revision[4];	/* product revision level */

	/*
	 * Bytes 36-55 are vendor-specific parameter bytes
	 */

	/* SSA specific definitions */
	/* bytes 36 - 39 */
#define	inq_ven_specific_1 inq_firmware_rev
	uchar_t	inq_firmware_rev[4];	/* firmware revision level */

	/* bytes 40 - 51 */
	uchar_t	inq_serial[12];		/* serial number, not used any more */

	/* bytes 52-53 */
	uchar_t	inq_res2[2];

	/* byte 54, 55 */
	uchar_t	inq_ssa_ports;		/* number of ports */
	uchar_t	inq_ssa_tgts;		/* number of targets */

	/*
	 * Bytes 56-95 are reserved.
	 */
	uchar_t	inq_res3[40];
	/*
	 * 96 to 'n' are vendor-specific parameter bytes
	 */
	uchar_t	inq_box_name[32];
	uchar_t	inq_avu[256];
} L_inquiry;
#define	HEX_ONLY	0	/* Print Hex only */
#define	HEX_ASCII	1	/* Print Hex and Ascii */
#define	WWN_SIZE	8	/* # of bytes to dump per line */

/* NOTE: These command op codes are not defined in commands.h */
#define	SCMD_SYNC_CACHE		    0x35
#define	SCMD_LOG_SENSE		    0x4d
#define	SCMD_PERS_RESERV_IN	    0x5e
#define	SCMD_PERS_RESERV_OUT	    0x5f

typedef struct rls_payload {
	uint_t  rls_portno;
	uint_t  rls_linkfail;
	uint_t  rls_syncfail;
	uint_t  rls_sigfail;
	uint_t  rls_primitiverr;
	uint_t  rls_invalidword;
	uint_t  rls_invalidcrc;
} rls_payload_t;

typedef struct l_inquiry00_struct {
#if defined(_BIT_FIELDS_LTOH)
uchar_t		qual    :3,
		dtype   :5;
#else
uchar_t		dtype	:5,
		qual	:3;
#endif	/* _BIT_FIELDS_LTOH */
uchar_t		page_code;
uchar_t		reserved;
uchar_t		len;
uchar_t		page_list[251];
} L_inquiry00;

#define	MIN(a, b) (a < b ? a : b)
#define	ER_DPRINTF	if (getenv("_LUX_ER_DEBUG") != NULL) (void) printf
#define	O_DPRINTF	if (getenv("_LUX_O_DEBUG") != NULL) (void) printf
#define	P_DPRINTF	if (getenv("_LUX_P_DEBUG") != NULL) (void) printf
#define	R_DPRINTF	if (getenv("_LUX_R_DEBUG") != NULL) (void) printf
#define	I_DPRINTF	if (getenv("_LUX_I_DEBUG") != NULL) (void) printf
#define	S_DPRINTF	if (getenv("_LUX_S_DEBUG") != NULL) (void) printf
#define	RETRY_FCIO_IOCTL    360
#define	WAIT_FCIO_IOCTL	    250000 /* 1/4 of a second */

#endif /* __x86 */


int adm_display_config(char **argv);
void adm_download(char **argv, char *file_name);
void up_encl_name(char **argv, int argc);
void adm_failover(char **argv);
void pho_probe();
void non_encl_probe();
void adm_led(char **argv, int led_action);
void up_password(char **argv);
int adm_start(char **argv);
int adm_stop(char **argv);
int adm_power_off(char **argv, int off_flag);
int adm_forcelip(char **argv);
void adm_bypass_enable(char **argv, int bypass_flag);
int adm_port_offline_online(char *argv[], int flag);
void display_link_status(char **argv);
int read_repos_file(char *repos_filename);
int adm_check_file(char **argv, int flag);
void dump(char **argv);
void dump_map(char **argv);
int adm_port_loopback(char *portpath, int flag);
int adm_inquiry(char **argv);
int adm_display_port(int verbose);

int adm_reserve(char *path);
int adm_release(char *path);
void i18n_catopen();
void dump_hex_data(char *, uchar_t *, int, int);
void print_errString(int, char *);
void	print_chars(uchar_t *, int, int);
void	print_inq_data(char *, char *, L_inquiry, uchar_t *, size_t);
void print_fabric_dtype_prop(uchar_t *hba_port_wwn, uchar_t *port_wwn,
	uchar_t dtype_prop);
void print_private_loop_dtype_prop(uchar_t *hba_port_wwn, uchar_t *port_wwn,
	uchar_t dtype_prop);
char *get_errString(int errornum);
int cmp_raw_wwn(uchar_t *wwn_1, uchar_t *wwn_2);

/* routines in fchba*.c files */
int fchba_display_port(int verbose);
int fchba_display_config(char **argv, int option_t_input, int argc);
char *get_slash_devices_from_osDevName(char *osDevName, int flag);
int get_scsi_vhci_pathinfo(char *dev_path, sv_iocdata_t *ioc,
		int *path_count);
int get_mode_page(char *path, uchar_t **pg_buf);
int scsi_mode_sense_cmd(int fd, uchar_t *buf_ptr, int buf_len, uchar_t pc,
	uchar_t page_code);
int scsi_release(char *path);
int scsi_reserve(char *path);
int is_path(char *arg);
int is_wwn(char *arg);
int loadLibrary();
uint32_t getNumberOfAdapters();
int getAdapterAttrs(HBA_HANDLE handle,
	char *name, HBA_ADAPTERATTRIBUTES *attrs);
int getAdapterPortAttrs(HBA_HANDLE handle, char *name, int portIndex,
	HBA_PORTATTRIBUTES *attrs);
HBA_STATUS fetch_mappings(HBA_HANDLE handle, HBA_WWN pwwn,
    HBA_FCPTARGETMAPPINGV2 **map);
int match_mappings(char *compare, HBA_FCPTARGETMAPPINGV2 *map);
uint64_t wwnConversion(uchar_t *wwn);


#ifdef	__cplusplus
}
#endif

#endif	/* _COMMON_H */
