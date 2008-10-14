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
 *	A5X00 Library definitions
 */

/*
 * I18N message number ranges
 *  This file: 16000 - 16499
 *  Shared common messages: 1 - 1999
 */

#ifndef	_A5K_H
#define	_A5K_H


#ifdef	__cplusplus
extern "C" {
#endif


/* Defines */
#define	ENCLOSURE_PROD_ID	"SENA"
#define	ENCLOSURE_PROD_NAME	"Network Array"
#define		MAX_DRIVES_PER_BOX	22
#define		MAX_DRIVES_DAK		12
#define	L_WWN_LENGTH		16
#define	BOX_ID_MASK		0x60
#define	BOX_ID			0x0d
#define	ALT_BOX_ID		0x10

#define	MAX_IB_ELEMENTS		50
#define	MAX_VEND_SPECIFIC_ENC	216
#define	MAX_POSSIBLE_ELEMENTS	255

#define	SET_RQST_INSRT	0
#define	SET_RQST_RMV	1
#define	OVERALL_STATUS	2
#define	SET_FAULT	3
#define	SET_DRV_ON	4
#define	INSERT_DEVICE	106
#define	REMOVE_DEVICE	114
/* device specific identification for display, etc */
#define	DAK_OFF_NAME	"Daktari official"  /* inq response, prod ident */
#define	DAK_PROD_STR	"SUNWGS INT FCBPL"
#define	UNDEF_ENC_TYPE	2
#define	DAK_ENC_TYPE	1
#define	SENA_ENC_TYPE	0


/* Page defines */
#define	L_PAGE_PAGE_LIST	0x00	/* Supported pages page */
#define	L_PAGE_CONFIG		0x01	/* Configuration page */
#define	L_PAGE_1		L_PAGE_CONFIG
#define	L_PAGE_ENCL_CTL		0x02	/* Enclosure Control page */
#define	L_PAGE_ENCL_STATUS	0x02	/* Enclosure status page */
#define	L_PAGE_2		L_PAGE_ENCL_STATUS
#define	L_PAGE_STRING		0x04
#define	L_PAGE_4		L_PAGE_STRING
#define	L_PAGE_7		0x07	/* Element Descriptor Page */

#define	L_MAX_POSSIBLE_PAGES	255
#define	L_MAX_SENAIB_PAGES	8

/*
 *	FRU types internal and external (host SES type)
 */
#define	ELM_TYP_NONE	0x0	/* Unspecified */
#define	ELM_TYP_DD	0x01	/* Disk Drive - device */
#define	ELM_TYP_PS	0x02	/* Power Supply */
#define	ELM_TYP_FT	0x03	/* Fan Tray - cooling element */
#define	ELM_TYP_TS	0x04	/* Temperature Sensors */
#define	ELM_TYP_FP	0x0c	/* FPM screen - display */
#define	ELM_TYP_KP	0x0d	/* keypad on FPM - keypad device */
#define	ELM_TYP_FL	0x0f	/* Fibre Link module - SCSI port/trancvr */
#define	ELM_TYP_LN	0x10	/* Language */
#define	ELM_TYP_SP	0x11	/* Serial Port - communicaion port */
#define	ELM_TYP_MB	0x80	/* Motherboard/Centerplane */
#define	ELM_TYP_IB	0x81	/* IB(ESI) - controller electronics */
#define	ELM_TYP_BP	0x82	/* BackPlane */
#define	ELM_TYP_LO	0xa0	/* Loop Configuration */
#define	ELM_TYP_OR	0xa2	/* Orientation */

#define	S_HI_SPEED	0x5

/* code (status code) definitions */
#define	S_OK		0x01
#define	S_CRITICAL	0x02
#define	S_NONCRITICAL	0x03
#define	S_NOT_INSTALLED	0x05
#define	S_NOT_AVAILABLE	0x07

/* String codes. */
#define	L_WWN		0x01
#define	L_PASSWORD	0x02
#define	L_ENCL_NAME	0x03
#define	L_BOX_ID	0x04
#define	L_AUTO_LIP	0x05

/* Loop states */
#define	L_NO_LOOP		0x80	/* drive not accessable */
#define	L_INVALID_WWN		0x100
#define	L_INVALID_MAP		0x200
#define	L_NO_PATH_FOUND		0x400

/* d_state_flags definitions */
#define	L_OK			0x00	/* NOTE: Must be zero. */
#define	L_NOT_READY		0x01
#define	L_NOT_READABLE		0x02
#define	L_SPUN_DWN_D		0x04
#define	L_RESERVED		0x08
#define	L_OPEN_FAIL		0x10
#define	L_NO_LABEL		0x20
#define	L_SCSI_ERR		0x40

/* Values used by the l_led function */
#define	L_LED_STATUS		0x00
#define	L_LED_RQST_IDENTIFY	0x01
#define	L_LED_ON		0x02
#define	L_LED_OFF		0x04

/* Structure definitions */
typedef	struct	box_list_struct {
	uchar_t	prod_id_s[17];	/* NULL terminated string */
	uchar_t	b_name[33];	/* NULL terminated string */
	char	logical_path[MAXNAMELEN];
	char	b_physical_path[MAXNAMELEN];
	char	b_node_wwn_s[17];	/* NULL terminated string */
	uchar_t	b_node_wwn[8];
	char	b_port_wwn_s[17];	/* NULL terminated string */
	uchar_t	b_port_wwn[8];
	struct	box_list_struct	*box_prev;
	struct	box_list_struct	*box_next;
} Box_list;


typedef	struct	path_struct {
	char	*p_physical_path;
	char	*argv;
	int	slot_valid;	/* Slot valid flag. */
	int	slot;
	int	f_flag;		/* Front/rear flag. 1 = front */
	int	ib_path_flag;
} Path_struct;


/*
 * Page 0
 */
typedef	struct	ib_page_0 {
	uchar_t		page_code;
	uchar_t		sub_enclosures;
	ushort_t	page_len;
	uchar_t		sup_page_codes[0x100];
} IB_page_0;

/*
 * Page 1
 * Configuration page
 */
typedef	struct	type_desc_hdr {
	uchar_t	type;
	uchar_t	num;
	uchar_t	sub_id;
	uchar_t	text_len;
} Type_desc_hdr;

typedef	struct	type_desc_text {
	uchar_t	text_element[256];
} Type_desc_text;

typedef	struct	ib_page_config {
	uchar_t		page_code;
	uchar_t		sub_enclosures;
	ushort_t	page_len;
	uint_t		gen_code;
	/* Enclosure descriptor header */
	uchar_t		enc_res;
	uchar_t		enc_sub_id;
	uchar_t		enc_num_elem;
	uchar_t		enc_len;
	/* Enclosure descriptor */
	uchar_t		enc_node_wwn[8];
	uchar_t		vend_id[8];
	uchar_t		prod_id[16];
	uchar_t		prod_revision[4];
	uchar_t		res[MAX_VEND_SPECIFIC_ENC];
	Type_desc_hdr	type_hdr[MAX_IB_ELEMENTS];
	Type_desc_text	text[MAX_IB_ELEMENTS];
} IB_page_config;


/*
 * Page 2
 * Enclosure status/control page
 */
/*
 * Loop Configuration.
 */
typedef struct	loop_element_status {
	uchar_t			: 1,		/* reserved */
		prd_fail	: 1,
				: 2,		/* reserved */
		code		: 4;
	uchar_t			: 8;		/* reserved */
	uchar_t			: 8;		/* reserved */
	uchar_t			: 7,		/* reserved */
		split		: 1;
} Loop_elem_st;

/*
 * Language
 */
typedef struct	language_element_status {
	uchar_t			: 1,		/* reserved */
		prd_fail	: 1,
				: 2,		/* reserved */
		code		: 4;
	uchar_t			: 8;		/* reserved */
	ushort_t	language_code;
} Lang_elem_st;

/*
 * Tranceiver status
 */
typedef struct	trans_element_status {
	uchar_t			: 1,		/* reserved */
		prd_fail	: 1,
				: 2,		/* reserved */
		code		: 4;
	uchar_t			: 8;		/* reserved */
	uchar_t			: 7,
		report		: 1;
	uchar_t			: 3,		/* reserved */
		disabled	: 1,
				: 2,
		lol		: 1,
		lsr_fail	: 1;
} Trans_elem_st;

/*
 * ESI Controller status
 */
typedef struct	ctlr_element_status {
	uchar_t			: 1,		/* reserved */
		prd_fail	: 1,
				: 2,		/* reserved */
		code		: 4;
	uchar_t			: 8;		/* reserved */
	uchar_t			: 7,		/* reserved */
		report		: 1;
	uchar_t			: 4,		/* reserved */
		overtemp_alart	: 1,
				: 1,		/* reserved */
		ib_loop_1_fail	: 1,
		ib_loop_0_fail	: 1;
} Ctlr_elem_st;

/*
 * Backplane status
 */
typedef struct	bp_element_status {
	uchar_t	select		: 1,
		prd_fail	: 1,
				: 2,		/* reserved */
		code		: 4;
	uchar_t			: 8;		/* reserved */
	uchar_t			: 8;		/* reserved */
	uchar_t			: 3,		/* reserved */
		disabled	: 1,
		en_bypass_a	: 1,		/* Not in Spec. */
		en_bypass_b	: 1,		/* Not in Spec. */
		byp_a_enabled	: 1,
		byp_b_enabled	: 1;

} Bp_elem_st;

/*
 * Temperature sensor status
 */
typedef struct	temp_element_status {
	uchar_t			: 1,		/* reserved */
		prd_fail	: 1,
				: 2,		/* reserved */
		code		: 4;
	uchar_t			: 8;		/* reserved */
	char			degrees;
	uchar_t			: 4,		/* reserved */
		ot_fail		: 1,
		ot_warn		: 1,
		ut_fail		: 1,
		ut_warn		: 1;
} Temp_elem_st;

typedef struct	fan_element_status {
	uchar_t			: 1,		/* reserved */
		prd_fail	: 1,
				: 2,		/* reserved */
		code		: 4;
	uchar_t			: 8;		/* reserved */
	uchar_t			: 8;		/* reserved */
	uchar_t			: 1,		/* reserved */
		fail		: 1,
		rqsted_on	: 1,
				: 2,
		speed		: 3;
} Fan_elem_st;


typedef	struct	ps_element_status {
	uchar_t			: 1,		/* reserved */
		prd_fail	: 1,
				: 1,		/* reserved */
		swap		: 1,
		code		: 4;
	uchar_t			: 8;		/* reserved */
	uchar_t			: 4,		/* reserved */
		dc_over		: 1,
		dc_under	: 1,
		dc_over_i	: 1,
				: 1;		/* reserved */
	uchar_t			: 1,		/* reserved */
		fail		: 1,
		rqsted_on	: 1,
				: 1,
		ovrtmp_fail	: 1,
		temp_warn	: 1,
		ac_fail		: 1,
		dc_fail		: 1;
} Ps_elem_st;


typedef	struct	device_element {
	uchar_t	select		: 1,
		prd_fail	: 1,
		disable		: 1,
		swap		: 1,
		code		: 4;
	uchar_t	sel_id;				/* Hard address */
	uchar_t			: 1,
		dont_remove	: 1,
				: 2,
		rdy_to_ins	: 1,
		rmv		: 1,
		ident		: 1,
		report		: 1;
	uchar_t			: 1,		/* reserved */
		fault		: 1,
		fault_req	: 1,
		dev_off		: 1,
		en_bypass_a	: 1,
		en_bypass_b	: 1,
		bypass_a_en	: 1,
		bypass_b_en	: 1;
} Dev_elem_st;


typedef struct	interconnect_assem_status {
	uchar_t			: 4,		/* reserved */
		code		: 4;
	uchar_t			: 8;		/* reserved */
	uchar_t			: 8;		/* reserved */
	uchar_t			: 7,		/* reserved */
		eprom_fail	: 1;
} Interconnect_st;


typedef	struct	ib_page_2 {
	uchar_t	page_code;
	union {
		uchar_t	res	: 3,	/* Reserved */
			invop	: 1,
			info	: 1,
			non_crit	: 1,
			crit	: 1,
			unrec	: 1;
		uchar_t	ab_cond;
	} ui;
	ushort_t	page_len;
	uint_t		gen_code;
	uint_t		element[MAX_POSSIBLE_ELEMENTS];
} IB_page_2;

/*
 * Page 4
 *
 * String page.
 */
typedef	struct page4_name {
	uchar_t		page_code;
	uchar_t		: 8;		/* reserved */
	ushort_t	page_len;
	uchar_t		string_code;
	uchar_t		: 7,
			enable	: 1;
	uchar_t		: 8;		/* reserved */
	uchar_t		: 8;		/* reserved */
	uchar_t		name[32];
} Page4_name;


typedef	struct	element_descriptor {
	uchar_t		: 8;		/* reserved */
	uchar_t		: 8;		/* reserved */
	ushort_t	desc_len;
	uchar_t		desc_string[0xff];
} Elem_desc;


typedef	struct	ib_page_7 {
	uchar_t		page_code;
	uchar_t		: 8;		/* reserved */
	ushort_t	page_len;
	uint_t		gen_code;
	Elem_desc	element_desc[MAX_POSSIBLE_ELEMENTS];
} IB_page_7;


/* structure for IB */
typedef struct ib_state_struct {
	uchar_t	enclosure_name[33];	/* extra character is NULL */
	IB_page_0	p0;
	IB_page_config	config;		/* Enclosure configuration page */
	IB_page_2	p2_s;		/* Enclosure status page */
	IB_page_7	p7_s;		/* Element descriptor page */
	int		res;
	int		box_id;
	struct dlist	*ib_multipath_list;
} Ib_state;


/* Individual SENA drive state */
typedef struct l_disk_state_struct {
	Dev_elem_st			ib_status;
	int				l_state_flag;	/* Loop State */
	struct g_disk_state_struct	g_disk_state;
} L_disk_state;

/*
 *		State of the Photon
 */
typedef struct l_state_struct {
	Ib_state	ib_tbl;	/* state of controller */

	int		total_num_drv;
	struct l_disk_state_struct	drv_front[MAX_DRIVES_PER_BOX/2];
	struct l_disk_state_struct	drv_rear[MAX_DRIVES_PER_BOX/2];
} L_state;


/*
 * Function Prototypes for the functions defined in libg_fc
 * These are the functions that will be visible to an end user
 * They are all CONTRACT PRIVATE
 */

#if defined(__STDC__)

extern int	l_chk_null_wwn(Path_struct *, char *, L_state *, int);
extern int	l_convert_name(char *, char **, struct path_struct **, int);
extern int	l_dev_pwr_up_down(char *, struct path_struct *, int, int, int);
extern int	l_device_present(char *, int, gfc_map_t *, int, char **);
extern int	l_download(char *, char *, int, int);
extern int	l_duplicate_names(Box_list *, char *, char *, int);
extern int	l_encl_status_page_funcs(int, char *, int, char *,
		struct l_state_struct  *, int, int, int);
extern int	l_format_ifp_status_msg(char *, int, int);
extern int	l_format_fc_status_msg(char *, int, int);
extern void	l_free_box_list(struct box_list_struct **);
extern int	l_free_lstate(L_state **);
extern int	l_get_allses(char *, struct box_list_struct *, struct dlist **,
		int);
extern int	l_get_box_list(struct box_list_struct **, int);
extern int	l_get_disk_element_index(struct l_state_struct *, int *, int *);
extern int	l_get_disk_port_status(char *, struct l_disk_state_struct *,
		int, int);
extern int	l_get_disk_status(char *, struct l_disk_state_struct *,
		WWN_list *, int);
extern void	l_get_drive_name(char *, int, int, char *);
extern int	l_get_envsen(char *, uchar_t *, int, int);
extern int	l_get_envsen_page(int, uchar_t *, int, uchar_t, int);
extern int	l_get_ib_status(char *, struct l_state_struct *, int);
extern int	l_get_individual_state(char *, struct l_disk_state_struct *,
		Ib_state *, int, struct box_list_struct *,
		struct wwn_list_struct *, int);
extern int	l_get_port(char *, int *, int);
extern int	l_get_ses_path(char *, char *, gfc_map_t *, int);
extern int	l_get_slot(struct path_struct *, L_state *, int);
extern int	l_get_status(char *, struct l_state_struct *, int);
extern int	l_led(struct path_struct *, int, struct device_element *, int);
extern int	l_make_node(char *, int, char *, gfc_map_t *, int);
extern int	l_new_name(char *, char *);
extern int	l_offline_photon(struct hotplug_disk_list *,
		struct wwn_list_struct *, int, int);
extern int	l_get_enc_type(L_inquiry inq);
extern int	l_pho_pwr_up_down(char *, char *, int, int, int);

#else /* __STDC__ */


extern int	l_chk_null_wwn();
extern int	l_convert_name();
extern int	l_dev_pwr_up_down();
extern int	l_device_present();
extern int	l_download();
extern int	l_duplicate_names();
extern int	l_encl_status_page_funcs();
extern int	l_format_fc_status_msg();
extern int	l_format_ifp_status_msg();
extern void	l_free_box_list();
extern int	l_free_lstate();
extern int	l_get_allses();
extern int	l_get_box_list();
extern int	l_get_disk_element_index();
extern int	l_get_disk_port_status();
extern int	l_get_disk_status();
extern void	l_get_drive_name();
extern int	l_get_envsen();
extern int	l_get_envsen_page();
extern int	l_get_ib_status();
extern int	l_get_individual_state();
extern int	l_get_port();
extern int	l_get_ses_path();
extern int	l_get_slot();
extern int	l_get_status();
extern int	l_led();
extern int	l_make_node();
extern int	l_new_name();
extern int	l_offline_photon();
extern int	l_pho_pwr_up_down();
extern int	l_get_enc_type();

#endif /* __STDC__ */

#ifdef	__cplusplus
}
#endif

#endif	/* _A5K_H */
