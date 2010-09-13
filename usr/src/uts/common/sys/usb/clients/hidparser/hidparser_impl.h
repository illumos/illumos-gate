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

#ifndef _SYS_USB_HIDPARSER_IMPL_H
#define	_SYS_USB_HIDPARSER_IMPL_H


#ifdef __cplusplus
extern "C" {
#endif


/*
 * This header file is only included by the hidparser.  It contains
 * implementation specifc information for the hidparser.
 */


/*
 *  This is for Global and Local items like Usage Page,
 *  Usage Min, Logical Min, Report Count, Report Size etc.
 *  "value" was declared as char array to handle
 *  the case of extended items which can be up to
 *  255 bytes.
 */
typedef struct entity_attribute {
	uint_t	entity_attribute_tag;		/* see tag codes below */
	char	*entity_attribute_value;	/* Data bytes */
	int	entity_attribute_length; 	/* No. of data bytes */

	/* linked list of attributes */
	struct	entity_attribute	*entity_attribute_next;
} entity_attribute_t;


/*
 *  This is for these entities: Collection, Input, Output,
 *  Feature and End Collection.
 */
typedef struct entity_item {

	/* input, output, collection, feature or end collection */
	int		entity_item_type;

	/* constant, variable, relative, etc... */
	char		*entity_item_params;

	int		entity_item_params_leng; /* No. of bytes for params */

	/*
	 *   linked list of entity and control attributes. Parser is
	 *   responsbile for handling entity attributes' inheritance,
	 *   therefore this is NULL for end collection. But not for
	 *   begin collection.
	 */
	entity_attribute_t	*entity_item_attributes;

	/*
	 *  linked list of children if this is a collection
	 *  otherwise pointer to data for input/output
	 */
	union info  {
		struct entity_item	*child;
		void			*data;
	} info;

	/* pointer to the right sibling */
	struct entity_item	*entity_item_right_sibling;

	struct entity_item	*prev_coll;

} entity_item_t;



/* Use this typedef in defining the FIRSTs */
typedef int			hidparser_terminal_t;


/*
 * Hid parser handle
 */
typedef struct hidparser_handle_impl {

	/* Pointer to the parser tree */
	entity_item_t		*hidparser_handle_parse_tree;

	/* Pointer to the hid descriptor */
	usb_hid_descr_t		*hidparser_handle_hid_descr;
} hidparser_handle;


/*
 * Additional items that are not defined in hid_parser.h because they should
 * not be exposed to the hid streams modules.
 */


/*
 * Additional Local Items
 *      See section 6.2.2.8 of the HID 1.0 specification for
 *      more details.
 */

#define	HIDPARSER_ITEM_SET_DELIMITER 0xA8


/*
 * Addtional Global Items
 *      See section 6.2.2.7 of the HID 1.0 specifations for
 *      more details.
 */
#define	HIDPARSER_ITEM_USAGE_PAGE 0x04
#define	HIDPARSER_ITEM_PUSH 0xA4
#define	HIDPARSER_ITEM_POP 0xB4

/*
 * Main Items
 *      See section 6.2.2.5 of the HID 1.0 specification for
 *      more details.
 */
#define	HIDPARSER_ITEM_COLLECTION 0xA0
#define	HIDPARSER_ITEM_END_COLLECTION 0xC0

typedef struct entity_attribute_stack {
	struct entity_attribute_stack	*next;
	entity_attribute_t	*list;
} entity_attribute_stack_t;

/*
 * This structure is the interface between the parser
 * and the scanner.
 */
typedef struct hidparser_tok {
	unsigned char		*hidparser_tok_text;	/* Data bytes */
	int			hidparser_tok_leng;	/* No. of data bytes */

	/* Maximum buffer size */
	size_t			hidparser_tok_max_bsize;

	/* Raw descriptor */
	unsigned char		*hidparser_tok_entity_descriptor;

	/* Index to token currently being processed */
	size_t			hidparser_tok_index;

	/* Current token being processed */
	int			hidparser_tok_token;

	/* Pointer to the Global Item list */
	entity_attribute_t	*hidparser_tok_gitem_head;

	/* Pointer to the Local Item list */
	entity_attribute_t	*hidparser_tok_litem_head;

	/* Stack for push|pop Items */
	entity_attribute_stack_t	*hidparser_head;

} hidparser_tok_t;


/*  Entity Item Tags - HID 5.4.3  */
#define	R_ITEM_INPUT 0x80
#define	R_ITEM_OUTPUT 0x90
#define	R_ITEM_COLLECTION 0xA0
#define	R_ITEM_FEATURE 0xB0
#define	R_ITEM_END_COLLECTION 0xC0

/*  Entity Attribute Item Tags HID 5.4.4 */
#define	R_ITEM_USAGE_PAGE 0x04
#define	R_ITEM_LOGICAL_MINIMUM 0x14
#define	R_ITEM_LOGICAL_MAXIMUM 0x24
#define	R_ITEM_PHYSICAL_MINIMUM 0x34
#define	R_ITEM_PHYSICAL_MAXIMUM 0x44
#define	R_ITEM_EXPONENT 0x54
#define	R_ITEM_UNIT 0x64
#define	R_ITEM_REPORT_SIZE 0x74
#define	R_ITEM_REPORT_ID 0x84
#define	R_ITEM_REPORT_COUNT 0x94
#define	R_ITEM_PUSH 0xA4
#define	R_ITEM_POP 0xB4

/*  Control Attribute Item Tags  */
#define	R_ITEM_USAGE 0x08
#define	R_ITEM_USAGE_MIN 0x18
#define	R_ITEM_USAGE_MAX 0x28
#define	R_ITEM_DESIGNATOR_INDEX 0x38
#define	R_ITEM_DESIGNATOR_MIN 0x48
#define	R_ITEM_DESIGNATOR_MAX 0x58
#define	R_ITEM_STRING_INDEX 0x78
#define	R_ITEM_STRING_MIN 0x88
#define	R_ITEM_STRING_MAX 0x98
#define	R_ITEM_SET_DELIMITER 0xA8


/* Tags used to find the FIRST tokens corresponding to a nonterminal */

#define	HIDPARSER_ITEMS		0

/* Used for hidparser Error check */
#define	HIDPARSER_ERR_ERROR		0x8000
#define	HIDPARSER_ERR_WARN		0x0000
#define	HIDPARSER_ERR_STANDARD		0x0000
#define	HIDPARSER_ERR_VENDOR		0x4000
#define	HIDPARSER_ERR_TAG_MASK		0x3f00
#define	HIDPARSER_ERR_SUBCODE_MASK	0xff
#define	HIDPARSER_DELIM_ERR1		1
#define	HIDPARSER_DELIM_ERR2		2
#define	HIDPARSER_DELIM_ERR3		3


/* other */
#define	EXTENDED_ITEM			0xFE
#define	HIDPARSER_TEXT_LENGTH		500
#define	HIDPARSER_ISLOCAL_MASK		0x08

/*
 * Debug printing
 */
#define	PRINT_MASK_ALL		0xFFFFFFFF


#ifdef __cplusplus
}
#endif

#endif	/* _SYS_USB_HIDPARSER_IMPL_H */
