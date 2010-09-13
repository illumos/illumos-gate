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

#ifndef _SYS_USB_HIDPARSER_H
#define	_SYS_USB_HIDPARSER_H


#ifdef __cplusplus
extern "C" {
#endif

#include <sys/usb/usbai.h>
#include <sys/usb/usba/usbai_private.h>

/*
 * This file contains interfaces accessible by both the hid driver and
 * a hid module.
 */

/*
 * HID parser handle
 *	The handle is opaque to the hid driver as well as the hid streams
 *	modules.
 */
typedef struct hidparser_handle_impl *hidparser_handle_t;

#define	HID_REPORT_ID_UNDEFINED	0


#define	USAGE_MAX	100	/* Max no. of usages in a report */

typedef struct hidparser_usage_info {
	uint16_t	usage_page;
	uint16_t	usage_id;
	uint32_t	usage_min;
	uint32_t	usage_max;
	uint32_t	collection_usage;
	int32_t		lmax;
	int32_t		lmin;
	uint32_t	rptcnt;
	uint32_t	rptsz;
} hidparser_usage_info_t;

/*
 * structure for each report type, INPUT, OUTPUT or FEATURE
 * Note report id 0 and only one collection is handled
 */
typedef struct hidparser_rpt {
	uint_t		report_id;
	uint_t		main_item_value;
	uint_t		no_of_usages;
	hidparser_usage_info_t	usage_descr[USAGE_MAX];
} hidparser_rpt_t;

/*
 * structure to return a list of report id used for a report
 * type, INPUT, OUTPUT or FEATURE.
 */
#define	REPORT_ID_MAX	10	/* Max no. of report ids supported per type */

typedef struct hidparser_report_id_list {
	uint_t		main_item_value;
	uint_t		no_of_report_ids;
	uint_t		report_id[REPORT_ID_MAX];
} hidparser_report_id_list_t;

typedef struct hidparser_packet_info {
	uint_t		max_packet_size;
	uint_t		report_id;
} hidparser_packet_info_t;

/*
 * hidparser_get_country_code():
 *	Obtain the country code value that was returned in the hid descriptor
 *	Fill in the country_code argument
 *
 * Arguments:
 *	parser_handle:
 *		hid parser handle
 *	country code
 *		filled in with the country code value, upon success
 *
 * Return values:
 *	HIDPARSER_SUCCESS - returned on success
 *	HIDPARSER_FAILURE - returned on an unspecified error
 */
int hidparser_get_country_code(hidparser_handle_t parser_handle,
				uint16_t *country_code);


/*
 * hidparser_get_packet_size():
 *	Obtain the size(no. of bits) for a particular packet type. Note
 *	that a hid transfer may span more than one USB transaction.
 *
 * Arguments:
 *	parser_handle:
 *		hid parser handle
 *	report_id:
 *		report id
 *	main_item_type:
 *		type of report, either Input, Output, or Feature
 *	size:
 *		the size if filled in upon success
 * Return values:
 *	HIDPARSER_SUCCESS - returned success
 *	HIDPARSER_FAILURE - returned failure
 */
int hidparser_get_packet_size(hidparser_handle_t parser_handle,
				uint_t report_id,
				uint_t main_item_type,
				uint_t *size);

/*
 * hidparser_get_usage_attribute()
 *	Find the specified local item associated with the given usage. For
 *	example, this function may be used to find the logical minimum for
 *	an X usage.  Note that only short items are supported.
 *
 *
 * Arguments:
 *	parser_handle:
 *		hid parser handle
 *	report id:
 *		report id of the particular report that the usage may be
 *		found in.
 *	main_item_type:
 *		type of report, either Input, Output, or Feature
 *	usage_page:
 *		usage page that the Usage may be found on.
 *	usage:
 *		the Usage for which the local item will be found
 *	usage_attribute:
 *		type of local item to be found. Possible local and global
 *		items are given below.
 *
 *	usage_attribute_value:
 *		filled in with the value of the attribute upon return
 *
 * Return values:
 *	HIDPARSER_SUCCESS - returned success
 *	HIDPARSER_NOT_FOUND - usage specified by the parameters was not found
 *	HIDPARSER_FAILURE - unspecified failure
 *
 */
int hidparser_get_usage_attribute(hidparser_handle_t parser_handle,
					uint_t report_id,
					uint_t main_item_type,
					uint_t usage_page,
					uint_t usage,
					uint_t usage_attribute,
					int *usage_attribute_value);

/*
 * hidparser_get_main_item_data_descr()
 *
 * Description:
 *	Query the parser to find the data description of the main item.
 *	Section 6.2.2.5 of the HID 1.0 specification gives details
 *	about the data descriptions. For example, this function may be
 *	used to find out if an X value sent by the a USB mouse is an
 *	absolute or relative value.
 *
 * Parameters:
 *	parser_handle		parser handle
 *	report_id		report id of the particular report that the
 *				usage may be found in
 *	main_item_type		type of report - either Input, Output, Feature,
 *				or Collection
 *	usage_page		usage page that the usage may be found on
 *	usage			type of local item to be found
 *	main_item_descr_value	filled in with the data description
 *
 * Return values:
 *	HIDPARSER_SUCCESS	attribute found successfully
 *	HIDPARSER_NOT_FOUND	usage specified by the parameters was not found
 *	HIDPARSER_FAILURE	unspecified failure
 */
int
hidparser_get_main_item_data_descr(
			hidparser_handle_t	parser_handle,
			uint_t		report_id,
			uint_t		main_item_type,
			uint_t		usage_page,
			uint_t		usage,
			uint_t		*main_item_descr_value);


/*
 * hidparser_get_usage_list_in_order()
 *	Find all the usages corresponding to a main item, report id and
 *	a particular usage page.
 *	Note that only short items and 0 report id is supported.
 *
 * Arguments:
 *	parser_handle:
 *		hid parser handle
 *	report id:
 *		report id of the particular report where the usages belong to
 *	main_item_type:
 *		type of report, either Input, Output, or Feature
 *	usage_list:
 *		Filled in with the pointer to the first element of the
 *		usage list
 *
 * Return values:
 *	HIDPARSER_SUCCESS - returned success
 *	HIDPARSER_NOT_FOUND - usage specified by the parameters was not found
 *	HIDPARSER_FAILURE - unspecified failure
 */
int
hidparser_get_usage_list_in_order(hidparser_handle_t parse_handle,
				uint_t report_id,
				uint_t main_item_type,
				hidparser_rpt_t *rpt);


/*
 * hidparser_get_report_id_list()
 *	Return a list of all report ids used for descriptor items
 *	corresponding to a main item.
 *
 * Arguments:
 *	parser_handle:
 *		hid parser handle
 *	main_item_type:
 *		type of report, either Input, Output, or Feature
 *	report_id_list:
 *		Filled in with a list of report ids found in the descriptor
 *
 * Return values:
 *	HIDPARSER_SUCCESS - returned success
 *	HIDPARSER_FAILURE - unspecified failure
 */
int
hidparser_get_report_id_list(hidparser_handle_t parser_handle,
    uint_t main_item_type, hidparser_report_id_list_t *report_id_list);

/*
 * hidparser_find_max_packet_size_from_report_descriptor()
 *	Returns the packet size of the largest report in the complete
 *	report descriptor.
 *
 * Arguments
 *	parser_handle:
 *		hidparser_handle_t
 *	packet_info:
 *		hidparser_packet_info_t *
 */
void
hidparser_find_max_packet_size_from_report_descriptor(
    hidparser_handle_t parser_handle, hidparser_packet_info_t *hpack);



/*
 * Local Items
 *	See section 6.2.2.8 of the HID 1.0 specification for
 *	more details.
 */
#define	HIDPARSER_ITEM_USAGE		0x08
#define	HIDPARSER_ITEM_USAGE_MIN	0x18
#define	HIDPARSER_ITEM_USAGE_MAX	0x28
#define	HIDPARSER_ITEM_DESIGNATOR_INDEX	0x38
#define	HIDPARSER_ITEM_DESIGNATOR_MIN	0x48
#define	HIDPARSER_ITEM_DESIGNATOR_MAX	0x58
#define	HIDPARSER_ITEM_STRING_INDEX	0x78
#define	HIDPARSER_ITEM_STRING_MIN	0x88
#define	HIDPARSER_ITEM_STRING_MAX	0x98

/*
 * Global Items
 *	See section 6.2.2.7 of the HID 1.0 specifations for
 *	more details.
 */
#define	HIDPARSER_ITEM_LOGICAL_MINIMUM	0x14
#define	HIDPARSER_ITEM_LOGICAL_MAXIMUM	0x24
#define	HIDPARSER_ITEM_PHYSICAL_MINIMUM	0x34
#define	HIDPARSER_ITEM_PHYSICAL_MAXIMUM	0x44
#define	HIDPARSER_ITEM_EXPONENT		0x54
#define	HIDPARSER_ITEM_UNIT		0x64
#define	HIDPARSER_ITEM_REPORT_SIZE	0x74
#define	HIDPARSER_ITEM_REPORT_ID	0x84
#define	HIDPARSER_ITEM_REPORT_COUNT	0x94

/*
 * Main Items
 *	See section 6.2.2.5 of the HID 1.0 specification for
 *	more details.
 */
#define	HIDPARSER_ITEM_INPUT		0x80
#define	HIDPARSER_ITEM_OUTPUT		0x90
#define	HIDPARSER_ITEM_FEATURE		0xB0
#define	HIDPARSER_ITEM_COLLECTION	0xA0


/*
 * Macros to extract the usage page and usage id from a 32 bit usage
 * value.
 */
#define	HID_USAGE_ID(usage)		((usage) & 0xffff)
#define	HID_USAGE_PAGE(usage)		((usage)>>16 & 0xffff)
#define	HID_BUILD_USAGE(page, id)	(((page) & 0xffff) << 16 | \
					((id) & 0xffff))

/*
 * Usage Pages
 *	See the "Universal Serial Bus HID Usages Table"
 *	specification for more information
 */
#define	HID_GENERIC_DESKTOP		0x01
#define	HID_KEYBOARD_KEYPAD_KEYS	0x07
#define	HID_LEDS			0x08
#define	HID_CONSUMER			0x0C
#define	HID_BUTTON_PAGE			0x09

/*
 * Any Usage Page
 *	See the "Universal Serial Bus HID Usages Table"
 *	specification for more information
 */
#define	HID_USAGE_UNDEFINED	0x00

/*
 * Generic Desktop Page (0x01)
 *	See the "Universal Serial Bus HID Usages Table"
 *	specification for more information
 */
#define	HID_GD_POINTER		0x01
#define	HID_GD_MOUSE		0x02
#define	HID_GD_KEYBOARD		0x06
#define	HID_GD_X		0x30
#define	HID_GD_Y		0x31
#define	HID_GD_Z		0x32
#define	HID_GD_WHEEL		0x38

/*
 * LED Page (0x08)
 *	See the "Universal Serial Bus HID Usages Table"
 *	specification for more information
 */
#define	HID_LED_NUM_LOCK	0x01
#define	HID_LED_CAPS_LOCK	0x02
#define	HID_LED_SCROLL_LOCK	0x03
#define	HID_LED_COMPOSE		0x04
#define	HID_LED_KANA		0x05

/*
 * Consumer page (0x0C)
 *	See the "Universal Serial Bus HID Usages Table"
 *	specification for more information
 */
#define	HID_CONSUMER_CONTROL	0x01
#define	HID_CONSUMER_MICROPHONE	0x04
#define	HID_CONSUMER_HEADPHONE	0x05
#define	HID_CONSUMER_GRAPHIC_EQ	0x06
#define	HID_CONSUMER_PLAY	0xB0
#define	HID_CONSUMER_RECORD	0xB2
#define	HID_CONSUMER_VOL	0xE0
#define	HID_CONSUMER_BALANCE	0xE1
#define	HID_CONSUMER_MUTE	0xE2
#define	HID_CONSUMER_BASS	0xE3
#define	HID_CONSUMER_TREBLE	0xE4
#define	HID_CONSUMER_VOL_INCR	0xE9
#define	HID_CONSUMER_VOL_DECR	0xEA
#define	HID_CONSUMER_BAL_RIGHT	0x150
#define	HID_CONSUMER_BAL_LEFT	0x151
#define	HID_CONSUMER_BASS_INCR	0x152
#define	HID_CONSUMER_BASS_DECR	0x153
#define	HID_CONSUMER_TREBLE_INCR 0x154
#define	HID_CONSUMER_TREBLE_DECR 0x155


/*
 * Main Item Data Descriptor Information for
 *	Input, Output, and Feature Main Items
 *	See section 6.2.2.5 of the HID 1.0 specification for
 *	more details.
 */


#define	HID_MAIN_ITEM_DATA		0x0000
#define	HID_MAIN_ITEM_CONSTANT		0x0001
#define	HID_MAIN_ITEM_ARRAY		0x0000
#define	HID_MAIN_ITEM_VARIABLE		0x0002
#define	HID_MAIN_ITEM_ABSOLUTE		0x0000
#define	HID_MAIN_ITEM_RELATIVE		0x0004
#define	HID_MAIN_ITEM_NO_WRAP		0x0000
#define	HID_MAIN_ITEM_WRAP		0x0008
#define	HID_MAIN_ITEM_LINEAR		0x0000
#define	HID_MAIN_ITEM_NONLINEAR		0x0010
#define	HID_MAIN_ITEM_PREFERRED 	0x0000
#define	HID_MAIN_ITEM_NO_PREFERRED	0x0020
#define	HID_MAIN_ITEM_NO_NULL		0x0000
#define	HID_MAIN_ITEM_NULL		0x0040
#define	HID_MAIN_ITEM_NON_VOLATILE	0x0000
#define	HID_MAIN_ITEM_VOLATILE		0x0080
#define	HID_MAIN_ITEM_BIT_FIELD		0x0000
#define	HID_MAIN_ITEM_BUFFERED_BYTE	0x0100

/*
 * Main Item Data Descriptor Information for
 *	Collection Main Items
 *	See section 6.2.2.4 of the HID 1.0 specification for
 *	more details.
 */
#define	HID_MAIN_ITEM_PHYSICAL		0x0000
#define	HID_MAIN_ITEM_APPLICATION	0x0001
#define	HID_MAIN_ITEM_LOGICAL		0x0002


/*
 * Other
 */
#define	HIDPARSER_SUCCESS	0
#define	HIDPARSER_FAILURE	1
#define	HIDPARSER_NOT_FOUND	2

#ifdef __cplusplus
}
#endif

#endif	/* _SYS_USB_HIDPARSER_H */
