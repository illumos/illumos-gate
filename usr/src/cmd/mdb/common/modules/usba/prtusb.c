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
 *
 * Copyright 2016 Joyent, Inc.
 */


#include <sys/mdb_modapi.h>


#include <sys/usb/usba.h>
#include <sys/usb/usba/usba_types.h>
#include <sys/usb/clients/hid/hid.h>
#include <sys/usb/clients/hidparser/hidparser.h>
#include <sys/usb/clients/hidparser/hidparser_impl.h>
#include <sys/usb/usba/genconsole.h>
#include <sys/usb/clients/hid/hidvar.h>


/* ****************************************************************** */

/* extenal definition */

typedef struct mdb_ctf_id {
	void *_opaque[2];
} mdb_ctf_id_t;

extern int mdb_ctf_lookup_by_name(const char *, mdb_ctf_id_t *);

extern int mdb_devinfo2driver(uintptr_t, char *, size_t);

extern int mdb_devinfo2statep(uintptr_t, char *, uintptr_t *);

extern char *mdb_ddi_pathname(uintptr_t, char *, size_t);


/* ****************************************************************** */

/* internal definition */

#define	OPT_TREE	0x01
#define	OPT_VERB	0x02

#define	STRLEN		256
#define	BYTE_OFFSET	8


typedef	struct usb_descr_item {
	uint_t	nlen;	/* if it's an byte array, nlen += BYTE_OFFSET */
	char	*name;	/* descriptor item name */
} usb_descr_item_t;

/* define the known descriptor items */
static usb_descr_item_t usb_cfg_descr[] = {
	{1, "bLength"},
	{1, "bDescriptorType"},
	{2, "wTotalLength"},
	{1, "bNumInterfaces"},
	{1, "bConfigurationValue"},
	{1, "iConfiguration"},
	{1, "bmAttributes"},
	{1, "bMaxPower"},
};
static uint_t usb_cfg_item = 8;

static usb_descr_item_t usb_ia_descr[] = {
	{1, "bLength"},
	{1, "bDescriptorType"},
	{1, "bFirstInterface"},
	{1, "bInterfaceCount"},
	{1, "bFunctionClass"},
	{1, "bFunctionSubClass"},
	{1, "bFunctionProtocol"},
	{1, "iFunction"},
};
static uint_t usb_ia_item = 8;

static usb_descr_item_t usb_if_descr[] = {
	{1, "bLength"},
	{1, "bDescriptorType"},
	{1, "bInterfaceNumber"},
	{1, "bAlternateSetting"},
	{1, "bNumEndpoints"},
	{1, "bInterfaceClass"},
	{1, "bInterfaceSubClass"},
	{1, "bInterfaceProtocol"},
	{1, "iInterface"},
};
static uint_t usb_if_item = 9;

static usb_descr_item_t usb_ep_descr[] = {
	{1, "bLength"},
	{1, "bDescriptorType"},
	{1, "bEndpointAddress"},
	{1, "bmAttributes"},
	{2, "wMaxPacketSize"},
	{1, "bInterval"},
};
static uint_t usb_ep_item = 6;

static usb_descr_item_t usb_ep_ss_comp_descr[] = {
	{1, "bLength"},
	{1, "bDescriptorType"},
	{1, "bMaxBurst"},
	{1, "bmAttributes"},
	{2, "wBytesPerInterval"}
};
static uint_t usb_ep_ss_comp_item = 5;

static usb_descr_item_t usb_qlf_descr[] = {
	{1, "bLength"},
	{1, "bDescriptorType"},
	{2, "bcdUSB"},
	{1, "bDeviceClass"},
	{1, "bDeviceSubClass"},
	{1, "bDeviceProtocol"},
	{1, "bMaxPacketSize0"},
	{1, "bNumConfigurations"},
	{1, "bReserved"},
};
static uint_t usb_qlf_item = 9;

static usb_descr_item_t usb_str_descr[] = {
	{1, "bLength"},
	{1, "bDescriptorType"},
	{1, "bString"},
};
static uint_t usb_str_item = 3;

static usb_descr_item_t usb_wa_descr[] = {
	{1, "bLength"},
	{1, "bDescriptorType"},
	{2, "bcdWAVersion"},
	{1, "bNumPorts"},
	{1, "bmAttributes"},
	{2, "wNumRPipes"},
	{2, "wRPipeMaxBlock"},
	{1, "bRPipeBlockSize"},
	{1, "bPwrOn2PwrGood"},
	{1, "bNumMMCIEs"},
	{1, "DeviceRemovable"},
};

static uint_t usb_wa_item = 11;

static usb_descr_item_t usb_hid_descr[] = {
	{1, "bLength"},
	{1, "bDescriptorType"},
	{2, "bcdHID"},
	{1, "bCountryCode"},
	{1, "bNumDescriptors"},
	{1, "bReportDescriptorType"},
	{2, "wReportDescriptorLength"},
};
static uint_t usb_hid_item = 7;

static usb_descr_item_t usb_ac_header_descr[] = {
	{1, "bLength"},
	{1, "bDescriptorType"},
	{1, "bDescriptorSubType"},
	{2, "bcdADC"},
	{2, "wTotalLength"},
	{1, "blnCollection"},
	{1, "baInterfaceNr"},
};
static uint_t usb_ac_header_item = 7;

static usb_descr_item_t usb_ac_input_term_descr[] = {
	{1, "bLength"},
	{1, "bDescriptorType"},
	{1, "bDescriptorSubType"},
	{1, "bTerminalID"},
	{2, "wTerminalType"},
	{1, "bAssocTerminal"},
	{1, "bNrChannels"},
	{2, "wChannelConfig"},
	{1, "iChannelNames"},
	{1, "iTerminal"},
};
static uint_t usb_ac_input_term_item = 10;

static usb_descr_item_t usb_ac_output_term_descr[] = {
	{1, "bLength"},
	{1, "bDescriptorType"},
	{1, "bDescriptorSubType"},
	{1, "bTerminalID"},
	{2, "wTerminalType"},
	{1, "bAssocTerminal"},
	{1, "bSourceID"},
	{1, "iTerminal"},
};
static uint_t usb_ac_output_term_item = 8;

static usb_descr_item_t usb_ac_mixer_descr[] = {
	{1, "bLength"},
	{1, "bDescriptorType"},
	{1, "bDescriptorSubType"},
	{1, "bUnitID"},
	{1, "bNrInPins"},
	{1, "baSourceID"},
};
static uint_t usb_ac_mixer_item = 6;

static usb_descr_item_t usb_ac_selector_descr[] = {
	{1, "bLength"},
	{1, "bDescriptorType"},
	{1, "bDescriptorSubType"},
	{1, "bUnitID"},
	{1, "bNrInPins"},
	{1, "baSourceID"},
};
static uint_t usb_ac_selector_item = 6;

static usb_descr_item_t usb_ac_feature_descr[] = {
	{1, "bLength"},
	{1, "bDescriptorType"},
	{1, "bDescriptorSubType"},
	{1, "bUnitID"},
	{1, "bSourceID"},
	{1, "bControlSize"},
	{1, "bmaControls"},
};
static uint_t usb_ac_feature_item = 7;

static usb_descr_item_t usb_ac_processing_descr[] = {
	{1, "bLength"},
	{1, "bDescriptorType"},
	{1, "bDescriptorSubType"},
	{1, "bUnitID"},
	{1, "wProcessType"},
	{1, "bNrInPins"},
	{1, "baSourceID"},
};
static uint_t usb_ac_processing_item = 7;

static usb_descr_item_t usb_ac_extension_descr[] = {
	{1, "bLength"},
	{1, "bDescriptorType"},
	{1, "bDescriptorSubType"},
	{1, "wExtensionCode"},
	{1, "bUnitID"},
	{1, "bNrInPins"},
	{1, "baSourceID"},
};
static uint_t usb_ac_extension_item = 7;

static usb_descr_item_t usb_as_ep_descr[] = {
	{1, "blength"},
	{1, "bDescriptorType"},
	{1, "bDescriptorSubType"},
	{1, "bmAttributes"},
	{1, "bLockDelayUnits"},
	{2, "wLockDelay"},
};
static uint_t usb_as_ep_item = 6;

static usb_descr_item_t usb_as_if_descr[] = {
	{1, "blength"},
	{1, "bDescriptorType"},
	{1, "bDescriptorSubType"},
	{1, "bTerminalLink"},
	{1, "bDelay"},
	{2, "wFormatTag"},
};
static uint_t usb_as_if_item = 6;

static usb_descr_item_t usb_as_format_descr[] = {
	{1, "blength"},
	{1, "bDescriptorType"},
	{1, "bDescriptorSubType"},
	{1, "bFormatType"},
	{1, "bNrChannels"},
	{1, "bSubFrameSize"},
	{1, "bBitResolution"},
	{1, "bSamFreqType"},
	{1, "bSamFreqs"},
};
static uint_t usb_as_format_item = 9;

static usb_descr_item_t usb_vc_header_descr[] = {
	{1, "bLength"},
	{1, "bDescriptorType"},
	{1, "bDescriptorSubtype"},
	{2, "bcdUVC"},
	{2, "wTotalLength"},
	{4, "dwClockFrequency"},
	{1, "bInCollection"},
};
static uint_t usb_vc_header_item = 7;

static usb_descr_item_t usb_vc_input_term_descr[] = {
	{1, "bLength"},
	{1, "bDescriptorType"},
	{1, "bDescriptorSubType"},
	{1, "bTerminalID"},
	{2, "wTerminalType"},
	{1, "AssocTerminal"},
	{1, "iTerminal"},
};
static uint_t usb_vc_input_term_item = 7;

static usb_descr_item_t usb_vc_output_term_descr[] = {
	{1, "bLength"},
	{1, "bDescriptorType"},
	{1, "bDescriptorSubType"},
	{1, "bTerminalID"},
	{2, "wTerminalType"},
	{1, "AssocTerminal"},
	{1, "bSourceID"},
	{1, "iTerminal"},
};
static uint_t usb_vc_output_term_item = 8;

static usb_descr_item_t usb_vc_processing_descr[] = {
	{1, "bLength"},
	{1, "bDescriptorType"},
	{1, "bDescriptorSubType"},
	{1, "bUnitID"},
	{1, "bSourceID"},
	{2, "wMaxMultiplier"},
	{1, "bControlSize"},
	{1, "bmControls"},
};
static uint_t usb_vc_processing_item = 8;

static usb_descr_item_t usb_vc_selector_descr[] = {
	{1, "bLength"},
	{1, "bDescriptorType"},
	{1, "bDescriptorSubType"},
	{1, "bUnitID"},
	{1, "bNrInPins"},
};
static uint_t usb_vc_selector_item = 5;

static usb_descr_item_t usb_vc_extension_descr[] = {
	{1, "bLength"},
	{1, "bDescriptorType"},
	{1, "bDescriptorSubType"},
	{1, "bUnitID"},
	{16 + BYTE_OFFSET, "guidExtensionCode[16]"},
	{1, "bNumControls"},
	{1, "bNrInPins"},
};
static uint_t usb_vc_extension_item = 7;

static usb_descr_item_t usb_vs_input_header_descr[] = {
	{1, "bLength"},
	{1, "bDescriptorType"},
	{1, "bDescriptorSubType"},
	{1, "bNumFormats"},
	{2, "wTotalLength"},
	{1, "bEndpointAddress"},
	{1, "bmInfo"},
	{1, "bTerminalLink"},
	{1, "bStillCaptureMethod"},
	{1, "bTriggerSupport"},
	{1, "bTriggerUsage"},
	{1, "bControlSize"},
	{1, "bmaControls"},
};
static uint_t usb_vs_input_header_item = 13;

static usb_descr_item_t usb_vs_output_header_descr[] = {
	{1, "bLength"},
	{1, "bDescriptorType"},
	{1, "bDescriptorSubType"},
	{1, "bNumFormats"},
	{2, "wTotalLength"},
	{1, "bEndpointAddress"},
	{1, "bTerminalLink"},
	{1, "bControlSize"},
	{1, "bmaControls"},
};
static uint_t usb_vs_output_header_item = 9;

static usb_descr_item_t usb_vs_still_image_descr[] = {
	{1, "bLength"},
	{1, "bDescriptorType"},
	{1, "bDescriptorSubType"},
	{1, "bEndpointAddress"},
	{1, "bNumImageSizePatterns"},
	{2, "wWidth"},
	{2, "wHeight"},
};
static uint_t usb_vs_still_image_item = 7;

static usb_descr_item_t usb_vs_color_matching_descr[] = {
	{1, "bLength"},
	{1, "bDescriptorType"},
	{1, "bDescriptorSubtype"},
	{1, "bColorPrimaries"},
	{1, "bTransferCharacteristics"},
	{1, "bMatrixCoefficients"},
};
static uint_t usb_vs_color_matching_item = 6;

static usb_descr_item_t usb_vs_2frame_descr[] = {
	{1, "bLength"},
	{1, "bDescriptorType"},
	{1, "bDescriptorSubType"},
	{1, "bFrameIndex"},
	{1, "bmCapabilities"},
	{2, "wWidth"},
	{2, "wHeight"},
	{4, "dwMinBitRate"},
	{4, "dwMaxBitRate"},
	{4, "dwMaxVideoFrameBufferSize"},
	{4, "dwDefaultFrameInterval"},
	{1, "bFrameIntervalType"},
};
static uint_t usb_vs_2frame_item = 12;

static usb_descr_item_t usb_vs_format_mjpeg_descr[] = {
	{1, "bLength"},
	{1, "bDescriptorType"},
	{1, "bDescriptorSubType"},
	{1, "bFormatIndex"},
	{1, "bNumFrameDescriptors"},
	{1, "bmFlags"},
	{1, "bDefaultFrameIndex"},
	{1, "bAspectRatioX"},
	{1, "bAspectRatioY"},
	{1, "bmInterlaceFlags"},
	{1, "bCopyProtect"},
};
static uint_t usb_vs_format_mjpeg_item = 11;

static usb_descr_item_t usb_vs_format_uncps_descr[] = {
	{1, "bLength"},
	{1, "bDescriptorType"},
	{1, "bDescriptorSubType"},
	{1, "bFormatIndex"},
	{1, "bNumFrameDescriptors"},
	{16 + BYTE_OFFSET, "guidFormat[16]"},
	{1, "bBitsPerPixel"},
	{1, "bDefaultFrameIndex"},
	{1, "bAspectRatioX"},
	{1, "bAspectRatioY"},
	{1, "bmInterlaceFlags"},
	{1, "bCopyProtect"},
};
static uint_t usb_vs_format_uncps_item = 12;

static usb_descr_item_t usb_vs_format_mp2ts_descr[] = {
	{1, "bLength"},
	{1, "bDescriptorType"},
	{1, "bDescriptorSubType"},
	{1, "bFormatIndex"},
	{1, "bDataOffset"},
	{1, "bPacketLength"},
	{1, "bStrideLength"},
	{16 + BYTE_OFFSET, "guidStrideFormat[16]"},
};
static uint_t usb_vs_format_mp2ts_item = 8;

static usb_descr_item_t usb_vs_format_dv_descr[] = {
	{1, "bLength"},
	{1, "bDescriptorType"},
	{1, "bDescriptorSubType"},
	{1, "bFormatIndex"},
	{4, "dwMaxVideoFrameBufferSize"},
	{1, "bFormatType"},
};
static uint_t usb_vs_format_dv_item = 6;


/* ****************************************************************** */

typedef struct hci_state {
	void			*hci_dip;
	uint_t			hci_instance;
	void			*hci_hcdi_ops;
	uint_t			hci_flags;
	uint16_t		vendor_id;
	uint16_t		device_id;
} hci_state_t;

static int prt_usb_tree(uintptr_t paddr, uint_t flag);

static int prt_usb_tree_node(uintptr_t paddr);

static void prt_usb_hid_item(uintptr_t paddr);

static void prt_usb_hid_item_params(entity_item_t *item);

static void prt_usb_hid_item_attrs(uintptr_t paddr);

static void prt_usb_hid_item_tags(uint_t tag);

static void prt_usb_hid_item_data(uintptr_t paddr, uint_t len);

static int prt_usb_desc(uintptr_t usb_cfg, uint_t cfg_len);

static int prt_usb_ac_desc(uintptr_t paddr, uint_t nlen);

static int prt_usb_as_desc(uintptr_t paddr, uint_t nlen);

static int prt_usb_vc_desc(uintptr_t paddr, uint_t nlen);

static int prt_usb_vs_desc(uintptr_t paddr, uint_t nlen);

static int print_descr(uintptr_t, uint_t, usb_descr_item_t *, uint_t);

static int print_struct(uintptr_t, uint_t, mdb_arg_t *);

static int prt_usb_buf(uintptr_t, uint_t);


/* ****************************************************************** */

/* exported functions */

void prt_usb_usage(void);

int prtusb(uintptr_t, uint_t, int, const mdb_arg_t *);

/* ****************************************************************** */

/* help of prtusb */
void
prt_usb_usage(void)
{
	mdb_printf("%-8s : %s\n", "-v", "print all descriptors");
	mdb_printf("%-8s : %s\n", "-t", "print device trees");
	mdb_printf("%-8s : %s\n", "-i index", "print the device by index");
}

/* the entry of ::prtusb */
int
prtusb(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	static int count = 1;
	uint64_t sel_num = 0;
	uint_t usb_flag = 0;
	usba_device_t usb_dev;
	usb_dev_descr_t dev_desc;
	struct dev_info usb_dip;
	char strbuf[STRLEN];

	/* print all usba devices if no address assigned */
	if (!(flags & DCMD_ADDRSPEC)) {
		if (mdb_walk_dcmd("usba_device", "prtusb", argc, argv) == -1) {
			mdb_warn("failed to walk usba_device");

			return (DCMD_ERR);
		}

		return (DCMD_OK);
	}

	/* for the first device, print head */
	if (DCMD_HDRSPEC(flags)) {
		count = 1;
		mdb_printf("%<u>%-8s%-12s%-6s%-14s%-5s%-12s%-20s%</u>\n",
		    "INDEX", "DRIVER", "INST", "NODE", "GEN", "VID.PID",
		    "PRODUCT");
	}

	if (mdb_getopts(argc, argv,
	    'i', MDB_OPT_UINT64, &sel_num,
	    't', MDB_OPT_SETBITS, OPT_TREE, &usb_flag,
	    'v', MDB_OPT_SETBITS, OPT_VERB, &usb_flag, NULL) != argc) {

		return (DCMD_USAGE);
	}

	if (mdb_vread(&usb_dev, sizeof (usba_device_t), addr) == -1) {
		mdb_warn("Failed to read usba_device!\n");

		return (DCMD_ERR);
	}

	if (mdb_vread(&usb_dip, sizeof (struct dev_info),
	    (uintptr_t)usb_dev.usb_dip) == -1) {
		mdb_warn("Failed to read dev_info!\n");

		return (DCMD_ERR);
	}

	/* process the "-i" */
	if (sel_num && sel_num != count) {
		count++;

		return (DCMD_OK);
	}

	/* index number of device node  */
	mdb_printf("%-8x", count++);

	/* driver and instance */
	mdb_devinfo2driver((uintptr_t)usb_dev.usb_dip, strbuf, STRLEN);
	mdb_printf("%-12s%-6d", strbuf, usb_dip.devi_instance);

	/* node name */
	if (mdb_readstr(strbuf, STRLEN,
	    (uintptr_t)usb_dip.devi_node_name) != -1) {

		mdb_printf("%-14s", strbuf);
	} else {

		mdb_printf("%-14s", "No Node Name");
	}


	if (mdb_vread(&dev_desc, sizeof (usb_dev_descr_t),
	    (uintptr_t)usb_dev.usb_dev_descr) != -1) {

		/* gen (note we read this from the bcd) */
		mdb_printf("%01x.%01x  ", dev_desc.bcdUSB >> 8,
		    (dev_desc.bcdUSB & 0xf0) >> 4);

		/* vid.pid */
		mdb_printf("%04x.%04x   ",
		    dev_desc.idVendor, dev_desc.idProduct);
	}

	/* product string */
	if (mdb_readstr(strbuf, STRLEN,
	    (uintptr_t)usb_dev.usb_product_str) != -1) {

		mdb_printf("%s\n", strbuf);
	} else {

		mdb_printf("%s\n", "No Product String");
	}

	/* tree, print usb device tree info */
	if (usb_flag & OPT_TREE) {

		mdb_printf("\nusba_device: 0x%x\n", addr);

		mdb_printf("mfg_prod_sn: ");
		if (mdb_readstr(strbuf, STRLEN,
		    (uintptr_t)usb_dev.usb_mfg_str) != -1) {
			mdb_printf("%s - ", strbuf);
		} else {
			mdb_printf("NULL - ");
		}
		if (mdb_readstr(strbuf, STRLEN,
		    (uintptr_t)usb_dev.usb_product_str) != -1) {
			mdb_printf("%s - ", strbuf);
		} else {
			mdb_printf("NULL -");
		}
		if (mdb_readstr(strbuf, STRLEN,
		    (uintptr_t)usb_dev.usb_serialno_str) != -1) {
			mdb_printf("%s", strbuf);
		} else {
			mdb_printf("NULL");
		}

		mdb_printf("\n\n");
		prt_usb_tree((uintptr_t)usb_dev.usb_dip, 0);
	}

	/* verbose, print all descriptors */
	if (usb_flag & OPT_VERB) {
		int i;
		uintptr_t cfg_buf;
		uint16_t cfg_len;

		mdb_printf("\n");

		/* device descriptor */
		prt_usb_desc((uintptr_t)usb_dev.usb_dev_descr, 18);

		/* config cloud descriptors */
		if (usb_dev.usb_n_cfgs == 1) {
			mdb_inc_indent(4);
			mdb_printf("-- Active Config Index 0\n");
			mdb_dec_indent(4);
			prt_usb_desc((uintptr_t)usb_dev.usb_cfg,
			    usb_dev.usb_cfg_length);
		} else {
			/* multiple configs */
			for (i = 0; i < usb_dev.usb_n_cfgs; i++) {

				if ((mdb_vread(&cfg_len, sizeof (uint16_t),
				    (uintptr_t)(usb_dev.usb_cfg_array_len + i))
				    != -1) &&
				    (mdb_vread(&cfg_buf, sizeof (uintptr_t),
				    (uintptr_t)(usb_dev.usb_cfg_array + i))
				    != -1)) {
					mdb_inc_indent(4);
					if (cfg_buf ==
					    (uintptr_t)usb_dev.usb_cfg) {
						mdb_printf("-- Active Config"
						    " Index %x\n", i);
					} else {
						mdb_printf("-- Inactive Config"
						    " Index %x\n", i);
					}
					mdb_dec_indent(4);

					prt_usb_desc(cfg_buf, cfg_len);
				}
			}
		}
	}

	if (usb_flag) {

		mdb_printf("%<u>%-72s%</u>\n", " ");
	}

	return (DCMD_OK);
}

/* print the info required by "-t" */
static int
prt_usb_tree(uintptr_t paddr, uint_t flag)
{
	struct dev_info usb_dip;

	if (mdb_vread(&usb_dip, sizeof (struct dev_info), paddr) == -1) {
		mdb_warn("prt_usb_tree: Failed to read dev_info!\n");

		return (DCMD_ERR);
	}

	prt_usb_tree_node(paddr);

	if (usb_dip.devi_child) {

		mdb_printf("{\n");
		mdb_inc_indent(4);
		prt_usb_tree((uintptr_t)usb_dip.devi_child, 1);
		mdb_dec_indent(4);
		mdb_printf("}\n\n");
	}

	if (usb_dip.devi_sibling && flag == 1) {
		/* print the sibling if flag == 1 */

		prt_usb_tree((uintptr_t)usb_dip.devi_sibling, 1);
	}

	return (DCMD_OK);
}

static int
prt_usb_tree_node(uintptr_t paddr)
{
	struct dev_info usb_dip;
	uintptr_t statep;
	uint_t errlevel;
	char driver_name[STRLEN] = "";
	char strbuf[STRLEN] = "";

	if (mdb_vread(&usb_dip, sizeof (struct dev_info), paddr) == -1) {
		mdb_warn("prt_usb_tree_node: Failed to read dev_info!\n");

		return (DCMD_ERR);
	}

	/* node name */
	if (mdb_readstr(strbuf, STRLEN,
	    (uintptr_t)usb_dip.devi_node_name) != -1) {
		mdb_printf("%s, ", strbuf);
	} else {
		mdb_printf("%s, ", "node_name");
	}

	/* instance */
	mdb_printf("instance #%d ", usb_dip.devi_instance);

	/* driver name */
	if (DDI_CF2(&usb_dip)) {

		mdb_devinfo2driver(paddr, driver_name, STRLEN);
		mdb_printf("(driver name: %s)\n", driver_name);
	} else {

		mdb_printf("(driver not attached)\n");
	}

	/* device path */
	mdb_ddi_pathname(paddr, strbuf, STRLEN);
	mdb_printf("  %s\n", strbuf);

	/* dip addr */
	mdb_printf("  dip: 0x%x\n", paddr);

	/* softe_sate */
	mdb_snprintf(strbuf, STRLEN, "%s_statep", driver_name);
	if (mdb_devinfo2statep(paddr, strbuf, &statep) != -1) {
		mdb_printf("  %s: 0x%x\n", strbuf, statep);
	}

	/* error level */
	mdb_snprintf(strbuf, STRLEN, "%s_errlevel", driver_name);
	if (mdb_readvar(&errlevel, strbuf) != -1) {
		mdb_printf("  %s: 0x%x\n", strbuf, errlevel);
	}

	if (strcmp(driver_name, "ehci") == 0) {
		mdb_arg_t argv[] = {
		    {MDB_TYPE_STRING, {"ehci_state_t"}},
		    {MDB_TYPE_STRING, {"ehci_root_hub.rh_descr"}}
		};
		mdb_call_dcmd("print", statep, DCMD_ADDRSPEC, 2, argv);
	}

	if (strcmp(driver_name, "ohci") == 0) {
		mdb_arg_t argv[] = {
		    {MDB_TYPE_STRING, {"ohci_state_t"}},
		    {MDB_TYPE_STRING, {"ohci_root_hub.rh_descr"}}
		};
		mdb_call_dcmd("print", statep, DCMD_ADDRSPEC, 2, argv);
	}

	if (strcmp(driver_name, "uhci") == 0) {
		mdb_arg_t argv[] = {
		    {MDB_TYPE_STRING, {"uhci_state_t"}},
		    {MDB_TYPE_STRING, {"uhci_root_hub.rh_descr"}}
		};
		mdb_call_dcmd("print", statep, DCMD_ADDRSPEC, 2, argv);
	}

	if (strcmp(driver_name, "hubd") == 0) {
		mdb_arg_t argv[] = {
		    {MDB_TYPE_STRING, {"hubd_t"}},
		    {MDB_TYPE_STRING, {"h_ep1_xdescr.uex_ep"}}
		};
		mdb_call_dcmd("print", statep, DCMD_ADDRSPEC, 2, argv);
	}

	if (strcmp(driver_name, "hid") == 0) {
		hid_state_t hidp;

		if (mdb_vread(&hidp, sizeof (hid_state_t), statep) != -1) {
			hidparser_handle hid_report;

			if (mdb_vread(&hid_report, sizeof (hidparser_handle),
			    (uintptr_t)hidp.hid_report_descr) != -1) {

				mdb_inc_indent(2);

				mdb_printf("\n");
				prt_usb_hid_item((uintptr_t)
				    hid_report.hidparser_handle_parse_tree);

				mdb_dec_indent(2);
			}
		}
	}

	mdb_printf("\n");

	return (DCMD_OK);
}

/* print hid report descriptor */
static void
prt_usb_hid_item(uintptr_t paddr)
{
	entity_item_t item;
	if (mdb_vread(&item, sizeof (entity_item_t), paddr) != -1) {

		prt_usb_hid_item_attrs((uintptr_t)item.entity_item_attributes);
		prt_usb_hid_item_params(&item);

		if (item.info.child) {
			mdb_inc_indent(4);
			prt_usb_hid_item((uintptr_t)item.info.child);
			mdb_dec_indent(4);
		}

		if (item.entity_item_right_sibling) {
			prt_usb_hid_item((uintptr_t)
			    item.entity_item_right_sibling);
		}
	}
}

static void
prt_usb_hid_item_params(entity_item_t *item)
{
	switch (item->entity_item_type) {
	case 0x80:
		mdb_printf("INPUT ");

		break;
	case 0x90:
		mdb_printf("OUTPUT ");

		break;
	case 0xA0:
		mdb_printf("COLLECTION ");

		break;
	case 0xB0:
		mdb_printf("FEATURE ");

		break;
	case 0xC0:
		mdb_printf("END_COLLECTION ");

		break;
	default:
		mdb_printf("MAIN_ITEM ");

		break;
	}

	prt_usb_hid_item_data((uintptr_t)item->entity_item_params,
	    item->entity_item_params_leng);

	mdb_printf("\n");
}

static void
prt_usb_hid_item_attrs(uintptr_t paddr)
{
	entity_attribute_t attr;

	if (mdb_vread(&attr, sizeof (entity_attribute_t), paddr) != -1) {

		prt_usb_hid_item_tags(attr.entity_attribute_tag);
		prt_usb_hid_item_data((uintptr_t)attr.entity_attribute_value,
		    attr.entity_attribute_length);

		mdb_printf("\n");

		if (attr.entity_attribute_next) {
			prt_usb_hid_item_attrs((uintptr_t)
			    attr.entity_attribute_next);
		}
	}
}

static void
prt_usb_hid_item_data(uintptr_t paddr, uint_t len)
{
	char data[4];
	int i;

	if (len > 4) {
		mdb_warn("Incorrect entity_item_length: 0x%x\n", len);

		return;
	}

	if (mdb_vread(data, len, paddr) != -1) {

		mdb_printf("( ");
		for (i = 0; i < len; i++) {
			mdb_printf("0x%02x ", data[i] & 0xff);
		}
		mdb_printf(")");
	}
}

static void
prt_usb_hid_item_tags(uint_t tag)
{
	switch (tag) {
	case 0x04:
		mdb_printf("usage page ");

		break;
	case 0x14:
		mdb_printf("logical minimum ");

		break;
	case 0x24:
		mdb_printf("logical maximum ");

		break;
	case 0x34:
		mdb_printf("physical minimum ");

		break;
	case 0x44:
		mdb_printf("physical maximum ");

		break;
	case 0x54:
		mdb_printf("exponent ");

		break;
	case 0x64:
		mdb_printf("unit ");

		break;
	case 0x74:
		mdb_printf("report size ");

		break;
	case 0x84:
		mdb_printf("report id ");

		break;
	case 0x94:
		mdb_printf("report count ");

		break;
	case 0x08:
		mdb_printf("usage ");

		break;
	case 0x18:
		mdb_printf("usage min ");

		break;
	case 0x28:
		mdb_printf("usage max ");

		break;

	default:
		mdb_printf("tag ");
	}
}

/* print the info required by "-v" */
static int
prt_usb_desc(uintptr_t usb_cfg, uint_t cfg_len)
{
	uintptr_t paddr = usb_cfg;
	uintptr_t pend = usb_cfg + cfg_len;
	uchar_t desc_type, nlen;
	usb_if_descr_t usb_if;
	ulong_t indent = 0;

	mdb_arg_t argv = {MDB_TYPE_STRING, {"usb_dev_descr_t"}};

	if (mdb_vread(&nlen, 1, paddr) == -1) {

		return (DCMD_ERR);
	}
	while ((paddr + nlen <= pend) && (nlen > 0)) {
		if (mdb_vread(&desc_type, 1, paddr + 1) == -1) {

			return (DCMD_ERR);
		}

		switch (desc_type) {
		case USB_DESCR_TYPE_DEV:
			mdb_printf("Device Descriptor\n");
			print_struct(paddr, nlen, &argv);

			break;
		case USB_DESCR_TYPE_CFG:
			indent = 4;
			mdb_inc_indent(indent);
			mdb_printf("Configuration Descriptor\n");
			print_descr(paddr, nlen, usb_cfg_descr, usb_cfg_item);
			mdb_dec_indent(indent);

			break;
		case USB_DESCR_TYPE_STRING:
			mdb_printf("String Descriptor\n");
			print_descr(paddr, nlen, usb_str_descr, usb_str_item);

			break;
		case USB_DESCR_TYPE_IF:
			indent = 8;
			mdb_inc_indent(indent);
			mdb_printf("Interface Descriptor\n");
			print_descr(paddr, nlen, usb_if_descr, usb_if_item);
			mdb_dec_indent(indent);
			mdb_vread(&usb_if, sizeof (usb_if_descr_t), paddr);

			break;
		case USB_DESCR_TYPE_EP:
			indent = 8;
			mdb_inc_indent(indent);
			mdb_printf("Endpoint Descriptor\n");
			print_descr(paddr, nlen, usb_ep_descr, usb_ep_item);
			mdb_dec_indent(indent);

			break;
		case USB_DESCR_TYPE_SS_EP_COMP:
			indent = 12;
			mdb_inc_indent(indent);
			mdb_printf("SuperSpeed Endpoint Companion "
			    "Descriptor\n");
			print_descr(paddr, nlen, usb_ep_ss_comp_descr,
			    usb_ep_ss_comp_item);
			mdb_dec_indent(indent);

			break;
		case USB_DESCR_TYPE_DEV_QLF:
			mdb_printf("Device_Qualifier Descriptor\n");
			print_descr(paddr, nlen, usb_qlf_descr, usb_qlf_item);

			break;
		case USB_DESCR_TYPE_OTHER_SPEED_CFG:
			indent = 4;
			mdb_inc_indent(indent);
			mdb_printf("Other_Speed_Configuration Descriptor\n");
			print_descr(paddr, nlen, usb_cfg_descr, usb_cfg_item);
			mdb_dec_indent(indent);

			break;
		case USB_DESCR_TYPE_IA:
			indent = 6;
			mdb_inc_indent(indent);
			mdb_printf("Interface_Association Descriptor\n");
			print_descr(paddr, nlen, usb_ia_descr, usb_ia_item);
			mdb_dec_indent(indent);

			break;
		case 0x21:	/* hid descriptor */
			indent = 12;
			mdb_inc_indent(indent);
			if (usb_if.bInterfaceClass == 0xe0 &&
			    usb_if.bInterfaceSubClass == 0x02) {
				mdb_printf("WA Descriptor\n");
				print_descr(paddr, nlen, usb_wa_descr,
				    usb_wa_item);
			} else {
				mdb_printf("HID Descriptor\n");
				print_descr(paddr, nlen, usb_hid_descr,
				    usb_hid_item);
			}
			mdb_dec_indent(indent);

			break;
		case 0x24:	/* class specific interfce descriptor */
			indent = 12;
			mdb_inc_indent(indent);
			if (usb_if.bInterfaceClass == 1 &&
			    usb_if.bInterfaceSubClass == 1) {
				mdb_printf("AudioControl_Interface: ");
				prt_usb_ac_desc(paddr, nlen);

			} else if (usb_if.bInterfaceClass == 1 &&
			    usb_if.bInterfaceSubClass == 2) {
				mdb_printf("AudioStream_Interface: ");
				prt_usb_as_desc(paddr, nlen);

			} else if (usb_if.bInterfaceClass == 0x0E &&
			    usb_if.bInterfaceSubClass == 1) {
				mdb_printf("VideoControl_Interface: ");
				prt_usb_vc_desc(paddr, nlen);


			} else if (usb_if.bInterfaceClass == 0x0E &&
			    usb_if.bInterfaceSubClass == 2) {
				mdb_printf("VideoStream_Interface: ");
				prt_usb_vs_desc(paddr, nlen);

			} else {
				mdb_printf("Unknown_Interface:"
				    "0x%x\n", desc_type);
				prt_usb_buf(paddr, nlen);
			}
			mdb_dec_indent(indent);

			break;
		case 0x25:	/* class specific endpoint descriptor */
			indent = 12;
			mdb_inc_indent(indent);
			if (usb_if.bInterfaceClass == 0x01) {
				mdb_printf("AudioEndpoint:\n");
				print_descr(paddr, nlen,
				    usb_as_ep_descr, usb_as_ep_item);

			} else if (usb_if.bInterfaceClass == 0x0E) {
				mdb_printf("VideoEndpoint:\n");
				print_descr(paddr, nlen,
				    usb_ep_descr, usb_ep_item);

			} else {
				mdb_printf("Unknown_Endpoint:"
				    "0x%x\n", desc_type);
				prt_usb_buf(paddr, nlen);
			}
			mdb_dec_indent(indent);

			break;
		default:
			mdb_inc_indent(indent);
			mdb_printf("Unknown Descriptor: 0x%x\n", desc_type);
			prt_usb_buf(paddr, nlen);
			mdb_dec_indent(indent);

			break;
		}

		paddr += nlen;
		if (mdb_vread(&nlen, 1, paddr) == -1) {

			return (DCMD_ERR);
		}
	};

	return (DCMD_OK);
}


/* print audio class specific control descriptor */
static int
prt_usb_ac_desc(uintptr_t addr, uint_t nlen)
{
	uchar_t sub_type;

	if (mdb_vread(&sub_type, 1, addr + 2) == -1) {

		return (DCMD_ERR);
	}
	switch (sub_type) {
	case 0x01:
		mdb_printf("header Descriptor\n");
		print_descr(addr, nlen,
		    usb_ac_header_descr, usb_ac_header_item);

		break;
	case 0x02:
		mdb_printf("input_terminal Descriptor\n");
		print_descr(addr, nlen,
		    usb_ac_input_term_descr, usb_ac_input_term_item);

		break;
	case 0x03:
		mdb_printf("output_terminal Descriptor\n");
		print_descr(addr, nlen,
		    usb_ac_output_term_descr, usb_ac_output_term_item);

		break;
	case 0x04:
		mdb_printf("mixer_unit Descriptor\n");
		print_descr(addr, nlen,
		    usb_ac_mixer_descr, usb_ac_mixer_item);

		break;
	case 0x05:
		mdb_printf("selector_unit Descriptor\n");
		print_descr(addr, nlen,
		    usb_ac_selector_descr, usb_ac_selector_item);

		break;
	case 0x06:
		mdb_printf("feature_unit Descriptor\n");
		print_descr(addr, nlen,
		    usb_ac_feature_descr, usb_ac_feature_item);

		break;
	case 0x07:
		mdb_printf("processing_unit Descriptor\n");
		print_descr(addr, nlen,
		    usb_ac_processing_descr, usb_ac_processing_item);

		break;
	case 0x08:
		mdb_printf("extension_unit Descriptor\n");
		print_descr(addr, nlen,
		    usb_ac_extension_descr, usb_ac_extension_item);

		break;
	default:
		mdb_printf("Unknown AC sub-descriptor 0x%x\n", sub_type);
		prt_usb_buf(addr, nlen);

		break;
	}

	return (DCMD_OK);
}

/* print audio class specific stream descriptor */
static int
prt_usb_as_desc(uintptr_t addr, uint_t nlen)
{
	uchar_t sub_type;

	if (mdb_vread(&sub_type, 1, addr + 2) == -1) {

		return (DCMD_ERR);
	}
	switch (sub_type) {
	case 0x01:
		mdb_printf("general_interface Descriptor\n");
		print_descr(addr, nlen,
		    usb_as_if_descr, usb_as_if_item);

		break;
	case 0x02:
		mdb_printf("format_type Descriptor\n");
		print_descr(addr, nlen,
		    usb_as_format_descr, usb_as_format_item);

		break;
	default:
		mdb_printf("Unknown AS sub-descriptor 0x%x\n", sub_type);
		prt_usb_buf(addr, nlen);

		break;
	}

	return (DCMD_OK);
}

/* print video class specific control descriptor */
static int
prt_usb_vc_desc(uintptr_t addr, uint_t nlen)
{
	uchar_t sub_type;

	if (mdb_vread(&sub_type, 1, addr + 2) == -1) {

		return (DCMD_ERR);
	}
	switch (sub_type) {
	case 0x01:
		mdb_printf("header Descriptor\n");
		print_descr(addr, nlen,
		    usb_vc_header_descr, usb_vc_header_item);

		break;
	case 0x02:
		mdb_printf("input_terminal Descriptor\n");
		print_descr(addr, nlen,
		    usb_vc_input_term_descr, usb_vc_input_term_item);

		break;
	case 0x03:
		mdb_printf("output_terminal Descriptor\n");
		print_descr(addr, nlen,
		    usb_vc_output_term_descr, usb_vc_output_term_item);

		break;
	case 0x04:
		mdb_printf("selector_unit Descriptor\n");
		print_descr(addr, nlen,
		    usb_vc_selector_descr, usb_vc_selector_item);

		break;
	case 0x05:
		mdb_printf("processing_unit Descriptor\n");
		print_descr(addr, nlen,
		    usb_vc_processing_descr, usb_vc_processing_item);

		break;
	case 0x06:
		mdb_printf("extension_unit Descriptor\n");
		print_descr(addr, nlen,
		    usb_vc_extension_descr, usb_vc_extension_item);

		break;
	default:
		mdb_printf("Unknown VC sub-descriptor 0x%x\n", sub_type);
		prt_usb_buf(addr, nlen);

		break;
	}

	return (DCMD_OK);
}

/* print video class specific stream descriptor */
static int
prt_usb_vs_desc(uintptr_t addr, uint_t nlen)
{
	uchar_t sub_type;

	if (mdb_vread(&sub_type, 1, addr + 2) == -1) {

		return (DCMD_ERR);
	}
	switch (sub_type) {
	case 0x01:
		mdb_printf("input_header Descriptor\n");
		print_descr(addr, nlen,
		    usb_vs_input_header_descr, usb_vs_input_header_item);

		break;
	case 0x02:
		mdb_printf("output_header Descriptor\n");
		print_descr(addr, nlen,
		    usb_vs_output_header_descr, usb_vs_output_header_item);

		break;
	case 0x03:
		mdb_printf("still_image_frame Descriptor\n");
		print_descr(addr, nlen,
		    usb_vs_still_image_descr, usb_vs_still_image_item);

		break;
	case 0x04:
		mdb_printf("format_uncompressed Descriptor\n");
		print_descr(addr, nlen,
		    usb_vs_format_uncps_descr, usb_vs_format_uncps_item);

		break;
	case 0x05:
		mdb_printf("frame_uncompressed Descriptor\n");
		print_descr(addr, nlen,
		    usb_vs_2frame_descr, usb_vs_2frame_item);

		break;
	case 0x06:
		mdb_printf("format_mjpeg Descriptor\n");
		print_descr(addr, nlen,
		    usb_vs_format_mjpeg_descr, usb_vs_format_mjpeg_item);

		break;
	case 0x07:
		mdb_printf("frame_mjpeg Descriptor\n");
		print_descr(addr, nlen,
		    usb_vs_2frame_descr, usb_vs_2frame_item);

		break;
	case 0x0A:
		mdb_printf("format_mpeg2ts Descriptor\n");
		print_descr(addr, nlen,
		    usb_vs_format_mp2ts_descr, usb_vs_format_mp2ts_item);

		break;
	case 0x0C:
		mdb_printf("format_dv Descriptor\n");
		print_descr(addr, nlen,
		    usb_vs_format_dv_descr, usb_vs_format_dv_item);

		break;
	case 0x0D:
		mdb_printf("color_matching Descriptor\n");
		print_descr(addr, nlen,
		    usb_vs_color_matching_descr, usb_vs_color_matching_item);

		break;
	default:
		mdb_printf("Unknown VS sub-descriptor 0x%x\n", sub_type);
		prt_usb_buf(addr, nlen);

		break;
	}

	return (DCMD_OK);
}

/* parse and print the descriptor items */
static int
print_descr(uintptr_t addr, uint_t nlen, usb_descr_item_t *item, uint_t nitem)
{
	int i, j;
	uint8_t buf[8];
	uint64_t value;
	uintptr_t paddr = addr;
	usb_descr_item_t *p = item;

	mdb_printf("{");
	for (i = 0; (i < nitem) && (paddr < addr + nlen); i++) {
		mdb_printf("\n    %s =", p->name);
		switch (p->nlen) {
		case 1:		/* uint8_t */
			if (mdb_vread(buf, 1, paddr) == -1) {

				return (DCMD_ERR);
			}
			value =  buf[0];

			break;
		case 2:		/* uint16_t */
			if (mdb_vread(buf, 2, paddr) == -1) {

				return (DCMD_ERR);
			}
			value = buf[0] | (buf[1] << 8);

			break;
		case 4:		/* uint32_t */
			if (mdb_vread(buf, 4, paddr) == -1) {

				return (DCMD_ERR);
			}
			value = buf[0] | (buf[1] << 8) |
			    (buf[2] << 16) | (buf[3] << 24);

			break;
		case 8:		/* uint64_t */
			if (mdb_vread(buf, 8, paddr) == -1) {

				return (DCMD_ERR);
			}
			value =	buf[4] | (buf[5] << 8) |
			    (buf[6] << 16) | (buf[7] << 24);
			value = buf[0] | (buf[1] << 8) |
			    (buf[2] << 16) | (buf[3] << 24) |
			    (value << 32);

			break;
		default:	/* byte array */
			value = 0;
			/* print an array instead of a value */
			for (j = 0; j < p->nlen - BYTE_OFFSET; j++) {
				if (mdb_vread(buf, 1, paddr + j) == -1) {

					break;
				}
				mdb_printf(" 0x%x", buf[0]);
			}

			break;
		}

		if (p->nlen > BYTE_OFFSET) {
			paddr += p->nlen - BYTE_OFFSET;
		} else {
			mdb_printf(" 0x%x", value);
			paddr += p->nlen;
		}

		p++;
	}

	/* print the unresolved bytes */
	if (paddr < addr + nlen) {
		mdb_printf("\n    ... =");
	}
	while (paddr < addr + nlen) {
		if (mdb_vread(buf, 1, paddr++) == -1) {

			break;
		}
		mdb_printf(" 0x%x", buf[0]);
	}
	mdb_printf("\n}\n");

	return (DCMD_OK);
}

/* print the buffer as a struct */
static int
print_struct(uintptr_t addr, uint_t nlen, mdb_arg_t *arg)
{
	mdb_ctf_id_t id;
	if (mdb_ctf_lookup_by_name(arg->a_un.a_str, &id) == 0) {

		mdb_call_dcmd("print", addr, DCMD_ADDRSPEC, 1, arg);
	} else {

		prt_usb_buf(addr, nlen);
	}

	return (DCMD_OK);
}

/* print the buffer as a byte array */
static int
prt_usb_buf(uintptr_t addr, uint_t nlen)
{
	int i;
	uchar_t val;

	mdb_printf("{\n");
	for (i = 0; i < nlen; i++) {
		if (mdb_vread(&val, 1, addr + i) == -1) {

			break;
		}
		mdb_printf("%02x ", val);
	}
	if (nlen) {
		mdb_printf("\n");
	}
	mdb_printf("}\n");

	return (DCMD_OK);
}
