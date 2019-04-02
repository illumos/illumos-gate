/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2019 Joyent, Inc.
 */

/*
 * Routines to access, parse, and manage the USB Binary Object Store
 */

#define	USBA_FRAMEWORK
#include <sys/usb/usba/usba_impl.h>
#include <sys/strsun.h>
#include <sys/sysmacros.h>

static size_t
usba_bos_parse_bos_descr(const uchar_t *buf, size_t buflen,
    usb_bos_descr_t *bosp, size_t rlen)
{
	if (buf == NULL || bosp == NULL || buflen < USB_BOS_PACKED_SIZE ||
	    buf[1] != USB_DESCR_TYPE_BOS) {
		return (USB_PARSE_ERROR);
	}

	return (usb_parse_data("ccsc", buf, buflen, bosp, rlen));
}

static boolean_t
usba_bos_parse_usb2ext(const uchar_t *buf, size_t buflen, usb_bos_t *bosp)
{
	size_t len;

	if (buflen != USB_BOS_USB2EXT_PACKED_SIZE) {
		return (B_FALSE);
	}

	len = usb_parse_data("cccl", buf, buflen, &bosp->ubos_caps.ubos_usb2,
	    sizeof (usb_bos_usb2ext_t));
	return (len == sizeof (usb_bos_usb2ext_t));
}

static boolean_t
usba_bos_parse_superspeed(const uchar_t *buf, size_t buflen, usb_bos_t *bosp)
{
	size_t len;

	if (buflen != USB_BOS_SSUSB_PACKED_SIZE) {
		return (B_FALSE);
	}

	len = usb_parse_data("ccccsccs", buf, buflen,
	    &bosp->ubos_caps.ubos_ssusb, sizeof (usb_bos_ssusb_t));
	return (len == sizeof (usb_bos_ssusb_t));
}

static boolean_t
usba_bos_parse_container(const uchar_t *buf, size_t buflen, usb_bos_t *bosp)
{
	size_t len;

	if (buflen != USB_BOS_CONTAINER_PACKED_SIZE) {
		return (B_FALSE);
	}

	len = usb_parse_data("cccc16c", buf, buflen,
	    &bosp->ubos_caps.ubos_container, sizeof (usb_bos_container_t));
	return (len == sizeof (usb_bos_container_t));
}

static boolean_t
usba_bos_parse_precision_time(const uchar_t *buf, size_t buflen,
    usb_bos_t *bosp)
{
	size_t len;

	if (buflen != USB_BOS_PRECISION_TIME_PACKED_SIZE) {
		return (B_FALSE);
	}

	len = usb_parse_data("ccc", buf, buflen, &bosp->ubos_caps.ubos_time,
	    sizeof (usb_bos_precision_time_t));
	/*
	 * The actual size of this structure will usually be rounded up to four
	 * bytes by the compiler, therefore we need to compare against the
	 * packed size.
	 */
	return (len == USB_BOS_PRECISION_TIME_PACKED_SIZE);
}

/*
 * Validate that the BOS looks reasonable. This means the following:
 *
 * - We read the whole length of the descriptor
 * - The total number of capabilities doesn't exceed the expected value
 * - The length of each device capabilities fits within our expected range
 *
 * After we finish that up, go through and save all of the valid BOS
 * descriptors, unpacking the ones that we actually understand.
 */
static boolean_t
usba_bos_save(usba_device_t *ud, const mblk_t *mp, usb_bos_descr_t *bdesc)
{
	size_t len = MBLKL(mp);
	const uchar_t *buf = mp->b_rptr;
	uint_t ncaps, nalloc;
	usb_bos_t *bos;

	if (bdesc->bLength != USB_BOS_PACKED_SIZE ||
	    bdesc->bNumDeviceCaps == 0 || len < USB_BOS_PACKED_SIZE ||
	    len < bdesc->wTotalLength) {
		return (B_FALSE);
	}

	len = MIN(len, bdesc->wTotalLength);
	buf += USB_BOS_PACKED_SIZE;
	len -= USB_BOS_PACKED_SIZE;

	if (len < USB_DEV_CAP_PACKED_SIZE) {
		return (B_FALSE);
	}

	ncaps = 0;
	while (len > 0) {
		usb_dev_cap_descr_t dev;

		if (usb_parse_data("ccc", buf, len, &dev, sizeof (dev)) !=
		    USB_DEV_CAP_PACKED_SIZE) {
			return (B_FALSE);
		}

		if (dev.bDescriptorType != USB_DESCR_TYPE_DEV_CAPABILITY ||
		    dev.bLength > len) {
			return (B_FALSE);
		}

		ncaps++;
		len -= dev.bLength;
		buf += dev.bLength;
	}

	if (ncaps != bdesc->bNumDeviceCaps) {
		return (B_FALSE);
	}

	nalloc = ncaps;
	bos = kmem_zalloc(sizeof (usb_bos_t) * nalloc, KM_SLEEP);
	buf = mp->b_rptr + USB_BOS_PACKED_SIZE;
	len = MIN(MBLKL(mp), bdesc->wTotalLength) - USB_BOS_PACKED_SIZE;
	ncaps = 0;
	while (len > 0) {
		usb_dev_cap_descr_t dev;
		boolean_t valid;

		if (usb_parse_data("ccc", buf, len, &dev, sizeof (dev)) !=
		    USB_DEV_CAP_PACKED_SIZE) {
			goto fail;
		}

		bos[ncaps].ubos_length = dev.bLength;
		bos[ncaps].ubos_type = dev.bDevCapabilityType;

		valid = B_FALSE;
		switch (dev.bDevCapabilityType) {
		case USB_BOS_TYPE_USB2_EXT:
			valid = usba_bos_parse_usb2ext(buf, dev.bLength,
			    &bos[ncaps]);
			break;
		case USB_BOS_TYPE_SUPERSPEED:
			valid = usba_bos_parse_superspeed(buf, dev.bLength,
			    &bos[ncaps]);
			break;
		case USB_BOS_TYPE_CONTAINER:
			valid = usba_bos_parse_container(buf, dev.bLength,
			    &bos[ncaps]);
			break;
		case USB_BOS_TYPE_PRECISION_TIME:
			valid = usba_bos_parse_precision_time(buf, dev.bLength,
			    &bos[ncaps]);
			break;
		default:
			/*
			 * Override the type to one that we know isn't used to
			 * indicate that the caller can't rely on the type
			 * that's present here.
			 */
			bos[ncaps].ubos_type = USB_BOS_TYPE_INVALID;
			bcopy(buf, bos[ncaps].ubos_caps.ubos_raw, dev.bLength);
			valid = B_TRUE;
			break;
		}

		if (valid) {
			ncaps++;
		} else {
			bos[ncaps].ubos_length = 0;
			bos[ncaps].ubos_type = USB_BOS_TYPE_INVALID;
			bzero(bos[ncaps].ubos_caps.ubos_raw,
			    sizeof (bos[ncaps].ubos_caps.ubos_raw));
		}
		len -= dev.bLength;
		buf += dev.bLength;
	}

	ud->usb_bos_nalloc = nalloc;
	ud->usb_bos_nents = ncaps;
	ud->usb_bos = bos;

	return (B_TRUE);

fail:
	kmem_free(bos, sizeof (usb_bos_t) * nalloc);
	return (B_FALSE);
}

/*
 * Read the Binary Object Store (BOS) data from the device and attempt to parse
 * it. Do not fail to attach the device if we cannot get all of the information
 * at this time. While certain aspects of the BOS are required for Windows,
 * which suggests that we could actually rely on it, we haven't historically.
 */
void
usba_get_binary_object_store(dev_info_t *dip, usba_device_t *ud)
{
	int			rval;
	mblk_t			*mp = NULL;
	usb_cr_t		completion_reason;
	usb_cb_flags_t		cb_flags;
	usb_pipe_handle_t	ph;
	size_t			size;
	usb_bos_descr_t		bos;

	/*
	 * The BOS is only supported on USB 3.x devices. Therefore if the bcdUSB
	 * is greater than USB 2.0, we can check this. Note, USB 3.x devices
	 * that are linked on a USB device will report version 2.1 in the bcdUSB
	 * field.
	 */
	if (ud->usb_dev_descr->bcdUSB <= 0x200) {
		return;
	}

	ph = usba_get_dflt_pipe_handle(dip);

	/*
	 * First get just the BOS descriptor itself.
	 */
	rval = usb_pipe_sync_ctrl_xfer(dip, ph,
	    USB_DEV_REQ_DEV_TO_HOST | USB_DEV_REQ_TYPE_STANDARD,
	    USB_REQ_GET_DESCR,			/* bRequest */
	    (USB_DESCR_TYPE_BOS << 8),		/* wValue */
	    0,					/* wIndex */
	    USB_BOS_PACKED_SIZE,		/* wLength */
	    &mp, USB_ATTRS_SHORT_XFER_OK,
	    &completion_reason, &cb_flags, 0);

	if (rval != USB_SUCCESS) {
		return;
	}

	size = usba_bos_parse_bos_descr(mp->b_rptr, MBLKL(mp), &bos,
	    sizeof (bos));
	freemsg(mp);
	mp = NULL;
	if (size < USB_BOS_PACKED_SIZE) {
		return;
	}

	/*
	 * Check to see if there are any capabilities and if it's worth getting
	 * the whole BOS.
	 */
	if (bos.bLength != USB_BOS_PACKED_SIZE || bos.bNumDeviceCaps == 0) {
		return;
	}

	rval = usb_pipe_sync_ctrl_xfer(dip, ph,
	    USB_DEV_REQ_DEV_TO_HOST | USB_DEV_REQ_TYPE_STANDARD,
	    USB_REQ_GET_DESCR,			/* bRequest */
	    (USB_DESCR_TYPE_BOS << 8),		/* wValue */
	    0,					/* wIndex */
	    bos.wTotalLength,			/* wLength */
	    &mp, USB_ATTRS_SHORT_XFER_OK,
	    &completion_reason, &cb_flags, 0);

	if (rval != USB_SUCCESS) {
		return;
	}

	size = usba_bos_parse_bos_descr(mp->b_rptr, MBLKL(mp), &bos,
	    sizeof (bos));
	if (size < USB_BOS_PACKED_SIZE) {
		freemsg(mp);
		return;
	}

	if (!usba_bos_save(ud, mp, &bos)) {
		freemsg(mp);
		return;
	}

	ud->usb_bos_mp = mp;
}

static void
usba_add_superspeed_props(dev_info_t *dip, usb_bos_ssusb_t *ssusb)
{
	char *supported[4];
	uint_t nsup = 0;
	char *min;

	if (ssusb->wSpeedsSupported & USB_BOS_SSUSB_SPEED_LOW) {
		supported[nsup++] = "low-speed";
	}

	if (ssusb->wSpeedsSupported & USB_BOS_SSUSB_SPEED_FULL) {
		supported[nsup++] = "full-speed";
	}

	if (ssusb->wSpeedsSupported & USB_BOS_SSUSB_SPEED_HIGH) {
		supported[nsup++] = "high-speed";
	}

	if (ssusb->wSpeedsSupported & USB_BOS_SSUSB_SPEED_SUPER) {
		supported[nsup++] = "super-speed";
	}

	if (nsup != 0 && ndi_prop_update_string_array(DDI_DEV_T_NONE, dip,
	    "usb-supported-speeds", supported, nsup) != DDI_PROP_SUCCESS) {
		USB_DPRINTF_L2(DPRINT_MASK_USBA, NULL, "failed to add "
		    "usb-supported-speeds property");
	}

	switch (ssusb->bFunctionalitySupport) {
	case 0:
		min = "low-speed";
		break;
	case 1:
		min = "full-speed";
		break;
	case 2:
		min = "high-speed";
		break;
	case 3:
		min = "super-speed";
		break;
	default:
		min = NULL;
	}

	if (min != NULL && ndi_prop_update_string(DDI_DEV_T_NONE, dip,
	    "usb-minimum-speed", min) != DDI_PROP_SUCCESS) {
		USB_DPRINTF_L2(DPRINT_MASK_USBA, NULL, "failed to add "
		    "usb-minimum-speed property");
	}
}

static void
usba_add_container_props(dev_info_t *dip, usb_bos_container_t *cp)
{
	if (ndi_prop_update_byte_array(DDI_DEV_T_NONE, dip, "usb-container-id",
	    cp->ContainerId, sizeof (cp->ContainerId)) != DDI_PROP_SUCCESS) {
		USB_DPRINTF_L2(DPRINT_MASK_USBA, NULL, "failed to add "
		    "usb-container-id property");
	}
}

void
usba_add_binary_object_store_props(dev_info_t *dip, usba_device_t *ud)
{
	uint_t i;

	if (ud->usb_bos == NULL) {
		return;
	}

	for (i = 0; i < ud->usb_bos_nents; i++) {
		usb_bos_t *bos = &ud->usb_bos[i];

		switch (bos->ubos_type) {
		case USB_BOS_TYPE_SUPERSPEED:
			usba_add_superspeed_props(dip,
			    &bos->ubos_caps.ubos_ssusb);
			break;
		case USB_BOS_TYPE_CONTAINER:
			usba_add_container_props(dip,
			    &bos->ubos_caps.ubos_container);
			break;
		default:
			/*
			 * This is a capability that we're not going to add
			 * devinfo properties to describe.
			 */
			continue;
		}
	}
}

void
usba_free_binary_object_store(usba_device_t *ud)
{
	if (ud->usb_bos_mp != NULL) {
		freemsg(ud->usb_bos_mp);
		ud->usb_bos_mp = NULL;
	}

	if (ud->usb_bos != NULL) {
		kmem_free(ud->usb_bos, sizeof (usb_bos_t) * ud->usb_bos_nalloc);
		ud->usb_bos = NULL;
		ud->usb_bos_nalloc = ud->usb_bos_nents = 0;
	}
}
