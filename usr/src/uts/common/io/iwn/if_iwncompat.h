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
 * Copyright 2016 Hans Rosenfeld <rosenfeld@grumpf.hope-2000.org>
 */

#ifndef _IF_IWNCOMPAT_H
#define	_IF_IWNCOMPAT_H

/* XXX Added for NetBSD */
#define	IEEE80211_NO_HT

/*
 * QoS  definitions
 */

#define	AC_NUM		(4)	/* the number of access category */

/*
 * index of every AC in firmware
 */
#define	QOS_AC_BK	(0)
#define	QOS_AC_BE	(1)
#define	QOS_AC_VI	(2)
#define	QOS_AC_VO	(3)
#define	QOS_AC_INVALID	(-1)

#define	QOS_CW_RANGE_MIN	(0)	/* exponential of 2 */
#define	QOS_CW_RANGE_MAX	(15)	/* exponential of 2 */
#define	QOS_TXOP_MIN		(0)	/* unit of 32 microsecond */
#define	QOS_TXOP_MAX		(255)	/* unit of 32 microsecond */
#define	QOS_AIFSN_MIN		(2)
#define	QOS_AIFSN_MAX		(15)	/* undefined */

/*
 * masks for flags of QoS parameter command
 */
#define	QOS_PARAM_FLG_UPDATE_EDCA	(0x01)
#define	QOS_PARAM_FLG_TGN		(0x02)

/*
 * index of TX queue for every AC
 */
#define	QOS_AC_BK_TO_TXQ	(3)
#define	QOS_AC_BE_TO_TXQ	(2)
#define	QOS_AC_VI_TO_TXQ	(1)
#define	QOS_AC_VO_TO_TXQ	(0)
#define	TXQ_FOR_AC_MIN		(0)
#define	TXQ_FOR_AC_MAX		(3)
#define	TXQ_FOR_AC_INVALID	(-1)
#define	NON_QOS_TXQ		QOS_AC_BE_TO_TXQ
#define	QOS_TXQ_FOR_MGT		QOS_AC_VO_TO_TXQ

#define	WME_TID_MIN	(0)
#define	WME_TID_MAX	(7)
#define	WME_TID_INVALID	((uint8_t)-1)

#define	PCI_VENDOR_INTEL	0x8086		/* Intel */

/* WiFi Link 1000 */
#define	PCI_PRODUCT_INTEL_WIFI_LINK_1000_1	0x0083
#define	PCI_PRODUCT_INTEL_WIFI_LINK_1000_2	0x0084

/* Centrino Wireless-N 100 */
#define	PCI_PRODUCT_INTEL_WIFI_LINK_100_1	0x08ae
#define	PCI_PRODUCT_INTEL_WIFI_LINK_100_2	0x08af

/* Centrino Wireless-N 105 */
#define	PCI_PRODUCT_INTEL_WIFI_LINK_105_1	0x0894
#define	PCI_PRODUCT_INTEL_WIFI_LINK_105_2	0x0895

/* Centrino Wireless-N 130 */
#define	PCI_PRODUCT_INTEL_WIFI_LINK_130_1	0x0896
#define	PCI_PRODUCT_INTEL_WIFI_LINK_130_2	0x0897

/* Centrino Wireless-N 135 */
#define	PCI_PRODUCT_INTEL_WIFI_LINK_135_1	0x0892
#define	PCI_PRODUCT_INTEL_WIFI_LINK_135_2	0x0893

/* Centrino Wireless-N 1030 */
#define	PCI_PRODUCT_INTEL_WIFI_LINK_1030_1	0x008a
#define	PCI_PRODUCT_INTEL_WIFI_LINK_1030_2	0x008b

/* Centrino Wireless-N 2200 */
#define	PCI_PRODUCT_INTEL_WIFI_LINK_2200_1	0x0890
#define	PCI_PRODUCT_INTEL_WIFI_LINK_2200_2	0x0891

/* Centrino Wireless-N 2230 */
#define	PCI_PRODUCT_INTEL_WIFI_LINK_2230_1	0x0887
#define	PCI_PRODUCT_INTEL_WIFI_LINK_2230_2	0x0888

/* Wireless WiFi Link 4965 */
#define	PCI_PRODUCT_INTEL_WIFI_LINK_4965_1	0x4229
#define	PCI_PRODUCT_INTEL_WIFI_LINK_4965_2	0x4230
#define	PCI_PRODUCT_INTEL_WIFI_LINK_4965_3	0x422d
#define	PCI_PRODUCT_INTEL_WIFI_LINK_4965_4	0x4233

/* WiFi Link 5100 */
#define	PCI_PRODUCT_INTEL_WIFI_LINK_5100_1	0x4232
#define	PCI_PRODUCT_INTEL_WIFI_LINK_5100_2	0x4237

/* WiFi Link 5150 */
#define	PCI_PRODUCT_INTEL_WIFI_LINK_5150_1	0x423c
#define	PCI_PRODUCT_INTEL_WIFI_LINK_5150_2	0x423d

/* WiFi Link 5300 */
#define	PCI_PRODUCT_INTEL_WIFI_LINK_5300_1	0x4235
#define	PCI_PRODUCT_INTEL_WIFI_LINK_5300_2	0x4236

/* WiFi Link 5350 */
#define	PCI_PRODUCT_INTEL_WIFI_LINK_5350_1	0x423a
#define	PCI_PRODUCT_INTEL_WIFI_LINK_5350_2	0x423b

/* Centrino Advanced-N 6200 */
#define	PCI_PRODUCT_INTEL_WIFI_LINK_6000_IPA_1	0x422c
#define	PCI_PRODUCT_INTEL_WIFI_LINK_6000_IPA_2	0x4239

/* Centrino Advanced-N 6205 */
#define	PCI_PRODUCT_INTEL_WIFI_LINK_6005_2X2_1	0x0082
#define	PCI_PRODUCT_INTEL_WIFI_LINK_6005_2X2_2	0x0085

/* Centrino Advanced-N 6230 */
#define	PCI_PRODUCT_INTEL_WIFI_LINK_6230_1	0x0090
#define	PCI_PRODUCT_INTEL_WIFI_LINK_6230_2	0x0091

/* Centrino Advanced-N 6235 */
#define	PCI_PRODUCT_INTEL_WIFI_LINK_6235	0x088e
#define	PCI_PRODUCT_INTEL_WIFI_LINK_6235_2	0x088f

/* Centrino Advanced-N 6250 */
#define	PCI_PRODUCT_INTEL_WIFI_LINK_6050_2X2_1	0x0087
#define	PCI_PRODUCT_INTEL_WIFI_LINK_6050_2X2_2	0x0089

/* Centrino Ultimate-N 6300 */
#define	PCI_PRODUCT_INTEL_WIFI_LINK_6000_3X3_1	0x422b
#define	PCI_PRODUCT_INTEL_WIFI_LINK_6000_3X3_2	0x4238

#define	__inline	inline
#define	__packed	__attribute__((packed))
#define	__arraycount(x)	ARRAY_SIZE(x)
#define	abs(x)		ABS(x)

#define	le16toh(x) LE_16(x)
#define	htole16(x) LE_16(x)
#define	le32toh(x) LE_32(x)
#define	htole32(x) LE_32(x)
#define	le64toh(x) LE_64(x)
#define	htole64(x) LE_64(x)

#define	IWN_SUCCESS		0
#define	IWN_FAIL		EIO

#endif	/* _IF_IWNCOMPAT_H */
