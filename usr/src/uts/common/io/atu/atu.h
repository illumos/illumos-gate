/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright (c) 2003
 *	Daan Vreeken <Danovitsch@Vitsch.net>.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by Daan Vreeken.
 * 4. Neither the name of the author nor the names of any co-contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY DAAN VREEKEN AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL Daan Vreeken OR THE VOICES IN HIS HEAD
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
 * THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#ifndef	_ATU_H
#define	_ATU_H

#ifdef __cplusplus
extern "C" {
#endif

enum atu_radio_type {
	RadioRFMD,
	RadioRFMD2958,
	RadioRFMD2958_SMC,
	RadioIntersil,
	AT76C503_i3863,
	AT76C503_RFMD_ACC,
	AT76C505_RFMD
};

struct atu_dev_type {
	uint16_t		atu_vid;
	uint16_t		atu_pid;
	enum atu_radio_type	atu_radio;
	uint16_t		atu_quirk;
};

struct atu_firmware {
	enum atu_radio_type	atur_type;
	uint8_t			*atur_int;
	uint8_t			*atur_ext;
	uint_t			atur_int_size;
	uint_t			atur_ext_size;
	uint8_t			max_rssi;
};

struct atu_softc {
	struct ieee80211com	sc_ic;

	char			sc_name[16];
	uint32_t		sc_flags;
	enum atu_radio_type	sc_radio;
	uint16_t		sc_quirk;

	dev_info_t		*sc_dip;
	usb_client_dev_data_t	*sc_udev;
	usb_pipe_handle_t	sc_rx_pipe;
	usb_pipe_handle_t	sc_tx_pipe;

	kmutex_t		sc_genlock;
	kmutex_t		sc_txlock;
	kmutex_t		sc_rxlock;

	boolean_t		sc_need_sched;
	int			tx_queued;
	int			rx_queued;

	uint32_t		sc_tx_nobuf;
	uint32_t		sc_rx_nobuf;
	uint32_t		sc_rx_err;

	timeout_id_t		sc_scan_timer;

	int			(*sc_newstate)(struct ieee80211com *,
				    enum ieee80211_state, int);
};

#define	ATU_FLAG_RUNNING	(1<<0)
#define	ATU_FLAG_REATTACH	(1<<1)
#define	ATU_FLAG_RADIO_ON	(1<<2)

#define	ATU_RUNNING(sc)		((sc)->sc_flags & ATU_FLAG_RUNNING)
#define	ATU_REATTACH(sc)	((sc)->sc_flags & ATU_FLAG_REATTACH)
#define	ATU_RADIO_ON(sc)	((sc)->sc_flags & ATU_FLAG_RADIO_ON)

#define	ATU_LOCK(sc)		mutex_enter(&(sc)->sc_genlock)
#define	ATU_UNLOCK(sc)		mutex_exit(&(sc)->sc_genlock)

#define	ATU_RX_LIST_CNT		1
#define	ATU_TX_LIST_CNT		8
#define	ATU_MIN_FRAMELEN	sizeof (struct ieee80211_frame_min)

#define	ATU_RX_BUFSZ \
				(ATU_RX_HDRLEN + \
				sizeof (struct ieee80211_frame_addr4) + \
				2312 + 4)
#define	ATU_TX_BUFSZ \
				(ATU_TX_HDRLEN + \
				sizeof (struct ieee80211_frame_addr4) + 2312)

#define	ATU_DEF_CHAN		10
#define	ATU_DEF_TX_RATE		3
#define	ATU_JOIN_TIMEOUT	2000

#define	ATU_QUIRK_NONE		0x0000
#define	ATU_QUIRK_NO_REMAP	0x0001
#define	ATU_QUIRK_FW_DELAY	0x0002

#define	ATU_ENC_NONE		0
#define	ATU_ENC_WEP40		1
#define	ATU_ENC_WEP104		2

#define	ATU_MODE_IBSS		1
#define	ATU_MODE_STA		2

#define	ATU_POWER_ACTIVE	1
#define	ATU_POWER_SAVE		2
#define	ATU_POWER_SMART		3

#define	ATU_PREAMBLE_LONG	0
#define	ATU_PREAMBLE_SHORT	1

/* AT76c503 operating modes */
#define	ATU_DEV_UNKNOWN		0x00
#define	ATU_DEV_READY		0x01
#define	ATU_DEV_CONFIG		0x02
#define	ATU_DEV_DFU		0x03
#define	ATU_DEV_STAGE2		0x04

/* AT76c503 commands */
#define	CMD_SET_MIB		0x01
#define	CMD_START_SCAN		0x03
#define	CMD_JOIN		0x04
#define	CMD_START_IBSS		0x05
#define	CMD_RADIO		0x06
#define	CMD_RADIO_ON		0x06
#define	CMD_RADIO_OFF		0x07
#define	CMD_STARTUP		0x0b

/* AT76c503 wait status */
#define	STATUS_IDLE			0x00
#define	STATUS_COMPLETE			0x01
#define	STATUS_UNKNOWN			0x02
#define	STATUS_INVALID_PARAMETER	0x03
#define	STATUS_FUNCTION_NOT_SUPPORTED	0x04
#define	STATUS_TIME_OUT			0x07
#define	STATUS_IN_PROGRESS		0x08
#define	STATUS_HOST_FAILURE		0xff
#define	STATUS_SCAN_FAILED		0xf0

/*	Name				Type		Size	Index	*/
#define	MIB_LOCAL			0x01
#define	MIB_LOCAL_BEACON_ENABLE	MIB_LOCAL,	1,	2
#define	MIB_LOCAL_AUTO_RATE_FALLBACK	MIB_LOCAL,	1,	3
#define	MIB_LOCAL_SSID_SIZE		MIB_LOCAL,	1,	5
#define	MIB_LOCAL_PREAMBLE		MIB_LOCAL,	1,	9
#define	MIB_MAC_ADDR			0x02
#define	MIB_MAC_ADDR_STA		MIB_MAC_ADDR,	6,	0
#define	MIB_MAC				0x03
#define	MIB_MAC_FRAG			MIB_MAC,	2,	8
#define	MIB_MAC_RTS			MIB_MAC,	2,	10
#define	MIB_MAC_DESIRED_SSID		MIB_MAC,	32,	28
#define	MIB_MAC_MGMT			0x05
#define	MIB_MAC_MGMT_BEACON_PERIOD	MIB_MAC_MGMT,	2,	0
#define	MIB_MAC_MGMT_CURRENT_BSSID	MIB_MAC_MGMT,	6,	14
#define	MIB_MAC_MGMT_CURRENT_ESSID	MIB_MAC_MGMT,	32,	20
#define	MIB_MAC_MGMT_POWER_MODE		MIB_MAC_MGMT,	1,	53
#define	MIB_MAC_MGMT_IBSS_CHANGE	MIB_MAC_MGMT,	1,	54
#define	MIB_MAC_WEP			0x06
#define	MIB_MAC_WEP_PRIVACY_INVOKED	MIB_MAC_WEP,	1,	0
#define	MIB_MAC_WEP_KEY_ID		MIB_MAC_WEP,	1,	1
#define	MIB_MAC_WEP_ICV_ERROR_COUNT	MIB_MAC_WEP,	4,	4
#define	MIB_MAC_WEP_EXCLUDED_COUNT	MIB_MAC_WEP,	4,	8
#define	MIB_MAC_WEP_KEYS(nr)		MIB_MAC_WEP,	13,	12+(nr)*13
#define	MIB_MAC_WEP_ENCR_LEVEL		MIB_MAC_WEP,	1,	64
#define	MIB_PHY				0x07
#define	MIB_PHY_CHANNEL			MIB_PHY,	1,	20
#define	MIB_PHY_REG_DOMAIN		MIB_PHY,	1,	23
#define	MIB_FW_VERSION			0x08
#define	MIB_DOMAIN			0x09
#define	MIB_DOMAIN_POWER_LEVELS		MIB_DOMAIN,	14,	0
#define	MIB_DOMAIN_CHANNELS		MIB_DOMAIN,	14,	14

/* USB request types */
#define	ATU_CLASS_IF_IN \
				(USB_DEV_REQ_DEV_TO_HOST | \
				USB_DEV_REQ_TYPE_CLASS | \
				USB_DEV_REQ_RCPT_IF)

#define	ATU_VENDOR_IF_IN \
				(USB_DEV_REQ_DEV_TO_HOST | \
				USB_DEV_REQ_TYPE_VENDOR | \
				USB_DEV_REQ_RCPT_IF)

#define	ATU_VENDOR_DEV_OUT \
				(USB_DEV_REQ_HOST_TO_DEV | \
				USB_DEV_REQ_TYPE_VENDOR | \
				USB_DEV_REQ_RCPT_DEV)

#define	ATU_CLASS_IF_OUT \
				(USB_DEV_REQ_HOST_TO_DEV | \
				USB_DEV_REQ_TYPE_CLASS | \
				USB_DEV_REQ_RCPT_IF)

#define	ATU_VENDOR_IF_OUT \
				(USB_DEV_REQ_HOST_TO_DEV | \
				USB_DEV_REQ_TYPE_VENDOR | \
				USB_DEV_REQ_RCPT_IF)

/* standard DFU commands */
#define	DFU_DNLOAD		ATU_CLASS_IF_OUT, 0x01
#define	DFU_GETSTATUS		ATU_CLASS_IF_IN, 0x03
#define	DFU_GETSTATE		ATU_CLASS_IF_IN, 0x05
#define	DFU_REMAP		ATU_VENDOR_IF_OUT, 0x0a

/* DFU states */
#define	DFUState_AppIdle	0
#define	DFUState_AppDetach	1
#define	DFUState_DFUIdle	2
#define	DFUState_DnLoadSync	3
#define	DFUState_DnLoadBusy	4
#define	DFUState_DnLoadIdle	5
#define	DFUState_ManifestSync	6
#define	DFUState_Manifest	7
#define	DFUState_ManifestWait	8
#define	DFUState_UploadIdle	9
#define	DFUState_DFUError	10
#define	DFU_MaxBlockSize	1024

#pragma pack(1)
/* AT76c503 command header */
struct atu_cmd {
	uint8_t		Cmd;
	uint8_t		Reserved;
	uint16_t	Size;
};

/* CMD_SET_MIB command (0x01) */
struct atu_cmd_set_mib {
	/* AT76c503 command header */
	uint8_t		AtCmd;
	uint8_t		AtReserved;
	uint16_t	AtSize;
	/* MIB header */
	uint8_t		MIBType;
	uint8_t		MIBSize;
	uint8_t		MIBIndex;
	uint8_t		MIBReserved;
	/* MIB data */
	uint8_t		data[72];
};

/* CMD_STARTUP command (0x0b) */
struct atu_cmd_card_config {
	uint8_t		Cmd;
	uint8_t		Reserved;
	uint16_t	Size;

	uint8_t		ExcludeUnencrypted;
	uint8_t		PromiscuousMode;
	uint8_t		ShortRetryLimit;
	uint8_t		EncryptionType;
	uint16_t	RTS_Threshold;
	uint16_t	FragThreshold;
	uint8_t		BasicRateSet[4];
	uint8_t		AutoRateFallback;
	uint8_t		Channel;
	uint8_t		PrivacyInvoked;
	uint8_t		WEP_DefaultKeyID;
	uint8_t		SSID[IEEE80211_NWID_LEN];
	uint8_t		WEP_DefaultKey[4][13];
	uint8_t		SSID_Len;
	uint8_t		ShortPreamble;
	uint16_t	BeaconPeriod;
};

/* CMD_SCAN command (0x03) */
struct atu_cmd_do_scan {
	uint8_t		Cmd;
	uint8_t		Reserved;
	uint16_t	Size;

	uint8_t		BSSID[IEEE80211_ADDR_LEN];
	uint8_t		SSID[IEEE80211_NWID_LEN];
	uint8_t		ScanType;
	uint8_t		Channel;
	uint16_t	ProbeDelay;
	uint16_t	MinChannelTime;
	uint16_t	MaxChannelTime;
	uint8_t		SSID_Len;
	uint8_t		InternationalScan;
};
#define	ATU_SCAN_ACTIVE		0x00
#define	ATU_SCAN_PASSIVE	0x01

/* CMD_JOIN command (0x04) */
struct atu_cmd_join {
	uint8_t		Cmd;
	uint8_t		Reserved;
	uint16_t	Size;

	uint8_t		bssid[IEEE80211_ADDR_LEN];
	uint8_t		essid[32];
	uint8_t		bss_type;
	uint8_t		channel;
	uint16_t	timeout;
	uint8_t		essid_size;
	uint8_t		reserved;
};

/* CMD_START_IBSS (0x05) */
struct atu_cmd_start_ibss {
	uint8_t		Cmd;
	uint8_t		Reserved;
	uint16_t	Size;

	uint8_t		BSSID[IEEE80211_ADDR_LEN];
	uint8_t		SSID[32];
	uint8_t		BSSType;
	uint8_t		Channel;
	uint8_t		SSIDSize;
	uint8_t		Res[3];
};

/*
 * The At76c503 adapters come with different types of radios on them.
 * At this moment the driver supports adapters with RFMD and Intersil radios.
 */

/* The config structure of an RFMD radio */
struct atu_rfmd_conf {
	uint8_t		CR20[14];
	uint8_t		CR21[14];
	uint8_t		BB_CR[14];
	uint8_t		PidVid[4];
	uint8_t		MACAddr[IEEE80211_ADDR_LEN];
	uint8_t		RegulatoryDomain;
	uint8_t		LowPowerValues[14];
	uint8_t		NormalPowerValues[14];
	uint8_t		Reserved[3];
	/* then we have 84 bytes, somehow Windows reads 95?? */
	uint8_t		Rest[11];
};

/* The config structure of an Intersil radio */
struct atu_intersil_conf {
	uint8_t		MACAddr[IEEE80211_ADDR_LEN];
	/* From the HFA3861B manual : */
	/* Manual TX power control (7bit : -64 to 63) */
	uint8_t		CR31[14];
	/* TX power measurement */
	uint8_t		CR58[14];
	uint8_t		PidVid[4];
	uint8_t		RegulatoryDomain;
	uint8_t		Reserved[1];
};

struct atu_rx_hdr {
	uint16_t	length;
	uint8_t		rx_rate;
	uint8_t		newbss;
	uint8_t		fragmentation;
	uint8_t		rssi;
	uint8_t		link_quality;
	uint8_t		noise_level;
	uint32_t	rx_time;
};
#define	ATU_RX_HDRLEN	sizeof (struct atu_rx_hdr)

struct atu_tx_hdr {
	uint16_t	length;
	uint8_t		tx_rate;
	uint8_t		padding;
	uint8_t		reserved[4];
};
#define	ATU_TX_HDRLEN	sizeof (struct atu_tx_hdr)
#pragma pack()

static struct atu_dev_type atu_dev_table[] = {
	{ 0x0506, 0x0a01, RadioRFMD, ATU_QUIRK_NONE },
	{ 0x07b8, 0xb000, RadioRFMD, ATU_QUIRK_NONE },
	{ 0x083a, 0x3501, AT76C503_RFMD_ACC, ATU_QUIRK_NONE },
	{ 0x04a5, 0x9000, RadioIntersil, ATU_QUIRK_NONE },
	{ 0x04a5, 0x9001, RadioRFMD, ATU_QUIRK_NONE },
	{ 0x1668, 0x7605, RadioRFMD, ATU_QUIRK_NONE },
	{ 0x05dd, 0xff31, RadioIntersil, ATU_QUIRK_NONE },
	{ 0x12fd, 0x1001, RadioRFMD2958, ATU_QUIRK_NONE },
	{ 0x069a, 0x0821, RadioIntersil, ATU_QUIRK_NONE },
	{ 0x069a, 0x0320, RadioIntersil, ATU_QUIRK_NONE },
	{ 0x069a, 0x0321, RadioRFMD, ATU_QUIRK_NONE },
	{ 0x03eb, 0x7603, RadioIntersil, ATU_QUIRK_NONE },
	{ 0x03eb, 0x7604, AT76C503_i3863, ATU_QUIRK_NONE },
	{ 0x03eb, 0x7605, RadioRFMD, ATU_QUIRK_NONE },
	{ 0x03eb, 0x7606, AT76C505_RFMD, ATU_QUIRK_NONE },
	{ 0x03eb, 0x7613, RadioRFMD2958, ATU_QUIRK_NONE },
	{ 0x03eb, 0x7614, RadioRFMD2958_SMC,
    ATU_QUIRK_NO_REMAP | ATU_QUIRK_FW_DELAY },
	{ 0x03eb, 0x7617, RadioRFMD2958_SMC,
    ATU_QUIRK_NO_REMAP | ATU_QUIRK_FW_DELAY },
	{ 0x03eb, 0x3301, RadioRFMD, ATU_QUIRK_NONE },
	{ 0x050d, 0x0050, RadioRFMD, ATU_QUIRK_NONE },
	{ 0x0d8e, 0x7100, RadioIntersil, ATU_QUIRK_NONE },
	{ 0x0d8e, 0x7110, RadioIntersil, ATU_QUIRK_NONE },
	{ 0x049f, 0x0032, RadioRFMD, ATU_QUIRK_NONE },
	{ 0x07aa, 0x7613, RadioRFMD2958, ATU_QUIRK_NONE },
	{ 0x1371, 0x0013, RadioRFMD2958, ATU_QUIRK_NONE },
	{ 0x1371, 0x0002, RadioRFMD, ATU_QUIRK_NONE },
	{ 0x1371, 0x0014, RadioRFMD2958, ATU_QUIRK_NONE },
	{ 0x1371, 0x5743, RadioRFMD, ATU_QUIRK_NONE },
	{ 0x2001, 0x3200, RadioRFMD, ATU_QUIRK_NONE },
	{ 0x1044, 0x8003, RadioRFMD, ATU_QUIRK_NONE },
	{ 0x1690, 0x0701, RadioRFMD2958_SMC,
    ATU_QUIRK_NO_REMAP | ATU_QUIRK_FW_DELAY },
	{ 0x03f0, 0x011c, RadioIntersil, ATU_QUIRK_NONE },
	{ 0x8086, 0x0200, RadioIntersil, ATU_QUIRK_NONE },
	{ 0x04bb, 0x0919, RadioIntersil, ATU_QUIRK_NONE },
	{ 0x05dc, 0xa002, RadioRFMD, ATU_QUIRK_NONE },
	{ 0x066b, 0x2211, RadioIntersil, ATU_QUIRK_NONE },
	{ 0x077b, 0x2219, RadioRFMD, ATU_QUIRK_NONE },
	{ 0x077b, 0x2219, RadioRFMD, ATU_QUIRK_NONE },
	{ 0x1915, 0x2233, RadioRFMD2958, ATU_QUIRK_NONE },
	{ 0x0db0, 0x1020, RadioRFMD2958, ATU_QUIRK_NONE },
	{ 0x0864, 0x4100, RadioIntersil, ATU_QUIRK_NONE },
	{ 0x0864, 0x4102, RadioRFMD, ATU_QUIRK_NONE },
	{ 0x1557, 0x0002, RadioRFMD2958_SMC,
    ATU_QUIRK_NO_REMAP | ATU_QUIRK_FW_DELAY },
	{ 0x2019, 0x3220, RadioRFMD, ATU_QUIRK_NONE },
	{ 0x055d, 0xa000, AT76C503_i3863, ATU_QUIRK_NONE },
	{ 0x0681, 0x001b, RadioRFMD, ATU_QUIRK_NONE },
	{ 0x0d5c, 0xa001, RadioIntersil, ATU_QUIRK_NONE },
	{ 0x0d5c, 0xa002, AT76C503_RFMD_ACC, ATU_QUIRK_NONE },
	{ 0x0b3b, 0x1612, RadioIntersil, ATU_QUIRK_NONE },
	{ 0x0cde, 0x0001, RadioIntersil, ATU_QUIRK_NONE },
};

static struct atu_firmware atu_fw_table[] = {
	{
	    RadioRFMD,
	    atmel_fw_rfmd_int,
	    atmel_fw_rfmd_ext,
	    sizeof (atmel_fw_rfmd_int),
	    sizeof (atmel_fw_rfmd_ext),
	    0
	},
	{
	    RadioRFMD2958,
	    atmel_fw_rfmd2958_int,
	    atmel_fw_rfmd2958_ext,
	    sizeof (atmel_fw_rfmd2958_int),
	    sizeof (atmel_fw_rfmd2958_ext),
	    81
	},
	{
	    RadioRFMD2958_SMC,
	    atmel_fw_rfmd2958_smc_int,
	    atmel_fw_rfmd2958_smc_ext,
	    sizeof (atmel_fw_rfmd2958_smc_int),
	    sizeof (atmel_fw_rfmd2958_smc_ext),
	    0
	},
	{
	    RadioIntersil,
	    atmel_fw_intersil_int,
	    atmel_fw_intersil_ext,
	    sizeof (atmel_fw_intersil_int),
	    sizeof (atmel_fw_intersil_ext),
	    0
	},
	{
	    AT76C503_i3863,
	    atmel_at76c503_i3863_fw_int,
	    atmel_at76c503_i3863_fw_ext,
	    sizeof (atmel_at76c503_i3863_fw_int),
	    sizeof (atmel_at76c503_i3863_fw_ext),
	    0
	},
	{
	    AT76C503_RFMD_ACC,
	    atmel_at76c503_rfmd_acc_fw_int,
	    atmel_at76c503_rfmd_acc_fw_ext,
	    sizeof (atmel_at76c503_rfmd_acc_fw_int),
	    sizeof (atmel_at76c503_rfmd_acc_fw_ext),
	    0
	},
	{
	    AT76C505_RFMD,
	    atmel_at76c505_rfmd_fw_int,
	    atmel_at76c505_rfmd_fw_ext,
	    sizeof (atmel_at76c505_rfmd_fw_int),
	    sizeof (atmel_at76c505_rfmd_fw_ext),
	    0
	}
};

#ifdef __cplusplus
}
#endif

#endif	/* _ATU_H */
