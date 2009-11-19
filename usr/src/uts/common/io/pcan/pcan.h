/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright (c) 1997, 1998, 1999
 *      Bill Paul <wpaul@ctr.columbia.edu>.  All rights reserved.
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
 *      This product includes software developed by Bill Paul.
 * 4. Neither the name of the author nor the names of any co-contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY Bill Paul AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL Bill Paul OR THE VOICES IN HIS HEAD
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
 * THE POSSIBILITY OF SUCH DAMAGE.
 */


#ifndef _SYS_PCAN_H
#define	_SYS_PCAN_H

#ifdef	__cplusplus
extern "C" {
#endif

#define	AN_TIMEOUT	600000

/*
 * Size of Aironet I/O space.
 */
#define	AN_IOSIZ		0x40

#define	PCAN_DEVICE_PCI		0x100
#define	PCAN_DEVICE_PCCARD	0x200

/*
 * Hermes register definitions and what little I know about them.
 */

/*
 * Hermes command/status registers.
 */
#define	AN_COMMAND(p)	(p->pcan_device_type == PCAN_DEVICE_PCI ? 0x00 : 0x00)
#define	AN_PARAM0(p)	(p->pcan_device_type == PCAN_DEVICE_PCI ? 0x04 : 0x02)
#define	AN_PARAM1(p)	(p->pcan_device_type == PCAN_DEVICE_PCI ? 0x08 : 0x04)
#define	AN_PARAM2(p)	(p->pcan_device_type == PCAN_DEVICE_PCI ? 0x0c : 0x06)
#define	AN_STATUS(p)	(p->pcan_device_type == PCAN_DEVICE_PCI ? 0x10 : 0x08)
#define	AN_RESP0(p)	(p->pcan_device_type == PCAN_DEVICE_PCI ? 0x14 : 0x0A)
#define	AN_RESP1(p)	(p->pcan_device_type == PCAN_DEVICE_PCI ? 0x18 : 0x0C)
#define	AN_RESP2(p)	(p->pcan_device_type == PCAN_DEVICE_PCI ? 0x1c : 0x0E)
#define	AN_LINKSTAT(p)	(p->pcan_device_type == PCAN_DEVICE_PCI ? 0x20 : 0x10)

/*
 * Command register
 */
#define	AN_CMD_BUSY		0x8000 /* busy bit */
#define	AN_CMD_NO_ACK		0x0080 /* don't acknowledge command */
#define	AN_CMD_CODE_MASK	0x003F
#define	AN_CMD_QUAL_MASK	0x7F00

/*
 * Command codes
 */
#define	AN_CMD_NOOP		0x0000 /* no-op */
#define	AN_CMD_ENABLE		0x0001 /* enable */
#define	AN_CMD_DISABLE		0x0002 /* disable */
#define	AN_CMD_FORCE_SYNCLOSS	0x0003 /* force loss of sync */
#define	AN_CMD_FW_RESTART	0x0004 /* firmware resrart */
#define	AN_CMD_HOST_SLEEP	0x0005
#define	AN_CMD_MAGIC_PKT	0x0006
#define	AN_CMD_READCFG		0x0008
#define	AN_CMD_ALLOC_MEM	0x000A /* allocate NIC memory */
#define	AN_CMD_TX		0x000B /* transmit */
#define	AN_CMD_DEALLOC_MEM	0x000C
#define	AN_CMD_NOOP2		0x0010
#define	AN_CMD_ALLOC_DESC	0x0020
#define	AN_CMD_ACCESS		0x0021
#define	AN_CMD_ALLOC_BUF	0x0028
#define	AN_CMD_PSP_NODES	0x0030
#define	AN_CMD_SET_PHYREG	0x003E
#define	AN_CMD_TX_TEST		0x003F
#define	AN_CMD_SLEEP		0x0085
#define	AN_CMD_SCAN		0x0103
#define	AN_CMD_SAVECFG		0x0108

/*
 * Reclaim qualifier bit, applicable to the
 * TX command.
 */
#define	AN_RECLAIM		0x0100 /* reclaim NIC memory */

/*
 * MPI 350 DMA descriptor information
 */
#define	AN_DESCRIPTOR_TX	0x01
#define	AN_DESCRIPTOR_RX	0x02
#define	AN_DESCRIPTOR_TXCMP	0x04
#define	AN_DESCRIPTOR_HOSTWRITE 0x08
#define	AN_DESCRIPTOR_HOSTREAD  0x10
#define	AN_DESCRIPTOR_HOSTRW    0x20

#define	AN_MAX_RX_DESC 1
#define	AN_MAX_TX_DESC 1
#define	AN_HOSTBUFSIZ 1840

/*
 * dma descriptor definition for miniPci card.
 * the miniPci card only works on x86.
 */
struct an_card_rid_desc
{
	uint32_t	an_rid:16;
	uint32_t	an_len:15;
	uint32_t	an_valid:1;
	uint64_t	an_phys;
};

struct an_card_rx_desc
{
	uint32_t	an_ctrl:15;
	uint32_t	an_done:1;
	uint32_t	an_len:15;
	uint32_t	an_valid:1;
	uint64_t	an_phys;
};

struct an_card_tx_desc
{
	uint32_t	an_offset:15;
	uint32_t	an_eoc:1;
	uint32_t	an_len:15;
	uint32_t	an_valid:1;
	uint64_t	an_phys;
};

#define	AN_MAX_DATALEN	4096
#define	AN_RID_BUFFER_SIZE	AN_MAX_DATALEN
#define	AN_RX_BUFFER_SIZE	AN_HOSTBUFSIZ
#define	AN_TX_BUFFER_SIZE	AN_HOSTBUFSIZ
#define	AN_HOST_DESC_OFFSET	0x800
#define	AN_RX_DESC_OFFSET  (AN_HOST_DESC_OFFSET + \
    sizeof (struct an_card_rid_desc))
#define	AN_TX_DESC_OFFSET (AN_RX_DESC_OFFSET + \
	(AN_MAX_RX_DESC * sizeof (struct an_card_rx_desc)))

/*
 * ACCESS command qualifier bits.
 */
#define	AN_ACCESS_READ		0x0000
#define	AN_ACCESS_WRITE		0x0100

/*
 * PROGRAM command qualifier bits.
 */
#define	AN_PROGRAM_DISABLE	0x0000
#define	AN_PROGRAM_ENABLE_RAM	0x0100
#define	AN_PROGRAM_ENABLE_NVRAM	0x0200
#define	AN_PROGRAM_NVRAM	0x0300

/*
 * Status register values
 */
#define	AN_STAT_CMD_CODE	0x003F
#define	AN_STAT_CMD_RESULT	0x7F00

/*
 * Linkstat register
 */
#define	AN_LINKSTAT_ASSOCIATED		0x0400
#define	AN_LINKSTAT_AUTHFAIL		0x0300
#define	AN_LINKSTAT_ASSOC_FAIL		0x8400	/* (low byte is reason code) */
#define	AN_LINKSTAT_DISASSOC		0x8200	/* (low byte is reason code) */
#define	AN_LINKSTAT_DEAUTH		0x8100	/* (low byte is reason code) */
#define	AN_LINKSTAT_SYNCLOST_TSF	0x8004
#define	AN_LINKSTAT_SYNCLOST_HOSTREQ	0x8003
#define	AN_LINKSTAT_SYNCLOST_AVGRETRY	0x8002
#define	AN_LINKSTAT_SYNCLOST_MAXRETRY	0x8001
#define	AN_LINKSTAT_SYNCLOST_MISSBEACON	0x8000

/*
 * Link stat low byte reason code
 */
#define	AN_LINKSTAT_RC_RESERVED		0 /* Reserved return code */
#define	AN_LINKSTAT_RC_NOREASON		1 /* Unspecified reason */
#define	AN_LINKSTAT_RC_AUTHINV		2 /* Prev auth invalid */
#define	AN_LINKSTAT_RC_DEAUTH		3 /* Deauth due sender leaving */
#define	AN_LINKSTAT_RC_NOACT		4 /* Disassociated due inactivity */
#define	AN_LINKSTAT_RC_MAXLOAD		5 /* Disassociated due 2many stations */
/*
 * Class 2 frame received from non-Authenticated station
 */
#define	AN_LINKSTAT_RC_BADCLASS2	6
/*
 * Class 3 frame received from non-Associated station
 */
#define	AN_LINKSTAT_RC_BADCLASS3	7
/*
 * Disassociated because sending station is leaving BSS
 */
#define	AN_LINKSTAT_RC_STATLEAVE	8
/*
 * Station requesting (Re)Association not Authenticated w/responding station
 */
#define	AN_LINKSTAT_RC_NOAUTH		9

/*
 * memory handle management registers
 */
#define	AN_RX_FID		0x20
#define	AN_ALLOC_FID		0x22
#define	AN_TX_CMP_FID(p) \
	(p->pcan_device_type == PCAN_DEVICE_PCI ? 0x1a : 0x24)

#define	AN_INVALID_FID		0xffff  /* invalid fid value */

/*
 * Buffer Access Path (BAP) registers.
 * These are I/O channels. I believe you can use each one for
 * any desired purpose independently of the other. In general
 * though, we use BAP1 for reading and writing LTV records and
 * reading received data frames, and BAP0 for writing transmit
 * frames. This is a convention though, not a rule.
 */
#define	AN_SEL0			0x18
#define	AN_SEL1			0x1A
#define	AN_OFF0			0x1C
#define	AN_OFF1			0x1E
#define	AN_DATA0		0x36
#define	AN_DATA1		0x38
#define	AN_BAP0			AN_DATA0
#define	AN_BAP1			AN_DATA1

#define	AN_OFF_BUSY		0x8000
#define	AN_OFF_ERR		0x4000
#define	AN_OFF_DONE		0x2000
#define	AN_OFF_DATAOFF		0x0FFF

/*
 * Event registers
 */
#define	AN_EVENT_STAT(p) (p->pcan_device_type == PCAN_DEVICE_PCI ? 0x60 : 0x30)
/*
 * Interrupt enable/disable
 */
#define	AN_INT_EN(p) (p->pcan_device_type == PCAN_DEVICE_PCI ? 0x64 : 0x32)
#define	AN_EVENT_ACK(p)	(p->pcan_device_type == PCAN_DEVICE_PCI ? 0x68 : 0x34)

/*
 * Events - AN_EVENT_ACK register only
 */
#define	AN_EV_CLR_STUCK_BUSY	0x4000	/* clear stuck busy bit */
#define	AN_EV_WAKEREQUEST	0x2000	/* awaken from PSP mode */
					/* Events shared by all 3 event regs: */
#define	AN_EV_MIC		0x1000	/* Message Integrity Check */
#define	AN_EV_AWAKE		0x0100	/* station woke up from PSP mode */
#define	AN_EV_LINKSTAT		0x0080	/* link status available */
#define	AN_EV_CMD		0x0010	/* command completed */
#define	AN_EV_ALLOC		0x0008	/* async alloc/reclaim completed */
#define	AN_EV_TX_EXC		0x0004	/* async xmit completed with failure */
#define	AN_EV_TX		0x0002	/* async xmit completed succesfully */
#define	AN_EV_RX		0x0001	/* async rx completed */
#define	AN_EV_TX_CPY		0x0400

#define	AN_EV_ALL		0xffff	/* all events */
#define	AN_INTRS(p) \
	(p->pcan_device_type == PCAN_DEVICE_PCI ? \
	(AN_EV_RX|AN_EV_TX|AN_EV_TX_EXC|AN_EV_ALLOC|AN_EV_LINKSTAT|AN_EV_MIC \
	|AN_EV_TX_CPY) : \
	(AN_EV_RX|AN_EV_TX|AN_EV_TX_EXC|AN_EV_ALLOC|AN_EV_LINKSTAT|AN_EV_MIC))

/*
 * Host software registers
 */
#define	AN_SW0(p)	(p->pcan_device_type == PCAN_DEVICE_PCI ? 0x50 : 0x28)
#define	AN_SW1(p)	(p->pcan_device_type == PCAN_DEVICE_PCI ? 0x54 : 0x2A)
#define	AN_SW2(p)	(p->pcan_device_type == PCAN_DEVICE_PCI ? 0x58 : 0x2C)
#define	AN_SW3(p)	(p->pcan_device_type == PCAN_DEVICE_PCI ? 0x5c : 0x2E)

#define	AN_CNTL			0x14

#define	AN_CNTL_AUX_ENA		0xC000
#define	AN_CNTL_AUX_ENA_STAT	0xC000
#define	AN_CNTL_AUX_DIS_STAT	0x0000
#define	AN_CNTL_AUX_ENA_CNTL	0x8000
#define	AN_CNTL_AUX_DIS_CNTL	0x4000

#define	AN_AUX_PAGE		0x3A
#define	AN_AUX_OFFSET		0x3C
#define	AN_AUX_DATA		0x3E

struct an_ltv_gen {
	uint16_t	an_len;
	uint16_t	an_type;
	uint16_t	an_val;
};

/*
 * General configuration information.
 */
#define	AN_RID_GENCONFIG	0xFF10
struct an_ltv_genconfig {
	uint16_t	an_len;			/* 0x00 */
	uint16_t	an_opmode;		/* 0x02 */
	uint16_t	an_rxmode;		/* 0x04 */
	uint16_t	an_fragthresh;		/* 0x06 */
	uint16_t	an_rtsthresh;		/* 0x08 */
	uint8_t		an_macaddr[6];		/* 0x0A */
	uint8_t		an_rates[8];		/* 0x10 */
	uint16_t	an_shortretry_limit;	/* 0x18 */
	uint16_t	an_longretry_limit;	/* 0x1A */
	uint16_t	an_tx_msdu_lifetime;	/* 0x1C */
	uint16_t	an_rx_msdu_lifetime;	/* 0x1E */
	uint16_t	an_stationary;		/* 0x20 */
	uint16_t	an_ordering;		/* 0x22 */
	uint16_t	an_devtype;		/* 0x24 */
	uint16_t	an_rsvd0[5];		/* 0x26 */
	/*
	 * Scanning associating.
	 */
	uint16_t	an_scanmode;		/* 0x30 */
	uint16_t	an_probedelay;		/* 0x32 */
	uint16_t	an_probe_energy_timeout; /* 0x34 */
	uint16_t	an_probe_response_timeout; /* 0x36 */
	uint16_t	an_beacon_listen_timeout; /* 0x38 */
	uint16_t	an_ibss_join_net_timeout; /* 0x3A */
	uint16_t	an_auth_timeout;	/* 0x3C */
	uint16_t	an_authtype;		/* 0x3E */
	uint16_t	an_assoc_timeout;	/* 0x40 */
	uint16_t	an_specified_ap_timeout; /* 0x42 */
	uint16_t	an_offline_scan_interval; /* 0x44 */
	uint16_t	an_offline_scan_duration; /* 0x46 */
	uint16_t	an_link_loss_delay;	/* 0x48 */
	uint16_t	an_max_beacon_lost_time; /* 0x4A */
	uint16_t	an_refresh_interval;	/* 0x4C */
	uint16_t	an_rsvd1;		/* 0x4E */
	/*
	 * Power save operation
	 */
	uint16_t	an_psave_mode;		/* 0x50 */
	uint16_t	an_sleep_for_dtims;	/* 0x52 */
	uint16_t	an_listen_interval;	/* 0x54 */
	uint16_t	an_fast_listen_interval; /* 0x56 */
	uint16_t	an_listen_decay;	/* 0x58 */
	uint16_t	an_fast_listen_decay;	/* 0x5A */
	uint16_t	an_rsvd2[2];		/* 0x5C */
	/*
	 * Ad-hoc (or AP) operation.
	 */
	uint16_t	an_beacon_period;	/* 0x60 */
	uint16_t	an_atim_duration;	/* 0x62 */
	uint16_t	an_rsvd3;		/* 0x64 */
	uint16_t	an_ds_channel;		/* 0x66 */
	uint16_t	an_rsvd4;		/* 0x68 */
	uint16_t	an_dtim_period;		/* 0x6A */
	uint16_t	an_rsvd5[2];		/* 0x6C */
	/*
	 * Radio operation.
	 */
	uint16_t	an_radiotype;		/* 0x70 */
	uint16_t	an_diversity;		/* 0x72 */
	uint16_t	an_tx_power;		/* 0x74 */
	uint16_t	an_rss_thresh;		/* 0x76 */
	uint16_t	an_rsvd6[4];		/* 0x78 */
	/*
	 * Aironet extensions.
	 */
	uint8_t		an_nodename[16];	/* 0x80 */
	uint16_t	an_arl_thresh;		/* 0x90 */
	uint16_t	an_arl_decay;		/* 0x92 */
	uint16_t	an_arl_delay;		/* 0x94 */
	uint8_t		an_rsvd7;		/* 0x96 */
	uint8_t		an_rsvd8;		/* 0x97 */
	uint8_t		an_magic_packet_action;	/* 0x98 */
	uint8_t		an_magic_packet_ctl;	/* 0x99 */
	uint16_t	an_auto_wake;		/* 0x9A */
	uint16_t	an_pad[20];
};

#define	AN_OPMODE_IBSS_ADHOC			0x0000
#define	AN_OPMODE_INFR_STATION			0x0001
#define	AN_OPMODE_AP				0x0002
#define	AN_OPMODE_AP_REPEATER			0x0003
#define	AN_OPMODE_UNMODIFIED_PAYLOAD		0x0100
#define	AN_OPMODE_AIRONET_EXTENSIONS		0x0200
#define	AN_OPMODE_AP_EXTENSIONS			0x0400

#define	AN_RXMODE_BC_MC_ADDR			0x0000
#define	AN_RXMODE_BC_ADDR			0x0001
#define	AN_RXMODE_ADDR				0x0002
#define	AN_RXMODE_80211_MONITOR_CURBSS		0x0003
#define	AN_RXMODE_80211_MONITOR_ANYBSS		0x0004
#define	AN_RXMODE_LAN_MONITOR_CURBSS		0x0005
#define	AN_RXMODE_NO_8023_HEADER		0x0100
#define	AN_RXMODE_USE_8023_HEADER		0x0000

#define	AN_RATE_1MBPS				0x0002
#define	AN_RATE_2MBPS				0x0004
#define	AN_RATE_5_5MBPS				0x000B
#define	AN_RATE_11MBPS				0x0016

#define	AN_DEVTYPE_PC4500			0x0065
#define	AN_DEVTYPE_PC4800			0x006D

#define	AN_SCANMODE_ACTIVE			0x0000
#define	AN_SCANMODE_PASSIVE			0x0001
#define	AN_SCANMODE_AIRONET_ACTIVE		0x0002

#define	AN_AUTHTYPE_NONE			0x0000
#define	AN_AUTHTYPE_OPEN			0x0001
#define	AN_AUTHTYPE_SHAREDKEY			0x0002
#define	AN_AUTHTYPE_EXCLUDE_UNENCRYPTED		0x0004
#define	AN_AUTHTYPE_ENABLEWEP			0x0100
#define	AN_AUTHTYPE_ALLOW_UNENCRYPTED		0x0200

#define	AN_PSAVE_NONE				0x0000
#define	AN_PSAVE_CAM				0x0001
#define	AN_PSAVE_PSP				0x0002
#define	AN_PSAVE_PSP_CAM			0x0003

#define	AN_RADIOTYPE_80211_FH			0x0001
#define	AN_RADIOTYPE_80211_DS			0x0002
#define	AN_RADIOTYPE_LM2000_DS			0x0004

#define	AN_DIVERSITY_FACTORY_DEFAULT		0x0000
#define	AN_DIVERSITY_ANTENNA_1_ONLY		0x0001
#define	AN_DIVERSITY_ANTENNA_2_ONLY		0x0002
#define	AN_DIVERSITY_ANTENNA_1_AND_2		0x0003

#define	AN_TXPOWER_FACTORY_DEFAULT		0x0000
#define	AN_TXPOWER_50MW				50
#define	AN_TXPOWER_100MW			100
#define	AN_TXPOWER_250MW			250

/*
 * Valid SSID list. You can specify up to three SSIDs denoting
 * the service sets that you want to join. The first SSID always
 * defaults to "tsunami" which is a handy way to detect the
 * card.
 */
#define	AN_RID_SSIDLIST		0xFF11
struct an_ltv_ssidlist {
	uint16_t		an_len;
	uint16_t		an_ssid1_len;
	char			an_ssid1[32];
	uint16_t		an_ssid2_len;
	char			an_ssid2[32];
	uint16_t		an_ssid3_len;
	char			an_ssid3[32];
	uint8_t			an_pad[748];
};

#define	AN_DEF_SSID_LEN		7
#define	AN_DEF_SSID		"tsunami"

/*
 * Valid AP list.
 */
#define	AN_RID_APLIST		0xFF12
struct an_ltv_aplist {
	uint16_t	an_len;
	uint8_t		an_ap1[6];
	uint8_t		an_ap2[6];
	uint8_t		an_ap3[6];
	uint8_t		an_ap4[6];
};

/*
 * Driver name.
 */
#define	AN_RID_DRVNAME		0xFF13
struct an_ltv_drvname {
	uint16_t	an_len;
	uint8_t		an_drvname[16];
};

/*
 * Frame encapsulation.
 */
#define	AN_RID_ENCAP		0xFF14
struct an_rid_encap {
	uint16_t		an_len;
	uint16_t		an_ethertype_default;
	uint16_t		an_action_default;
	uint16_t		an_ethertype0;
	uint16_t		an_action0;
	uint16_t		an_ethertype1;
	uint16_t		an_action1;
	uint16_t		an_ethertype2;
	uint16_t		an_action2;
	uint16_t		an_ethertype3;
	uint16_t		an_action3;
	uint16_t		an_ethertype4;
	uint16_t		an_action4;
	uint16_t		an_ethertype5;
	uint16_t		an_action5;
	uint16_t		an_ethertype6;
	uint16_t		an_action6;
};

#define	AN_ENCAP_ACTION_RX	0x0001
#define	AN_ENCAP_ACTION_TX	0x0002

#define	AN_RXENCAP_NONE		0x0000
#define	AN_RXENCAP_RFC1024	0x0001

#define	AN_TXENCAP_RFC1024	0x0000
#define	AN_TXENCAP_80211	0x0002

#define	AN_RID_WEPKEY		0xFF15
#define	AN_RID_WEPKEY2		0xFF16
struct an_ltv_wepkey {
	uint16_t	an_len;
	uint16_t	an_index;
	uint8_t		an_macaddr[6];
	uint16_t	an_keylen;	/* WEP40: 5, WEP128: 13 bytes */
	uint8_t		an_key[16];	/* key value */
};

#define	AN_RID_CRYPT		0xFF18
struct an_ltv_crypt {
	uint16_t	an_operation;		/* 0: enable  1: disable */
	uint8_t		an_optionmask[2];	/* 1: WEP40   2: WEP128 */
	uint8_t		an_filler[8];		/* put struct 6 bytes longer */
};

/*
 * Actual config, same structure as general config (read only).
 */
#define	AN_RID_ACTUALCFG	0xFF20

/*
 * Card capabilities (read only).
 */
#define	AN_RID_CAPABILITIES	0xFF00
struct an_ltv_caps {
	uint16_t	an_len;
	uint8_t		an_oui[3];		/* 0x02 */
	uint8_t		an_pad0;		/* 0x05 */
	uint16_t	an_prodnum;		/* 0x06 */
	uint8_t		an_manufname[32];	/* 0x08 */
	uint8_t		an_prodname[16];	/* 0x28 */
	uint8_t		an_prodvers[8];		/* 0x38 */
	uint8_t		an_oemaddr[6];		/* 0x40 */
	uint8_t		an_aironetaddr[6];	/* 0x46 */
	uint16_t	an_radiotype;		/* 0x4C */
	uint16_t	an_country;		/* 0x4E */
	uint8_t		an_callid[6];		/* 0x50 */
	uint8_t		an_supported_rates[8];	/* 0x56 */
	uint8_t		an_rx_diversity;	/* 0x5E */
	uint8_t		an_tx_diversity;	/* 0x5F */
	uint16_t	an_tx_powerlevels[8];	/* 0x60 */
	uint16_t	an_hwver;		/* 0x70 */
	uint16_t	an_hwcaps;		/* 0x72 */
	uint16_t	an_temprange;		/* 0x74 */
	uint16_t	an_fwrev;		/* 0x76 */
	uint16_t	an_fwsubrev;		/* 0x78 */
	uint16_t	an_interfacerev;	/* 0x7A */
	uint16_t	an_softcap;		/* 0x7C */
	uint16_t	an_bootblockrev;	/* 0x7E */
	uint16_t	an_requiredhw;		/* 0x80 */
	uint16_t	an_pad;
};

/*
 * Access point (read only)
 */
#define	AN_RID_APINFO		0xFF01
struct an_ltv_apinfo {
	uint16_t		an_len;
	uint16_t		an_tim_addr;
	uint16_t		an_airo_addr;
};

/*
 * Radio info (read only).
 */
#define	AN_RID_RADIOINFO	0xFF02
struct an_ltv_radioinfo {
	uint16_t		an_len;
	/*
	 * some more fields here, waiting for freebsd code update.
	 */
};

/*
 * Status (read only). Note: the manual claims this RID is 108 bytes
 * long (0x6A is the last datum, which is 2 bytes long) however when
 * this RID is read from the NIC, it returns a length of 110. To be
 * on the safe side, this structure is padded with an extra 16-bit
 * word. (There is a misprint in the manual which says the macaddr
 * field is 8 bytes long.)
 *
 * Also, the channel_set and current_channel fields appear to be
 * reversed. Either that, or the hop_period field is unused.
 */
#define	AN_RID_STATUS		0xFF50
struct an_ltv_status {
	uint16_t	an_len;
	uint8_t		an_macaddr[6];		/* 0x02 */
	uint16_t	an_opmode;		/* 0x08 */
	uint16_t	an_errcode;		/* 0x0A */
	uint16_t	an_cur_signal_quality;	/* 0x0C */
	uint16_t	an_ssidlen;		/* 0x0E */
	uint8_t		an_ssid[32];		/* 0x10 */
	uint8_t		an_ap_name[16];		/* 0x30 */
	uint8_t		an_cur_bssid[6];	/* 0x40 */
	uint8_t		an_prev_bssid1[6];	/* 0x46 */
	uint8_t		an_prev_bssid2[6];	/* 0x4C */
	uint8_t		an_prev_bssid3[6];	/* 0x52 */
	uint16_t	an_beacon_period;	/* 0x58 */
	uint16_t	an_dtim_period;		/* 0x5A */
	uint16_t	an_atim_duration;	/* 0x5C */
	uint16_t	an_hop_period;		/* 0x5E */
	uint16_t	an_channel_set;		/* 0x60 */
	uint16_t	an_cur_channel;		/* 0x62 */
	uint16_t	an_hops_to_backbone;	/* 0x64 */
	uint16_t	an_ap_total_load;	/* 0x66 */
	uint16_t	an_our_generated_load;	/* 0x68 */
	uint16_t	an_accumulated_arl;	/* 0x6A */
	uint16_t	an_signale_quality;	/* 0x6C */
	uint16_t	an_cur_tx_rate;		/* 0x6E */
	uint16_t	an_ap_device;		/* 0x70 */
	uint16_t	an_normallized_rssi;	/* 0x72 */
	uint16_t	an_short_preamble;	/* 0x74 */
	uint8_t		an_ap_ip_address[4];	/* 0x76 */
	uint8_t		an_noise_pct;		/* 0x7A */
	uint8_t		an_noise_dbm;		/* 0x7B */
	uint8_t		an_noise_average_pct;	/* 0x7C */
	uint8_t		an_noise_average_dbm;	/* 0x7D */
	uint8_t		an_noise_max_pct;	/* 0x7E */
	uint8_t		an_noise_max_dbm;	/* 0x7F */
	uint16_t	an_load;		/* 0x80 */
	uint8_t		an_carrier[4];		/* 0x82 */
	uint16_t	an_assoc_status;	/* 0x86 */
	uint16_t	an_pad;
};

#define	AN_STATUS_OPMODE_CONFIGURED		0x0001
#define	AN_STATUS_OPMODE_MAC_ENABLED		0x0002
#define	AN_STATUS_OPMODE_RX_ENABLED		0x0004
#define	AN_STATUS_OPMODE_IN_SYNC		0x0010
#define	AN_STATUS_OPMODE_ASSOCIATED		0x0020
#define	AN_STATUS_OPMODE_ERROR			0x8000


/*
 * Statistics
 */
#define	AN_RID_16BITS_CUM	0xFF60	/* Cumulative 16-bit stats counters */
#define	AN_RID_16BITS_DELTA	0xFF61	/* 16-bit stats (since last clear) */
#define	AN_RID_16BITS_DELTACLR	0xFF62	/* 16-bit stats, clear on read */
#define	AN_RID_32BITS_CUM	0xFF68	/* Cumulative 32-bit stats counters */
#define	AN_RID_32BITS_DELTA	0xFF69	/* 32-bit stats (since last clear) */
#define	AN_RID_32BITS_DELTACLR	0xFF6A	/* 32-bit stats, clear on read */

/*
 * Grrr. The manual says the statistics record is 384 bytes in length,
 * but the card says the record is 404 bytes. There's some padding left
 * at the end of this structure to account for any discrepancies.
 */
struct an_ltv_stats {
	uint16_t		an_len;
	uint16_t		an_rx_overruns;		/* 0x02 */
	uint16_t		an_rx_plcp_csum_errs;	/* 0x04 */
	uint16_t		an_rx_plcp_format_errs;	/* 0x06 */
	uint16_t		an_rx_plcp_len_errs;	/* 0x08 */
	uint16_t		an_rx_mac_crc_errs;	/* 0x0A */
	uint16_t		an_rx_mac_crc_ok;	/* 0x0C */
	uint16_t		an_rx_wep_errs;		/* 0x0E */
	uint16_t		an_rx_wep_ok;		/* 0x10 */
	uint16_t		an_retry_long;		/* 0x12 */
	uint16_t		an_retry_short;		/* 0x14 */
	uint16_t		an_retry_max;		/* 0x16 */
	uint16_t		an_no_ack;		/* 0x18 */
	uint16_t		an_no_cts;		/* 0x1A */
	uint16_t		an_rx_ack_ok;		/* 0x1C */
	uint16_t		an_rx_cts_ok;		/* 0x1E */
	uint16_t		an_tx_ack_ok;		/* 0x20 */
	uint16_t		an_tx_rts_ok;		/* 0x22 */
	uint16_t		an_tx_cts_ok;		/* 0x24 */
	uint16_t		an_tx_lmac_mcasts;	/* 0x26 */
	uint16_t		an_tx_lmac_bcasts;	/* 0x28 */
	uint16_t		an_tx_lmac_ucast_frags;	/* 0x2A */
	uint16_t		an_tx_lmac_ucasts;	/* 0x2C */
	uint16_t		an_tx_beacons;		/* 0x2E */
	uint16_t		an_rx_beacons;		/* 0x30 */
	uint16_t		an_tx_single_cols;	/* 0x32 */
	uint16_t		an_tx_multi_cols;	/* 0x34 */
	uint16_t		an_tx_defers_no;	/* 0x36 */
	uint16_t		an_tx_defers_prot;	/* 0x38 */
	uint16_t		an_tx_defers_energy;	/* 0x3A */
	uint16_t		an_rx_dups;		/* 0x3C */
	uint16_t		an_rx_partial;		/* 0x3E */
	uint16_t		an_tx_too_old;		/* 0x40 */
	uint16_t		an_rx_too_old;		/* 0x42 */
	uint16_t		an_lostsync_max_retries; /* 0x44 */
	uint16_t		an_lostsync_missed_beacons; /* 0x46 */
	uint16_t		an_lostsync_arl_exceeded; /* 0x48 */
	uint16_t		an_lostsync_deauthed;	/* 0x4A */
	uint16_t		an_lostsync_disassociated; /* 0x4C */
	uint16_t		an_lostsync_tsf_timing;	/* 0x4E */
	uint16_t		an_tx_host_mcasts;	/* 0x50 */
	uint16_t		an_tx_host_bcasts;	/* 0x52 */
	uint16_t		an_tx_host_ucasts;	/* 0x54 */
	uint16_t		an_tx_host_failed;	/* 0x56 */
	uint16_t		an_rx_host_mcasts;	/* 0x58 */
	uint16_t		an_rx_host_bcasts;	/* 0x5A */
	uint16_t		an_rx_host_ucasts;	/* 0x5C */
	uint16_t		an_rx_host_discarded;	/* 0x5E */
	uint16_t		an_tx_hmac_mcasts;	/* 0x60 */
	uint16_t		an_tx_hmac_bcasts;	/* 0x62 */
	uint16_t		an_tx_hmac_ucasts;	/* 0x64 */
	uint16_t		an_tx_hmac_failed;	/* 0x66 */
	uint16_t		an_rx_hmac_mcasts;	/* 0x68 */
	uint16_t		an_rx_hmac_bcasts;	/* 0x6A */
	uint16_t		an_rx_hmac_ucasts;	/* 0x6C */
	uint16_t		an_rx_hmac_discarded;	/* 0x6E */
	uint16_t		an_tx_hmac_accepted;	/* 0x70 */
	uint16_t		an_ssid_mismatches;	/* 0x72 */
	uint16_t		an_ap_mismatches;	/* 0x74 */
	uint16_t		an_rates_mismatches;	/* 0x76 */
	uint16_t		an_auth_rejects;	/* 0x78 */
	uint16_t		an_auth_timeouts;	/* 0x7A */
	uint16_t		an_assoc_rejects;	/* 0x7C */
	uint16_t		an_assoc_timeouts;	/* 0x7E */
	uint16_t		an_reason_outside_table; /* 0x80 */
	uint16_t		an_reason1;		/* 0x82 */
	uint16_t		an_reason2;		/* 0x84 */
	uint16_t		an_reason3;		/* 0x86 */
	uint16_t		an_reason4;		/* 0x88 */
	uint16_t		an_reason5;		/* 0x8A */
	uint16_t		an_reason6;		/* 0x8C */
	uint16_t		an_reason7;		/* 0x8E */
	uint16_t		an_reason8;		/* 0x90 */
	uint16_t		an_reason9;		/* 0x92 */
	uint16_t		an_reason10;		/* 0x94 */
	uint16_t		an_reason11;		/* 0x96 */
	uint16_t		an_reason12;		/* 0x98 */
	uint16_t		an_reason13;		/* 0x9A */
	uint16_t		an_reason14;		/* 0x9C */
	uint16_t		an_reason15;		/* 0x9E */
	uint16_t		an_reason16;		/* 0xA0 */
	uint16_t		an_reason17;		/* 0xA2 */
	uint16_t		an_reason18;		/* 0xA4 */
	uint16_t		an_reason19;		/* 0xA6 */
	uint16_t		an_rx_mgmt_pkts;	/* 0xA8 */
	uint16_t		an_tx_mgmt_pkts;	/* 0xAA */
	uint16_t		an_rx_refresh_pkts;	/* 0xAC */
	uint16_t		an_tx_refresh_pkts;	/* 0xAE */
	uint16_t		an_rx_poll_pkts;	/* 0xB0 */
	uint16_t		an_tx_poll_pkts;	/* 0xB2 */
	uint16_t		an_host_retries;	/* 0xB4 */
	uint16_t		an_lostsync_hostreq;	/* 0xB6 */
	uint16_t		an_host_tx_bytes;	/* 0xB8 */
	uint16_t		an_host_rx_bytes;	/* 0xBA */
	uint16_t		an_uptime_usecs;	/* 0xBC */
	uint16_t		an_uptime_secs;		/* 0xBE */
	uint16_t		an_lostsync_better_ap;	/* 0xC0 */
	uint16_t		an_privacy_mismatch;	/* 0xC2 */
	uint16_t		an_jammed;		/* 0xC4 */
	uint16_t		an_rx_disc_wep_off;	/* 0xC6 */
	uint16_t		an_phy_ele_mismatch;	/* 0xC8 */
	uint16_t		an_leap_success;	/* 0xCA */
	uint16_t		an_leap_failure;	/* 0xCC */
	uint16_t		an_leap_timeouts;	/* 0xCE */
	uint16_t		an_leap_keylen_fail;	/* 0xD0 */
};

#define	AN_RID_ESSIDLIST_FIRST	0xFF72
#define	AN_RID_ESSIDLIST_NEXT	0xFF73

struct an_ltv_scanresult {
	uint16_t	an_len;
	uint16_t	an_index;
	uint16_t	an_radiotype;
	uint8_t		an_bssid[6];
#ifdef	_BIG_ENDIAN
	uint8_t		an_ssidlen;
	uint8_t		an_zero;
#else
	uint8_t		an_zero;
	uint8_t		an_ssidlen;
#endif
	char		an_ssid[32];
	uint16_t	an_rssi;
	uint16_t	an_cap;
	uint16_t	an_beaconinterval;
	uint8_t		an_rates[8];
	struct {
		uint16_t	dwell;
		uint8_t		hopset;
		uint8_t		hoppattern;
		uint8_t		hopindex;
		uint8_t		pad;
	} an_fh;
	uint16_t	an_dschannel;
	uint16_t	an_atimwindow;
};

/*
 * seconds after which the scan item ages
 */
#define	AN_SCAN_TIMEOUT_MAX	30

/*
 * threshold of scan result items below which scan will run again.
 */
#define	AN_SCAN_AGAIN_THRESHOLD	5

typedef struct an_scan_list {
	struct an_ltv_scanresult	an_val;
	uint32_t			an_timeout;
	list_node_t			an_scan_node;
} an_scan_list_t;

/*
 * Receive frame structure.
 */
typedef struct an_rxframe {
	uint32_t	an_rx_time;		/* 0x00 */
	uint16_t	an_rx_status;		/* 0x04 */
	uint16_t	an_rx_payload_len;	/* 0x06 */
	uint8_t		an_rsvd0;		/* 0x08 */
	uint8_t		an_rx_signal_strength;	/* 0x09 */
	uint8_t		an_rx_rate;		/* 0x0A */
	uint8_t		an_rx_chan;		/* 0x0B */
	uint8_t		an_rx_assoc_cnt;	/* 0x0C */
	uint8_t		an_rsvd1[3];		/* 0x0D */
	uint8_t		an_plcp_hdr[4];		/* 0x10 */
	uint16_t	an_frame_ctl;		/* 0x14 */
	uint16_t	an_duration;		/* 0x16 */
	uint8_t		an_addr1[6];		/* 0x18 */
	uint8_t		an_addr2[6];		/* 0x1E */
	uint8_t		an_addr3[6];		/* 0x24 */
	uint16_t	an_seq_ctl;		/* 0x2A */
	uint8_t		an_addr4[6];		/* 0x2C */
	uint16_t	an_gaplen;		/* 0x32 */
} an_rxfrm_t;

#define	AN_RXGAP_MAX	8

/*
 * Transmit frame structure.
 */
typedef struct an_txframe {
	uint32_t	an_tx_sw;		/* 0x00 */
	uint16_t	an_tx_status;		/* 0x04 */
	uint16_t	an_tx_payload_len;	/* 0x06 */
	uint16_t	an_tx_ctl;		/* 0x08 */
	uint16_t	an_tx_assoc_id;		/* 0x0A */
	uint16_t	an_tx_retry;		/* 0x0C */
	uint8_t		an_tx_assoc_cnt;	/* 0x0E */
	uint8_t		an_tx_rate;		/* 0x0F */
	uint8_t		an_tx_max_long_retries;	/* 0x10 */
	uint8_t		an_tx_max_short_retries; /* 0x11 */
	uint8_t		an_rsvd0[2];		/* 0x12 */
	uint16_t	an_frame_ctl;		/* 0x14 */
	uint16_t	an_duration;		/* 0x16 */
	uint8_t		an_addr1[6];		/* 0x18 */
	uint8_t		an_addr2[6];		/* 0x1E */
	uint8_t		an_addr3[6];		/* 0x24 */
	uint16_t	an_seq_ctl;		/* 0x2A */
	uint8_t		an_addr4[6];		/* 0x2C */
	uint16_t	an_gaplen;		/* 0x32 */
} an_txfrm_t;

typedef struct an_frame {
	union {
		an_rxfrm_t rxfrm;
		an_txfrm_t txfrm;
	} frm;
} an_frm_t;

#define	AN_TXSTAT_EXCESS_RETRY	0x0002
#define	AN_TXSTAT_LIFE_EXCEEDED	0x0004
#define	AN_TXSTAT_AID_FAIL	0x0008
#define	AN_TXSTAT_MAC_DISABLED	0x0010
#define	AN_TXSTAT_ASSOC_LOST	0x0020

#define	AN_TXCTL_RSVD		0x0001
#define	AN_TXCTL_TXOK_INTR	0x0002
#define	AN_TXCTL_TXERR_INTR	0x0004
#define	AN_TXCTL_HEADER_TYPE	0x0008
#define	AN_TXCTL_PAYLOAD_TYPE	0x0010
#define	AN_TXCTL_NORELEASE	0x0020
#define	AN_TXCTL_NORETRIES	0x0040
#define	AN_TXCTL_CLEAR_AID	0x0080
#define	AN_TXCTL_STRICT_ORDER	0x0100
#define	AN_TXCTL_USE_RTS	0x0200

#define	AN_HEADERTYPE_8023	0x0000
#define	AN_HEADERTYPE_80211	0x0008

#define	AN_PAYLOADTYPE_ETHER	0x0000
#define	AN_PAYLOADTYPE_LLC	0x0010

typedef enum {
	ANC_RX_OVERRUNS,		/* 0x04 */
	ANC_RX_PLCP_CSUM_ERRS,		/* 0x08 */
	ANC_RX_PLCP_FORMAT_ERRS,	/* 0x0c */
	ANC_RX_PLCP_LEN_ERRS,		/* 0x10 */
	ANC_RX_MAC_CRC_ERRS,		/* 0x14 */
	ANC_RX_MAC_CRC_OK,		/* 0x18 */
	ANC_RX_WEP_ERRS,		/* 0x1c */
	ANC_RX_WEP_OK,			/* 0x20 */
	ANC_RETRY_LONG,			/* 0x24 */
	ANC_RETRY_SHORT,		/* 0x28 */
	ANC_RETRY_MAX,			/* 0x2c */
	ANC_NO_ACK,			/* 0x30 */
	ANC_NO_CTS,			/* 0x34 */
	ANC_RX_ACK_OK,			/* 0x38 */
	ANC_RX_CTS_OK,			/* 0x3c */
	ANC_TX_ACK_OK,			/* 0x40 */
	ANC_TX_RTS_OK,			/* 0x44 */
	ANC_TX_CTS_OK,			/* 0x48 */
	ANC_TX_LMAC_MCASTS,		/* 0x4c */
	ANC_TX_LMAC_BCASTS,		/* 0x50 */
	ANC_TX_LMAC_UCAST_FRAGS,	/* 0x54 */
	ANC_TX_LMAC_UCASTS,		/* 0x58 */
	ANC_TX_BEACONS,			/* 0x5c */
	ANC_RX_BEACONS,			/* 0x60 */
	ANC_TX_SINGLE_COLS,		/* 0x64 */
	ANC_TX_MULTI_COLS,		/* 0x68 */
	ANC_TX_DEFERS_NO,		/* 0x6c */
	ANC_TX_DEFERS_PROT,		/* 0x70 */
	ANC_TX_DEFERS_ENERGY,		/* 0x74 */
	ANC_RX_DUPS,			/* 0x78 */
	ANC_RX_PARTIAL,			/* 0x7c */
	ANC_TX_TOO_OLD,			/* 0x80 */
	ANC_RX_TOO_OLD,			/* 0x84 */
	ANC_LOSTSYNC_MAX_RETRIES,	/* 0x88 */
	ANC_LOSTSYNC_MISSED_BEACONS,	/* 0x8c */
	ANC_LOSTSYNC_ARL_EXCEEDED,	/* 0x90 */
	ANC_LOSTSYNC_DEAUTHED,		/* 0x94 */
	ANC_LOSTSYNC_DISASSOCIATED,	/* 0x98 */
	ANC_LOSTSYNC_TSF_TIMING,	/* 0x9c */
	ANC_TX_HOST_MCASTS,		/* 0xa0 */
	ANC_TX_HOST_BCASTS,		/* 0xa4 */
	ANC_TX_HOST_UCASTS,		/* 0xa8 */
	ANC_TX_HOST_FAILED,		/* 0xac */
	ANC_RX_HOST_MCASTS,		/* 0xb0 */
	ANC_RX_HOST_BCASTS,		/* 0xb4 */
	ANC_RX_HOST_UCASTS,		/* 0xb8 */
	ANC_RX_HOST_DISCARDED,		/* 0xbc */
	ANC_TX_HMAC_MCASTS,		/* 0xc0 */
	ANC_TX_HMAC_BCASTS,		/* 0xc4 */
	ANC_TX_HMAC_UCASTS,		/* 0xc8 */
	ANC_TX_HMAC_FAILED,		/* 0xcc */
	ANC_RX_HMAC_MCASTS,		/* 0xd0 */
	ANC_RX_HMAC_BCASTS,		/* 0xd4 */
	ANC_RX_HMAC_UCASTS,		/* 0xd8 */
	ANC_RX_HMAC_DISCARDED,		/* 0xdc */
	ANC_TX_HMAC_ACCEPTED,		/* 0xe0 */
	ANC_SSID_MISMATCHES,		/* 0xe4 */
	ANC_AP_MISMATCHES,		/* 0xe8 */
	ANC_RATES_MISMATCHES,		/* 0xec */
	ANC_AUTH_REJECTS,		/* 0xf0 */
	ANC_AUTH_TIMEOUTS,		/* 0xf4 */
	ANC_ASSOC_REJECTS,		/* 0xf8 */
	ANC_ASSOC_TIMEOUTS,		/* 0xfc */
	ANC_REASON_OUTSIDE_TABLE,	/* 0x100 */
	ANC_REASON1,			/* 0x104 */
	ANC_REASON2,			/* 0x108 */
	ANC_REASON3,			/* 0x10c */
	ANC_REASON4,			/* 0x110 */
	ANC_REASON5,			/* 0x114 */
	ANC_REASON6,			/* 0x118 */
	ANC_REASON7,			/* 0x11c */
	ANC_REASON8,			/* 0x120 */
	ANC_REASON9,			/* 0x124 */
	ANC_REASON10,			/* 0x128 */
	ANC_REASON11,			/* 0x12c */
	ANC_REASON12,			/* 0x130 */
	ANC_REASON13,			/* 0x134 */
	ANC_REASON14,			/* 0x138 */
	ANC_REASON15,			/* 0x13c */
	ANC_REASON16,			/* 0x140 */
	ANC_REASON17,			/* 0x144 */
	ANC_REASON18,			/* 0x148 */
	ANC_REASON19,			/* 0x14c */
	ANC_RX_MGMT_PKTS,		/* 0x150 */
	ANC_TX_MGMT_PKTS,		/* 0x154 */
	ANC_RX_REFRESH_PKTS,		/* 0x158 */
	ANC_TX_REFRESH_PKTS,		/* 0x15c */
	ANC_RX_POLL_PKTS,		/* 0x160 */
	ANC_TX_POLL_PKTS,		/* 0x164 */
	ANC_HOST_RETRIES,		/* 0x168 */
	ANC_LOSTSYNC_HOSTREQ,		/* 0x16c */
	ANC_HOST_TX_BYTES,		/* 0x170 */
	ANC_HOST_RX_BYTES,		/* 0x174 */
	ANC_UPTIME_USECS,		/* 0x178 */
	ANC_UPTIME_SECS,		/* 0x17c */
	ANC_LOSTSYNC_BETTER_AP,		/* 0x180 */
	ANC_PRIVACY_MISMATCH,		/* 0x184 */
	ANC_JAMMED,			/* 0x188 */
	ANC_RX_DISC_WEP_OFF,		/* 0x18c */
	ANC_PHY_ELE_MISMATCH,		/* 0x190 */
	ANC_LEAP_SUCCESS,		/* 0x194 */
	ANC_LEAP_FAILURE,		/* 0x198 */
	ANC_LEAP_TIMEOUTS,		/* 0x19c */
	ANC_LEAP_KEYLEN_FAIL,		/* 0x1a0 */
	ANC_STAT_CNT			/* - keep it as the last entry */
} pcan_cntr_offset;

#define	AN_TXCTL_80211	(AN_TXCTL_TXOK_INTR | AN_TXCTL_TXERR_INTR | \
		AN_HEADERTYPE_80211 | AN_PAYLOADTYPE_LLC | AN_TXCTL_NORELEASE)

#define	AN_TXCTL_8023	(AN_TXCTL_TXOK_INTR | AN_TXCTL_TXERR_INTR |\
		AN_HEADERTYPE_8023 | AN_PAYLOADTYPE_ETHER | AN_TXCTL_NORELEASE)

#define	AN_TXGAP_80211		6
#define	AN_TXGAP_8023		0

#define	AN_NORMAL_RXMODE	(AN_RXMODE_BC_MC_ADDR | \
					AN_RXMODE_USE_8023_HEADER)
#define	AN_MONITOR_RXMODE	(AN_RXMODE_LAN_MONITOR_CURBSS | \
					AN_RXMODE_USE_8023_HEADER)
struct an_802_3_hdr {
	uint16_t		an_8023_status;
	uint16_t		an_8023_payload_len;
	uint8_t			an_8023_dst_addr[6];
	uint8_t			an_8023_src_addr[6];
	uint16_t		an_8023_dat[3];	/* SNAP header */
	uint16_t		an_8023_type;
};

typedef struct an_snap_hdr {
	uint16_t		an_snap_dat[3];	/* SNAP header */
	uint16_t		an_snap_type;
} pcan_snaphdr_t;

#define	AN_TX_RING_CNT		4
#define	AN_TX_RING_MASK		(4 - 1)
#define	AN_INC(x, y)		(x) = (x + 1) % (y)

typedef struct an_tx_ring_data {
	uint16_t		an_tx_fids[AN_TX_RING_CNT];
	uint16_t		an_tx_ring[AN_TX_RING_CNT];
	int			an_tx_prod;
	int			an_tx_cons;
	kmutex_t		an_tx_lock;	/* for send only */
} pcan_txring_t;

#define	AN_802_3_OFFSET		0x2E
#define	AN_802_11_OFFSET	0x44
#define	AN_802_11_OFFSET_RAW	0x3C

#define	AN_STAT_BADCRC		0x0001
#define	AN_STAT_UNDECRYPTABLE	0x0002
#define	AN_STAT_ERRSTAT		0x0003
#define	AN_STAT_MAC_PORT	0x0700
#define	AN_STAT_1042		0x2000	/* RFC1042 encoded */
#define	AN_STAT_TUNNEL		0x4000	/* Bridge-tunnel encoded */
#define	AN_STAT_WMP_MSG		0x6000	/* WaveLAN-II management protocol */
#define	AN_RXSTAT_MSG_TYPE	0xE000

#define	AN_ENC_TX_802_3		0x00
#define	AN_ENC_TX_802_11	0x11
#define	AN_ENC_TX_E_II		0x0E

#define	AN_ENC_TX_1042		0x00
#define	AN_ENC_TX_TUNNEL	0xF8

#define	AN_TXCNTL_MACPORT	0x00FF
#define	AN_TXCNTL_STRUCTTYPE	0xFF00

/*
 * SNAP (sub-network access protocol) constants for transmission
 * of IP datagrams over IEEE 802 networks, taken from RFC1042.
 * We need these for the LLC/SNAP header fields in the TX/RX frame
 * structure.
 */
#define	AN_SNAP_K1		0xaa	/* assigned global SAP for SNAP */
#define	AN_SNAP_K2		0x00
#define	AN_SNAP_CONTROL		0x03	/* unnumbered information format */
#define	AN_SNAP_WORD0		(AN_SNAP_K1 | (AN_SNAP_K1 << 8))
#define	AN_SNAP_WORD1		(AN_SNAP_K2 | (AN_SNAP_CONTROL << 8))
#define	AN_SNAPHDR_LEN		0x6

#define	AN_FTYPE_DATA		0x8
#define	ETH_HDRLEN		(sizeof (struct ether_header))	/* 14 bytes */
#define	MLEN(mp)		((mp)->b_wptr - (mp)->b_rptr)

typedef struct pcan_dma_info {
	ddi_dma_handle_t	dma_handle;
	ddi_acc_handle_t	dma_acc_handle;
	uint32_t		dma_physaddr;
	caddr_t			dma_virtaddr;
	uint_t			ncookies;
} pcan_dma_info_t;

#define	PCAN_DMA_SYNC(hdl, len, flag) ((void) ddi_dma_sync(hdl, 0, len, (flag)))

/*
 * The macinfo is really used as the softstate structure.
 *
 * pcan_mh	 - mac_handle_t structure
 * pcan_cslock	 - lock for card services request. Used with pcan_cscv
 * pcan_cscv	 - condition variable to wait for card events
 * pcan_chdl	 - client handle, an uint32_t bit mask encoding for socket,
 *			function, and client info.
 *			See cs_priv.h MAKE_CLIENT_HANDLE.
 * pcan_log_sock - holds the logical to physical translation for this card.
 *			Specifically has physical adapter and socket #.
 *			Socket # is the same as part of the pcan_chdl encoding.
 *			Physical adapter # is from card service socket impl.
 */
typedef struct pcan_macinfo {
	mac_handle_t		pcan_mh;
	dev_info_t		*pcan_dip;

	kmutex_t		pcan_cslock;	/* for card services */
	kcondvar_t		pcan_cscv;	/* for card services */
	client_handle_t		pcan_chdl;	/* s,f,c encoding, cs_priv.h */
	map_log_socket_t	pcan_log_sock;	/* logical/phys socket map */
	int			pcan_socket;	/* socket number */
	int			pcan_config_hi;	/* cfttbl index */
	int			pcan_config;	/* default config index */
	int			pcan_vcc;	/* vcc level */
	int			pcan_iodecode;	/* # of address lines */
	int			pcan_usewep;
	int			pcan_reset_delay;

	caddr_t			pcan_cfg_base;
	ddi_acc_handle_t	pcan_cfg_handle;
	caddr_t			pcan_bar0;
	ddi_acc_handle_t	pcan_handle0;
	caddr_t			pcan_bar1;
	ddi_acc_handle_t	pcan_handle1;
	caddr_t			pcan_bar2;
	ddi_acc_handle_t	pcan_handle2;
	int			pcan_device_type; /* pci or pcmcia card */

	uint8_t 		pcan_mac_addr[ETHERADDRL];
	uint32_t		pcan_flag;
	uint32_t		pcan_reschedule_need;
	uint32_t		glds_nocarrier;
	uint32_t		glds_noxmtbuf;
	uint32_t		glds_norcvbuf;
	uint32_t		glds_intr;

	pcan_dma_info_t	pcan_cmd;
	pcan_dma_info_t	pcan_rx[AN_MAX_RX_DESC];
	pcan_dma_info_t	pcan_tx[AN_MAX_TX_DESC];

	kmutex_t		pcan_glock;	/* generic lock */
	kmutex_t		pcan_scanlist_lock;	/* scanlist lock */
	pcan_txring_t		pcan_txring;

	struct an_ltv_ssidlist	an_ssidlist;
	struct an_ltv_aplist	an_aplist;
	struct an_ltv_caps	an_caps;
	struct an_ltv_crypt	an_crypt;
	struct an_ltv_wepkey	an_wepkey[4];
	struct an_ltv_scanresult an_scanresult[32];
	uint16_t		an_cur_wepkey;
	uint16_t		an_scan_num;
	timeout_id_t		an_scanlist_timeout_id;
	list_t			an_scan_list;
	struct an_ltv_status	an_status;
	struct an_ltv_genconfig	an_config;
	struct an_ltv_genconfig	an_actual_config;
	struct an_ltv_stats	an_stats;
	uint64_t pcan_cntrs_s[ANC_STAT_CNT];

	ddi_acc_handle_t	pcan_port;
	ddi_iblock_cookie_t	pcan_ib_cookie;
	ddi_softintr_t		pcan_softint_id;

	ddi_softintr_t		pcan_info_softint_id;
	uint32_t		pcan_info_softint_pending;

	timeout_id_t		pcan_connect_timeout_id;
	timeout_id_t		pcan_linkdown_timeout_id;
	int			pcan_badrids_len;
	prop_1275_cell_t	*pcan_badrids;
} pcan_maci_t;

#define	PCAN_IDENT_STRING	modldrv.drv_linkinfo

#define	HDL(pcan_p)		((pcan_p)->pcan_port)
#define	GLD3(pcan_p)		((pcan_p)->pcan_mh)
#define	DIP(pcan_p)		((pcan_p)->pcan_dip)

#define	PCAN_CARD_INTREN	0x1
#define	PCAN_CARD_LINKUP	0x2
#define	PCAN_ATTACHED		0x4
#define	PCAN_CS_REGISTERED	0x8
#define	PCAN_ENABLED		0x10
#define	PCAN_CARD_SEND		0x20
#define	PCAN_CARD_READY		0x40
#define	PCAN_CARD_FAILED	0x80
#define	PCAN_PLUMBED		0x100
#define	PCAN_SUSPENDED		0x200

#define	PCAN_STATE_IDLE		0x1

#define	PCAN_NICMEM_SZ		(2048) /* 80211MTU set as 1500, so 2k here */

static int	pcan_probe(dev_info_t *dip);
static int	pcan_attach(dev_info_t *dip, ddi_attach_cmd_t cmd);
static int	pcan_detach(dev_info_t *dip, ddi_detach_cmd_t cmd);

static int	pcan_register_cs(dev_info_t *dip, pcan_maci_t *pcan_p);
static void	pcan_unregister_cs(pcan_maci_t *pcan_p);
static void	pcan_destroy_locks(pcan_maci_t *pcan_p);
static void	pcan_reset_backend(pcan_maci_t *pcan_p, int timeout);
static uint32_t	pcan_get_cap(pcan_maci_t *pcan_p);
static int	pcan_card_insert(pcan_maci_t *pcan_p);
static int	pcan_ev_hdlr(event_t ev, int pri, event_callback_args_t *arg);
static void	pcan_card_remove(pcan_maci_t *pcan_p);
static int	pcan_init_nicmem(pcan_maci_t *pcan_p);
static void	pcan_do_suspend(pcan_maci_t *pcan_p);

/*
 * high level device access primitives, glock must held before calling
 */
static uint16_t	pcan_set_cmd0(pcan_maci_t *pcan_p, uint16_t cmd, uint16_t p0,
    uint16_t p1, uint16_t p2);
static uint16_t	pcan_set_cmd(pcan_maci_t *pcan_p, uint16_t cmd, uint16_t param);
static uint16_t pcan_set_ch(pcan_maci_t *, uint16_t, uint16_t, uint16_t);
static int pcan_init_dma_desc(pcan_maci_t *pcan_p);
static int pcan_init_dma(dev_info_t *dip, pcan_maci_t *pcan_p);
static void pcan_free_dma(pcan_maci_t *pcan_p);
static uint16_t pcan_put_ltv(pcan_maci_t *pcan_p, uint16_t len, uint16_t type,
    uint16_t *val_p);
static uint16_t	pcan_get_ltv(pcan_maci_t *pcan_p, uint16_t len, uint16_t type,
    uint16_t *val_p);
#define	PCAN_READ_LTV	0
#define	PCAN_WRITE_LTV	1
static uint16_t pcan_status_ltv(int rw, pcan_maci_t *pcan_p,
    struct an_ltv_status *status_p);
static uint16_t pcan_cfg_ltv(int rw, pcan_maci_t *pcan_p,
    struct an_ltv_genconfig *cfg_p);
static uint16_t pcan_cap_ltv(int rw, pcan_maci_t *pcan_p);
static uint16_t pcan_ssid_ltv(int rw, pcan_maci_t *pcan_p);
static uint16_t pcan_aplist_ltv(int rw, pcan_maci_t *pcan_p);
static uint16_t pcan_scanresult_ltv(int rw, pcan_maci_t *pcan_p, uint16_t type,
    struct an_ltv_scanresult *scanresult_p);
static uint16_t pcan_wepkey_ltv(int rw, pcan_maci_t *pcan_p);
static uint16_t pcan_rdch0(pcan_maci_t *pcan_p, uint16_t type, uint16_t off,
    uint16_t *buf_p, int len, int order);
static uint16_t pcan_wrch1(pcan_maci_t *pcan_p, uint16_t type, uint16_t off,
    uint16_t *buf_p, int len, int order);
static int	pcan_config_mac(pcan_maci_t *pcan_p);
static void	pcan_start_locked(pcan_maci_t *pcan_p);
static void	pcan_stop_locked(pcan_maci_t *pcan_p);
static uint16_t	pcan_alloc_nicmem(pcan_maci_t *pcan_p, uint16_t len,
    uint16_t *id_p);

/*
 * Required driver entry points for gld
 */
static int	pcan_start(void *);
static void	pcan_stop(void *);
static int	pcan_saddr(void *, const uint8_t *);
static mblk_t	*pcan_tx(void *, mblk_t *);
static int	pcan_send(pcan_maci_t *, mblk_t *);
static int	pcian_send(pcan_maci_t *, mblk_t *);
static int	pcan_prom(void *, boolean_t);
static int	pcan_gstat(void *, uint_t, uint64_t *);
static int	pcan_sdmulti(void *, boolean_t, const uint8_t *);
static void	pcan_ioctl(void *, queue_t *, mblk_t *);

static uint_t	pcan_intr(caddr_t arg);
static uint_t	pcan_intr_hi(caddr_t arg);
static void	pcan_rcv(pcan_maci_t *pcan_p);
static void	pcian_rcv(pcan_maci_t *pcan_p);
static uint_t	pcan_info_softint(caddr_t arg);
static uint32_t	pcan_txdone(pcan_maci_t *pcan_p, uint16_t err);
static int	pcan_getset(mblk_t *mp, pcan_maci_t *pcan_p, uint32_t cmd);
static void	pcan_wlan_ioctl(pcan_maci_t *pcan_p, queue_t *wq,
    mblk_t *mp, uint32_t cmd);
static int	pcan_loaddef(pcan_maci_t *pcan_p);

static void	pcan_scanlist_timeout(void *);
static void	pcan_delete_scan_item(pcan_maci_t *, an_scan_list_t *);
static int	pcan_add_scan_item(pcan_maci_t *, struct an_ltv_scanresult);
static void	pcan_connect_timeout(void *arg);

#define	RDCH0(h, t, o, bufp, l)		pcan_rdch0(h, t, o, bufp, l, 1)
#define	WRCH1(h, t, o, bufp, l)		pcan_wrch1(h, t, o, bufp, l, 1)
#define	RDPKT(h, t, o, bufp, l)		pcan_rdch0(h, t, o, bufp, l, 0)
#define	WRPKT(h, t, o, bufp, l)		pcan_wrch1(h, t, o, bufp, l, 0)

#define	PCAN_READ(p, o, v)	{ \
	if (p->pcan_device_type == PCAN_DEVICE_PCI) { \
		uint16_t t = ddi_get16(p->pcan_handle0, \
		    (uint16_t *)(p->pcan_bar0 + o)); \
		v = LE_16(t); \
	} else { \
		uint16_t t = csx_Get16(HDL(p), o); \
		v = LE_16(t); \
	}\
}
#define	PCAN_WRITE(p, o, v)	{ \
	if (p->pcan_device_type == PCAN_DEVICE_PCI) { \
		ddi_put16(p->pcan_handle0, \
		    (uint16_t *)(p->pcan_bar0 + o), LE_16(v)); \
	} else { \
		csx_Put16(HDL(p), o, LE_16(v)); \
	}\
}
#define	PCAN_READ_P(p, o, v, h)	{ \
	if (p->pcan_device_type == PCAN_DEVICE_PCI) { \
		uint16_t t = ddi_get16(p->pcan_handle0, \
		    (uint16_t *)(p->pcan_bar0 + o)); \
		*(v) = h ? LE_16(t) : t; \
	} else { \
		uint16_t t = csx_Get16(HDL(p), o); \
		*(v) = h ? LE_16(t) : t; \
	}\
}
#define	PCAN_WRITE_P(p, o, v, h)	{ \
	if (p->pcan_device_type == PCAN_DEVICE_PCI) { \
		ddi_put16(p->pcan_handle0, (uint16_t *)(p->pcan_bar0 + o), \
		    h ? LE_16(*(v)) : (*(v))); \
	} else {\
		csx_Put16(HDL(p), o, h ? LE_16(*(v)) : (*(v))); \
	}\
}

#ifdef _BIG_ENDIAN
#define	PCAN_SWAP16(buf_p, len) { \
	uint16_t pcan_swap_len = len; \
	for (pcan_swap_len = (pcan_swap_len + 1) >> 1; pcan_swap_len; ) { \
		uint16_t val; \
		pcan_swap_len--; \
		val = *((uint16_t *)(buf_p) + pcan_swap_len); \
		*((uint16_t *)(buf_p) + pcan_swap_len) = LE_16(val); \
	} \
}
#define	PCAN_SWAP16_BUF(buf_p) PCAN_SWAP16(buf_p, sizeof (buf_p))
#else /* _BIG_ENDIAN */
#define	PCAN_SWAP16(buf_p, len)
#define	PCAN_SWAP16_BUF(buf_p)
#endif /* _BIG_ENDIAN */

#define	PCAN_ENABLE_INTR(pcan_p)	{\
	PCAN_WRITE(pcan_p, AN_INT_EN(pcan_p), AN_INTRS(pcan_p));\
}
#define	PCAN_DISABLE_INTR(pcan_p)	{ \
	PCAN_WRITE(pcan_p, AN_INT_EN(pcan_p), 0); \
}
#define	PCAN_DISABLE_INTR_CLEAR(pcan_p)	{ \
	PCAN_WRITE(pcan_p, AN_INT_EN(pcan_p), 0); \
	PCAN_WRITE(pcan_p, AN_EVENT_ACK(pcan_p), 0xffff);\
}

#define	PCAN_AUX_PUT32(p, o, v)\
	ddi_put32(p->pcan_handle2, (uint32_t *)(p->pcan_bar2 + o), v)
#define	PCAN_AUX_GET32(p, o, v) {\
	v = ddi_get32(p->pcan_handle2, (uint32_t *)(p->pcan_bar2 + o));\
}

/*
 * 16-bit driver private status code
 */
#define	PCAN_SUCCESS		0
#define	PCAN_FAIL		1
#define	PCAN_TIMEDOUT_CMD	0x10
#define	PCAN_TIMEDOUT_ACCESS	0x11
#define	PCAN_TIMEDOUT_TARGET	0x12
#define	PCAN_BADLEN		0x13
#define	PCAN_BADTYPE		0x14
#define	PCAN_TIMEDOUT_ALLOC	0x15

#define	PCAN_STATUS_MAX		0xffff

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_PCAN_H */
