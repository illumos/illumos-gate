#include "t4_hw.h"
#include "t4_chip_type.h"
#include "common.h"

/* legacy compatibility routines */
int t4_memory_rw(struct adapter *adap, int win,
			       int mtype, u32 maddr, u32 len,
			       void *hbuf, int dir)
{
	return t4_memory_rw_mtype(adap, win, mtype, maddr, len, hbuf, dir);
}

/**
 *	hash_mac_addr - return the hash value of a MAC address
 *	@addr: the 48-bit Ethernet MAC address
 *
 *	Hashes a MAC address according to the hash function used by hardware
 *	inexact (hash) address matching.  The description in the hardware
 *	documentation for the MPS says this:
 *
 *	    The hash function takes the 48 bit MAC address and hashes
 *	    it down to six bits.  Bit zero of the hash is the XOR of
 *	    bits 0, 6 ... 42 of the MAC address.  The other hash bits
 *	    are computed in a similar fashion ending with bit five of
 *	    the hash as the XOR of bits 5, 11 ... 47 of the MAC address.
 */
int hash_mac_addr(const u8 *addr)
{
	u32 a = ((u32)addr[0] << 16) | ((u32)addr[1] << 8) | addr[2];
	u32 b = ((u32)addr[3] << 16) | ((u32)addr[4] << 8) | addr[5];

	a ^= b;
	a ^= (a >> 12);
	a ^= (a >> 6);
	return a & 0x3f;
}

int t4_wr_mbox_ns(struct adapter *adap, int mbox, const void *cmd,
				int size, void *rpl)
{
	return t4_wr_mbox_meat(adap, mbox, cmd, size, rpl, false);
}

int t4_wr_mbox_timeout(struct adapter *adap, int mbox,
				     const void *cmd, int size, void *rpl,
				     int timeout)
{
	return t4_wr_mbox_meat_timeout(adap, mbox, cmd, size, rpl, true,
				       timeout);
}

unsigned int dack_ticks_to_usec(const struct adapter *adap,
					      unsigned int ticks)
{
	return (ticks << adap->params.tp.dack_re) / core_ticks_per_usec(adap);
}

unsigned int us_to_core_ticks(const struct adapter *adap,
					    unsigned int us)
{
	return (us * adap->params.vpd.cclk) / 1000;
}

int is_offload(const struct adapter *adap)
{
	return adap->params.offload;
}

/*
 * Given a pointer to a Firmware Mailbox Command Log and a log entry index,
 * return a pointer to the specified entry.
 */
struct mbox_cmd *mbox_cmd_log_entry(struct mbox_cmd_log *log,
						  unsigned int entry_idx)
{
	return &((struct mbox_cmd *)&(log)[1])[entry_idx];
}

int is_t4(enum chip_type chip)
{
	return (CHELSIO_CHIP_VERSION(chip) == CHELSIO_T4);
}

int is_t5(enum chip_type chip)
{

	return (CHELSIO_CHIP_VERSION(chip) == CHELSIO_T5);
}

int is_t6(enum chip_type chip)
{
	return (CHELSIO_CHIP_VERSION(chip) == CHELSIO_T6);
}

int is_fpga(enum chip_type chip)
{
	 return chip & CHELSIO_CHIP_FPGA;
}

/**
 *     t4_is_inserted_mod_type - is a plugged in Firmware Module Type
 *     @fw_mod_type: the Firmware Mofule Type
 *
 *     Return whether the Firmware Module Type represents a real Transceiver
 *     Module/Cable Module Type which has been inserted.
 */
bool t4_is_inserted_mod_type(unsigned int fw_mod_type)
{
	return (fw_mod_type != FW_PORT_MOD_TYPE_NONE &&
		fw_mod_type != FW_PORT_MOD_TYPE_NOTSUPPORTED &&
		fw_mod_type != FW_PORT_MOD_TYPE_UNKNOWN &&
		fw_mod_type != FW_PORT_MOD_TYPE_ERROR);
}

int t4_wr_mbox(struct adapter *adap, int mbox, const void *cmd,
			     int size, void *rpl)
{
	return t4_wr_mbox_meat(adap, mbox, cmd, size, rpl, true);
}

unsigned int core_ticks_per_usec(const struct adapter *adap)
{
	return adap->params.vpd.cclk / 1000;
}
