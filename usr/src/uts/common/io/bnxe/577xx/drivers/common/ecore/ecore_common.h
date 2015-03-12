#ifndef ECORE_COMMON_H
#define ECORE_COMMON_H

#define ECORE_SWCID_SHIFT	17
#define ECORE_SWCID_MASK	((0x1 << ECORE_SWCID_SHIFT) - 1)


/* Manipulate a bit vector defined as an array of u64 */

/* Number of bits in one sge_mask array element */
#define BIT_VEC64_ELEM_SZ		64
#define BIT_VEC64_ELEM_SHIFT		6
#define BIT_VEC64_ELEM_MASK		((u64)BIT_VEC64_ELEM_SZ - 1)


#define __BIT_VEC64_SET_BIT(el, bit) \
	do { \
		el = ((el) | ((u64)0x1 << (bit))); \
	} while (0)

#define __BIT_VEC64_CLEAR_BIT(el, bit) \
	do { \
		el = ((el) & (~((u64)0x1 << (bit)))); \
	} while (0)


#define BIT_VEC64_SET_BIT(vec64, idx) \
	__BIT_VEC64_SET_BIT((vec64)[(idx) >> BIT_VEC64_ELEM_SHIFT], \
			   (idx) & BIT_VEC64_ELEM_MASK)

#define BIT_VEC64_CLEAR_BIT(vec64, idx) \
	__BIT_VEC64_CLEAR_BIT((vec64)[(idx) >> BIT_VEC64_ELEM_SHIFT], \
			     (idx) & BIT_VEC64_ELEM_MASK)

#define BIT_VEC64_TEST_BIT(vec64, idx) \
	(((vec64)[(idx) >> BIT_VEC64_ELEM_SHIFT] >> \
	((idx) & BIT_VEC64_ELEM_MASK)) & 0x1)

/* Creates a bitmask of all ones in less significant bits.
   idx - index of the most significant bit in the created mask */
#define BIT_VEC64_ONES_MASK(idx) \
		(((u64)0x1 << (((idx) & BIT_VEC64_ELEM_MASK) + 1)) - 1)
#define BIT_VEC64_ELEM_ONE_MASK	((u64)(~0))


static __inline void __storm_memset_struct(struct _lm_device_t *pdev,
					 u32 addr, size_t size, u32 *data)
{
	u8 i;
	for (i = 0; i < size/4; i++)
		REG_WR(pdev, addr + (i * 4), data[i]);
}

#define MC_HASH_SIZE			8
#define MC_HASH_OFFSET(bp, i)		(BAR_TSTRORM_INTMEM + \
	TSTORM_APPROXIMATE_MATCH_MULTICAST_FILTERING_OFFSET(FUNC_ID(pdev)) + i*4)

#define ECORE_MAX_MULTICAST		    64
#define ECORE_MAX_EMUL_MULTI		1


/**
 * Fill in a MAC address the way the FW likes it
 *
 * @param fw_hi
 * @param fw_mid
 * @param fw_lo
 * @param mac
 */
static __inline void ecore_set_fw_mac_addr(u16 *fw_hi, u16 *fw_mid, u16 *fw_lo,
					 u8 *mac)
{
	((u8 *)fw_hi)[0]  = mac[1];
	((u8 *)fw_hi)[1]  = mac[0];
	((u8 *)fw_mid)[0] = mac[3];
	((u8 *)fw_mid)[1] = mac[2];
	((u8 *)fw_lo)[0]  = mac[5];
	((u8 *)fw_lo)[1]  = mac[4];
}


#endif

