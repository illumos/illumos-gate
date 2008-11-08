#if !defined(ISA_H) && defined(CONFIG_ISA)
#define ISA_H

struct dev;

#define ISAPNP_VENDOR(a,b,c)	(((((a)-'A'+1)&0x3f)<<2)|\
				((((b)-'A'+1)&0x18)>>3)|((((b)-'A'+1)&7)<<13)|\
				((((c)-'A'+1)&0x1f)<<8))

#define	GENERIC_ISAPNP_VENDOR	ISAPNP_VENDOR('P','N','P')

struct isa_driver
{
	int type;
	const char *name;
	int (*probe)(struct dev *, unsigned short *);
	unsigned short *ioaddrs;
};

#define __isa_driver	__attribute__ ((unused,__section__(".drivers.isa")))
extern const struct isa_driver isa_drivers[];
extern const struct isa_driver isa_drivers_end[];

#define ISA_ROM(IMAGE, DESCRIPTION)

#endif /* ISA_H */

