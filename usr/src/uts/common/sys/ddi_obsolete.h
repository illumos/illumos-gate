/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*
 * Copyright 2014 Garrett D'Amore <garrett@damore.org>
 */

#ifndef	_SYS_DDI_OBSOLETE_H
#define	_SYS_DDI_OBSOLETE_H

/*
 * Obsoleted DDI Interfaces
 */

#include <sys/types.h>
#include <sys/dditypes.h>
#include <sys/sunldi.h>


#ifdef	__cplusplus
extern "C" {
#endif


#ifndef	_DDI_STRICT

extern long strtol(const char *, char **, int);
extern unsigned long strtoul(const char *, char **, int);

uint8_t ddi_mem_get8(ddi_acc_handle_t handle, uint8_t *host_addr);
uint16_t ddi_mem_get16(ddi_acc_handle_t handle, uint16_t *host_addr);
uint32_t ddi_mem_get32(ddi_acc_handle_t handle, uint32_t *host_addr);
uint64_t ddi_mem_get64(ddi_acc_handle_t handle, uint64_t *host_addr);
void ddi_mem_put8(ddi_acc_handle_t handle, uint8_t *dev_addr, uint8_t value);
void ddi_mem_put16(ddi_acc_handle_t handle, uint16_t *dev_addr, uint16_t value);
void ddi_mem_put32(ddi_acc_handle_t handle, uint32_t *dev_addr, uint32_t value);
void ddi_mem_put64(ddi_acc_handle_t handle, uint64_t *dev_addr, uint64_t value);

void ddi_mem_rep_get8(ddi_acc_handle_t handle, uint8_t *host_addr,
    uint8_t *dev_addr, size_t repcount, uint_t flags);
void ddi_mem_rep_get16(ddi_acc_handle_t handle, uint16_t *host_addr,
    uint16_t *dev_addr, size_t repcount, uint_t flags);
void ddi_mem_rep_get32(ddi_acc_handle_t handle, uint32_t *host_addr,
    uint32_t *dev_addr, size_t repcount, uint_t flags);
void ddi_mem_rep_get64(ddi_acc_handle_t handle, uint64_t *host_addr,
    uint64_t *dev_addr, size_t repcount, uint_t flags);
void ddi_mem_rep_put8(ddi_acc_handle_t handle, uint8_t *host_addr,
    uint8_t *dev_addr, size_t repcount, uint_t flags);
void ddi_mem_rep_put16(ddi_acc_handle_t handle, uint16_t *host_addr,
    uint16_t *dev_addr, size_t repcount, uint_t flags);
void ddi_mem_rep_put32(ddi_acc_handle_t handle, uint32_t *host_addr,
    uint32_t *dev_addr, size_t repcount, uint_t flags);
void ddi_mem_rep_put64(ddi_acc_handle_t handle, uint64_t *host_addr,
    uint64_t *dev_addr, size_t repcount, uint_t flags);

uint8_t ddi_io_get8(ddi_acc_handle_t handle, uint8_t *dev_addr);
uint16_t ddi_io_get16(ddi_acc_handle_t handle, uint16_t *dev_addr);
uint32_t ddi_io_get32(ddi_acc_handle_t handle, uint32_t *dev_addr);
void ddi_io_put8(ddi_acc_handle_t handle, uint8_t *dev_addr, uint8_t value);
void ddi_io_put16(ddi_acc_handle_t handle, uint16_t *dev_addr, uint16_t value);
void ddi_io_put32(ddi_acc_handle_t handle, uint32_t *dev_addr, uint32_t value);

void ddi_io_rep_get8(ddi_acc_handle_t handle,
    uint8_t *host_addr, uint8_t *dev_addr, size_t repcount);
void ddi_io_rep_get16(ddi_acc_handle_t handle,
    uint16_t *host_addr, uint16_t *dev_addr, size_t repcount);
void ddi_io_rep_get32(ddi_acc_handle_t handle,
    uint32_t *host_addr, uint32_t *dev_addr, size_t repcount);
void ddi_io_rep_put8(ddi_acc_handle_t handle,
    uint8_t *host_addr, uint8_t *dev_addr, size_t repcount);
void ddi_io_rep_put16(ddi_acc_handle_t handle,
    uint16_t *host_addr, uint16_t *dev_addr, size_t repcount);
void ddi_io_rep_put32(ddi_acc_handle_t handle,
    uint32_t *host_addr, uint32_t *dev_addr, size_t repcount);

/* only support older interfaces on 32-bit systems */
#ifdef _ILP32
#define	ddi_mem_getb		ddi_mem_get8
#define	ddi_mem_getw		ddi_mem_get16
#define	ddi_mem_getl		ddi_mem_get32
#define	ddi_mem_getll		ddi_mem_get64
#define	ddi_mem_rep_getb	ddi_mem_rep_get8
#define	ddi_mem_rep_getw	ddi_mem_rep_get16
#define	ddi_mem_rep_getl	ddi_mem_rep_get32
#define	ddi_mem_rep_getll	ddi_mem_rep_get64
#define	ddi_mem_putb		ddi_mem_put8
#define	ddi_mem_putw		ddi_mem_put16
#define	ddi_mem_putl		ddi_mem_put32
#define	ddi_mem_putll		ddi_mem_put64
#define	ddi_mem_rep_putb	ddi_mem_rep_put8
#define	ddi_mem_rep_putw	ddi_mem_rep_put16
#define	ddi_mem_rep_putl	ddi_mem_rep_put32
#define	ddi_mem_rep_putll	ddi_mem_rep_put64
#define	ddi_io_getb		ddi_io_get8
#define	ddi_io_getw		ddi_io_get16
#define	ddi_io_getl		ddi_io_get32
#define	ddi_io_putb		ddi_io_put8
#define	ddi_io_putw		ddi_io_put16
#define	ddi_io_putl		ddi_io_put32
#define	ddi_getb		ddi_get8
#define	ddi_getw		ddi_get16
#define	ddi_getl		ddi_get32
#define	ddi_getll		ddi_get64
#define	ddi_rep_getb		ddi_rep_get8
#define	ddi_rep_getw		ddi_rep_get16
#define	ddi_rep_getl		ddi_rep_get32
#define	ddi_rep_getll		ddi_rep_get64
#define	ddi_putb		ddi_put8
#define	ddi_putw		ddi_put16
#define	ddi_putl		ddi_put32
#define	ddi_putll		ddi_put64
#define	ddi_rep_putb		ddi_rep_put8
#define	ddi_rep_putw		ddi_rep_put16
#define	ddi_rep_putl		ddi_rep_put32
#define	ddi_rep_putll		ddi_rep_put64

/* These can't be define's since they're not asm routines */
void ddi_io_rep_getb(ddi_acc_handle_t handle, uint8_t *host_addr,
    uint8_t *dev_addr, size_t repcount);
void ddi_io_rep_getw(ddi_acc_handle_t handle, uint16_t *host_addr,
    uint16_t *dev_addr, size_t repcount);
void ddi_io_rep_getl(ddi_acc_handle_t handle, uint32_t *host_addr,
    uint32_t *dev_addr, size_t repcount);
void ddi_io_rep_putb(ddi_acc_handle_t handle, uint8_t *host_addr,
    uint8_t *dev_addr, size_t repcount);
void ddi_io_rep_putw(ddi_acc_handle_t handle, uint16_t *host_addr,
    uint16_t *dev_addr, size_t repcount);
void ddi_io_rep_putl(ddi_acc_handle_t handle, uint32_t *host_addr,
    uint32_t *dev_addr, size_t repcount);

int ddi_peekc(dev_info_t *dip, int8_t *addr, int8_t *val_p);
int ddi_peeks(dev_info_t *dip, int16_t *addr, int16_t *val_p);
int ddi_peekl(dev_info_t *dip, int32_t *addr, int32_t *val_p);
int ddi_peekd(dev_info_t *dip, int64_t *addr, int64_t *val_p);
int ddi_pokec(dev_info_t *dip, int8_t *addr, int8_t val);
int ddi_pokes(dev_info_t *dip, int16_t *addr, int16_t val);
int ddi_pokel(dev_info_t *dip, int32_t *addr, int32_t val);
int ddi_poked(dev_info_t *dip, int64_t *addr, int64_t val);

uint8_t pci_config_getb(ddi_acc_handle_t handle, off_t offset);
uint16_t pci_config_getw(ddi_acc_handle_t handle, off_t offset);
uint32_t pci_config_getl(ddi_acc_handle_t handle, off_t offset);
uint64_t pci_config_getll(ddi_acc_handle_t handle, off_t offset);
void pci_config_putb(ddi_acc_handle_t handle, off_t offset, uint8_t value);
void pci_config_putw(ddi_acc_handle_t handle, off_t offset, uint16_t value);
void pci_config_putl(ddi_acc_handle_t handle, off_t offset, uint32_t value);
void pci_config_putll(ddi_acc_handle_t handle, off_t offset, uint64_t value);

extern void repinsb(int port, uint8_t *addr, int count);
extern void repinsw(int port, uint16_t *addr, int count);
extern void repinsd(int port, uint32_t *addr, int count);
extern void repoutsb(int port, uint8_t *addr, int count);
extern void repoutsw(int port, uint16_t *addr, int count);
extern void repoutsd(int port, uint32_t *addr, int count);
#endif

/* Obsolete LDI event interfaces */
extern int ldi_get_eventcookie(ldi_handle_t, char *,
    ddi_eventcookie_t *);
extern int ldi_add_event_handler(ldi_handle_t, ddi_eventcookie_t,
    void (*handler)(ldi_handle_t, ddi_eventcookie_t, void *, void *),
    void *, ldi_callback_id_t *);
extern int ldi_remove_event_handler(ldi_handle_t, ldi_callback_id_t);


#endif /* not _DDI_STRICT */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_DDI_OBSOLETE_H */
