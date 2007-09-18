#ifndef __XEN_PUBLIC_HVM_HVM_OP_H__
#define __XEN_PUBLIC_HVM_HVM_OP_H__

/* Get/set subcommands: extra argument == pointer to xen_hvm_param struct. */
#define HVMOP_set_param           0
#define HVMOP_get_param           1
struct xen_hvm_param {
    domid_t  domid;    /* IN */
    uint32_t index;    /* IN */
    uint64_t value;    /* IN/OUT */
};
typedef struct xen_hvm_param xen_hvm_param_t;
DEFINE_XEN_GUEST_HANDLE(xen_hvm_param_t);

/* Set the logical level of one of a domain's PCI INTx wires. */
#define HVMOP_set_pci_intx_level  2
struct xen_hvm_set_pci_intx_level {
    /* Domain to be updated. */
    domid_t  domid;
    /* PCI INTx identification in PCI topology (domain:bus:device:intx). */
    uint8_t  domain, bus, device, intx;
    /* Assertion level (0 = unasserted, 1 = asserted). */
    uint8_t  level;
};
typedef struct xen_hvm_set_pci_intx_level xen_hvm_set_pci_intx_level_t;
DEFINE_XEN_GUEST_HANDLE(xen_hvm_set_pci_intx_level_t);

/* Set the logical level of one of a domain's ISA IRQ wires. */
#define HVMOP_set_isa_irq_level   3
struct xen_hvm_set_isa_irq_level {
    /* Domain to be updated. */
    domid_t  domid;
    /* ISA device identification, by ISA IRQ (0-15). */
    uint8_t  isa_irq;
    /* Assertion level (0 = unasserted, 1 = asserted). */
    uint8_t  level;
};
typedef struct xen_hvm_set_isa_irq_level xen_hvm_set_isa_irq_level_t;
DEFINE_XEN_GUEST_HANDLE(xen_hvm_set_isa_irq_level_t);

#define HVMOP_set_pci_link_route  4
struct xen_hvm_set_pci_link_route {
    /* Domain to be updated. */
    domid_t  domid;
    /* PCI link identifier (0-3). */
    uint8_t  link;
    /* ISA IRQ (1-15), or 0 (disable link). */
    uint8_t  isa_irq;
};
typedef struct xen_hvm_set_pci_link_route xen_hvm_set_pci_link_route_t;
DEFINE_XEN_GUEST_HANDLE(xen_hvm_set_pci_link_route_t);

#endif /* __XEN_PUBLIC_HVM_HVM_OP_H__ */
