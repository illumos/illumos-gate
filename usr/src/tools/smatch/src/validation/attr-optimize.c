
#define __noclone	__attribute__((__noclone__, __optimize__("no-tracer")))

struct kvm_vcpu;

static void __noclone vmx_vcpu_run(struct kvm_vcpu *vcpu)
{
	__asm__("");
}

extern void *run;
void *run = vmx_vcpu_run;

/*
 * check-name: optimize attributes
 */
