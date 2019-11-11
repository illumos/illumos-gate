
#define __kernel __attribute__((address_space(0)))
#define __user   __attribute__((address_space(__user)))
#define __iomem  __attribute__((address_space(__iomem)))
#define __percpu __attribute__((address_space(__percpu)))
#define __rcu    __attribute__((address_space(__rcu)))


typedef struct s obj_t;

static void expl(obj_t __kernel *k, obj_t __iomem *o,
		 obj_t __user *p, obj_t __percpu *pc,
		 obj_t __rcu *r)
{
	(__UINTPTR_TYPE__)(k);	// OK
	(unsigned long)(k);	// OK
	(void *)(k);		// OK
	(obj_t*)(k);		// OK
	(obj_t __kernel*)(k);	// OK

	(__UINTPTR_TYPE__)(o);	// OK
	(unsigned long)(o);	// OK
	(void *)(o);
	(obj_t*)(o);
	(obj_t __iomem*)(o);	// OK

	(__UINTPTR_TYPE__)(p);	// OK
	(unsigned long)(p);	// OK
	(void *)(p);
	(obj_t*)(p);
	(obj_t __user*)(p);	// OK

	(__UINTPTR_TYPE__)(pc);	// OK
	(unsigned long)(pc);	// OK
	(void *)(pc);
	(obj_t*)(pc);
	(obj_t __percpu*)(pc);	// OK

	(__UINTPTR_TYPE__)(r);	// OK
	(unsigned long)(r);	// OK
	(void *)(r);
	(obj_t*)(r);
	(obj_t __rcu*)(r);	// OK
}

/*
 * check-name: Waddress-space-from
 * check-command: sparse -Wno-cast-from-as $file
 * check-description: Test the removal of AS from a pointer but only
 *	in the non-strict variant where casts to ulong (or uintptr_t)
 *	are allowed.
 *
 * check-error-start
Waddress-space-from.c:23:10: warning: cast removes address space '__iomem' of expression
Waddress-space-from.c:24:10: warning: cast removes address space '__iomem' of expression
Waddress-space-from.c:29:10: warning: cast removes address space '__user' of expression
Waddress-space-from.c:30:10: warning: cast removes address space '__user' of expression
Waddress-space-from.c:35:10: warning: cast removes address space '__percpu' of expression
Waddress-space-from.c:36:10: warning: cast removes address space '__percpu' of expression
Waddress-space-from.c:41:10: warning: cast removes address space '__rcu' of expression
Waddress-space-from.c:42:10: warning: cast removes address space '__rcu' of expression
 * check-error-end
 */
