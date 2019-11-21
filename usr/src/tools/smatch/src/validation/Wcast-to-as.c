#define __user __attribute__((address_space(1)))

typedef __UINTPTR_TYPE__ uintptr_t;
typedef unsigned long ulong;
typedef struct s obj_t;

static void expl(ulong u, uintptr_t uip, void *v, obj_t *o, obj_t __user *p)
{
	(obj_t*)(u);
	(obj_t __user*)(u);

	(obj_t*)(uip);
	(obj_t __user*)(uip);

	(obj_t*)(v);
	(obj_t __user*)(v);

	(ulong)(o);
	(void *)(o);
	(obj_t*)(o);
	(obj_t __user*)(o);

	(ulong)(p);
	(obj_t __user*)(p);

}

/*
 * check-name: cast-to-as
 * check-command: sparse -Wcast-to-as $file
 *
 * check-error-start
Wcast-to-as.c:16:10: warning: cast adds address space '<asn:1>' to expression
Wcast-to-as.c:21:10: warning: cast adds address space '<asn:1>' to expression
 * check-error-end
 */
