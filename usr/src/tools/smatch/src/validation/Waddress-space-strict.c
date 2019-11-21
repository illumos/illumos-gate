#define __user __attribute__((address_space(1)))

typedef unsigned long ulong;
typedef struct s obj_t;

static void expl(ulong u, void *v, obj_t *o, obj_t __user *p)
{
	(obj_t*)(u);
	(obj_t __user*)(u);

	(obj_t*)(v);
	(obj_t __user*)(v);

	(ulong)(o);
	(void *)(o);
	(obj_t*)(o);
	(obj_t __user*)(o);

	(ulong)(p);		// w!
	(void *)(p);		// w
	(obj_t*)(p);		// w
	(obj_t __user*)(p);	// ok
}

/*
 * check-name: Waddress-space-strict
 * check-command: sparse -Wcast-from-as -Wcast-to-as $file
 *
 * check-error-start
Waddress-space-strict.c:12:10: warning: cast adds address space '<asn:1>' to expression
Waddress-space-strict.c:17:10: warning: cast adds address space '<asn:1>' to expression
Waddress-space-strict.c:19:10: warning: cast removes address space '<asn:1>' of expression
Waddress-space-strict.c:20:10: warning: cast removes address space '<asn:1>' of expression
Waddress-space-strict.c:21:10: warning: cast removes address space '<asn:1>' of expression
 * check-error-end
 */
