extern void __attribute__((cdecl)) c1(void);
typedef void (__attribute__((cdecl)) *c2)(void);
typedef c2 c2ptr;

extern void __attribute__((__cdecl__)) c_1(void);
typedef void (__attribute__((__cdecl__)) *c_2)(void);
typedef c_2 c_2ptr;

extern void __attribute__((stdcall)) s1(void);
typedef void (__attribute__((stdcall)) *s2)(void);
typedef s2 s2ptr;

extern void __attribute__((__stdcall__)) s_1(void);
typedef void (__attribute__((__stdcall__)) *s_2)(void);
typedef s_2 s_2ptr;

extern void __attribute__((fastcall)) f1(void);
typedef void (__attribute__((fastcall)) *f2)(void);
typedef f2 f2ptr;

extern void __attribute__((__fastcall__)) f_1(void);
typedef void (__attribute__((__fastcall__)) *f_2)(void);
typedef f_2 f_2ptr;
/*
 * check-name: Calling convention attributes
 */
