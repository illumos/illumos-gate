#ifndef PTRMAP_H
#define PTRMAP_H

struct ptrmap;

#define DECLARE_PTRMAP(name, ktype, vtype)				\
	struct name ## _pair { ktype key; vtype val; };			\
	struct name { struct name ## _pair block[1]; };			\
	static inline							\
	void name##_add(struct name **map, ktype k, vtype v) {		\
		__ptrmap_add((struct ptrmap**)map, k, v);		\
	}								\
	static inline							\
	void name##_update(struct name **map, ktype k, vtype v) {	\
		__ptrmap_update((struct ptrmap**)map, k, v);		\
	}								\
	static inline							\
	vtype name##_lookup(struct name *map, ktype k) {		\
		vtype val = __ptrmap_lookup((struct ptrmap*)map, k);	\
		return val;						\
	}								\

/* ptrmap.c */
void __ptrmap_add(struct ptrmap **mapp, void *key, void *val);
void __ptrmap_update(struct ptrmap **mapp, void *key, void *val);
void *__ptrmap_lookup(struct ptrmap *map, void *key);

#endif
