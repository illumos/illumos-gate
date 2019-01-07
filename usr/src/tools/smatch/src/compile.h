#ifndef COMPILE_H
#define COMPILE_H

struct symbol;

extern void emit_one_symbol(struct symbol *);
extern void emit_unit_begin(const char *);
extern void emit_unit_end(void);

#endif /* COMPILE_H */
