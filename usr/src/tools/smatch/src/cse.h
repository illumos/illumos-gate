#ifndef CSE_H
#define CSE_H

struct instruction;
struct entrypoint;

/* cse.c */
void cse_collect(struct instruction *insn);
void cse_eliminate(struct entrypoint *ep);

#endif
