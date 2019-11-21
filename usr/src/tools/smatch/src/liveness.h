#ifndef LIVENESS_H
#define LIVENESS_H

struct entrypoint;

/* liveness.c */
void clear_liveness(struct entrypoint *ep);
void track_pseudo_liveness(struct entrypoint *ep);
void track_pseudo_death(struct entrypoint *ep);

#endif
