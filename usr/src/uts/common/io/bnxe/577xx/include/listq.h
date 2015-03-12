/*******************************************************************************
 * The information contained in this file is confidential and proprietary to
 * ZNK Corporation.  No part of this file may be reproduced or distributed,
 * in any form or by any means for any purpose, without the express written
 * permission of ZNK Corporation.
 *
 * (c) COPYRIGHT 1998 ZNK Corporation, ALL RIGHTS RESERVED.
 *
 * Single link list routines:
 *    void              s_list_init        (s_list_t *,  *head, *tail, cnt)
 *    void              s_list_clear       (s_list_t *)
 *    void              s_list_push_head   (s_list_t *,  s_list_entry_t *)
 *    s_list_entry_t *  s_list_pop_head    (s_list_t *)
 *    void              s_list_push_tail   (s_list_t *,  s_list_entry_t *)
 *    s_list_entry_t *  s_list_peek_head   (s_list_t *)
 *    s_list_entry_t *  s_list_peek_tail   (s_list_t *)
 *    s_list_entry_t *  s_list_next_entry  (s_list_entry_t *)
 *    unsigned long     s_list_entry_cnt   (s_list_t *)
 *    char              s_list_is_empty    (s_list_t *)
 *    void              s_list_add_head    (s_list_t *,  s_list_t *)
 *    void              s_list_add_tail    (s_list_t *,  s_list_t *)
 *    void              s_list_split       (d_list_t *,  d_list_t *, d_list_entry_t *, ulong)
 *
 * Double link list routines:
 *    void              d_list_init        (d_list_t *,  *head, *tail, cnt)
 *    void              d_list_clear       (d_list_t *)
 *    void              d_list_push_head   (d_list_t *,  d_list_entry_t *)
 *    d_list_entry_t *  d_list_pop_head    (d_list_t *)
 *    void              d_list_push_tail   (d_list_t *,  d_list_entry_t *)
 *    d_list_entry_t *  d_list_pop_tail    (d_list_t *)
 *    d_list_entry_t *  d_list_peek_head   (d_list_t *)
 *    d_list_entry_t *  d_list_peek_tail   (d_list_t *)
 *    d_list_entry_t *  d_list_next_entry  (d_list_entry_t *)
 *    void              d_list_remove_entry(d_list_t *,  d_list_entry_t *)
 *    void              d_list_insert_entry(d_list_t *,  *prev, *next, *new)
 *    d_list_entry_t *  d_list_prev_entry  (d_list_entry_t *)
 *    unsigned long     d_list_entry_cnt   (d_list_t *)
 *    char              d_list_is_empty    (d_list_t *)
 *    void              d_list_add_head    (d_list_t *,  d_list_t *)
 *    void              d_list_add_tail    (d_list_t *,  d_list_t *)
 *
 * Array list routines:
 *    void              q_list_init        (q_list_t *,  q_list_entry *, ulong)
 *    void              q_list_clear       (q_list_t *)
 *    void              q_list_push_head   (q_list_t *,  q_list_entry_t)
 *    q_list_entry_t    q_list_pop_head    (q_list_t *)
 *    void              q_list_push_tail   (q_list_t *,  q_list_entry_t)
 *    q_list_entry_t    q_list_pop_tail    (q_list_t *)
 *    q_list_entry_t    q_list_peek_head   (q_list_t *)
 *    q_list_entry_t    q_list_peek_tail   (q_list_t *)
 *    unsigned long     q_list_entry_cnt   (q_list_t *)
 *    char              q_list_is_empty    (q_list_t *)
 *    char              q_list_is_full     (q_list_t *)
 *
 * History:
 *    03/30/98 Hav Khauv                Initial version.
 ******************************************************************************/

#ifndef _listq_h_
#define _listq_h_



/*******************************************************************************
 * Single link list.
 ******************************************************************************/

typedef struct _s_list_entry_t
{
    struct _s_list_entry_t *next;
} s_list_entry_t;

#define S_LINK_CAST(_p)                 ((s_list_entry_t *) (_p))


typedef struct _s_list_t
{
    s_list_entry_t *head;
    s_list_entry_t *tail;
    unsigned long cnt;
} s_list_t;



#ifdef _INLINE_LISTQ_CALLS


__inline
void 
s_list_init(
    s_list_t *s_list,
    s_list_entry_t *head_entry,
    s_list_entry_t *tail_entry,
    unsigned long entry_cnt)
{
    s_list->head = head_entry;
    s_list->tail = tail_entry;
    s_list->cnt = entry_cnt;
}


__inline
void 
s_list_clear(
    s_list_t *s_list)
{
    s_list->head = (s_list_entry_t *) 0;
    s_list->tail = (s_list_entry_t *) 0;
    s_list->cnt = 0;
}


__inline
void
s_list_push_head(
    s_list_t *s_list,
    s_list_entry_t *s_entry)
{
    s_entry->next = s_list->head;

    if(s_list->tail == (s_list_entry_t *) 0)
    {
        s_list->tail = s_entry;
    }
    s_list->head = s_entry;

    s_list->cnt++;
}


__inline
s_list_entry_t *
s_list_pop_head(
    s_list_t *s_list)
{
    s_list_entry_t *s_entry;

    s_entry = s_list->head;
    if(s_list->head)
    {
        s_list->head = s_list->head->next;
        if(s_list->head == (s_list_entry_t *) 0)
        {
            s_list->tail = (s_list_entry_t *) 0;
        }

        s_list->cnt--;
    }

    return s_entry;
}


__inline
void
s_list_push_tail(
    s_list_t *s_list,
    s_list_entry_t *s_entry)
{
    s_entry->next = (s_list_entry_t *) 0;

    if(s_list->tail)
    {
        s_list->tail->next = s_entry;
    }
    else
    {
        s_list->head = s_entry;
    }
    s_list->tail = s_entry;

    s_list->cnt++;
}


__inline
s_list_entry_t *
s_list_peek_head(
    s_list_t *s_list)
{
    return s_list->head;
}


__inline
s_list_entry_t *
s_list_peek_tail(
    s_list_t *s_list)
{
    return s_list->tail;
}


__inline
s_list_entry_t *
s_list_next_entry(
    s_list_entry_t *s_entry)
{
    return s_entry->next;
}


__inline
unsigned long
s_list_entry_cnt(
    s_list_t *s_list)
{
    return s_list->cnt;
}


__inline
char
s_list_is_empty(
    s_list_t *s_list)
{
    return s_list->cnt == 0;
}


__inline
void
s_list_add_head(
    s_list_t *s_list,
    s_list_t *s_list_head)
{
    if(s_list->cnt == 0)
    {
        *s_list = *s_list_head;
    }
    else if(s_list_head->cnt)
    {
        s_list_head->tail->next = s_list->head;
        s_list->head = s_list_head->head;
        s_list->cnt += s_list_head->cnt;
    }
}


__inline
void
s_list_add_tail(
    s_list_t *s_list,
    s_list_t *s_list_tail)
{
    if(s_list->cnt == 0)
    {
        *s_list = *s_list_tail;
    }
    else if(s_list_tail->cnt)
    {
        s_list->tail->next = s_list_tail->head;
        s_list->tail = s_list_tail->tail;
        s_list->cnt += s_list_tail->cnt;
    }
}

__inline
void
s_list_split(
    s_list_t * s_list, 
    s_list_t * s_list_head, 
    s_list_entry_t * split_entry, 
    unsigned long entry_cnt)
{
    if (split_entry->next == NULL) {
        s_list_head->head = s_list->head;
        s_list_head->tail = split_entry;
        s_list_head->cnt = entry_cnt;

        s_list->head = NULL;
        s_list->tail = NULL;
        s_list->cnt = 0;
    } else {
        s_list_head->head = s_list->head;
        s_list_head->tail = split_entry;
        s_list_head->cnt = entry_cnt;

        s_list->head = split_entry->next;
        s_list->cnt = s_list->cnt - entry_cnt;
        split_entry->next = NULL;
        
    }
}

#else


#define s_list_init(_s_list, _head_entry, _tail_entry, _entry_cnt) \
    (_s_list)->head = (_head_entry); \
    (_s_list)->tail = (_tail_entry); \
    (_s_list)->cnt = (_entry_cnt)


#define s_list_clear(_s_list) \
    (_s_list)->head = (s_list_entry_t *) 0; \
    (_s_list)->tail = (s_list_entry_t *) 0; \
    (_s_list)->cnt = 0


#define s_list_push_head(_s_list, _s_entry) \
    (_s_entry)->next = (_s_list)->head; \
    if((_s_list)->tail == (s_list_entry_t *) 0) \
    { \
        (_s_list)->tail = (_s_entry); \
    } \
    (_s_list)->head = (_s_entry); \
    (_s_list)->cnt++


#define s_list_pop_head(_s_list) \
    (_s_list)->head; \
    if((_s_list)->head) \
    { \
        (_s_list)->head = (_s_list)->head->next; \
        if((_s_list)->head == (s_list_entry_t *) 0) \
        { \
            (_s_list)->tail = (s_list_entry_t *) 0; \
        } \
        (_s_list)->cnt--; \
    }


#define s_list_push_tail(_s_list, _s_entry) \
    (_s_entry)->next = (s_list_entry_t *) 0; \
    if((_s_list)->tail) \
    { \
        (_s_list)->tail->next = (_s_entry); \
    } \
    else \
    { \
        (_s_list)->head = (_s_entry); \
    } \
    (_s_list)->tail = (_s_entry); \
    (_s_list)->cnt++ 


#define s_list_peek_head(_s_list)       ((_s_list)->head)


#define s_list_peek_tail(_s_list)       ((_s_list)->tail)


#define s_list_next_entry(_s_entry)     ((_s_entry)->next)


#define s_list_entry_cnt(_s_list)       ((_s_list)->cnt)


#define s_list_is_empty(_s_list)        ((_s_list)->cnt == 0)


#define s_list_add_head(_s_list, _s_list_head) \
    if((_s_list)->cnt == 0) \
    { \
        *(_s_list) = *(_s_list_head); \
    } \
    else if((_s_list_head)->cnt) \
    { \
        (_s_list_head)->tail->next = (_s_list)->head; \
        (_s_list)->head = (_s_list_head)->head; \
        (_s_list)->cnt += (_s_list_head)->cnt; \
    }

#define s_list_add_tail(_s_list, _s_list_tail) \
    if((_s_list)->cnt == 0) \
    { \
        *(_s_list) = *(_s_list_tail); \
    } \
    else if((_s_list_tail)->cnt) \
    { \
        (_s_list)->tail->next = (_s_list_tail)->head; \
        (_s_list)->tail = (_s_list_tail)->tail; \
        (_s_list)->cnt += (_s_list_tail)->cnt; \
    }

#define s_list_split(_s_list, _s_list_head, _split_entry, _entry_cnt) \
    if ((_split_entry)->next == NULL) { \
        (_s_list_head)->head = (_s_list)->head; \
        (_s_list_head)->tail = _split_entry; \
        (_s_list_head)->cnt = _entry_cnt; \
        (_s_list)->head = NULL; \
        (_s_list)->tail = NULL; \
        (_s_list)->cnt = 0; \
    } else { \
        (_s_list_head)->head = (_s_list)->head; \
        (_s_list_head)->tail = _split_entry; \
        (_s_list_head)->cnt = (_entry_cnt); \
        (_s_list)->head = (_split_entry)->next; \
        (_s_list)->cnt = (_s_list)->cnt - (_entry_cnt); \
        (_split_entry)->next = NULL; \
    }

#endif



/*******************************************************************************
 * Double link list entry.
 ******************************************************************************/

typedef struct _d_list_entry_t
{
    struct _d_list_entry_t *next;
    struct _d_list_entry_t *prev;
} d_list_entry_t;

#define D_LINK_CAST(_p)                 ((d_list_entry_t *) (_p))


typedef struct _d_list_t
{
    d_list_entry_t *head;
    d_list_entry_t *tail;
    unsigned long cnt;
} d_list_t;



#ifdef _INLINE_LISTQ_CALLS


__inline
void 
d_list_init(
    d_list_t *d_list,
    d_list_entry_t *head_entry,
    d_list_entry_t *tail_entry,
    unsigned long entry_cnt)
{
    d_list->head = head_entry;
    d_list->tail = tail_entry;
    d_list->cnt = entry_cnt;
}


__inline
void 
d_list_clear(
    d_list_t *d_list)
{
    d_list->head = (d_list_entry_t *) 0;
    d_list->tail = (d_list_entry_t *) 0;
    d_list->cnt = 0;
}


__inline
void
d_list_push_head(
    d_list_t *d_list,
    d_list_entry_t *d_entry)
{
    d_entry->prev = (d_list_entry_t *) 0;
    d_entry->next = d_list->head;

    if(d_list->tail == (d_list_entry_t *) 0)
    {
        d_list->tail = d_entry;
    }
    else
    {
        d_list->head->prev = d_entry;
    }

    d_list->head = d_entry;

    d_list->cnt++;
}


__inline
d_list_entry_t *
d_list_pop_head(
    d_list_t *d_list)
{
    d_list_entry_t *d_entry;

    d_entry = d_list->head;
    if(d_list->head)
    {
        d_list->head = d_list->head->next;
        if(d_list->head)
        {
            d_list->head->prev = (d_list_entry_t *) 0;
        }
        else
        {
            d_list->tail = (d_list_entry_t *) 0;
        }

        d_list->cnt--;
    }

    return d_entry;
}


__inline
void
d_list_push_tail(
    d_list_t *d_list,
    d_list_entry_t *d_entry)
{
    d_entry->next = (d_list_entry_t *) 0;
    d_entry->prev = d_list->tail;

    if(d_list->tail)
    {
        d_list->tail->next = d_entry;
    }
    else
    {
        d_list->head = d_entry;
    }
    d_list->tail = d_entry;

    d_list->cnt++;
}


__inline
d_list_entry_t *
d_list_pop_tail(
    d_list_t *d_list)
{
    d_list_entry_t *d_entry;

    d_entry = d_list->tail;

    if(d_list->tail)
    {
        d_list->tail = d_list->tail->prev;
        if(d_list->tail)
        {
            d_list->tail->next = (d_list_entry_t *) 0;
        }
        else
        {
            d_list->head = (d_list_entry_t *) 0;
        }

        d_list->cnt--;
    }

    return d_entry;
}


__inline
d_list_entry_t *
d_list_peek_head(
    d_list_t *d_list)
{
    return d_list->head;
}


__inline
d_list_entry_t *
d_list_peek_tail(
    d_list_t *d_list)
{
    return d_list->tail;
}


__inline
d_list_entry_t *
d_list_next_entry(
    d_list_entry_t *d_entry)
{
    return d_entry->next;
}


__inline
void
d_list_remove_entry(
    d_list_t *d_list,
    d_list_entry_t *d_entry)
{
    if(d_list->head == d_entry)
    {
        d_list_pop_head(d_list);
    }
    else if(d_list->tail == d_entry)
    {
        d_list_pop_tail(d_list);
    }
    else
    {
        d_entry->prev->next = d_entry->next;
        d_entry->next->prev = d_entry->prev;
        d_list->cnt--;
    }
}

__inline
void
d_list_insert_entry(
    d_list_t *d_list,
    d_list_entry_t *d_entry_prev,
    d_list_entry_t *d_entry_next,
    d_list_entry_t *d_entry)
{
    if (d_entry_prev  == NULL)
    {
        d_list_push_head(d_list, d_entry);
    }
    else if (d_entry_next == NULL)
    {
        d_list_push_tail(d_list, d_entry);
    }
    else
    {
        d_entry->next = d_entry_next;
        d_entry->prev = d_entry_prev;
        d_entry_prev->next = d_entry;
        d_entry_next->prev = d_entry;
        d_list->cnt++;
    }
}


__inline
d_list_entry_t *
d_list_prev_entry(
    d_list_entry_t *d_entry)
{
    return d_entry->prev;
}


__inline
unsigned long
d_list_entry_cnt(
    d_list_t *d_list)
{
    return d_list->cnt;
}


__inline
char
d_list_is_empty(
    d_list_t *d_list)
{
    return d_list->cnt == 0;
}


__inline
void
d_list_add_head(
    d_list_t *d_list,
    d_list_t *d_list_head)
{
    d_list_head->tail->next = d_list->head;

    if(d_list->head)
    {
        d_list->head->prev = d_list_head->tail;
    }
    else
    {
        d_list->tail = d_list_head->tail;
    }
    d_list->head = d_list_head->head;

    d_list->cnt += d_list_head->cnt;
}


__inline
void
d_list_add_tail(
    d_list_t *d_list,
    d_list_t *d_list_tail)
{
    d_list_tail->head->prev = d_list->tail;

    if(d_list->tail)
    {
        d_list->tail->next = d_list_tail->head;
    }
    else
    {
        d_list->head = d_list_tail->head;
    }
    d_list->tail = d_list_tail->tail;

    d_list->cnt += d_list_tail->cnt;
}


#else


#define d_list_init(_d_list, _head_entry, _tail_entry, _entry_cnt) \
    (_d_list)->head = (_head_entry); \
    (_d_list)->tail = (_tail_entry); \
    (_d_list)->cnt = (_entry_cnt)


#define d_list_clear(_d_list) \
    (_d_list)->head = (d_list_entry_t *) 0; \
    (_d_list)->tail = (d_list_entry_t *) 0; \
    (_d_list)->cnt = 0


#define d_list_push_head(_d_list, _d_entry) \
    (_d_entry)->prev = (d_list_entry_t *) 0; \
    (_d_entry)->next = (_d_list)->head; \
    if((_d_list)->tail == (d_list_entry_t *) 0) \
    { \
        (_d_list)->tail = (_d_entry); \
    } \
    else \
    { \
        (_d_list)->head->prev = (_d_entry); \
    } \
    (_d_list)->head = (_d_entry); \
    (_d_list)->cnt++ 


#define d_list_pop_head(_d_list) \
    (_d_list)->head; \
    if((_d_list)->head) \
    { \
        (_d_list)->head = (_d_list)->head->next; \
        if((_d_list)->head) \
        { \
            (_d_list)->head->prev = (d_list_entry_t *) 0; \
        } \
        else \
        { \
            (_d_list)->tail = (d_list_entry_t *) 0; \
        } \
        (_d_list)->cnt--; \
    }


#define d_list_push_tail(_d_list, _d_entry) \
    (_d_entry)->next = (d_list_entry_t *) 0; \
    (_d_entry)->prev = (_d_list)->tail; \
    if((_d_list)->tail) \
    { \
        (_d_list)->tail->next = (_d_entry); \
    } \
    else \
    { \
        (_d_list)->head = (_d_entry); \
    } \
    (_d_list)->tail = (_d_entry); \
    (_d_list)->cnt++


#define d_list_pop_tail(_d_list) \
    (_d_list)->tail; \
    if((_d_list)->tail) \
    { \
        (_d_list)->tail = (_d_list)->tail->prev; \
        if((_d_list)->tail) \
        { \
            (_d_list)->tail->next = (d_list_entry_t *) 0; \
        } \
        else \
        { \
            (_d_list)->head = (d_list_entry_t *) 0; \
        } \
        (_d_list)->cnt--; \
    }


#define d_list_peek_head(_d_list)       ((_d_list)->head)


#define d_list_peek_tail(_d_list)       ((_d_list)->tail)


#define d_list_next_entry(_d_entry)     ((_d_entry)->next)

#define d_list_insert_entry(_d_list, _d_entry_prev, _d_entry_next, _d_entry) \
    if (_d_entry_prev  == NULL ) \
    { \
        (_d_entry)->prev = (d_list_entry_t *) 0; \
        (_d_entry)->next = (_d_list)->head; \
        if((_d_list)->tail == (d_list_entry_t *) 0) \
        { \
            (_d_list)->tail = (_d_entry); \
        } \
        (_d_list)->head = (_d_entry); \
        (_d_list)->cnt++; \
    } \
    else if (_d_entry_next == NULL ) \
    { \
        (_d_entry)->next = (d_list_entry_t *) 0; \
        (_d_entry)->prev = (_d_list)->tail; \
        if((_d_list)->tail) \
        { \
            (_d_list)->tail->next = (_d_entry); \
        } \
        else \
        { \
            (_d_list)->head = (_d_entry); \
        } \
        (_d_list)->tail = (_d_entry); \
        (_d_list)->cnt++; \
    } \
    else \
    { \
        (_d_entry)->next = (_d_entry_next); \
        (_d_entry)->prev = (_d_entry_prev); \
        (_d_entry_prev)->next = (_d_entry); \
        (_d_entry_next)->prev = (_d_entry); \
        (_d_list)->cnt++; \
    }

#define d_list_remove_entry(_d_list, _d_entry) \
    if((_d_list)->head == (_d_entry)) \
    { \
        if((_d_list)->head) \
        { \
            (_d_list)->head = (_d_list)->head->next; \
            if((_d_list)->head) \
            { \
                (_d_list)->head->prev = (d_list_entry_t *) 0; \
            } \
            else \
            { \
                (_d_list)->tail = (d_list_entry_t *) 0; \
            } \
            (_d_list)->cnt--; \
        } \
    } \
    else if((_d_list)->tail == (_d_entry)) \
    { \
        if((_d_list)->tail) \
        { \
            (_d_list)->tail = (_d_list)->tail->prev; \
            if((_d_list)->tail) \
            { \
                (_d_list)->tail->next = (d_list_entry_t *) 0; \
            } \
            else \
            { \
                (_d_list)->head = (d_list_entry_t *) 0; \
            } \
            (_d_list)->cnt--; \
        } \
    } \
    else \
    { \
        (_d_entry)->prev->next = (_d_entry)->next; \
        (_d_entry)->next->prev = (_d_entry)->prev; \
        (_d_list)->cnt--; \
    }


#define d_list_prev_entry(_d_entry)     ((_d_entry)->prev)


#define d_list_entry_cnt(_d_list)       ((_d_list)->cnt)


#define d_list_is_empty(_d_list)        ((_d_list)->cnt == 0)


#define d_list_add_head(_d_list, _d_list_head) \
    (_d_list_head)->tail->next = (_d_list)->head; \
    if((_d_list)->head) \
    { \
        (_d_list)->head->prev = (_d_list_head)->tail; \
    } \
    else \
    { \
        (_d_list)->tail = (_d_list_head)->tail; \
    } \
    (_d_list)->head = (_d_list_head)->head; \
    (_d_list)->cnt += (_d_list_head)->cnt


#define d_list_add_tail(_d_list, _d_list_tail) \
    (_d_list_tail)->head->prev = (_d_list)->tail; \
    if((_d_list)->tail) \
    { \
        (_d_list)->tail->next = (_d_list_tail)->head; \
    } \
    else \
    { \
        (_d_list)->head = (_d_list_tail)->head; \
    } \
    (_d_list)->tail = (_d_list_tail)->tail; \
    (_d_list)->cnt += (_d_list_tail)->cnt


#endif



/*******************************************************************************
 * Array list.
 ******************************************************************************/

typedef void *q_list_entry_t;

typedef struct _q_list_t
{
    q_list_entry_t *head;
    q_list_entry_t *tail;
    unsigned long cnt;

    unsigned long max_cnt;
    q_list_entry_t *first_entry_addr;
    q_list_entry_t *last_entry_addr;
} q_list_t;



#ifdef _INLINE_LISTQ_CALLS


__inline
void 
q_list_init(
    q_list_t *q_list,
    q_list_entry_t q_list_arr[],
    unsigned long max_cnt)
{
    q_list->max_cnt = max_cnt;
    q_list->first_entry_addr = q_list_arr;
    q_list->last_entry_addr = q_list_arr + (max_cnt-1);

    q_list->head = q_list->first_entry_addr;
    q_list->tail = q_list->first_entry_addr;
    q_list->cnt = 0;
}


__inline
void
q_list_clear(
    q_list_t *q_list)
{
    q_list->head = q_list->first_entry_addr;
    q_list->tail = q_list->first_entry_addr;
    q_list->cnt = 0;
}


__inline
void
q_list_push_head(
    q_list_t *q_list,
    q_list_entry_t q_entry)
{
    if(q_list->cnt < q_list->max_cnt)
    {
        if(q_list->head == q_list->first_entry_addr)
        {
            q_list->head = q_list->last_entry_addr;
        }
        else
        {
            q_list->head--;
        }

        *(q_list->head) = q_entry;
        q_list->cnt++;
    }
}


__inline
q_list_entry_t
q_list_pop_head(
    q_list_t *q_list)
{
    q_list_entry_t q_entry;

    q_entry = q_list->cnt ? *q_list->head : (q_list_entry_t *) 0;
    if(q_list->cnt)
    {
        if(q_list->head == q_list->last_entry_addr)
        {
            q_list->head = q_list->first_entry_addr;
        }
        else
        {
            q_list->head++;
        }

        q_list->cnt--;
    }

    return q_entry;
}


__inline
void
q_list_push_tail(
    q_list_t *q_list,
    q_list_entry_t q_entry)
{
    if(q_list->cnt < q_list->max_cnt)
    {
        *q_list->tail = q_entry;
        if(q_list->tail == q_list->last_entry_addr)
        {
            q_list->tail = q_list->first_entry_addr;
        }
        else
        {
            q_list->tail++;
        }

        q_list->cnt++;
    }
}


__inline
q_list_entry_t
q_list_pop_tail(
    q_list_t *q_list)
{
    q_list_entry_t q_entry;

    q_entry = q_list->cnt ?
        (q_list->tail == q_list->first_entry_addr ?
            *q_list->last_entry_addr : *(q_list->tail-1)) :
        (q_list_entry_t *) 0;

    if(q_list->cnt)
    {
        if(q_list->tail == q_list->first_entry_addr)
        {
            q_list->tail = q_list->last_entry_addr;
        }
        else
        {
            q_list->tail--;
        }

        q_list->cnt--;
    }

    return q_entry;
}


__inline
q_list_entry_t
q_list_peek_head(
    q_list_t *q_list)
{
    q_list_entry_t q_entry;

    q_entry = q_list->cnt ? *q_list->head : (q_list_entry_t *) 0;

    return q_entry;
}


__inline
q_list_entry_t
q_list_peek_tail(
    q_list_t *q_list)
{
    q_list_entry_t q_entry;

    q_entry = q_list->cnt ?
        (q_list->tail == q_list->first_entry_addr ?
            *q_list->last_entry_addr : *(q_list->tail - 1)) :
        (q_list_entry_t *) 0;

    return q_entry;
}


__inline
unsigned long
q_list_entry_cnt(
    q_list_t *q_list)
{
    return q_list->cnt;
}


__inline
char
q_list_is_empty(
    q_list_t *q_list)
{
    return q_list->cnt == 0;
}


__inline
char
q_list_is_full(
    q_list_t *q_list)
{
    return q_list->cnt == q_list->max_cnt;
}


#else


#define q_list_init(_q_list, _q_list_arr, _max_cnt) \
    (_q_list)->max_cnt = (_max_cnt); \
    (_q_list)->first_entry_addr = (_q_list_arr); \
    (_q_list)->last_entry_addr = (_q_list_arr) + ((_max_cnt) - 1); \
    (_q_list)->head = (_q_list)->first_entry_addr; \
    (_q_list)->tail = (_q_list)->first_entry_addr; \
    (_q_list)->cnt = 0


#define q_list_clear(_q_list) \
    (_q_list)->head = (_q_list)->first_entry_addr; \
    (_q_list)->tail = (_q_list)->first_entry_addr; \
    (_q_list)->cnt = 0


#define q_list_push_head(_q_list, _q_entry) \
    if((_q_list)->cnt < (_q_list)->max_cnt) \
    { \
        if((_q_list)->head == (_q_list)->first_entry_addr) \
        { \
            (_q_list)->head = (_q_list)->last_entry_addr; \
        } \
        else \
        { \
            (_q_list)->head--; \
        } \
        *((_q_list)->head) = (_q_entry); \
        (_q_list)->cnt++; \
    }


#define q_list_pop_head(_q_list) \
    (_q_list)->cnt ? *(_q_list)->head : (q_list_entry_t *) 0; \
    if((_q_list)->cnt) \
    { \
        if((_q_list)->head == (_q_list)->last_entry_addr) \
        { \
            (_q_list)->head = (_q_list)->first_entry_addr; \
        } \
        else \
        { \
            (_q_list)->head++; \
        } \
        (_q_list)->cnt--; \
    }


#define q_list_push_tail(_q_list, _q_entry) \
    if((_q_list)->cnt < (_q_list)->max_cnt) \
    { \
        *(_q_list)->tail = (_q_entry); \
        if((_q_list)->tail == (_q_list)->last_entry_addr) \
        { \
            (_q_list)->tail = (_q_list)->first_entry_addr; \
        } \
        else \
        { \
            (_q_list)->tail++; \
        } \
        (_q_list)->cnt++; \
    }


#define q_list_pop_tail(_q_list) \
    (_q_list)->cnt ? ((_q_list)->tail == (_q_list)->first_entry_addr ? \
        *(_q_list)->last_entry_addr : *((_q_list)->tail-1)) : \
        (q_list_entry_t *) 0; \
    if((_q_list)->cnt) \
    { \
        if((_q_list)->tail == (_q_list)->first_entry_addr) \
        { \
            (_q_list)->tail = (_q_list)->last_entry_addr; \
        } \
        else \
        { \
            (_q_list)->tail--; \
        } \
        (_q_list)->cnt--; \
    } \


#define q_list_peek_head(_q_list) \
    ((_q_list)->cnt ? *(_q_list)->head : (q_list_entry_t *) 0)


#define q_list_peek_tail(_q_list) \
    ((_q_list)->cnt ? ((_q_list)->tail == (_q_list)->first_entry_addr ? \
        *(_q_list)->last_entry_addr : *((_q_list)->tail - 1)) : \
        (q_list_entry_t *) 0)


#define q_list_entry_cnt(_q_list)   ((_q_list)->cnt)


#define q_list_is_empty(_q_list)    ((_q_list)->cnt == 0)


#define q_list_is_full(_q_list)     ((_q_list)->cnt == (_q_list)->max_cnt)


#endif




#endif /* _listq_h_ */

