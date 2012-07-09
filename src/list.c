#include "cryopid.h"
#include "list.h"

void list_append(struct list *l, void *p)
{
	if (l->tail == NULL) {
		l->head = l->tail = xmalloc(sizeof(struct item));
		l->tail->next = NULL;
		l->tail->p = p;
	} else {
		l->tail->next = xmalloc(sizeof(struct item));
		l->tail->next->p = p;
		l->tail->next->next = NULL;
		l->tail = l->tail->next;
	}
}

void list_insert(struct list *l, void *p)
{
    /* Inserts at the start of the list */
    struct item *item = xmalloc(sizeof(struct item));
    item->p = p;
    item->next = l->head;
    l->head = item;
}

/* vim:set ts=8 sw=4 noet: */
