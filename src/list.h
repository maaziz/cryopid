#ifndef _LIST_H_
#define _LIST_H_

struct item {
	void *p;
	struct item *next;
};

struct list {
	struct item *head, *tail; 
};

#define list_init(list)		{ list.head = list.tail = NULL; }
void list_append(struct list *l, void *p);
void list_insert(struct list *l, void *p);

#endif /* _LIST_H_ */

/* vim:set ts=8 sw=4 noet: */
