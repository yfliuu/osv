#ifndef GNTTAB_COMMON
#define GNTTAB_COMMON

#include <sys/types.h>
#include <bsd/sys/sys/ioccom.h>
#include <bsd/porting/sync_stub.h>

// TEMPORARY
typedef uint32_t evtchn_port_t;

#define __GFP_ZERO 0x100u

#define pr_debug(_f,_a...)	debugf(_f,_a)
#define pr_err(_f,_a...)	debugf(_f,_a)
#define BUG_ON(_a)			assert(_a)
#define GFP_KERNEL	0

#define WRITE_ONCE(var, val) \
	(*((volatile typeof(val) *)(&(var))) = (val))

#define READ_ONCE(var) (*((volatile typeof(var) *)(&(var))))

struct list_head {
	struct list_head *next, *prev;
};

#define LIST_HEAD_INIT(name) { &(name), &(name) }

#define LIST_HEAD_LINUX(name) \
	struct list_head name = LIST_HEAD_INIT(name)

#define container_of(ptr, type, member) ({				\
	void *__mptr = (void *)(ptr);					\
	((type *)(__mptr - offsetof(type, member))); })

#define list_entry(ptr, type, member) \
	container_of(ptr, type, member)

#define list_first_entry(ptr, type, member) \
	list_entry((ptr)->next, type, member)

#define list_next_entry(pos, member) \
	list_entry((pos)->member.next, typeof(*(pos)), member)

static inline void INIT_LIST_HEAD(struct list_head *list)
{
	WRITE_ONCE(list->next, list);
	list->prev = list;
}

static inline int list_empty(const struct list_head *head)
{
	return READ_ONCE(head->next) == head;
}

static inline bool __list_add_valid(struct list_head *_new,
				struct list_head *prev,
				struct list_head *next)
{
	return true;
}

static inline void __list_del(struct list_head * prev, struct list_head * next)
{
	next->prev = prev;
	WRITE_ONCE(prev->next, next);
}

static inline void __list_del_entry(struct list_head *entry)
{
	__list_del(entry->prev, entry->next);
}

static inline void list_del(struct list_head *entry)
{
	__list_del_entry(entry);
	entry->next = NULL;
	entry->prev = NULL;
}

#define list_for_each_entry(pos, head, member)				\
	for (pos = list_first_entry(head, typeof(*pos), member);	\
	     &pos->member != (head);					\
	     pos = list_next_entry(pos, member))

#define list_for_each_entry_safe(pos, n, head, member)			\
	for (pos = list_first_entry(head, typeof(*pos), member),	\
		n = list_next_entry(pos, member);			\
	     &pos->member != (head); 					\
	     pos = n, n = list_next_entry(n, member))

static inline void __list_add(struct list_head *_new,
			      struct list_head *prev,
			      struct list_head *next)
{
	if (!__list_add_valid(_new, prev, next))
		return;

	next->prev = _new;
	_new->next = next;
	_new->prev = prev;
	WRITE_ONCE(prev->next, _new);
}

static inline void list_add(struct list_head *_new, struct list_head *head)
{
	__list_add(_new, head, head->next);
}

static inline void list_add_tail(struct list_head *_new, struct list_head *head)
{
	__list_add(_new, head->prev, head);
}

static inline void __list_splice(const struct list_head *list,
				 struct list_head *prev,
				 struct list_head *next)
{
	struct list_head *first = list->next;
	struct list_head *last = list->prev;

	first->prev = prev;
	prev->next = first;

	last->next = next;
	next->prev = last;
}

static inline void list_splice(const struct list_head *list,
				struct list_head *head)
{
	if (!list_empty(list))
		__list_splice(list, head, head->next);
}

static inline void list_splice_tail(struct list_head *list,
				struct list_head *head)
{
	if (!list_empty(list))
		__list_splice(list, head->prev, head);
}


struct page {
	char _pad[0x1000];
} __attribute__ ((aligned (0x1000)));

typedef struct refcount_struct {
	atomic_t refs;
} refcount_t;

struct mmu_interval_notifier {
    int _pad;
};

static inline void *kvcalloc(size_t count, size_t size, size_t type)
{
	return calloc(count, size);
}

static inline void kvfree(void *ptr)
{
	free(ptr);
}

static inline void *kzalloc(size_t size, size_t type)
{
	void *p = malloc(size);
	memset(p, 0, size);
	return p;
}

static inline void *kcalloc(size_t count, size_t size, size_t type)
{
    return calloc(count, size);
}

static inline void *kmalloc(size_t size, size_t type)
{
    return malloc(size);
}

static inline void kfree(void *p)
{
	free(p);
}

static inline int copy_from_user(void *to, const void *from, unsigned long n)
{
	memcpy(to, from, n);
	return 0;
}

static inline int copy_to_user(void *to, const void *from, unsigned long n)
{
	memcpy(to, from, n);
	return 0;
}

struct mmap_temp_store {
	uintptr_t start;
	uintptr_t end;
	int count;
	struct page **pages;
	struct mmap_temp_store *next;
};

static inline struct mmap_temp_store *mmap_temp_store_search(struct mmap_temp_store *head, uintptr_t start, uintptr_t end) {
	struct mmap_temp_store *t;
	for (t = head; t; t = t->next) { if (t->start == start && t->end == end) return t; }
	return NULL;
}

static inline void mmap_temp_store_add(struct mmap_temp_store *head, uintptr_t start, uintptr_t end, struct page *page) {
	struct mmap_temp_store *t;
	int count = (end - start) >> PAGE_SHIFT;

	if ((t = mmap_temp_store_search(head, start, end)) == NULL) {
		t = (struct mmap_temp_store *)malloc(sizeof(struct mmap_temp_store));
		t->start = start;
		t->end = end;
		t->count = 0;
		t->pages = (struct page **)malloc(sizeof(struct page *) * count);
		t->next = head;
		head = t;
	}

	t->pages[t->count++] = page;
	assert(t->count <= count);
}

#endif
