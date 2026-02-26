#pragma once 

#include <scx/common.bpf.h>
#include <sdt_task.h>


#ifndef WRITE_ONCE
#define WRITE_ONCE(x, val) ((*(volatile typeof(x) *) &(x)) = (val))
#endif

#ifndef NUMA_NO_NODE
#define	NUMA_NO_NODE	(-1)
#endif

#ifndef arena_container_of
#define arena_container_of(ptr, type, member)			\
	({							\
		void __arena *__mptr = (void __arena *)(ptr);	\
		((type *)(__mptr - offsetof(type, member)));	\
	})
#endif

#ifdef __BPF__ /* when compiled as bpf program */

#ifndef PAGE_SIZE
#define PAGE_SIZE __PAGE_SIZE
/*
 * for older kernels try sizeof(struct genradix_node)
 * or flexible:
 * static inline long __bpf_page_size(void) {
 *   return bpf_core_enum_value(enum page_size_enum___l, __PAGE_SIZE___l) ?: sizeof(struct genradix_node);
 * }
 * but generated code is not great.
 */
#endif

#if defined(__BPF_FEATURE_ADDR_SPACE_CAST) && !defined(BPF_ARENA_FORCE_ASM)
#define __arena __attribute__((address_space(1)))
#define __arena_global __attribute__((address_space(1)))
#define cast_kern(ptr) /* nop for bpf prog. emitted by LLVM */
#define cast_user(ptr) /* nop for bpf prog. emitted by LLVM */
#else
#define __arena
#define __arena_global SEC(".addr_space.1")
#define cast_kern(ptr) bpf_addr_space_cast(ptr, 0, 1)
#define cast_user(ptr) bpf_addr_space_cast(ptr, 1, 0)
#endif

void __arena* bpf_arena_alloc_pages(void *map, void __arena *addr, __u32 page_cnt,
				    int node_id, __u64 flags) __ksym __weak;
void bpf_arena_free_pages(void *map, void __arena *ptr, __u32 page_cnt) __ksym __weak;

#else /* when compiled as user space code */

#define __arena
#define __arg_arena
#define cast_kern(ptr) /* nop for user space */
#define cast_user(ptr) /* nop for user space */
extern char arena[1] __attribute__((weak));

#ifndef offsetof
#define offsetof(type, member)  ((unsigned long)&((type *)0)->member)
#endif

static inline void __arena* bpf_arena_alloc_pages(void *map, void *addr, __u32 page_cnt,
						  int node_id, __u64 flags)
{
	return NULL;
}
static inline void bpf_arena_free_pages(void *map, void __arena *ptr, __u32 page_cnt)
{
}
#endif

struct arena_list_node;

typedef struct arena_list_node __arena arena_list_node_t;

struct arena_list_node {
	arena_list_node_t *next;
	arena_list_node_t * __arena *pprev;
};

struct arena_list_head {
	struct arena_list_node __arena *first;
};
typedef struct arena_list_head __arena arena_list_head_t;

#define list_entry(ptr, type, member) arena_container_of(ptr, type, member)

#define list_entry_safe(ptr, type, member) \
	({ typeof(*ptr) * ___ptr = (ptr); \
	 ___ptr ? ({ cast_kern(___ptr); list_entry(___ptr, type, member); }) : NULL; \
	 })

#ifndef __BPF__
static inline void *bpf_iter_num_new(struct bpf_iter_num *it, int i, int j) { return NULL; }
static inline void bpf_iter_num_destroy(struct bpf_iter_num *it) {}
static inline bool bpf_iter_num_next(struct bpf_iter_num *it) { return true; }
#define cond_break ({})
#define can_loop true
#endif

/* Safely walk link list elements. Deletion of elements is allowed. */
#define list_for_each_entry(pos, head, member)					\
	for (void * ___tmp = (pos = list_entry_safe((head)->first,		\
						    typeof(*(pos)), member),	\
			      (void *)0);					\
	     pos && ({ ___tmp = (void *)pos->member.next; 1; }) && can_loop;    \
	     pos = list_entry_safe((void __arena *)___tmp, typeof(*(pos)), member))

static inline void list_add_head(arena_list_node_t *n, arena_list_head_t *h)
{
	arena_list_node_t *first = h->first, * __arena *tmp;

	cast_user(first);
	cast_kern(n);
	WRITE_ONCE(n->next, first);
	cast_kern(first);
	if (first) {
		tmp = &n->next;
		cast_user(tmp);
		WRITE_ONCE(first->pprev, tmp);
	}
	cast_user(n);
	WRITE_ONCE(h->first, n);

	tmp = &h->first;
	cast_user(tmp);
	cast_kern(n);
	WRITE_ONCE(n->pprev, tmp);
}

static inline void __list_del(arena_list_node_t *n)
{
	arena_list_node_t *next = n->next;
	arena_list_node_t * __arena *pprev = n->pprev;

	cast_user(next);
	cast_kern(pprev);
	WRITE_ONCE(*pprev, next);
	if (next) {
		cast_user(pprev);
		cast_kern(next);
		WRITE_ONCE(next->pprev, pprev);
	}
}

#define POISON_POINTER_DELTA 0

#define LIST_POISON1  ((void __arena *) 0x100 + POISON_POINTER_DELTA)
#define LIST_POISON2  ((void __arena *) 0x122 + POISON_POINTER_DELTA)

static inline void list_del(arena_list_node_t *n)
{
	__list_del(n);
	n->next = LIST_POISON1;
	n->pprev = LIST_POISON2;
}

// Map from bucket index to list head ptr
struct scx_list_map_val {
    struct bpf_spin_lock lock;
	union sdt_id		tid;
	__u64			tptr;
	struct sdt_data __arena	*data;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, u64);
	__type(value, struct scx_list_map_val);
    __uint(max_entries, 2048);
} scx_list_map SEC(".maps");

struct scx_allocator scx_list_allocator;

__hidden
int scx_list_init(__u64 data_size)
{
	return scx_alloc_init(&scx_list_allocator, data_size);
}

__hidden
void __arena *scx_list_alloc(const u64 list_idx)
{
	struct sdt_data __arena *data = NULL;
	data = scx_alloc(&scx_list_allocator);
	if (unlikely(!data)) {
		bpf_printk("%s:%d scx_alloc failed", __func__, __LINE__);
		return NULL;
	}

    // Book keeping for the pointer
    struct scx_list_map_val mval;
    mval.tid = data->tid;
	mval.data = data;
    long res = bpf_map_update_elem(&scx_list_map, &list_idx, &mval, BPF_ANY);
	if (res)
	{
		scx_bpf_error("Failed to create map entry for linked list arena pointer (linked list index %llu)", list_idx);
		return NULL;
	}

	return (void __arena *)data->payload;
}

__hidden
void __arena *scx_list_data(const u64 list_idx)
{
	struct sdt_data __arena *data = NULL;
	struct scx_list_map_val *mval = NULL;

	scx_arena_subprog_init();

    mval = bpf_map_lookup_elem(&scx_list_map, &list_idx);
	if (!mval)
		return NULL;

	data = mval->data;

	return (void __arena *)data->payload;
}

__hidden
void scx_list_free(const u64 list_idx)
{
	struct scx_list_map_val *mval = NULL;

	scx_arena_subprog_init();

	mval = bpf_map_lookup_elem(&scx_list_map, &list_idx);
	if (!mval)
		return;

	scx_alloc_free_idx(&scx_list_allocator, mval->tid.idx);
    bpf_map_delete_elem(&scx_list_map, &list_idx);
}
