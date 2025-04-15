#include "magic_buddy.h"
#include <assert.h>
#include <math.h>
#include <stdio.h>
#include <string.h>

struct free_block {
    struct free_block *next;
    struct free_block **pprev;
    uint8_t magic[MAGIC_COOKIE_BYTES];
    uint8_t logsize;
};

// log2 of size rounded up (ceil) or down (!ceil) to the nearest power of 2
// https://stackoverflow.com/questions/11376288/fast-computing-of-log2-for-64-bit-integers
static size_t size2log(size_t size, int ceil) {
#if 1
    if (!size)
        return 0;
    size_t floor_log = (8 * sizeof(unsigned long long)) -
                       __builtin_clzll((unsigned long long)size) - 1;
    return (ceil && (size > (1 << floor_log))) ? (floor_log + 1) : floor_log;
#else
    size_t floor_log = 0;
    for (size_t i = 0; i < (8 * sizeof(size)); i++)
        if (size & (1ul << i))
            floor_log = i;

    return (ceil && (size > (1 << floor_log))) ? (floor_log + 1) : floor_log;
#endif
}

static struct free_block *buddy_of(struct free_block *block, size_t logsize,
                                   struct buddy *state) {
    size_t virt_block = (size_t)block - (size_t)state->base;
    size_t virt_buddy = virt_block ^ (1 << logsize);
    return (void *)((uint8_t *)state->base + virt_buddy);
}

// interpret @block as a block at depth @logsize. is it free?
static int isfree(struct free_block *block, size_t logsize,
                  struct buddy *state) {
    return !memcmp(block->magic, state->magic, sizeof(state->magic)) &&
           block->logsize == logsize;
}

static void makefree(struct free_block *block, struct buddy *state) {
    memcpy(block->magic, state->magic, sizeof(state->magic));
}

static struct free_block *pop(struct free_block *block) {
    *(block->pprev) = block->next;
    if (block->next)
        block->next->pprev = block->pprev;
    return block;
}

static void push(struct free_block *block, size_t logsize,
                 struct buddy *state) {
    block->next = state->avail[logsize];
    if (block->next)
        block->next->pprev = &(block->next);
    state->avail[logsize] = block;
    block->pprev = &(state->avail[logsize]);
    block->logsize = logsize;
}

void init_buddy(uint8_t *base, size_t size, uint8_t magic[MAGIC_COOKIE_BYTES],
                struct buddy *state) {
    memset(state, 0, sizeof(*state));
    state->base = base;

    size_t logsize = size2log(size, 0);
    state->root_logsize = logsize;

    memcpy(state->magic, magic, sizeof(state->magic));

    memset(base, 0, sizeof(struct free_block));
    makefree((void *)base, state);
    push((void *)base, logsize, state);
}

static void *_allocate(size_t logsize, struct buddy *state) {
    if (logsize > state->root_logsize)
        return 0;
    if (state->avail[logsize]) {
        struct free_block *block = pop(state->avail[logsize]);
        memset(block, 0, sizeof(struct free_block));
        return block;
    }
    if (logsize == state->root_logsize)
        return 0;

    struct free_block *parent = _allocate(logsize + 1, state);
    if (!parent)
        return 0;
    struct free_block *buddy = buddy_of(parent, logsize, state);
    // split @parent in half and place the buddy on the avail list.
    memcpy(buddy->magic, state->magic, sizeof(state->magic));
    push(buddy, logsize, state);
    return parent;
}

void *allocate(size_t size, struct buddy *state) {
    if (size < sizeof(struct free_block))
        size = sizeof(struct free_block);
    return _allocate(size2log(size, 1), state);
}

static void _liberate(struct free_block *block, size_t logsize,
                      struct buddy *state) {
    push(block, logsize, state);
    if (logsize == state->root_logsize)
        return;

    struct free_block *buddy = buddy_of(block, logsize, state);
    if (!isfree(buddy, logsize, state))
        return;

    // coalesce up!
    struct free_block *lhs = (buddy < block) ? buddy : block;
    struct free_block *rhs = (buddy < block) ? block : buddy;
    pop(rhs);
    memset(rhs, 0, sizeof(*rhs));

    pop(lhs);

    _liberate(lhs, logsize + 1, state);
}

void liberate(void *base, size_t size, struct buddy *state) {
    struct free_block *block = base;
    memset(block, 0, sizeof(*block));
    makefree(block, state);

    _liberate(block, size2log(size, 1), state);
}

void debug_buddy(struct buddy *state) {
    for (size_t i = 0; i <= state->root_logsize; i++) {
        printf("Free blocks at size 2^%lu = %lu:\n", i, 1ul << i);
        for (struct free_block *block = state->avail[i]; block;
             block = block->next) {
            assert(isfree(block, block->logsize, state));
            printf("\t%p\n", block);
        }
    }
}

///////// "advanced features"
static struct free_block *rhs_child_of(struct free_block *block, size_t logsize,
                                       struct buddy *state) {
    size_t virt_block = (size_t)block - (size_t)state->base;
    size_t virt_child = virt_block | (1 << (logsize - 1));
    return (void *)((uint8_t *)state->base + virt_child);
}

// NOTE: this method is perhaps more complicated than it needs to be because we
// take great pains to avoid writing to the region that is being reserved
// (e.g., in case it is device MMIO).
int reserve(void *start, size_t size, void **out_start, size_t *out_size,
            struct buddy *state) {
    // (1) find the first free block to the left of start
    uint8_t *base = state->base;
    size_t virtual_start = (uint8_t *)start - base;
    struct free_block *block = (void *)(base + virtual_start);
    // repeatedly zero out least significant bits until we find a free block
    while (memcmp(block->magic, state->magic, sizeof(state->magic))) {
        if (!virtual_start)
            return 0;
        virtual_start = virtual_start & (virtual_start - 1);
        block = (void *)(base + virtual_start);
    }

    // (2) check whether the block fits it
    void *end = (void *)((uint8_t *)start + size);
    void *block_end = ((uint8_t *)block + (1 << block->logsize));
    if (block_end < end)
        return 0;

    // (3) split the block until we get a tight fit
    int needs_zero = 1;
    size_t min_logsize = size2log(sizeof(struct free_block), 1);
    pop(block);
    size_t logsize = block->logsize;
    while (logsize > min_logsize) {
        struct free_block *rhs_child = rhs_child_of(block, logsize, state);
        if ((void *)rhs_child <= start) { // move right
            block = rhs_child;
            makefree(block, state);
            push(block, --logsize, state);
            needs_zero = 0;
        } else { // move left
            if (end > (void *)rhs_child)
                break;
            makefree(rhs_child, state);
            push(rhs_child, --logsize, state);
        }
    }
    if (needs_zero)
        memset(block, 0, sizeof(struct free_block));
    if (out_start)
        *out_start = block;
    if (out_size)
        *out_size = logsize;
    return 1;
}

static void *_naive_reallocate(void *old, size_t old_size, size_t new_size,
                               struct buddy *state) {
    assert(old_size < new_size);
    void *new = allocate(new_size, state);
    if (!new)
        return 0;
    memcpy(new, old, old_size);
    liberate(old, old_size, state);
    return new;
}

void *reallocate(void *old, size_t new_size, size_t old_size,
                 struct buddy *state) {
    if (new_size == 0)
        return liberate(old, old_size, state), (void *)0;

    if (new_size < sizeof(struct free_block))
        new_size = sizeof(struct free_block);

    size_t old_logsize = size2log(old_size, 1);
    size_t new_logsize = size2log(new_size, 1);

    if (new_logsize == old_logsize)
        return old;

    if (new_logsize < old_logsize) {
        // repeatedly split, keeping lhs.
        struct free_block *block = old;
        while (new_logsize < old_logsize) {
            old_logsize--;
            struct free_block *right_half = buddy_of(block, old_logsize, state);
            makefree(right_half, state);
            push(right_half, old_logsize, state);
        }
        return old;
    }

    // otherwise, we must iterate up the tree and ensure that at each level:
    // (1) we are the left-buddy, and
    // (2) our buddy is free.
    // up until we reach an ancestor of the proper size.

    // First, just verify this claim.
    size_t pos_logsize = old_logsize;
    if (new_logsize > state->root_logsize)
        return 0;
    struct free_block *pos = old;
    while (pos_logsize != new_logsize) {
        struct free_block *buddy = buddy_of(pos, pos_logsize, state);
        if (pos > buddy) {
            // oh no, we're the right buddy!
            return _naive_reallocate(old, old_size, new_size, state);
        } else if (!isfree(buddy, pos_logsize, state)) {
            // oh no, our buddy at this level isn't free!
            return _naive_reallocate(old, old_size, new_size, state);
        }
        pos_logsize++;
    }

    // Then, revisit the path and coalesce on the way up.
    pos_logsize = old_logsize;
    pos = old;
    while (pos_logsize != new_logsize) {
        struct free_block *buddy = buddy_of(pos, pos_logsize, state);
        pop(buddy);
        memset(buddy, 0, sizeof(struct free_block));
        pos_logsize++;
    }
    return old;
}

// grow can also be used to move the buddy's data. grow can never fail.
void grow_buddy(uint8_t *new_base, size_t new_size, struct buddy *state) {
    // first: make sure all pointers in @state are pointing into @new_base.
    for (size_t i = 0; i < ADDRESS_BITS; i++) {
        if (!state->avail[i])
            continue;
        state->avail[i] = (void *)(new_base + ((uint8_t *)state->avail[i] -
                                               (uint8_t *)state->base));
    }
    state->base = new_base;

    // then, increase the size by 1 repeatedly
    size_t logsize = size2log(new_size, 0);
    assert(logsize >= state->root_logsize);
    if (logsize == state->root_logsize)
        return;
    if (isfree((void *)new_base, state->root_logsize, state)) {
        pop((void *)new_base);
        push((void *)new_base, state->root_logsize++, state);
    } else {
        struct free_block *buddy =
            buddy_of((void *)new_base, state->root_logsize, state);
        makefree(buddy, state);
        push(buddy, state->root_logsize++, state);
    }
    return grow_buddy(new_base, new_size, state);
}

// 0 -> failure
int shrink_buddy(size_t new_size, struct buddy *state) {
    // To divide the space in half, we need either:
    // (1) the root is available, or
    // (2) the root is split, with the right child being free.
    // to divide the space by 2^k, we need that property to be true recursively
    // along the lhs path, until the root itself is free.

    size_t logsize = size2log(new_size, 0);
    if ((1 << logsize) <= sizeof(struct free_block))
        return 0;

    // First, just check whether we'll be able to do it:
    size_t virtual_root_logsize = state->root_logsize;
    while (virtual_root_logsize > logsize) {
        if (!isfree(state->base, virtual_root_logsize, state)) {
            struct free_block *rhs_child =
                rhs_child_of(state->base, virtual_root_logsize, state);
            if (!isfree(rhs_child, virtual_root_logsize - 1, state))
                return 0;
        }
        virtual_root_logsize--;
    }

    // It's possible! So go through and actually free the rhs children.
    while (state->root_logsize > logsize) {
        if (isfree(state->base, state->root_logsize, state)) {
            pop(state->base);
            push(state->base, state->root_logsize - 1, state);
        } else {
            struct free_block *rhs_child =
                rhs_child_of(state->base, state->root_logsize, state);
            memset(rhs_child, 0, sizeof(struct free_block));
        }
        state->root_logsize--;
    }
    state->root_logsize = logsize;
    return 1;
}

void move_buddy(struct buddy *new_state, struct buddy *old_state) {
    if (new_state == old_state)
        return;
    memmove(new_state, old_state, sizeof(struct buddy));
    for (size_t i = 0; i < ADDRESS_BITS; i++) {
        if (!new_state->avail[i])
            continue;
        new_state->avail[i]->pprev = &(new_state->avail[i]);
    }
}
