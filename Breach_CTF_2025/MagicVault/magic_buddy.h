#pragma once

#include <stddef.h>
#include <stdint.h>

#define MAGIC_COOKIE_BYTES 32
#define ADDRESS_BITS (8 * sizeof(void *))

struct buddy {
    uint8_t magic[MAGIC_COOKIE_BYTES];
    struct free_block *(avail[ADDRESS_BITS]);
    size_t root_logsize;
    void *base;
};

// Note: O(1) below means linear in the number of address bits.

// Initialize a buddy with (constant) global state stored in @state.
// NOTE: after initializing the buddy, you should always pass the exact same
// pointer in for @state in future calls. If you need to move @state, use
// move_buddy(...).
// O(1)
void init_buddy(uint8_t *base, size_t size, uint8_t magic[MAGIC_COOKIE_BYTES],
                struct buddy *state);

// Allocate a block of size >= @size
// O(1)
void *allocate(size_t size, struct buddy *state);

// Liberate a block of size @size starting at @base.
// iyO(1)
void liberate(void *base, size_t size, struct buddy *state);

// Print debug information for the allocator.
// O(N) where N is number of liberated items
void debug_buddy(struct buddy *state);

// Simulates @new = allocate, memcpy(@new, @old), free(@old), with some
// optimizations for cases where the reallocation can be done in place.
// O(1)
void *reallocate(void *old, size_t new_size, size_t old_size,
                 struct buddy *state);

// Attempts to reserve a range [@start,@start+@size).
//
// Returns 1 if success, 0 otherwise.
//
// Whenever possible, we avoid writing anything into the reserved region.
//
// If the reservation succeeds, and @out_start (@out_size) is negative, it puts
// the start (size) of the actually reserved region into *@out_start
// (*@out_size). These can be passed into liberate(...) later to unreserve.
//
// O(1)
int reserve(void *start, size_t size, void **out_start, size_t *out_size,
            struct buddy *state);

// Update @state to assume the memory pool has been copied to
// [@new_base,@new_base+@new_size)
// Can *ONLY* be used when @new_size >= the existing size.
// O(1)
void grow_buddy(uint8_t *new_base, size_t new_size, struct buddy *state);

// Update @state to only use the subset of the pool in range
// [@state->base,@state->base+new_size)
// Can *ONLY* be used when @new_size <= the existing size.
// This *CAN* write to anything in the old pool.
// This *CAN* fail, in which case everything is unmodified and 0 is returned.
// Upon success, 1 is returned.
// O(1)
int shrink_buddy(size_t new_size, struct buddy *state);

// Used to move the global state of the buddy.
// O(1)
void move_buddy(struct buddy *new_state, struct buddy *old_state);
