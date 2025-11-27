#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "atomic_util.h"
#include "ring_buffer.h"

// Mempool: a lock-free SPSC ring-buffer memory pool.
//
// Layout:
//   head  = alloc pointer (producer advances after allocation)
//   tail  = free pointer  (consumer advances after freeing)
//   limit = end-of-data boundary; normally equals capacity.
//
// The buffer is treated as a circular ring. Both head and tail are offsets
// in [0, capacity). We reserve 1 byte so that head == tail means empty.
//
// When a contiguous allocation doesn't fit at the end of the buffer, the
// producer sets limit = head (marking where valid data ends) and wraps
// head to 0 to allocate from the beginning. The consumer, upon reaching
// tail == limit, knows to skip the padding by resetting tail = 0 and
// limit = capacity.
//
// Concurrency note on `limit`:
//   Producer sets  limit = head   (when wrapping)
//   Consumer sets  limit = cap    (when passing the wrap point)
//   These two writes are naturally serialized by FIFO ordering — the
//   consumer can only reach `limit` after the producer has already moved
//   on, so there is no data race.
//
// Invariant: the region [tail, head) (mod capacity) is "in use".
//            head == tail means the pool is empty.

struct Mempool
{
    uint8_t *mem;
    size_t capacity;

    size_t head;  // alloc (producer write) offset
    size_t tail;  // free  (consumer write) offset
    size_t limit; // end-of-data boundary (producer & consumer write, never concurrent)
};

mempool_t *mempool_create(size_t capacity)
{
    mempool_t *mp = malloc(sizeof(mempool_t));
    if (!mp)
        return NULL;

    mp->mem = malloc(capacity);
    if (!mp->mem)
    {
        free(mp);
        return NULL;
    }

    mp->capacity = capacity;
    atomic_store_relaxed(&mp->head, 0);
    atomic_store_relaxed(&mp->tail, 0);
    atomic_store_relaxed(&mp->limit, capacity);
    return mp;
}

void mempool_destroy(mempool_t *mp)
{
    free(mp->mem);
    free(mp);
}

void *mempool_alloc(mempool_t *mp, size_t size)
{
    assert(size > 0);

    size_t head = atomic_load_relaxed(&mp->head); // only producer writes head
    size_t tail = atomic_load_acquire(&mp->tail); // consumer may update tail
    size_t cap = mp->capacity;

    if (head >= tail)
    {
        // Free space: [head, cap) and [0, tail).
        size_t remain = cap - head;
        if (remain >= size)
        {
            // Fits at current head position.
            void *ptr = mp->mem + head;
            size_t new_head = head + size;
            if (new_head == cap)
                new_head = 0;
            atomic_store_release(&mp->head, new_head);
            return ptr;
        }

        // Tail end too small. Try wrapping to beginning.
        // Need size < tail to keep the 1-byte empty gap.
        if (size >= tail)
            return NULL;

        // Mark the wrap point so the consumer knows where data ends.
        // Must store limit BEFORE advancing head, so the consumer
        // sees the limit by the time it observes the new head.
        atomic_store_release(&mp->limit, head);
        void *ptr = mp->mem;
        atomic_store_release(&mp->head, size);
        return ptr;
    }
    else
    {
        // head < tail: free space is [head, tail).
        if (tail - head - 1 < size)
            return NULL;

        void *ptr = mp->mem + head;
        atomic_store_release(&mp->head, head + size);
        return ptr;
    }
}

void mempool_free(mempool_t *mp, size_t size)
{
    assert(size > 0);

    size_t tail = atomic_load_relaxed(&mp->tail); // only consumer writes tail
    size_t limit = atomic_load_acquire(&mp->limit);
    size_t cap = mp->capacity;

    size_t new_tail = tail + size;

    if (limit != cap)
    {
        // Producer wrapped — there is padding in [limit, cap).
        // When we reach the wrap point, skip padding and continue from 0.
        if (new_tail >= limit)
        {
            assert(new_tail == limit);
            new_tail = 0;
            // Reset limit so the producer can wrap again in the future.
            atomic_store_release(&mp->limit, cap);
        }
    }
    else if (new_tail >= cap)
    {
        // Natural wrap at capacity boundary (no padding involved).
        assert(new_tail == cap);
        new_tail = 0;
    }

    atomic_store_release(&mp->tail, new_tail);
}

struct SpscRing
{
    ring_msg_t **buf;
    size_t size;
    size_t head; // push (producer write) offset
    size_t tail; // pop (consumer write) offset
};

spsc_ring_t *spsc_ring_create(size_t size)
{
    spsc_ring_t *r = malloc(sizeof(spsc_ring_t));
    if (!r)
        return NULL;

    r->size = size;
    r->buf = calloc(size, sizeof(ring_msg_t *));
    if (!r->buf)
    {
        free(r);
        return NULL;
    }
    atomic_store_relaxed(&r->head, 0);
    atomic_store_relaxed(&r->tail, 0);
    return r;
}

void spsc_ring_destroy(spsc_ring_t *r)
{
    free(r->buf);
    free(r);
}

size_t spsc_ring_size(spsc_ring_t *r) { return r->size; }

size_t spsc_ring_used(spsc_ring_t *r)
{
    size_t head = atomic_load_acquire(&r->head);
    size_t tail = atomic_load_acquire(&r->tail);
    if (tail <= head)
        return head - tail;
    else
        return r->size - tail + head;
}

bool spsc_ring_push(spsc_ring_t *r, ring_msg_t *msg)
{
    size_t head = atomic_load_acquire(&r->head);
    size_t tail = atomic_load_acquire(&r->tail);

    size_t next = (head + 1) % r->size;
    if (next == tail)
        return false; // full

    r->buf[head] = msg;
    atomic_store_release(&r->head, next);
    return true;
}

bool spsc_ring_pop(spsc_ring_t *r, ring_msg_t **out)
{
    size_t head = atomic_load_acquire(&r->head);
    size_t tail = atomic_load_acquire(&r->tail);

    if (tail == head)
        return false; // empty

    *out = r->buf[tail];
    atomic_store_release(&r->tail, (tail + 1) % r->size);
    return true;
}

struct SimpleAllocator
{
    size_t capacity;
    size_t used;
};

simple_allocator_t *simple_allocator_create(size_t capacity)
{
    simple_allocator_t *alloc = malloc(sizeof(simple_allocator_t));
    if (!alloc)
        return NULL;

    atomic_store_relaxed(&alloc->capacity, capacity);
    atomic_store_relaxed(&alloc->used, 0);
    return alloc;
}

void simple_allocator_destroy(simple_allocator_t *alloc) { free(alloc); }

ring_msg_t *simple_alloc_packet(simple_allocator_t *alloc, const struct pcap_pkthdr *header, const uint8_t *pkt_data)
{
    size_t total = sizeof(ring_msg_t) + header->caplen;
    size_t cap = atomic_load_relaxed(&alloc->capacity);
    size_t old = atomic_load_relaxed(&alloc->used);
    while (1)
    {
        if (old + total > cap)
            return NULL;

        // CAS (weak)
        if (atomic_compare_exchange_weak(&alloc->used, &old, old + total))
        {
            break;
        }
    }

    ring_msg_t *msg = malloc(total);
    if (!msg)
    {
        atomic_fetch_sub_relaxed(&alloc->used, total);
        return NULL;
    }

    msg->type = RING_MSG_PACKET;
    msg->user = NULL;
    msg->pkt.direction = 0;
    msg->pkt.hdr = *header;
    memcpy(msg->pkt.data, pkt_data, header->caplen);
    return msg;
}

ring_msg_t *simple_alloc_heartbeat(simple_allocator_t *alloc, time_t ts)
{
    size_t len = sizeof(ring_msg_t);
    size_t cap = atomic_load_relaxed(&alloc->capacity);
    size_t old_used = atomic_load_relaxed(&alloc->used);
    while (1)
    {
        if (old_used + len > cap)
            return NULL;

        // CAS (weak)
        if (atomic_compare_exchange_weak(&alloc->used, &old_used, old_used + len))
        {
            break;
        }
    }

    ring_msg_t *msg = malloc(len);
    if (!msg)
    {
        atomic_fetch_sub_relaxed(&alloc->used, len);
        return NULL;
    }

    msg->type = RING_MSG_HEARTBEAT;
    msg->user = NULL;
    msg->heartbeat.ts = ts;
    return msg;
}

void simple_msg_free(simple_allocator_t *alloc, ring_msg_t *msg)
{
    size_t len;

    switch (msg->type)
    {
    case RING_MSG_PACKET:
        len = sizeof(ring_msg_t) + msg->pkt.hdr.caplen;
        break;

    case RING_MSG_HEARTBEAT:
        len = sizeof(ring_msg_t);
        break;

    default:
        return;
    }

    size_t curr_used = atomic_load_relaxed(&alloc->used);
    if (curr_used < len)
        len = curr_used;
    atomic_fetch_sub_release(&alloc->used, len);
    free(msg);
}

size_t simple_allocator_capacity(simple_allocator_t *alloc) { return atomic_load_relaxed(&alloc->capacity); }

size_t simple_allocator_used(simple_allocator_t *alloc) { return atomic_load_relaxed(&alloc->used); }

void simple_allocator_resize(simple_allocator_t *alloc, size_t new_capacity)
{
    atomic_store_release(&alloc->capacity, new_capacity);
}