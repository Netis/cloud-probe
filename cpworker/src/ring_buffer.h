#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <time.h>

#include <pcap/pcap.h>

typedef enum
{
    RING_MSG_PACKET = 0,
    RING_MSG_HEARTBEAT = 1,
} ring_msg_type_t;

typedef struct
{
    ring_msg_type_t type;
    void *user;
    union
    {
        struct
        {
            int direction;
            struct pcap_pkthdr hdr;
            uint8_t data[];
        } pkt;

        struct
        {
            time_t ts;
        } heartbeat;
    };
} ring_msg_t;

typedef struct Mempool mempool_t;

typedef struct SpscRing spsc_ring_t;

typedef struct SimpleAllocator simple_allocator_t;

mempool_t *mempool_create(size_t capacity);
void mempool_destroy(mempool_t *mp);
void *mempool_alloc(mempool_t *mp, size_t size);
void mempool_free(mempool_t *mp, size_t size);

spsc_ring_t *spsc_ring_create(size_t size);
void spsc_ring_destroy(spsc_ring_t *r);
size_t spsc_ring_size(spsc_ring_t *r);
size_t spsc_ring_used(spsc_ring_t *r);
bool spsc_ring_push(spsc_ring_t *r, ring_msg_t *msg);
bool spsc_ring_pop(spsc_ring_t *r, ring_msg_t **out);

simple_allocator_t *simple_allocator_create(size_t capacity);
void simple_allocator_destroy(simple_allocator_t *alloc);
void simple_allocator_resize(simple_allocator_t *alloc, size_t new_capacity);
size_t simple_allocator_capacity(simple_allocator_t *alloc);
size_t simple_allocator_used(simple_allocator_t *alloc);
size_t simple_allocator_free_size(simple_allocator_t *alloc);
ring_msg_t *simple_alloc_packet(simple_allocator_t *alloc, const struct pcap_pkthdr *header, const uint8_t *pkt_data);
ring_msg_t *simple_alloc_heartbeat(simple_allocator_t *alloc, time_t ts);
void simple_msg_free(simple_allocator_t *alloc, ring_msg_t *msg);
