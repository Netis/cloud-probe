#ifndef PKTMINERG_GREDEF_H
#define PKTMINERG_GREDEF_H

typedef struct grehdr {
    uint16_t flags;
    uint16_t protocol;
    uint32_t keybit;
} grehdr_t;

#endif //PKTMINERG_GREDEF_H
