#include "router_hal.h"

// configure this to match the output of `ip a`
const char *interfaces[N_IFACE_ON_BOARD] = {
    "veth-net0",
    "veth-net1",
    "eth3",
    "eth4",
};

/**
 * "eth0",
 * "eth2",
 * "eth3",
 * "eth4",
 */ 
