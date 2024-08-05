#ifndef LWIP_CLIENT_H
#define LWIP_CLIENT_H

#include "lwip/ip_addr.h"

/**
 * PING_USE_SOCKETS: Set to 1 to use sockets, otherwise the raw api is used
 */
#ifndef PING_USE_SOCKETS
#define PING_USE_SOCKETS    LWIP_SOCKET
#endif

void client_init(void);
void tcp_client_send(void);


#if !PING_USE_SOCKETS
#endif /* !PING_USE_SOCKETS */

#endif /* LWIP_PING_H */

