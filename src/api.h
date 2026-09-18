#ifndef API_H
#define API_H

// Minimal read-only HTTP API (raw sockets, no external deps).
// Thread model: api_start() spawns a thread serving GET /health /stats /alerts
// and POST /filter (live only). Handlers snapshot stats under lock only.
int api_start(void);
void api_stop(void);
int api_is_running(void);

#endif
