#include "https.h"
#include "dns.h"
#include "ethernet.h"
#include "stats.h"
#include "security.h"
#include "logger.h"
#include "util.h"
#include <stddef.h>
#include <stdint.h>
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    static int initialized;
    if (!initialized) {
        log_init();
        current_log_level_int = LOG_ERROR;
        if (stats_init(NULL))
            return 0;
        security_init();
        initialized = 1;
    }
    if (size > 65536)
        return 0;
    parse_https(data, (int)size, "1", "2", 1, 443);
    parse_dns(data, (int)size);
    parse_ethernet(data, (int)size);
    return 0;
}
