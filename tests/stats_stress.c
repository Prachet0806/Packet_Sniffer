#include "stats.h"
#include "security.h"
#include "logger.h"
#include "util.h"
#include <stdlib.h>
int main(void) {
    log_init();
    const char *info = getenv("PACKET_TEST_CONNINFO");
    if (!info || stats_init(info))
        return 1;
    security_init();
    for (int i = 0; i < 250; i++) {
        for (int j = 0; j < 1000; j++)
            stats_capture(1, 1);
        sleep_ms(5);
    }
    security_set_context(1700000000000000LL, 0);
    security_alert("integration", "src", "dst", "durable alert");
    int rc = stats_cleanup();
    security_cleanup();
    log_cleanup();
    return rc ? 1 : 0;
}
