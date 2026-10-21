#include "stats.h"
#include "security.h"
#include "api.h"
#include "logger.h"
#include "sniffer.h"
#include <stdio.h>
#ifdef _WIN32
#include <windows.h>
#else
#include <unistd.h>
#endif
int main(void) {
    log_init();
    if (sniffer_init() || stats_init(NULL))
        return 1;
    security_init();
    if (api_start() != 0) {
        printf("API_START_FAIL\n");
        return 1;
    }
    printf("API_UP\n");
    fflush(stdout);
#ifdef _WIN32
    Sleep(8000);
#else
    sleep(8);
#endif
    api_stop();
    stats_cleanup();
    security_cleanup();
    log_cleanup();
    sniffer_cleanup();
    printf("API_DOWN\n");
    return 0;
}
