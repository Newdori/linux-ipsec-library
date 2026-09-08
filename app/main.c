#include "app_internal.h"

#include <signal.h>

static void HandleNativeAppSignal(int iSignal)
{
    if (SIGTERM == iSignal) {
        RequestNativeAppExit();
    }
    else {
        RequestNativeAppStop();
    }
}

int main(int iArgumentCount, char **ppcArguments)
{
    struct sigaction Action = {0};
    Action.sa_handler = HandleNativeAppSignal;
    (void)sigemptyset(&Action.sa_mask);
    /* Interrupt input/waits so SIGTERM reaches the normal cleanup path. */
    if ((0 != sigaction(SIGINT, &Action, NULL)) ||
        (0 != sigaction(SIGTERM, &Action, NULL))) {
        return 1;
    }
    return RunNativeAppCli((int32_t)iArgumentCount, ppcArguments);
}
