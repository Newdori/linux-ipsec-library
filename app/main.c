#include "app_internal.h"

#include <signal.h>

static void HandleNativeAppSignal(int iSignal)
{
    (void)iSignal;
    RequestNativeAppStop();
}

int main(int iArgumentCount, char **ppcArguments)
{
    (void)signal(SIGINT, HandleNativeAppSignal);
    (void)signal(SIGTERM, HandleNativeAppSignal);
    return RunNativeAppCli((int32_t)iArgumentCount, ppcArguments);
}
