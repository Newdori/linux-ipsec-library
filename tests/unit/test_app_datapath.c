#include "app_internal.h"

#include <stdio.h>

#define CHECK(Condition) do { if (!(Condition)) { \
    (void)fprintf(stderr, "datapath check failed at line %d\n", __LINE__); \
    return false; } } while (0)

static bool VerifyDatapathSettings(void)
{
    NativeAppConfig_t Config;
    NativeAppConfig_t Copy;
    InitializeNativeAppConfig(&Config);
    CHECK(IPSEC_OK == ValidateNativeAppDatapathConfig(&Config));
    CHECK(IPSEC_PACKET_PATH_SYSTEM == Config.Datapath.eProtectedPacketPath);
    CHECK(IPSEC_PACKET_PATH_SYSTEM == Config.Datapath.ePlainPacketPath);
    CHECK(IPSEC_DATAPATH_PREFER_AUTO == Config.Datapath.ePreference);
    CHECK(IPSEC_ERR_INVALID_ARGUMENT == SetNativeAppConfigSetting(
        NULL, "protected_packet_path", "application"));
    CHECK(IPSEC_ERR_INVALID_ARGUMENT == SetNativeAppConfigSetting(
        &Config, "protected_packet_path", "bogus"));
    CHECK(IPSEC_ERR_INVALID_ARGUMENT == SetNativeAppConfigSetting(
        &Config, "protected_unknown", "x"));
    CHECK(IPSEC_OK == SetNativeAppConfigSetting(
        &Config, "protected_packet_path", "application"));
    CHECK(IPSEC_OK != ValidateNativeAppDatapathConfig(&Config));
    CHECK(IPSEC_OK == SetNativeAppConfigSetting(&Config, "local_ip", "192.0.2.1"));
    CHECK(IPSEC_OK == SetNativeAppConfigSetting(
        &Config, "protected_local_ip", "192.0.2.1"));
    CHECK(IPSEC_OK == SetNativeAppConfigSetting(
        &Config, "protected_remote_ip", "192.0.2.2"));
    CHECK(IPSEC_OK == SetNativeAppConfigSetting(
        &Config, "protected_egress_interface", "eth-test.1"));
    CHECK(IPSEC_OK == SetNativeAppConfigSetting(
        &Config, "protected_interface", "ipsec-path"));
    CHECK(IPSEC_OK == ValidateNativeAppDatapathConfig(&Config));
    CHECK(IPSEC_OK == SetNativeAppConfigSetting(
        &Config, "plain_packet_path", "application"));
    CHECK(IPSEC_OK != ValidateNativeAppDatapathConfig(&Config));
    CHECK(IPSEC_OK == SetNativeAppConfigSetting(
        &Config, "plain_queue_number", "32002"));
    CHECK(IPSEC_OK == ValidateNativeAppDatapathConfig(&Config));
    Copy = Config;
    CHECK(AreNativeAppContextSettingsEqual(&Copy, &Config));
    Copy.acRemoteId[0] = 'X';
    CHECK(AreNativeAppContextSettingsEqual(&Copy, &Config));
    Copy.Datapath.usPlainQueueNumber++;
    CHECK(!AreNativeAppContextSettingsEqual(&Copy, &Config));
    Copy = Config;
    Copy.Datapath.ePlainPacketPath = IPSEC_PACKET_PATH_SYSTEM;
    CHECK(!AreNativeAppContextSettingsEqual(&Copy, &Config));
    CHECK(IPSEC_OK == SetNativeAppConfigSetting(
        &Config, "protected_filter_priority", "65534"));
    CHECK(65534U == Config.Datapath.usProtectedFilterPriority);
    CHECK(IPSEC_ERR_INVALID_ARGUMENT == SetNativeAppConfigSetting(
        &Config, "protected_filter_priority", "65535"));
    CHECK(IPSEC_ERR_INVALID_ARGUMENT == SetNativeAppConfigSetting(
        &Config, "plain_queue_number", "0"));
    CHECK(IPSEC_ERR_INVALID_ARGUMENT == SetNativeAppConfigSetting(
        &Config, "plain_queue_number", "65536"));
    return true;
}

static bool VerifyPacketArguments(void)
{
    NativeAppPacketOptions_t Options;
    NativeAppShowOptions_t Show;
    char *pacProtectedReceive[] = {
        "packet", "protected-receive", "packet.bin", "--timeout-ms", "0"
    };
    char *pacProtectedSubmit[] = {
        "packet", "protected-submit", "packet.bin", "--timeout-ms", "10"
    };
    char *pacPlainReceive[] = {
        "packet", "plain-receive", "plain.bin", "--timeout-ms", "10"
    };
    char *pacShow[] = {"show", "packet-path", "detail"};
    CHECK(ParseNativeAppPacketOptions(3U, pacProtectedReceive, &Options));
    CHECK((NATIVE_APP_PACKET_PROTECTED_RECEIVE == Options.eAction) &&
          (10000U == Options.uiTimeoutMs));
    CHECK(ParseNativeAppPacketOptions(5U, pacProtectedReceive, &Options));
    CHECK(0U == Options.uiTimeoutMs);
    pacProtectedReceive[4] = "600001";
    CHECK(!ParseNativeAppPacketOptions(5U, pacProtectedReceive, &Options));
    CHECK(ParseNativeAppPacketOptions(3U, pacProtectedSubmit, &Options));
    CHECK(NATIVE_APP_PACKET_PROTECTED_SUBMIT == Options.eAction);
    CHECK(!ParseNativeAppPacketOptions(5U, pacProtectedSubmit, &Options));
    CHECK(ParseNativeAppPacketOptions(5U, pacPlainReceive, &Options));
    CHECK(NATIVE_APP_PACKET_PLAIN_RECEIVE == Options.eAction);
    CHECK(ParseNativeAppShowOptions(2U, pacShow, &Show));
    CHECK(!ParseNativeAppShowOptions(3U, pacShow, &Show));
    return true;
}

int main(void)
{
    return (VerifyDatapathSettings() && VerifyPacketArguments()) ? 0 : 1;
}
