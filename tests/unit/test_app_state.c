#include "app_internal.h"

#include <stdio.h>
#include <string.h>

static bool SetTestText(
    char *pcDestination,
    size_t zDestinationLength,
    const char *pcSource)
{
    int32_t iLength = snprintf(pcDestination, zDestinationLength, "%s",
                               pcSource);

    return (0 <= iLength) && ((size_t)iLength < zDestinationLength);
}

static bool VerifyStateResolution(void)
{
    NativeAppConfig_t Config = {0};
    NativeAppTargetStatus_t Status;
    IpsecConnectionInfo_t Connection = {0};
    IpsecIkeSaInfo_t Ike = {0};
    IpsecChildSaInfo_t Child = {0};
    IpsecConnectionList_t Connections = {
        .pItems = &Connection,
        .uiCount = 1U
    };
    IpsecIkeSaList_t IkeSas = {
        .pItems = &Ike,
        .uiCount = 1U
    };
    IpsecChildSaList_t ChildSas = {
        .pItems = &Child,
        .uiCount = 1U
    };

    if (!SetTestText(Config.acConnectionName,
                     sizeof(Config.acConnectionName), "conn-rcst-1-1") ||
        !SetTestText(Config.acChildName,
                     sizeof(Config.acChildName), "child-rcst-1-1") ||
        !SetTestText(Connection.acName, sizeof(Connection.acName),
                     "conn-rcst-1-1") ||
        !SetTestText(Ike.acName, sizeof(Ike.acName), "conn-rcst-1-1") ||
        !SetTestText(Child.acName, sizeof(Child.acName),
                     "child-rcst-1-1") ||
        !SetTestText(Child.acState, sizeof(Child.acState), "INSTALLED")) {
        return false;
    }
    Ike.bEstablished = true;
    Child.uiReqid = 17U;
    ResolveNativeAppTargetStatus(&Config, &Connections, &IkeSas, &ChildSas,
                                 &Status);
    return Status.bConnectionLoaded && Status.bIkeEstablished &&
        Status.bChildInstalled && (17U == Status.uiReqid) &&
        (NATIVE_APP_PEER_STATE_CHILD_INSTALLED == GetNativeAppPeerState(
            Status.bConnectionLoaded, true, Status.bIkeEstablished,
            Status.bChildInstalled));
}

static bool VerifyPeerUpsert(void)
{
    NativeAppPeerTable_t Table;
    NativeAppPeer_t Peer = {0};
    NativeAppPeer_t StoredPeer;
    NativeAppPeer_t SelectedPeer;
    bool bValid = false;

    if (IPSEC_OK != InitializeNativeAppPeerTable(&Table)) {
        return false;
    }
    Peer.uiGroupId = 1U;
    Peer.uiLogonId = 1U;
    Peer.uiRegistrationCount = 1U;
    Peer.Config.eRole = NATIVE_APP_ROLE_INITIATOR;
    Peer.eState = NATIVE_APP_PEER_STATE_REGISTERED;
    if (SetTestText(Peer.Config.acRemoteAddress,
                    sizeof(Peer.Config.acRemoteAddress), "192.0.2.2") &&
        SetTestText(Peer.Config.acConnectionName,
                    sizeof(Peer.Config.acConnectionName), "conn-rcst-1-1") &&
        SetTestText(Peer.Config.acChildName,
                    sizeof(Peer.Config.acChildName), "child-rcst-1-1") &&
        SetTestText(Peer.Config.acCredentialId,
                    sizeof(Peer.Config.acCredentialId), "psk-rcst-1-1") &&
        SetTestText(Peer.Config.acRemoteId,
                    sizeof(Peer.Config.acRemoteId), "rcst-1-1") &&
        (IPSEC_OK == UpsertNativeAppPeer(&Table, &Peer, &StoredPeer)) &&
        (1U == Table.uiCount) &&
        (IPSEC_OK == UpsertNativeAppPeer(&Table, &Peer, &StoredPeer)) &&
        (1U == Table.uiCount) &&
        (2U == StoredPeer.uiRegistrationCount) &&
        (IPSEC_OK == SelectNativeAppPeerRecord(
            &Table, "rcst-1-1", &SelectedPeer)) &&
        (0U == Table.uiSelectedIndex) &&
        (2U == SelectedPeer.uiRegistrationCount)) {
        SelectedPeer.uiRegistrationCount = UINT32_MAX;
        if (2U != Table.aPeers[0].uiRegistrationCount) {
            DeinitializeNativeAppPeerTable(&Table);
            return false;
        }
        else {
            /* The selected record is a caller-owned snapshot. */
        }
        bValid = true;
    }
    else {
        /* Report failure after releasing the table mutex. */
    }
    DeinitializeNativeAppPeerTable(&Table);
    return bValid;
}

static bool VerifyActivePeerRenameRejected(void)
{
    NativeAppPeerTable_t Table;
    NativeAppPeer_t Peer = {0};
    NativeAppPeer_t ChangedPeer;
    NativeAppPeer_t StoredPeer;
    bool bValid = false;

    if (IPSEC_OK != InitializeNativeAppPeerTable(&Table)) {
        return false;
    }
    Peer.uiGroupId = 1U;
    Peer.uiLogonId = 1U;
    Peer.uiRegistrationCount = 1U;
    Peer.Config.eRole = NATIVE_APP_ROLE_INITIATOR;
    Peer.bConnectionLoaded = true;
    if (SetTestText(Peer.Config.acRemoteAddress,
                    sizeof(Peer.Config.acRemoteAddress), "192.0.2.2") &&
        SetTestText(Peer.Config.acConnectionName,
                    sizeof(Peer.Config.acConnectionName), "conn-rcst-1-1") &&
        SetTestText(Peer.Config.acChildName,
                    sizeof(Peer.Config.acChildName), "child-rcst-1-1") &&
        SetTestText(Peer.Config.acCredentialId,
                    sizeof(Peer.Config.acCredentialId), "psk-rcst-1-1") &&
        (IPSEC_OK == UpsertNativeAppPeer(&Table, &Peer, &StoredPeer))) {
        ChangedPeer = Peer;
        if (SetTestText(ChangedPeer.Config.acConnectionName,
                        sizeof(ChangedPeer.Config.acConnectionName),
                        "conn-reassigned") &&
            (IPSEC_ERR_INVALID_ARGUMENT == UpsertNativeAppPeer(
                &Table, &ChangedPeer, &StoredPeer)) &&
            (1U == Table.uiCount)) {
            bValid = true;
        }
        else {
            /* The active resource identity must remain unchanged. */
        }
    }
    else {
        /* Report failure after releasing the table mutex. */
    }
    DeinitializeNativeAppPeerTable(&Table);
    return bValid;
}

int main(void)
{
    if (!VerifyStateResolution()) {
        (void)fprintf(stderr, "application state resolution failed\n");
        return 1;
    }
    else if (!VerifyPeerUpsert()) {
        (void)fprintf(stderr, "peer duplicate registration handling failed\n");
        return 1;
    }
    else if (!VerifyActivePeerRenameRejected()) {
        (void)fprintf(stderr, "active peer reassignment was not rejected\n");
        return 1;
    }
    else if (IPSEC_ERR_INVALID_ARGUMENT != RemoveIpsecPsk(NULL, "psk")) {
        (void)fprintf(stderr, "targeted PSK validation failed\n");
        return 1;
    }
    else if ((NATIVE_APP_PEER_STATE_READY != GetNativeAppPeerState(
                  true, true, false, false)) ||
             (0 != strcmp("READY", GetNativeAppPeerStateName(
                 NATIVE_APP_PEER_STATE_READY)))) {
        (void)fprintf(stderr, "peer state naming failed\n");
        return 1;
    }
    else {
        return 0;
    }
}
