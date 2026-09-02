#ifndef IPSEC_CRYPTO_INTERNAL_H
#define IPSEC_CRYPTO_INTERNAL_H

/* Reserved design boundary, deliberately not compiled:
 * - control side: required-provider policy, capability/health observations;
 * - charon side (separate project/plugin): actual KCMVP operation adapter.
 * Ordinary VICI does not install an encryption callback into charon.
 * Do not put vendor keys, encryption entry points or strongSwan headers here.
 * See README "Future KCMVP boundary" before defining a vendor-specific ABI.
 */

#endif
