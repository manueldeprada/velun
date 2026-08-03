/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2018-2023 WireGuard LLC. All Rights Reserved.
 */

#ifndef WIREGUARD_H
#define WIREGUARD_H

#include <sys/types.h>
#include <stdint.h>
#include <stdbool.h>

typedef void(*logger_fn_t)(void *context, int level, const char *msg);
extern void wgSetLogger(void *context, logger_fn_t logger_fn);
extern int wgTurnOn(const char *settings, int32_t tun_fd);
/* velun extension: like wgTurnOn but pins the WireGuard UDP bind
 * sockets to a specific physical interface ifindex via
 * setsockopt(IP_BOUND_IF / IPV6_BOUND_IF). ifindex == 0 means
 * "no pinning" and matches the legacy wgTurnOn behavior. */
extern int wgTurnOnPinned(const char *settings, int32_t tun_fd, int32_t ifindex);
/* velun extension: re-pin the existing UDP bind sockets to a new
 * ifindex without reopening them. Returns 0 on success, -1 if the
 * handle is unknown or has no PinnedBind, -2 on setsockopt failure. */
extern int wgSetBoundInterface(int handle, int32_t ifindex);
extern void wgTurnOff(int handle);
/* velun extension: callback-tun bring-up. Instead of a utun fd, wireguard-go
 * is driven via callbacks so the velun unified extension can own the single
 * utun and demux WireGuard alongside the OpenConnect-family tunnels.
 * deliver_fn is invoked for every decrypted peer->host packet (it must copy
 * synchronously); deliver_ctx is passed back verbatim. ifindex pins the UDP
 * bind exactly like wgTurnOnPinned. */
typedef void(*wg_deliver_fn_t)(void *ctx, const uint8_t *buf, int len);
extern int wgTurnOnCallback(const char *settings, int32_t mtu, int32_t ifindex, wg_deliver_fn_t deliver_fn, void *deliver_ctx);
/* velun extension: queue a host->peer packet for a callback-tun device.
 * Returns 0 ok, -1 unknown/non-callback handle, -2 queue full (dropped). */
extern int wgInject(int handle, const uint8_t *packet, int len);
extern int64_t wgSetConfig(int handle, const char *settings);
extern char *wgGetConfig(int handle);
extern void wgBumpSockets(int handle);
extern void wgDisableSomeRoamingForBrokenMobileSemantics(int handle);
extern const char *wgVersion();

#endif
