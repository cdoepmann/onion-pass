/* Copyright (c) 2001 Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2012, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#ifndef TOR_ADDRESSMAP_H
#define TOR_ADDRESSMAP_H

void addressmap_init(void);
void addressmap_clear_excluded_trackexithosts(const or_options_t *options);
void addressmap_clear_invalid_automaps(const or_options_t *options);
void addressmap_clean(time_t now);
void addressmap_clear_configured(void);
void addressmap_clear_transient(void);
void addressmap_free_all(void);
#define AMR_FLAG_USE_IPV4_DNS (1u<<0)
#define AMR_FLAG_USE_IPV6_DNS (1u<<1)
int addressmap_rewrite(char *address, size_t maxlen, unsigned flags,
                       time_t *expires_out,
                       addressmap_entry_source_t *exit_source_out);
int addressmap_rewrite_reverse(char *address, size_t maxlen, unsigned flags,
                               time_t *expires_out);
int addressmap_have_mapping(const char *address, int update_timeout);

void addressmap_register(const char *address, char *new_address,
                         time_t expires, addressmap_entry_source_t source,
                         const int address_wildcard,
                         const int new_address_wildcard);
int parse_virtual_addr_network(const char *val, int validate_only,
                               char **msg);
int client_dns_incr_failures(const char *address);
void client_dns_clear_failures(const char *address);
void client_dns_set_addressmap(origin_circuit_t *on_circ,
                               const char *address, const tor_addr_t *val,
                               const char *exitname, int ttl);
const char *addressmap_register_virtual_address(int type, char *new_address);
void addressmap_get_mappings(smartlist_t *sl, time_t min_expires,
                             time_t max_expires, int want_expiry);
int address_is_in_virtual_range(const char *addr);
void clear_trackexithost_mappings(const char *exitname);
void client_dns_set_reverse_addressmap(origin_circuit_t *on_circ,
                                       const char *address, const char *v,
                                       const char *exitname, int ttl);

#endif

