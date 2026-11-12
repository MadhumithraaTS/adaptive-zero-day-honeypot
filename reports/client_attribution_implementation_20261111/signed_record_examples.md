# Signed relay record examples (from `evidence/relay_mapping.jsonl`)

- Schema: `relay-mapping-record-1`.
- Key: Ed25519, `key_id` `a52b8c522a4bb091` (first 16 hex characters of the public-key SHA-256 `a52b8c522a4bb0916536af2bf7d4f2f92f0cea47fe49553665e2a5b0a0d272bf`).
- Log: 11 records; chain head `cbca9711…67ba40`; verification result "chain and signatures verify".

## How a record is verified
1. Take the record without `record_hash` and `signature`. Serialise it as canonical JSON: sorted keys, `,`/`:` separators, UTF-8. Compute SHA-256; it must equal `record_hash`.
2. Verify `signature` (hex) with the pinned Ed25519 public key, over the ASCII bytes of `record_hash`.
3. `seq` must be the previous `seq` + 1, and `prev_hash` must equal the previous `record_hash`. The first record links to 64 zeros.
4. `key_id` must be the pinned key, and `written_utc` must be inside the key validity window.

## relay_start (seq 1)
```json
{"backend":"cowrie:2222","config_sha256":"401773deb4eefb9b5bce64116c58bed99e23b82d95a370b880a2a8122820a117","key_id":"a52b8c522a4bb091",
 "listeners":[{"bind":"172.21.0.2","mode":"published","name":"published","port":2222},{"bind":"10.250.25.2","mode":"demo","name":"demo","port":2222}],
 "prev_hash":"0000000000000000000000000000000000000000000000000000000000000000",
 "public_key_sha256":"a52b8c522a4bb0916536af2bf7d4f2f92f0cea47fe49553665e2a5b0a0d272bf",
 "record_hash":"fb9e56520e29df1076fabf9466f1d823c88a1f74c7b14c233cd44e931871892d","record_type":"relay_start","schema":"relay-mapping-record-1","seq":1,
 "signature":"ae0f325e91cb559806abd320184b02099742b3fbdaa7ddf7f200b7e1e0b773d5dc59f0c1adce217f601a58d77a3e92937aad41a8f4f4a20fb28400638213e60d",
 "written_utc":"2026-11-11T17:16:41.037751Z"}
```
`config_sha256` equals the SHA-256 of `cowrie/attributing_relay/relay_config.json` on the host.

## connection_open — S4 test client shell (seq 8)
```json
{"accepted_local":"10.250.25.2:2222","accepted_utc":"2026-11-11T17:19:28.188322Z","client_ip":"10.250.25.3","client_port":42370,
 "connection_id":"cbc790bd-c8a5-4a76-98a1-b2d679b4d773","ingress_listener":"10.250.25.2:2222","key_id":"a52b8c522a4bb091",
 "listener":"demo","listener_mode":"demo","prev_hash":"75441c2347612f620e1dbf24ee1902f332796a31fee56607b389d5140e9d44b0",
 "record_hash":"7730fc4d0a2654da526468a205bc5a169c2bcfad3cf6909d8772c953980e38f8","record_type":"connection_open","schema":"relay-mapping-record-1","seq":8,
 "signature":"88fcf3235bcd827a340d5762806ae958e5a61ad7855dd1feb690ce129c29f1d8395759900c5a4e9687d469b8721ee729e02a4dd2ff507f2c91ec8f115d93e00e",
 "upstream_connected_utc":"2026-11-11T17:19:28.190665Z","upstream_local_ip":"172.22.0.2","upstream_local_port":59090,
 "upstream_peer":"172.22.0.1:2222","written_utc":"2026-11-11T17:19:28.190711Z"}
```
The matching Cowrie event:

```
2026-11-11T17:19:28.191662Z 3eede5e19e25 cowrie.session.connect src_ip=172.22.0.2 src_port=59090
```

- The tuple matches exactly.
- The connect is 1.0 ms after `upstream_connected_utc`, inside the 2 s skew.
- The connect is after `accepted_utc`.
- The test client independently reported its local socket as `10.250.25.3:42370`.

## connection_close — S4 (seq 9)
```json
{"bytes_in":2152,"bytes_out":11432,"client_ip":"10.250.25.3","client_port":42370,"closed_utc":"2026-11-11T17:19:37.829584Z",
 "connection_id":"cbc790bd-c8a5-4a76-98a1-b2d679b4d773","key_id":"a52b8c522a4bb091","listener":"demo",
 "prev_hash":"7730fc4d0a2654da526468a205bc5a169c2bcfad3cf6909d8772c953980e38f8",
 "record_hash":"98b7a1cd1eef8d61e95215afe635c6adfa514687fae7fb88140ab5fb7c2d56ff","record_type":"connection_close","schema":"relay-mapping-record-1","seq":9,
 "signature":"f7898f85d21b6f9c2889b3e521bb99b78d90d85bc2e222bb0ccdb6cd3951ec2d9f24b09e015d893d7a2f5440fa6c3d17b97ee3f372e2f8a0a499c5dfa990a80e",
 "upstream_local_ip":"172.22.0.2","upstream_local_port":59090,"written_utc":"2026-11-11T17:19:37.829643Z"}
```
Cowrie logged `cowrie.session.closed` for session `3eede5e19e25` at 17:19:37.839892Z. That is 10.3 ms after the relay close, on the same connection, so the close is `consistent`.

## Published-path record (S1, seq 2), never attributable
- `listener` = `published`, `client_ip` = `172.21.0.1` (the Docker Desktop proxy), `accepted_local` = `172.21.0.2:2222`, upstream `172.22.0.2:41994`.
- It correlates with Cowrie session `9441bcce555c` and is classified `unattributed:published_listener`.
