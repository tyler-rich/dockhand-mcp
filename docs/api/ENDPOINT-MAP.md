# DockHand API endpoint map (v1.0.46)

Generated from the `/api/docs` OpenAPI 3.0.3 document by `scripts/gen-endpoint-map.py` (the JSON itself is not committed; see `docs/api/README.md`). Regenerate when the spec is refreshed; diff the result and record tier changes in `docs/ARCHIVE.md` §14.

**Totals:** 261 paths, 375 operations. Tier counts: admin=17, destructive=24, excluded=176, operator=63, read=94, split=1


## Tier legend (this is the security decision, not documentation)

| Tier | Meaning | Exposed by profile |
|---|---|---|
| `read` | Read-only. No state change on DockHand or Docker. | `read-only`, `operator`, `admin` |
| `operator` | Changes runtime state but is reversible (start/stop/restart/deploy/compose+env edits/pull/scan/update-check). | `operator`, `admin` |
| `destructive` | Deletes data or resources, or is hard to undo (remove, prune, down, delete-with-volumes, restore, relocate). Requires `confirm=true` at the MCP layer. | `admin` only |
| `admin` | Changes DockHand's own configuration (environments, git repos/stacks, backup destinations, scanner settings). **Out of scope for v1**; listed so exclusion is a conscious decision. | *(not exposed in v1)* |
| `split` | One endpoint, tier decided by a body field. Only `POST /api/batch`: `operation` ∈ start/stop/restart/pause/unpause → **operator** (`dockhand_batch_containers`); `remove` → **destructive** (`dockhand_batch_remove_containers`); anything else → not exposed. | per operation |
| `excluded` | Never exposed by this MCP server in any profile: auth-provider config, API/hawser tokens, users/roles/MFA, license, in-container exec/file access, DockHand host filesystem, UI preferences, icons, raw SSE feeds, self-update, secret providers, git/registry credentials, image export/load/push, volume file browsing, webhooks. See `docs/SECURITY.md` §4. | never |

Columns: **Async** = `job` (returns `{jobId}`; poll `GET /api/jobs/{id}`), `sse` (streams Server-Sent Events), `accept-json` (send `Accept: application/json` to receive the final result synchronously instead of a job id / SSE). **Perm** = DockHand RBAC permission strings found in the spec text for that operation (Enterprise edition only; the Free edition grants every authenticated user everything).


## `activity` (5 ops)

| Method | Path | Tier | Public | Query params | Body fields | Async | Perm |
|---|---|---|---|---|---|---|---|
| `GET` | `/api/activity` | **read** |  | environmentId, containerId, containerName, actions, labels, fromDate, toDate, limit, offset |  |  | activity:view |
| `DELETE` | `/api/activity` | **destructive** |  |  |  |  | activity:delete |
| `GET` | `/api/activity/containers` | **read** |  | environment_id |  |  | activity:view |
| `GET` | `/api/activity/events` | **excluded** |  |  |  | sse | activity:view |
| `GET` | `/api/activity/stats` | **read** |  | environment_id |  |  | activity:view |

## `audit` (6 ops)

| Method | Path | Tier | Public | Query params | Body fields | Async | Perm |
|---|---|---|---|---|---|---|---|
| `GET` | `/api/audit` | **read** |  | usernames, entityTypes, actions, username, entityType, action, environmentId, labels, fromDate, toDate, limit, offset |  |  |  |
| `GET` | `/api/audit/events` | **excluded** |  |  |  | sse |  |
| `GET` | `/api/audit/export` | **read** |  | username, entityType, action, environmentId, fromDate, toDate, format |  |  |  |
| `GET` | `/api/audit/users` | **read** |  |  |  |  |  |
| `GET` | `/audit` | **read** |  | username, entity_type, action, environment_id, from_date, to_date, limit, offset |  |  |  |
| `GET` | `/audit/users` | **read** |  |  |  |  |  |

## `auth` (24 ops)

| Method | Path | Tier | Public | Query params | Body fields | Async | Perm |
|---|---|---|---|---|---|---|---|
| `GET` | `/api/auth/ldap` | **excluded** |  |  |  |  |  |
| `POST` | `/api/auth/ldap` | **excluded** |  |  | name, serverUrl, baseDn, enabled, bindDn, bindPassword, userFilter, usernameAttribute, emailAttribute, displayNameAttribute… |  |  |
| `GET` | `/api/auth/ldap/{id}` | **excluded** |  |  |  |  |  |
| `PUT` | `/api/auth/ldap/{id}` | **excluded** |  |  | name, enabled, serverUrl, bindDn, bindPassword, baseDn, userFilter, usernameAttribute, emailAttribute, displayNameAttribute… |  |  |
| `DELETE` | `/api/auth/ldap/{id}` | **excluded** |  |  |  |  |  |
| `POST` | `/api/auth/ldap/{id}/test` | **excluded** |  |  |  |  |  |
| `POST` | `/api/auth/login` | **excluded** | yes |  | username, password, mfaToken, provider |  |  |
| `POST` | `/api/auth/logout` | **excluded** | yes |  |  |  |  |
| `GET` | `/api/auth/oidc` | **excluded** | yes |  |  |  | settings:view |
| `POST` | `/api/auth/oidc` | **excluded** | yes |  | name, issuerUrl, clientId, clientSecret, redirectUri, enabled, scopes, usernameClaim, emailClaim, displayNameClaim… |  | settings:edit |
| `GET` | `/api/auth/oidc/{id}` | **excluded** | yes |  |  |  | settings:view |
| `PUT` | `/api/auth/oidc/{id}` | **excluded** | yes |  | name, enabled, issuerUrl, clientId, clientSecret, redirectUri, scopes, usernameClaim, emailClaim, displayNameClaim… |  | settings:edit |
| `DELETE` | `/api/auth/oidc/{id}` | **excluded** | yes |  |  |  | settings:edit |
| `GET` | `/api/auth/oidc/{id}/initiate` | **excluded** | yes | redirect |  |  |  |
| `POST` | `/api/auth/oidc/{id}/initiate` | **excluded** | yes |  | redirect |  |  |
| `POST` | `/api/auth/oidc/{id}/test` | **excluded** | yes |  |  |  |  |
| `GET` | `/api/auth/oidc/callback` | **excluded** | yes | code, state, error, error_description |  |  |  |
| `GET` | `/api/auth/providers` | **excluded** | yes |  |  |  |  |
| `GET` | `/api/auth/session` | **excluded** | yes |  |  |  |  |
| `GET` | `/api/auth/settings` | **excluded** | yes |  |  |  | settings:view |
| `PUT` | `/api/auth/settings` | **excluded** | yes |  | authEnabled, defaultProvider, sessionTimeout |  | settings:edit |
| `GET` | `/api/auth/tokens` | **excluded** |  |  |  |  |  |
| `POST` | `/api/auth/tokens` | **excluded** |  |  | name, expiresAt, password |  |  |
| `DELETE` | `/api/auth/tokens/{id}` | **excluded** |  |  |  |  |  |

## `auto-update` (4 ops)

| Method | Path | Tier | Public | Query params | Body fields | Async | Perm |
|---|---|---|---|---|---|---|---|
| `GET` | `/api/auto-update` | **read** |  | env |  |  |  |
| `GET` | `/api/auto-update/{containerName}` | **read** |  | env |  |  |  |
| `POST` | `/api/auto-update/{containerName}` | **operator** |  | env | enabled, cronExpression, cron_expression, vulnerabilityCriteria, vulnerability_criteria |  |  |
| `DELETE` | `/api/auto-update/{containerName}` | **operator** |  | env |  |  |  |

## `backup` (31 ops)

| Method | Path | Tier | Public | Query params | Body fields | Async | Perm |
|---|---|---|---|---|---|---|---|
| `GET` | `/api/backup/configs` | **read** |  | type, target, env |  |  | backups:view |
| `POST` | `/api/backup/configs` | **operator** |  |  | destinationId, targetName, type, environmentId, enabled, allVolumes, selectedVolumes, stopBeforeBackup, schedule, retention… |  | backups:manage |
| `GET` | `/api/backup/configs/{id}` | **read** |  |  |  |  | backups:view |
| `PUT` | `/api/backup/configs/{id}` | **operator** |  |  | destinationId, enabled, allVolumes, selectedVolumes, stopBeforeBackup, schedule, retention, options, tags |  | backups:manage |
| `DELETE` | `/api/backup/configs/{id}` | **destructive** |  | deleteSnapshots |  |  | backups:manage |
| `POST` | `/api/backup/configs/{id}/run` | **operator** |  |  |  | sse | backups:manage |
| `POST` | `/api/backup/configs/{id}/stop` | **operator** |  |  |  |  | backups:manage |
| `GET` | `/api/backup/destinations` | **read** |  |  |  |  | backups:view |
| `POST` | `/api/backup/destinations` | **admin** |  |  | name, repository, password, envVars, flags, backupFlags, restoreFlags, hostPath, cacert, tlsClientCert… |  | backups:manage |
| `GET` | `/api/backup/destinations/{id}` | **excluded** |  |  |  |  | backups:manage, backups:view |
| `PUT` | `/api/backup/destinations/{id}` | **excluded** |  |  | name, repository, password, envVars, flags, backupFlags, restoreFlags, hostPath, cacert, tlsClientCert… |  | backups:manage |
| `DELETE` | `/api/backup/destinations/{id}` | **excluded** |  |  |  |  | backups:manage |
| `POST` | `/api/backup/destinations/{id}/init` | **operator** |  |  |  |  | backups:manage |
| `POST` | `/api/backup/destinations/{id}/rotate-key` | **excluded** |  |  | currentPassword, newPassword |  | backups:manage |
| `POST` | `/api/backup/destinations/{id}/task` | **destructive** |  |  | task |  | backups:manage |
| `POST` | `/api/backup/destinations/{id}/test` | **operator** |  |  |  |  | backups:manage |
| `POST` | `/api/backup/destinations/{id}/verify` | **operator** |  |  | dataSubset | sse | backups:manage |
| `POST` | `/api/backup/destinations/test` | **operator** |  |  | destinationId, repository, password, envVars, cacert, tlsClientCert |  | backups:manage |
| `GET` | `/api/backup/instance` | **read** |  |  |  |  | backups:view |
| `POST` | `/api/backup/restore` | **destructive** |  |  | destinationId, snapshotId, mode, targetType, volumes, environmentId, confirmOverwrite, targetPath, targetName, postRestore… | sse | backups:manage |
| `POST` | `/api/backup/restore/preview` | **operator** |  |  | destinationId, snapshotId, includeTargets, targetEnvId, environmentId, mode, targetType, targetName, targetPath, volumeDestinations… |  | backups:view |
| `POST` | `/api/backup/restore/stop` | **operator** |  |  | snapshotId, environmentId |  | backups:manage |
| `GET` | `/api/backup/snapshots` | **read** |  | configId, destinationId, allDestinations |  | job | backups:view |
| `DELETE` | `/api/backup/snapshots/{id}` | **destructive** |  | destinationId, env |  |  | backups:manage |
| `GET` | `/api/backup/snapshots/{id}/browse` | **read** |  | destinationId, path, env |  | job | backups:view |
| `GET` | `/api/backup/snapshots/{id}/dump` | **excluded** |  | destinationId, path, type, download |  | job | backups:view |
| `GET` | `/api/backup/snapshots/{id}/metadata` | **read** |  | destinationId |  | job |  |
| `POST` | `/api/backup/snapshots/batch-delete` | **destructive** |  |  | destinationId, snapshotIds |  | backups:manage |
| `GET` | `/api/backup/snapshots/diff` | **read** |  | destinationId, snapshotA, snapshotB |  | job |  |
| `GET` | `/api/backup/stack-dir-listing` | **read** |  | target, env |  |  | backups:view |
| `GET` | `/api/backup/stack-path` | **read** |  | target, env |  |  | backups:view |

## `batch` (1 ops)

| Method | Path | Tier | Public | Query params | Body fields | Async | Perm |
|---|---|---|---|---|---|---|---|
| `POST` | `/api/batch` | **split** |  | env | operation, entityType, items, options | job, sse, accept-json |  |

## `changelog` (1 ops)

| Method | Path | Tier | Public | Query params | Body fields | Async | Perm |
|---|---|---|---|---|---|---|---|
| `GET` | `/api/changelog` | **excluded** | yes |  |  |  |  |

## `config-sets` (5 ops)

| Method | Path | Tier | Public | Query params | Body fields | Async | Perm |
|---|---|---|---|---|---|---|---|
| `GET` | `/api/config-sets` | **excluded** |  |  |  |  | configsets:view |
| `POST` | `/api/config-sets` | **excluded** |  |  | name, description, envVars, labels, ports, volumes, networkMode, restartPolicy |  | configsets:create |
| `GET` | `/api/config-sets/{id}` | **excluded** |  |  |  |  | configsets:view |
| `PUT` | `/api/config-sets/{id}` | **excluded** |  |  | name, description, envVars, labels, ports, volumes, networkMode, restartPolicy |  | configsets:edit |
| `DELETE` | `/api/config-sets/{id}` | **excluded** |  |  |  |  | configsets:delete |

## `container-icons` (4 ops)

| Method | Path | Tier | Public | Query params | Body fields | Async | Perm |
|---|---|---|---|---|---|---|---|
| `GET` | `/api/container-icons` | **excluded** |  | env |  |  | containers:view |
| `GET` | `/api/container-icons/{name}` | **excluded** |  | env |  |  | containers:view |
| `POST` | `/api/container-icons/{name}` | **excluded** |  | env | icon, image |  | containers:edit |
| `DELETE` | `/api/container-icons/{name}` | **excluded** |  | env |  |  | containers:edit |

## `containers` (39 ops)

| Method | Path | Tier | Public | Query params | Body fields | Async | Perm |
|---|---|---|---|---|---|---|---|
| `GET` | `/api/containers` | **read** |  | env, all |  |  |  |
| `POST` | `/api/containers` | **operator** |  | env | name, image, ports, volumes, volumeBinds, env, labels, cmd, entrypoint, workingDir… |  |  |
| `GET` | `/api/containers/{id}` | **read** |  | env |  |  |  |
| `DELETE` | `/api/containers/{id}` | **destructive** |  | env, force |  |  |  |
| `GET` | `/api/containers/{id}/compose` | **read** |  | env |  |  |  |
| `POST` | `/api/containers/{id}/exec` | **excluded** |  | envId | shell, user |  |  |
| `GET` | `/api/containers/{id}/files` | **excluded** |  | env, path, simpleLs |  |  | containers:exec |
| `POST` | `/api/containers/{id}/files/chmod` | **excluded** |  | env | path, mode, recursive |  |  |
| `GET` | `/api/containers/{id}/files/content` | **excluded** |  | env, path |  |  | containers:exec |
| `PUT` | `/api/containers/{id}/files/content` | **excluded** |  | env, path | content |  |  |
| `POST` | `/api/containers/{id}/files/create` | **excluded** |  | env | path, type |  |  |
| `DELETE` | `/api/containers/{id}/files/delete` | **excluded** |  | env, path |  |  |  |
| `GET` | `/api/containers/{id}/files/download` | **excluded** |  | env, path, format |  |  |  |
| `POST` | `/api/containers/{id}/files/rename` | **excluded** |  | env | oldPath, newPath |  |  |
| `POST` | `/api/containers/{id}/files/upload` | **excluded** |  | env, path |  |  |  |
| `GET` | `/api/containers/{id}/inspect` | **read** |  | env |  |  |  |
| `GET` | `/api/containers/{id}/logs` | **read** |  | env, tail, since, until |  |  |  |
| `GET` | `/api/containers/{id}/logs/stream` | **excluded** |  | env, tail, since, until |  | sse |  |
| `POST` | `/api/containers/{id}/pause` | **operator** |  | env |  |  |  |
| `POST` | `/api/containers/{id}/rename` | **operator** |  | env | name |  |  |
| `POST` | `/api/containers/{id}/restart` | **operator** |  | env |  |  |  |
| `GET` | `/api/containers/{id}/shells` | **excluded** |  | env |  |  |  |
| `POST` | `/api/containers/{id}/start` | **operator** |  | env |  |  |  |
| `GET` | `/api/containers/{id}/stats` | **read** |  | env |  |  |  |
| `POST` | `/api/containers/{id}/stop` | **operator** |  | env |  |  |  |
| `GET` | `/api/containers/{id}/top` | **read** |  | env |  |  |  |
| `POST` | `/api/containers/{id}/unpause` | **operator** |  | env |  |  |  |
| `POST` | `/api/containers/{id}/update` | **operator** |  | env | image, name, repullImage, startAfterUpdate |  |  |
| `POST` | `/api/containers/{id}/update-runtime` | **operator** |  | env | RestartPolicy, CpuShares, CpuPeriod, CpuQuota, CpuRealtimePeriod, CpuRealtimeRuntime, CpusetCpus, CpusetMems, NanoCpus, Memory… |  |  |
| `GET` | `/api/containers/{id}/version-notes` | **read** |  | env, versions |  |  |  |
| `POST` | `/api/containers/batch-update` | **operator** |  | env | containerIds |  |  |
| `POST` | `/api/containers/batch-update-stream` | **excluded** |  | env | containerIds, vulnerabilityCriteria | sse |  |
| `GET` | `/api/containers/check-updates` | **read** |  | env |  |  |  |
| `POST` | `/api/containers/check-updates` | **operator** |  | env |  | sse, accept-json |  |
| `GET` | `/api/containers/pending-updates` | **read** |  | env |  |  |  |
| `DELETE` | `/api/containers/pending-updates` | **operator** |  | env, containerId |  |  |  |
| `GET` | `/api/containers/sizes` | **read** |  | env |  |  |  |
| `GET` | `/api/containers/stats` | **read** |  | env, debug |  |  |  |
| `GET` | `/api/containers/stats/stream` | **excluded** |  | env |  | sse |  |

## `dashboard` (4 ops)

| Method | Path | Tier | Public | Query params | Body fields | Async | Perm |
|---|---|---|---|---|---|---|---|
| `GET` | `/api/dashboard/preferences` | **excluded** |  |  |  |  |  |
| `POST` | `/api/dashboard/preferences` | **excluded** |  |  | gridLayout, locked, viewMode |  |  |
| `GET` | `/api/dashboard/stats` | **read** |  | env |  |  | environments:view |
| `GET` | `/api/dashboard/stats/stream` | **excluded** |  |  |  | sse, accept-json | environments:view |

## `debug` (1 ops)

| Method | Path | Tier | Public | Query params | Body fields | Async | Perm |
|---|---|---|---|---|---|---|---|
| `GET` | `/api/debug/memory` | **excluded** |  | gc |  |  |  |

## `dependencies` (1 ops)

| Method | Path | Tier | Public | Query params | Body fields | Async | Perm |
|---|---|---|---|---|---|---|---|
| `GET` | `/api/dependencies` | **excluded** | yes |  |  |  |  |

## `docs` (1 ops)

| Method | Path | Tier | Public | Query params | Body fields | Async | Perm |
|---|---|---|---|---|---|---|---|
| `GET` | `/api/docs` | **excluded** | yes |  |  |  |  |

## `environments` (27 ops)

| Method | Path | Tier | Public | Query params | Body fields | Async | Perm |
|---|---|---|---|---|---|---|---|
| `GET` | `/api/environments` | **read** |  |  |  |  | environments:view |
| `POST` | `/api/environments` | **admin** |  |  | name, connectionType, host, port, protocol, socketPath, icon, publicIp, labels |  | environments:create |
| `GET` | `/api/environments/{id}` | **read** |  |  |  |  | environments:view |
| `PUT` | `/api/environments/{id}` | **admin** |  |  | name, host, port, protocol, tlsCa, tlsCert, tlsKey, tlsSkipVerify, icon, socketPath… |  | environments:edit |
| `DELETE` | `/api/environments/{id}` | **admin** |  |  |  |  | environments:delete |
| `GET` | `/api/environments/{id}/disk-warning` | **read** |  |  |  |  | environments:view |
| `POST` | `/api/environments/{id}/disk-warning` | **admin** |  |  | enabled, mode, threshold, thresholdGb |  | environments:edit |
| `GET` | `/api/environments/{id}/icon` | **excluded** |  |  |  |  |  |
| `POST` | `/api/environments/{id}/icon` | **excluded** |  |  | image |  | environments:edit |
| `DELETE` | `/api/environments/{id}/icon` | **excluded** |  |  |  |  | environments:edit |
| `GET` | `/api/environments/{id}/image-prune` | **read** |  |  |  |  | environments:view |
| `POST` | `/api/environments/{id}/image-prune` | **admin** |  |  | enabled, cronExpression, pruneMode |  | environments:edit |
| `PUT` | `/api/environments/{id}/image-prune` | **destructive** |  |  |  |  | environments:edit |
| `GET` | `/api/environments/{id}/notifications` | **excluded** |  |  |  |  | notifications:view |
| `POST` | `/api/environments/{id}/notifications` | **excluded** |  |  | notificationId, enabled, eventTypes |  | notifications:edit |
| `GET` | `/api/environments/{id}/notifications/{notificationId}` | **excluded** |  |  |  |  | notifications:view |
| `PUT` | `/api/environments/{id}/notifications/{notificationId}` | **excluded** |  |  | enabled, eventTypes |  | notifications:edit |
| `DELETE` | `/api/environments/{id}/notifications/{notificationId}` | **excluded** |  |  |  |  | notifications:delete |
| `GET` | `/api/environments/{id}/remote-stacks-dir` | **read** |  |  |  |  | environments:view |
| `POST` | `/api/environments/{id}/remote-stacks-dir` | **admin** |  |  | remoteStacksDir |  | environments:edit |
| `POST` | `/api/environments/{id}/test` | **operator** |  |  |  |  |  |
| `GET` | `/api/environments/{id}/timezone` | **read** |  |  |  |  | environments:view |
| `POST` | `/api/environments/{id}/timezone` | **admin** |  |  | timezone |  | environments:edit |
| `GET` | `/api/environments/{id}/update-check` | **read** |  |  |  |  | environments:view |
| `POST` | `/api/environments/{id}/update-check` | **admin** |  |  | enabled, cron, autoUpdate, vulnerabilityCriteria |  | environments:edit |
| `GET` | `/api/environments/detect-socket` | **read** |  |  |  |  |  |
| `POST` | `/api/environments/test` | **operator** |  |  | connectionType, socketPath, host, port, protocol, tlsCa, tlsCert, tlsKey, tlsSkipVerify, hawserToken… |  |  |

## `events` (1 ops)

| Method | Path | Tier | Public | Query params | Body fields | Async | Perm |
|---|---|---|---|---|---|---|---|
| `GET` | `/api/events` | **excluded** |  | env |  | sse |  |

## `git` (32 ops)

| Method | Path | Tier | Public | Query params | Body fields | Async | Perm |
|---|---|---|---|---|---|---|---|
| `POST` | `/api/git/branches` | **operator** |  |  | repositoryId, url, credentialId | accept-json | git:edit |
| `GET` | `/api/git/credentials` | **excluded** |  |  |  |  | git:view |
| `POST` | `/api/git/credentials` | **excluded** |  |  | name, authType, username, password, sshPrivateKey, sshPassphrase |  | git:create |
| `GET` | `/api/git/credentials/{id}` | **excluded** |  |  |  |  | git:view |
| `PUT` | `/api/git/credentials/{id}` | **excluded** |  |  | name, authType, username, password, sshPrivateKey, sshPassphrase |  | git:edit |
| `DELETE` | `/api/git/credentials/{id}` | **excluded** |  |  |  |  | git:delete |
| `POST` | `/api/git/preview-env` | **excluded** |  |  | repositoryId, url, branch, credentialId, composePath, envFilePath |  | git:edit |
| `GET` | `/api/git/repositories` | **read** |  |  |  |  | git:view |
| `POST` | `/api/git/repositories` | **admin** |  |  | name, url, branch, credentialId |  | git:create |
| `GET` | `/api/git/repositories/{id}` | **read** |  |  |  |  | git:view |
| `PUT` | `/api/git/repositories/{id}` | **admin** |  |  | name, url, branch, credentialId |  | git:edit |
| `DELETE` | `/api/git/repositories/{id}` | **destructive** |  |  |  |  | git:delete |
| `POST` | `/api/git/repositories/{id}/deploy` | **operator** |  |  |  |  | git:edit |
| `GET` | `/api/git/repositories/{id}/sync` | **read** |  |  |  |  | git:view |
| `POST` | `/api/git/repositories/{id}/sync` | **operator** |  |  |  |  | git:edit |
| `POST` | `/api/git/repositories/{id}/test` | **operator** |  |  |  |  | git:edit |
| `POST` | `/api/git/repositories/test` | **operator** |  |  | url, branch, credentialId |  | settings:manage |
| `GET` | `/api/git/stacks` | **read** |  | env |  |  | stacks:view |
| `POST` | `/api/git/stacks` | **admin** |  |  | stackName, environmentId, repositoryId, secretProviderId, webhookEnabled, webhookSecret |  | secrets:view, stacks:create |
| `GET` | `/api/git/stacks/{id}` | **read** |  |  |  |  | stacks:view |
| `PUT` | `/api/git/stacks/{id}` | **admin** |  |  | stackName, secretProviderId, webhookEnabled, webhookSecret |  | secrets:view, stacks:edit |
| `DELETE` | `/api/git/stacks/{id}` | **destructive** |  |  |  |  | stacks:delete |
| `POST` | `/api/git/stacks/{id}/deploy` | **operator** |  |  |  |  | stacks:start |
| `POST` | `/api/git/stacks/{id}/deploy-stream` | **operator** |  |  |  | job, accept-json | stacks:start |
| `GET` | `/api/git/stacks/{id}/env-files` | **read** |  |  |  |  | stacks:view |
| `POST` | `/api/git/stacks/{id}/env-files` | **excluded** |  |  | path |  | stacks:view |
| `POST` | `/api/git/stacks/{id}/sync` | **operator** |  |  |  |  | stacks:edit |
| `POST` | `/api/git/stacks/{id}/test` | **operator** |  |  |  |  | stacks:view |
| `GET` | `/api/git/stacks/{id}/webhook` | **excluded** | yes | secret |  |  |  |
| `POST` | `/api/git/stacks/{id}/webhook` | **excluded** | yes |  |  |  |  |
| `GET` | `/api/git/webhook/{id}` | **excluded** | yes | secret |  |  |  |
| `POST` | `/api/git/webhook/{id}` | **excluded** | yes |  | ref |  |  |

## `hawser` (5 ops)

| Method | Path | Tier | Public | Query params | Body fields | Async | Perm |
|---|---|---|---|---|---|---|---|
| `GET` | `/api/hawser/connect` | **excluded** |  |  |  |  |  |
| `POST` | `/api/hawser/connect` | **excluded** |  |  |  |  |  |
| `GET` | `/api/hawser/tokens` | **excluded** |  |  |  |  |  |
| `POST` | `/api/hawser/tokens` | **excluded** |  |  | name, environmentId, expiresAt, rawToken |  |  |
| `DELETE` | `/api/hawser/tokens` | **excluded** |  | id |  |  |  |

## `health` (2 ops)

| Method | Path | Tier | Public | Query params | Body fields | Async | Perm |
|---|---|---|---|---|---|---|---|
| `GET` | `/api/health` | **read** | yes |  |  |  |  |
| `GET` | `/api/health/database` | **read** | yes |  |  |  | settings:view |

## `host` (1 ops)

| Method | Path | Tier | Public | Query params | Body fields | Async | Perm |
|---|---|---|---|---|---|---|---|
| `GET` | `/api/host` | **read** |  | env |  |  |  |

## `icons` (3 ops)

| Method | Path | Tier | Public | Query params | Body fields | Async | Perm |
|---|---|---|---|---|---|---|---|
| `GET` | `/api/icons/selfhst/{ref}` | **excluded** |  |  |  |  |  |
| `POST` | `/api/icons/selfhst/batch` | **excluded** |  |  | refs |  |  |
| `GET` | `/api/icons/selfhst-manifest` | **excluded** |  |  |  |  |  |

## `images` (11 ops)

| Method | Path | Tier | Public | Query params | Body fields | Async | Perm |
|---|---|---|---|---|---|---|---|
| `GET` | `/api/images` | **read** |  | env |  |  |  |
| `DELETE` | `/api/images/{id}` | **destructive** |  | env, force |  |  |  |
| `GET` | `/api/images/{id}/export` | **excluded** |  | env, compress |  |  |  |
| `GET` | `/api/images/{id}/history` | **read** |  | env |  |  |  |
| `POST` | `/api/images/{id}/tag` | **operator** |  | env | repo, tag |  |  |
| `POST` | `/api/images/load` | **excluded** |  | env |  |  |  |
| `POST` | `/api/images/pull` | **operator** |  | env | image, scanAfterPull | sse |  |
| `POST` | `/api/images/push` | **excluded** |  | env | imageId, registryId, imageName, newTag | job, accept-json |  |
| `GET` | `/api/images/scan` | **read** |  | env, image, scanner |  |  |  |
| `POST` | `/api/images/scan` | **operator** |  | env | imageName, scanner | sse |  |
| `GET` | `/api/images/scan/export` | **excluded** |  | imageId, image, format |  |  |  |

## `jobs` (2 ops)

| Method | Path | Tier | Public | Query params | Body fields | Async | Perm |
|---|---|---|---|---|---|---|---|
| `GET` | `/api/jobs/{id}` | **read** |  |  |  |  |  |
| `DELETE` | `/api/jobs/{id}` | **operator** |  |  |  |  |  |

## `labels` (2 ops)

| Method | Path | Tier | Public | Query params | Body fields | Async | Perm |
|---|---|---|---|---|---|---|---|
| `GET` | `/api/labels` | **excluded** |  |  |  |  | environments:view |
| `POST` | `/api/labels` | **excluded** |  |  | action, oldLabel, newLabel, label, environmentIds, color |  | environments:edit |

## `legal` (2 ops)

| Method | Path | Tier | Public | Query params | Body fields | Async | Perm |
|---|---|---|---|---|---|---|---|
| `GET` | `/api/legal/license` | **excluded** |  | format |  |  |  |
| `GET` | `/api/legal/privacy` | **excluded** |  | format |  |  |  |

## `license` (3 ops)

| Method | Path | Tier | Public | Query params | Body fields | Async | Perm |
|---|---|---|---|---|---|---|---|
| `GET` | `/api/license` | **excluded** | yes |  |  |  |  |
| `POST` | `/api/license` | **excluded** | yes |  | name, key |  | license:manage |
| `DELETE` | `/api/license` | **excluded** | yes |  |  |  | license:manage |

## `logs` (1 ops)

| Method | Path | Tier | Public | Query params | Body fields | Async | Perm |
|---|---|---|---|---|---|---|---|
| `GET` | `/api/logs/merged` | **excluded** |  | containers, tail, since, until, env |  | sse | containers:logs |

## `metrics` (1 ops)

| Method | Path | Tier | Public | Query params | Body fields | Async | Perm |
|---|---|---|---|---|---|---|---|
| `GET` | `/metrics` | **excluded** |  |  |  |  |  |

## `networks` (7 ops)

| Method | Path | Tier | Public | Query params | Body fields | Async | Perm |
|---|---|---|---|---|---|---|---|
| `GET` | `/api/networks` | **read** |  | env |  |  |  |
| `POST` | `/api/networks` | **operator** |  | env | name, driver, internal, attachable, ingress, enableIPv6, options, labels, ipam |  |  |
| `GET` | `/api/networks/{id}` | **read** |  | env |  |  |  |
| `DELETE` | `/api/networks/{id}` | **destructive** |  | env |  |  |  |
| `POST` | `/api/networks/{id}/connect` | **operator** |  | env | containerId, containerName |  |  |
| `POST` | `/api/networks/{id}/disconnect` | **operator** |  | env | containerId, containerName, force |  |  |
| `GET` | `/api/networks/{id}/inspect` | **read** |  | env |  |  |  |

## `notifications` (9 ops)

| Method | Path | Tier | Public | Query params | Body fields | Async | Perm |
|---|---|---|---|---|---|---|---|
| `GET` | `/api/notifications` | **read** |  |  |  |  | notifications:view |
| `POST` | `/api/notifications` | **excluded** |  |  | type, name, enabled, config, eventTypes, event_types |  | notifications:create |
| `GET` | `/api/notifications/{id}` | **read** |  |  |  |  | notifications:view |
| `PUT` | `/api/notifications/{id}` | **excluded** |  |  | name, enabled, config, eventTypes, event_types |  | notifications:edit |
| `DELETE` | `/api/notifications/{id}` | **excluded** |  |  |  |  | notifications:delete |
| `POST` | `/api/notifications/{id}/test` | **operator** |  |  |  |  | notifications:edit |
| `POST` | `/api/notifications/test` | **operator** |  |  | type, name, config |  | settings:edit |
| `GET` | `/api/notifications/trigger-test` | **read** |  |  |  |  |  |
| `POST` | `/api/notifications/trigger-test` | **operator** |  |  | eventType, environmentId, payload |  |  |

## `preferences` (10 ops)

| Method | Path | Tier | Public | Query params | Body fields | Async | Perm |
|---|---|---|---|---|---|---|---|
| `GET` | `/api/preferences/favorite-groups` | **excluded** |  | env |  |  |  |
| `POST` | `/api/preferences/favorite-groups` | **excluded** |  |  | environmentId, action, name, containers, newName, groups |  |  |
| `GET` | `/api/preferences/favorites` | **excluded** |  | env |  |  |  |
| `POST` | `/api/preferences/favorites` | **excluded** |  |  | environmentId, action, containerName, favorites |  |  |
| `GET` | `/api/preferences/grid` | **excluded** |  |  |  |  |  |
| `POST` | `/api/preferences/grid` | **excluded** |  |  | gridId, columns |  |  |
| `DELETE` | `/api/preferences/grid` | **excluded** |  | gridId |  |  |  |
| `GET` | `/api/preferences/sidebar` | **excluded** |  |  |  |  |  |
| `POST` | `/api/preferences/sidebar` | **excluded** |  |  | order, hidden |  |  |
| `DELETE` | `/api/preferences/sidebar` | **excluded** |  |  |  |  |  |

## `profile` (6 ops)

| Method | Path | Tier | Public | Query params | Body fields | Async | Perm |
|---|---|---|---|---|---|---|---|
| `GET` | `/api/profile` | **excluded** |  |  |  |  |  |
| `PUT` | `/api/profile` | **excluded** |  |  | email, displayName, currentPassword, newPassword |  |  |
| `POST` | `/api/profile/avatar` | **excluded** |  |  | avatar |  |  |
| `DELETE` | `/api/profile/avatar` | **excluded** |  |  |  |  |  |
| `GET` | `/api/profile/preferences` | **excluded** |  |  |  |  |  |
| `PUT` | `/api/profile/preferences` | **excluded** |  |  | lightTheme, darkTheme, font, fontSize, gridFontSize, terminalFont, editorFont, animateIcons, coloredActionButtons, actionIconSize… |  |  |

## `prune` (5 ops)

| Method | Path | Tier | Public | Query params | Body fields | Async | Perm |
|---|---|---|---|---|---|---|---|
| `POST` | `/api/prune/all` | **destructive** |  | env |  |  |  |
| `POST` | `/api/prune/containers` | **destructive** |  | env |  |  |  |
| `POST` | `/api/prune/images` | **destructive** |  | dangling, env |  | sse |  |
| `POST` | `/api/prune/networks` | **destructive** |  | env |  |  |  |
| `POST` | `/api/prune/volumes` | **destructive** |  | env |  |  |  |

## `registries` (7 ops)

| Method | Path | Tier | Public | Query params | Body fields | Async | Perm |
|---|---|---|---|---|---|---|---|
| `GET` | `/api/registries` | **read** |  |  |  |  | registries:view |
| `POST` | `/api/registries` | **excluded** |  |  | name, url, username, password, isDefault |  | registries:create |
| `GET` | `/api/registries/{id}` | **read** |  |  |  |  | registries:view |
| `PUT` | `/api/registries/{id}` | **excluded** |  |  | name, url, username, password, isDefault |  | registries:edit |
| `DELETE` | `/api/registries/{id}` | **excluded** |  |  |  |  | registries:delete |
| `POST` | `/api/registries/{id}/default` | **excluded** |  |  |  |  | settings:edit |
| `POST` | `/api/registries/test` | **excluded** |  |  | registryId, url, username, password |  | registries:view |

## `registry` (5 ops)

| Method | Path | Tier | Public | Query params | Body fields | Async | Perm |
|---|---|---|---|---|---|---|---|
| `GET` | `/api/registry/catalog` | **read** |  | registry, last |  |  | registries:view |
| `DELETE` | `/api/registry/image` | **excluded** |  | registry, image, tag |  |  | settings:edit |
| `GET` | `/api/registry/search` | **read** |  | term, limit, registry |  |  | registries:view |
| `GET` | `/api/registry/tag-info` | **read** |  | registry, image, tag |  |  | registries:view |
| `GET` | `/api/registry/tags` | **read** |  | registry, image, page, pageSize |  |  | registries:view |

## `roles` (5 ops)

| Method | Path | Tier | Public | Query params | Body fields | Async | Perm |
|---|---|---|---|---|---|---|---|
| `GET` | `/api/roles` | **excluded** |  |  |  |  |  |
| `POST` | `/api/roles` | **excluded** |  |  | name, description, permissions, environmentIds |  |  |
| `GET` | `/api/roles/{id}` | **excluded** |  |  |  |  |  |
| `PUT` | `/api/roles/{id}` | **excluded** |  |  | name, description, permissions, environmentIds |  |  |
| `DELETE` | `/api/roles/{id}` | **excluded** |  |  |  |  |  |

## `schedules` (11 ops)

| Method | Path | Tier | Public | Query params | Body fields | Async | Perm |
|---|---|---|---|---|---|---|---|
| `GET` | `/api/schedules` | **read** |  |  |  |  |  |
| `DELETE` | `/api/schedules/{type}/{id}` | **destructive** |  |  |  |  |  |
| `POST` | `/api/schedules/{type}/{id}/run` | **operator** |  |  |  |  |  |
| `POST` | `/api/schedules/{type}/{id}/toggle` | **operator** |  |  |  |  |  |
| `GET` | `/api/schedules/executions` | **read** |  | scheduleType, scheduleId, environmentId, status, statuses, triggeredBy, fromDate, toDate, limit, offset |  |  |  |
| `GET` | `/api/schedules/executions/{id}` | **read** |  |  |  |  |  |
| `DELETE` | `/api/schedules/executions/{id}` | **destructive** |  |  |  |  |  |
| `GET` | `/api/schedules/settings` | **excluded** |  |  |  |  |  |
| `PUT` | `/api/schedules/settings` | **excluded** |  |  | hideSystemJobs |  |  |
| `GET` | `/api/schedules/stream` | **excluded** |  |  |  | sse | schedules:view |
| `POST` | `/api/schedules/system/{id}/toggle` | **operator** |  |  |  |  | settings:edit |

## `secret-providers` (8 ops)

| Method | Path | Tier | Public | Query params | Body fields | Async | Perm |
|---|---|---|---|---|---|---|---|
| `GET` | `/api/secret-providers` | **excluded** |  |  |  |  | secrets:view |
| `POST` | `/api/secret-providers` | **excluded** |  |  | name, type, config |  | secrets:create |
| `GET` | `/api/secret-providers/{id}` | **excluded** |  |  |  |  | secrets:view |
| `PUT` | `/api/secret-providers/{id}` | **excluded** |  |  | name, type, config |  | secrets:edit |
| `DELETE` | `/api/secret-providers/{id}` | **excluded** |  |  |  |  | secrets:delete |
| `POST` | `/api/secret-providers/{id}/probe` | **excluded** |  |  | selector, refs |  | secrets:view |
| `POST` | `/api/secret-providers/{id}/test` | **excluded** |  |  | config |  | secrets:view |
| `POST` | `/api/secret-providers/test` | **excluded** |  |  | type, config |  | secrets:create |

## `self-update` (3 ops)

| Method | Path | Tier | Public | Query params | Body fields | Async | Perm |
|---|---|---|---|---|---|---|---|
| `POST` | `/api/self-update` | **excluded** |  |  | newImage | sse, accept-json |  |
| `GET` | `/api/self-update/check` | **excluded** |  |  |  |  |  |
| `GET` | `/api/self-update/progress` | **excluded** |  | id |  |  |  |

## `settings` (11 ops)

| Method | Path | Tier | Public | Query params | Body fields | Async | Perm |
|---|---|---|---|---|---|---|---|
| `GET` | `/api/settings/general` | **read** |  |  |  |  |  |
| `POST` | `/api/settings/general` | **excluded** |  |  | animateIcons, editorIndentGuides, coloredActionButtons, lightTheme, darkTheme, defaultTimezone, logBufferSizeKb, externalStackPaths, actionIconSize, compactPorts… |  | settings:edit |
| `GET` | `/api/settings/navigation` | **excluded** |  |  |  |  |  |
| `PUT` | `/api/settings/navigation` | **excluded** |  | scope | landingPage, envClickPage |  | settings:edit |
| `GET` | `/api/settings/scanner` | **read** |  | env, checkUpdates, settingsOnly |  |  | settings:view |
| `POST` | `/api/settings/scanner` | **admin** |  |  | scanner, grypeArgs, trivyArgs, envId, grypeImage, trivyImage |  | settings:edit |
| `DELETE` | `/api/settings/scanner` | **admin** |  | removeImages, scanner, env |  |  | settings:edit |
| `DELETE` | `/api/settings/scanner/cache` | **admin** |  |  |  |  |  |
| `GET` | `/api/settings/semver` | **read** |  |  |  |  |  |
| `POST` | `/api/settings/semver` | **admin** |  |  | enabled, maxBump, matchFlavor, includePrerelease |  | settings:edit |
| `GET` | `/api/settings/theme` | **excluded** | yes |  |  |  |  |

## `stacks` (33 ops)

| Method | Path | Tier | Public | Query params | Body fields | Async | Perm |
|---|---|---|---|---|---|---|---|
| `GET` | `/api/stacks` | **read** |  | env |  |  | stacks:view |
| `POST` | `/api/stacks` | **operator** |  | env | name, compose, composePath, envPath, envVars, rawEnvContent, secretProviderId, start, envId, environmentId… |  | secrets:view, stacks:create |
| `DELETE` | `/api/stacks/{name}` | **destructive** |  | env, force, volumes, files |  |  |  |
| `POST` | `/api/stacks/{name}/check-path-change` | **operator** |  | env | newComposePath |  | stacks:edit |
| `GET` | `/api/stacks/{name}/compose` | **read** |  | env |  |  | stacks:view |
| `PUT` | `/api/stacks/{name}/compose` | **operator** |  | env | content, composePath, envPath, oldComposePath, oldEnvPath, moveFromDir, restart, secretProviderId, pull, build… |  | secrets:view, stacks:edit |
| `GET` | `/api/stacks/{name}/delete-preview` | **read** |  | env |  |  | stacks:remove |
| `POST` | `/api/stacks/{name}/deploy` | **operator** |  | env | pull, build, forceRecreate | sse | stacks:start |
| `GET` | `/api/stacks/{name}/deploys` | **read** |  | env |  |  | stacks:view |
| `GET` | `/api/stacks/{name}/deploys/{runId}` | **read** |  |  |  |  | stacks:view |
| `DELETE` | `/api/stacks/{name}/deploys/{runId}` | **destructive** |  |  |  |  | stacks:edit |
| `GET` | `/api/stacks/{name}/deploys/{runId}/log` | **read** |  |  |  |  | stacks:view |
| `POST` | `/api/stacks/{name}/down` | **destructive** |  | env | removeVolumes | job, sse, accept-json |  |
| `GET` | `/api/stacks/{name}/env` | **read** |  | env |  |  | stacks:view |
| `PUT` | `/api/stacks/{name}/env` | **operator** |  | env | variables |  | stacks:edit |
| `GET` | `/api/stacks/{name}/env/raw` | **read** |  | env |  |  | stacks:view |
| `PUT` | `/api/stacks/{name}/env/raw` | **operator** |  | env | content |  | stacks:edit |
| `POST` | `/api/stacks/{name}/env/validate` | **read** |  | env | compose, variables |  | stacks:view |
| `GET` | `/api/stacks/{name}/icon` | **excluded** |  | env |  |  | stacks:view |
| `POST` | `/api/stacks/{name}/icon` | **excluded** |  | env | icon, image |  | stacks:edit |
| `DELETE` | `/api/stacks/{name}/icon` | **excluded** |  | env |  |  | stacks:edit |
| `POST` | `/api/stacks/{name}/relocate` | **destructive** |  | env | oldDir, newComposePath, newEnvPath |  | stacks:edit |
| `POST` | `/api/stacks/{name}/restart` | **operator** |  | env, mode |  | sse | stacks:restart |
| `POST` | `/api/stacks/{name}/start` | **operator** |  | env |  | job, sse, accept-json |  |
| `POST` | `/api/stacks/{name}/stop` | **operator** |  | env |  | job, sse, accept-json |  |
| `POST` | `/api/stacks/{name}/validate` | **read** |  | env | compose, existing, config, envVars |  |  |
| `POST` | `/api/stacks/adopt` | **operator** |  |  | stacks, environmentId |  | stacks:create |
| `GET` | `/api/stacks/base-path` | **read** |  | env |  |  |  |
| `GET` | `/api/stacks/default-path` | **read** |  | name, env, location |  |  |  |
| `GET` | `/api/stacks/path-hints` | **read** |  | name, env |  |  |  |
| `POST` | `/api/stacks/scan` | **operator** |  |  | path |  | stacks:create |
| `GET` | `/api/stacks/sources` | **read** |  | env |  |  | stacks:view |
| `POST` | `/api/stacks/validate-path` | **operator** |  |  | path |  | settings:edit |

## `system` (5 ops)

| Method | Path | Tier | Public | Query params | Body fields | Async | Perm |
|---|---|---|---|---|---|---|---|
| `GET` | `/api/system` | **read** |  | env |  |  |  |
| `GET` | `/api/system/disk` | **read** |  | env |  |  |  |
| `GET` | `/api/system/files` | **excluded** |  | path |  |  |  |
| `POST` | `/api/system/files` | **excluded** |  |  | path |  |  |
| `GET` | `/api/system/files/content` | **excluded** |  | path |  |  |  |

## `templates` (6 ops)

| Method | Path | Tier | Public | Query params | Body fields | Async | Perm |
|---|---|---|---|---|---|---|---|
| `GET` | `/api/templates` | **excluded** |  |  |  |  |  |
| `POST` | `/api/templates/compose` | **excluded** |  |  | template |  |  |
| `GET` | `/api/templates/sources` | **excluded** |  |  |  |  |  |
| `POST` | `/api/templates/sources` | **excluded** |  |  | name, url |  |  |
| `PUT` | `/api/templates/sources` | **excluded** |  |  | id, enabled, name, url |  |  |
| `DELETE` | `/api/templates/sources` | **excluded** |  | id |  |  |  |

## `users` (10 ops)

| Method | Path | Tier | Public | Query params | Body fields | Async | Perm |
|---|---|---|---|---|---|---|---|
| `GET` | `/api/users` | **excluded** |  |  |  |  |  |
| `POST` | `/api/users` | **excluded** |  |  | username, email, password, displayName |  | users:create |
| `GET` | `/api/users/{id}` | **excluded** |  |  |  |  |  |
| `PUT` | `/api/users/{id}` | **excluded** |  |  | username, email, displayName, isAdmin, isActive, password, confirmDisableAuth |  | users:edit |
| `DELETE` | `/api/users/{id}` | **excluded** |  | confirmDisableAuth |  |  | users:remove |
| `POST` | `/api/users/{id}/mfa` | **excluded** |  |  | action, token |  |  |
| `DELETE` | `/api/users/{id}/mfa` | **excluded** |  |  |  |  |  |
| `GET` | `/api/users/{id}/roles` | **excluded** |  |  |  |  |  |
| `POST` | `/api/users/{id}/roles` | **excluded** |  |  | roleId, environmentId |  |  |
| `DELETE` | `/api/users/{id}/roles` | **excluded** |  |  | roleId, environmentId |  |  |

## `volumes` (10 ops)

| Method | Path | Tier | Public | Query params | Body fields | Async | Perm |
|---|---|---|---|---|---|---|---|
| `GET` | `/api/volumes` | **read** |  | env |  |  | volumes:view |
| `POST` | `/api/volumes` | **operator** |  | env | name, driver, driverOpts, labels |  | volumes:create |
| `GET` | `/api/volumes/{name}` | **read** |  | env |  |  | volumes:inspect |
| `DELETE` | `/api/volumes/{name}` | **destructive** |  | env, force |  |  | volumes:remove |
| `GET` | `/api/volumes/{name}/browse` | **excluded** |  | env, path |  |  | volumes:inspect |
| `GET` | `/api/volumes/{name}/browse/content` | **excluded** |  | path, env |  |  | volumes:inspect |
| `POST` | `/api/volumes/{name}/browse/release` | **excluded** |  | env |  |  | volumes:inspect |
| `POST` | `/api/volumes/{name}/clone` | **operator** |  | env | name |  | volumes:create |
| `GET` | `/api/volumes/{name}/export` | **excluded** |  | env, path, format |  |  | volumes:inspect |
| `GET` | `/api/volumes/{name}/inspect` | **read** |  | env |  |  | volumes:inspect |

## `vulnerabilities` (4 ops)

| Method | Path | Tier | Public | Query params | Body fields | Async | Perm |
|---|---|---|---|---|---|---|---|
| `GET` | `/api/vulnerabilities` | **read** |  |  |  | accept-json |  |
| `GET` | `/api/vulnerabilities/count` | **read** |  |  |  |  |  |
| `GET` | `/api/vulnerabilities/export` | **read** |  | format |  |  |  |
| `POST` | `/api/vulnerabilities/scan-all` | **operator** |  | env |  | sse |  |
