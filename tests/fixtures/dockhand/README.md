# DockHand response fixtures

Every file here is **invented**, not recorded. Bodies follow the DockHand 1.0.46 OpenAPI 200
schemas and, where the spec has none or disagrees with the live server, the key names live
DockHand answers with (observed read-only in S2; no values were copied). Each file's `_comment`
says which applies; the response body is under `body`.

`{{NAME}}` placeholders (container, image and network ids, digests, fake secrets) are filled in at
load time by `tests/conftest.py::load_fixture`, so no committed file holds a 64-hex id or a
secret-shaped value. Host `dockhand.example.test`, environment id `7`.
