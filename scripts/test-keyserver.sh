#!/bin/bash
# 試験用の鍵サーバー（Hockeypuck と PostgreSQL）を Podman で動かす。localhost:11371 だけで受け付け、外には出さない。
# 本物の鍵サーバーに送らずに、送る・取ってくる・探すを確かめるためのもの。中身はコンテナを消すと消える。
# 使い方:
#   CONTAINER_CONNECTION=<podman の接続名> scripts/test-keyserver.sh up    # 起動（hkp://127.0.0.1:11371）
#   CONTAINER_CONNECTION=<podman の接続名> scripts/test-keyserver.sh down  # 止めて消す
# dirmngr は hkp://localhost を「URI の構文エラー」で断る（::1 を引くため）ので、127.0.0.1 で指す。
# 指すときは 127.0.0.1 で（dirmngr は hkp://localhost:11371 を「Syntax error in URI」で断る）。
# 試験: AMONHEN_TEST_KEYSERVER=hkp://127.0.0.1:11371 cargo test --workspace -- --ignored test_keyserver
set -eu
POD=amonhen-keyserver
# Docker Hub にはもうない。latest は開発版なので、出ている版に留める
HOCKEYPUCK=ghcr.io/hockeypuck/hockeypuck:2.4.1
POSTGRES=docker.io/library/postgres:16-alpine

case "${1:-}" in
up)
  # 設定はコンテナに置く（podman machine の中から macOS のファイルを読ませない）
  conf=$(cat <<'EOF'
[hockeypuck]
loglevel="INFO"
indexTemplate="/hockeypuck/lib/templates/index.html.tmpl"
vindexTemplate="/hockeypuck/lib/templates/index.html.tmpl"
statsTemplate="/hockeypuck/lib/templates/stats.html.tmpl"
responseTemplate="/hockeypuck/lib/templates/response.html.tmpl"
webroot="/hockeypuck/lib/www"

[hockeypuck.hkp]
bind=":11371"

# 標準の場所だと、初めての起動で鍵のダンプを読み込もうとして止まる
[hockeypuck.conflux.recon.leveldb]
path="/hockeypuck/data/ptree-local"

[hockeypuck.openpgp.db]
driver="postgres-jsonb"
dsn="database=hkp host=localhost user=hkp password=hkp port=5432 sslmode=disable"
EOF
)
  # 前に途中で止まって残った Pod は消してから作る
  podman pod rm -f "$POD" >/dev/null 2>&1 || true
  podman pod create --name "$POD" -p 127.0.0.1:11371:11371 >/dev/null
  podman run -d --pod "$POD" --name "$POD-db" \
    -e POSTGRES_USER=hkp -e POSTGRES_PASSWORD=hkp -e POSTGRES_DB=hkp "$POSTGRES" >/dev/null
  until podman exec "$POD-db" pg_isready -U hkp -d hkp >/dev/null 2>&1; do sleep 1; done
  podman create --pod "$POD" --name "$POD-hkp" "$HOCKEYPUCK" >/dev/null
  printf '%s\n' "$conf" > "${TMPDIR:-/tmp}/amonhen-hockeypuck.conf"
  podman cp "${TMPDIR:-/tmp}/amonhen-hockeypuck.conf" "$POD-hkp:/hockeypuck/etc/hockeypuck.conf"
  rm -f "${TMPDIR:-/tmp}/amonhen-hockeypuck.conf"
  podman start "$POD-hkp" >/dev/null
  for _ in $(seq 60); do
    if curl -fsS -o /dev/null "http://127.0.0.1:11371/pks/lookup?op=stats"; then
      echo "hkp://127.0.0.1:11371"
      exit 0
    fi
    sleep 1
  done
  podman logs "$POD-hkp" >&2
  exit 1
  ;;
down)
  podman pod rm -f "$POD" >/dev/null
  ;;
*)
  echo "usage: $0 up|down" >&2
  exit 2
  ;;
esac
