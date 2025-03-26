#!/bin/sh

set -ex
GOOS=js GOARCH=wasm go build -o ./web/main.wasm main.go
# cp "$(go env GOROOT)/misc/wasm/wasm_exec.js" .
echo 'window.WASM_CODE = ' > ./web/main.js
cat ./web/main.wasm | base64 | sed -E 's/^/"/g; s/$/" + /g' >> ./web/main.js
echo '"";' >> ./web/main.js

