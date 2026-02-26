#!/usr/bin/env bash
set -euo pipefail

# 本地测试 ipban 插件
# 用法: ./testdata/test.sh
#
# 前置条件: xcaddy build --with github.com/ysicing/caddy2-ipban=.
#   或: task build

CADDY=${CADDY:-./caddy}
BASE="http://127.0.0.1:8080"
# 伪造公网 IP（通过 X-Forwarded-For，Caddyfile 已配 trusted_proxies）
XFF="-H X-Forwarded-For:203.0.113.1"

if [[ ! -x "$CADDY" ]]; then
    echo "未找到 caddy 二进制，先构建:"
    echo "  task build"
    exit 1
fi

# 启动 caddy
echo "==> 启动 caddy..."
$CADDY run --config testdata/Caddyfile --adapter caddyfile &
CADDY_PID=$!
trap 'kill $CADDY_PID 2>/dev/null; wait $CADDY_PID 2>/dev/null' EXIT
sleep 2

pass=0
fail=0

check() {
    local desc="$1" url="$2" expect="$3"
    shift 3
    code=$(curl -s -o /dev/null -w '%{http_code}' "$@" "$url")
    if [[ "$code" == "$expect" ]]; then
        echo "  PASS: $desc (got $code)"
        ((pass++))
    else
        echo "  FAIL: $desc (expected $expect, got $code)"
        ((fail++))
    fi
}

echo ""
echo "==> 正常请求（应放行）"
check "GET /"           "$BASE/"           200 $XFF
check "GET /index.html" "$BASE/index.html" 200 $XFF

echo ""
echo "==> 恶意路径（首次触发封禁，返回 451）"
check "GET /.env"          "$BASE/.env"          451 $XFF
check "GET /.git/config"   "$BASE/.git/config"   451 $XFF

echo ""
echo "==> 已封禁 IP 访问正常路径（应拦截）"
check "banned IP normal path" "$BASE/index.html" 451 $XFF

echo ""
echo "==> 不同 IP 访问恶意路径"
XFF2="-H X-Forwarded-For:198.51.100.1"
check "GET /wp-login.php"    "$BASE/wp-login.php"    451 $XFF2
check "GET /phpmyadmin"      "$BASE/phpmyadmin"      451 $XFF2
check "GET /actuator/health" "$BASE/actuator/health" 451 $XFF2

echo ""
echo "==> 恶意 UA"
XFF3="-H X-Forwarded-For:198.51.100.2"
check "sqlmap UA"  "$BASE/anything" 451 $XFF3 -A "sqlmap/1.0"
check "nikto UA"   "$BASE/anything" 451 $XFF3 -A "nikto/2.1"

echo ""
echo "==> 无 XFF 的本地请求（私有 IP，应放行）"
check "local /.env" "$BASE/.env" 200

echo ""
echo "==> 结果: $pass passed, $fail failed"
[[ $fail -eq 0 ]] && echo "ALL PASSED" || exit 1
