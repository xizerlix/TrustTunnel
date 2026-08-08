#!/bin/bash

# --- НАСТРОЙКИ ---
TOKEN=""
MY_CHAT_ID=""
IP_SERVER=""
TIME_DIR="/tmp/vpn_times"
METRICS_URL="http://127.0.0.1:1987/clients"
ACTIVE_VPN_STATE="$TIME_DIR/active_vpn.json"
# -----------------

LAST_UPDATE_ID=0

mkdir -p "$TIME_DIR"

format_time() {
    local sec=$1
    printf '%dh %dm %ds' $((sec / 3600)) $((sec % 3600 / 60)) $((sec % 60))
}

fetch_clients_json() {
    curl -s --connect-timeout 3 "$METRICS_URL"
}

clients_json_valid() {
    local json="$1"
    [[ -n "$json" ]] && echo "$json" | jq -e 'type == "array"' >/dev/null 2>&1
}

# Текущие пары username|ip для активных VPN-туннелей (из /clients).
build_vpn_key_map() {
    local json="$1"
    echo "$json" | jq -c '
        [.[] | select(.sessions > 0) | .username as $u | (.ips // [])[] | .address |
            select(. != null and . != "") | "\($u)|\(.)"] | unique | map({(.): true}) | add // {}
    '
}

# Сводка: уникальные IP, сумма сессий, юзеры с активными туннелями.
clients_totals_line() {
    local json="$1"
    echo "$json" | jq -r '
        ([.[] | (.ips // [])[] | .address] | unique | length) as $ips |
        ([.[] | .sessions] | add // 0) as $sess |
        ([.[] | select(.sessions > 0)] | length) as $users |
        "VPN: \($ips) IP · \($sess) сесс. · \($users) юз."
    '
}

get_lsof_tcp_ips() {
    local pid
    pid=$(pgrep -x trusttunnel_endpoint 2>/dev/null | head -n 1)
    [[ -z "$pid" ]] && pid=$(pgrep -x trusttunnel_end 2>/dev/null | head -n 1)
    [[ -z "$pid" ]] && return 0
    lsof -p "$pid" -i -n 2>/dev/null |
        grep "$IP_SERVER:https" |
        awk '{print $9}' | cut -d'>' -f2 | cut -d':' -f1 | sort -u
}

format_geo_block() {
    local ip="$1"
    local prefix="$2"
    local ip_info geo_status ip_tag country city isp org as_info mob proxy hosting tags block=""

    ip_info=$(curl -s --connect-timeout 3 "http://ip-api.com/json/$ip?fields=status,country,city,isp,org,as,mobile,proxy,hosting")
    geo_status=$(echo "$ip_info" | jq -r '.status // empty')
    ip_tag="#ip_${ip//./_}"

    if [[ "$geo_status" == "success" ]]; then
        country=$(echo "$ip_info" | jq -r '.country')
        city=$(echo "$ip_info" | jq -r '.city')
        isp=$(echo "$ip_info" | jq -r '.isp')
        org=$(echo "$ip_info" | jq -r '.org // empty')
        as_info=$(echo "$ip_info" | jq -r '.as')
        mob=$(echo "$ip_info" | jq -r '.mobile')
        proxy=$(echo "$ip_info" | jq -r '.proxy')
        hosting=$(echo "$ip_info" | jq -r '.hosting')
        tags=""
        [[ "$mob" == "true" ]] && tags+=" 📱"
        [[ "$proxy" == "true" ]] && tags+=" 🛡️"
        [[ "$hosting" == "true" ]] && tags+=" ☁️"
        block+="${prefix}%0A🌐 \`$ip\`$tags%0A🆔 $ip_tag%0A📍 $country, $city"
        [[ -n "$org" && "$org" != "null" && "$org" != "$isp" ]] && block+="%0A🏢 $org"
        block+="%0A📡 $isp ($as_info)"
    else
        block+="${prefix}%0A🌐 \`$ip\`%0A🆔 $ip_tag%0A⚠️ GeoIP недоступен."
    fi
    echo -n "$block"
}

send_message() {
    local chat_id="$1"
    local text="$2"
    local decoded payload
    decoded="${text//%0A/$'\n'}"
    payload=$(jq -n \
        --arg chat_id "$chat_id" \
        --arg text "$decoded" \
        '{chat_id: $chat_id, text: $text, parse_mode: "Markdown", disable_web_page_preview: true}')
    curl -s -X POST "https://api.telegram.org/bot$TOKEN/sendMessage" \
        -H "Content-Type: application/json" \
        -d "$payload" >/dev/null
}

format_traffic_clients() {
    local json="$1"
    local count totals
    count=$(echo "$json" | jq 'length')
    if [[ "$count" -eq 0 ]]; then
        echo "ℹ️ Нет данных о клиентах."
        return
    fi

    totals=$(clients_totals_line "$json")
    local TEXT="📶 *Трафик по клиентам VPN*%0A${totals}%0A(сесс. = активные VPN-туннели, не TCP-сокеты)"

    while IFS= read -r block; do
        [[ -n "$block" ]] && TEXT+="%0A%0A$block"
    done < <(echo "$json" | jq -r '.[] |
        (if .quota_exceeded then "⛔" else "✅" end) as $icon |
        (if .limit != null and .limit > 0
            then ((.total * 100 / .limit) | floor | tostring) + "%"
            else "—" end) as $pct |
        (if .inbound >= 1073741824 then ((.inbound / 1073741824 * 100 | round) / 100 | tostring) + " GiB"
            elif .inbound >= 1048576 then ((.inbound / 1048576 * 10 | round) / 10 | tostring) + " MiB"
            elif .inbound >= 1024 then ((.inbound / 1024 * 10 | round) / 10 | tostring) + " KiB"
            else (.inbound | tostring) + " B" end) as $down |
        (if .outbound >= 1073741824 then ((.outbound / 1073741824 * 100 | round) / 100 | tostring) + " GiB"
            elif .outbound >= 1048576 then ((.outbound / 1048576 * 10 | round) / 10 | tostring) + " MiB"
            elif .outbound >= 1024 then ((.outbound / 1024 * 10 | round) / 10 | tostring) + " KiB"
            else (.outbound | tostring) + " B" end) as $up |
        (if .total >= 1073741824 then ((.total / 1073741824 * 100 | round) / 100 | tostring) + " GiB"
            elif .total >= 1048576 then ((.total / 1048576 * 10 | round) / 10 | tostring) + " MiB"
            elif .total >= 1024 then ((.total / 1024 * 10 | round) / 10 | tostring) + " KiB"
            else (.total | tostring) + " B" end) as $sum |
        (if .limit != null
            then (if .limit >= 1073741824 then ((.limit / 1073741824 * 100 | round) / 100 | tostring) + " GiB"
                  elif .limit >= 1048576 then ((.limit / 1048576 * 10 | round) / 10 | tostring) + " MiB"
                  else (.limit | tostring) + " B" end)
            else "∞" end) as $lim |
        $icon + " *" + .username + "* — " + (.sessions | tostring) + " сесс." +
        (if (.ips | length) > 0
            then (.ips | map("%0A   🌐 `" + .address + "`%0A   🆔 " + .tag) | join(""))
            else "" end) +
        "%0A   ⬇️ " + $down + "  ⬆️ " + $up +
        "%0A   Σ *" + $sum + "* / " + $lim +
        (if .limit != null then " (" + $pct + ")" else "" end)
    ')

    echo "$TEXT"
}

build_status_text() {
    local clients_json="$1"
    local TEXT="" NOW tcp_ips=() tcp_count vpn_line

    NOW=$(date +%s)
    while IFS= read -r ip; do
        [[ -n "$ip" ]] && tcp_ips+=("$ip")
    done < <(get_lsof_tcp_ips)
    tcp_count=${#tcp_ips[@]}

    if ! clients_json_valid "$clients_json"; then
        TEXT="⚠️ /clients недоступен.%0A%0AПроверьте \`[metrics]\` в vpn.toml и custom-сборку TrustTunnel."
        if [[ "$tcp_count" -gt 0 ]]; then
            TEXT+="%0A%0ATCP-сокетов (lsof): $tcp_count"
        fi
        echo "$TEXT"
        return
    fi

    vpn_line=$(clients_totals_line "$clients_json")
    TEXT="📊 *Текущие подключения*%0A*${vpn_line}*%0ATCP-сокетов (lsof): $tcp_count"

    local grouped
    grouped=$(echo "$clients_json" | jq -c '
        [.[] | select(.sessions > 0 and (.ips | length) > 0) |
            .username as $u | .sessions as $s | .ips[] |
            {ip: .address, tag: .tag, user: $u, sessions: $s}] |
        group_by(.ip) |
        map({ip: .[0].ip, tag: .[0].tag,
             users: (map({user: .user, sessions: .sessions}) | unique_by(.user))})
    ')

    local group_count
    group_count=$(echo "$grouped" | jq 'length')

    if [[ "$group_count" -eq 0 ]]; then
        TEXT+="%0A%0Aℹ️ Активных VPN-туннелей нет."
    else
        TEXT+="%0A%0A*—— VPN-туннели ——*"
        local i ip tag users_line start dur
        for ((i = 0; i < group_count; i++)); do
            ip=$(echo "$grouped" | jq -r ".[$i].ip")
            tag=$(echo "$grouped" | jq -r ".[$i].tag")
            users_line=$(echo "$grouped" | jq -r ".[$i].users | map(\"\(.user) (\(.sessions) сесс.)\") | join(\", \")")
            start=$(jq -r --arg ip "$ip" '
                [to_entries[] | select(.key | endswith("|" + $ip)) | .value] | min // empty
            ' "$ACTIVE_VPN_STATE" 2>/dev/null)
            [[ -z "$start" || "$start" == "null" ]] && start=$NOW
            dur=$(format_time $((NOW - start)))
            TEXT+="%0A%0A🌐 \`$ip\` — *$dur*%0A🆔 \`$tag\`%0A👤 $users_line"
        done
    fi

    local vpn_ips unmapped=""
    vpn_ips=$(echo "$clients_json" | jq -r '[.[] | (.ips // [])[] | .address] | unique | .[]')
    local ip
    for ip in "${tcp_ips[@]}"; do
        [[ -z "$ip" ]] && continue
        if ! echo "$vpn_ips" | grep -qx "$ip"; then
            unmapped+="$ip"$'\n'
        fi
    done

    if [[ -n "$unmapped" ]]; then
        TEXT+="%0A%0A*—— TCP без VPN ——*"
        TEXT+="%0A(handshake / idle / не авторизован)"
        while IFS= read -r ip; do
            [[ -z "$ip" ]] && continue
            TEXT+=$(format_geo_block "$ip" "%0A")
        done <<< "$unmapped"
    fi

    echo "$TEXT"
}

# Уведомления о новых VPN-подключениях (username + IP из /clients).
monitor_vpn_connections() {
    [[ -z "$MY_CHAT_ID" || -z "$TOKEN" ]] && return 0

    local clients_json current_map prev_map now key user ip start dur text

    clients_json=$(fetch_clients_json)
    if ! clients_json_valid "$clients_json"; then
        return 0
    fi

    now=$(date +%s)
    current_map=$(build_vpn_key_map "$clients_json")

    if [[ ! -f "$ACTIVE_VPN_STATE" ]]; then
        jq -n --argjson now "$now" --argjson keys "$current_map" '
            ($keys | keys) | map({key: ., value: $now}) | from_entries
        ' >"$ACTIVE_VPN_STATE"
        return 0
    fi

    prev_map=$(cat "$ACTIVE_VPN_STATE" 2>/dev/null || echo '{}')
    if ! echo "$prev_map" | jq -e 'type == "object"' >/dev/null 2>&1; then
        prev_map='{}'
    fi

    while IFS= read -r key; do
        [[ -z "$key" ]] && continue
        if ! echo "$prev_map" | jq -e --arg k "$key" 'has($k)' >/dev/null; then
            user="${key%%|*}"
            ip="${key#*|}"
            text="🔔 *Новый VPN-туннель*%0A👤 *${user}*%0A🌐 \`${ip}\`%0A🆔 #ip_${ip//./_}"
            send_message "$MY_CHAT_ID" "$text"
        fi
    done < <(echo "$current_map" | jq -r 'keys[]')

    jq -n --argjson prev "$prev_map" --argjson cur "$current_map" --argjson now "$now" '
        ($cur | keys) as $keys |
        [$keys[] | . as $k | {key: $k, value: ($prev[$k] // $now)}] | from_entries
    ' >"$ACTIVE_VPN_STATE"
}

while true; do
    RESPONSE=$(curl -s "https://api.telegram.org/bot$TOKEN/getUpdates?offset=$((LAST_UPDATE_ID + 1))&timeout=30")
    UPDATE_ID=$(echo "$RESPONSE" | jq -r '.result[0].update_id // empty')

    if [[ -n "$UPDATE_ID" ]]; then
        LAST_UPDATE_ID=$UPDATE_ID
        MESSAGE=$(echo "$RESPONSE" | jq -r '.result[0].message.text // empty')
        CHAT_ID=$(echo "$RESPONSE" | jq -r '.result[0].message.chat.id // empty')

        if [[ "$CHAT_ID" == "$MY_CHAT_ID" ]]; then
            TEXT=""

            if [[ "$MESSAGE" == "/status" ]]; then
                CLIENTS_JSON=$(fetch_clients_json)
                TEXT=$(build_status_text "$CLIENTS_JSON")
                send_message "$CHAT_ID" "$TEXT"

            elif [[ "$MESSAGE" == "/traffic" || "$MESSAGE" =~ ^/traffic[[:space:]] ]]; then
                FILTER_USER=""
                if [[ "$MESSAGE" =~ ^/traffic[[:space:]]+(.+)$ ]]; then
                    FILTER_USER="${BASH_REMATCH[1]}"
                fi

                CLIENTS_JSON=$(fetch_clients_json)
                if [[ -z "$CLIENTS_JSON" || "$CLIENTS_JSON" == "[]" ]]; then
                    TEXT="⚠️ Нет данных.%0A%0AПроверьте:%0A• \`[metrics]\` в vpn.toml%0A• endpoint запущен%0A• собрана версия с /clients"
                elif ! clients_json_valid "$CLIENTS_JSON"; then
                    TEXT="⚠️ /clients вернул неожиданный ответ.%0AУстановлена ли новая версия TrustTunnel?"
                else
                    if [[ -n "$FILTER_USER" ]]; then
                        CLIENTS_JSON=$(echo "$CLIENTS_JSON" | jq --arg u "$FILTER_USER" '[.[] | select(.username == $u)]')
                        if [[ $(echo "$CLIENTS_JSON" | jq 'length') -eq 0 ]]; then
                            TEXT="⚠️ Пользователь \`$FILTER_USER\` не найден."
                        else
                            TEXT=$(format_traffic_clients "$CLIENTS_JSON")
                        fi
                    else
                        TEXT=$(format_traffic_clients "$CLIENTS_JSON")
                    fi
                fi
                send_message "$CHAT_ID" "$TEXT"

            elif [[ "$MESSAGE" == "/top" ]]; then
                TT_VER=$(/opt/trusttunnel/trusttunnel_endpoint --version 2>/dev/null | xargs)
                [ -z "$TT_VER" ] && TT_VER="неизвестно"
                LATEST_VER=$(curl -s https://api.github.com/repos/TrustTunnel/TrustTunnel/releases/latest | jq -r '.tag_name // empty' | sed 's/^v//')
                VER_DISPLAY="*$TT_VER*"
                [[ -n "$LATEST_VER" && "$TT_VER" != "$LATEST_VER" && "$TT_VER" != "неизвестно" ]] && VER_DISPLAY="*$TT_VER* ⚠️ (Доступна: $LATEST_VER)"

                CPU=$(top -bn1 | grep "Cpu(s)" | awk '{print $2 + $4}')
                RAM=$(free -m | awk '/Mem:/ { printf("%.2f%% (%d/%d MB)", $3/$2*100, $3, $2) }')
                DISK=$(df -h / | awk '/\// {print $5}' | tail -n 1)
                UPTIME=$(uptime -p)
                CERT_DATA=$(certbot certificates 2>/dev/null | grep -E "Certificate Name:|Expiry Date:" | sed 's/^[[:space:]]*//')

                TEXT="🖥 **Статус сервера:**%0A🛡 TrustTunnel: $VER_DISPLAY%0A🔥 CPU: *$CPU%*%0A📟 RAM: *$RAM*%0A💾 Диск: *$DISK*%0A⏱ Uptime: *$UPTIME*%0A%0A🔐 **Сертификаты:**%0A"
                if [[ -z "$CERT_DATA" ]]; then TEXT+="⚠️ Данные не найдены"; else
                    FORMATTED_CERTS=$(echo "$CERT_DATA" | sed ':a;N;$!ba;s/\n/%0A/g')
                    TEXT+="\`\`\`%0A$FORMATTED_CERTS%0A\`\`\`"; fi
                send_message "$CHAT_ID" "$TEXT"

            elif [[ "$MESSAGE" == "/net" ]]; then
                R1=$(awk '{if(NR>2) s+=$2} END {print s}' /proc/net/dev); T1=$(awk '{if(NR>2) s+=$10} END {print s}' /proc/net/dev)
                sleep 1
                R2=$(awk '{if(NR>2) s+=$2} END {print s}' /proc/net/dev); T2=$(awk '{if(NR>2) s+=$10} END {print s}' /proc/net/dev)
                RXKB=$(( (R2 - R1) / 1024 )); TXKB=$(( (T2 - T1) / 1024 ))
                TRAFFIC=$(awk '{if(NR>2) {r+=$2; t+=$10}} END {printf "%.2f|%.2f|%.2f", r/1073741824, t/1073741824, (r+t)/1073741824}' /proc/net/dev)
                RX_TOTAL=$(echo "$TRAFFIC" | cut -d'|' -f1); TX_TOTAL=$(echo "$TRAFFIC" | cut -d'|' -f2); SUM_TOTAL=$(echo "$TRAFFIC" | cut -d'|' -f3)

                TEXT="📊 **Сеть:**%0AСкорость: ⬇️ $RXKB KB/s | ⬆️ $TXKB KB/s%0AТрафик: ⬇️ $RX_TOTAL GB | ⬆️ $TX_TOTAL GB%0AВсего: *$SUM_TOTAL GB*"
                send_message "$CHAT_ID" "$TEXT"

            elif [[ "$MESSAGE" == "/update" ]]; then
                CURRENT_VER=$(/opt/trusttunnel/trusttunnel_endpoint --version 2>/dev/null | xargs)
                LATEST_TAG=$(curl -s https://api.github.com/repos/TrustTunnel/TrustTunnel/releases/latest | jq -r '.tag_name // empty')
                LATEST_VER=$(echo "$LATEST_TAG" | sed 's/^v//')
                LOG_FILE="/tmp/tt_update.log"
                TIMESTAMP=$(date "+[%Y-%m-%d %H:%M:%S]")

                if [[ -z "$LATEST_TAG" ]]; then
                    TEXT="❌ Не удалось проверить обновления на GitHub."
                elif [[ "$CURRENT_VER" == "$LATEST_VER" ]]; then
                    TEXT="✅ У вас уже последняя версия (*$CURRENT_VER*)."
                else
                    send_message "$CHAT_ID" "🚀 Обновление *$CURRENT_VER* -> *$LATEST_VER*..."

                    echo "$TIMESTAMP --- Начало обновления с $CURRENT_VER до $LATEST_VER ---" >>"$LOG_FILE"

                    sudo systemctl stop trusttunnel
                    ARCH_NAME="trusttunnel-${LATEST_TAG}-linux-x86_64"
                    ARCHIVE="/tmp/${ARCH_NAME}.tar.gz"

                    if curl -L -o "$ARCHIVE" "https://github.com/TrustTunnel/TrustTunnel/releases/download/${LATEST_TAG}/${ARCH_NAME}.tar.gz" >>"$LOG_FILE" 2>&1; then
                        if tar -xzf "$ARCHIVE" -C /opt/trusttunnel --strip-components=1 "${ARCH_NAME}/trusttunnel_endpoint" >>"$LOG_FILE" 2>&1; then
                            chmod +x /opt/trusttunnel/trusttunnel_endpoint
                            sudo systemctl start trusttunnel
                            TEXT="✅ *Обновление до $LATEST_VER завершено!*"
                            echo "$(date "+[%Y-%m-%d %H:%M:%S]") Успешно обновлено до $LATEST_VER" >>"$LOG_FILE"
                        else
                            sudo systemctl start trusttunnel
                            TEXT="❌ Ошибка при распаковке. Откат к старой версии."
                            echo "$(date "+[%Y-%m-%d %H:%M:%S]") ОШИБКА: Распаковка не удалась" >>"$LOG_FILE"
                        fi
                    else
                        sudo systemctl start trusttunnel
                        TEXT="❌ Ошибка при скачивании файла."
                        echo "$(date "+[%Y-%m-%d %H:%M:%S]") ОШИБКА: Скачивание не удалось" >>"$LOG_FILE"
                    fi

                    rm -f "$ARCHIVE"
                    if [[ -f "$LOG_FILE" ]]; then
                        echo "$(tail -n 50 "$LOG_FILE")" >"$LOG_FILE"
                    fi
                fi
                send_message "$CHAT_ID" "$TEXT"
            fi
        fi
    fi

    monitor_vpn_connections
done
