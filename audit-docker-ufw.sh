#!/usr/bin/env bash
# =============================================================================
#  audit-docker-ufw.sh   |   ByteAutomate AI   |   канал: @ByteAutomate_AI
#  Аудит: какие порты Docker открыл в интернет в обход файрвола UFW.
#
#  Почему это важно: порт, опубликованный через `-p 5432:5432` или
#  `ports: ["5432:5432"]`, Docker перенаправляет правилом DNAT в таблице nat
#  (цепочка PREROUTING -> DOCKER). Пакет идёт через FORWARD и не попадает в
#  INPUT, где работает UFW. Поэтому `ufw status` может показывать порт
#  закрытым, а из интернета он доступен.
#
#  Скрипт ТОЛЬКО ЧИТАЕТ: ufw status, iptables -t nat -L DOCKER -n -v, ss -tulnp.
#  Он ничего не меняет в системе, ничего не отправляет наружу и не удаляет.
#  Команды исправления выводятся текстом: проверьте и выполните их сами.
#
#  Запуск (нужны права root для iptables и списка процессов):
#      sudo bash audit-docker-ufw.sh
#      sudo bash audit-docker-ufw.sh --no-color      # без цвета (для логов)
#  Код возврата: 0 критичных портов нет, 1 найдены критичные, 2 не хватает прав/утилит.
#
#  Ограничения: проверяется IPv4-таблица nat (iptables), IPv6 виден только в ss;
#  nftables без совместимого iptables, Podman и rootless Docker не проверялись.
#  Надёжная проверка: просканируйте сервер снаружи (с другого хоста или из сети
#  вашего провайдера), `ufw status` обход не показывает.
#  Бэкап базы по правилу 3-2-1 делайте до любых изменений. Без подписки,
#  без облачных сервисов: скрипт работает локально.
# =============================================================================

set -u
LC_ALL=C
export LC_ALL

# ---------- цвета ----------
USE_COLOR=1
for arg in "$@"; do
  case "$arg" in
    --no-color) USE_COLOR=0 ;;
    -h|--help) sed -n '2,28p' "$0"; exit 0 ;;
  esac
done
[ -n "${NO_COLOR:-}" ] && USE_COLOR=0
[ -t 1 ] || USE_COLOR=0
if [ "$USE_COLOR" -eq 1 ]; then
  RED=$'\033[1;31m'; ORANGE=$'\033[1;38;5;208m'; GREEN=$'\033[1;32m'; CYAN=$'\033[1;36m'
  DIM=$'\033[2m'; BOLD=$'\033[1m'; RST=$'\033[0m'
else
  RED=""; ORANGE=""; GREEN=""; CYAN=""; DIM=""; BOLD=""; RST=""
fi

SENSITIVE_PORTS=" 1433 2375 2376 3306 5432 5601 5984 6379 8086 9042 9200 9300 11211 15672 27017 "
CRITICAL=0
WARNINGS=0
SAFE=0

say()   { printf '%s\n' "$*"; }
head_() { printf '\n%s== %s ==%s\n' "$CYAN" "$*" "$RST"; }
CRIT_SEEN=" "
crit()  {
  # crit <порт> <текст>: один и тот же порт в nat и в ss (IPv4/IPv6) считается один раз
  local key="$1"; shift
  case "$CRIT_SEEN" in *" $key "*) ;; *) CRITICAL=$((CRITICAL+1)); CRIT_SEEN="$CRIT_SEEN$key " ;; esac
  printf '%s[CRITICAL EXPOSED]%s %s\n' "$RED" "$RST" "$*"
}
warn()  { WARNINGS=$((WARNINGS+1));  printf '%s[WARNING]%s %s\n' "$ORANGE" "$RST" "$*"; }
safe()  { SAFE=$((SAFE+1));          printf '%s[SAFE LOCAL]%s %s\n' "$GREEN" "$RST" "$*"; }
info()  { printf '%s[INFO]%s %s\n' "$DIM" "$RST" "$*"; }
fix()   { printf '    %sFIX:%s %s\n' "$BOLD" "$RST" "$*"; }

has() { command -v "$1" >/dev/null 2>&1; }

say "${BOLD}Docker + UFW аудит${RST}  ${DIM}| ByteAutomate AI | @ByteAutomate_AI | только чтение${RST}"

if [ "$(id -u)" -ne 0 ]; then
  warn "запущено без root: iptables и список процессов могут быть недоступны. Запустите: sudo bash $0"
fi
if [ "$(uname -s)" != "Linux" ]; then
  say "${RED}Скрипт рассчитан на Linux-сервер (uname: $(uname -s)).${RST}"
  exit 2
fi

# ---------- 1. UFW ----------
head_ "1. UFW (файрвол сервера)"
UFW_OUT=""
if has ufw; then
  UFW_OUT=$(ufw status 2>/dev/null || true)
  case "$UFW_OUT" in
    *"Status: active"*)   info "ufw активен. Но он НЕ видит порты, опубликованные Docker." ;;
    *"Status: inactive"*) warn "ufw установлен, но выключен. Включение (после разрешения SSH): ufw allow OpenSSH && ufw enable" ;;
    *)                    warn "статус ufw не прочитан (нужны права root?)" ;;
  esac
  if [ -n "$UFW_OUT" ]; then
    printf '%s\n' "$UFW_OUT" | sed 's/^/    /'
  fi
else
  warn "ufw не найден: файрвол вне Docker не настроен"
fi

ufw_mentions_port() {
  # $1 порт; 0, если ufw status упоминает этот порт
  [ -z "$UFW_OUT" ] && return 1
  printf '%s\n' "$UFW_OUT" | grep -Eq "(^|[^0-9])$1(/(tcp|udp))?([[:space:]]|\$)"
}

# ---------- 2. Правила Docker в таблице nat ----------
head_ "2. Порты Docker: iptables -t nat -L DOCKER -n -v"
EXT_IF=""
if has ip; then
  EXT_IF=$(ip route show default 2>/dev/null | awk '/default/ {for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}')
fi
[ -z "$EXT_IF" ] && EXT_IF="eth0"

NAT_OUT=""
if has iptables; then
  NAT_OUT=$(iptables -t nat -L DOCKER -n -v 2>/dev/null || true)
else
  warn "iptables не найден"
fi

if [ -z "$NAT_OUT" ]; then
  if has docker; then
    info "цепочка DOCKER пуста или недоступна (нет опубликованных портов или не хватает прав root)"
  else
    info "Docker не найден, цепочки DOCKER нет"
  fi
else
  RULES=$(printf '%s\n' "$NAT_OUT" | awk '
    $3=="DNAT" {
      proto=$4; src=$8; dst=$9; port=""; to=""
      for (i=10; i<=NF; i++) {
        if ($i ~ /^dpt:/)  port=substr($i,5)
        else if ($i ~ /^dpts:/) port=substr($i,6)
        else if ($i ~ /^to:/)   to=substr($i,4)
      }
      print proto "|" src "|" dst "|" port "|" to
    }')
  if [ -z "$RULES" ]; then
    info "правил DNAT нет: Docker не публикует порты"
  else
    while IFS='|' read -r proto src dst port to; do
      [ -z "$port" ] && continue
      case "$dst" in
        0.0.0.0/0)
          if [[ "$SENSITIVE_PORTS" == *" $port "* ]]; then
            crit "$port" "$proto/$port -> $to  (привязан к 0.0.0.0, это БД или админ-порт, доступен из интернета)"
          elif [ "$port" = "80" ] || [ "$port" = "443" ]; then
            warn "$proto/$port -> $to  (веб на 0.0.0.0: Docker обходит UFW; для сайта лучше Cloudflare Tunnel без открытых 80/443)"
          else
            crit "$port" "$proto/$port -> $to  (привязан к 0.0.0.0, доступен из интернета в обход UFW)"
          fi
          if ufw_mentions_port "$port"; then
            info "    UFW упоминает порт $port: проверьте, что открытие намеренное"
          else
            info "    UFW про порт $port молчит, а он открыт: обход подтверждён"
          fi
          case "$port" in
            *:*) fix "диапазон портов: привяжите каждый порт из диапазона к 127.0.0.1 в compose или закройте диапазон в цепочке DOCKER-USER" ;;
            *)
              fix "docker run: -p 127.0.0.1:$port:$port   |   compose: ports: [\"127.0.0.1:$port:$port\"]"
              fix "срочно, не трогая контейнер: iptables -I DOCKER-USER -i $EXT_IF -p $proto -m conntrack --ctorigdstport $port --ctdir ORIGINAL -j DROP"
              ;;
          esac
          ;;
        127.*)
          safe "$proto/$port -> $to  (привязан к $dst, доступен только самому серверу)"
          ;;
        *)
          info "$proto/$port -> $to  (привязан к адресу $dst; источник: $src)"
          ;;
      esac
    done <<EOF
$RULES
EOF
  fi
fi

# ---------- 3. Слушающие сокеты ----------
head_ "3. Слушающие порты: ss -tulnp"
if has ss; then
  SS_OUT=$(ss -tulnp 2>/dev/null | awk 'NR>1 {proc=""; for(i=7;i<=NF;i++) proc=proc $i " "; print $1 "|" $5 "|" proc}')
  if [ -z "$SS_OUT" ]; then
    info "ss ничего не показал (нужны права root?)"
  else
    while IFS='|' read -r netid local proc; do
      [ -z "$local" ] && continue
      addr="${local%:*}"; port="${local##*:}"
      pname=$(printf '%s' "$proc" | sed -n 's/.*users:(("\([^"]*\)".*/\1/p')
      [ -z "$pname" ] && pname="?"
      case "$addr" in
        127.*|"[::1]"|"::1")
          safe "$netid $local  ($pname): только локально" ;;
        *)
          if [[ "$SENSITIVE_PORTS" == *" $port "* ]]; then
            crit "$port" "$netid $local  ($pname): чувствительный порт слушает все адреса"
            fix "ограничьте слушающий адрес в настройках сервиса или опубликуйте порт Docker как 127.0.0.1:$port:$port"
          elif [ "$pname" = "docker-proxy" ]; then
            warn "$netid $local  (docker-proxy): порт опубликован Docker на всех адресах"
          else
            info "$netid $local  ($pname): публичный сокет, проверьте, что он нужен"
          fi ;;
      esac
    done <<EOF
$SS_OUT
EOF
  fi
else
  warn "ss не найден (пакет iproute2)"
fi

# ---------- 4. Итог ----------
head_ "4. Итог"
say "критичных: ${CRITICAL}   предупреждений: ${WARNINGS}   безопасных локальных: ${SAFE}"
if [ "$CRITICAL" -gt 0 ]; then
  say "${RED}Есть порты, открытые в интернет в обход UFW.${RST}"
  say "  1) Сначала бэкап базы по правилу 3-2-1 (копия на внешний диск, оригиналы не удалять, пока копия не проверена)."
  say "  2) Привяжите порт к 127.0.0.1 или уберите ports: у сервиса БД; сеть базы пометьте internal: true."
  say "  3) Правила iptables не переживают перезагрузку: сохраняйте их (netfilter-persistent) или исправляйте compose."
  say "  4) Проверьте снаружи: nmap -Pn -p <порт> <адрес сервера> с другого хоста."
  say "  5) Если порт был открыт долго, смените пароли и проверьте логи БД на чужие подключения."
  exit 1
fi
say "${GREEN}Критичных открытых портов не найдено.${RST} Проверьте результат снаружи (nmap с другого хоста): аудит видит только локальные правила."
exit 0
