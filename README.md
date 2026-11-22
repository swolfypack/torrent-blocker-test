<div align="center">

# 🛡️ TorrentGuard v1.1.0

**Лёгкая и обратимая сигнатурная блокировка типичного BitTorrent-трафика на VPN/VPS**

`Ubuntu / Debian` · `iptables / ip6tables` · `Docker` · `Xray / Remnawave` · `systemd`

</div>

> [!IMPORTANT]
> **Не обещает полного запрета торрентов или защиты от жалоб хостингу.** MSE/PE, uTP на произвольных UDP-портах, HTTPS-трекеры, сегментированные TCP-потоки, нестандартные клиенты и вложенные VPN-туннели могут обойти фильтрацию. Для более серьёзной защиты потребуются настройки Xray и/или отдельный DPI — после нагрузочных тестов.

## Что делает

- Блокирует **исходящие** TCP и UDP соединения к `6881–6889`, `51413`, `6969`. Это эвристика по портам, а не определение протокола: возможны ложные срабатывания на других приложениях.
- Находит открытые **UDP DHT** запросы: `find_node`, `get_peers`, `announce_peer`.
- Находит открытый **BEP 3 TCP handshake**: байт `0x13` + `BitTorrent protocol`, включая нестандартные TCP-порты, если сигнатура полностью находится в одном доступном пакете.
- Находит открытый **UDP-tracker connect** по 8-байтовой константе `0x0000041727101980` (BEP 15), если она видима.
- Использует `xt_string --algo kmp`, рекомендуемый для security-фильтрации вместо `bm`.
- Поддерживает `OUTPUT` для процессов на VPS (в том числе Xray в `network_mode: host`), `FORWARD` для маршрутизируемого трафика и `DOCKER-USER` для контейнеров на Docker iptables-backend.
- Добавляет отдельные правила IPv4/IPv6, учитывает разные внешние интерфейсы.
- Переключает **две версии управляемых цепочек** без предварительного опустошения активной цепочки. Если создание новых правил упало, старые привязки остаются активными.
- Позволяет просмотреть счётчики, включить ограниченное логирование и выполнить откат без глобального `iptables -F`.
- Поддерживает миграцию с первой версии проекта (`TG_EGRESS`, `TG_DROP` и т. д.).

> [!NOTE]
> Применение поочерёдно к IPv4 и IPv6 и переключение нескольких hook-ов **не являются единой атомарной транзакцией**. На короткое время во время обновления могут действовать и старые, и новые правила. Фильтр не исправляет firewall-конфликты, уже существующие в системе.

## Установка и удаление

> [!IMPORTANT]
> Команды рассчитаны на **Ubuntu/Debian с systemd** и репозиторий `swolfypack/torrent-blocker-test`, где `config/`, `scripts/`, `systemd/` и другие файлы находятся в корне репозитория. Для изменения firewall нужны root-права. Перед установкой на удалённый VPS рекомендуется иметь доступ к консоли хостера.
>
> При выполнении `curl | sudo bash` вы запускаете код из GitHub с правами root. Для более безопасного варианта сначала скачайте и проверьте `install.sh`, затем запустите его отдельно.

### 1. Установка одной командой через curl

Если `curl` ещё не установлен:

```bash
sudo apt update && sudo apt install -y curl ca-certificates
```

Установка **без `git clone`**:

```bash
curl -fsSL https://raw.githubusercontent.com/swolfypack/torrent-blocker-test/main/install.sh | sudo bash
```

Корневой [`install.sh`](install.sh) скачивает архив репозитория **с папками в корне**, проверяет наличие `scripts/`, `config/` и `systemd/`, затем запускает `scripts/install.sh` из временной директории. Отдельная папка `torrent-guard/` не требуется. В Ubuntu/Debian недостающие `iptables`, `iproute2` и `util-linux` установятся автоматически через `apt-get`. Для скачивания необходимы `curl` и `tar`, а для автозапуска — systemd.

После установки будут созданы `/usr/local/sbin/torrent-guard`, `/etc/systemd/system/torrent-guard.service` и (при первой установке) `/etc/torrent-guard.conf`. Установщик включит автозапуск и применит правила. При повторной установке существующая конфигурация сохраняется.

**Проверка:**

```bash
sudo systemctl status torrent-guard --no-pager
sudo torrent-guard status
sudo torrent-guard preview
```

> [!NOTE]
> `torrent-guard.service` — служба типа `oneshot` с `RemainAfterExit=yes`. Для неё состояние `active (exited)` нормально: правила работают в ядре, а не в постоянно запущенном процессе.

### 2. Конфигурация

```bash
sudo nano /etc/torrent-guard.conf
sudo torrent-guard preview
sudo systemctl reload torrent-guard
sudo torrent-guard status
```

Для Remnawave Node с `network_mode: host` обычно необходим `FILTER_OUTPUT=1`; рекомендации по настройкам приведены [ниже](#конфигурация-для-remnawave--xray).

### 3. Обновление одной командой

Повторите команду установки:

```bash
curl -fsSL https://raw.githubusercontent.com/swolfypack/torrent-blocker-test/main/install.sh | sudo bash
```

Установщик обновит программу и службу, но **не перезапишет** ваш `/etc/torrent-guard.conf`. Затем проверьте статус:

```bash
sudo torrent-guard status
```

### 4. Удаление через curl

Для удаления установленной программы, службы systemd и управляемых правил IPv4/IPv6 без клонирования репозитория:

```bash
curl -fsSL https://raw.githubusercontent.com/swolfypack/torrent-blocker-test/main/scripts/uninstall.sh | sudo bash
```

Скрипт отключит автозапуск, удалит свои правила и исполняемый файл. **Остальные правила firewall не очищаются.** Конфигурация сохраняется для возможной переустановки.

Полностью удалить и настройки:

```bash
sudo rm -f /etc/torrent-guard.conf
```

**Проверка удаления:**

```bash
systemctl is-enabled torrent-guard.service 2>/dev/null || true
command -v torrent-guard || true
sudo iptables -S | grep TG_ || true
sudo ip6tables -S | grep TG_ || true
```

> [!CAUTION]
> Команда `sudo torrent-guard remove` снимает правила, но **не отключает автозапуск**. Для временного отключения программы с сохранением файлов используйте `sudo systemctl disable --now torrent-guard.service`. Чтобы включить снова — `sudo systemctl enable --now torrent-guard.service`.

### 5. Журнал и диагностика

```bash
sudo journalctl -u torrent-guard -n 100 --no-pager
sudo torrent-guard status
```

Если после установки не работают сайты, DNS или VPN, проверьте `/etc/torrent-guard.conf` и для диагностики отключите защиту: `sudo systemctl disable --now torrent-guard.service`. **Не выполняйте `iptables -F`**: это сотрёт и чужие правила, включая правила Docker.

## Конфигурация для Remnawave / Xray

**Remnawave Node с `network_mode: host`:** исходящие сокеты создаются процессом Xray на самом хосте и обычно проходят через `OUTPUT`. Для такого развёртывания рекомендуются параметры:

```bash
FILTER_OUTPUT=1
FILTER_FORWARD=0
FILTER_DOCKER_USER=0
FILTER_INPUT=0
ENABLE_IPV6=1
ENABLE_PORTS=1
ENABLE_DHT=1
ENABLE_UDP_TRACKER=1
ENABLE_HANDSHAKE=1
ENABLE_CONNLIMIT=0
EGRESS_IFACE='auto'
IPV6_EGRESS_IFACE='auto'
ENABLE_LOG=0
```

При **Docker bridge** обычно нужны `DOCKER-USER` и/или `FORWARD`. При маршрутизируемом **WireGuard/OpenVPN** нужен `FORWARD`. Одновременное включение FORWARD и DOCKER-USER может удвоить проверку части пакетов в Docker с iptables-backend, поэтому тщательно проверяйте путь трафика.

С `EGRESS_IFACE='auto'` скрипт проверяет только внешний интерфейс IPv4 по умолчанию, а с `IPV6_EGRESS_IFACE='auto'` — интерфейс маршрута IPv6 по умолчанию. Для VPN с несколькими выходными маршрутами/интерфейсами лучше задать интерфейсы явно или пустую строку (`''`, все интерфейсы) и измерить CPU.

> [!CAUTION]
> **Не включайте `ENABLE_CONNLIMIT=1` на многопользовательской Remnawave-ноде** без отдельного анализа. Из-за NAT и общих исходящих IP можно затронуть тысячи нормальных соединений. По умолчанию отключено.

### Второй слой: блокировка в самом Xray

В Xray можно добавить правило маршрутизации для распознанного BitTorrent и `blackhole` outbound. Это полезно, потому что Xray получает уже расшифрованные данные клиента (после VLESS), тогда как iptables смотрит сетевые пакеты на выходе. **Но sniffing Xray также не гарантирует распознавания шифрованного BitTorrent.**

В файле [`examples/xray-bittorrent-parts.json`](examples/xray-bittorrent-parts.json) находятся **только фрагменты**, а не готовая конфигурация сервера. В существующем профиле Remnawave:

1. Убедитесь, что у нужных `inbounds` включено `sniffing.enabled = true` и `metadataOnly` не установлен в `true`. Оставьте свои актуальные `destOverride`; значение `bittorrent` **не является** допустимым элементом `destOverride`.
2. В `outbounds` добавьте `{ "tag": "block-bittorrent", "protocol": "blackhole" }` (если такого тега ещё нет).
3. В **начало** `routing.rules` добавьте:

```json
{
  "type": "field",
  "protocol": ["bittorrent"],
  "outboundTag": "block-bittorrent"
}
```

4. Сохраните профиль через панель, убедитесь, что конфигурация Xray валидна, и протестируйте подключение. Не подменяйте `routing` или `outbounds` целиком: там уже могут быть другие правила/балансировка.

Справка: [Xray inbound/sniffing](https://xtls.github.io/ru/config/inbound.html), [Xray routing](https://xtls.github.io/en/config/routing.html), [Xray blackhole](https://xtls.github.io/en/config/outbounds/blackhole.html).

### nDPI — только как отдельный проект

Оригинальная [статья MHOST](https://mhost.ee/ru/wiki/security/block-torrent-traffic) предлагает необязательный модуль `xt_ndpi`. Он не включён в автоматическую установку TorrentGuard: он требует совместимого расширения ядра/iptables, тестов на вашей версии ядра и может быть дорогим для производительности. Современная библиотека [ntop/nDPI](https://github.com/ntop/nDPI) сама по себе не добавляет автоматически модуль `-m ndpi` к `iptables` — нужна отдельная интеграция.

## Проверка в действующей системе

Сначала проверьте, **где реально проходит трафик**:

```bash
ip -4 route show default
ip -6 route show default
iptables -V
ip6tables -V
sudo iptables -S OUTPUT
sudo iptables -S FORWARD
sudo iptables -S DOCKER-USER 2>/dev/null || true
sudo torrent-guard status
```

После применения проверьте доступность VPN, SSH, HTTPS, DNS, QUIC/UDP-сервисов и ваши обычные сценарии. Затем на отдельной тестовой ноде, с разрешённым тестовым трафиком, сравните счётчики блокировок до и после попыток подключения BitTorrent. Обратите внимание: **рост счётчиков подтверждает совпадение правила, но не отсутствие обходов**. Для проверки эффективности нужны отдельные тесты plaintext TCP, DHT, UDP tracker, MSE и uTP, как на стандартных, так и нестандартных портах.

Измерьте CPU, задержку и throughput **до и после** включения `ENABLE_DHT`, `ENABLE_UDP_TRACKER`, `ENABLE_HANDSHAKE`: каждый пакет потенциально проходит через несколько строковых сравнений. При большом трафике это может оказаться дороже, чем ожидается.

При изменении Docker firewall backend на нативный nftables `DOCKER-USER` отсутствует. Docker/containerd/firewalld/UFW могут изменить порядок правил при перезапуске — после таких событий повторите `sudo torrent-guard status` и при необходимости `sudo torrent-guard apply`. Проверяйте не только наличие цепочек, но и счётчики обработки пакетов.

## Тесты

```bash
sudo bash tests/test.sh
```

Тесты **не трогают реальный firewall**: симулятор iptables проверяет создание IPv4/IPv6 цепочек, обновление без предварительного удаления старых правил, откат при ошибке вставки, миграцию с v1.0.0, сохранность чужих правил и валидацию конфигурации. Эти тесты **не проверяют реальное совпадение сигнатур ядром** и не заменяют испытания на отдельном VPS.

## Ограничения

- Шифрование MSE/PE, VPN-в-VPN, HTTPS-трекеры, uTP с произвольными портами могут проходить.
- `xt_string` не собирает произвольные TCP-потоки; сигнатура, разбитая на сегменты, может остаться незамеченной.
- Привязка к портам может задеть обычные сервисы с такими же номерами портов.
- Конфигурационный файл `/etc/torrent-guard.conf` исполняется как Bash от root: права должны быть только у доверенных администраторов.
- Правила не гарантируют соблюдение всех ограничений конкретного хостинга.

## Источники

- [MHOST — Блокировка торрент-трафика](https://mhost.ee/ru/wiki/security/block-torrent-traffic)
- [BitTorrent BEP 3](https://www.bittorrent.org/beps/bep_0003.html)
- [BitTorrent BEP 5](https://www.bittorrent.org/beps/bep_0005.html)
- [BitTorrent BEP 15](https://bittorrent.org/beps/bep_0015.html)
- [Docker iptables](https://docs.docker.com/engine/network/firewall-iptables/)
- [Docker nftables](https://docs.docker.com/engine/network/firewall-nftables/)
- [iptables-extensions](https://manpages.debian.org/trixie/iptables/iptables-extensions.8.en.html)

MIT License — [`LICENSE`](LICENSE).
