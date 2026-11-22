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

> [!NOTE]
> Команды ниже рассчитаны на **Ubuntu / Debian с systemd** и структуру этого репозитория, в которой проект находится в каталоге `torrent-guard/`. Понадобятся root-права. Перед изменением firewall на удалённой VPS желательно иметь доступ к аварийной консоли хостера.

### 1. Быстрая установка из GitHub

```bash
sudo apt update
sudo apt install -y git iptables iproute2 util-linux

git clone https://github.com/swolfypack/torrent-blocker-test.git
cd torrent-blocker-test/torrent-guard

sudo bash scripts/install.sh
```

Установщик:

- Копирует исполняемый файл в `/usr/local/sbin/torrent-guard`.
- Создаёт `/etc/torrent-guard.conf` из примера, **только если файла ещё нет** (настройки сохраняются при повторной установке).
- Устанавливает службу `/etc/systemd/system/torrent-guard.service`.
- Включает автозапуск службы и применяет правила. Если служба уже активна, использует `reload`, а не `restart`, чтобы не удалять правила на время обновления.

**Проверьте установку:**

```bash
sudo systemctl status torrent-guard --no-pager
sudo torrent-guard status
sudo torrent-guard preview
```

> [!IMPORTANT]
> Фильтр работает **не как отдельный постоянно запущенный процесс**: `torrent-guard.service` — служба `oneshot` с `RemainAfterExit=yes`. Состояние `active (exited)` для неё нормально. Время запуска и наличие цепочек в firewall проверяйте командой `sudo torrent-guard status`.

### 2. Настройка и применение изменений

Откройте конфигурацию:

```bash
sudo nano /etc/torrent-guard.conf
```

Посмотрите настройки, затем примените их без остановки службы:

```bash
sudo torrent-guard preview
sudo systemctl reload torrent-guard
sudo torrent-guard status
```

Для Remnawave Node c `network_mode: host` особенно важен `FILTER_OUTPUT=1`; подробные параметры приведены [ниже](#конфигурация-для-remnawave--xray).

### 3. Обновление до последней версии

Из ранее клонированного проекта:

```bash
cd torrent-blocker-test
git pull --ff-only
cd torrent-guard
sudo bash scripts/install.sh
```

Установщик не перезаписывает `/etc/torrent-guard.conf`. После обновления проверьте `sudo torrent-guard status`.

### 4. Полное удаление программы и правил

**Рекомендуемый способ — через скрипт из репозитория:**

```bash
cd torrent-blocker-test/torrent-guard
sudo bash scripts/uninstall.sh
```

Скрипт остановит и отключит службу, удалит управляемые правила IPv4/IPv6, исполняемый файл `/usr/local/sbin/torrent-guard` и unit-файл `/etc/systemd/system/torrent-guard.service`, затем обновит systemd. **Другие правила firewall не очищаются.**

Если папки репозитория больше нет, удалить установленную версию можно вручную:

```bash
sudo systemctl disable --now torrent-guard.service 2>/dev/null || true
if [ -x /usr/local/sbin/torrent-guard ]; then
  sudo /usr/local/sbin/torrent-guard remove
fi
sudo rm -f /etc/systemd/system/torrent-guard.service /usr/local/sbin/torrent-guard
sudo systemctl daemon-reload
```

**Конфигурация специально сохраняется**, чтобы при переустановке не потерять настройки. Если нужно удалить и её:

```bash
sudo rm -f /etc/torrent-guard.conf
```

Проверка после удаления:

```bash
systemctl is-enabled torrent-guard.service 2>/dev/null || true
command -v torrent-guard || true
sudo iptables -S | grep -E 'TG_(EGRESS|DROP|INPUT|OUTPUT|FORWARD)' || true
sudo ip6tables -S | grep -E 'TG_(EGRESS|DROP|INPUT|OUTPUT|FORWARD)' || true
```

Если ранее правила или службы создавались **другими** скриптами, этот деинсталлятор их не удаляет.

> [!CAUTION]
> `sudo torrent-guard remove` **только снимает правила** — но не отключает systemd-службу, поэтому после перезагрузки правила могут вернуться. Для постоянного отключения без удаления программы используйте `sudo systemctl disable --now torrent-guard.service`. Чтобы снова включить защиту: `sudo systemctl enable --now torrent-guard.service`.

### 5. Журнал и диагностика

```bash
sudo journalctl -u torrent-guard -n 100 --no-pager
sudo torrent-guard status
```

Если после установки недоступны обычные сайты, DNS или сервисы VPN, проверьте параметры в `/etc/torrent-guard.conf` и временно отключите защиту: `sudo systemctl disable --now torrent-guard.service`. **Не используйте `iptables -F`: эта команда затронет чужие правила, включая Docker и SSH-защиту.**

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
