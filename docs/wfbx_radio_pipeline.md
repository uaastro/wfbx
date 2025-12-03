# Базовый радио‑пайплайн wfbX

Коротко: приложение шлет UDP → `wfbx_ptx` (опционально) → `wfbx_tx` инжектит как raw 802.11 в monitor‑mode → эфир → `wfbx_rx` принимает и выводит обратно в UDP. Все модули работают без ACK/SEQ, фиксированным PHY‑профилем и с трейлером тайм‑штампа для mesh.

## Принципы
- Raw 802.11 Data кадры через libpcap в monitor‑mode; адреса в шапке кодируют группу/tx_id/link/radio_port.
- Фиксированный PHY (MCS/GI/BW/LDPC/STBC) из CLI; без агрегации и без ACK.
- В конце payload добавляется mesh‑трейлер с epoch/ts (поля ts_tx/ts_rx драйвер может проставлять).
- UDP↔радио выполняют только `wfbx_tx`/`wfbx_rx`; остальной обвес (FEC/proxy/L2Tap и пр.) работает поверх UDP.

## Mesh и синхронизация
- `wfbx_mx` слушает эфир, парсит radiotap (фактический PHY) и трейлер, оценивает `T_epoch`, airtime и задержки.
- По UDS (`@wfbx.mx`) публикует Epoch/TDMA параметры подписчикам (`wfbx_tx`), чтобы TX вписывался в суперкадр/слоты и делал fit‑check.
- В `wfbx_tx` синхронизация включается ключом `--epoch_sync` (можно указать адрес через `--mx`).

## Модули и ключевые параметры
- **wfbx_ptx** — прием UDP, мультиплекс в единый поток с `radio_port`/seq заголовком для `wfbx_tx`. Параметры: `--ip/--port` (bind), `--radio_port`, `--xtx_ip/--xtx_port` (куда шить дальше), `--stat_ip/--stat_port/--stat_id/--stat_period`.
- **wfbx_tx** — UDP→802.11 инжекция. Параметры: источник `--ip/--port`; режим `--mode solo|ptx`; PHY `--mcs_idx --gi short|long --bw 20|40 --ldpc --stbc`; адресация `--group_id --tx_id --link_id --radio_port`; mesh/TDMA `--epoch_len --epoch_gi --slot_start --slot_len --gi_tx --delta_us --d_max --eps_us --send_gi --prewake_q --prewake_min --epoch_sync --mx`; статистика `--stat_ip/--stat_port/--stat_id/--stat_period`; позиционный аргумент — интерфейс.
- **wfbx_rx** — 802.11→UDP прием. Параметры: вывод `--ip/--port`; фильтры `--tx_id --group_id --link_id --radio_port`; статистика `--stat_ip/--stat_port/--stat_id/--stat_period`; далее список интерфейсов.
- **wfbx_mx** — mesh RX менеджер/монитор, оценивает тайминг и раздает control сообщения. Параметры: `--ip/--port` (UDP forward, опц.), фильтры `--tx_id` (список/any), `--group_id`; задержки `--delta_us` (стек), `--d_max` (расстояние→tau_us), `--ctrl` (UDS адрес подписки, по умолчанию @wfbx.mx); статистика `--stat_ip/--stat_port/--stat_id/--stat_period`; debug `--debug on|off`; интерфейсы списком.
- **wfb_tx / wfb_rx** — легаси однонаправленная пара без TDMA/mesh; параметры аналогичны xtx/xrx, но без mx/slot полей.

Эти модули составляют базовый радио‑пайплайн; остальные утилиты в `wfbx_server` (FEC/proxy/L2Tap/interval/статистика) работают поверх UDP и не трогают эфир напрямую.
