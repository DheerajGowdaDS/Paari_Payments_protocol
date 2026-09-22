# Cards export — run `python scripts/export_cards.py --tx TXN-proof-9c5ffd55`

Generates 15 PNGs (1200×750 @2x) under `exports/cards/png/` from live proof bundle `TXN-proof-9c5ffd55`.
HTML intermediates in `exports/cards/html/`. Requires live DB `paari_live_e2e.db` or fallback JSON `evidence_live_e2e_2026-09-19.json`.

```
pip install Jinja2 playwright
playwright install chromium
python scripts/export_cards.py --tx TXN-proof-9c5ffd55
```
