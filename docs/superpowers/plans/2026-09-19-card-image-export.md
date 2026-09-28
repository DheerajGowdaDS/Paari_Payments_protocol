# Card Image Export Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Export 15 PNG images (one per Stage Outputs row) from live proof bundle `TXN-proof-9c5ffd55` for visual use.

**Architecture:** CLI `scripts/export_cards.py` loads bundle via `app.proof_bundle.collect_proof_bundle` (or JSON fallback), renders 15 HTML cards via Jinja2 (`scripts/templates/card_base.html` + `cards.css`), writes `exports/cards/html/`, then Playwright screenshots each to `exports/cards/png/stage-*.png` at 1200x750 @2x. Read-only, no secrets.

**Tech Stack:** Python 3.11, Jinja2, Playwright chromium, SQLAlchemy, Paari proof bundle.

## Global Constraints

- Python 3.11; no new DB tables; no secrets in cards (only fingerprints, truncated sigs, public keys)
- Exports under `exports/` gitignored except `exports/cards/README.md`
- Each card 1200x750 @2x, indigo-600/white theme, rounded-2xl, shadow-xl
- Uses live IDs: `order_TdrLnfAh9TBQie`, `pay_TdrWE1S8hVE0PJ`, `TXN-proof-9c5ffd55`, `b89778e0...`, `f358feea...`
- Fallback if playwright missing: leave HTML and print install hint

---

### Task 1: Card Templates and Styles

**Files:**
- Create: `scripts/templates/card_base.html`
- Create: `scripts/templates/cards.css`
- Create: `exports/cards/README.md`

**Interfaces:**
- Consumes: None
- Produces: Jinja base template `card_base.html` with blocks `stage_badge`, `title`, `body`, `footer` used by Task 2

- [ ] **Step 1: Create cards.css**

```css
/* Paari card theme */
.card { width:1200px; height:750px; background:#fff; border-radius:24px; box-shadow:0 20px 60px rgba(0,0,0,0.15); font-family:system-ui, -apple-system, sans-serif; overflow:hidden; display:flex; flex-direction:column; }
.header { background:#4f46e5; color:#fff; padding:24px 32px; display:flex; justify-content:space-between; align-items:center; }
.badge { background:#fff; color:#4f46e5; padding:6px 14px; border-radius:999px; font-weight:700; font-size:14px; }
.body { padding:28px 32px; flex:1; display:grid; grid-template-columns:1fr 1fr; gap:18px; font-size:14px; color:#1f2937; }
.footer { border-top:1px solid #e5e7eb; padding:16px 32px; display:flex; justify-content:space-between; font-size:12px; color:#6b7280; }
.mono { font-family:ui-monospace, monospace; background:#f3f4f6; padding:2px 6px; border-radius:6px; }
.qr { width:64px; height:64px; background:#e0e7ff; border-radius:8px; display:flex; align-items:center; justify-content:center; font-size:10px; color:#4f46e5; }
```

- [ ] **Step 2: Create card_base.html**

```html
<!doctype html><html><head><meta charset="utf-8"><link rel="stylesheet" href="cards.css"></head>
<body><div class="card">
<div class="header"><div>{{ stage_title }}</div><div class="badge">Stage {{ stage_num }}</div></div>
<div class="body">{% for k,v in fields %}<div><div style="color:#6b7280;font-size:11px;text-transform:uppercase">{{k}}</div><div class="mono" title="{{v_full[k]}}">{{v}}</div></div>{% endfor %}</div>
<div class="footer"><span>{{ bundle_id }} · chain {{ chain_verified }}</span><span class="qr">QR</span></div>
</div></body></html>
```

- [ ] **Step 3: Create exports/cards/README.md**

```
# Cards export — run `python scripts/export_cards.py --tx TXN-proof-9c5ffd55`
```

- [ ] **Step 4: Verify templates exist**

Run: `ls scripts/templates/card_base.html scripts/templates/cards.css`
Expected: both files present

### Task 2: Export CLI — Bundle Load and HTML Render

**Files:**
- Create: `scripts/export_cards.py`
- Modify: `requirements.txt` (add `Jinja2` if missing)

**Interfaces:**
- Consumes: `card_base.html` + `cards.css` from Task 1, `app.proof_bundle.collect_proof_bundle`, `evidence_live_e2e_2026-09-19.json`
- Produces: `exports/cards/html/stage-*.html` (15 files) and CLI `export_cards(tx, json_path)`

- [ ] **Step 1: Write export_cards.py skeleton**

```python
import argparse, json, pathlib
from jinja2 import Environment, FileSystemLoader
def trunc(s, n=12): return s[:n]+"..." if s and len(s)>n else (s or "—")
STAGES = [
  ("01","Discovery","discovery"), ("02","Parent Trust Pending","parent_trust"), ... # 15 entries mapping to bundle keys
]
def load_bundle(tx, json_path):
    if json_path and pathlib.Path(json_path).exists():
        return json.loads(pathlib.Path(json_path).read_text())
    from sqlalchemy.orm import sessionmaker
    from app.database import get_engine
    from app.proof_bundle import collect_proof_bundle
    engine=get_engine("sqlite:///./paari_live_e2e.db")
    Session=sessionmaker(bind=engine)
    db=Session()
    try: return collect_proof_bundle(db, tx)
    finally: db.close()
```

- [ ] **Step 2: Implement render loop**

```python
def render_all(bundle):
    env=Environment(loader=FileSystemLoader("scripts/templates"))
    tpl=env.get_template("card_base.html")
    out=pathlib.Path("exports/cards/html"); out.mkdir(parents=True, exist_ok=True)
    for num,title,key in STAGES:
        # build fields list from bundle["artifacts"][key] truncating hashes
        fields=[(k,trunc(str(v))) for k,v in bundle["artifacts"].get(key,{}).items()][:8]
        html=tpl.render(stage_num=num, stage_title=title, fields=fields, v_full={}, bundle_id=bundle["bundle_id"], chain_verified=bundle["artifacts"]["audit_record"]["chain_verified"])
        (out/f"stage-{num}-{key}.html").write_text(html)
```

Full 15 STAGES list must match `docs/STAGE_OUTPUTS.md:7-24` exactly: `01-discovery`, `02-parent-trust-pending`, `03-parent-trust-verified`, `04-delegation`, `05-agent-identity`, `06-agent-card`, `07-credential`, `08-authentication`, `09-governance`, `10-bounded-authorization`, `11-payment-execution`, `12-webhook`, `13-payment-result`, `14-audit-record`, `15-revocation`.

- [ ] **Step 3: Add CLI entry**

```python
if __name__=="__main__":
    ap=argparse.ArgumentParser(); ap.add_argument("--tx", default="TXN-proof-9c5ffd55"); ap.add_argument("--json", default="evidence_live_e2e_2026-09-19.json")
    args=ap.parse_args(); bundle=load_bundle(args.tx, args.json); render_all(bundle); print("HTML done")
```

- [ ] **Step 4: Run HTML generation**

Run: `python scripts/export_cards.py --tx TXN-proof-9c5ffd55`
Expected: `exports/cards/html/` contains 15 html files, no error

- [ ] **Step 5: Verify pytest still green**

Run: `python -m pytest -q`
Expected: `88 passed, 1 skipped`

### Task 3: Playwright PNG Export

**Files:**
- Modify: `scripts/export_cards.py` (add screenshot function)

**Interfaces:**
- Consumes: `exports/cards/html/stage-*.html` from Task 2
- Produces: `exports/cards/png/stage-*.png` (15 PNGs 1200x750 @2x)

- [ ] **Step 1: Add screenshot function**

```python
def screenshot_all():
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        print("playwright not installed — HTML ready at exports/cards/html. Run: pip install playwright && playwright install chromium")
        return
    import pathlib
    html_dir=pathlib.Path("exports/cards/html"); png_dir=pathlib.Path("exports/cards/png"); png_dir.mkdir(parents=True, exist_ok=True)
    with sync_playwright() as p:
        browser=p.chromium.launch(); page=browser.new_page(viewport={"width":1200,"height":750,"deviceScaleFactor":2})
        for html in sorted(html_dir.glob("*.html")):
            page.goto(html.resolve().as_uri()); page.wait_for_timeout(400)
            page.screenshot(path=str(png_dir / (html.stem + ".png")), full_page=False)
        browser.close()
    print("PNG done")
```

Call it at end of `if __name__=="__main__"`: after `render_all(bundle)` call `screenshot_all()`.

- [ ] **Step 2: Run full export**

Run: `pip install playwright Jinja2 -q; playwright install chromium; python scripts/export_cards.py --tx TXN-proof-9c5ffd55`
Expected: `exports/cards/png/` contains 15 png files

- [ ] **Step 3: Verify 15 PNGs**

Run: `ls exports/cards/png/*.png | Measure-Object | Select-Object Count; ls exports/cards/png/`
Expected: Count 15, files `stage-01-discovery.png` ... `stage-15-revocation.png`

- [ ] **Step 4: Final pytest**

Run: `python -m pytest -q`
Expected: `88 passed, 1 skipped`
