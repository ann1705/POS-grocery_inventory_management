# Grocery POS (small Flask app)

This repository is a compact grocery Point-of-Sale demo built with Flask and SQLite. It is intended for development and small demos only.

Quick start (Windows - cmd.exe):

```
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
python app.py
```

Features
- Single-file Flask app: `app.py` contains models, routes, and the small business logic.
- Roles: `superadmin`, `admin`, `sales`.
- POS view: split categories/products and cart. Cart actions by `sales` require admin authentication.
- Small scripts: `scripts/create_sales_user.py` and `scripts/test_sales_login.py` for quick smoke checks.

Notes for contributors
- Do not commit production secrets. `app.py` uses `SECRET_KEY` from the environment if present; otherwise it falls back to a dev string.
- Database file: `grocery_pos.db` lives in the repo root for convenience. Back it up before destructive changes.
- To run tests / smoke checks: start the server, then run `python scripts/test_sales_login.py`.

If you'd like, I can split `app.py` into blueprints, add pytest-based tests, or add GitHub Actions CI next.
