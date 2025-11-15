## Quick orientation

This is a small Flask-based POS (grocery) app. Key facts an AI code agent should know up front:

- Single-process Flask app: main app entry is `app.py`. Running `python app.py` will call `init_db()` and start the dev server (debug=True).
- Persistent data: SQLite configured via `app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///grocery_pos.db'` (file in repo root).
- Roles: three role strings are used across the codebase: `superadmin`, `admin`, and `sales`.
- Templates & static: HTML templates live in `templates/` (examples: `admin_dashboard.html`, `receipt.html`, `login.html`); CSS in `static/`.

## High-level architecture / flows

- app.py contains models (User, Category, Product, Sale, SaleItem, Inventory), route handlers, and simple decorators `login_required` and `role_required`.
- Auth state is stored in Flask `session` keys: `user_id`, `username`, `role`, and `cart` (cart is a list of dicts). Many routes rely on those keys.
- Sales flow: client adds items via `/api/add-to-cart` and finalizes via `/api/process-sale`. `process_sale()` decrements `Product.stock`, creates `Sale`, `SaleItem`, and `Inventory` records in a single transaction.

## Important code conventions & patterns (concrete)

- Role checks: use `@role_required('admin')` or `@role_required('sales')`; `role_required` allows `superadmin` to bypass.
- Password checking: `werkzeug.security.generate_password_hash` and `check_password_hash` are used. Routes that delete or edit sensitive records ask for `admin_password` and verify against the current user's stored hash.
- DB creation: `init_db()` (in `app.py`) runs `db.create_all()` and seeds one `superadmin` if no users exist.
- Cascades: relationships define `cascade='all, delete-orphan'` (e.g., Category.products) — deleting a Category will delete its Products.

## Developer workflows / commands

Setup (recommended): create a venv and install minimal deps.

Windows (cmd.exe) example:

```
python -m venv .venv
.venv\Scripts\activate
pip install Flask Flask_SQLAlchemy Werkzeug
```

Run app (dev):

```
python app.py
```

Lightweight tests / scripts:
- Create a sales user: `python scripts/create_sales_user.py` (calls app context and adds `sales1`).
- Quick login test: `python scripts/test_sales_login.py` or `python tests/login_test.py` — these hit the running server at http://127.0.0.1:5000 and expect the default superadmin credentials `superadmin / superadmin123`.

## Where an AI should be careful / safety notes

- SECRET_KEY is hard-coded in `app.py` — do not commit secrets in changes. Prefer using environment variables for production.
- DB is SQLite file `grocery_pos.db` in repo root. Avoid destructive migrations without backups. Many routes modify stock and commit immediately.
- `process_sale()` modifies product stock and commits; changes here affect inventory accounting — keep transactional semantics intact when refactoring.

## Useful file references (examples to open when working)

- `app.py` — single-file app and the authoritative source for routes, models, and business logic.
- `scripts/create_sales_user.py` — example of programmatically using `app.app_context()` to add users.
- `scripts/test_sales_login.py` and `tests/login_test.py` — examples of how to test endpoints by posting to `/login` and checking a protected page.
- `templates/*` — UI expectations: when changing a route, ensure a matching template exists (names are referenced by `render_template`).

If anything here is incomplete or you want a different focus (more test scaffolding, CI steps, or a requirements file), tell me which area to expand and I'll iterate.
