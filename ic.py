# ──────────────────────────────────────────────────────────────────────────────
#  StockFlow Pro – FULL WEB APP (Flask + Bootstrap 5 + SQLite)
#  Run: pip install flask flask-login && python web_app.py
#  Open: http://127.0.0.1:5000
# ──────────────────────────────────────────────────────────────────────────────

import os
import sqlite3
import hashlib
import binascii
import secrets
from datetime import datetime, date
from pathlib import Path
from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory, session
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import csv
from io import StringIO

# ─── Config ────────────────────────────────────────────────────────────────
app = Flask(__name__)
app.secret_key = secrets.token_hex(16)
app.config['DATABASE'] = 'stock_web.db'
app.config['REPORTS_DIR'] = 'reports'
app.config['LOW_STOCK_THRESHOLD'] = 5

os.makedirs(app.config['REPORTS_DIR'], exist_ok=True)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# ─── DB Connection ─────────────────────────────────────────────────────────
def get_db():
    conn = sqlite3.connect(app.config['DATABASE'], timeout=10)  # Increased timeout
    conn.row_factory = sqlite3.Row
    conn.execute('PRAGMA journal_mode = WAL')  # Enable Write-Ahead Logging
    conn.execute('PRAGMA busy_timeout = 5000')  # Increase busy timeout
    return conn

def init_db():
    conn = get_db()
    try:
        conn.executescript('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            shop_name TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS products (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            category TEXT,
            quantity INTEGER NOT NULL DEFAULT 0,
            price REAL DEFAULT 0,
            supplier TEXT,
            last_updated TEXT,
            FOREIGN KEY(user_id) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            product_id INTEGER,
            action TEXT NOT NULL,
            qty_change INTEGER,
            timestamp TEXT NOT NULL,
            note TEXT,
            FOREIGN KEY(user_id) REFERENCES users(id),
            FOREIGN KEY(product_id) REFERENCES products(id)
        );

        CREATE TABLE IF NOT EXISTS sales (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            product_id INTEGER NOT NULL,
            quantity INTEGER NOT NULL,
            unit_price REAL NOT NULL,
            total_amount REAL NOT NULL,
            sale_date TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id),
            FOREIGN KEY(product_id) REFERENCES products(id)
        );
        ''')
        conn.commit()
    finally:
        conn.close()

init_db()

# ─── User Model ────────────────────────────────────────────────────────────
class User(UserMixin):
    def __init__(self, id, username, shop_name):
        self.id = id
        self.username = username
        self.shop_name = shop_name

@login_manager.user_loader
def load_user(user_id):
    conn = get_db()
    try:
        user = conn.execute('SELECT id, username, shop_name FROM users WHERE id = ?', (user_id,)).fetchone()
        if user:
            return User(user['id'], user['username'], user['shop_name'])
        return None
    finally:
        conn.close()

# ─── Helpers ───────────────────────────────────────────────────────────────
def hash_password(password):
    return generate_password_hash(password, method='pbkdf2:sha256', salt_length=16)

def verify_password(stored_hash, password):
    return check_password_hash(stored_hash, password)

def log_history(user_id, product_id, action, qty_change=None, note=None):
    conn = get_db()
    try:
        conn.execute('INSERT INTO history (user_id, product_id, action, qty_change, timestamp, note) VALUES (?, ?, ?, ?, ?, ?)',
                   (user_id, product_id, action, qty_change, datetime.utcnow().isoformat(), note))
        conn.commit()
    finally:
        conn.close()

def log_sale(user_id, product_id, quantity, unit_price, total_amount):
    conn = get_db()
    try:
        now = datetime.utcnow()
        conn.execute('''INSERT INTO sales (user_id, product_id, quantity, unit_price, total_amount, sale_date, timestamp)
                      VALUES (?, ?, ?, ?, ?, ?, ?)''',
                   (user_id, product_id, quantity, unit_price, total_amount, now.date().isoformat(), now.isoformat()))
        conn.commit()
    finally:
        conn.close()

# ─── Routes ────────────────────────────────────────────────────────────────
@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        conn = get_db()
        try:
            user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
            if user and verify_password(user['password_hash'], password):
                login_user(User(user['id'], user['username'], user['shop_name']))
                return redirect(url_for('dashboard'))
            flash('Invalid username or password', 'danger')
        finally:
            conn.close()
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        shop_name = request.form['shop_name'].strip()
        if not username or not password:
            flash('Username and password required', 'danger')
            return render_template('register.html')
        
        conn = get_db()
        try:
            existing = conn.execute('SELECT id FROM users WHERE username = ?', (username,)).fetchone()
            if existing:
                flash('Username already taken', 'danger')
            else:
                conn.execute('INSERT INTO users (username, password_hash, shop_name) VALUES (?, ?, ?)',
                           (username, hash_password(password), shop_name))
                conn.commit()
                flash('Account created! Please login.', 'success')
                return redirect(url_for('login'))
        finally:
            conn.close()
    return render_template('register.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out successfully', 'info')
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    conn = get_db()
    try:
        search = request.args.get('search', '').strip()
        query = '''SELECT id, name, category, quantity, price, supplier, last_updated 
                   FROM products WHERE user_id = ?'''
        params = [current_user.id]
        if search:
            query += ' AND (name LIKE ? OR category LIKE ?)'
            pattern = f'%{search}%'
            params.extend([pattern, pattern])
        query += ' ORDER BY name'
        products = conn.execute(query, params).fetchall()
        low_stock = [p for p in products if p['quantity'] < app.config['LOW_STOCK_THRESHOLD']]
        
        # Get today's sales summary
        today = date.today().isoformat()
        sales_data = conn.execute('''SELECT COUNT(*) as count, SUM(total_amount) as total 
                                   FROM sales WHERE user_id = ? AND sale_date = ?''',
                                (current_user.id, today)).fetchone()
        
        return render_template('dashboard.html', products=products, low_stock=low_stock, 
                              search=search, sales_data=sales_data)
    finally:
        conn.close()

@app.route('/add', methods=['GET', 'POST'])
@login_required
def add_product():
    if request.method == 'POST':
        name = request.form['name'].strip()
        category = request.form['category'].strip()
        try:
            quantity = int(request.form['quantity'] or 0)
            price = float(request.form['price'] or 0)
        except ValueError:
            flash('Invalid quantity or price', 'danger')
            return render_template('add.html')
        supplier = request.form['supplier'].strip()
        if not name:
            flash('Product name required', 'danger')
            return render_template('add.html')
        
        conn = get_db()
        try:
            cursor = conn.execute('''INSERT INTO products (user_id, name, category, quantity, price, supplier, last_updated)
                                   VALUES (?, ?, ?, ?, ?, ?, ?)''',
                                (current_user.id, name, category, quantity, price, supplier, datetime.utcnow().isoformat()))
            conn.commit()
            log_history(current_user.id, cursor.lastrowid, 'add', quantity, f'Added "{name}"')
            flash('Product added!', 'success')
            return redirect(url_for('dashboard'))
        finally:
            conn.close()
    return render_template('add.html')

@app.route('/sell/<int:pid>', methods=['GET', 'POST'])
@login_required
def sell_product(pid):
    if request.method == 'GET':
        conn = get_db()
        try:
            product = conn.execute('SELECT * FROM products WHERE id = ? AND user_id = ?', (pid, current_user.id)).fetchone()
            if not product:
                flash('Product not found', 'danger')
                return redirect(url_for('dashboard'))
            return render_template('sell.html', product=product)
        finally:
            conn.close()
    
    elif request.method == 'POST':
        # Get connection for the entire transaction
        conn = get_db()
        try:
            # Get product with lock
            product = conn.execute('SELECT * FROM products WHERE id = ? AND user_id = ?', (pid, current_user.id)).fetchone()
            if not product:
                flash('Product not found', 'danger')
                return redirect(url_for('dashboard'))
            
            try:
                quantity = int(request.form['quantity'])
                if quantity <= 0:
                    flash('Quantity must be positive', 'danger')
                    return render_template('sell.html', product=product)
                if quantity > product['quantity']:
                    flash(f'Not enough stock! Available: {product["quantity"]}', 'danger')
                    return render_template('sell.html', product=product)
                
                unit_price = product['price']
                total_amount = quantity * unit_price
                
                # Update product quantity
                new_qty = product['quantity'] - quantity
                conn.execute('UPDATE products SET quantity=?, last_updated=? WHERE id=?',
                           (new_qty, datetime.utcnow().isoformat(), pid))
                
                # Log sale
                now = datetime.utcnow()
                conn.execute('''INSERT INTO sales (user_id, product_id, quantity, unit_price, total_amount, sale_date, timestamp)
                              VALUES (?, ?, ?, ?, ?, ?, ?)''',
                           (current_user.id, pid, quantity, unit_price, total_amount, now.date().isoformat(), now.isoformat()))
                
                # Log history
                conn.execute('INSERT INTO history (user_id, product_id, action, qty_change, timestamp, note) VALUES (?, ?, ?, ?, ?, ?)',
                           (current_user.id, pid, 'sell', -quantity, now.isoformat(), f'Sold {quantity} units'))
                
                # Commit all changes
                conn.commit()
                
                flash(f'Sold {quantity} units of {product["name"]} for {total_amount:.2f}', 'success')
                return redirect(url_for('dashboard'))
                
            except ValueError:
                flash('Invalid quantity', 'danger')
                return render_template('sell.html', product=product)
                
        except sqlite3.OperationalError as e:
            conn.rollback()
            flash(f'Database error: {str(e)}. Please try again.', 'danger')
            return redirect(url_for('dashboard'))
        finally:
            conn.close()

@app.route('/update/<int:pid>', methods=['GET', 'POST'])
@login_required
def update_product(pid):
    if request.method == 'GET':
        conn = get_db()
        try:
            product = conn.execute('SELECT * FROM products WHERE id = ? AND user_id = ?', (pid, current_user.id)).fetchone()
            if not product:
                flash('Product not found', 'danger')
                return redirect(url_for('dashboard'))
            return render_template('update.html', product=product)
        finally:
            conn.close()
    
    elif request.method == 'POST':
        conn = get_db()
        try:
            product = conn.execute('SELECT * FROM products WHERE id = ? AND user_id = ?', (pid, current_user.id)).fetchone()
            if not product:
                flash('Product not found', 'danger')
                return redirect(url_for('dashboard'))
            
            name = request.form['name'].strip()
            category = request.form['category'].strip()
            try:
                quantity = int(request.form['quantity'])
                price = float(request.form['price'])
            except ValueError:
                flash('Invalid numbers', 'danger')
                return render_template('update.html', product=product)
            supplier = request.form['supplier'].strip()
            old_qty = product['quantity']
            
            conn.execute('''UPDATE products SET name=?, category=?, quantity=?, price=?, supplier=?, last_updated=?
                          WHERE id=? AND user_id=?''',
                       (name, category, quantity, price, supplier, datetime.utcnow().isoformat(), pid, current_user.id))
            
            if quantity != old_qty:
                conn.execute('INSERT INTO history (user_id, product_id, action, qty_change, timestamp, note) VALUES (?, ?, ?, ?, ?, ?)',
                           (current_user.id, pid, 'update_qty', quantity - old_qty, datetime.utcnow().isoformat(), f'Qty: {old_qty} → {quantity}'))
            else:
                conn.execute('INSERT INTO history (user_id, product_id, action, qty_change, timestamp, note) VALUES (?, ?, ?, ?, ?, ?)',
                           (current_user.id, pid, 'update', None, datetime.utcnow().isoformat(), f'Updated "{name}"'))
            
            conn.commit()
            flash('Product updated!', 'success')
            return redirect(url_for('dashboard'))
        finally:
            conn.close()

@app.route('/delete/<int:pid>')
@login_required
def delete_product(pid):
    conn = get_db()
    try:
        product = conn.execute('SELECT name, quantity FROM products WHERE id = ? AND user_id = ?', (pid, current_user.id)).fetchone()
        if not product:
            flash('Product not found', 'danger')
            return redirect(url_for('dashboard'))
        
        conn.execute('DELETE FROM products WHERE id = ? AND user_id = ?', (pid, current_user.id))
        conn.execute('INSERT INTO history (user_id, product_id, action, qty_change, timestamp, note) VALUES (?, ?, ?, ?, ?, ?)',
                   (current_user.id, pid, 'delete', -product['quantity'], datetime.utcnow().isoformat(), f'Deleted "{product["name"]}"'))
        conn.commit()
        flash('Product deleted', 'success')
        return redirect(url_for('dashboard'))
    finally:
        conn.close()

@app.route('/history')
@login_required
def history():
    conn = get_db()
    try:
        rows = conn.execute('SELECT * FROM history WHERE user_id = ? ORDER BY timestamp DESC', (current_user.id,)).fetchall()
        return render_template('history.html', history=rows)
    finally:
        conn.close()

@app.route('/sales')
@login_required
def sales_history():
    conn = get_db()
    try:
        rows = conn.execute('''SELECT sales.*, products.name 
                             FROM sales 
                             JOIN products ON sales.product_id = products.id 
                             WHERE sales.user_id = ? 
                             ORDER BY sales.timestamp DESC''',
                          (current_user.id,)).fetchall()
        return render_template('sales.html', sales=rows)
    finally:
        conn.close()

@app.route('/daily_report')
@login_required
def daily_report():
    conn = get_db()
    try:
        today = date.today().isoformat()
        
        # Get today's sales
        sales = conn.execute('''SELECT sales.*, products.name 
                              FROM sales 
                              JOIN products ON sales.product_id = products.id 
                              WHERE sales.user_id = ? AND sales.sale_date = ? 
                              ORDER BY sales.timestamp DESC''',
                           (current_user.id, today)).fetchall()
        
        # Calculate totals
        total_sales = conn.execute('''SELECT COUNT(*) as count, SUM(total_amount) as total 
                                    FROM sales WHERE user_id = ? AND sale_date = ?''',
                                 (current_user.id, today)).fetchone()
        
        # Get top selling products today
        top_products = conn.execute('''SELECT products.name, SUM(sales.quantity) as total_qty, SUM(sales.total_amount) as total_amount
                                     FROM sales 
                                     JOIN products ON sales.product_id = products.id 
                                     WHERE sales.user_id = ? AND sales.sale_date = ?
                                     GROUP BY sales.product_id 
                                     ORDER BY total_qty DESC 
                                     LIMIT 5''',
                                  (current_user.id, today)).fetchall()
        
        # Generate CSV report
        output = StringIO()
        writer = csv.writer(output)
        writer.writerow(['Daily Sales Report', f'Date: {today}'])
        writer.writerow(['Shop:', current_user.shop_name or current_user.username])
        writer.writerow(['Total Sales:', total_sales['count'] or 0])
        writer.writerow(['Total Revenue:', f"{total_sales['total'] or 0:.2f}"])
        writer.writerow([])
        writer.writerow(['Time', 'Product', 'Quantity', 'Unit Price', 'Total'])
        
        for sale in sales:
            writer.writerow([
                sale['timestamp'][11:19],
                sale['name'],
                sale['quantity'],
                f"{sale['unit_price']:.2f}",
                f"{sale['total_amount']:.2f}"
            ])
        
        writer.writerow([])
        writer.writerow(['Top Selling Products Today'])
        writer.writerow(['Product', 'Quantity Sold', 'Revenue'])
        for product in top_products:
            writer.writerow([
                product['name'],
                product['total_qty'],
                f"{product['total_amount']:.2f}"
            ])
        
        output.seek(0)
        filename = f'{current_user.username}_daily_report_{today}.csv'
        
        # Save to reports directory
        report_path = os.path.join(app.config['REPORTS_DIR'], filename)
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(output.getvalue())
        
        return render_template('daily_report.html', 
                              sales=sales, 
                              total_sales=total_sales,
                              top_products=top_products,
                              today=today)
    finally:
        conn.close()

@app.route('/export/csv')
@login_required
def export_csv():
    conn = get_db()
    try:
        rows = conn.execute('SELECT id, name, category, quantity, price, supplier, last_updated FROM products WHERE user_id = ? ORDER BY name', (current_user.id,)).fetchall()
        output = StringIO()
        writer = csv.writer(output)
        writer.writerow(['ID', 'Name', 'Category', 'Quantity', 'Price', 'Supplier', 'Last Updated'])
        for r in rows:
            writer.writerow(r)
        output.seek(0)
        
        filename = f'{current_user.username}_stock_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'
        csv_data = output.getvalue()
        
        # Save to reports directory
        report_path = os.path.join(app.config['REPORTS_DIR'], filename)
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(csv_data)
        
        return send_from_directory(
            directory=app.config['REPORTS_DIR'],
            path=filename,
            as_attachment=True,
            download_name=filename,
            mimetype='text/csv'
        )
    finally:
        conn.close()

# Serve static reports
@app.route('/reports/<path:filename>')
def reports(filename):
    return send_from_directory(app.config['REPORTS_DIR'], filename)

# ─── HTML Templates (inline for single-file) ───────────────────────────────
HTML_TEMPLATES = {
    'base.html': '''<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>{% block title %}StockFlow Pro{% endblock %}</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
  <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.css" rel="stylesheet">
  <style>
    body { background: #f8f9fa; }
    .navbar { box-shadow: 0 2px 10px rgba(0,0,0,.1); }
    .card { border: none; border-radius: 12px; box-shadow: 0 4px 12px rgba(0,0,0,.05); }
    .low-stock { background-color: #ffe6e6 !important; }
    .table th { background: #1a5fb4; color: white; }
    .btn-action { min-width: 36px; }
    .flash-msg { border-radius: 8px; }
    .sales-card { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; }
    .stat-card { background: #fff; border-left: 4px solid #0d6efd; }
  </style>
</head>
<body>
  {% with messages = get_flashed_messages(with_categories=true) %}
    {% if messages %}
      <div class="container mt-3">
        {% for category, msg in messages %}
          <div class="alert alert-{{ 'danger' if category=='danger' else 'success' if category=='success' else 'info' }} alert-dismissible fade show flash-msg" role="alert">
            {{ msg }}
            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
          </div>
        {% endfor %}
      </div>
    {% endif %}
  {% endwith %}

  {% if current_user.is_authenticated %}
  <nav class="navbar navbar-expand-lg navbar-dark bg-primary">
    <div class="container-fluid">
      <a class="navbar-brand fw-bold" href="{{ url_for('dashboard') }}">
        <i class="bi bi-box-seam"></i> StockFlow Pro
      </a>
      <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#nav">
        <span class="navbar-toggler-icon"></span>
      </button>
      <div class="collapse navbar-collapse" id="nav">
        <ul class="navbar-nav me-auto">
          <li class="nav-item"><a class="nav-link" href="{{ url_for('dashboard') }}">Dashboard</a></li>
          <li class="nav-item"><a class="nav-link" href="{{ url_for('add_product') }}">Add Product</a></li>
          <li class="nav-item"><a class="nav-link" href="{{ url_for('history') }}">History</a></li>
          <li class="nav-item"><a class="nav-link" href="{{ url_for('sales_history') }}">Sales</a></li>
          <li class="nav-item"><a class="nav-link" href="{{ url_for('daily_report') }}">Daily Report</a></li>
        </ul>
        <ul class="navbar-nav">
          <li class="nav-item dropdown">
            <a class="nav-link dropdown-toggle" href="#" role="button" data-bs-toggle="dropdown">
              <i class="bi bi-person-circle"></i> {{ current_user.username }}
            </a>
            <ul class="dropdown-menu dropdown-menu-end">
              <li><a class="dropdown-item" href="{{ url_for('logout') }}">Logout</a></li>
            </ul>
          </li>
        </ul>
      </div>
    </div>
  </nav>
  {% endif %}

  <div class="container mt-4">
    {% block content %}{% endblock %}
  </div>

  <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>''',

    'login.html': '''{% extends "base.html" %}
{% block title %}Login - StockFlow Pro{% endblock %}
{% block content %}
<div class="row justify-content-center">
  <div class="col-md-5">
    <div class="card p-4">
      <h3 class="text-center mb-4">Login</h3>
      <form method="post">
        <div class="mb-3">
          <label class="form-label">Username</label>
          <input type="text" name="username" class="form-control" required autofocus>
        </div>
        <div class="mb-3">
          <label class="form-label">Password</label>
          <input type="password" name="password" class="form-control" required>
        </div>
        <button type="submit" class="btn btn-primary w-100">Login</button>
      </form>
      <div class="text-center mt-3">
        <a href="{{ url_for('register') }}" class="text-decoration-none">Create an account</a>
      </div>
    </div>
  </div>
</div>
{% endblock %}''',

    'register.html': '''{% extends "base.html" %}
{% block title %}Register - StockFlow Pro{% endblock %}
{% block content %}
<div class="row justify-content-center">
  <div class="col-md-5">
    <div class="card p-4">
      <h3 class="text-center mb-4">Create Account</h3>
      <form method="post">
        <div class="mb-3">
          <label class="form-label">Username</label>
          <input type="text" name="username" class="form-control" required>
        </div>
        <div class="mb-3">
          <label class="form-label">Password</label>
          <input type="password" name="password" class="form-control" required>
        </div>
        <div class="mb-3">
          <label class="form-label">Shop Name <small class="text-muted">(optional)</small></label>
          <input type="text" name="shop_name" class="form-control">
        </div>
        <button type="submit" class="btn btn-success w-100">Register</button>
      </form>
      <div class="text-center mt-3">
        <a href="{{ url_for('login') }}" class="text-decoration-none">Already have an account?</a>
      </div>
    </div>
  </div>
</div>
{% endblock %}''',

    'dashboard.html': '''{% extends "base.html" %}
{% block title %}Dashboard - {{ current_user.username }}{% endblock %}
{% block content %}
<div class="d-flex justify-content-between align-items-center mb-4">
  <h2>Stock Dashboard</h2>
  <div>
    <a href="{{ url_for('daily_report') }}" class="btn btn-info btn-sm me-2">
      <i class="bi bi-file-bar-graph"></i> Daily Report
    </a>
    <a href="{{ url_for('export_csv') }}" class="btn btn-outline-success btn-sm">
      <i class="bi bi-download"></i> Export CSV
    </a>
  </div>
</div>

{% if sales_data and (sales_data['count'] or 0) > 0 %}
<div class="alert alert-success">
  <strong>Today's Sales:</strong> {{ sales_data['count'] or 0 }} transactions | 
  <strong>Revenue:</strong> {{ "%.2f"|format(sales_data['total'] or 0) }}
  <a href="{{ url_for('daily_report') }}" class="float-end text-decoration-none">View Report →</a>
</div>
{% endif %}

<form method="get" class="mb-3">
  <div class="input-group">
    <input type="text" name="search" class="form-control" placeholder="Search name or category..." value="{{ search }}">
    <button class="btn btn-outline-secondary" type="submit">Search</button>
  </div>
</form>

{% if low_stock %}
<div class="alert alert-warning">
  <strong>Low Stock Alert!</strong> {{ low_stock|length }} item(s) below threshold.
</div>
{% endif %}

<div class="table-responsive">
  <table class="table table-hover align-middle">
    <thead>
      <tr>
        <th>ID</th>
        <th>Name</th>
        <th>Category</th>
        <th class="text-center">Qty</th>
        <th class="text-end">Price</th>
        <th>Supplier</th>
        <th>Updated</th>
        <th class="text-center">Actions</th>
      </tr>
    </thead>
    <tbody>
      {% for p in products %}
      <tr {% if p.quantity < 5 %}class="low-stock"{% endif %}>
        <td>{{ p.id }}</td>
        <td><strong>{{ p.name }}</strong></td>
        <td>{{ p.category or '-' }}</td>
        <td class="text-center"><span class="badge bg-{{ 'danger' if p.quantity < 5 else 'secondary' }}">{{ p.quantity }}</span></td>
        <td class="text-end">{{ "%.2f"|format(p.price) }}</td>
        <td>{{ p.supplier or '-' }}</td>
        <td>{{ p.last_updated[:10] }}</td>
        <td class="text-center">
          <a href="{{ url_for('sell_product', pid=p.id) }}" class="btn btn-sm btn-success btn-action" title="Sell">
            <i class="bi bi-cart-check"></i>
          </a>
          <a href="{{ url_for('update_product', pid=p.id) }}" class="btn btn-sm btn-primary btn-action" title="Edit">
            <i class="bi bi-pencil"></i>
          </a>
          <a href="{{ url_for('delete_product', pid=p.id) }}" class="btn btn-sm btn-danger btn-action" title="Delete" onclick="return confirm('Delete {{ p.name }}?')">
            <i class="bi bi-trash"></i>
          </a>
        </td>
      </tr>
      {% endfor %}
    </tbody>
  </table>
</div>
{% endblock %}''',

    'add.html': '''{% extends "base.html" %}
{% block title %}Add Product{% endblock %}
{% block content %}
<h2>Add New Product</h2>
<div class="card p-4">
  <form method="post">
    <div class="row">
      <div class="col-md-6 mb-3">
        <label class="form-label">Name <span class="text-danger">*</span></label>
        <input type="text" name="name" class="form-control" required>
      </div>
      <div class="col-md-6 mb-3">
        <label class="form-label">Category</label>
        <input type="text" name="category" class="form-control">
      </div>
    </div>
    <div class="row">
      <div class="col-md-4 mb-3">
        <label class="form-label">Quantity</label>
        <input type="number" name="quantity" class="form-control" value="0" min="0">
      </div>
      <div class="col-md-4 mb-3">
        <label class="form-label">Price</label>
        <input type="number" name="price" class="form-control" step="0.01" value="0.00">
      </div>
      <div class="col-md-4 mb-3">
        <label class="form-label">Supplier</label>
        <input type="text" name="supplier" class="form-control">
      </div>
    </div>
    <button type="submit" class="btn btn-success">Add Product</button>
    <a href="{{ url_for('dashboard') }}" class="btn btn-secondary">Cancel</a>
  </form>
</div>
{% endblock %}''',

    'sell.html': '''{% extends "base.html" %}
{% block title %}Sell {{ product.name }}{% endblock %}
{% block content %}
<h2>Sell Product</h2>
<div class="card p-4">
  <div class="mb-4">
    <h4>{{ product.name }}</h4>
    <p class="mb-1"><strong>Available Stock:</strong> <span class="badge bg-secondary">{{ product.quantity }}</span></p>
    <p class="mb-1"><strong>Price:</strong> {{ "%.2f"|format(product.price) }}</p>
    <p><strong>Category:</strong> {{ product.category or '-' }}</p>
  </div>
  
  <form method="post">
    <div class="row">
      <div class="col-md-6 mb-3">
        <label class="form-label">Quantity to Sell</label>
        <input type="number" name="quantity" class="form-control" min="1" max="{{ product.quantity }}" value="1" required>
        <div class="form-text">Max available: {{ product.quantity }}</div>
      </div>
      <div class="col-md-6 mb-3">
        <label class="form-label">Unit Price</label>
        <input type="number" name="unit_price" class="form-control" step="0.01" value="{{ product.price }}" readonly>
      </div>
    </div>
    
    <div class="alert alert-info">
      <strong>Total Amount:</strong> <span id="totalAmount">{{ "%.2f"|format(product.price * 1) }}</span>
    </div>
    
    <button type="submit" class="btn btn-success">Confirm Sale</button>
    <a href="{{ url_for('dashboard') }}" class="btn btn-secondary">Cancel</a>
  </form>
</div>

<script>
  document.querySelector('input[name="quantity"]').addEventListener('input', function() {
    var quantity = parseInt(this.value) || 0;
    var price = {{ product.price }};
    var total = quantity * price;
    document.getElementById('totalAmount').textContent = total.toFixed(2);
  });
</script>
{% endblock %}''',

    'update.html': '''{% extends "base.html" %}
{% block title %}Update {{ product.name }}{% endblock %}
{% block content %}
<h2>Update Product</h2>
<div class="card p-4">
  <form method="post">
    <div class="row">
      <div class="col-md-6 mb-3">
        <label class="form-label">Name</label>
        <input type="text" name="name" class="form-control" value="{{ product.name }}" required>
      </div>
      <div class="col-md-6 mb-3">
        <label class="form-label">Category</label>
        <input type="text" name="category" class="form-control" value="{{ product.category }}">
      </div>
    </div>
    <div class="row">
      <div class="col-md-4 mb-3">
        <label class="form-label">Quantity</label>
        <input type="number" name="quantity" class="form-control" value="{{ product.quantity }}" min="0">
      </div>
      <div class="col-md-4 mb-3">
        <label class="form-label">Price</label>
        <input type="number" name="price" class="form-control" step="0.01" value="{{ product.price }}">
      </div>
      <div class="col-md-4 mb-3">
        <label class="form-label">Supplier</label>
        <input type="text" name="supplier" class="form-control" value="{{ product.supplier }}">
      </div>
    </div>
    <button type="submit" class="btn btn-primary">Save Changes</button>
    <a href="{{ url_for('dashboard') }}" class="btn btn-secondary">Cancel</a>
  </form>
</div>
{% endblock %}''',

    'history.html': '''{% extends "base.html" %}
{% block title %}Activity History{% endblock %}
{% block content %}
<h2>Activity History</h2>
<div class="table-responsive">
  <table class="table table-sm table-striped">
    <thead>
      <tr>
        <th>Time</th>
        <th>Action</th>
        <th>Product ID</th>
        <th>Qty Δ</th>
        <th>Note</th>
      </tr>
    </thead>
    <tbody>
      {% for h in history %}
      <tr>
        <td>{{ h.timestamp[:19].replace('T', ' ') }}</td>
        <td><span class="badge bg-{{ 'success' if h.action=='add' else 'primary' if h.action=='update' else 'warning' if h.action=='sell' else 'danger' }}">{{ h.action }}</span></td>
        <td>{{ h.product_id }}</td>
        <td>{{ h.qty_change or '-' }}</td>
        <td>{{ h.note }}</td>
      </tr>
      {% endfor %}
    </tbody>
  </table>
</div>
{% endblock %}''',

    'sales.html': '''{% extends "base.html" %}
{% block title %}Sales History{% endblock %}
{% block content %}
<h2>Sales History</h2>
<div class="table-responsive">
  <table class="table table-sm table-striped">
    <thead>
      <tr>
        <th>Date</th>
        <th>Time</th>
        <th>Product</th>
        <th>Quantity</th>
        <th>Unit Price</th>
        <th>Total Amount</th>
      </tr>
    </thead>
    <tbody>
      {% for sale in sales %}
      <tr>
        <td>{{ sale.sale_date }}</td>
        <td>{{ sale.timestamp[11:19] }}</td>
        <td>{{ sale.name }}</td>
        <td>{{ sale.quantity }}</td>
        <td>{{ "%.2f"|format(sale.unit_price) }}</td>
        <td><strong>{{ "%.2f"|format(sale.total_amount) }}</strong></td>
      </tr>
      {% endfor %}
    </tbody>
  </table>
</div>
<a href="{{ url_for('daily_report') }}" class="btn btn-info">
  <i class="bi bi-file-bar-graph"></i> View Daily Report
</a>
{% endblock %}''',

    'daily_report.html': '''{% extends "base.html" %}
{% block title %}Daily Report - {{ today }}{% endblock %}
{% block content %}
<div class="d-flex justify-content-between align-items-center mb-4">
  <h2>Daily Sales Report</h2>
  <div>
    <button onclick="window.print()" class="btn btn-outline-secondary btn-sm me-2">
      <i class="bi bi-printer"></i> Print
    </button>
    <a href="{{ url_for('export_csv') }}" class="btn btn-success btn-sm">
      <i class="bi bi-download"></i> Export CSV
    </a>
  </div>
</div>

<div class="row mb-4">
  <div class="col-md-4">
    <div class="card stat-card p-3">
      <h5 class="text-muted">Date</h5>
      <h3>{{ today }}</h3>
    </div>
  </div>
  <div class="col-md-4">
    <div class="card stat-card p-3">
      <h5 class="text-muted">Total Transactions</h5>
      <h3>{{ total_sales['count'] or 0 }}</h3>
    </div>
  </div>
  <div class="col-md-4">
    <div class="card stat-card p-3">
      <h5 class="text-muted">Total Revenue</h5>
      <h3>{{ "%.2f"|format(total_sales['total'] or 0) }}</h3>
    </div>
  </div>
</div>

<h4>Today's Sales</h4>
<div class="table-responsive mb-5">
  <table class="table table-hover">
    <thead>
      <tr>
        <th>Time</th>
        <th>Product</th>
        <th>Quantity</th>
        <th>Unit Price</th>
        <th>Total</th>
      </tr>
    </thead>
    <tbody>
      {% for sale in sales %}
      <tr>
        <td>{{ sale.timestamp[11:19] }}</td>
        <td>{{ sale.name }}</td>
        <td>{{ sale.quantity }}</td>
        <td>{{ "%.2f"|format(sale.unit_price) }}</td>
        <td><strong>{{ "%.2f"|format(sale.total_amount) }}</strong></td>
      </tr>
      {% endfor %}
    </tbody>
  </table>
</div>

{% if top_products %}
<h4>Top Selling Products Today</h4>
<div class="table-responsive">
  <table class="table table-sm">
    <thead>
      <tr>
        <th>Product</th>
        <th>Quantity Sold</th>
        <th>Revenue</th>
      </tr>
    </thead>
    <tbody>
      {% for product in top_products %}
      <tr>
        <td>{{ product.name }}</td>
        <td>{{ product.total_qty }}</td>
        <td>{{ "%.2f"|format(product.total_amount) }}</td>
      </tr>
      {% endfor %}
    </tbody>
  </table>
</div>
{% endif %}

{% if not sales %}
<div class="alert alert-info">
  <i class="bi bi-info-circle"></i> No sales recorded for today.
</div>
{% endif %}
{% endblock %}'''
}

# Auto-create template folder and files with force overwrite
def create_templates():
    import shutil
    # Delete existing templates folder to ensure clean creation
    if os.path.exists('templates'):
        shutil.rmtree('templates')
    
    os.makedirs('templates', exist_ok=True)
    for name, content in HTML_TEMPLATES.items():
        path = os.path.join('templates', name)
        with open(path, 'w', encoding='utf-8') as f:
            f.write(content)
        print(f"Created template: {name}")

create_templates()

# ─── Run App ───────────────────────────────────────────────────────────────
if __name__ == '__main__':
    print("\n🚀 StockFlow Pro Web App Starting...")
    print("   Open: http://127.0.0.1:5000")
    print("   First user? Go to /register\n")
    print("   Features:")
    print("   • Selling button (green cart icon) for each product")
    print("   • Daily sales report")
    print("   • Sales history tracking")
    print("   • Low stock alerts")
    print("   • CSV export")
    print("   • Fixed database locking issues\n")
    app.run(host='0.0.0.0', port=5000, debug=True)