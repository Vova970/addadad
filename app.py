from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
import secrets

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)
app.config['DATABASE'] = 'database.db'
app.config['TELEGRAM_BOT_URL'] = 'https://t.me/aoubebfoubewfpiwnfbot'  # Замените на ссылку вашего бота

# Инициализация БД
def init_db():
    conn = sqlite3.connect(app.config['DATABASE'])
    cursor = conn.cursor()
    
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS categories (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL
    )
    ''')
    
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS products (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        category_id INTEGER,
        name TEXT NOT NULL,
        description TEXT,
        price INTEGER NOT NULL,
        item TEXT NOT NULL,
        FOREIGN KEY (category_id) REFERENCES categories (id)
    )
    ''')
    
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS special_offers (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        description TEXT,
        price_rub INTEGER NOT NULL,
        price_uah INTEGER NOT NULL,
        price_usd INTEGER NOT NULL
    )
    ''')
    
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        telegram_id TEXT UNIQUE NOT NULL,
        telegram_name TEXT NOT NULL,
        balance INTEGER DEFAULT 0,
        auth_token TEXT UNIQUE,
        last_login TEXT
    )
    ''')
    
    # Админ по умолчанию
    admin = cursor.execute('SELECT * FROM users WHERE telegram_id = "admin"').fetchone()
    if not admin:
        cursor.execute(
            'INSERT INTO users (telegram_id, telegram_name, auth_token) VALUES (?, ?, ?)',
            ('admin', 'Admin', secrets.token_hex(16))
        )
    
    conn.commit()
    conn.close()

init_db()

def get_db():
    conn = sqlite3.connect(app.config['DATABASE'])
    conn.row_factory = sqlite3.Row
    return conn

# Telegram Auth
@app.route('/auth/telegram', methods=['POST'])
def telegram_auth():
    data = request.json
    if not data or 'id' not in data or 'first_name' not in data:
        return jsonify({'error': 'Invalid data'}), 400
    
    conn = get_db()
    user = conn.execute(
        'SELECT * FROM users WHERE telegram_id = ?',
        (str(data['id']),)
    ).fetchone()
    
    if not user:
        auth_token = secrets.token_hex(16)
        conn.execute(
            'INSERT INTO users (telegram_id, telegram_name, auth_token) VALUES (?, ?, ?)',
            (str(data['id']), data['first_name'], auth_token)
        )
    else:
        auth_token = secrets.token_hex(16)
        conn.execute(
            'UPDATE users SET auth_token = ?, last_login = datetime("now") WHERE telegram_id = ?',
            (auth_token, str(data['id']))
        )
    
    conn.commit()
    conn.close()
    
    return jsonify({
        'status': 'success',
        'auth_token': auth_token,
        'redirect': url_for('index')
    })

@app.route('/auth/complete')
def auth_complete():
    # Проверяем реферер (что переход с Telegram)
    if request.referrer and 'telegram.org' in request.referrer:
        flash('Авторизация через Telegram успешно завершена!', 'success')
    return redirect(url_for('index'))

@app.route('/auth/telegram_redirect')
def telegram_redirect():
    # Перенаправление в бота с callback_url
    callback_url = url_for('auth_complete', _external=True)
    bot_url = f"https://t.me/aoubebfoubewfpiwnfbot?start=login_{secrets.token_urlsafe(8)}"
    return redirect(bot_url)

@app.route('/auth/check')
def check_auth():
    token = request.args.get('token')
    if not token:
        return jsonify({'authenticated': False})
    
    conn = get_db()
    user = conn.execute('SELECT * FROM users WHERE auth_token = ?', (token,)).fetchone()
    conn.close()
    
    if user:
        return jsonify({
            'authenticated': True,
            'user': {
                'id': user['telegram_id'],
                'name': user['telegram_name'],
                'balance': user['balance']
            }
        })
    return jsonify({'authenticated': False})

# Основные маршруты
@app.route('/')
def index():
    conn = get_db()
    categories = conn.execute('SELECT * FROM categories').fetchall()
    special_offers = conn.execute('SELECT * FROM special_offers LIMIT 3').fetchall()
    conn.close()
    
    return render_template('index.html', 
                         categories=categories,
                         special_offers=special_offers)

@app.route('/category/<int:category_id>')
def category(category_id):
    conn = get_db()
    category = conn.execute('SELECT * FROM categories WHERE id = ?', (category_id,)).fetchone()
    products = conn.execute('SELECT id, name, price FROM products WHERE category_id = ?', (category_id,)).fetchall()
    conn.close()
    
    if not category:
        flash('Категория не найдена', 'error')
        return redirect(url_for('index'))
    
    return render_template('category.html', category=category, products=products)

@app.route('/special_offers')
def all_special_offers():
    conn = get_db()
    offers = conn.execute('SELECT * FROM special_offers').fetchall()
    conn.close()
    return render_template('special_offers.html', offers=offers)

@app.route('/special_offer/<int:offer_id>')
def special_offer(offer_id):
    conn = get_db()
    offer = conn.execute('SELECT * FROM special_offers WHERE id = ?', (offer_id,)).fetchone()
    conn.close()
    
    if not offer:
        flash('Предложение не найдено', 'error')
        return redirect(url_for('all_special_offers'))
    
    return render_template('special_offer.html', offer=offer)

@app.route('/product/<int:product_id>')
def product(product_id):
    conn = get_db()
    product = conn.execute('''
        SELECT p.*, c.name as category_name 
        FROM products p 
        JOIN categories c ON p.category_id = c.id 
        WHERE p.id = ?
    ''', (product_id,)).fetchone()
    conn.close()
    
    if not product:
        flash('Товар не найден', 'error')
        return redirect(url_for('index'))
    
    return render_template('product.html', product=product)

@app.route('/login')
def login():
    if 'user_id' in session:
        return redirect(url_for('index'))
    return redirect(url_for('telegram_redirect'))

@app.route('/logout')
def logout():
    if 'user_id' in session:
        # Инвалидация токена
        conn = get_db()
        conn.execute(
            'UPDATE users SET auth_token = NULL WHERE telegram_id = ?',
            (session['telegram_id'],)
        )
        conn.commit()
        conn.close()
    
    session.clear()
    flash('Вы вышли из системы', 'success')
    return redirect(url_for('index'))

@app.route('/profile')
def profile():
    if 'user_id' not in session:
        flash('Пожалуйста, войдите в систему', 'error')
        return redirect(url_for('login'))
    
    conn = get_db()
    user = conn.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    conn.close()
    
    return render_template('profile.html', user=user)

@app.route('/admin', methods=['GET', 'POST'])
def admin():
    # Проверка через telegram_id == 'admin'
    if 'user_id' not in session or session.get('telegram_id') != 'admin':
        flash('Доступ запрещен', 'error')
        return redirect(url_for('index'))
    
    conn = get_db()
    
    if request.method == 'POST':
        if 'add_category' in request.form:
            name = request.form['category_name']
            conn.execute('INSERT INTO categories (name) VALUES (?)', (name,))
            conn.commit()
            flash('Категория добавлена', 'success')
        
        elif 'add_product' in request.form:
            category_id = request.form['category_id']
            name = request.form['product_name']
            description = request.form['description']
            price = request.form['price']
            item = request.form['item']
            
            conn.execute(
                'INSERT INTO products (category_id, name, description, price, item) VALUES (?, ?, ?, ?, ?)',
                (category_id, name, description, price, item)
            )
            conn.commit()
            flash('Товар добавлен', 'success')
    
    categories = conn.execute('SELECT * FROM categories').fetchall()
    products = conn.execute('SELECT p.*, c.name as category_name FROM products p JOIN categories c ON p.category_id = c.id').fetchall()
    conn.close()
    
    return render_template('admin.html', categories=categories, products=products)

@app.route('/buy/<int:product_id>')
def buy(product_id):
    if 'user_id' not in session:
        flash('Пожалуйста, войдите в систему', 'error')
        return redirect(url_for('login'))
    
    conn = get_db()
    product = conn.execute('SELECT * FROM products WHERE id = ?', (product_id,)).fetchone()
    user = conn.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    
    if not product or not user:
        conn.close()
        flash('Ошибка при покупке', 'error')
        return redirect(url_for('index'))
    
    if user['balance'] < product['price']:
        conn.close()
        flash('Недостаточно средств', 'error')
        return redirect(url_for('profile'))
    
    # Обновляем баланс
    new_balance = user['balance'] - product['price']
    conn.execute('UPDATE users SET balance = ? WHERE id = ?', (new_balance, user['id']))
    conn.commit()
    conn.close()
    
    flash(f'Вы купили: {product["name"]}. Получите: {product["item"]}', 'success')
    return redirect(url_for('profile'))

if __name__ == '__main__':
    app.run(debug=True)