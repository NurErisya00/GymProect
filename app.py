# GymProject/app.py

from flask import Flask, render_template, request, redirect, url_for, session, g
import sqlite3
import click
from flask.cli import with_appcontext
# ***** STEP 1: Import hashing functions *****
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
# SECURITY RISK: Use a strong, random secret key loaded from config/env variables
app.secret_key = "supersecretkey"

# BEST PRACTICE: Load database path from config/env variables
DATABASE = 'members.db'


USERS = {
    "staff": {"password_hash": generate_password_hash("staffpass"), "role": "staff"},
    "member": {"password_hash": generate_password_hash("memberpass"), "role": "member"},
    "pakkarim": {"password_hash": generate_password_hash("karim"), "role": "staff"}
    # Example using manually generated hash (yours will differ):plaintext password
    # "staff": {"password_hash": "pbkdf2:sha256:600000$...", "role": "staff"},
    # "member": {"password_hash": "pbkdf2:sha256:600000$...", "role": "member"},
    # "pakkarim": {"password_hash": "pbkdf2:sha256:600000$...", "role": "staff"}
}



def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row # Optional: Return rows that behave like dicts
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def query_db(query, args=(), one=False):
    try:
        cur = get_db().execute(query, args)
        rv = cur.fetchall()
        # Note: `cur.close()` is typically not needed here
        return (rv[0] if rv else None) if one else rv
    except sqlite3.Error as e:
        print(f"Database query error: {e}")
        return None if one else []

# (Keep @app.before_request create_tables as before)
@app.before_request
def create_tables():
    try:
        db = get_db()
        db.execute('''CREATE TABLE IF NOT EXISTS members (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        name TEXT NOT NULL,
                        membership_status TEXT NOT NULL
                      )''')
        db.execute('''CREATE TABLE IF NOT EXISTS classes (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        class_name TEXT NOT NULL,
                        class_time TEXT NOT NULL
                      )''')
        db.execute('''CREATE TABLE IF NOT EXISTS member_classes (
                        member_id INTEGER,
                        class_id INTEGER,
                        PRIMARY KEY (member_id, class_id), -- Avoid duplicate registrations
                        FOREIGN KEY (member_id) REFERENCES members (id) ON DELETE CASCADE, -- Cascade delete
                        FOREIGN KEY (class_id) REFERENCES classes (id) ON DELETE CASCADE
                      )''')
        db.commit()
    except sqlite3.Error as e:
        print(f"Database table creation error: {e}")


# --- Flask CLI Command (Keep populate-classes as before) ---

@click.command('populate-classes')
@with_appcontext
def populate_classes_command():
    """Inserts initial class data into the classes table."""
    classes_data = [
        ('Pilates', 'Mon 10:00 AM'), ('Kick Boxing', 'Tue 5:00 PM'), ('Silat', 'Wed 6:00 PM'),
        ('Zumba', 'Thu 7:00 PM'), ('Personal Session', 'Flexible'), ('Cardio', 'Fri 6:00 AM'),
        ('Strength and Flexibility', 'Sat 8:00 AM')
    ]
    db = get_db()
    cursor = db.cursor()
    try:
        cursor.execute("SELECT COUNT(*) FROM classes")
        count = cursor.fetchone()[0]
        if count > 0:
            click.echo("Classes table already populated. Skipping insertion.")
            return
        sql = "INSERT INTO classes (class_name, class_time) VALUES (?, ?)"
        db.executemany(sql, classes_data)
        db.commit()
        click.echo(f"Successfully inserted {len(classes_data)} records into the 'classes' table.")
    except sqlite3.Error as e:
        db.rollback()
        click.echo(f"An error occurred during population: {e}", err=True)

app.cli.add_command(populate_classes_command)


# --- Web Application Routes ---

@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password'] # Plaintext password from form

        user_data = USERS.get(username) # Get user data from dict

        # ***** STEP 3: Check HASHED password *****
        if user_data and check_password_hash(user_data['password_hash'], password):
            # Password matches!
            session['user'] = username
            session['role'] = user_data['role']
            # Optional: Add flash message for success
            return redirect(url_for('dashboard'))
        else:
            # Invalid username or password
            # BEST PRACTICE: Use flash messages for feedback
            return render_template('login.html', error="Invalid username or password.")

    # For GET request
    return render_template('login.html')

# --- Keep all other routes as they were in the previous version ---
# (/dashboard, /add_member, /register_member, /view_members, /member/<id>/classes,
#  /register_class/<id>, /add_class, /delete_member/<id>, /view_classes, /logout)

@app.route('/dashboard')
def dashboard():
    if 'user' not in session:
        return redirect(url_for('login'))
    username = session['user']
    role = session.get('role', 'member')
    return render_template('dashboard.html', username=username, role=role)

@app.route('/add_member', methods=['GET', 'POST'])
def add_member():
    if 'user' not in session or session.get('role') != 'staff':
        return redirect(url_for('login'))
    if request.method == 'POST':
        name = request.form['name']
        status = request.form['status']
        if not name or not status:
             return render_template('add_member.html', error="Name and status cannot be empty")
        try:
            db = get_db()
            db.execute("INSERT INTO members (name, membership_status) VALUES (?, ?)", (name, status))
            db.commit()
            return redirect(url_for('view_members'))
        except sqlite3.Error as e:
            print(f"Error adding member: {e}")
            return render_template('add_member.html', error="Failed to add member")
    return render_template('add_member.html')

@app.route('/register_member', methods=['GET', 'POST'])
def register_member():
    if 'user' not in session or session.get('role') != 'staff':
        return redirect(url_for('login'))
    if request.method == 'POST':
        name = request.form['name']
        status = request.form['status']
        if not name or not status:
            return render_template('register_member.html', error="Name and status cannot be empty")
        try:
            db = get_db()
            db.execute("INSERT INTO members (name, membership_status) VALUES (?,?)", (name, status))
            db.commit()
            return redirect(url_for('view_members'))
        except sqlite3.Error as e:
            print(f"Error registering member: {e}")
            return render_template('register_member.html', error="Failed to register member")
    return render_template('register_member.html')

@app.route('/view_members')
def view_members():
    if 'user' not in session or session.get('role') != 'staff':
        return redirect(url_for('login'))
    members = query_db("SELECT * FROM members ORDER BY name")
    if members is None:
         return "Error fetching members from database", 500
    return render_template('view_members.html', members=members)

@app.route('/member/<int:member_id>/classes')
def member_classes(member_id):
    if 'user' not in session:
        return redirect(url_for('login'))
    member = query_db("SELECT * FROM members WHERE id = ?", [member_id], one=True)
    if not member:
        return "Member not found", 404
    registered_classes = query_db(
        "SELECT c.id, c.class_name, c.class_time FROM classes c "
        "JOIN member_classes mc ON c.id = mc.class_id "
        "WHERE mc.member_id = ? ORDER BY c.class_name", [member_id]
        )
    if registered_classes is None:
        return "Error fetching member classes", 500
    member_dict = dict(member) if member else None
    classes_list = [dict(cls) for cls in registered_classes] if registered_classes else []
    return render_template('member_classes.html', member=member_dict, classes=classes_list)

@app.route('/register_class/<int:member_id>', methods=['GET', 'POST'])
def register_class(member_id):
    if 'user' not in session or session.get('role') != 'staff':
        return redirect(url_for('login'))
    member = query_db("SELECT id, name FROM members WHERE id = ?", [member_id], one=True)
    if not member:
        return "Member not found", 404
    if request.method == 'POST':
        class_id = request.form.get('class_id', type=int)
        if not class_id:
             available_classes_post = query_db(
                 "SELECT id, class_name, class_time FROM classes "
                 "WHERE id NOT IN (SELECT class_id FROM member_classes WHERE member_id = ?) "
                 "ORDER BY class_name", [member_id]
             )
             classes_list_post = [dict(cls) for cls in available_classes_post] if available_classes_post else []
             return render_template('register_class.html', member=dict(member), classes=classes_list_post, error="Invalid class selected")
        try:
            db = get_db()
            existing = query_db("SELECT 1 FROM member_classes WHERE member_id = ? AND class_id = ?", [member_id, class_id], one=True)
            if existing:
                print(f"Member {member_id} already registered for class {class_id}")
            else:
                db.execute("INSERT INTO member_classes (member_id, class_id) VALUES (?, ?)", (member_id, class_id))
                db.commit()
                print(f"Registered member {member_id} for class {class_id}")
            return redirect(url_for('member_classes', member_id=member_id))
        except sqlite3.IntegrityError:
             print(f"Integrity error registering class {class_id} for member {member_id}")
             available_classes_err = query_db("SELECT id, class_name, class_time FROM classes WHERE id NOT IN (SELECT class_id FROM member_classes WHERE member_id = ?) ORDER BY class_name", [member_id])
             classes_list_err = [dict(cls) for cls in available_classes_err] if available_classes_err else []
             return render_template('register_class.html', member=dict(member), classes=classes_list_err, error="Already registered or invalid class.")
        except sqlite3.Error as e:
            print(f"Error registering class for member {member_id}: {e}")
            available_classes_err2 = query_db("SELECT id, class_name, class_time FROM classes WHERE id NOT IN (SELECT class_id FROM member_classes WHERE member_id = ?) ORDER BY class_name", [member_id])
            classes_list_err2 = [dict(cls) for cls in available_classes_err2] if available_classes_err2 else []
            return render_template('register_class.html', member=dict(member), classes=classes_list_err2, error="Failed to register class")

    available_classes = query_db("SELECT id, class_name, class_time FROM classes WHERE id NOT IN (SELECT class_id FROM member_classes WHERE member_id = ?) ORDER BY class_name", [member_id])
    if available_classes is None:
        return "Error fetching available classes", 500
    member_dict = dict(member) if member else None
    classes_list = [dict(cls) for cls in available_classes] if available_classes else []
    return render_template('register_class.html', member=member_dict, classes=classes_list)


@app.route('/add_class', methods=['GET', 'POST'])
def add_class():
    if 'user' not in session or session.get('role') != 'staff':
        return redirect(url_for('login'))
    if request.method == 'POST':
        class_name = request.form['class_name']
        class_time = request.form['class_time']
        if not class_name or not class_time:
            return render_template('add_class.html', error="Class name and time cannot be empty")
        try:
            db = get_db()
            db.execute("INSERT INTO classes (class_name, class_time) VALUES (?, ?)", (class_name, class_time))
            db.commit()
            return redirect(url_for('view_classes'))
        except sqlite3.Error as e:
            print(f"Error adding class: {e}")
            return render_template('add_class.html', error="Failed to add class")
    return render_template('add_class.html')

@app.route('/delete_member/<int:member_id>', methods=['POST'])
def delete_member(member_id):
    if 'user' not in session or session.get('role') != 'staff':
        return redirect(url_for('login'))
    try:
        db = get_db()
        cursor = db.execute("DELETE FROM members WHERE id = ?", [member_id])
        if cursor.rowcount == 0:
             print(f"Member {member_id} not found for deletion.")
             return redirect(url_for('view_members'))
        db.commit()
        print(f"Member {member_id} deleted successfully.")
        return redirect(url_for('view_members'))
    except sqlite3.Error as e:
        print(f"Error deleting member {member_id}: {e}")
        return redirect(url_for('view_members'))

@app.route('/view_classes')
def view_classes():
    if 'user' not in session:
        return redirect(url_for('login'))
    classes = query_db("SELECT * FROM classes ORDER BY class_name")
    if classes is None:
        return "Error fetching classes", 500
    classes_list = [dict(cls) for cls in classes] if classes else []
    return render_template('view_classes.html', classes=classes_list)

@app.route('/logout')
def logout():
    session.pop('user', None)
    session.pop('role', None)
    return redirect(url_for('login'))

# --- Main Execution ---

if __name__ == '__main__':
    app.run(debug=True)