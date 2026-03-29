import sqlite3
import os

# Always resolve path relative to THIS file — works from any working directory
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
db_path  = os.path.join(BASE_DIR, "database.db")

# Remove old DB so setup is always idempotent
if os.path.exists(db_path):
    os.remove(db_path)

con = sqlite3.connect(db_path)
cur = con.cursor()

# ── Create Tables ──────────────────────────────────────────────────────────────

# VULNERABILITY: No password hashing — passwords stored in plaintext
cur.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id           INTEGER PRIMARY KEY AUTOINCREMENT,
        username     TEXT    NOT NULL UNIQUE,
        password     TEXT    NOT NULL,
        dateOfBirth  TEXT,
        bio          TEXT,
        role         TEXT    DEFAULT "user"
    )
''')

cur.execute('''
    CREATE TABLE IF NOT EXISTS posts (
        id        INTEGER PRIMARY KEY AUTOINCREMENT,
        author    TEXT,
        content   TEXT,
        timestamp TEXT DEFAULT CURRENT_TIMESTAMP
    )
''')

cur.execute('''
    CREATE TABLE IF NOT EXISTS messages (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        sender     TEXT,
        recipient  TEXT,
        body       TEXT,
        timestamp  TEXT DEFAULT CURRENT_TIMESTAMP
    )
''')

# ── Seed Users ─────────────────────────────────────────────────────────────────
users = [
    ('admin',      '$2b$12$yA8bII4jcCipWIOa.B39ZuV/Wnffg3TINYDM2Bj58FOGrIqx9s5Rq', '01/01/1990', 'Site administrator. Here to keep things running.', 'admin'),
    ('GamerGirl',  '$2b$12$iXk1D.NR0KmnP4xbUAnEQO1BYorE0WJMSoSzKoP3NfXh7lKncY3P6', '15/05/2002', 'Casual gamer | Indie titles and retro consoles.', 'user'),
    ('TechNerd42', '$2b$12$puHlfNzCHSL2vSVAZfDKL.ylkSd2Ui8HVO5vRI4k5l3iWscr2Mb7G', '22/08/1998', 'Software dev by day, CTF player by night. Python fan.', 'user'),
    ('CryptoKing', '$2b$12$d0OHmK2/0W0SHMu4jfCJcehnX4HerV8cJglL8yP9f8HA/6Jcng4pa', '09/03/1995', 'Bitcoin maximalist. Not financial advice.', 'user'),
    ('Sarah_J',    '$2b$12$zvWvmIqM3yngn1oJr/TlEOfCXwCab5gvP9V/TqRN6SKLK//gf0aB6', '30/11/2001', 'Cat mum | Photography student | She/Her', 'user'),
    ('x0_h4ck3r',  '$2b$12$gm7TT83KiXo8gAvuQUQBou5mMy6c8BtJ875jyQDwqXSmyzauOpdbO', '14/02/1999', "Security researcher. I find bugs so you don't have to.", 'user'),
]

cur.executemany(
    "INSERT INTO users (username, password, dateOfBirth, bio, role) VALUES (?,?,?,?,?)",
    users
)

# ── Seed Posts ─────────────────────────────────────────────────────────────────
posts = [
    ('admin',      'Welcome to the Unsecure Social PWA! This platform is for educational use only. Explore, post, and see what you can find.'),
    ('GamerGirl',  "Can anyone tell me how to patch an XSS vulnerability? My friend's site keeps getting hit."),
    ('TechNerd42', 'Just finished a 48-hour CTF. Sleep is overrated. Flag captured: 3 out of 10 challenges. Still proud.'),
    ('CryptoKing', 'HODL. That is all.'),
    ('Sarah_J',    'Posted new photos to my portfolio! Let me know what you think. Link in bio.'),
    ('x0_h4ck3r',  'Friendly reminder: always sanitise your inputs. SQL injection is not dead. Not even close.'),
    ('admin',      'Reminder: do NOT share your password with anyone. Not even admins. Especially admins!'),
    ('GamerGirl',  'Anyone else think the login page feels slower for some usernames? Interesting...'),
    ('TechNerd42', 'Hot take: storing passwords in plaintext is technically just a feature for users who forget their password.'),
    ('Sarah_J',    'My cat walked across my keyboard and somehow managed to SQL inject my terminal. Talented beast.'),
    ('x0_h4ck3r',  'The service worker on this site caches everything including the feed page. Wonder what you could do with that.'),
    ('CryptoKing', 'My DMs are open if anyone wants to talk trading strategies. Not financial advice obviously.'),
]

cur.executemany("INSERT INTO posts (author, content) VALUES (?,?)", posts)

# ── Seed Messages ──────────────────────────────────────────────────────────────
messages = [
    ('admin',      'GamerGirl',  'Hey! Welcome to the platform. Let us know if you have any issues logging in.'),
    ('GamerGirl',  'admin',      'Thanks! Quick question — is there a way to change my password? I used qwerty and now I regret it.'),
    ('admin',      'GamerGirl',  'Ha! Probably a good idea. We will add a settings page soon. For now just re-register.'),
    ('TechNerd42', 'x0_h4ck3r', 'Did you see the login form? No rate limiting. No CSRF token. Beautiful disaster.'),
    ('x0_h4ck3r',  'TechNerd42','I saw. Also the service worker caches the feed. And the CORS is wide open. Lovely stuff.'),
    ('CryptoKing', 'Sarah_J',   'Hey your portfolio link in your bio is broken btw.'),
    ('Sarah_J',    'CryptoKing','Ugh, thanks for spotting that. Fixed now hopefully!'),
]

cur.executemany("INSERT INTO messages (sender, recipient, body) VALUES (?,?,?)", messages)

con.commit()
con.close()

print("=" * 55)
print("  database.db generated successfully!")
print("=" * 55)
print("  Users seeded:")
for u in users:
    print(f"    [{u[4]:5s}]  {u[0]:12s}  password: <bcrypt hash>")
print(f"  Posts seeded:     {len(posts)}")
print(f"  Messages seeded:  {len(messages)}")
print("=" * 55)
print("  Run:  python main.py")
print("=" * 55)
