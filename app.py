import streamlit as st
import sqlite3
from datetime import datetime
import os
from streamlit_cookies_manager import EncryptedCookieManager
from streamlit_autorefresh import st_autorefresh

# Initialize cookie manager
cookies = EncryptedCookieManager(
    prefix="mychat/1.0/",
    password=os.environ.get("COOKIES_PASSWORD", "your-very-secret-password")
)

if not cookies.ready():
    st.stop()

# Database connection
conn = sqlite3.connect('chat_app.db', check_same_thread=False)
c = conn.cursor()

# Create tables if not exist
c.execute("""
CREATE TABLE IF NOT EXISTS users (
    username TEXT PRIMARY KEY,
    password TEXT NOT NULL
)
""")
c.execute("""
CREATE TABLE IF NOT EXISTS messages (
    sender TEXT,
    receiver TEXT,
    timestamp TEXT,
    message TEXT
)
""")
conn.commit()

# Functions for register, authenticate, send, and get messages
def register(username, password):
    try:
        c.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, password))
        conn.commit()
        return True
    except:
        return False

def authenticate(username, password):
    c.execute("SELECT * FROM users WHERE username=? AND password=?", (username, password))
    return c.fetchone() is not None

def send_message(sender, receiver, message):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    c.execute("INSERT INTO messages (sender, receiver, timestamp, message) VALUES (?, ?, ?, ?)",
              (sender, receiver, timestamp, message))
    conn.commit()

def get_messages(user1, user2):
    c.execute("""
    SELECT sender, receiver, timestamp, message FROM messages 
    WHERE (sender=? AND receiver=?) OR (sender=? AND receiver=?) 
    ORDER BY timestamp ASC
    """, (user1, user2, user2, user1))
    return c.fetchall()

# Session state initialization
if 'logged_in' not in st.session_state:
    st.session_state.logged_in = False
    st.session_state.username = ''

# Auto-login via cookies
if not st.session_state.logged_in:
    saved_user = cookies.get('username')
    saved_pass = cookies.get('password')
    if saved_user and saved_pass and authenticate(saved_user, saved_pass):
        st.session_state.logged_in = True
        st.session_state.username = saved_user

st.title("Private Chatting")

if not st.session_state.logged_in:
    menu = st.sidebar.selectbox("Menu", ["Login", "Register"])
    if menu == "Register":
        st.header("Register")
        new_user = st.text_input("New Username", key="reg_user")
        new_pass = st.text_input("New Password", type="password", key="reg_pass")
        if st.button("Register"):
            if new_user.strip() == "" or new_pass.strip() == "":
                st.error("Username and password cannot be empty")
            elif register(new_user.strip(), new_pass.strip()):
                st.success("Registration successful! Please login.")
            else:
                st.error("Username already exists or registration error.")
    else:
        st.header("Login")
        user = st.text_input("Username", key="login_user")
        pwd = st.text_input("Password", type="password", key="login_pass")
        if st.button("Login"):
            if authenticate(user.strip(), pwd.strip()):
                st.session_state.logged_in = True
                st.session_state.username = user.strip()
                cookies['username'] = user.strip()
                cookies['password'] = pwd.strip()
                cookies.save()
                st.rerun()
            else:
                st.error("Invalid username or password.")

else:
    st.sidebar.write(f"Logged in as: **{st.session_state.username}**")
    if st.sidebar.button("Logout"):
        st.session_state.logged_in = False
        st.session_state.username = ''
        cookies['username'] = ""
        cookies['password'] = ""
        cookies.save()
        st.rerun()

    c.execute("SELECT username FROM users WHERE username != ?", (st.session_state.username,))
    others = [row[0] for row in c.fetchall()]
    if others:
        chat_with = st.sidebar.selectbox("Chat with:", others)
    else:
        chat_with = None

    if chat_with:
        st.subheader(f"Chat with {chat_with}")

        # Auto-refresh messages every 3 seconds
        st_autorefresh(interval=3000, key="message_refresh")

        messages = get_messages(st.session_state.username, chat_with)
        for sender, receiver, timestamp, msg in messages:
            align = "right" if sender == st.session_state.username else "left"
            color = "#639AD8" if sender == st.session_state.username else "#639AD8"
            st.markdown(
                f"<div style='text-align:{align}; padding: 5px;'>"
                f"<span style='background-color:{color}; padding:8px; border-radius:10px; display:inline-block; max-width:60%;'>"
                f"<b>{sender}</b>: {msg}<br><small style='font-size:10px;'>{timestamp}</small></span></div>",
                unsafe_allow_html=True,
            )

        # Message input form with auto-clear
        with st.form(key=f"form_{chat_with}", clear_on_submit=True):
            new_msg = st.text_input("Type a message", key=f"input_{chat_with}")
            send_button = st.form_submit_button("Send")

            if send_button and new_msg.strip():
                send_message(st.session_state.username, chat_with, new_msg.strip())
                st.rerun()
    else:
        st.info("No other users registered to chat with yet.")

# Save cookies
cookies.save()
