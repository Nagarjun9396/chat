import streamlit as st
import sqlite3
from datetime import datetime
import os
from streamlit_cookies_manager import EncryptedCookieManager
from streamlit_autorefresh import st_autorefresh
import pytz

ist = pytz.timezone("Asia/Kolkata")

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
    password TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'user'   -- new column for roles
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

# ---------------- Functions ----------------
def register(username, password, role="user"):
    try:
        c.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", 
                  (username, password, role))
        conn.commit()
        return True
    except:
        return False

def authenticate(username, password):
    c.execute("SELECT * FROM users WHERE username=? AND password=?", (username, password))
    return c.fetchone() is not None

def get_role(username):
    c.execute("SELECT role FROM users WHERE username=?", (username,))
    row = c.fetchone()
    return row[0] if row else None

def send_message(sender, receiver, message):
    timestamp = datetime.now(ist).strftime("%Y-%m-%d %I:%M:%S %p")
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

# -------- Admin Functions --------
def delete_user(username):
    c.execute("DELETE FROM users WHERE username=?", (username,))
    c.execute("DELETE FROM messages WHERE sender=? OR receiver=?", (username, username))
    conn.commit()

def change_password(username, new_password):
    c.execute("UPDATE users SET password=? WHERE username=?", (new_password, username))
    conn.commit()

def clear_chat_history():
    c.execute("DELETE FROM messages")
    conn.commit()

# ---------------- Session State ----------------
if 'logged_in' not in st.session_state:
    st.session_state.logged_in = False
    st.session_state.username = ''
    st.session_state.role = 'user'

# Auto-login via cookies
if not st.session_state.logged_in:
    saved_user = cookies.get('username')
    saved_pass = cookies.get('password')
    if saved_user and saved_pass and authenticate(saved_user, saved_pass):
        st.session_state.logged_in = True
        st.session_state.username = saved_user
        st.session_state.role = get_role(saved_user)

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
                st.session_state.role = get_role(user.strip())
                cookies['username'] = user.strip()
                cookies['password'] = pwd.strip()
                cookies.save()
                st.rerun()
            else:
                st.error("Invalid username or password.")

else:
    st.sidebar.write(f"Logged in as: **{st.session_state.username}** ({st.session_state.role})")
    if st.sidebar.button("Logout"):
        st.session_state.logged_in = False
        st.session_state.username = ''
        st.session_state.role = 'user'
        cookies['username'] = ""
        cookies['password'] = ""
        cookies.save()
        st.rerun()

    # If admin, show admin panel
    if st.session_state.role == "admin":
        st.sidebar.subheader("⚙️ Admin Panel")
        admin_action = st.sidebar.radio("Choose action:", 
                                        ["Manage Users", "Change Passwords", "Clear Chats"])

        if admin_action == "Manage Users":
            st.subheader("User Management")
            c.execute("SELECT username FROM users WHERE username != ?", (st.session_state.username,))
            users = [u[0] for u in c.fetchall()]
            if users:
                user_to_delete = st.selectbox("Select user to delete:", users)
                if st.button("Delete User"):
                    delete_user(user_to_delete)
                    st.success(f"User {user_to_delete} deleted along with their chats.")

            # Add user directly
            st.subheader("Add User")
            new_user = st.text_input("New Username")
            new_pass = st.text_input("New Password", type="password")
            if st.button("Add User"):
                if register(new_user.strip(), new_pass.strip()):
                    st.success("User added successfully")
                else:
                    st.error("User already exists!")

        elif admin_action == "Change Passwords":
            st.subheader("Change User Password")
            c.execute("SELECT username FROM users")
            users = [u[0] for u in c.fetchall()]
            target_user = st.selectbox("Select user:", users)
            new_pass = st.text_input("New Password", type="password")
            if st.button("Change Password"):
                change_password(target_user, new_pass.strip())
                st.success(f"Password updated for {target_user}")

        elif admin_action == "Clear Chats":
            if st.button("Clear All Chat History"):
                clear_chat_history()
                st.success("All chat history cleared!")

    # Normal Chat UI for everyone
    c.execute("SELECT username FROM users WHERE username != ?", (st.session_state.username,))
    others = [row[0] for row in c.fetchall()]
    if others:
        chat_with = st.sidebar.selectbox("Chat with:", others)
    else:
        chat_with = None

    if chat_with:
        st.subheader(f"Chat with {chat_with}")

        st_autorefresh(interval=3000, key="message_refresh")

        messages = get_messages(st.session_state.username, chat_with)
        for sender, receiver, timestamp, msg in messages:
            align = "right" if sender == st.session_state.username else "left"
            color = "#639AD8"
            st.markdown(
                f"<div style='text-align:{align}; padding: 5px;'>"
                f"<span style='background-color:{color}; padding:8px; border-radius:10px; display:inline-block; max-width:60%;'>"
                f"{msg}<br><small style='font-size:10px;'>{timestamp}</small></span></div>",
                unsafe_allow_html=True,
            )

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
