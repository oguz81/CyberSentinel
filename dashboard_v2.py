import streamlit as st
import time
import re
import socket
import os
from sentinel_agent import get_rag_context, ask_claude 
import sentinel_tools as tools

# --- CONFIGURATION & PATTERNS ---
st.set_page_config(page_title="CYBER SENTINEL", layout="wide")
LOG_PATH = "/var/log/apache2/redmine_access.log" 
LOG_PATTERN = r'(?P<ip>[\d\.]+) - - \[(?P<timestamp>.*?)\] "(?P<method>\w+) (?P<path>.*?) HTTP/.*?" (?P<status>\d+) (?P<size>\d+|-) "(?P<referrer>.*?)" "(?P<user_agent>.*?)"'

def parse_line(line):
    match = re.search(LOG_PATTERN, line)
    if match:
        data = match.groupdict()
        data['path'] = data['path'].split('?')[0]
        return data
    return None

# --- SYSTEM DIAGNOSTIC CHECKS ---
def check_internet():
    try:
        socket.create_connection(("8.8.8.8", 53), timeout=1.5)
        return True
    except OSError:
        return False

def check_redmine():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1.0)
        result = s.connect_ex(('127.0.0.1', 80))
        s.close()
        return result == 0
    except:
        return False

# --- STATE INITIALIZATION ---
if "activities" not in st.session_state:
    st.session_state.activities = []
if "action_history" not in st.session_state:
    st.session_state.action_history = []
if "file_position" not in st.session_state:
    st.session_state.file_position = os.path.getsize(LOG_PATH) if os.path.exists(LOG_PATH) else 0

# --- BACKGROUND LOG POLLING ENGINE ---
def poll_new_logs():
    if not os.path.exists(LOG_PATH):
        return
    
    with open(LOG_PATH, "r") as f:
        f.seek(st.session_state.file_position)
        lines = f.readlines()
        st.session_state.file_position = f.tell()
        
        for line in lines:
            parsed_log = parse_line(line.strip())
            if not parsed_log:
                continue
                
            if parsed_log['status'] in ['403', '404', '500'] or parsed_log['method'] == 'POST' or "/etc/" in parsed_log['path']:
                context = get_rag_context(parsed_log) 
                report = ask_claude(parsed_log, context)
                
                new_event = {
                    "id": str(time.time_ns()), 
                    "ip": parsed_log['ip'],
                    "log": line.strip(),
                    "report": report,
                    "printed_at": time.strftime("%X"),
                    "alert_on": True
                }
                st.session_state.activities.insert(0, new_event)

poll_new_logs()

# --- 🚀 CUSTOM CSS INJECTION FOR SCROLLING & BLINKING ---
st.markdown("""
    <style>
    /* 1. Make the Incident Response Stream section independently scrollable */
    .scrollable-stream {
        max-height: 75vh;
        overflow-y: auto;
        padding-right: 15px;
        border: 1px solid rgba(49, 51, 63, 0.2);
        border-radius: 10px;
        padding: 15px;
        background-color: rgba(49, 51, 63, 0.02);
    }
    
    /* 2. Fast blinking animation class */
    .blink-fast {
        animation: blinker 0.4s linear infinite;
        font-size: 2rem;
        text-align: center;
        cursor: pointer;
        line-height: 1;
    }
    
    @keyframes blinker {
        50% { opacity: 0; }
    }
    </style>
""", unsafe_allow_html=True)

# --- INTERFACE LAYOUT GRAPHICS ---
st.title("🛡️ CYBER SENTINEL-- Real-time Log Monitor and Security System")
st.markdown("---")

left_panel, right_panel = st.columns([1, 3], gap="large")

# --- LEFT PANEL: STATUS & HISTORY (Stays Fixed) ---
with left_panel:
    st.markdown("### 📊 System Infrastructure")
    
    is_online = check_internet()
    if is_online:
        st.success("🌐 Internet Access: ONLINE")
    else:
        st.error("🛑 Internet Access: OFFLINE")
        
    is_redmine_up = check_redmine()
    if is_redmine_up:
        st.success("🦊 Redmine Server: ONLINE")
    else:
        st.error("🚨 Redmine Server: OFFLINE")
        
    st.markdown("---")
    
    st.markdown("### 📜 Action History (Last 10)")
    if not st.session_state.action_history:
        st.caption("No mitigation defenses executed yet.")
    else:
        for action in st.session_state.action_history[:10]:
            st.info(action)

# --- RIGHT PANEL: LIVE ACTIVITY CELLS (Independent Scroll) ---
with right_panel:
    st.markdown("### 📡 Real-time Incident Response Stream")
    
    # Open the HTML wrapper tag for independent scrolling
    st.markdown('<div class="scrollable-stream">', unsafe_allow_html=True)
    
    if not st.session_state.activities:
        st.info("System quiet. Monitoring active network vectors cleanly...")
    
    for act in st.session_state.activities:
        with st.container(border=True):
            cell_data, cell_controls, cell_alert = st.columns([3, 1, 0.4])
            
            with cell_data:
                st.markdown("**Raw Log Signature:**")
                st.code(act['log'], language="bash")
                st.markdown(f"🧠 **AI SOC Analyst Evaluation** *(Published to stream at: `{act['printed_at']}`)*:")
                st.markdown(act['report'])
                
            with cell_controls:
                st.markdown("<p style='text-align: center; font-weight: bold;'>Mitigation Manual</p>", unsafe_allow_html=True)
                
                if st.button("🚫 Drop IP", key=f"drop_{act['id']}", use_container_width=True):
                    success = tools.drop_ip(act['ip'])
                    status = "SUCCESS" if success else "FAILED"
                    st.session_state.action_history.insert(0, f"[{time.strftime('%X')}] Drop IP vs {act['ip']}: {status}")
                    st.rerun()
                    
                if st.button("💥 Kill Sockets", key=f"kill_{act['id']}", use_container_width=True):
                    success = tools.kill_active_connections(act['ip'])
                    status = "SUCCESS" if success else "FAILED"
                    st.session_state.action_history.insert(0, f"[{time.strftime('%X')}] Kill Sockets vs {act['ip']}: {status}")
                    st.rerun()
                    
                if st.button("⏳ Throttle", key=f"throt_{act['id']}", use_container_width=True):
                    success = tools.throttle_ip(act['ip'], requests_per_minute=5)
                    status = "SUCCESS" if success else "FAILED"
                    st.session_state.action_history.insert(0, f"[{time.strftime('%X')}] Throttle vs {act['ip']}: {status}")
                    st.rerun()
            
            with cell_alert:
                st.markdown("<p style='text-align: center; font-weight: bold;'>Alert</p>", unsafe_allow_html=True)
                
                if act['alert_on']:
                    # Native Streamlit buttons don't animate well, so we use HTML string inside a small button component
                    if st.button("🔴 Acknowledge", key=f"light_{act['id']}", help="Click to turn off fast-blinking light", use_container_width=True):
                        act['alert_on'] = False
                        st.rerun()
                    # Renders a custom blinking circle indicator right below the acknowledgement button
                    st.markdown('<div class="blink-fast">🔴</div>', unsafe_allow_html=True)
                else:
                    st.markdown("<h3 style='text-align: center; color: gray;'>⚪</h3>", unsafe_allow_html=True)
                    
    # Close the HTML wrapper tag for independent scrolling
    st.markdown('</div>', unsafe_allow_html=True)

# --- AUTOREFRESH LOOP EXECUTION ---
time.sleep(1.0)
st.rerun()