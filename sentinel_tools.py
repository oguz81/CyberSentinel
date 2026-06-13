import subprocess
import logging

# Setup basic logging for forensic auditing
logging.basicConfig(filename="sentinel_actions.log", level=logging.INFO,
                    format="%(asctime)s - %(levelname)s - %(message)s")

# 🛡️ THE IMMUNITY SHIELD
# Never allow the agent to block localhost or your physical development host machine
WHITELISTED_IPS = ["127.0.0.1", "192.168.1.105"] 

def _is_safe(ip):
    if ip in WHITELISTED_IPS:
        print(f"⚠️ SAFETY TRIGGERED: Prevented defensive action against whitelisted IP: {ip}")
        logging.warning(f"Safety shield triggered for whitelisted IP: {ip}")
        return False
    return True

def drop_ip(ip):
    """Instantly drops all network traffic from the target IP."""
    if not _is_safe(ip): return False
    
    try:
        # -A INPUT: Append to incoming traffic rules
        # -s: Source IP
        # -j DROP: Silently discard the packets
        cmd = ["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"]
        subprocess.run(cmd, check=True)
        
        msg = f"🚫 IP_DROP executed successfully against {ip}."
        print(msg)
        logging.info(msg)
        return True
    except subprocess.CalledProcessError as e:
        logging.error(f"Failed to execute IP_DROP against {ip}: {e}")
        return False

def kill_active_connections(ip):
    """Forcibly tears down all open TCP sockets belonging to the target IP."""
    if not _is_safe(ip): return False
    
    try:
        # ss -K: Socket Statistics utility with the Kill flag
        # dst: Destination matching the attacker's IP address
        cmd = ["sudo", "ss", "-K", "dst", ip]
        result = subprocess.run(cmd, check=True, capture_output=True, text=True)
        
        msg = f"💥 CONNECTION_DROP executed. Terminated active sockets for {ip}."
        print(msg)
        logging.info(msg)
        return True
    except subprocess.CalledProcessError as e:
        # ss -K can return non-zero if no active connections exist at that exact millisecond
        logging.warning(f"Connection kill command finished for {ip} (may have already closed).")
        return True

def throttle_ip(ip, requests_per_minute=5):
    """Throttles incoming traffic from an IP if it exceeds a threshold."""
    if not _is_safe(ip): return False
    
    try:
        # Standard iptables limit module creates a bucket threshold
        # Allows up to x requests per minute, then matches and drops the excess
        cmd_limit = [
            "sudo", "iptables", "-A", "INPUT", "-s", ip, 
            "-m", "limit", f"--limit", f"{requests_per_minute}/minute", "-j", "ACCEPT"
        ]
        cmd_drop = ["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"]
        
        subprocess.run(cmd_limit, check=True)
        subprocess.run(cmd_drop, check=True)
        
        msg = f"⏳ RATE_LIMIT active for {ip}. Throttled to {requests_per_minute}/min."
        print(msg)
        logging.info(msg)
        return True
    except subprocess.CalledProcessError as e:
        logging.error(f"Failed to apply RATE_LIMIT to {ip}: {e}")
        return False
