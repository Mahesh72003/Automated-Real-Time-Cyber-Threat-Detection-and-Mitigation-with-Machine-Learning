import asyncio
from telegram import Bot
import json


# === Telegram Bot Setup ===
BOT_TOKEN = '7503247145:AAGKkFDTmRamUTreDS_IN2Joofq1EUv2Kqg'
CHAT_ID = '1542494811'
bot = Bot(token=BOT_TOKEN)
JSON_PATH = "/home/mahesh/mahesh2003/project/json log/finial_result.json"
# === Attack Type Mapping ===
attack_type_mapping = {
    'brute_force_log.json': 'Brute Force Attack',
    'ddos_log_live.json': 'DDOS Attack',
    'sql_injection_log.json': 'SQL Injection Attack',
    'ZeroDay_suspicious_ips.json': 'Zero-Day Exploit Attack'
}


def format_message(ip, info):
    type_attack = info.get("type_attack", "")
    attack_type = ""
    message_body = ""

    if type_attack == "brute_force_log.json":
        attack_type = "Brute Force Attack"
        message_body = (
            f"🔹 *Internal IP:* `{ip}`\n"
            f"🔹 *MAC Address:* `{info.get('mac_address', 'Unknown')}`\n"
            f"🔹 *Device Name:* {info.get('device_name', 'Unknown')}\n"
            f"🔹 *OS:* {info.get('os', 'Unknown')}\n"
            f"🔹 *External IP:* `{info['location'].get('ip', 'N/A')}`\n"
            f"🔹 *Location:* {info['location'].get('city', 'Unknown')}, {info['location'].get('region', 'Unknown')}, {info['location'].get('country', 'Unknown')}\n"
            f"🔹 *ISP:* {info['location'].get('isp', 'Unknown')}\n"
            f"🔹 *Protocol:* {info.get('protocol', 'Unknown')}\n"
            f"🔹 *Attempt Count:* {info.get('attempt_count', 'N/A')}\n"
            f"🔹 *Timestamp:* {info.get('timestamp', 'N/A')}\n"
            f"🔹 *IP Blocked:* {info.get('ip_blocked', 'false')}\n"
        )

    elif type_attack == "ddos_log_live.json":
        attack_type = "DDoS Attack"
        message_body = (
            f"🔹 *Internal IP:* `{ip}`\n"
            f"🔹 *MAC Address:* `{info.get('mac_address', 'Unknown')}`\n"
            f"🔹 *Device Name:* {info.get('device_name', 'Unknown')}\n"
            f"🔹 *OS:* {info.get('os', 'Unknown')}\n"
            f"🔹 *External IP:* `{info['location'].get('ip', 'N/A')}`\n"
            f"🔹 *Location:* {info['location'].get('city', 'Unknown')}, {info['location'].get('region', 'Unknown')}, {info['location'].get('country', 'Unknown')}\n"
            f"🔹 *ISP:* {info['location'].get('isp', 'Unknown')}\n"
            f"🔹 *Packets (1min):* {info.get('total_packets_1min', 'N/A')}\n"
            f"🔹 *Packets (7sec):* {info.get('total_packets_7sec', 'N/A')}\n"
            f"🔹 *Timestamp:* {info.get('timestamp', 'N/A')}\n"
            f"🔹 *IP Blocked:* {info.get('ip_blocked', 'false')}\n"
        )

    elif type_attack == "sql_injection_log.json":
        attack_type = "SQL Injection Attack"
        message_body = (
            f"🔹 *Internal IP:* `{ip}`\n"
            f"🔹 *MAC Address:* `{info.get('mac_address', 'Unknown')}`\n"
            f"🔹 *Device Name:* {info.get('device_name', 'Unknown')}\n"
            f"🔹 *OS:* {info.get('os', 'Unknown')}\n"
            f"🔹 *External IP:* `{info['location'].get('ip', 'N/A')}`\n"
            f"🔹 *Location:* {info['location'].get('city', 'Unknown')}, {info['location'].get('region', 'Unknown')}, {info['location'].get('country', 'Unknown')}\n"
            f"🔹 *ISP:* {info['location'].get('isp', 'Unknown')}\n"
            f"🔹 *Username Payload:* `{info.get('username', 'N/A')}`\n"
            f"🔹 *Password Payload:* `{info.get('password', 'N/A')}`\n"
            f"🔹 *Timestamp:* {info.get('timestamp', 'N/A')}\n"
            f"🔹 *IP Blocked:* {info.get('ip_blocked', 'false')}\n"
        )

    elif type_attack == "ZeroDay_suspicious_ips.json":
        attack_type = "Zero-Day Exploit Attack"
        protocols = ", ".join(info.get("protocols", []))
        message_body = (
            f"🔹 *Internal IP:* `{ip}`\n"
            f"🔹 *MAC Address:* `{info.get('mac_address', 'Unknown')}`\n"
            f"🔹 *Device Name:* {info.get('device_name', 'Unknown')}\n"
            f"🔹 *OS:* {info.get('os', 'Unknown')}\n"
            f"🔹 *External IP:* `{info['location'].get('ip', 'N/A')}`\n"
            f"🔹 *Location:* {info['location'].get('city', 'Unknown')}, {info['location'].get('region', 'Unknown')}, {info['location'].get('country', 'Unknown')}\n"
            f"🔹 *ISP:* {info['location'].get('isp', 'Unknown')}\n"
            f"🔹 *Suspicious Protocols:* {protocols or 'Unknown'}\n"
            f"🔹 *Count:* {info.get('count', 'N/A')}\n"
            f"🔹 *Timestamp:* {info.get('timestamp', 'N/A')}\n"
            f"🔹 *IP Blocked:* {info.get('ip_blocked', 'false')}\n"
        )

    else:
        attack_type = "Unknown Attack"
        message_body = "No detailed information available for this attack type."

    return (
        f"🚨 *Attack Detected!*\n\n"
        f"🚨 🚨 *Attack Type:* {attack_type}\n"
        f"*-------------------------------------------------------------*\n"
        f"{message_body}"
    )

# === Async Telegram Sender ===
async def send_alert_from_file():
    try:
        with open(JSON_PATH, 'r') as file:
            content = file.read().strip()

        if not content:
            print(f"[!] JSON file is empty: {JSON_PATH}")
            return

        data = json.loads(content)

        print("[*] Telegram message sending started...")

        for ip, info in data.items():
            message = format_message(ip, info)
            await bot.send_message(chat_id=CHAT_ID, text=message, parse_mode='Markdown')
            print(f"[+] Alert sent for IP: {ip}")
            await asyncio.sleep(0.5)  # To avoid flooding the API

        print("[?] All Telegram messages have been sent.")

    except json.JSONDecodeError as je:
        print(f"[!] JSON decoding failed: {je}")
    except Exception as e:
        print(f"[!] Error reading or sending message: {e}")
if __name__ == "__main__":
    asyncio.run(send_alert_from_file())
