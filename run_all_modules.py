from multiprocessing import Process
import os

def run_bruteforce():
    print("[*] Starting Bruteforce Detection Module")
    os.system("python3 /home/mahesh/mahesh2003/project/Module_Training/bruteforce_Attack/model_brute_force_finder_live.py > /home/mahesh/logs/bruteforce.log 2>&1")

def run_ddos():
    print("[*] Starting DDoS Detection Module")
    os.system("python3 /home/mahesh/mahesh2003/project/Module_Training/DDOS_Attack/model_ddos_attack_finder_live.py > /home/mahesh/logs/ddos.log 2>&1")

def run_sql():
    print("[*] Starting SQL Injection Detection Module")
    os.system("python3 /home/mahesh/mahesh2003/project/Module_Training/SQL_injection/model_sql_injuction_finder_live.py > /home/mahesh/logs/sqlinjection.log 2>&1")

def run_zero_day():
    print("[*] Starting Zero-Day Detection Module")
    os.system("python3 /home/mahesh/mahesh2003/project/Module_Training/Zero_exploration/model_Zero_exploration_finder_live.py > /home/mahesh/logs/zeroday.log 2>&1")

def run_telegram_alert():
    print("[*] Starting Telegram Alert Module")
    os.system("python3 /home/mahesh/mahesh2003/project/Telegram_alert/Telegram_alert.py > /home/mahesh/logs/telegram_alert.log 2>&1")

if __name__ == "__main__":
    # Create logs directory if it doesn't exist
    os.makedirs("/home/mahesh/logs", exist_ok=True)

    # Start all modules as parallel processes
    p1 = Process(target=run_bruteforce)
    p2 = Process(target=run_ddos)
    p3 = Process(target=run_sql)
    p4 = Process(target=run_zero_day)
    p5 = Process(target=run_telegram_alert)

    p1.start()
    p2.start()
    p3.start()
    p4.start()
    p5.start()

    # Optional: Do not block main process — remove joins for non-blocking mode
    # p1.join()
    # p2.join()
    # p3.join()
    # p4.join()
    # p5.join()
