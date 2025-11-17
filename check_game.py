from appium import webdriver
from appium.webdriver.common.appiumby import AppiumBy
import time
import threading
import queue
import os
from colorama import init, Fore, Style
import subprocess

init(autoreset=True)

# ==================== CẤU HÌNH ====================
THREAD_COUNT = 1  # Appium chỉ hỗ trợ 1 thiết bị/lần (có thể scale bằng nhiều máy ảo)
INPUT_FILE = "accounts.txt"
OUTPUT_DIR = "result"
APPIUM_PORT = 4723
DEVICE_NAME = "emulator-5554"  # Xem bằng: adb devices
APP_PACKAGE = "com.garena.game.kgvn"  # Liên Quân VN
APP_ACTIVITY = "com.garena.game.kgvn.ShellActivity"

# Tạo thư mục
os.makedirs(OUTPUT_DIR, exist_ok=True)
ALIVE_FILE = os.path.join(OUTPUT_DIR, "alive.txt")
BANNED_FILE = os.path.join(OUTPUT_DIR, "banned.txt")
ERROR_FILE = os.path.join(OUTPUT_DIR, "error.txt")

account_queue = queue.Queue()
lock = threading.Lock()

# ================================================

def start_appium():
    print(f"{Fore.CYAN}[Appium] Khởi động server trên cổng {APPIUM_PORT}...")
    subprocess.Popen(["appium", "-p", str(APPIUM_PORT)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(5)

def get_driver():
    desired_caps = {
        "platformName": "Android",
        "deviceName": DEVICE_NAME,
        "appPackage": APP_PACKAGE,
        "appActivity": APP_ACTIVITY,
        "automationName": "UiAutomator2",
        "noReset": False,
        "fullReset": False,
        "newCommandTimeout": 300,
        "adbExecTimeout": 30000
    }
    try:
        driver = webdriver.Remote(f"http://localhost:{APPIUM_PORT}", desired_caps)
        driver.implicitly_wait(10)
        return driver
    except Exception as e:
        print(f"{Fore.RED}[Appium] Lỗi kết nối: {e}")
        return None

def login_and_check(driver, username, password):
    try:
        # B1: Mở app → chờ màn hình đăng nhập
        time.sleep(8)

        # Nhấn "Đăng nhập bằng Garena"
        try:
            btn_garena = driver.find_element(AppiumBy.XPATH, "//android.widget.TextView[contains(@text, 'Garena')]")
            btn_garena.click()
            time.sleep(3)
        except:
            pass  # Đã ở màn hình login

        # Nhập username
        try:
            input_user = driver.find_element(AppiumBy.XPATH, "//android.widget.EditText[@resource-id='username' or contains(@text, 'Tài khoản')]")
            input_user.clear()
            input_user.send_keys(username)
            time.sleep(1)
        except:
            pass

        # Nhập password
        try:
            input_pass = driver.find_element(AppiumBy.XPATH, "//android.widget.EditText[@resource-id='password' or contains(@text, 'Mật khẩu')]")
            input_pass.clear()
            input_pass.send_keys(password)
            time.sleep(1)
        except:
            pass

        # Nhấn Đăng nhập
        try:
            btn_login = driver.find_element(AppiumBy.XPATH, "//android.widget.Button[contains(@text, 'Đăng nhập')]")
            btn_login.click()
        except:
            try:
                driver.tap([(500, 1200)])  # Tap giữa màn hình nếu không thấy nút
            except:
                pass

        print(f"{Fore.YELLOW}[Đang đăng nhập] {username}")
        time.sleep(10)  # Chờ phản hồi

        # Kiểm tra kết quả
        current_activity = driver.current_activity

        # Nếu vào được sảnh chính
        if "Lobby" in current_activity or "Home" in current_activity:
            return "ALIVE"

        # Kiểm tra popup lỗi
        try:
            error_text = driver.find_element(AppiumBy.XPATH, "//android.widget.TextView[contains(@text, '10009') or contains(@text, '10010') or contains(@text, 'bị khóa') or contains(@text, 'banned')]")
            if error_text:
                return "BANNED"
        except:
            pass

        # Kiểm tra nút "OK" của popup lỗi
        try:
            ok_btn = driver.find_element(AppiumBy.XPATH, "//android.widget.Button[contains(@text, 'OK')]")
            if ok_btn:
                return "BANNED"
        except:
            pass

        # Nếu vẫn ở login → sai pass
        if "Login" in current_activity or "sso" in driver.current_package:
            return "ERROR"

        return "ERROR"

    except Exception as e:
        return "ERROR"

def process_account():
    driver = get_driver()
    if not driver:
        return

    while True:
        try:
            line = account_queue.get_nowait()
        except queue.Empty:
            break

        line = line.strip()
        if not line or "|" not in line:
            account_queue.task_done()
            continue

        username, password = line.split("|", 1)
        username = username.strip()
        password = password.strip()

        print(f"{Fore.CYAN}[Bắt đầu] {username}")

        result = login_and_check(driver, username, password)

        with lock:
            if result == "ALIVE":
                with open(ALIVE_FILE, "a", encoding="utf-8") as f:
                    f.write(f"{username}|{password} | CÒN SỐNG\n")
                print(f"{Fore.GREEN}[CÒN SỐNG] {username}")
            elif result == "BANNED":
                with open(BANNED_FILE, "a", encoding="utf-8") as f:
                    f.write(f"{username}|{password} | BỊ BAN\n")
                print(f"{Fore.RED}[BỊ BAN] {username}")
            else:
                with open(ERROR_FILE, "a", encoding="utf-8") as f:
                    f.write(f"{username}|{password} | Sai pass / Lỗi\n")
                print(f"{Fore.MAGENTA}[LỖI] {username}")

        # Reset app sau mỗi lần kiểm tra
        driver.terminate_app(APP_PACKAGE)
        time.sleep(3)
        driver.activate_app(APP_PACKAGE)
        time.sleep(5)

        account_queue.task_done()
        time.sleep(2)

    driver.quit()

def main():
    print(f"{Fore.CYAN}=== LIÊN QUÂN AUTO LOGIN - GIẢ LẬP THIẾT BỊ ===")
    print(f"{Fore.YELLOW}Thiết bị: {DEVICE_NAME}")
    print(f"{Fore.YELLOW}App: {APP_PACKAGE}\n")

    # Khởi động Appium
    start_appium()

    # Đọc acc
    if not os.path.exists(INPUT_FILE):
        print(f"{Fore.RED}Không tìm thấy {INPUT_FILE}")
        return

    with open(INPUT_FILE, "r", encoding="utf-8") as f:
        lines = [l for l in f.readlines() if l.strip()]

    for line in lines:
        account_queue.put(line)

    print(f"{Fore.CYAN}Tổng acc: {len(lines)}\n")

    # Xóa file cũ
    for f in [ALIVE_FILE, BANNED_FILE, ERROR_FILE]:
        if os.path.exists(f): os.remove(f)

    # Chạy (chỉ 1 luồng vì 1 thiết bị)
    process_account()

    print(f"\n{Fore.CYAN}HOÀN TẤT!")
    print(f"{Fore.GREEN}Còn sống → {ALIVE_FILE}")
    print(f"{Fore.RED}Bị ban → {BANNED_FILE}")
    print(f"{Fore.MAGENTA}Lỗi → {ERROR_FILE}")

if __name__ == "__main__":
    main()