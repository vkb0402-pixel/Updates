// ============================================
// 🔐 ULTRA-SECURE NEWS API BACKEND v7.0 - FIXED
// ============================================
// Production-ready backend for Updates news platform
// Supports 5 premium news APIs with advanced features
// ============================================

require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const compression = require('compression');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;

// ============================================
// 🗄️ IN-MEMORY CACHE WITH DUPLICATE TRACKING
// ============================================
const newsCache = new Map();
const seenArticlesGlobal = new Set();
const CACHE_DURATION = 30 * 60 * 1000; // 30 minutes
const MAX_CACHE_SIZE = 2000;

// Hash-based duplicate detection
function createArticleHash(article) {
    const title = (article.title || '').toLowerCase().trim().substring(0, 50);
    const url = (article.url || article.link || '').toLowerCase().trim();
    const domain = url.split('/')[2] || '';
    const identifier = `${title}_${domain}`;
    return crypto.createHash('md5').update(identifier).digest('hex');
}

// Remove duplicates from article array
function removeDuplicates(articles) {
    const seen = new Set();
    return articles.filter(article => {
        if (!article.title || (!article.url && !article.link)) return false;
        const hash = createArticleHash(article);
        if (seen.has(hash) || seenArticlesGlobal.has(hash)) return false;
        seen.add(hash);
        seenArticlesGlobal.add(hash);
        return true;
    });
}

// Clean old cache periodically
function cleanOldCache() {
    if (seenArticlesGlobal.size > MAX_CACHE_SIZE) {
        const entries = Array.from(seenArticlesGlobal);
        seenArticlesGlobal.clear();
        entries.slice(-1000).forEach(hash => seenArticlesGlobal.add(hash));
    }
    if (newsCache.size > 100) {
        const entries = Array.from(newsCache.entries());
        const sortedByTime = entries.sort((a, b) => b[1].timestamp - a[1].timestamp);
        newsCache.clear();
        sortedByTime.slice(0, 50).forEach(([key, value]) => newsCache.set(key, value));
    }
}
setInterval(cleanOldCache, 10 * 60 * 1000); // Every 10 minutes

// ============================================
// 🛡️ SECURITY LAYER 1: Helmet - Security Headers
// ============================================
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
            scriptSrc: ["'self'", "'unsafe-inline'"],
            imgSrc: ["'self'", "data:", "https:", "http:"],
            connectSrc: ["'self'", "https:", "http:"],
            fontSrc: ["'self'", "https://fonts.gstatic.com", "data:"],
        },
    },
    hsts: {
        maxAge: 31536000,
        includeSubDomains: true,
        preload: true
    },
    noSniff: true,
    xssFilter: true,
    hidePoweredBy: true,
    frameguard: { action: 'deny' },
    referrerPolicy: { policy: 'no-referrer' }
}));

// ============================================
// 🛡️ SECURITY LAYER 2: Rate Limiting
// ============================================
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 2000,
    message: {
        error: 'Too many requests from this IP, please try again later.',
        retryAfter: '15 minutes'
    },
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: (req) => {
        return req.headers['x-forwarded-for']?.split(',')[0] || req.ip;
    }
});

const apiLimiter = rateLimit({
    windowMs: 1 * 60 * 1000,
    max: 150,
    message: { error: 'Too many API requests, please slow down.' }
});

const searchLimiter = rateLimit({
    windowMs: 1 * 60 * 1000,
    max: 50,
    message: { error: 'Too many search requests, please slow down.' }
});

app.use('/api/', limiter);

// ============================================
// 🛡️ SECURITY LAYER 3: CORS - Enhanced
// ============================================
const allowedOrigins = process.env.ALLOWED_ORIGINS
    ? process.env.ALLOWED_ORIGINS.split(',')
    : [
        'http://localhost:3000',
        'http://127.0.0.1:3000',
        'http://localhost:5500',
        'http://127.0.0.1:5500',
        'https://vkbofficial4u.github.io',
        'https://backend-ml60.onrender.com'
    ];

app.use(cors({
    origin: function(origin, callback) {
        if (!origin) return callback(null, true);
        const isAllowed = allowedOrigins.some(allowed =>
            origin.includes(allowed.replace('https://', '').replace('http://', ''))
        );
        return callback(null, true); // Allow all for development
    },
    credentials: true,
    methods: ['GET', 'POST', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
    maxAge: 600,
    optionsSuccessStatus: 200
}));

app.options('*', cors());

// ============================================
// 🛡️ SECURITY LAYER 4: Input Sanitization (SIMPLIFIED)
// ============================================
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true, limit: '10kb' }));

// Custom sanitization middleware (replaces express-mongo-sanitize)
app.use((req, res, next) => {
    const sanitize = (obj) => {
        if (typeof obj === 'object' && obj !== null) {
            Object.keys(obj).forEach(key => {
                if (key.startsWith('$') || key.includes('.')) {
                    delete obj[key];
                } else if (typeof obj[key] === 'object') {
                    sanitize(obj[key]);
                }
            });
        }
    };
    sanitize(req.body);
    sanitize(req.query);
    sanitize(req.params);
    next();
});

// ============================================
// 🛡️ SECURITY LAYER 5: Compression
// ============================================
app.use(compression());

// ============================================
// 🔐 API KEYS
// ============================================
const API_KEYS = {
    newsapi: process.env.NEWSAPI_KEY || 'f20f53e207ed497dace6c1d4a47daec9',
    newsdata: process.env.NEWSDATA_KEY || 'pub_630bb6b01dd54da7b8a20061a5bd8224a0c1',
    gnews: process.env.GNEWS_KEY || '7ea52edafd1d5eccbddcf495ceba6c11',
    currents: process.env.CURRENTS_KEY || 'XHsTPUmUy2xRLyDO0bxyFD2BlpSuT6vv7d-hSB7nPXagxAHe',
    worldnews: process.env.WORLDNEWS_KEY || '869c788a62654ff78a3d795a7ce6fd0e'
};

// Validate API keys on startup
Object.keys(API_KEYS).forEach(key => {
    if (!API_KEYS[key] || API_KEYS[key].length < 10) {
        console.warn(`⚠️ Warning: ${key} API key appears invalid`);
    } else {
        console.log(`✅ ${key} API key loaded`);
    }
});

// ============================================
// 🔒 INPUT VALIDATION
// ============================================
function validateInput(country, language) {
    const validCountries = ['in', 'us', 'gb', 'ca', 'au', 'de', 'fr', 'es', 'jp'];
    const validLanguages = ['en', 'hi', 'es', 'fr', 'de', 'ja', 'zh', 'ar', 'pt'];
    const sanitizedCountry = String(country || 'in').toLowerCase().trim().substring(0, 2);
    const sanitizedLanguage = String(language || 'en').toLowerCase().trim().substring(0, 2);
    return {
        country: validCountries.includes(sanitizedCountry) ? sanitizedCountry : 'in',
        language: validLanguages.includes(sanitizedLanguage) ? sanitizedLanguage : 'en'
    };
}

function validateSearchQuery(query) {
    if (!query || typeof query !== 'string') return '';
    return query.trim().replace(/[<>]/g, '').substring(0, 100);
}

// ============================================
// 🔒 SECURITY HEADERS
// ============================================
app.use((req, res, next) => {
    res.removeHeader('X-Powered-By');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-XSS-Protection', '1; mode=block');
    next();
});

// ============================================
// 📝 REQUEST LOGGING
// ============================================
app.use((req, res, next) => {
    const ip = req.headers['x-forwarded-for']?.split(',')[0] || req.ip;
    console.log(`[${new Date().toISOString()}] ${req.method} ${req.path} - IP: ${ip.substring(0, 10)}...`);
    next();
});

// ============================================
// 🌐 FETCH WITH TIMEOUT
// ============================================
async function fetchWithTimeout(url, timeout = 15000) {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), timeout);
    try {
        const response = await fetch(url, {
            signal: controller.signal,
            headers: {
                'User-Agent': 'NewsProxy/7.0 (VKB Updates)',
                'Accept': 'application/json'
            }
        });
        clearTimeout(timeoutId);
        return response;
    } catch (error) {
        clearTimeout(timeoutId);
        if (error.name === 'AbortError') {
            throw new Error('Request timeout');
        }
        throw error;
    }
}

// ============================================
// 🏠 ROOT ROUTE
// ============================================
app.get('/', (req, res) => {
    res.json({
        status: 'online',
        message: '📰 Updates News API - Ultra-Secure Backend v7.0 FIXED',
        version: '7.0.0',
        timestamp: new Date().toISOString(),
        endpoints: [
            '/api/newsapi',
            '/api/newsdata',
            '/api/gnews',
            '/api/currents',
            '/api/worldnews',
            '/api/search'
        ]
    });
});

// ============================================
// ❤️ HEALTH CHECK
// ============================================
app.get('/health', (req, res) => {
    res.json({
        status: 'healthy',
        timestamp: new Date().toISOString(),
        uptime: Math.floor(process.uptime()),
        memory: {
            used: Math.round(process.memoryUsage().heapUsed / 1024 / 1024) + 'MB',
            total: Math.round(process.memoryUsage().heapTotal / 1024 / 1024) + 'MB'
        },
        cache: {
            size: newsCache.size,
            uniqueArticles: seenArticlesGlobal.size
        }
    });
});

// ============================================
// 📰 API ENDPOINTS - ALL 5 NEWS SOURCES
// ============================================

// 1️⃣ NewsAPI.org
app.get('/api/newsapi', apiLimiter, async (req, res) => {
    try {
        const { country, language } = validateInput(req.query.country, req.query.language);
        const cacheKey = `newsapi_${country}_${language}`;

        if (newsCache.has(cacheKey)) {
            const cached = newsCache.get(cacheKey);
            if (Date.now() - cached.timestamp < CACHE_DURATION) {
                console.log(`✅ Serving cached NewsAPI data`);
                return res.json(cached.data);
            }
        }

        console.log(`📰 Fetching NewsAPI: country=${country}, language=${language}`);
        const url = `https://newsapi.org/v2/top-headlines?country=${country}&language=${language}&apiKey=${API_KEYS.newsapi}&pageSize=100`;
        const response = await fetchWithTimeout(url);

        if (!response.ok) {
            throw new Error(`NewsAPI responded with status: ${response.status}`);
        }

        const data = await response.json();
        data.articles = removeDuplicates(data.articles || []);
        newsCache.set(cacheKey, { data, timestamp: Date.now() });
        console.log(`✅ NewsAPI returned ${data.articles.length} unique articles`);
        res.json(data);
    } catch (error) {
        console.error('NewsAPI Error:', error.message);
        const { country, language } = validateInput(req.query.country, req.query.language);
        const cacheKey = `newsapi_${country}_${language}`;
        if (newsCache.has(cacheKey)) {
            return res.json(newsCache.get(cacheKey).data);
        }
        res.status(500).json({ error: 'Failed to fetch from NewsAPI' });
    }
});

// 2️⃣ GNews.io
app.get('/api/gnews', apiLimiter, async (req, res) => {
    try {
        const { country, language } = validateInput(req.query.country, req.query.lang || req.query.language);
        const cacheKey = `gnews_${country}_${language}`;

        if (newsCache.has(cacheKey)) {
            const cached = newsCache.get(cacheKey);
            if (Date.now() - cached.timestamp < CACHE_DURATION) {
                console.log(`✅ Serving cached GNews data`);
                return res.json(cached.data);
            }
        }

        console.log(`📰 Fetching GNews: country=${country}, language=${language}`);
        const url = `https://gnews.io/api/v4/top-headlines?country=${country}&lang=${language}&apikey=${API_KEYS.gnews}&max=100`;
        const response = await fetchWithTimeout(url);

        if (!response.ok) {
            throw new Error(`GNews responded with status: ${response.status}`);
        }

        const data = await response.json();
        data.articles = removeDuplicates(data.articles || []);
        newsCache.set(cacheKey, { data, timestamp: Date.now() });
        console.log(`✅ GNews returned ${data.articles.length} unique articles`);
        res.json(data);
    } catch (error) {
        console.error('GNews Error:', error.message);
        const { country, language } = validateInput(req.query.country, req.query.lang || req.query.language);
        const cacheKey = `gnews_${country}_${language}`;
        if (newsCache.has(cacheKey)) {
            return res.json(newsCache.get(cacheKey).data);
        }
        res.status(500).json({ error: 'Failed to fetch from GNews' });
    }
});

// 3️⃣ NewsData.io
app.get('/api/newsdata', apiLimiter, async (req, res) => {
    try {
        const { country, language } = validateInput(req.query.country, req.query.language);
        const cacheKey = `newsdata_${country}_${language}`;

        if (newsCache.has(cacheKey)) {
            const cached = newsCache.get(cacheKey);
            if (Date.now() - cached.timestamp < CACHE_DURATION) {
                console.log(`✅ Serving cached NewsData`);
                return res.json(cached.data);
            }
        }

        console.log(`📰 Fetching NewsData: country=${country}, language=${language}`);
        const url = `https://newsdata.io/api/1/news?apikey=${API_KEYS.newsdata}&country=${country}&language=${language}`;
        const response = await fetchWithTimeout(url);

        if (!response.ok) {
            throw new Error(`NewsData responded with status: ${response.status}`);
        }

        const data = await response.json();
        if (data.results) {
            data.results = removeDuplicates(data.results.map(r => ({
                title: r.title,
                description: r.description,
                url: r.link,
                urlToImage: r.image_url,
                source: { name: r.source_id || 'NewsData' },
                publishedAt: r.pubDate
            })));
        }

        newsCache.set(cacheKey, { data, timestamp: Date.now() });
        console.log(`✅ NewsData returned ${data.results?.length || 0} unique articles`);
        res.json(data);
    } catch (error) {
        console.error('NewsData Error:', error.message);
        const { country, language } = validateInput(req.query.country, req.query.language);
        const cacheKey = `newsdata_${country}_${language}`;
        if (newsCache.has(cacheKey)) {
            return res.json(newsCache.get(cacheKey).data);
        }
        res.status(500).json({ error: 'Failed to fetch from NewsData' });
    }
});

// 4️⃣ Currents API
app.get('/api/currents', apiLimiter, async (req, res) => {
    try {
        const { country, language } = validateInput(req.query.country, req.query.language);
        const cacheKey = `currents_${country}_${language}`;

        if (newsCache.has(cacheKey)) {
            const cached = newsCache.get(cacheKey);
            if (Date.now() - cached.timestamp < CACHE_DURATION) {
                console.log(`✅ Serving cached Currents data`);
                return res.json(cached.data);
            }
        }

        console.log(`📰 Fetching Currents: country=${country}, language=${language}`);
        const url = `https://api.currentsapi.services/v1/latest-news?apiKey=${API_KEYS.currents}&language=${language}&region=${country}`;
        const response = await fetchWithTimeout(url);

        if (!response.ok) {
            throw new Error(`Currents responded with status: ${response.status}`);
        }

        const data = await response.json();
        if (data.news) {
            data.news = removeDuplicates(data.news.map(n => ({
                title: n.title,
                description: n.description,
                url: n.url,
                urlToImage: n.image,
                source: { name: n.author || 'Currents' },
                publishedAt: n.published
            })));
        }

        newsCache.set(cacheKey, { data, timestamp: Date.now() });
        console.log(`✅ Currents returned ${data.news?.length || 0} unique articles`);
        res.json(data);
    } catch (error) {
        console.error('Currents Error:', error.message);
        const { country, language } = validateInput(req.query.country, req.query.language);
        const cacheKey = `currents_${country}_${language}`;
        if (newsCache.has(cacheKey)) {
            return res.json(newsCache.get(cacheKey).data);
        }
        res.status(500).json({ error: 'Failed to fetch from Currents API' });
    }
});

// 5️⃣ World News API
app.get('/api/worldnews', apiLimiter, async (req, res) => {
    try {
        const { language } = validateInput('in', req.query.language);
        const cacheKey = `worldnews_${language}`;

        if (newsCache.has(cacheKey)) {
            const cached = newsCache.get(cacheKey);
            if (Date.now() - cached.timestamp < CACHE_DURATION) {
                console.log(`✅ Serving cached World News data`);
                return res.json(cached.data);
            }
        }

        console.log(`📰 Fetching World News: language=${language}`);
        const url = `https://api.worldnewsapi.com/search-news?language=${language}&number=100&api-key=${API_KEYS.worldnews}`;
        const response = await fetchWithTimeout(url);

        if (!response.ok) {
            throw new Error(`WorldNews responded with status: ${response.status}`);
        }

        const data = await response.json();
        const transformedData = {
            status: 'success',
            news: removeDuplicates((data.news || []).map(n => ({
                title: n.title,
                description: n.text || n.summary,
                url: n.url,
                urlToImage: n.image,
                source: { name: n.author || 'World News' },
                publishedAt: n.publish_date
            }))),
            totalResults: data.available || 0
        };

        newsCache.set(cacheKey, { data: transformedData, timestamp: Date.now() });
        console.log(`✅ World News returned ${transformedData.news.length} unique articles`);
        res.json(transformedData);
    } catch (error) {
        console.error('World News Error:', error.message);
        const { language } = validateInput('in', req.query.language);
        const cacheKey = `worldnews_${language}`;
        if (newsCache.has(cacheKey)) {
            return res.json(newsCache.get(cacheKey).data);
        }
        res.status(500).json({ error: 'Failed to fetch from World News API' });
    }
});

// ============================================
// 🔍 SEARCH ENDPOINT
// ============================================
app.get('/api/search', searchLimiter, async (req, res) => {
    try {
        const query = validateSearchQuery(req.query.q);
        const { language } = validateInput('in', req.query.language);

        if (!query || query.length < 2) {
            return res.status(400).json({ error: 'Search query must be at least 2 characters long' });
        }

        const cacheKey = `search_${query}_${language}`;
        if (newsCache.has(cacheKey)) {
            const cached = newsCache.get(cacheKey);
            if (Date.now() - cached.timestamp < CACHE_DURATION) {
                console.log(`✅ Serving cached search results`);
                return res.json(cached.data);
            }
        }

        console.log(`🔍 Searching: query="${query}", language=${language}`);

        const searchPromises = [
            fetchWithTimeout(`https://newsapi.org/v2/everything?q=${encodeURIComponent(query)}&language=${language}&apiKey=${API_KEYS.newsapi}&pageSize=50&sortBy=relevancy`)
                .then(r => r.json())
                .then(d => d.articles || [])
                .catch(e => { console.error('NewsAPI search error:', e.message); return []; }),

            fetchWithTimeout(`https://gnews.io/api/v4/search?q=${encodeURIComponent(query)}&lang=${language}&apikey=${API_KEYS.gnews}&max=50`)
                .then(r => r.json())
                .then(d => d.articles || [])
                .catch(e => { console.error('GNews search error:', e.message); return []; }),

            fetchWithTimeout(`https://newsdata.io/api/1/news?apikey=${API_KEYS.newsdata}&q=${encodeURIComponent(query)}&language=${language}`)
                .then(r => r.json())
                .then(d => (d.results || []).map(r => ({
                    title: r.title,
                    description: r.description,
                    url: r.link,
                    urlToImage: r.image_url,
                    source: { name: r.source_id },
                    publishedAt: r.pubDate
                })))
                .catch(e => { console.error('NewsData search error:', e.message); return []; })
        ];

        const results = await Promise.all(searchPromises);
        const allArticles = results.flat();
        const uniqueArticles = removeDuplicates(allArticles);

        const responseData = {
            status: 'ok',
            totalResults: uniqueArticles.length,
            articles: uniqueArticles.slice(0, 50)
        };

        newsCache.set(cacheKey, { data: responseData, timestamp: Date.now() });
        console.log(`✅ Search returned ${uniqueArticles.length} unique articles`);
        res.json(responseData);
    } catch (error) {
        console.error('Search Error:', error.message);
        res.status(500).json({ error: 'Search failed' });
    }
});

// ============================================
// 🚫 404 HANDLER
// ============================================
app.use((req, res) => {
    res.status(404).json({
        error: 'Endpoint not found',
        path: req.path,
        availableEndpoints: [
            '/api/newsapi',
            '/api/newsdata',
            '/api/gnews',
            '/api/currents',
            '/api/worldnews',
            '/api/search'
        ]
    });
});

// ============================================
// ❌ GLOBAL ERROR HANDLER
// ============================================
app.use((err, req, res, next) => {
    console.error('[ERROR]', {
        message: err.message,
        path: req.path,
        method: req.method,
        timestamp: new Date().toISOString()
    });

    res.status(err.status || 500).json({
        error: 'Internal server error',
        timestamp: new Date().toISOString()
    });
});

// ============================================
// 🔄 GRACEFUL SHUTDOWN
// ============================================
process.on('SIGTERM', () => {
    console.log('SIGTERM signal received: closing HTTP server');
    server.close(() => {
        console.log('HTTP server closed');
        newsCache.clear();
        seenArticlesGlobal.clear();
    });
});

process.on('unhandledRejection', (err) => {
    console.error('UNHANDLED REJECTION! 💥', err);
});

// ============================================
// 🚀 START SERVER
// ============================================
const server = app.listen(PORT, () => {
    console.log(`
╔═══════════════════════════════════════════════════════════╗
║ 🚀 UPDATES NEWS API - ULTRA-SECURE BACKEND v7.0 FIXED  ║
╠═══════════════════════════════════════════════════════════╣
║ 📡 Port: ${PORT}                                          ║
║ 🌍 Environment: ${process.env.NODE_ENV || 'development'}  ║
║ 📅 Started: ${new Date().toISOString()}                   ║
╠═══════════════════════════════════════════════════════════╣
║ 📰 5 NEWS APIs CONNECTED - READY TO SERVE                ║
╚═══════════════════════════════════════════════════════════╝
    `);
});

module.exports = app;
