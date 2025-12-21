require('dotenv').config();

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const mongoSanitize = require('express-mongo-sanitize');
const xss = require('xss-clean');
const hpp = require('hpp');
const compression = require('compression');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;

// ============================================
// 🗄️ IN-MEMORY CACHE
// ============================================
const newsCache = new Map();
const seenArticlesGlobal = new Set();
const CACHE_DURATION = 10 * 60 * 1000; // 10 minutes
const MAX_CACHE_SIZE = 1000;

function createArticleHash(article) {
    const title = (article.title || '').toLowerCase().trim().substring(0, 50);
    const url = (article.url || article.link || '').toLowerCase().trim();
    const domain = url.split('/')[2] || '';
    const identifier = `${title}_${domain}`;
    return crypto.createHash('md5').update(identifier).digest('hex');
}

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

function cleanOldCache() {
    if (seenArticlesGlobal.size > MAX_CACHE_SIZE) {
        const entries = Array.from(seenArticlesGlobal);
        seenArticlesGlobal.clear();
        entries.slice(-500).forEach(hash => seenArticlesGlobal.add(hash));
    }
}

setInterval(cleanOldCache, 10 * 60 * 1000);

// ============================================
// 🛡️ SECURITY: Helmet
// ============================================
app.use(helmet({
    contentSecurityPolicy: false, // Disable for flexibility
    crossOriginEmbedderPolicy: false,
    crossOriginResourcePolicy: false
}));

// ============================================
// 🛡️ SECURITY: Rate Limiting
// ============================================
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 1000,
    message: {
        error: 'Too many requests, please try again later.',
        retryAfter: '15 minutes'
    },
    standardHeaders: true,
    legacyHeaders: false
});

const apiLimiter = rateLimit({
    windowMs: 1 * 60 * 1000,
    max: 120,
    message: { error: 'Too many API requests, please slow down.' }
});

app.use('/api/', limiter);

// ============================================
// 🛡️ CORS - ALLOW ALL (FOR TESTING)
// ============================================
app.use(cors({
    origin: '*', // Allow all origins for testing
    credentials: false,
    methods: ['GET', 'POST', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
    optionsSuccessStatus: 200
}));

app.options('*', cors());

// ============================================
// 🛡️ Input Sanitization
// ============================================
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true, limit: '10kb' }));
app.use(mongoSanitize());
app.use(xss());
app.use(hpp());
app.use(compression());

// ============================================
// 🔐 API KEYS
// ============================================
const API_KEYS = {
    newsapi: process.env.NEWSAPI_KEY || 'f20f53e207ed497dace6c1d4a47daec9',
    newsdata: process.env.NEWSDATA_KEY || 'pub_630bb6b01dd54da7b8a20061a5bd8224a0c1',
    gnews: process.env.GNEWS_KEY || '7ea52edafd1d5eccbddcf495ceba6c11',
    currents: process.env.CURRENTS_KEY || 'XHsTPUmUy2xRLyDO0bxyFD2BlpSuT6vv7d-hSB7nPXagxAHe'
};

// ============================================
// 🔒 INPUT VALIDATION
// ============================================
function validateInput(country, language) {
    const validCountries = ['in', 'us', 'gb', 'ca', 'au', 'de', 'fr', 'es', 'jp', 'cn'];
    const validLanguages = ['en', 'hi', 'es', 'fr', 'de', 'ja', 'zh', 'ar', 'pt', 'ru'];
    
    const sanitizedCountry = String(country || 'in').toLowerCase().trim().substring(0, 2);
    const sanitizedLanguage = String(language || 'en').toLowerCase().trim().substring(0, 2);
    
    return {
        country: validCountries.includes(sanitizedCountry) ? sanitizedCountry : 'in',
        language: validLanguages.includes(sanitizedLanguage) ? sanitizedLanguage : 'en'
    };
}

// ============================================
// 🌐 FETCH WITH TIMEOUT
// ============================================
async function fetchWithTimeout(url, timeout = 12000) {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), timeout);
    
    try {
        const response = await fetch(url, {
            signal: controller.signal,
            headers: {
                'User-Agent': 'NewsProxy/4.0',
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
        message: 'News API Proxy Service v4.0',
        version: '4.0.0',
        timestamp: new Date().toISOString(),
        endpoints: [
            '/api/newsapi',
            '/api/newsdata',
            '/api/gnews',
            '/api/currents'
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
        cacheSize: newsCache.size,
        uniqueArticles: seenArticlesGlobal.size
    });
});

// ============================================
// 📰 NEWS API ENDPOINTS
// ============================================

// NewsAPI
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
            throw new Error(`NewsAPI error: ${response.status}`);
        }
        
        const data = await response.json();
        
        if (data.articles && Array.isArray(data.articles)) {
            data.articles = removeDuplicates(data.articles);
        }
        
        newsCache.set(cacheKey, { data, timestamp: Date.now() });
        console.log(`✅ NewsAPI returned ${data.articles?.length || 0} unique articles`);
        
        res.json(data);
    } catch (error) {
        console.error('NewsAPI Error:', error.message);
        const { country, language } = validateInput(req.query.country, req.query.language);
        const cacheKey = `newsapi_${country}_${language}`;
        
        if (newsCache.has(cacheKey)) {
            console.log('⚠️ Serving stale cache');
            return res.json(newsCache.get(cacheKey).data);
        }
        
        res.status(500).json({
            error: 'Failed to fetch news',
            message: 'Please try again later'
        });
    }
});

// GNews
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
            throw new Error(`GNews error: ${response.status}`);
        }
        
        const data = await response.json();
        
        if (data.articles && Array.isArray(data.articles)) {
            data.articles = removeDuplicates(data.articles);
        }
        
        newsCache.set(cacheKey, { data, timestamp: Date.now() });
        console.log(`✅ GNews returned ${data.articles?.length || 0} unique articles`);
        
        res.json(data);
    } catch (error) {
        console.error('GNews Error:', error.message);
        const { country, language } = validateInput(req.query.country, req.query.lang || req.query.language);
        const cacheKey = `gnews_${country}_${language}`;
        
        if (newsCache.has(cacheKey)) {
            return res.json(newsCache.get(cacheKey).data);
        }
        
        res.status(500).json({
            error: 'Failed to fetch news',
            message: 'Please try again later'
        });
    }
});

// NewsData
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
            throw new Error(`NewsData error: ${response.status}`);
        }
        
        const data = await response.json();
        
        if (data.results && Array.isArray(data.results)) {
            data.results = removeDuplicates(data.results);
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
        
        res.status(500).json({
            error: 'Failed to fetch news',
            message: 'Please try again later'
        });
    }
});

// Currents
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
        const url = `https://api.currentsapi.services/v1/latest-news?apiKey=${API_KEYS.currents}&language=${language}`;
        
        const response = await fetchWithTimeout(url);
        if (!response.ok) {
            throw new Error(`Currents error: ${response.status}`);
        }
        
        const data = await response.json();
        
        if (data.news && Array.isArray(data.news)) {
            data.news = removeDuplicates(data.news);
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
        
        res.status(500).json({
            error: 'Failed to fetch news',
            message: 'Please try again later'
        });
    }
});

// ============================================
// 🚫 404 HANDLER
// ============================================
app.use((req, res) => {
    res.status(404).json({
        error: 'Endpoint not found',
        path: req.path,
        availableEndpoints: ['/api/newsapi', '/api/newsdata', '/api/gnews', '/api/currents']
    });
});

// ============================================
// ❌ ERROR HANDLER
// ============================================
app.use((err, req, res, next) => {
    console.error('[ERROR]', err.message);
    res.status(err.status || 500).json({
        error: 'Internal server error',
        message: 'Please try again later'
    });
});

// ============================================
// 🚀 START SERVER
// ============================================
const server = app.listen(PORT, () => {
    console.log(`
╔════════════════════════════════════════╗
║   🚀 NEWS API PROXY v4.0 RUNNING      ║
╠════════════════════════════════════════╣
║   Port: ${PORT}                           ║
║   Status: ✅ ONLINE                    ║
║   Cache: ✅ ENABLED                    ║
║   CORS: ✅ OPEN (All Origins)         ║
╠════════════════════════════════════════╣
║   Endpoints:                          ║
║   • /api/newsapi                      ║
║   • /api/gnews                        ║
║   • /api/newsdata                     ║
║   • /api/currents                     ║
╚════════════════════════════════════════╝
    `);
});

process.on('SIGTERM', () => {
    console.log('Shutting down gracefully...');
    server.close(() => {
        newsCache.clear();
        seenArticlesGlobal.clear();
        console.log('Server closed');
    });
});

module.exports = app;
