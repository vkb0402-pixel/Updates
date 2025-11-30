const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const mongoSanitize = require('express-mongo-sanitize');
const xss = require('xss-clean');
const hpp = require('hpp');
const compression = require('compression');

const app = express();
const PORT = process.env.PORT || 3000;

// 🛡️ SECURITY LAYER 1: Helmet - FIXED CSP for external API calls
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:", "https:", "http:"],
      connectSrc: ["'self'", "https:", "http:"], // 🔧 FIX: Allow external API connections
      fontSrc: ["'self'", "https:", "data:"],
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

// 🛡️ SECURITY LAYER 2: Rate Limiting - Enhanced Protection
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 750,
  message: {
    error: 'Too many requests from this IP, please try again later.',
    retryAfter: '15 minutes',
    limit: 750,
    window: '15 minutes'
  },
  standardHeaders: true,
  legacyHeaders: false,
  skipSuccessfulRequests: false,
  skipFailedRequests: false,
  keyGenerator: (req) => {
    return req.headers['x-forwarded-for']?.split(',')[0] || req.ip;
  }
});

const apiLimiter = rateLimit({
  windowMs: 1 * 60 * 1000,
  max: 100, // 🔧 INCREASED from 50 to 100
  message: {
    error: 'Too many API requests, please slow down.',
    retryAfter: '1 minute'
  }
});

app.use('/api/', limiter);

// 🛡️ SECURITY LAYER 3: CORS - FIXED to allow your deployed frontend
const allowedOrigins = process.env.ALLOWED_ORIGINS 
  ? process.env.ALLOWED_ORIGINS.split(',') 
  : [
      'http://localhost:3000',
      'http://127.0.0.1:3000',
      'http://localhost:5500',
      'http://127.0.0.1:5500',
      'http://localhost:5501',
      'http://127.0.0.1:5501',
      // 🔧 FIX: Add your deployed frontend URLs
      'https://pixel.github.io',
      'http://pixel.github.io',
      'https://vkbofficial4u.github.io',
      'http://vkbofficial4u.github.io'
    ];

app.use(cors({
  origin: function(origin, callback) {
    // 🔧 FIX: Allow requests with no origin (for mobile apps and direct access)
    if (!origin) return callback(null, true);
    
    // 🔧 FIX: Check if origin matches allowed list
    const isAllowed = allowedOrigins.some(allowed => 
      origin.includes(allowed.replace('https://', '').replace('http://', ''))
    );
    
    if (isAllowed) {
      return callback(null, true);
    }
    
    // Log blocked origin for debugging
    console.warn(`⚠️  CORS blocked origin: ${origin}`);
    return callback(null, true); // 🔧 TEMPORARY: Allow all origins for testing
  },
  credentials: true,
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
  maxAge: 600,
  optionsSuccessStatus: 200
}));

// 🔧 Handle preflight requests
app.options('*', cors());

// 🛡️ SECURITY LAYER 4: Input Sanitization
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true, limit: '10kb' }));
app.use(mongoSanitize());
app.use(xss());
app.use(hpp());

// 🛡️ SECURITY LAYER 5: Compression
app.use(compression());

// 🔐 API Keys
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
    console.warn(`⚠️  Warning: ${key} API key appears invalid or missing`);
  } else {
    console.log(`✅ ${key} API key loaded`);
  }
});

// Input validation
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

// Sanitize response headers
app.use((req, res, next) => {
  res.removeHeader('X-Powered-By');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  next();
});

// Root route
app.get('/', (req, res) => {
  res.json({
    status: 'online',
    message: 'News API Proxy Service - Ultra-Secure Edition',
    version: '3.0.1',
    timestamp: new Date().toISOString(),
    endpoints: [
      '/api/newsapi',
      '/api/newsdata',
      '/api/gnews',
      '/api/currents',
      '/api/worldnews'
    ],
    security: {
      helmet: 'enabled',
      rateLimit: '750 requests per 15 minutes (global), 100 per minute (per API)',
      cors: 'enabled for all origins (testing mode)',
      xssProtection: 'enabled',
      noSqlInjectionPrevention: 'enabled',
      compressionEnabled: true,
      tlsRequired: process.env.NODE_ENV === 'production'
    }
  });
});

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({ 
    status: 'healthy', 
    timestamp: new Date().toISOString(),
    uptime: Math.floor(process.uptime()),
    memory: process.memoryUsage(),
    environment: process.env.NODE_ENV || 'development'
  });
});

// Request logging (sanitized)
app.use((req, res, next) => {
  const ip = req.headers['x-forwarded-for']?.split(',')[0] || req.ip;
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.path} - IP: ${ip.substring(0, 10)}...`);
  next();
});

// ============================================
// 🔧 FIXED: Fetch with proper error handling
// ============================================
async function fetchWithTimeout(url, timeout = 15000) {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), timeout);
  
  try {
    const response = await fetch(url, {
      signal: controller.signal,
      headers: { 
        'User-Agent': 'NewsProxy/3.0',
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
// API ENDPOINTS WITH ENHANCED ERROR HANDLING
// ============================================

// NewsAPI endpoint
app.get('/api/newsapi', apiLimiter, async (req, res) => {
  try {
    const { country, language } = validateInput(
      req.query.country,
      req.query.language
    );
    
    console.log(`📰 Fetching NewsAPI: country=${country}, language=${language}`);
    
    const url = `https://newsapi.org/v2/top-headlines?country=${country}&language=${language}&apiKey=${API_KEYS.newsapi}&pageSize=100`;
    
    const response = await fetchWithTimeout(url);
    
    if (!response.ok) {
      console.error(`❌ NewsAPI responded with status: ${response.status}`);
      throw new Error(`NewsAPI responded with status: ${response.status}`);
    }
    
    const data = await response.json();
    
    // Check for API errors
    if (data.code === 'apiKeyInvalid' || data.code === 'apiKeyMissing') {
      console.error('❌ NewsAPI authentication failed');
      return res.status(401).json({ 
        error: 'Authentication failed',
        source: 'NewsAPI'
      });
    }
    
    console.log(`✅ NewsAPI returned ${data.articles?.length || 0} articles`);
    res.json(data);
  } catch (error) {
    console.error('NewsAPI Error:', error.message);
    res.status(500).json({ 
      error: 'Failed to fetch from NewsAPI',
      details: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// NewsData endpoint
app.get('/api/newsdata', apiLimiter, async (req, res) => {
  try {
    const { country, language } = validateInput(
      req.query.country,
      req.query.language
    );
    
    console.log(`📰 Fetching NewsData: country=${country}, language=${language}`);
    
    const url = `https://newsdata.io/api/1/news?apikey=${API_KEYS.newsdata}&country=${country}&language=${language}`;
    
    const response = await fetchWithTimeout(url);
    
    if (!response.ok) {
      console.error(`❌ NewsData responded with status: ${response.status}`);
      throw new Error(`NewsData responded with status: ${response.status}`);
    }
    
    const data = await response.json();
    console.log(`✅ NewsData returned ${data.results?.length || 0} articles`);
    res.json(data);
  } catch (error) {
    console.error('NewsData Error:', error.message);
    res.status(500).json({ 
      error: 'Failed to fetch from NewsData',
      details: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// GNews endpoint
app.get('/api/gnews', apiLimiter, async (req, res) => {
  try {
    const { country, language } = validateInput(
      req.query.country,
      req.query.lang || req.query.language
    );
    
    console.log(`📰 Fetching GNews: country=${country}, language=${language}`);
    
    const url = `https://gnews.io/api/v4/top-headlines?country=${country}&lang=${language}&apikey=${API_KEYS.gnews}&max=100`;
    
    const response = await fetchWithTimeout(url);
    
    if (!response.ok) {
      console.error(`❌ GNews responded with status: ${response.status}`);
      throw new Error(`GNews responded with status: ${response.status}`);
    }
    
    const data = await response.json();
    console.log(`✅ GNews returned ${data.articles?.length || 0} articles`);
    res.json(data);
  } catch (error) {
    console.error('GNews Error:', error.message);
    res.status(500).json({ 
      error: 'Failed to fetch from GNews',
      details: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// Currents API endpoint
app.get('/api/currents', apiLimiter, async (req, res) => {
  try {
    const { country, language } = validateInput(
      req.query.country,
      req.query.language
    );
    
    console.log(`📰 Fetching Currents: country=${country}, language=${language}`);
    
    const url = `https://api.currentsapi.services/v1/latest-news?apiKey=${API_KEYS.currents}&language=${language}&region=${country}`;
    
    const response = await fetchWithTimeout(url);
    
    if (!response.ok) {
      console.error(`❌ Currents responded with status: ${response.status}`);
      throw new Error(`Currents responded with status: ${response.status}`);
    }
    
    const data = await response.json();
    console.log(`✅ Currents returned ${data.news?.length || 0} articles`);
    res.json(data);
  } catch (error) {
    console.error('Currents API Error:', error.message);
    res.status(500).json({ 
      error: 'Failed to fetch from Currents API',
      details: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// World News API endpoint
app.get('/api/worldnews', apiLimiter, async (req, res) => {
  try {
    const { language } = validateInput('in', req.query.language);
    
    console.log(`📰 Fetching World News: language=${language}`);
    
    const url = `https://api.worldnewsapi.com/search-news?language=${language}&number=100&api-key=${API_KEYS.worldnews}`;
    
    const response = await fetchWithTimeout(url);
    
    if (!response.ok) {
      console.error(`❌ WorldNews responded with status: ${response.status}`);
      throw new Error(`WorldNews responded with status: ${response.status}`);
    }
    
    const data = await response.json();
    console.log(`✅ World News returned ${data.news?.length || 0} articles`);
    
    // Transform response to match expected format
    res.json({
      status: 'success',
      news: data.news || [],
      totalResults: data.available || 0
    });
  } catch (error) {
    console.error('World News API Error:', error.message);
    res.status(500).json({ 
      error: 'Failed to fetch from World News API',
      details: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({ 
    error: 'Endpoint not found',
    path: req.path,
    timestamp: new Date().toISOString()
  });
});

// Global error handler
app.use((err, req, res, next) => {
  console.error('[ERROR]', {
    message: err.message,
    path: req.path,
    method: req.method,
    timestamp: new Date().toISOString()
  });
  
  const errorResponse = {
    error: 'Internal server error',
    timestamp: new Date().toISOString()
  };
  
  if (process.env.NODE_ENV === 'development') {
    errorResponse.details = err.message;
    errorResponse.stack = err.stack;
  }
  
  res.status(err.status || 500).json(errorResponse);
});

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('SIGTERM signal received: closing HTTP server');
  server.close(() => {
    console.log('HTTP server closed');
  });
});

process.on('unhandledRejection', (err) => {
  console.error('UNHANDLED REJECTION! 💥');
  console.error(err);
  // Don't exit in production, just log
  if (process.env.NODE_ENV !== 'production') {
    process.exit(1);
  }
});

// Start server
const server = app.listen(PORT, () => {
  console.log(`
╔═══════════════════════════════════════════════════════════╗
║  🚀 SERVER RUNNING - ULTRA-SECURE EDITION v3.0.1         ║
╠═══════════════════════════════════════════════════════════╣
║  📡 Port: ${PORT}                                        ║
║  🌍 Environment: ${process.env.NODE_ENV || 'development'}                           ║
║  📅 Started: ${new Date().toISOString()}              ║
╠═══════════════════════════════════════════════════════════╣
║  📰 AVAILABLE ENDPOINTS:                                 ║
║     • /api/newsapi                                       ║
║     • /api/newsdata                                      ║
║     • /api/gnews                                         ║
║     • /api/currents                                      ║
║     • /api/worldnews  🆕 NEW!                          ║
╠═══════════════════════════════════════════════════════════╣
║  🛡️  SECURITY FEATURES ENABLED:                          ║
║     ✓ Helmet.js (15+ security headers)                  ║
║     ✓ Rate limiting (750/15min global, 100/min per API) ║
║     ✓ CORS enabled (testing mode - allow all)           ║
║     ✓ XSS protection                                     ║
║     ✓ NoSQL injection prevention                        ║
║     ✓ HTTP parameter pollution prevention               ║
║     ✓ Request compression                               ║
║     ✓ Input validation & sanitization                   ║
║     ✓ Error sanitization                                ║
║     ✓ Request logging (sanitized)                       ║
║     ✓ Graceful shutdown handling                        ║
╚═══════════════════════════════════════════════════════════╝
  `);
});

module.exports = app;
