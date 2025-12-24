# 📰 News API Proxy v6.0 - Ultra-Secure Edition

<div align="center">

![Version](https://img.shields.io/badge/version-6.0.0-blue.svg)
![Node](https://img.shields.io/badge/node-%3E%3D18.0.0-brightgreen.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Security](https://img.shields.io/badge/security-enterprise--grade-red.svg)
![APIs](https://img.shields.io/badge/news--APIs-5-orange.svg)

**Production-ready news aggregation API with intelligent search, duplicate removal, offline caching, and full multilingual support.**

[Features](#-features) • [Quick Start](#-quick-start) • [API Documentation](#-api-documentation) • [Configuration](#-configuration) • [Deployment](#-deployment) • [Security](#-security)

</div>

---

## 🚀 Features

### Core Features
- ✅ **5 Premium News APIs**: NewsAPI, GNews, NewsData, Currents, WorldNews
- ✅ **Intelligent Multi-API Search**: Cross-platform keyword search with relevancy scoring
- ✅ **Advanced Duplicate Removal**: MD5 hash-based deduplication algorithm
- ✅ **Offline Support**: Persistent caching serves content when APIs fail (30-min TTL)
- ✅ **12 Languages Supported**: en, hi, es, fr, de, ja, zh, ar, pt, ru, it, ko
- ✅ **15 Countries**: India, USA, UK, Canada, Australia, Germany, France, Spain, Japan, China, Brazil, Mexico, Italy, Russia, South Korea

### Technical Features
- ⚡ **High Performance**: In-memory caching with 30-minute TTL
- 🔒 **Military-Grade Security**: 13+ security layers (Helmet, XSS, NoSQL injection prevention, rate limiting)
- 📊 **Monitoring**: Health check endpoint with detailed metrics
- 🌐 **Scalability**: Supports 2000+ concurrent users
- 🛡️ **Reliability**: Automatic fallback to stale cache on API failures
- 🔍 **Smart Search**: Relevance scoring algorithm across 3 news sources
- 🎯 **Zero Duplicates**: Intelligent hash-based duplicate detection

### Security Features
1. **Helmet.js** - 15+ security headers
2. **Rate Limiting** - Global (2000/15min), API (150/min), Search (50/min)
3. **CORS** - Whitelist-based origin validation
4. **XSS Protection** - Input sanitization with xss-clean
5. **NoSQL Injection Prevention** - express-mongo-sanitize
6. **HPP** - HTTP Parameter Pollution prevention
7. **Compression** - Response compression (gzip)
8. **Input Validation** - Whitelist-based validation
9. **Error Sanitization** - No stack traces in production
10. **Request Logging** - Sanitized IP logging
11. **Graceful Shutdown** - Proper cleanup on termination
12. **HTTPS Enforcement** - HSTS headers
13. **Content Security Policy** - Strict CSP headers

---

## 📦 Quick Start

### Prerequisites
- **Node.js** >= 18.0.0
- **npm** >= 9.0.0
- API keys from 5 news providers (see [API Keys](#-api-keys))

### Installation
