require('dotenv').config();
const express = require('express');
const axios = require('axios');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');

const app = express();
const PORT = process.env.PORT || 3001;

// Security middleware
app.use(helmet());
app.use(cors({ origin: 'http://localhost:3000' })); // Adjust for your frontend URL
app.use(express.json());

const limiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 100 });
app.use('/api/', limiter); // Limit API calls [web:5]

const API_KEYS = {
  newsapi: process.env.NEWSAPI_KEY,
  newsdata: process.env.NEWSDATA_KEY,
  gnews: process.env.GNEWS_KEY,
  currentsnews: process.env.CURRENTSNEWS_KEY,
  worldnews: process.env.WORLDNEWS_KEY
};

// Proxy endpoint for frontend (e.g., GET /api/news?source=newsapi&q=trump&country=us)
app.get('/api/news', async (req, res) => {
  const { source, q, country, category, pageSize = 10 } = req.query;
  
  if (!source || !API_KEYS[source]) {
    return res.status(400).json({ error: 'Valid source required: newsapi, newsdata, gnews, currentsnews, worldnews' });
  }

  try {
    let url;
    switch (source) {
      case 'newsapi':
        url = `https://newsapi.org/v2/top-headlines?q=${q}&country=${country}&apiKey=${API_KEYS[source]}`;
        break;
      case 'newsdata':
        url = `https://newsdata.io/api/1/news?apikey=${API_KEYS[source]}&q=${q}&country=${country}`;
        break;
      case 'gnews':
        url = `https://gnews.io/api/v4/search?q=${q}&lang=en&country=${country}&token=${API_KEYS[source]}`;
        break;
      case 'currentsnews':
        url = `https://api.currentsapi.services/v1/search?api_key=${API_KEYS[source]}&keywords=${q}`;
        break;
      case 'worldnews':
        url = `https://api.worldnewsapi.com/search-news?api-key=${API_KEYS[source]}&text=${q}`;
        break;
      default:
        return res.status(400).json({ error: 'Unsupported source' });
    }

    const response = await axios.get(url);
    res.json(response.data);
  } catch (error) {
    res.status(500).json({ error: 'API request failed' });
  }
});

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
