const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const rateLimit = require('express-rate-limit');
const path = require('path');

const { initDB, pool } = require('./db/database');
const { initRedis, getRedis } = require('./middleware/cache');

const locationsRouter = require('./routes/locations');
const productsRouter = require('./routes/products');
const authRouter = require('./routes/auth');
const ordersRouter = require('./routes/orders');
const adminRouter = require('./routes/admin');

const app = express();
const PORT = process.env.PORT || 3000;
const isProd = process.env.NODE_ENV === 'production';

app.set('trust proxy', 1);

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", 'https://js.stripe.com'],
      frameSrc: ["'self'", 'https://js.stripe.com'],
      connectSrc: ["'self'", 'https://api.stripe.com'],
      imgSrc: ["'self'", 'data:', 'https:'],
      styleSrc: ["'self'", 'https://fonts.googleapis.com'],
      fontSrc: ["'self'", 'https://fonts.gstatic.com'],
    }
  },
  hsts: isProd ? { maxAge: 63072000, includeSubDomains: true, preload: true } : false,
}));

app.use(cors({
  origin: process.env.CORS_ORIGIN || 'http://localhost:3000',
  credentials: true,
}));

app.use(cookieParser());
app.use(express.json({ limit: '1mb' }));

const apiLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 200, standardHeaders: true, legacyHeaders: false });
const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 5, standardHeaders: true, legacyHeaders: false });

app.use('/api/', apiLimiter);
app.use('/api/auth/login', authLimiter);
app.use('/api/admin', authLimiter);

// Kubernetes liveness probe — checks process is running
app.get('/api/health', (req, res) => res.json({ status: 'ok', timestamp: new Date().toISOString() }));

// Kubernetes readiness probe — checks DB and Redis before accepting traffic
app.get('/api/ready', async (req, res) => {
  try {
    await pool.query('SELECT 1');
    const redis = getRedis();
    if (redis) await redis.ping();
    res.json({ status: 'ready', db: 'ok', redis: redis ? 'ok' : 'disabled' });
  } catch (err) {
    res.status(503).json({ status: 'not ready', error: err.message });
  }
});

app.use('/api/locations', locationsRouter);
app.use('/api/products', productsRouter);
app.use('/api/auth', authRouter);
app.use('/api/orders', ordersRouter);
app.use('/api/admin', adminRouter);

app.use(express.static(path.join(__dirname, '..', 'public')));
app.use((req, res) => res.status(404).json({ error: 'Not found' }));
app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ error: 'Internal server error' });
});

async function start() {
  initRedis();
  await initDB();

  const server = app.listen(PORT, () => {
    console.log(`AGW API running on port ${PORT} [${process.env.NODE_ENV || 'development'}]`);
  });

  // Istio-aware graceful shutdown:
  // When Kubernetes terminates a pod, both the application and the Envoy sidecar
  // receive SIGTERM simultaneously. If the app exits immediately, Envoy may still
  // be routing in-flight requests. The preStop hook in deployment.yaml adds a 5s
  // delay, but we also wait here before closing to handle the SIGTERM path.
  const shutdown = async (signal) => {
    console.log(`${signal} received`);

    // Wait 5s for Envoy sidecar to drain connections before we stop accepting
    if (isProd) {
      await new Promise(resolve => setTimeout(resolve, 5000));
    }

    server.close(async () => {
      const redis = getRedis();
      if (redis) await redis.quit();
      await pool.end();
      console.log('Shutdown complete');
      process.exit(0);
    });

    setTimeout(() => process.exit(1), 30000).unref();
  };

  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT', () => shutdown('SIGINT'));
}

start().catch(err => {
  console.error('Failed to start:', err);
  process.exit(1);
});
