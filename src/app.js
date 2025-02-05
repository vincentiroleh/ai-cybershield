import express from 'express';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import hpp from 'hpp';
import cors from 'cors';
import { fileURLToPath } from 'url';
import { dirname } from 'path';
import { config } from 'dotenv';
import v8 from 'v8';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

config(); // Load environment variables

const app = express();

// Set timeout
app.timeout = 300000; // 5 minutes

// Security Headers
app.use(helmet());

// Rate Limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  message: {
    status: 'error',
    message: 'Too many requests, please try again later.',
  },
  standardHeaders: true,
  legacyHeaders: false,
});

// Apply rate limiting to all routes
app.use(limiter);

// Increase payload limits for file upload
app.use(express.json({ 
  limit: '200mb' // Increased from 50mb
}));

// Add timeout middleware 
app.use((req, res, next) => {
  res.setTimeout(300000, () => {
      res.status(408).json({
          status: 'error',
          message: 'Request timeout',
          timestamp: new Date().toISOString()
      });
  });
  next();
});

// Parse URL-encoded bodies with increased limits
app.use(express.urlencoded({ 
  limit: '200mb', // Increased from 50mb
  extended: true,
  parameterLimit: 100000 // Increased from 50000
}));

// Handle raw bodies
app.use(express.raw({limit: '200mb'})); // Increased from 50mb

// Prevent parameter pollution
app.use(hpp());

// CORS configuration
const corsOptions = {
  origin: process.env.ALLOWED_ORIGINS?.split(',') || '*',
  methods: ['GET', 'POST'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  exposedHeaders: ['Content-Range', 'X-Content-Range'],
  maxAge: 600,
  credentials: true,
};
app.use(cors(corsOptions));

// Security Middleware
app.use((req, res, next) => {
  // Remove sensitive headers
  res.removeHeader('X-Powered-By');
  
  // Add security headers
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Content-Security-Policy', "default-src 'self'");
  
  next();
});

// Debug middleware for file uploads
app.use((req, res, next) => {
  if (req.path.includes('/analyze/file')) {
    console.log('Debug - Upload Request:', {
      path: req.path,
      method: req.method,
      contentType: req.headers['content-type'],
      contentLength: req.headers['content-length']
    });
  }
  next();
});

// Increase heap size limits
v8.setFlagsFromString('--max-old-space-size=4096'); // 4GB heap size

// Add memory usage monitoring (add before routes)
app.use((req, res, next) => {
    if (req.path.includes('/analyze/file')) {
        const memUsage = process.memoryUsage();
        console.log('Memory usage before request:', {
            rss: `${Math.round(memUsage.rss / 1024 / 1024)}MB`,
            heapTotal: `${Math.round(memUsage.heapTotal / 1024 / 1024)}MB`,
            heapUsed: `${Math.round(memUsage.heapUsed / 1024 / 1024)}MB`,
            external: `${Math.round(memUsage.external / 1024 / 1024)}MB`
        });
    }
    next();
});

// Routes
import v1LogRoutes from './routes/v1/logRoutes.js';
app.use('/api/v1/logs', v1LogRoutes);


app.use((req, res, next) => {
  if (req.path.includes('/analyze/file')) {
      const memUsage = process.memoryUsage();
      console.log('Memory usage after request:', {
          rss: `${Math.round(memUsage.rss / 1024 / 1024)}MB`,
          heapTotal: `${Math.round(memUsage.heapTotal / 1024 / 1024)}MB`,
          heapUsed: `${Math.round(memUsage.heapUsed / 1024 / 1024)}MB`,
          external: `${Math.round(memUsage.external / 1024 / 1024)}MB`
      });
  }
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Error:', err);
  
  const message = process.env.NODE_ENV === 'production' 
    ? 'Internal server error' 
    : err.message;
    
  res.status(500).json({
    status: 'error',
    message,
    timestamp: new Date().toISOString(),
  });
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({
    status: 'error',
    message: 'Resource not found',
    timestamp: new Date().toISOString(),
  });
});

// Server startup with increased timeouts
const PORT = process.env.PORT || 3000;
const server = app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});

// Set server timeouts
server.timeout = 600000; // 10 minutes
server.keepAliveTimeout = 300000; // 5 minutes
server.headersTimeout = 301000; // 5 minutes + 1 second

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('SIGTERM signal received: closing HTTP server');
  server.close(() => {
    console.log('HTTP server closed');
    process.exit(0);
  });
});

process.on('SIGINT', () => {
  console.log('SIGINT signal received: closing HTTP server');
  server.close(() => {
    console.log('HTTP server closed');
    process.exit(0);
  });
});

export default app;
