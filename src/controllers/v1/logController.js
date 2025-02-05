import fs from 'fs/promises';
import path from 'path';
import csv from 'csv-parser';
import { promisify } from 'util';
import { pipeline } from 'stream/promises';
import { createReadStream } from 'fs';
import { analyzeLogs } from '../../utils/logAnalyzer.js';

const streamProcessor = async (filePath) => {
  let content = '';
  const readStream = createReadStream(filePath, {
    encoding: 'utf8',
    highWaterMark: 64 * 1024 // 64KB chunks
  });

  for await (const chunk of readStream) {
    content += chunk;
  }
  return content;
};

const cleanupResources = async (filePath) => {
  try {
    await fs.unlink(filePath);
    // Force garbage collection if available
    if (global.gc) {
      global.gc();
    }
  } catch (error) {
    console.warn('Cleanup warning:', error);
  }
};

// Standard response formatter
const formatResponse = (data) => ({
  status: 'success',
  timestamp: new Date().toISOString(),
  data,
});

// Error handler with specific error types
const handleError = (error, operation) => {
  console.error(`Error during ${operation}:`, error);

  const errorResponses = {
    ENOENT: {
      code: 'FILE_NOT_FOUND',
      status: 404,
      message: 'File not found'
    },
    INVALID_JSON: {
      code: 'INVALID_FILE_FORMAT',
      status: 400,
      message: 'Invalid JSON format'
    },
    INVALID_CSV: {
      code: 'INVALID_FILE_FORMAT',
      status: 400,
      message: 'Invalid CSV format'
    },
    DEFAULT: {
      code: 'INTERNAL_SERVER_ERROR',
      status: 500,
      message: `Error during ${operation}`
    }
  };

  const errorType = errorResponses[error.code] || errorResponses.DEFAULT;

  return {
    status: 'error',
    code: errorType.code,
    message: error.message || errorType.message,
    timestamp: new Date().toISOString(),
    statusCode: errorType.status
  };
};

// File content parsers with format handling
const parsers = {
  async json(filePath) {
    try {
      const content = await fs.readFile(filePath, 'utf8');
      const jsonData = JSON.parse(content);

      // Handle different JSON structures
      if (jsonData.logs && Array.isArray(jsonData.logs)) {
        return jsonData.logs; // Return logs array
      } else if (Array.isArray(jsonData)) {
        return jsonData; // Return array directly
      } else {
        return [jsonData]; // Return single object as array
      }
    } catch (error) {
      error.code = 'INVALID_JSON';
      throw error;
    }
  },

  async csv(filePath) {
    try {
      const results = [];
      await new Promise((resolve, reject) => {
        createReadStream(filePath)
          .pipe(csv())
          .on('data', (data) => results.push(data))
          .on('end', () => resolve())
          .on('error', reject);
      });
      return results;
    } catch (error) {
      error.code = 'INVALID_CSV';
      throw error;
    }
  },

  async text(filePath) {
    const content = await fs.readFile(filePath, 'utf8');
    // Split text logs by newline and parse if possible
    return content.split('\n')
      .filter(line => line.trim())
      .map(line => {
        try {
          return JSON.parse(line);
        } catch {
          return { message: line, timestamp: new Date().toISOString() };
        }
      });
  }
};

// File processor
const processFile = async (filePath, fileType) => {
  const fileExtension = fileType.toLowerCase();
  const parserMap = {
    '.json': parsers.json,
    '.csv': parsers.csv,
    '.log': parsers.text,
    '.txt': parsers.text
  };

  const parser = parserMap[fileExtension];
  if (!parser) {
    throw new Error('Unsupported file type');
  }

  return parser(filePath);
};

// Format log data for analysis
const formatLogsForAnalysis = (logs) => {
  if (!Array.isArray(logs)) {
    logs = [logs];
  }

  return logs.map(log => {
    // Ensure each log entry has required fields
    const formattedLog = {
      timestamp: log.timestamp || new Date().toISOString(),
      level: log.level || 'INFO',
      message: log.message || JSON.stringify(log),
      ...log
    };

    return JSON.stringify(formattedLog);
  }).join('\n');
};

// Controller methods
export const analyzeLogFile = async (req, res) => {
  const startTime = Date.now();
  let filePath = null;

  try {
    console.log(`[${startTime}] Starting file analysis...`);

    if (!req.file) {
      return res.status(400).json({
        status: 'error',
        message: 'No file uploaded',
        timestamp: new Date().toISOString()
      });
    }

    filePath = req.file.path;
    const fileSize = req.file.size;
    const fileExtension = path.extname(req.file.originalname).toLowerCase();
    console.log(`[${startTime}] Processing ${fileExtension} file: ${req.file.originalname} (${fileSize} bytes)`);

    // Use the appropriate parser based on file extension
    let parsedContent;
    try {
      switch (fileExtension) {
        case '.json':
          const fileContent = await streamProcessor(filePath);
          parsedContent = JSON.parse(fileContent);
          break;
        case '.csv':
          parsedContent = await parsers.csv(filePath);
          break;
        case '.txt':
        case '.log':
          parsedContent = await parsers.text(filePath);
          break;
        default:
          throw new Error('Unsupported file type');
      }
    } catch (parseError) {
      throw new Error(`File parsing error: ${parseError.message}`);
    }

    // Process logs
    let logsToAnalyze = Array.isArray(parsedContent) ?
      parsedContent :
      (parsedContent.logs || [parsedContent]);

    console.log(`[${startTime}] Processing ${logsToAnalyze.length} log entries`);



    // Convert to string format in chunks
    const chunkSize = 1000;
    let results = [];

    for (let i = 0; i < logsToAnalyze.length; i += chunkSize) {
      const chunk = logsToAnalyze.slice(i, i + chunkSize);
      const chunkString = chunk
        .map(log => typeof log === 'string' ? log : JSON.stringify(log))
        .join('\n');

      const chunkResults = await analyzeLogs(chunkString);
      results = results.concat(chunkResults);

      console.log(`[${startTime}] Processed ${i + chunk.length}/${logsToAnalyze.length} entries`);
    }

    // Clear variables for garbage collection
    parsedContent = null;
    logsToAnalyze = null;

    // Cleanup resources
    await cleanupResources(filePath);
    filePath = null;

    const processingTime = Date.now() - startTime;
    console.log(`[${startTime}] Analysis complete in ${processingTime}ms`);

    return res.status(200).json({
      status: 'success',
      data: results,
      processingTime,
      timestamp: new Date().toISOString()
    });

  } catch (error) {
    console.error(`[${startTime}] Error:`, error);

    // Ensure cleanup on error
    if (filePath) {
      await cleanupResources(filePath);
    }

    // Clear any remaining response headers
    if (!res.headersSent) {
      res.status(500).json({
        status: 'error',
        message: error.message || 'Error processing file',
        timestamp: new Date().toISOString()
      });
    }
  } finally {
    // Force cleanup
    if (global.gc) {
      global.gc();
    }
  }
};


export const analyzeText = async (req, res) => {
  try {
    const { logData } = req.body;

    if (!logData) {
      return res.status(400).json({
        status: 'error',
        message: 'Log data is required',
        timestamp: new Date().toISOString()
      });
    }

    // Handle if logData is already an object or array
    const formattedLogs = typeof logData === 'string'
      ? logData
      : formatLogsForAnalysis(logData);

    const results = await analyzeLogs(formattedLogs);
    res.status(200).json(formatResponse(results));
  } catch (error) {
    const errorResponse = handleError(error, 'text analysis');
    res.status(errorResponse.statusCode).json(errorResponse);
  }
};

// Rate limiting middleware remains unchanged
export const rateLimiter = (req, res, next) => {
  const ip = req.ip;
  const now = Date.now();
  const windowMs = 15 * 60 * 1000; // 15 minutes
  const maxRequests = 100;

  const requestLog = requestTracker.get(ip) || [];
  const recentRequests = requestLog.filter(time => now - time < windowMs);

  if (recentRequests.length >= maxRequests) {
    return res.status(429).json({
      status: 'error',
      message: 'Too many requests, please try again later',
      timestamp: new Date().toISOString()
    });
  }

  requestLog.push(now);
  requestTracker.set(ip, requestLog);
  next();
};
