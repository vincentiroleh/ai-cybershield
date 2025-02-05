import multer from 'multer';
import path from 'path';
import { fileURLToPath } from 'url';
import { dirname } from 'path';
import fs from 'fs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// Ensure upload directory exists
const uploadDir = path.join(__dirname, '../temp');
if (!fs.existsSync(uploadDir)) {
    fs.mkdirSync(uploadDir, { recursive: true });
}

// Security and validation configurations
const FILE_CONFIG = {
    MAX_SIZE: 200 * 1024 * 1024, // 200MB
    ALLOWED_EXTENSIONS: ['.json', '.csv', '.log', '.txt'],
    ALLOWED_MIME_TYPES: [
        'text/plain',
        'text/csv',
        'application/csv',
        'application/json',
        'text/json',
        'application/x-ndjson',
        'text/x-log'
    ]
};

// Storage configuration with security checks
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        // Verify directory exists and is writable
        try {
            fs.accessSync(uploadDir, fs.constants.W_OK);
            cb(null, uploadDir);
        } catch (error) {
            cb(new Error('Upload directory is not writable'));
        }
    },
    filename: (req, file, cb) => {
        // Generate secure filename
        const uniqueSuffix = `${Date.now()}-${Math.round(Math.random() * 1E9)}`;
        const fileExt = path.extname(file.originalname).toLowerCase();
        const sanitizedFilename = `log-${uniqueSuffix}${fileExt}`;
        
        // Verify filename is safe
        if (sanitizedFilename.includes('..') || !FILE_CONFIG.ALLOWED_EXTENSIONS.includes(fileExt)) {
            cb(new Error('Invalid filename'));
            return;
        }
        
        cb(null, sanitizedFilename);
    }
});

// Enhanced file filter with security checks
const fileFilter = (req, file, cb) => {
    console.log('Processing file:', file.originalname);

    const fileExt = path.extname(file.originalname).toLowerCase();
    
    // Security checks
    if (file.originalname.includes('..')) {
        cb(new Error('Invalid file name'));
        return;
    }

    if (!FILE_CONFIG.ALLOWED_EXTENSIONS.includes(fileExt)) {
        cb(new Error(`Invalid file type. Allowed: ${FILE_CONFIG.ALLOWED_EXTENSIONS.join(', ')}`));
        return;
    }

    if (!FILE_CONFIG.ALLOWED_MIME_TYPES.includes(file.mimetype)) {
        cb(new Error('Invalid file type'));
        return;
    }

    cb(null, true);
};

// Multer configuration
const upload = multer({
    storage,
    fileFilter,
    limits: {
        fileSize: FILE_CONFIG.MAX_SIZE,
        files: 1
    }
});

// Export middleware chain with enhanced error handling
export const uploadMiddleware = [
    // Request validation
    (req, res, next) => {
        if (!req.headers['content-type']?.includes('multipart/form-data')) {
            return res.status(400).json({
                status: 'error',
                message: 'Content-Type must be multipart/form-data',
                timestamp: new Date().toISOString()
            });
        }
        next();
    },

    // File upload handling
    (req, res, next) => {
        upload.single('logfile')(req, res, (err) => {
            if (err) {
                console.error('Upload error:', err);
                if (err instanceof multer.MulterError) {
                    return res.status(400).json({
                        status: 'error',
                        message: `Upload error: ${err.message}`,
                        code: err.code,
                        timestamp: new Date().toISOString()
                    });
                }
                return res.status(500).json({
                    status: 'error',
                    message: err.message,
                    timestamp: new Date().toISOString()
                });
            }

            if (!req.file) {
                return res.status(400).json({
                    status: 'error',
                    message: 'No file uploaded',
                    timestamp: new Date().toISOString()
                });
            }

            console.log('File upload successful:', {
                filename: req.file.filename,
                size: req.file.size,
                mimetype: req.file.mimetype
            });
            
            next();
        });
    }
];

// Export cleanup utility
export const cleanup = {
    temp: async (filePath) => {
        try {
            await fs.promises.unlink(filePath);
        } catch (error) {
            console.warn(`Failed to cleanup temp file: ${filePath}`, error);
        }
    }
};

// Export configuration for testing
export const config = {
    ...FILE_CONFIG,
    uploadDir
};
