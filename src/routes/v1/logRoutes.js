import express from 'express';
import { analyzeLogFile, analyzeText } from '../../controllers/v1/logController.js';
import { uploadMiddleware } from '../../middleware/fileUpload.js';

const router = express.Router();

// Add timeout wrapper
const withTimeout = (handler) => async (req, res, next) => {
    try {
        // Set a timeout for the response
        const timeout = setTimeout(() => {
            if (!res.headersSent) {
                res.status(504).json({
                    status: 'error',
                    message: 'Request timeout',
                    timestamp: new Date().toISOString()
                });
            }
        }, 300000); // 5 minutes

        // Clear timeout headers to prevent automatic timeout
        res.setTimeout(0);

        // Execute the handler
        await handler(req, res, next);

        // Clear the timeout if the request completes
        clearTimeout(timeout);
    } catch (error) {
        next(error);
    }
};

// Update routes with timeout wrapper
router.post('/analyze/file', 
    uploadMiddleware,
    withTimeout(analyzeLogFile)
);

router.post('/analyze/text', 
    withTimeout(analyzeText)
);

export default router;
