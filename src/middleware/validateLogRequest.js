const validateFile = (req, res, next) => {
  if (!req.file) {
    return res.status(400).json({
      status: 'error',
      code: 'MISSING_FILE',
      message: 'No log file uploaded',
      timestamp: new Date().toISOString(),
    });
  }

  const allowedTypes = ['text/plain', 'application/log'];
  if (!allowedTypes.includes(req.file.mimetype)) {
    return res.status(415).json({
      status: 'error',
      code: 'INVALID_FILE_TYPE',
      message: 'Only plain text log files are allowed',
      timestamp: new Date().toISOString(),
    });
  }

  next();
};

const validateText = (req, res, next) => {
  const { logData } = req.body;

  if (!logData) {
    return res.status(400).json({
      status: 'error',
      code: 'MISSING_LOG_DATA',
      message: 'Log data is required',
      timestamp: new Date().toISOString(),
    });
  }

  if (typeof logData !== 'string') {
    return res.status(400).json({
      status: 'error',
      code: 'INVALID_LOG_DATA',
      message: 'Log data must be a string',
      timestamp: new Date().toISOString(),
    });
  }

  next();
};

export { validateFile, validateText };
