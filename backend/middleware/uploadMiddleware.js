import multer from 'multer';

// Accept only image files
const fileFilter = (req, file, cb) => {
    file.mimetype.startsWith('image/')
        ? cb(null, true)
        : cb(new Error('Only image files are allowed!'), false);
};

// Configure multer (in-memory)
const upload = multer({
    storage: multer.memoryStorage(),
    fileFilter,
    limits: {
        fileSize: 5 * 1024 * 1024, // Max 5MB
        files: 1
    }
});

// Middleware: Single file upload
export const uploadSingleImage = upload.single('eventimage');

// Middleware: Multer error handling
export const handleUploadError = (err, req, res, next) => {
    if (err instanceof multer.MulterError) {
        let message = 'File upload error.';
        if (err.code === 'LIMIT_FILE_SIZE') message = 'File too large. Max size is 5MB.';
        if (err.code === 'LIMIT_FILE_COUNT') message = 'Too many files. Only one is allowed.';
        return res.status(400).json({ error: message });
    }

    if (err.message === 'Only image files are allowed!') {
        return res.status(400).json({ error: err.message });
    }

    next(err);
};

// Middleware: Ensure file was uploaded
export const checkFileUpload = (req, res, next) => {
    if (!req.file) {
        return res.status(400).json({ error: 'No image uploaded.' });
    }
    next();
};
