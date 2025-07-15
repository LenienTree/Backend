import jwt from 'jsonwebtoken';

export const verifyAuthToken = (req, res, next) => {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ error: 'No token provided or malformed header' });
    }

    const token = authHeader.split(' ')[1];

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET); // ✅ Must match the JWT secret from Auth service
        req.user = {
            id: decoded.userId, // Fix: use userId from token payload
            email: decoded.email, // keep if present in token
            role: decoded.role
        };
        next();
    } catch (error) {
        console.error('JWT Verification Error:', error);
        return res.status(401).json({ error: 'Invalid or expired token' });
    }
};
