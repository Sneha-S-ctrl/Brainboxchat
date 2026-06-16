import jwt from 'jsonwebtoken';
import redisClient from '../services/redis.service.js';

export const authUser = async (req, res, next) => {
    try {
        const authHeader = req.headers.authorization;
        
        // 🚀 Extract token directly from header safely
        const token = authHeader && authHeader.startsWith('Bearer ') 
            ? authHeader.split(' ')[1] 
            : null;

        if (!token) {
            return res.status(401).send({ error: 'Unauthorized User - Token Missing' });
        }

        const isBlackListed = await redisClient.get(token);

        if (isBlackListed) {
            return res.status(401).send({ error: 'Unauthorized User - Blacklisted Token' });
        }

        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = decoded;
        next();
    } catch (error) {
        console.log("🔐 Token verification error:", error.message);
        res.status(401).send({ error: 'Unauthorized User - Invalid Token' });
    }
}
