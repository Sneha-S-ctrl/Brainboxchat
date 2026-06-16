import jwt from 'jsonwebtoken';
import redisClient from '../services/redis.service.js';

export const authUser = async (req, res, next) => {
    try {
        const authHeader = req.headers.authorization;
        const tokenFromHeader = authHeader?.split(' ')[1];
        const tokenFromCookie = req.cookies?.token;
        const token = tokenFromHeader || tokenFromCookie;

        console.log("🔐 Received Token:", token); // 🪵 Debug log

        if (!token) {
            return res.status(401).send({ error: 'Unauthorized User - Token Missing' });
        }

        const isBlackListed = await redisClient.get(token);

        if (isBlackListed) {
            res.cookie('token', '');
            return res.status(401).send({ error: 'Unauthorized User - Blacklisted Token' });
        }

        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = decoded;
        next();
    } catch (error) {
        console.log("🔐 Token verification error:", error);
        res.status(401).send({ error: 'Unauthorized User - Invalid Token' });
    }
}
