/* eslint-disable require-await */
import ApiError from '../utils/ApiError.ts';
import { NextFunction, Request, Response } from 'express';
import httpStatus from 'http-status';
import jwt from 'jsonwebtoken';

/**
 * Authentication middleware
 * Extracts backend JWT, verifies it, verifies IDP access token, and attaches user to request
 * If IDP token is expired, client should use /auth/refresh endpoint
 */

export function verifyJWT(token: string) {
    try {
        const publicKeyBase64 = process.env.IDP_PUBLIC_KEY_BASE64!;
        const publicKey = Buffer.from(publicKeyBase64, 'base64').toString('utf8');
        const decoded = jwt.verify(token, publicKey, { algorithms: ['RS256'] }) as jwt.JwtPayload;
        return { ...decoded, userId: decoded.sub, invalid: false } as {
            userId: string;
            invalid: false;
        };
    } catch (error: any) {
        return { invalid: true } as { invalid: true; userId?: never };
    }
}

const auth = async (req: Request, res: Response, next: NextFunction) => {
    // Extract token from Authorization header
    const authorization = req.headers.authorization;
    if (!authorization) return next(new ApiError(httpStatus.UNAUTHORIZED, 'Invalid access token'));
    const [type, token] = authorization.split(' ');
    if (type !== 'Bearer') return next(new ApiError(httpStatus.UNAUTHORIZED, 'Invalid access token'));
    const decoded = verifyJWT(token);
    if (!decoded?.userId) return next(new ApiError(httpStatus.UNAUTHORIZED, 'Invalid or expired token'));
    // Attach user info to request
    (req as any).user = {
        userId: decoded.userId,
        accessToken: token
    };
    next();
};

export default auth;
