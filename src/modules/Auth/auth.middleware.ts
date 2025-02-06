import { ObjectId } from "mongodb";
import { AppError } from "@/utils/error.utils";
import { User } from "../User/user.model";
import { config } from "@/config/environment.config";
import { getDB } from "@/config/db.config";
import { NextFunction, Request, Response } from "express";
import jwt from "jsonwebtoken";



export interface AuthRequest extends Request
{
    user?: {
        id: string;
        email: string;
        role: string;
    };
}

export const authenticate = async (
    req: AuthRequest,
    _res: Response,
    next: NextFunction
) =>
{
    try {
        const token = req.headers.authorization?.split(' ')[ 1 ];

        if (!token) {
            throw new AppError('Authentication required', 401);
        }

        // @ts-ignore
        const decoded = jwt.verify(token, config.jwt.accessSecret) as { userId: string; };
        const db = getDB();

        const user = await db.collection<User>('users').findOne({
            _id: new ObjectId(decoded.userId)
        });

        if (!user) {
            throw new AppError('User not found', 401);
        }

        req.user = {
            id: user._id.toString(),
            email: user.email,
            role: user.role
        };

        next();
    } catch (error) {
        if (error instanceof jwt.JsonWebTokenError) {
            next(new AppError('Invalid token', 401));
        } else {
            next(error);
        }
    }
};


export const requireRole = (roles: string[]) =>
{
    return (req: AuthRequest, _res: Response, next: NextFunction) =>
    {
        if (!req.user) {
            throw new AppError('Authentication required', 401);
        }

        if (!roles.includes(req.user.role)) {
            throw new AppError('Insufficient permissions', 403);
        }

        next();
    };
};
