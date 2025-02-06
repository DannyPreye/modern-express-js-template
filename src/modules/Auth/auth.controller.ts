import { Request, Response, NextFunction } from 'express';
import { AuthService } from './auth.service';
import { logger } from '@/utils/logger.utils';

export class AuthController
{
    static async register(req: Request, res: Response, next: NextFunction)
    {
        try {
            const result = await AuthService.register(req.body);
            res.status(201).json({
                message: 'Registration successful. Please verify your email.',
                userId: result.id
            });
        } catch (error) {
            next(error);
        }
    }

    static async login(req: Request, res: Response, next: NextFunction)
    {
        try {
            const { email, password } = req.body;
            const result = await AuthService.login(email, password);
            res.json(result);
        } catch (error) {
            next(error);
        }
    }

    static async refreshToken(req: Request, res: Response, next: NextFunction)
    {
        try {
            const { refreshToken } = req.body;
            const tokens = await AuthService.refreshToken(refreshToken);
            res.json(tokens);
        } catch (error) {
            next(error);
        }
    }

    static async requestPasswordReset(req: Request, res: Response, next: NextFunction)
    {
        try {
            await AuthService.requestPasswordReset(req.body.email);
            res.json({ message: 'If your email is registered, you will receive a password reset link.' });
        } catch (error) {
            next(error);
        }
    }

    static async resetPassword(req: Request, res: Response, next: NextFunction)
    {
        try {
            const { token, newPassword } = req.body;
            await AuthService.resetPassword(token, newPassword);
            res.json({ message: 'Password reset successful' });
        } catch (error) {
            next(error);
        }
    }

    static async verifyEmail(req: Request, res: Response, next: NextFunction)
    {
        try {
            await AuthService.verifyEmail(req.body.token);
            res.json({ message: 'Email verified successfully' });
        } catch (error) {
            next(error);
        }
    }
}
