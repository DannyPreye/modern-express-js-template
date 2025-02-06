import bcrypt from 'bcryptjs';
import crypto from "crypto";
import { ObjectId } from 'mongodb';
import jwt from "jsonwebtoken";
import { getDB } from '@/config/db.config';
import { User } from '../User/user.model';
import { AppError } from '@/utils/error.utils';
import { config } from '@/config/environment.config';


export class AuthService
{
    private static readonly MAX_LOGIN_ATTEMPTS = 5;
    private static readonly LOCK_TIME = 15 * 60 * 1000; // 15 minutes


    static async generateTokens(userId: string)
    {
        // @ts-ignore
        const accessToken = jwt.sign(
            { userId },
            config.jwt.accessSecret as string,
            { expiresIn: config.jwt.accessExpiresIn }
        );

        // @ts-ignore
        const refreshToken = jwt.sign(
            { userId },
            config.jwt.refreshSecret as string,
            { expiresIn: config.jwt.refreshExpiresIn }

        );

        await getDB().collection<User>('users').updateOne(
            { _id: new ObjectId(userId) },
            { $set: { refreshToken, lastLogin: new Date() } }
        );

        return { accessToken, refreshToken };
    }

    static async register(userData: {
        email: string;
        password: string;
        firstName?: string;
        lastName?: string;
    })
    {
        const db = getDB();
        const userCollection = db.collection<User>('users');

        const existingUser = await userCollection.findOne({ email: userData.email });
        if (existingUser) {
            throw new AppError('User already exists', 409);
        }

        const verificationToken = crypto.randomBytes(32).toString('hex');

        const hashedPassword = await bcrypt.hash(userData.password, 12);


        const result = await userCollection.insertOne({
            ...userData,
            password: hashedPassword,
            verificationToken,
            isEmailVerified: false,
            role: 'user',
            failedLoginAttempts: 0,
            createdAt: new Date(),
            updatedAt: new Date()
        } as User);

        // Todo: handle send email logic here
        return {
            id: result.insertedId.toString(),

        };
    }

    static async login(email: string, password: string)
    {
        const db = getDB();
        const usersCollection = db.collection<User>('users');

        const user = await usersCollection.findOne({ email });
        if (!user) {
            throw new AppError('Invalid credentials', 401);
        }

        // Check if account is locked
        if (user.lockUntil && user.lockUntil > new Date()) {
            throw new AppError('Account is temporarily locked. Try again later', 423);
        }

        // Verify password
        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (!isPasswordValid) {
            // Increment failed login attempts
            const updates: Partial<User> = {
                failedLoginAttempts: (user.failedLoginAttempts || 0) + 1,
                updatedAt: new Date()
            } as Partial<User>;

            // Lock account if too many failed attempts
            if (updates?.failedLoginAttempts && updates.failedLoginAttempts >= this.MAX_LOGIN_ATTEMPTS) {
                updates.lockUntil = new Date(Date.now() + this.LOCK_TIME);
            }

            await usersCollection.updateOne(
                { _id: user._id },
                { $set: updates }
            );

            throw new AppError('Invalid credentials', 401);
        }

        // Reset failed login attempts on successful login
        await usersCollection.updateOne(
            { _id: user._id },
            {
                $set: {
                    failedLoginAttempts: 0,
                    lockUntil: null
                }
            }
        );

        // Generate tokens
        const tokens = await this.generateTokens(user._id.toString());

        return {
            tokens,
            user: {
                id: user._id,
                email: user.email,
                firstName: user.firstName,
                lastName: user.lastName,
                isEmailVerified: user.isEmailVerified
            }
        };
    }

    static async refreshToken(refreshToken: string)
    {
        try {
            // @ts-ignore
            const decoded = jwt.verify(refreshToken, config.jwt.refreshSecret) as { userId: string; };
            const db = getDB();

            const user = await db.collection<User>('users').findOne({
                _id: new ObjectId(decoded.userId),
                refreshToken
            });

            if (!user) {
                throw new AppError('Invalid refresh token', 401);
            }

            return this.generateTokens(user._id.toString());
        } catch (error) {
            throw new AppError('Invalid refresh token', 401);
        }
    }

    static async requestPasswordReset(email: string)
    {
        const db = getDB();
        const user = await db.collection<User>('users').findOne({ email });

        if (!user) {
            // Don't reveal if email exists
            return;
        }

        const resetToken = crypto.randomBytes(32).toString('hex');
        const resetPasswordToken = crypto
            .createHash('sha256')
            .update(resetToken)
            .digest('hex');

        await db.collection<User>('users').updateOne(
            { _id: user._id },
            {
                $set: {
                    resetPasswordToken,
                    resetPasswordExpires: new Date(Date.now() + 60 * 60 * 1000), // 1 hour
                    updatedAt: new Date()
                }
            }
        );

        //TODO: Send password reset email

    }

    static async resetPassword(token: string, newPassword: string)
    {
        const resetPasswordToken = crypto
            .createHash('sha256')
            .update(token)
            .digest('hex');

        const db = getDB();
        const user = await db.collection<User>('users').findOne({
            resetPasswordToken,
            resetPasswordExpires: { $gt: new Date() }
        });

        if (!user) {
            throw new AppError('Invalid or expired reset token', 400);
        }

        const hashedPassword = await bcrypt.hash(newPassword, 12);

        await db.collection<User>('users').updateOne(
            { _id: user._id },
            {
                $set: {
                    password: hashedPassword,
                    resetPasswordToken: null,
                    resetPasswordExpires: null,
                    updatedAt: new Date()
                }
            }
        );
    }

    static async verifyEmail(token: string)
    {
        const db = getDB();
        const user = await db.collection<User>('users').findOne({
            verificationToken: token
        });

        if (!user) {
            throw new AppError('Invalid verification token', 400);
        }

        await db.collection<User>('users').updateOne(
            { _id: user._id },
            {
                $set: {
                    isEmailVerified: true,
                    verificationToken: null,
                    updatedAt: new Date()
                }
            }
        );
    }

}
