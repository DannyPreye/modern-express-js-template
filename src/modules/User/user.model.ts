import { z } from "zod";
import { ObjectId } from "mongodb";

export const UserSchema = z.object({
    _id: z.instanceof(ObjectId),
    email: z.string().email(),
    password: z.string(),
    firstName: z.string().optional(),
    lastName: z.string().optional(),
    role: z.enum([ 'user', 'admin' ]).default('user'),
    isEmailVerified: z.boolean().default(false),
    verificationToken: z.string().or(z.literal(null)).optional(),
    resetPasswordToken: z.string().or(z.literal(null)).optional(),
    resetPasswordExpires: z.date().or(z.literal(null)).optional(),
    lastLogin: z.date().optional(),
    refreshToken: z.string().or(z.literal(null)).optional(),
    failedLoginAttempts: z.number().default(0),
    lockUntil: z.date().or(z.literal(null)).optional(),
    createdAt: z.date(),
    updatedAt: z.date()
});

export type User = z.infer<typeof UserSchema>;
