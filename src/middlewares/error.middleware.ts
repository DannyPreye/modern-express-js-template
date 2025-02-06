
import { config } from '@/config/environment.config';
import { ErrorResponse } from '@/types/error.types';
import { AppError } from '@/utils/error.utils';
import { logger } from '@/utils/logger.utils';
import { Request, Response, NextFunction } from 'express';
import { MongoError } from 'mongodb';
import { ZodError } from 'zod';


export const errorHandler = (
    err: Error,
    req: Request,
    res: Response<ErrorResponse>,
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    next: NextFunction
) =>
{
    logger.error({
        err,
        req: {
            method: req.method,
            path: req.path,
            body: req.body,
            query: req.query,
            params: req.params,
        },
    });

    // Default error response
    let statusCode = 500;
    let message = 'Internal Server Error';
    let errors: any[] | undefined;

    // Handle different types of errors
    if (err instanceof AppError) {
        statusCode = err.statusCode;
        message = err.message;
        errors = err.errors;
    } else if (err instanceof ZodError) {
        statusCode = 400;
        message = 'Validation Error';
        errors = err.errors;
    } else if (err instanceof MongoError) {
        // Handle MongoDB specific errors
        if (err.code === 11000) {
            statusCode = 409;
            message = 'Duplicate key error';
        }
    } else if (err instanceof SyntaxError && 'body' in err) {
        statusCode = 400;
        message = 'Invalid JSON payload';
    }

    // Prepare the error response
    const errorResponse: ErrorResponse = {
        message,
        code: statusCode,
        ...(errors && { errors }),
        ...(config.nodeEnv === 'development' && { stack: err.stack }),
    };

    // Log the error (but not in test environment)
    if (config.nodeEnv !== 'test') {
        logger.error({
            statusCode,
            message: err.message,
            stack: err.stack,
            errors,
        });
    }

    res.status(statusCode).json(errorResponse);
};
