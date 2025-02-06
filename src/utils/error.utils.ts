export class AppError extends Error
{
    public readonly statusCode: number;
    public readonly isOperational: boolean;
    public readonly errors?: any[];

    constructor (message: string, statusCode: number, errors?: any[])
    {
        super(message);
        this.statusCode = statusCode;
        this.isOperational = true;
        this.errors = errors;

        // Capturing stack trace
        Error.captureStackTrace(this, this.constructor);
    }
}

export class ValidationError extends AppError
{
    constructor (errors: any[])
    {
        super('Validation Error', 400, errors);
    }
}

export class NotFoundError extends AppError
{
    constructor (resource: string = 'Resource')
    {
        super(`${resource} not found`, 404);
    }
}

export class UnauthorizedError extends AppError
{
    constructor (message: string = 'Unauthorized access')
    {
        super(message, 401);
    }
}

export class ForbiddenError extends AppError
{
    constructor (message: string = 'Forbidden access')
    {
        super(message, 403);
    }
}
