export interface ErrorResponse
{
    message: string;
    code?: number;
    stack?: string;
    errors?: any[];
}
