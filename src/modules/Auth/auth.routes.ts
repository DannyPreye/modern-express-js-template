import { Router } from "express";
import { AuthController } from "./auth.controller";
import { authenticate } from "./auth.middleware";

const AuthRouter = Router();

AuthRouter.post(`/register`, AuthController.register);
AuthRouter.post(`/login`, AuthController.login);
AuthRouter.post(`/refresh-token`, authenticate, AuthController.refreshToken);
AuthRouter.post(`/request-password-reset`, AuthController.requestPasswordReset);
AuthRouter.post(`/reset-password`, AuthController.resetPassword);
AuthRouter.post(`/verify-email`, AuthController.verifyEmail);


export default AuthRouter;
