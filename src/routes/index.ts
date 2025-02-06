import AuthRouter from "@/modules/Auth/auth.routes";
import { Router } from "express";

const MainRouter = Router();

MainRouter.use(`/auth`, AuthRouter);

export default MainRouter;
