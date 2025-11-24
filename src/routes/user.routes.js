// src/routes/user.routes.js
import { Router } from "express";
import { loginUser, registerUser, logoutUser, refreshAccessToken } from "../controllers/user.controller.js";
import { upload } from "../middlewares/multer.middleware.js";
import { verifyJWT } from "../middlewares/auth.middleware.js";

const router = Router();

// Register route (multipart/form-data with files)
router.route("/register").post(
  upload.fields([
    { name: "avatar", maxCount: 1 },
    { name: "coverImage", maxCount: 1 }
  ]),
  registerUser
);

// Login route (raw JSON body)
router.route("/login").post(loginUser);

// Logout route (secured)
router.route("/logout").post(verifyJWT, logoutUser);

// Refresh token route
router.route("/refresh-token").post(refreshAccessToken);

export default router;
