import { NextFunction, Request, Response } from "express";
import { clerkClient, getAuth } from "@clerk/express";
import User from "../models/User.js";

export interface AuthRequest extends Request {
  user?: { id: string; name: string; email: string };
}

export const authMiddleware = async (
  req: AuthRequest,
  res: Response,
  next: NextFunction,
) => {
  try {
    const { userId } = getAuth(req);

    if (!userId) {
      res.status(401).json({ success: false, message: "Unauthenticated" });
      return;
    }

    // Check if user exists locally in MongoDB
    let localUser = await User.findById(userId);
    if (!localUser) {
      // Lazy sync: Fetch details from Clerk API
      const clerkUser = await clerkClient.users.getUser(userId);
      const email = clerkUser.emailAddresses[0]?.emailAddress ?? "";
      const name =
        [clerkUser.firstName, clerkUser.lastName].filter(Boolean).join(" ") ||
        clerkUser.username ||
        "Anonymous";
      // Create fallback handle
      let baseHandle = (clerkUser.username || email.split("@")[0] || userId)
        .toLowerCase()
        .replace(/[^a-z0-9_]/g, "");

      // Upsert with retry loop to handle race conditions
      let attempts = 0;
      while (!localUser && attempts < 5) {
        try {
          const suffix = attempts === 0 ? "" : attempts;
          const finalHandle = `${baseHandle}${suffix}`;

          localUser = await User.findOneAndUpdate(
            { _id: userId },
            {
              $setOnInsert: {
                _id: userId,
                name,
                email: email.toLowerCase(),
                handle: finalHandle,
                avatar: clerkUser.imageUrl || "",
                bio: "Hey there! I am using InstaChat.",
                isOnline: true,
                lastSeen: new Date(),
              },
            },
            { upsert: true, new: true, setDefaultsOnInsert: true },
          );
        } catch (err: any) {
          if (err.code === 11000) {
            attempts++;
            continue;
          }
          throw err;
        }
      }

      if (!localUser) {
        throw new Error("Failed to provision user after multiple attempts");
      }
    }

    // Attach user info to request for compatibility
    req.user = {
      id: localUser._id.toString(),
      name: localUser.name,
      email: localUser.email,
    };

    next();
  } catch (error) {
    console.error("Auth Middleware Error:", error);
    res
      .status(401)
      .json({ success: false, message: "Invalid or expired token" });
  }
};
