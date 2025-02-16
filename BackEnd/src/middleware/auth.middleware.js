import jwt from "jsonwebtoken"
import User from "../models/user.model.js"

export const protectRoute = async(req, res, next) => {
    try {
        const token = req.cookies.jwt

        // Handling no token
        if (!token){
            return res.status(401).json({message: "No token provided - Unauthorized transaction"})
        }

        // Token
        const decoded = jwt.verify(token, process.env.JWT_SECRET)

        // Handling the invalid token
        if (!decoded){
            return res.status(401).json({message: "Invalid token - Unauthorized transaction"})
        }

        const user = await User.findById(decoded.userId).select("-password")

        // Handling when the user not found
        if (!user) {
            return res.status(404).json({ message: "User not found" });
        }

        // Found the user
        req.user = user
        next()


    } catch (error) {
        console.log("Error in protectRoute middleware: ", error.message);
        res.status(500).json({ message: "Internal server error" })
    }
}