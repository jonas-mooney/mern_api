const jwt = require('jsonwebtoken')
const asyncHandler = require('express-async-handler')
const User = require('../models/userModel')

const protect = asyncHandler(async(req, res, next) => {
    let token

    if(req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
        try {
            // get token from header (turning token into an array where 'bearer' is first item and token is the second)
            token = req.headers.authorization.split(' ')[1]

            // decode and verify token
            const decoded = jwt.verify(token, process.env.JWT_SECRET)

            // get user from the token (user id) and assign to req.user
            // who can then access any protected route
            // excluding the hashed password
            req.user = await User.findById(decoded.id).select('-password')

            // calling the next piece of middleware
            next()
        } catch (error) {
            console.log(error)
            res.status(401)
            throw new Error('Not authorized')
        }
    }

    if(!token) {
        res.status(401)
        throw new Error('Not authorized, no token')
    }
})


module.exports = { protect }