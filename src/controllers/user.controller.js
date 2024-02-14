import { asyncHandler } from '../utils/asyncHandler.js'
import { ApiError } from '../utils/ApiError.js'
import { User } from './../models/user.model.js';
import { uploadOnCloudinary } from '../utils/Cloudinary.js';
import { ApiResponse } from '../utils/ApiResponse.js'
import jwt from 'jsonwebtoken';

const generateAccessAndRefreshToken = async(userId) => {
    try {
        const user = await User.findById(userId)
        const accessToken = user.generateAccessToken()
        const refreshToken = user.generateRefreshToken()
        user.refreshToken = refreshToken
        await user.save({ validateBeforeSave: false })

        return { accessToken, refreshToken }

    } catch (error) {
        throw new ApiError(500, "Something went Wrong")
    }
}

const registerUser =  asyncHandler( async(req, res) => {
    // get user details from frontend
    const {fullName, email, username, password} = req.body;


    // validations using email & username
    if(
        [fullName, email, username, password].some( (field) =>
        field === undefined || field?.trim() === "" )
        ) {
            throw new ApiError(400, 'All fields are required.')
        }


    // check if user already exists
    const existedUser = await User.findOne({
        $or: [ { username }, { email }]
    })
    if(existedUser){
        throw new ApiError(409, 'User with username or email already exists.')
    }


    // check for images, especially avatar
    const avatarLocalPath = req.files?.avatar[0]?.path;
    // const coverImageLocalPath = req.files?.coverImage[0]?.path;
    let coverImageLocalPath;
    if( req.files && Array.isArray(req.files.coverImage) && req.files.coverImage.length > 0){
        coverImageLocalPath = req.files.coverImage[0].path;
    }
    if(!avatarLocalPath){
        throw new ApiError(400, 'Avatar is required.')
    }


    // upload file to cloudinary - avatar
    const avatar = await uploadOnCloudinary(avatarLocalPath)
    const coverImage = await uploadOnCloudinary(coverImageLocalPath)
    if(!avatar){
        throw new ApiError(400, 'Avatar is required.')
    }


    // create user object - create entry in db
    // remove password and refresh token field from response
    // check for user creation
    const user = await User.create({
        fullName,
        avatar: avatar.url,
        coverImage: coverImage?.url || " ",
        email,
        password,
        username: username.toLowerCase()
    })

    const createdUser = await User.findById(user._id).select(" -password -refreshToken ")
    if(!createdUser){
        throw new ApiError(500, 'Something went wrong, while registering user.')
    }


    //return res
    return res.status(201).json(
        new ApiResponse(200, createdUser, 'User registered succesfully.')
    )


})

const loginUser = asyncHandler( async(req, res) => {

    // req body --> send data
    const { username, email, password }= req.body


    // username or email
    if(!(username || email)){
        throw new ApiError(400, "Username or email is required.")
    }


    // find the user
    const user = await User.findOne({
        $or: [ {username}, {email} ]
    })

    if(!user){
        throw new ApiError(404, "User does not exist.")
    }


    // password check
    const isPasswordValid = await user.isPasswordCorrect(password)

    if(!isPasswordValid){
        throw new ApiError(401, "Invalid credentials.")
    }


    // access and refresh token
    const { accessToken, refreshToken } = await generateAccessAndRefreshToken(user._id)


    // send cookie
    const loggedInUser = await User.findById(user._id).
    select(" --password --refreshToken ")

    const options = {
        httpOnly: true,
        secure: true
    }

    return res
    .status(200)
    .cookie("accessToken", accessToken, options)
    .cookie("refreshToken", refreshToken, options)
    .json(
        new ApiResponse(200, {
            user: loggedInUser, accessToken, refreshToken
        },
        "User Logged in successfully."
        )
    )

})

const logoutUser = asyncHandler( async(req, res) => {
    await User.findByIdAndUpdate(
        req.user._id,
        {
            $set: {
                refreshToken: undefined
            }
        },
        {
            new: true
        }
    )

    const options = {
        httpOnly: true,
        secure: true
    }

    return res
    .status(200)
    .clearCookie("accessToken", options)
    .clearCookie("refreshToken", options)
    .json(new ApiResponse(200, {}, "User logged out successfully."))
})

const refreshRefreshToken = asyncHandler( async(req, res) => {
    try {
        const incomingRefreshToken = req.cookies.refreshToken || req.body.refreshToken

        if (!incomingRefreshToken) {
            throw new ApiError(401, "Invalid refresh token.")
        }

        const decodedToken = jwt.verify(
            incomingRefreshToken,
            process.env.REFRESH_TOKEN_SECRET
        )

        const user = await User.findById(decodedToken._id)

        if (!user) {
            throw new ApiError(401, "Unauthorised Access.")
        }

        if(decodedToken !== user?.refreshToken){
            throw new ApiError(402, "Refresh token expired.")
        }

        const options = {
            httpOnly: true,
            secure: true
        }

        const { accessToken, newRefreshToken}= await generateAccessAndRefreshToken(user._id)

        return res
        .status(200)
        .cookie("accessToken", accessToken, options)
        .cookie("refreshToken", newRefreshToken, options)
        .json(
            200,
            { accessToken, refreshToken: newRefreshToken },
            "Refresh Token refreshed"
        )
    } catch (error) {
        throw new ApiError(401, error?.message || "Invalid refresh token.")
    }
})

export {
    registerUser,
    loginUser,
    logoutUser,
    refreshRefreshToken
}