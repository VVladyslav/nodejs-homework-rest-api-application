import User from "../models/user.js";
import path from "path";
import fs from "fs/promises";
import { HttpError, sendEmail } from "../helpers/index.js";
import { ctrlWrapper } from "../decorators/index.js";
import bcrypt from "bcryptjs";
import dotenv from "dotenv";
import jwt from "jsonwebtoken";
import gravatar from "gravatar";
import Jimp from "jimp";
import { nanoid } from "nanoid";

dotenv.config();

const { JWT_SECRET, BASE_URL } = process.env;

const register = async (req, res) => {
  const { email, password } = req.body;
  const user = await User.findOne({ email });
  if (user) {
    throw HttpError(409, "Email in use");
  }

  const hashedPassword = await bcrypt.hash(password, 10);
  const verificationToken = nanoid();
  const avatar = gravatar.url(email);
  const newUser = await User.create({
    ...req.body,
    password: hashedPassword,
    verificationToken,
    avatarURL: avatar,
  });
  const verifyEmail = {
    to: email,
    subject: "Email verification2",
    html: `<a href="${BASE_URL}/api/auth/verify/${verificationToken}" target="_blanc">Click to verify email</a>`,
  };

  await sendEmail(verifyEmail);

  res.status(201).json({
    user: {
      email: newUser.email,
      subscription: newUser.subscription,
    },
  });
};

const verify = async (req, res) => {
  const { verificationToken } = req.params;
  const user = await User.findOne({ verificationToken });
  if (!user) {
    throw HttpError(404, "User not found");
  }
  await User.findByIdAndUpdate(user._id, {
    verificationToken: null,
    verify: true,
  });
  res.json({
    message: "Verification successful",
  });
};

const resendVerifyEmail = async (req, res) => {
  const { email } = req.body;
  const user = User.findOne({ email });
  if (!user) {
    throw HttpError(404, "User not found");
  }
  if (user.verify) {
    throw HttpError(400, "Verification has already been passed");
  }
  const verifyEmail = {
    to: email,
    subject: "Email verification",
    html: `<a href="${BASE_URL}/api/auth/verify/${user.verificationToken}" target="_blanc">Click to verify email</a>`,
  };

  await sendEmail(verifyEmail);

  res.json({
    message: "Verification email resent",
  });
};

const login = async (req, res) => {
  const { email, password } = req.body;
  const user = await User.findOne({ email });
  if (!user) {
    throw HttpError(401, "Email or password is wrong");
  }
  const passwordCompare = await bcrypt.compare(password, user.password);
  if (!passwordCompare) {
    throw HttpError(401, "Email or password is wrong");
  }
  if (!user.verify) {
    throw HttpError(403, "Email verification is needed");
  }
  const payload = {
    id: user._id,
  };
  const token = jwt.sign(payload, JWT_SECRET, { expiresIn: "23h" });
  await User.findByIdAndUpdate(user._id, { token });
  res.json({
    token,
    user: {
      email,
      subscription: user.subscription,
    },
  });
};

const avatarsPath = path.resolve("public", "avatars");

const updateAvatar = async (req, res) => {
  // * завантажуємо, обробляємо і зберігаємо новий аватар
  const { path: oldPath, filename } = req.file;
  const image = await Jimp.read(oldPath);
  image.resize(250, 250);
  const newPath = path.join(avatarsPath, filename);
  image.write(newPath);
  fs.unlink(oldPath);
  let { _id, avatarURL } = req.user;

  // *отримуємо назву файла попереднього аватара (розвертаэмо масив, щоб назва файлу гарантовано була першим елементом масиву)

  const avatarsDirContent = await fs.readdir(path.join("public", "avatars"));
  const usersAvatarFileName = avatarURL.split("\\").reverse();
  const isCurrentAvatarExist = avatarsDirContent.includes(
    usersAvatarFileName[0]
  );

  // * перевіряємо папку на наявність аватара користувач, записуємо новий файл, видаляємо старий за наявності

  if (!isCurrentAvatarExist) {
    avatarURL = path.join("avatars", filename);
    await User.findByIdAndUpdate(_id, { avatarURL });
  } else {
    fs.unlink(path.resolve("public", avatarURL));
    avatarURL = path.join("avatars", filename);
    await User.findByIdAndUpdate(_id, { avatarURL });
  }
  res.json({
    avatarURL,
  });
};

const getCurrent = (req, res) => {
  const { email, subscription } = req.user;
  res.json({
    email,
    subscription,
  });
};

const logout = async (req, res) => {
  const { _id } = req.user;
  await User.findByIdAndUpdate(_id, { token: "" });
  res.json();
};

const updateUsersSubscription = async (req, res) => {
  const { _id } = req.user;
  const { ...query } = req.query;
  await User.findByIdAndUpdate(_id, { ...query });
  res.json();
};

export default {
  register: ctrlWrapper(register),
  verify: ctrlWrapper(verify),
  resendVerifyEmail: ctrlWrapper(resendVerifyEmail),
  signin: ctrlWrapper(login),
  updateAvatar: ctrlWrapper(updateAvatar),
  getCurrent: ctrlWrapper(getCurrent),
  logout: ctrlWrapper(logout),
  updateUsersSubscription: ctrlWrapper(updateUsersSubscription),
};
