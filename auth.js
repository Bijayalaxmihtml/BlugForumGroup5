import jwt from 'jsonwebtoken';
import bcrypt from 'bcrypt';
import dotenv from 'dotenv';
dotenv.config();
const JWT_SECRET = process.env.JWT_SECRET || 'change_me';
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '2h';
export async function hashPassword(plain) { return bcrypt.hash(plain, 12); }
export async function checkPassword(plain, hash) { return bcrypt.compare(plain, hash); }
export function signToken(payload) { return jwt.sign(payload, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN }); }
export function verifyToken(token) { return jwt.verify(token, JWT_SECRET); }
