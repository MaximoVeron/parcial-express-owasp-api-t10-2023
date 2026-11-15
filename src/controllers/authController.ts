import { Request, Response } from 'express';
import { db, hashPassword, verifyPassword } from '../services/Database';
import jwt from 'jsonwebtoken';
import crypto from 'crypto';
import { User } from '../models/user';
import axios from 'axios';

export const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(64).toString('hex');

// Lista de revocación de tokens en memoria para invalidar sesiones al hacer logout
const revokedTokens = new Set<string>();

export const isTokenRevoked = (token: string): boolean => {
  return revokedTokens.has(token);
};

// Control de intentos fallidos de inicio de sesión (protección contra fuerza bruta)
const MAX_LOGIN_ATTEMPTS = 5;
const LOCKOUT_TIME_MS = 15 * 60 * 1000; // 15 minutos
const loginAttempts = new Map<string, { count: number; lockUntil: number }>();

export const register = async (req: Request, res: Response) => {
  try {
    const { username, password, email } = req.body;

    if (!username || !password || !email) {
      return res.status(400).json({ message: 'Username, password and email are required.' });
    }

    if (typeof password !== 'string' || password.length < 8) {
      return res.status(400).json({ message: 'Password must be at least 8 characters long.' });
    }

    let countryData: any = {};
    try {
      const geoResponse = await axios.get(`https://fictional-geo-api.com/email-to-country?email=${email}`);
      countryData = geoResponse.data;
    } catch (geoError) {
      console.error('Fallo al obtener datos de la API de geolocalización:', (geoError as Error).message);
    }

    const hashedPassword = hashPassword(password);
    const sql = 'INSERT INTO users (username, password, email, role, profile_picture_url) VALUES (?, ?, ?, ?, ?)';
    db.run(sql, [username, hashedPassword, email, 'user', countryData.profile_picture_url], function (err) {
      if (err) {
        return res.status(500).json({ message: 'Error creating user', error: err.message });
      }
      res.status(201).json({ message: 'User created', userId: this.lastID, data: countryData });
    });

  } catch (error) {
    res.status(500).json({ message: 'Error creating user', error: (error as Error).message });
  }
};

export const login = async (req: Request, res: Response) => {
  const { username, password } = req.body;

  if (!username || !password || typeof username !== 'string' || typeof password !== 'string') {
    return res.status(400).json({ message: 'Username and password are required' });
  }

  const attemptKey = `${req.ip}:${username}`;
  const attemptRecord = loginAttempts.get(attemptKey);
  const now = Date.now();

  if (attemptRecord && attemptRecord.lockUntil > now) {
    return res.status(429).json({
      message: 'Demasiados intentos fallidos. Cuenta bloqueada temporalmente. Intente más tarde.'
    });
  }

  const sql = 'SELECT * FROM users WHERE username = ?';
  db.get(sql, [username], (err, user: User) => {
    if (err) {
      return res.status(500).json({ message: 'Error logging in', error: err.message });
    }

    if (!user || !verifyPassword(password, user.password)) {
      const currentCount = attemptRecord && attemptRecord.lockUntil <= now ? 1 : (attemptRecord?.count || 0) + 1;
      const lockUntil = currentCount >= MAX_LOGIN_ATTEMPTS ? now + LOCKOUT_TIME_MS : 0;
      loginAttempts.set(attemptKey, { count: currentCount, lockUntil });
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    loginAttempts.delete(attemptKey);

    const token = jwt.sign(
      { id: user.id, role: user.role },
      JWT_SECRET,
      { algorithm: 'HS256', expiresIn: '15m' }
    );
    res.json({ token });
  });
};

export const logout = (req: Request, res: Response) => {
  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith('Bearer ')) {
    const token = authHeader.split(' ')[1];
    if (token) {
      revokedTokens.add(token);
    }
  }
  res.json({ message: 'Sesión cerrada con éxito y token revocado en el servidor.' });
};