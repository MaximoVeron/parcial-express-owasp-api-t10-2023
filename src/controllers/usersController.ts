import { Request, Response } from 'express';
import { db } from '../services/Database';
import { User } from '../models/user';
import axios from 'axios';
import dns from 'dns';
import net from 'net';

const isPrivateOrInternalIP = (ip: string): boolean => {
  if (net.isIPv4(ip)) {
    const parts = ip.split('.').map(Number);
    return (
      parts[0] === 0 ||
      parts[0] === 10 ||
      parts[0] === 127 ||
      (parts[0] === 169 && parts[1] === 254) ||
      (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) ||
      (parts[0] === 192 && parts[1] === 168)
    );
  }
  if (net.isIPv6(ip)) {
    const normalized = ip.toLowerCase();
    return (
      normalized === '::1' ||
      normalized === '::' ||
      normalized.startsWith('fc') ||
      normalized.startsWith('fd') ||
      normalized.startsWith('fe80') ||
      normalized.startsWith('::ffff:127.') ||
      normalized.startsWith('::ffff:10.') ||
      normalized.startsWith('::ffff:192.168.') ||
      normalized.startsWith('::ffff:169.254.')
    );
  }
  return true;
};

interface CustomRequest extends Request {
    user?: User;
}

export const getUserById = async (req: CustomRequest, res: Response) => {
  try {
    const { id } = req.params;
    const requestedId = Number(id);

    if (!req.user || (req.user.id !== requestedId && req.user.role !== 'admin')) {
      return res.status(403).json({ message: 'Acceso denegado: no tienes permisos sobre este recurso.' });
    }

    const sql = 'SELECT id, username, email, role, profile_picture_url FROM users WHERE id = ?';
    db.get(sql, [requestedId], (err, user: User) => {
      if (err) {
        return res.status(500).json({ message: 'Server error', error: err.message });
      }

      if (!user) {
        return res.status(404).json({ message: 'User not found' });
      }

      res.json(user);
    });
  } catch (error) {
    res.status(500).json({ message: 'Server error', error: (error as Error).message });
  }
};

export const updateUser = async (req: CustomRequest, res: Response) => {
  try {
    const { id } = req.params;
    const requestedId = Number(id);

    if (!req.user || (req.user.id !== requestedId && req.user.role !== 'admin')) {
      return res.status(403).json({ message: 'Acceso denegado: no puedes modificar otro usuario.' });
    }

    const ALLOWED_FIELDS = ['username', 'email', 'profile_picture_url'] as const;
    const sanitizedEntries = Object.entries(req.body || {}).filter(([key]) =>
      (ALLOWED_FIELDS as readonly string[]).includes(key)
    );

    if (sanitizedEntries.length === 0) {
      return res.status(400).json({
        message: 'No se proporcionaron campos válidos para actualizar. Campos permitidos: username, email, profile_picture_url.'
      });
    }

    const fields = sanitizedEntries.map(([key]) => `${key} = ?`).join(', ');
    const values = sanitizedEntries.map(([, value]) => value);

    const sql = `UPDATE users SET ${fields} WHERE id = ?`;
    db.run(sql, [...values, requestedId], function (err) {
      if (err) {
        return res.status(500).json({ message: 'Server error', error: err.message });
      }
      if (this.changes === 0) {
        return res.status(404).json({ message: 'User not found or no changes made.' });
      }
      res.json({ message: 'User updated successfully', changes: this.changes });
    });
  } catch (error) {
    res.status(500).json({ message: 'Server error', error: (error as Error).message });
  }
};

export const getAllUsers = async (req: Request, res: Response) => {
  try {
    const DEFAULT_LIMIT = 10;
    const MAX_LIMIT = 50;

    const rawLimit = req.query.limit !== undefined ? parseInt(req.query.limit as string, 10) : DEFAULT_LIMIT;
    const rawPage = req.query.page !== undefined ? parseInt(req.query.page as string, 10) : 1;

    if (Number.isNaN(rawLimit) || rawLimit <= 0 || Number.isNaN(rawPage) || rawPage <= 0) {
      return res.status(400).json({ message: 'Los parámetros "limit" y "page" deben ser enteros positivos.' });
    }

    const limit = Math.min(rawLimit, MAX_LIMIT);
    const offset = (rawPage - 1) * limit;

    const sql = 'SELECT id, username, email, role, profile_picture_url FROM users LIMIT ? OFFSET ?';
    const params: number[] = [limit, offset];

    db.all(sql, params, (err, users: User[]) => {
      if (err) {
        return res.status(500).json({ message: 'Server error', error: err.message });
      }
      res.json({
        page: rawPage,
        limit,
        count: users.length,
        data: users
      });
    });
  } catch (error) {
    res.status(500).json({ message: 'Server error', error: (error as Error).message });
  }
};

export const deleteUser = async (req: Request, res: Response) => {
  try {
    const { id } = req.params;

    const sql = 'DELETE FROM users WHERE id = ?';
    db.run(sql, [id], function (err) {
      if (err) {
        return res.status(500).json({ message: 'Server error', error: err.message });
      }
      if (this.changes === 0) {
        return res.status(404).json({ message: 'User not found.' });
      }
      res.status(200).json({ message: 'User deleted' });
    });
  } catch (error) {
    res.status(500).json({ message: 'Server error', error: (error as Error).message });
  }
};

export const setProfilePictureFromUrl = async (req: CustomRequest, res: Response) => {
  const { url } = req.body;

  if (!url || typeof url !== 'string') {
    return res.status(400).json({ message: 'URL is required' });
  }

  let parsedUrl: URL;
  try {
    parsedUrl = new URL(url);
  } catch {
    return res.status(400).json({ message: 'Invalid URL format.' });
  }

  if (parsedUrl.protocol !== 'https:') {
    return res.status(400).json({ message: 'Only HTTPS URLs are allowed.' });
  }

  const hostname = parsedUrl.hostname.toLowerCase();
  if (hostname === 'localhost' || hostname.endsWith('.local') || hostname.endsWith('.internal')) {
    return res.status(403).json({ message: 'Access to internal hosts is forbidden.' });
  }

  try {
    const addresses = await dns.promises.lookup(hostname, { all: true });
    if (addresses.length === 0 || addresses.some(addr => isPrivateOrInternalIP(addr.address))) {
      return res.status(403).json({ message: 'URL resolves to a forbidden private or loopback IP address.' });
    }

    const response = await axios.get(parsedUrl.toString(), {
      responseType: 'arraybuffer',
      timeout: 3000,
      maxRedirects: 0,
      maxContentLength: 2 * 1024 * 1024
    });

    const contentType = String(response.headers['content-type'] || '');
    if (!contentType.startsWith('image/')) {
      return res.status(400).json({ message: 'The remote resource is not a valid image.' });
    }

    console.log(`Fetched image from ${parsedUrl.toString()}, size: ${response.data.length} bytes.`);

    res.status(200).json({ message: 'Profile picture updated from URL.' });
  } catch (error) {
    res.status(400).json({ message: 'Failed to fetch a valid image from the provided URL.' });
  }
};

export const searchUsers = (req: Request, res: Response) => {
    const query = req.query.q as string;

    const sql = `SELECT id, username, role FROM users WHERE username LIKE '%${query}%'`;

    db.all(sql, [], (err, rows: User[]) => {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        res.json({ users: rows });
    });
};

export const updateEmail = (req: CustomRequest, res: Response) => {
    const { new_email } = req.body;
    const loggedInUser = req.user!;

    const sql = 'UPDATE users SET email = ? WHERE id = ?';
    db.run(sql, [new_email, loggedInUser.id], function (err) {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        if (this.changes === 0) {
            return res.status(404).send('User not found or email not changed.');
        }
        res.json({ message: 'Email updated successfully.' });
    });
};

export const getAccountInfo = (req: CustomRequest, res: Response) => {
    const accountId = Number(req.params.id);

    if (!req.user || (req.user.id !== accountId && req.user.role !== 'admin')) {
        return res.status(403).json({ error: 'Acceso denegado a la información de esta cuenta.' });
    }

    const sql = 'SELECT id, username, role FROM users WHERE id = ?';

    db.get(sql, [accountId], (err, row: User) => {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        if (!row) {
            return res.status(404).json({ error: 'Cuenta no encontrada' });
        }
        res.json({ account: row });
    });
};

export const recoverPassword = (req: Request, res: Response) => {
    const { username, security_answer } = req.body;

    res.status(501).json({ message: 'Función no implementada.' });
};

export const getSystemLogs = (req: Request, res: Response) => {
    res.json({ logs: "Mostrando logs del sistema... Acceso concedido.", user: (req as any).user });
};

export const exportAllUsers = (req: CustomRequest, res: Response) => {

    const sql = 'SELECT id, username, email, role FROM users';
    db.all(sql, [], (err, rows: User[]) => {
        if (err) {
            return res.status(500).json({ error: err.message });
        }

        res.json({
            total_users: rows.length,
            user_list: rows.map(u => ({ userId: u.id, username: u.username, role: u.role }))
        });
    });
};