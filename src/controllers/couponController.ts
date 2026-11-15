import { Response } from 'express';
import { CustomRequest } from '../middlewares/auth';

let totalCoupons = 100; // Recurso limitado
const claimedUsers = new Set<number>();
const ipAttemptTimestamps = new Map<string, number>();
const MIN_INTERVAL_MS = 5000; // Cooldown anti-automatización por IP

export const claimCoupon = (req: CustomRequest, res: Response) => {
  if (!req.user) {
    return res.status(401).json({ message: 'Authentication required to claim a coupon.' });
  }

  const clientIp = req.ip || 'unknown';
  const now = Date.now();
  const lastAttempt = ipAttemptTimestamps.get(clientIp) || 0;

  if (now - lastAttempt < MIN_INTERVAL_MS) {
    return res.status(429).json({
      message: 'Demasiadas solicitudes. Por favor espere unos segundos antes de intentar nuevamente.'
    });
  }
  ipAttemptTimestamps.set(clientIp, now);

  if (claimedUsers.has(req.user.id)) {
    return res.status(409).json({
      message: 'Ya has reclamado tu cupón promocional. Solo se permite un cupón por usuario.'
    });
  }

  if (totalCoupons > 0) {
    totalCoupons--;
    claimedUsers.add(req.user.id);
    res.status(200).json({ message: 'Coupon claimed!', coupons_left: totalCoupons });
  } else {
    res.status(400).json({ message: 'No more coupons left!' });
  }
};