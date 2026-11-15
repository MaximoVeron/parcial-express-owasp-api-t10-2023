import { Router } from 'express';
import {
    getUserById,
    updateUser,
    getAllUsers,
    deleteUser,
    setProfilePictureFromUrl,
    searchUsers,
    updateEmail,
    getAccountInfo,
    recoverPassword,
    getSystemLogs,
    exportAllUsers
} from '../controllers/usersController';
import { authenticate, checkAdminRole } from '../middlewares/auth';

const router: Router = Router();

// Rutas de administración protegidas con control de rol (checkAdminRole)
router.get('/admin/system-logs', authenticate, checkAdminRole, getSystemLogs);
router.get('/admin/users/export_all', authenticate, checkAdminRole, exportAllUsers);

// Rutas generales y de perfil
router.get('/', authenticate, checkAdminRole, getAllUsers);
router.post('/profile-picture', setProfilePictureFromUrl); // A07: SSRF
router.put('/profile/update_email', authenticate, updateEmail);
router.get('/search', authenticate, searchUsers);
router.get('/account/:id', authenticate, getAccountInfo);
router.post('/recover', recoverPassword);

// Rutas por ID de usuario
router.get('/:id', authenticate, getUserById);
router.put('/:id', authenticate, updateUser);
router.delete('/:id', authenticate, checkAdminRole, deleteUser);

export default router;