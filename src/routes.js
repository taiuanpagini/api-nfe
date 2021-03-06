import { Router } from 'express';
import multer from 'multer';
import UserController from './app/controllers/UserController';
import SessionController from './app/controllers/SessionController';
import FileController from './app/controllers/FileController';
import ProviderController from './app/controllers/ProviderController';
import NotificationController from './app/controllers/NotificationController';
import authMiddleware from './app/middlewares/auth';
import multerConfig from './config/multer';

const routes = new Router();
const upload = multer(multerConfig);

routes.post('/user', UserController.store);
routes.post('/sessions', SessionController.store);

// Todas as rotas que forem chamadas a partir daqui tem que ser autenticada
routes.use(authMiddleware);
routes.get('/users', UserController.index);
routes.put('/user', UserController.update);

routes.get('/providers', ProviderController.index);

routes.get('/notifications', NotificationController.index);
routes.put('/notifications/:id', NotificationController.update);

routes.post('/files', upload.single('file'), FileController.store);

export default routes;
