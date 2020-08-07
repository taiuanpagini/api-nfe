import * as Yup from 'yup';
import jwt from 'jsonwebtoken';
import authConf from '../../config/auth';
import User from '../models/User';
import File from '../models/File';

class SessionController {
  async store(req, res) {
    const schema = Yup.object().shape({
      user: Yup.string()
        .required(),
      password: Yup.string().required(),
    });

    if (!(await schema.isValid(req.body))) {
      return res.status(400).json({ error: 'Validation fails' });
    }

    const { user, password } = req.body;

    const userLogin = await User.findOne({
      where: { user },
      include: [
        {
          model: File,
          as:'avatar',
          attributes: ['id', 'path', 'url']
        }
      ]
    });
    if (!userLogin) {
      return res.status(401).json({ error: 'User not found' });
    }

    if (!(await userLogin.checkPassword(password))) {
      return res.status(401).json({ error: 'Password does not match!' });
    }

    const { id, name, email, active, phone, provider, avatar, db } = userLogin;

    return res.json({
      user: {
        id,
        name,
        email,
        user,
        provider,
        active,
        phone,
        avatar,
        db
      },
      token: jwt.sign({ id }, authConf.secret, {
        expiresIn: authConf.expireIn,
      }),
    });
  }
}

export default new SessionController();
