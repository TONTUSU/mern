const {Router} = require('express')
const bcrypt = require('bcryptjs')
const config = require('config')
const jwt = require('jsonwebtoken')
const {check, validationResult} = require('express-validator')
const User = require('../models/User')
const router = Router()

router.post(
    '/register',
    [
      check('email', 'С email что то не так').isEmail(),
      check('password', 'Минимальная длина пароля 6 символов').isLength({min: 6})
    ],
    async (req, res) => {
      try {
        const errors = validationResult(req)

        if (!errors.isEmpty()) {
          return res.status(400).json({
            errors: errors.array(),
            message: 'Некорректные данные'
          })
        }

        const {email, password} = req.body
        const candidate = await User.findOne({email})

        if (candidate) {
          return res.status(400).json({
            message: 'Такой челик уже существует'
          })
        }

        const hashedPassword = await bcrypt.hash(password, 10)
        const user = new User({email, password: hashedPassword})

        await user.save()
        res.status(201).json({
          message: 'Челик создан'
        })
      } catch (e) {
        res.status(500).json({
          message: 'Что то пошло не так О_о Попробуй еще раз'
        })
      }
    })

router.post('/login',
    [
      check('email', 'С email что то не так').normalizeEmail().isEmail(),
      check('password', 'Введите пароль').exists()
    ],
    async (req, res) => {
      try {
        const errors = validationResult(req)

        if (!errors.isEmpty()) {
          return res.status(400).json({
            errors: errors.array(),
            message: 'Некорректные данные'
          })
        }

        const {email, password} = req.body
        const user = await User.findOne({email})

        if (!user) {
          return res.status(400).json({
            message: 'Пользователь не найден'
          })
        }

        const isMath = await bcrypt.compare(password, user.password)

        if (!isMath) {
          return res.status(400).json({
            message: 'Неверный пароль'
          })
        }

        const token = jwt.sign(
            {userId: user.id},
            config.get('jwtSecret'),
            {expiresIn: '1h'}
        )

        res.json({
          token,
          userId: user.id
        })
      } catch (e) {
        res.status(500).json({
          message: 'Что то пошло не так О_о Попробуй еще раз'
        })
      }
    })

module.exports = router