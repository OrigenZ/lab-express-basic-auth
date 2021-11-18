const router = require('express').Router()
const mongoose = require('mongoose')
const bcryptjs = require('bcryptjs')

const User = require('../models/User.model')
const { isLoggedIn, isLoggedOut } = require('../middleware/route-guard.js')

//GET USERPROFILE
router.get('/profile', isLoggedIn, (req, res) => {
  res.render('users/user-profile', { user: req.session.currentUser })
})

//GET SIGNUP
router.get('/signup', isLoggedOut, (_, res) => {
  res.render('auth/signup')
})

//POST SIGNUP
router.post('/signup', async (req, res, next) => {
  const { username, email, password } = req.body

  if (!username || !email || !password) {
    res.render('auth/signup', { errorMessage: 'Please fill in all fields.' })
  }

  const regex = /(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{6,}/

  if (!regex.test(password)) {
    res.status(500).render('auth/signup', {
      errorMessage:
        'Password needs to have at least 6 chars and must contain at least one number, one lowercase and one uppercase letter.',
    })
  }

  try {
    const salt = await bcryptjs.genSalt(10)
    const passwordHash = await bcryptjs.hash(password, salt)
    const userCreated = await User.create({ username, email, passwordHash })
    res.render('users/user-profile', { user: userCreated })
  } catch (err) {
    if (err instanceof mongoose.Error.ValidationError) {
      res.status(500).render('auth/signup', { errorMessage: err.message })
    } else if (err.code === 11000) {
      res.status(500).render('auth/signup', {
        errorMessage: 'Username or email is already used.',
      })
    } else {
      next(error)
    }
  }
})

//GET LOGIN
router.get('/login', isLoggedOut, (_, res) => {
  res.render('auth/login')
})

//POST LOGIN
router.post('/login', async (req, res, next) => {
  //   console.log("SESSION =====> ", req.session);
  const { email, password } = req.body

  if (email === '' || password === '') {
    res.render('auth/login', { errorMessage: 'Please fill in all the fields' })
  }

  try {
    const user = await User.findOne({ email })
    if (!user) {
      res.render('auth/login', { errorMessage: 'Email does not exist' })
    } else {
      const passMatch = await bcryptjs.compare(password, user.passwordHash)
      if (passMatch) {
        req.session.currentUser = user
        res.redirect('/auth/profile')
      } else {
        res.render('auth/login', { errorMessage: 'Incorrect password' })
      }
    }
  } catch (err) {
    next(err)
  }
})

//POST LOGOUT
router.post('/logout', isLoggedIn, (req, res, next) => {
  
  res.status(200).clearCookie('connect.sid', {
    path: '/',
  })

  req.session.destroy((err) => {
    if (err) next(err)
    res.redirect('/')
  })
})

module.exports = router
