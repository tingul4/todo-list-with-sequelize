const express = require('express')
const router = express.Router()
const db = require('../../models')
const Todo = db.Todo

router.get('/', (req, res) => {
  const userId = req.user.id
  return Todo.findAll({ where: { userId }, raw: true, nest: true })
              .then(todos => res.render('index', { todos }))
              .catch((error) => { return res.status(422).json(error) })
})

module.exports = router