import express from 'express'
import serverSetup from './initialization/serverSetup.js'

const app = express()

const start = async () => {
  try {
    await serverSetup(app)
  } catch (err) {
    console.log(err.message)
    process.emit(1)
  }
}

start()
