import mongoose from 'mongoose'
import dotenv from 'dotenv'

dotenv.config()

async function DBstart() {
  try {
    await mongoose.connect(process.env.MONGODB_URL),
      {
        useNewUrlParser: true,
        useUnifiedTopologi: true,
        useCreateIndex: true
      }
  } catch (e) {
    console.log(e.message)
    process.emit(1)
  }
}

export default DBstart
