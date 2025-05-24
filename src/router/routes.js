import { Router } from 'express'
import authRouter from './auth.routes.js'
import productRouter from './product.routes.js'
import chatRouter from './chat.routes.js'

const router = Router()

router.use('/auth', authRouter)
router.use('/product', productRouter)
router.use('/chat', chatRouter)

export default router
