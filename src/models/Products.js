import { Schema, model } from 'mongoose'

const productsSchema = new Schema({
  userId: { type: Schema.Types.ObjectId, ref: 'User', required: true },
  name: { type: String, required: true },
  description: { type: String, required: true },
  category: { type: String, required: true },
  images: [{ type: String }],
  purpose: {
    type: String,
    required: true,
    enum: ['needs', 'proposals'], 
  },
})

const Products = model('Products', productsSchema)

export default Products
